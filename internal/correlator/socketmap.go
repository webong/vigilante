package correlator

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/webong/ext/res/system"
	"github.com/webong/vigilante/ext/agent"
	"github.com/webong/vigilante/internal/deps"
)

// ResolveSocketOwner scans caller-visible processes via github.com/webong/ext/res/system
// to find the actual OS process that owns the socket listening on or connected to
// targetAddr (for example "127.0.0.1:3000" or ":8080").
func (c *Correlator) ResolveSocketOwner(ctx context.Context, targetAddr string) (ProcessEntry, bool) {
	port := extractPort(targetAddr)
	cacheKey := port
	if cacheKey == "" {
		cacheKey = targetAddr
	}

	c.mu.RLock()
	cached, ok := c.portCache[cacheKey]
	c.mu.RUnlock()
	if ok && time.Since(cached.UpdatedAt) < c.cacheTTL {
		return cached, false
	}

	var matchedSnap *system.ProcessSnapshot
	var matchedInfo *system.ProcessInfo

	// 1. If a fallback PID is configured, inspect it first to check if it owns the target port.
	if c.fallbackPID > 0 {
		if snap, err := system.InspectProcess(ctx, c.fallbackPID, system.ProcessOptions{
			MaxResources: 512,
			Timeout:      2 * time.Second,
		}); err == nil && len(snap.Processes) == 1 {
			p := snap.Processes[0]
			if port == "" || processOwnsPort(p, port) {
				matchedSnap = &snap
				matchedInfo = &p
			}
		}
	}

	// 2. If not owned by fallbackPID, scan caller-visible processes owned by the current user
	// to discover which daemon/server process owns the listening port.
	if matchedInfo == nil && port != "" {
		if snap, info, found := scanProcessesForPort(ctx, port, c.fallbackPID); found {
			matchedSnap = &snap
			matchedInfo = &info
		}
	}

	// 3. Final fallback: inspect fallbackPID (or os.Getpid()) even if the socket was ephemeral.
	if matchedInfo == nil {
		pid := c.fallbackPID
		if pid <= 0 {
			pid = os.Getpid()
		}
		if snap, err := system.InspectProcess(ctx, pid, system.ProcessOptions{
			MaxResources: 512,
			Timeout:      2 * time.Second,
		}); err == nil && len(snap.Processes) == 1 {
			matchedSnap = &snap
			p := snap.Processes[0]
			matchedInfo = &p
		}
	}

	var procCtx agent.ServerProcessContext
	var openDirs []string

	if matchedInfo != nil {
		if matchedSnap != nil {
			_ = c.sysGraph.ObserveProcesses(ctx, *matchedSnap)
		}
		procCtx.PID = matchedInfo.PID
		procCtx.ParentPID = matchedInfo.ParentPID
		procCtx.Name = matchedInfo.Name
		procCtx.Executable = matchedInfo.Executable
		procCtx.StartID = matchedInfo.StartID
		procCtx.Owner = matchedInfo.Owner

		for _, r := range matchedInfo.Resources {
			switch r.Kind {
			case "socket":
				sockDesc := r.Protocol + " " + r.LocalAddress
				if r.RemoteAddress != "" {
					sockDesc += "->" + r.RemoteAddress
				}
				if r.State != "" {
					sockDesc += " (" + r.State + ")"
				}
				procCtx.OpenSockets = append(procCtx.OpenSockets, strings.TrimSpace(sockDesc))
			case "mapping":
				if r.Path != "" {
					procCtx.MappedLibs = append(procCtx.MappedLibs, r.Path)
				}
			case "file":
				if r.Path != "" {
					if r.Descriptor == "cwd" || strings.HasSuffix(r.Descriptor, "cwd") {
						openDirs = append([]string{r.Path}, openDirs...)
					} else if st, err := os.Stat(r.Path); err == nil && st.IsDir() {
						openDirs = append(openDirs, r.Path)
					} else if st, err := os.Stat(filepath.Dir(r.Path)); err == nil && st.IsDir() {
						openDirs = append(openDirs, filepath.Dir(r.Path))
					}
				}
			}
		}
	} else {
		pid := os.Getpid()
		exe, _ := os.Executable()
		procCtx.PID = pid
		procCtx.Name = "vigilante-target"
		procCtx.Executable = exe
	}

	workDir := c.workingDir
	for _, candidate := range openDirs {
		if candidate != "" && candidate != "/" {
			workDir = candidate
			break
		}
	}

	depGraph := deps.Inspect(procCtx.Executable, workDir, procCtx.MappedLibs)
	entry := ProcessEntry{
		Process:   procCtx,
		Deps:      depGraph,
		UpdatedAt: time.Now().UTC(),
	}

	c.mu.Lock()
	c.portCache[cacheKey] = entry
	c.mu.Unlock()

	return entry, true
}

func scanProcessesForPort(ctx context.Context, port string, skipPID int) (system.ProcessSnapshot, system.ProcessInfo, bool) {
	all, err := system.DiscoverProcesses(ctx, system.ProcessOptions{
		MaxProcesses: 1024,
		Timeout:      3 * time.Second,
	})
	if err != nil {
		return system.ProcessSnapshot{}, system.ProcessInfo{}, false
	}

	selfPID := os.Getpid()
	var selfOwner string
	for _, p := range all.Processes {
		if p.PID == selfPID {
			selfOwner = p.Owner
			break
		}
	}

	// Inspect most recently started / higher PID processes first (typical for local dev/app servers),
	// capped at 24 candidates so cache-miss resolution stays fast.
	inspected := 0
	for i := len(all.Processes) - 1; i >= 0 && inspected < 24; i-- {
		cand := all.Processes[i]
		if cand.PID == skipPID || cand.PID <= 1 {
			continue
		}
		if selfOwner != "" && cand.Owner != "" && cand.Owner != selfOwner {
			continue
		}
		inspected++
		snap, err := system.InspectProcess(ctx, cand.PID, system.ProcessOptions{
			MaxResources: 256,
			Timeout:      750 * time.Millisecond,
		})
		if err != nil || len(snap.Processes) != 1 {
			continue
		}
		p := snap.Processes[0]
		if processOwnsPort(p, port) {
			return snap, p, true
		}
	}
	return system.ProcessSnapshot{}, system.ProcessInfo{}, false
}

func processOwnsPort(p system.ProcessInfo, wantPort string) bool {
	if wantPort == "" {
		return false
	}
	for _, r := range p.Resources {
		if r.Kind != "socket" {
			continue
		}
		for _, addr := range []string{r.LocalAddress, r.Endpoint} {
			if addrMatchesPort(addr, wantPort) {
				return true
			}
		}
	}
	return false
}

func addrMatchesPort(addr, wantPort string) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return false
	}
	if _, port, err := net.SplitHostPort(addr); err == nil && port == wantPort {
		return true
	}
	if strings.HasSuffix(addr, ":"+wantPort) {
		return true
	}
	return false
}
