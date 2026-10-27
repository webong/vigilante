package repo

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/webong/ext/res/system"
)

// DiscoverRoot infers the source root for a target service so Vigilante can
// index its codebase without an explicit -repo. It maps the target's port to a
// listening process (via ext/res/system), then walks that process's open-file
// descriptors looking for a directory that looks like a source checkout (has a
// .git dir or a recognizable project manifest).
//
// It returns "" when nothing is confidently found, so callers keep their
// configured -repo. It is deliberately conservative: it never guesses.
func DiscoverRoot(ctx context.Context, target string) string {
	port := portOf(target)
	if port == "" {
		return ""
	}
	dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	pid := listeningPIDForPort(dctx, port)
	if pid <= 0 {
		return ""
	}
	snap, err := system.InspectProcess(dctx, pid, system.ProcessOptions{MaxResources: 512, Timeout: 2 * time.Second})
	if err != nil || len(snap.Processes) == 0 {
		return ""
	}
	// Collect candidate directories from the process's open files, cwd first.
	var cands []string
	for _, r := range snap.Processes[0].Resources {
		if r.Kind != "file" || r.Path == "" {
			continue
		}
		if r.Descriptor == "cwd" || strings.HasSuffix(r.Descriptor, "cwd") {
			cands = append([]string{r.Path}, cands...)
		} else if st, err := os.Stat(r.Path); err == nil && st.IsDir() {
			cands = append(cands, r.Path)
		} else {
			cands = append(cands, filepath.Dir(r.Path))
		}
	}
	for _, c := range cands {
		if c == "" || c == "/" {
			continue
		}
		if root := sourceRootFrom(c); root != "" {
			return root
		}
	}
	return ""
}

// listeningPIDForPort returns the PID of a process listening on the given port,
// or 0 if none is visible to the current user. It enumerates caller-visible
// processes, then inspects the most recently started candidates (typical for
// local dev/app servers) for a listening socket on the port.
func listeningPIDForPort(ctx context.Context, port string) int {
	all, err := system.DiscoverProcesses(ctx, system.ProcessOptions{MaxProcesses: 1024, Timeout: 3 * time.Second})
	if err != nil {
		return 0
	}
	selfPID := os.Getpid()
	inspected := 0
	for i := len(all.Processes) - 1; i >= 0 && inspected < 24; i-- {
		cand := all.Processes[i]
		if cand.PID == selfPID || cand.PID <= 1 {
			continue
		}
		inspected++
		snap, err := system.InspectProcess(ctx, cand.PID, system.ProcessOptions{MaxResources: 256, Timeout: 750 * time.Millisecond})
		if err != nil || len(snap.Processes) != 1 {
			continue
		}
		if processListensOn(snap.Processes[0], port) {
			return snap.Processes[0].PID
		}
	}
	return 0
}

// processListensOn reports whether p has a listening socket resource on port.
func processListensOn(p system.ProcessInfo, port string) bool {
	for _, r := range p.Resources {
		if r.Kind != "socket" {
			continue
		}
		if r.State != "" && !strings.Contains(strings.ToLower(r.State), "listen") {
			continue
		}
		if portOf(r.LocalAddress) == port {
			return true
		}
	}
	return false
}

// sourceRootFrom walks up from dir to find the nearest source-checkout root
// (a directory containing .git or a project manifest). Returns "" if none.
func sourceRootFrom(dir string) string {
	cur := dir
	for i := 0; i < 6; i++ { // bound the walk
		if isSourceRoot(cur) {
			return cur
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}
	return ""
}

// isSourceRoot reports whether dir looks like the root of a source checkout.
func isSourceRoot(dir string) bool {
	if st, err := os.Stat(filepath.Join(dir, ".git")); err == nil && (st.IsDir() || st.Mode().IsRegular()) {
		return true
	}
	for _, manifest := range []string{
		"go.mod", "package.json", "pyproject.toml", "requirements.txt",
		"Cargo.toml", "pom.xml", "build.gradle", "composer.json", "Gemfile",
	} {
		if st, err := os.Stat(filepath.Join(dir, manifest)); err == nil && st.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// portOf extracts the port from "host:port", a URL host, or a bare port.
func portOf(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	// Strip scheme if a URL was passed (http://host:port/path).
	if i := strings.Index(addr, "://"); i >= 0 {
		addr = addr[i+3:]
	}
	// Strip any path component.
	if i := strings.IndexByte(addr, '/'); i >= 0 {
		addr = addr[:i]
	}
	// host:port -> the part after the last ':' if numeric.
	if i := strings.LastIndexByte(addr, ':'); i >= 0 {
		if p := addr[i+1:]; isDigits(p) {
			return p
		}
	}
	if isDigits(addr) {
		return addr
	}
	return ""
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
