// Package correlator bridges mirrored network packets with the live OS, process,
// network topology, and application dependency graph powered by webong/ext.
package correlator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/webong/ext/res/system"
	"github.com/webong/ext/res/system/graph"
	"github.com/webong/ext/res/system/network"
	"github.com/webong/vigilante/internal/agent"
	"github.com/webong/vigilante/internal/deps"
	"github.com/webong/vigilante/internal/schema"
)

// ProcessEntry caches the resolved process, sockets, mappings, and dependencies
// for a listening or connected local port.
type ProcessEntry struct {
	Process   agent.ServerProcessContext
	Deps      deps.Graph
	UpdatedAt time.Time
}

// Options configures the Correlator.
type Options struct {
	SystemGraph *system.Graph
	Gateway     *agent.Gateway
	CacheTTL    time.Duration
	// FallbackPID is used when inspecting a local process in environments where
	// the target port belongs to the current or child process.
	FallbackPID int
	WorkingDir  string
	OnVerdict   func(agent.EnrichedEnvelope, agent.Verdict)
}

// Correlator maintains the fast socket-to-PID cache, refreshes host/network/process
// context via github.com/webong/ext/res/system, projects topological facts into
// graph.Store, and dispatches interesting flows to the agent gateway.
type Correlator struct {
	sysGraph    *system.Graph
	store       graph.Store
	gateway     *agent.Gateway
	cacheTTL    time.Duration
	fallbackPID int
	workingDir  string
	onVerdict   func(agent.EnrichedEnvelope, agent.Verdict)

	mu          sync.RWMutex
	osContext   agent.OSContext
	netSnapshot network.Snapshot
	portCache   map[string]ProcessEntry
	seenFlows   map[string]uint64
}

// New initializes the Correlator and registers the vigilante.net schema on the
// shared ext graph.Store.
func New(opts Options) (*Correlator, error) {
	if opts.SystemGraph == nil || opts.SystemGraph.Store == nil {
		return nil, fmt.Errorf("system graph store is required")
	}
	if opts.Gateway == nil {
		return nil, fmt.Errorf("agent gateway is required")
	}
	if err := schema.Register(opts.SystemGraph.Store); err != nil {
		return nil, err
	}
	ttl := opts.CacheTTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	wd := opts.WorkingDir
	if wd == "" {
		wd, _ = os.Getwd()
	}
	return &Correlator{
		sysGraph:    opts.SystemGraph,
		store:       opts.SystemGraph.Store,
		gateway:     opts.Gateway,
		cacheTTL:    ttl,
		fallbackPID: opts.FallbackPID,
		workingDir:  wd,
		onVerdict:   opts.OnVerdict,
		portCache:   make(map[string]ProcessEntry),
		seenFlows:   make(map[string]uint64),
	}, nil
}

// RefreshBaseline runs an initial host, process, and network discovery pass
// using github.com/webong/ext/res/system and github.com/webong/ext/res/system/network.
func (c *Correlator) RefreshBaseline(ctx context.Context) error {
	hostInv, err := c.sysGraph.ScanHost(ctx)
	if err != nil {
		// Even if a subset fails, DiscoverHost is still attempted.
		hostInv, _ = system.DiscoverHost(ctx)
	}

	procSnap, procErr := c.sysGraph.ScanProcesses(ctx, system.ProcessOptions{
		MaxProcesses: 1024,
		MaxResources: 512,
		Timeout:      5 * time.Second,
	})

	netSnap, netErr := network.Discover(ctx, network.Options{
		Timeout: 3 * time.Second,
	})
	if netErr != nil {
		netSnap = network.Snapshot{Platform: runtime.GOOS, ObservedAt: time.Now().UTC()}
	}

	hostname, _ := os.Hostname()
	osCtx := agent.OSContext{
		Hostname:   hostname,
		OS:         runtime.GOOS,
		Arch:       runtime.GOARCH,
		ShellCount: len(hostInv.Shells),
		MountCount: len(hostInv.Filesystems),
	}
	if procErr == nil {
		osCtx.ProcessCount = len(procSnap.Processes)
	}

	c.mu.Lock()
	c.osContext = osCtx
	c.netSnapshot = netSnap
	c.mu.Unlock()

	return nil
}

// ProcessPacket correlates a mirrored PacketEvent with the owning server process,
// OS state, and application dependency graph, projects the flow into graph.Store,
// and invokes the agent gateway when appropriate.
func (c *Correlator) ProcessPacket(ctx context.Context, ev agent.PacketEvent) (agent.Verdict, error) {
	if ev.FlowID == "" {
		ev.FlowID = hashID(ev.Protocol + "|" + ev.SrcAddr + "|" + ev.DstAddr + "|" + ev.TargetAddr)
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}

	targetAddr := ev.TargetAddr
	if targetAddr == "" {
		targetAddr = ev.DstAddr
	}

	procEntry, isNewSocket := c.resolveTargetProcess(ctx, targetAddr)

	c.mu.Lock()
	c.seenFlows[ev.FlowID]++
	flowCount := c.seenFlows[ev.FlowID]
	osCtx := c.osContext
	netSnap := c.netSnapshot
	c.mu.Unlock()

	triggerReason := "periodic-sample"
	if isNewSocket || flowCount == 1 {
		triggerReason = "new-unseen-process-socket"
	}
	if isSuspiciousPayload(ev) {
		triggerReason = "anomalous-payload-signature"
	}

	commit, err := c.projectFlowToGraph(ctx, ev, procEntry, netSnap)
	var revision uint64
	if err == nil {
		revision = commit.Revision
	}

	envelope := agent.EnrichedEnvelope{
		Event:           ev,
		TriggerReason:   triggerReason,
		OS:              osCtx,
		ServerProcess:   procEntry.Process,
		NetworkTopology: netSnap,
		DependencyGraph: procEntry.Deps,
		GraphRevision:   revision,
	}

	verdict, err := c.gateway.Triage(ctx, envelope)
	if err != nil {
		return agent.Verdict{}, err
	}

	if verdict.Severity == "high" || verdict.Severity == "critical" {
		_ = c.projectAlertToGraph(ctx, ev, verdict)
	}

	if c.onVerdict != nil {
		c.onVerdict(envelope, verdict)
	}
	return verdict, nil
}

func (c *Correlator) resolveTargetProcess(ctx context.Context, targetAddr string) (ProcessEntry, bool) {
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

	pid := c.fallbackPID
	if pid <= 0 {
		pid = os.Getpid()
	}

	var procCtx agent.ServerProcessContext
	procCtx.PID = pid

	// Use github.com/webong/ext/res/system.InspectProcess to gather live OS evidence
	// for the target process (executable, start_id, sockets, and mapped libraries).
	snap, err := system.InspectProcess(ctx, pid, system.ProcessOptions{
		MaxResources: 512,
		Timeout:      3 * time.Second,
	})
	if err == nil && len(snap.Processes) == 1 {
		_ = c.sysGraph.ObserveProcesses(ctx, snap)
		p := snap.Processes[0]
		procCtx.PID = p.PID
		procCtx.ParentPID = p.ParentPID
		procCtx.Name = p.Name
		procCtx.Executable = p.Executable
		procCtx.StartID = p.StartID
		procCtx.Owner = p.Owner
		for _, r := range p.Resources {
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
			}
		}
	} else {
		exe, _ := os.Executable()
		procCtx.Name = "vigilante-target"
		procCtx.Executable = exe
		procCtx.StartID = strconv.Itoa(pid)
	}

	depGraph := deps.Inspect(procCtx.Executable, c.workingDir, procCtx.MappedLibs)
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

func (c *Correlator) projectFlowToGraph(ctx context.Context, ev agent.PacketEvent, procEntry ProcessEntry, netSnap network.Snapshot) (graph.Commit, error) {
	now := time.Now().UTC()
	prov := graph.Provenance{Source: "vigilante", Operation: "flow-mirrored", At: now}

	listenerID := "listener/" + hashID(ev.DstAddr)
	flowID := "flow/" + ev.FlowID
	procID := "process-ref/" + strconv.Itoa(procEntry.Process.PID)
	topoID := "topology/" + netSnap.Platform

	vertices := []graph.Vertex{
		{
			ID:   listenerID,
			Kind: schema.KindListener,
			Attributes: map[string]any{
				"listen_addr": ev.DstAddr,
				"target_addr": ev.TargetAddr,
				"protocol":    ev.Protocol,
			},
			Provenance: prov,
		},
		{
			ID:   flowID,
			Kind: schema.KindFlow,
			Attributes: map[string]any{
				"src_addr":      ev.SrcAddr,
				"dst_addr":      ev.DstAddr,
				"protocol":      ev.Protocol,
				"method":        ev.Method,
				"path":          ev.Path,
				"payload_bytes": ev.PayloadBytes,
				"observed_at":   ev.Timestamp.Format(time.RFC3339Nano),
			},
			Provenance: prov,
		},
		{
			ID:   procID,
			Kind: schema.KindProcessRef,
			Attributes: map[string]any{
				"pid":         procEntry.Process.PID,
				"name":        procEntry.Process.Name,
				"executable":  procEntry.Process.Executable,
				"main_module": procEntry.Deps.MainModule,
			},
			Provenance: prov,
		},
		{
			ID:   topoID,
			Kind: schema.KindNetTopology,
			Attributes: map[string]any{
				"platform":        netSnap.Platform,
				"interface_count": len(netSnap.Interfaces),
				"route_count":     len(netSnap.Routes),
			},
			Provenance: prov,
		},
	}

	edges := []graph.Edge{
		{
			ID:         "accepts/" + hashID(listenerID+"->"+flowID),
			From:       listenerID,
			To:         flowID,
			Type:       schema.RelAcceptsFlow,
			Provenance: prov,
		},
		{
			ID:         "owned-by/" + hashID(flowID+"->"+procID),
			From:       flowID,
			To:         procID,
			Type:       schema.RelOwnedBy,
			Provenance: prov,
		},
		{
			ID:         "routes/" + hashID(flowID+"->"+topoID),
			From:       flowID,
			To:         topoID,
			Type:       schema.RelRoutesThrough,
			Provenance: prov,
		},
	}

	// Project up to 32 dependencies into the graph so queries stay bounded and fast.
	maxDeps := len(procEntry.Deps.Dependencies)
	if maxDeps > 32 {
		maxDeps = 32
	}
	for i := 0; i < maxDeps; i++ {
		dep := procEntry.Deps.Dependencies[i]
		depID := "dep/" + hashID(dep.Ecosystem+":"+dep.Path+"@"+dep.Version)
		vertices = append(vertices, graph.Vertex{
			ID:   depID,
			Kind: schema.KindDependency,
			Attributes: map[string]any{
				"ecosystem": dep.Ecosystem,
				"path":      dep.Path,
				"version":   dep.Version,
				"source":    dep.Source,
			},
			Provenance: prov,
		})
		edges = append(edges, graph.Edge{
			ID:         "depends-on/" + hashID(procID+"->"+depID),
			From:       procID,
			To:         depID,
			Type:       schema.RelDependsOn,
			Provenance: prov,
		})
	}

	return c.store.Apply(ctx, graph.Transaction{
		Namespace: schema.Namespace,
		Vertices:  vertices,
		Edges:     edges,
	})
}

func (c *Correlator) projectAlertToGraph(ctx context.Context, ev agent.PacketEvent, v agent.Verdict) error {
	now := time.Now().UTC()
	prov := graph.Provenance{Source: "vigilante.agent", Operation: "triage-alert", At: now}
	flowID := "flow/" + ev.FlowID
	alertID := "alert/" + hashID(ev.FlowID+"|"+now.Format(time.RFC3339Nano))

	_, err := c.store.Apply(ctx, graph.Transaction{
		Namespace: schema.Namespace,
		Vertices: []graph.Vertex{
			{
				ID:   alertID,
				Kind: schema.KindAgentAlert,
				Attributes: map[string]any{
					"severity": v.Severity,
					"action":   v.Action,
					"summary":  v.Summary,
				},
				Provenance: prov,
			},
		},
		Edges: []graph.Edge{
			{
				ID:         "triggered/" + hashID(flowID+"->"+alertID),
				From:       flowID,
				To:         alertID,
				Type:       schema.RelTriggered,
				Provenance: prov,
			},
		},
	})
	return err
}

func isSuspiciousPayload(ev agent.PacketEvent) bool {
	combined := strings.ToLower(ev.Path + " " + ev.PayloadPreview)
	for _, needle := range []string{"../", "/etc/passwd", "jndi:", "select ", "union ", "<script"} {
		if strings.Contains(combined, needle) {
			return true
		}
	}
	return false
}

func extractPort(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	if err == nil {
		return port
	}
	return ""
}

func hashID(input string) string {
	sum := sha256.Sum256([]byte(input))
	return hex.EncodeToString(sum[:10])
}
