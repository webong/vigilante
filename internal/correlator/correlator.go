// Package correlator bridges mirrored network packets with the live OS, process,
// network topology, application dependency graph, and target codebase/repository
// powered by webong/ext.
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
	"sync"
	"time"

	"github.com/webong/ext/res/system"
	"github.com/webong/ext/res/system/graph"
	"github.com/webong/ext/res/system/network"
	"github.com/webong/vigilante/ext/agent"
	"github.com/webong/vigilante/ext/redact"
	"github.com/webong/vigilante/internal/deps"
	"github.com/webong/vigilante/internal/repo"
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
	Repo        *repo.Index
	CacheTTL    time.Duration
	// FallbackPID is used when inspecting a local process in environments where
	// the target port belongs to the current or child process.
	FallbackPID    int
	WorkingDir     string
	OnVerdict      func(agent.EnrichedEnvelope, agent.Verdict)
	RemoteBundle   bool
	AdvisoryClient *deps.OSVClient
}

// Correlator maintains the fast socket-to-PID cache, refreshes host/network/process
// context via github.com/webong/ext/res/system, projects topological facts into
// graph.Store, and dispatches interesting flows to the agent gateway.
type Correlator struct {
	sysGraph       *system.Graph
	store          graph.Store
	gateway        *agent.Gateway
	repoIdx        *repo.Index
	cacheTTL       time.Duration
	fallbackPID    int
	workingDir     string
	onVerdict      func(agent.EnrichedEnvelope, agent.Verdict)
	remoteBundle   bool
	advisoryClient *deps.OSVClient
	sourceCache    map[string]string
	research       map[string]*researchEntry

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
		if opts.Repo != nil && opts.Repo.Snapshot().LocalRoot != "" {
			wd = opts.Repo.Snapshot().LocalRoot
		} else {
			wd, _ = os.Getwd()
		}
	}
	return &Correlator{
		sysGraph:       opts.SystemGraph,
		store:          opts.SystemGraph.Store,
		gateway:        opts.Gateway,
		repoIdx:        opts.Repo,
		cacheTTL:       ttl,
		fallbackPID:    opts.FallbackPID,
		workingDir:     wd,
		onVerdict:      opts.OnVerdict,
		remoteBundle:   opts.RemoteBundle,
		advisoryClient: opts.AdvisoryClient,
		sourceCache:    make(map[string]string),
		research:       make(map[string]*researchEntry),
		portCache:      make(map[string]ProcessEntry),
		seenFlows:      make(map[string]uint64),
	}, nil
}

// RefreshBaseline runs an initial host, process, and network discovery pass
// using github.com/webong/ext/res/system and github.com/webong/ext/res/system/network.
func (c *Correlator) RefreshBaseline(ctx context.Context) error {
	hostInv, err := c.sysGraph.ScanHost(ctx)
	if err != nil {
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
// OS state, application dependency graph, and indexed repository routes/sinks,
// projects the flow into graph.Store, and invokes the agent gateway.
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

	procEntry, isNewSocket := c.ResolveSocketOwner(ctx, targetAddr)

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

	codebaseCtx := c.buildCodebaseContext(ev)
	var advisoryResearch *agent.AdvisoryResearch
	if c.remoteBundle && c.advisoryClient != nil {
		advisoryResearch = c.researchSnapshot(ctx, procEntry)
	}

	commit, err := c.projectFlowToGraph(ctx, ev, procEntry, netSnap, codebaseCtx)
	var revision uint64
	if err == nil {
		revision = commit.Revision
	}

	envelope := agent.EnrichedEnvelope{
		Event:            ev,
		TriggerReason:    triggerReason,
		OS:               osCtx,
		ServerProcess:    procEntry.Process,
		NetworkTopology:  netSnap,
		DependencyGraph:  procEntry.Deps,
		Codebase:         codebaseCtx,
		GraphRevision:    revision,
		AdvisoryResearch: advisoryResearch,
	}

	verdict, err := c.gateway.Triage(ctx, envelope)
	if err != nil {
		return agent.Verdict{}, err
	}
	if verdict.Severity == "" && verdict.Action == "" && verdict.Summary == "" {
		// The agent accepted the envelope and owns its output destination.
		return agent.Verdict{}, nil
	}

	if verdict.Severity == "high" || verdict.Severity == "critical" {
		_ = c.projectAlertToGraph(ctx, ev, verdict)
	}

	if c.onVerdict != nil {
		c.onVerdict(envelope, verdict)
	}
	return verdict, nil
}

func (c *Correlator) buildCodebaseContext(ev agent.PacketEvent) *agent.CodebaseContext {
	if c.repoIdx == nil {
		return nil
	}
	snap := c.repoIdx.Snapshot()
	ctx := &agent.CodebaseContext{
		Source:     snap.Source,
		Commit:     snap.Commit,
		TreeDigest: snap.TreeDigest,
		FileCount:  snap.FileCount,
		Languages:  snap.Languages,
	}
	if matched, ok := c.repoIdx.MatchRoute(ev.Method, ev.Path); ok {
		ctx.MatchedRoute = &matched
	}
	// Attach up to 8 relevant sinks (prioritizing the matched route's file if present).
	for _, s := range snap.Sinks {
		if ctx.MatchedRoute != nil && s.File == ctx.MatchedRoute.File {
			ctx.RelevantSinks = append(ctx.RelevantSinks, s)
		}
		if len(ctx.RelevantSinks) >= 8 {
			break
		}
	}
	for _, s := range snap.Sinks {
		if len(ctx.RelevantSinks) >= 8 {
			break
		}
		if ctx.MatchedRoute != nil && s.File == ctx.MatchedRoute.File {
			continue
		}
		ctx.RelevantSinks = append(ctx.RelevantSinks, s)
	}
	if c.remoteBundle {
		seen := make(map[string]bool)
		add := func(file string, line int) {
			key := fmt.Sprintf("%s:%d", file, line)
			if file == "" || line < 1 || seen[key] || len(ctx.SourceExcerpts) >= 3 {
				return
			}
			seen[key] = true
			start := line - 4
			if start < 1 {
				start = 1
			}
			if text := c.sourceExcerpt(file, start, line+8); text != "" {
				ctx.SourceExcerpts = append(ctx.SourceExcerpts, agent.SourceExcerpt{File: file, StartLine: start, Text: text})
			}
		}
		if ctx.MatchedRoute != nil {
			add(ctx.MatchedRoute.File, ctx.MatchedRoute.Line)
		}
		for _, sink := range ctx.RelevantSinks {
			add(sink.File, sink.Line)
		}
	}
	return ctx
}

func (c *Correlator) sourceExcerpt(file string, start, end int) string {
	key := fmt.Sprintf("%s:%d:%d", file, start, end)
	c.mu.RLock()
	text, ok := c.sourceCache[key]
	c.mu.RUnlock()
	if ok {
		return text
	}
	text, err := c.repoIdx.ReadSnippet(file, start, end)
	if err != nil {
		return ""
	}
	text = redact.String(text)
	if len(text) > 2048 {
		text = text[:2048]
	}
	c.mu.Lock()
	if len(c.sourceCache) >= 256 {
		c.sourceCache = make(map[string]string)
	}
	c.sourceCache[key] = text
	c.mu.Unlock()
	return text
}

func (c *Correlator) projectFlowToGraph(ctx context.Context, ev agent.PacketEvent, procEntry ProcessEntry, netSnap network.Snapshot, cb *agent.CodebaseContext) (graph.Commit, error) {
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

	if cb != nil {
		codebaseID := "codebase/" + hashID(cb.Source+"|"+cb.TreeDigest)
		vertices = append(vertices, graph.Vertex{
			ID:   codebaseID,
			Kind: schema.KindCodebase,
			Attributes: map[string]any{
				"source":      cb.Source,
				"commit":      cb.Commit,
				"tree_digest": cb.TreeDigest,
				"file_count":  cb.FileCount,
			},
			Provenance: prov,
		})
		edges = append(edges, graph.Edge{
			ID:         "built-from/" + hashID(procID+"->"+codebaseID),
			From:       procID,
			To:         codebaseID,
			Type:       schema.RelBuiltFrom,
			Provenance: prov,
		})

		if cb.MatchedRoute != nil {
			mr := cb.MatchedRoute
			routeID := "route/" + hashID(codebaseID+"|"+mr.Method+"|"+mr.Pattern+"|"+mr.File)
			vertices = append(vertices, graph.Vertex{
				ID:   routeID,
				Kind: schema.KindRouteHandler,
				Attributes: map[string]any{
					"method":  mr.Method,
					"pattern": mr.Pattern,
					"file":    mr.File,
					"line":    mr.Line,
				},
				Provenance: prov,
			})
			edges = append(edges,
				graph.Edge{
					ID:         "exposes-route/" + hashID(codebaseID+"->"+routeID),
					From:       codebaseID,
					To:         routeID,
					Type:       schema.RelExposesRoute,
					Provenance: prov,
				},
				graph.Edge{
					ID:         "matches-route/" + hashID(flowID+"->"+routeID),
					From:       flowID,
					To:         routeID,
					Type:       schema.RelMatchesRoute,
					Provenance: prov,
				},
			)
		}
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
					"severity":        v.Severity,
					"action":          v.Action,
					"summary":         v.Summary,
					"matched_handler": v.MatchedHandler,
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
