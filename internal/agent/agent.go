// Package agent implements the typed ext.plugin/v1 contract and gateway for
// dispatching mirrored network flows enriched with OS, server, application
// dependency graphs, and indexed codebase/repository context to a security/triage
// agent. It supports both in-process guests and out-of-process JSON-line agents
// supervised by res/system/supervisor, with reverse host callbacks so the agent
// can query the live ext.system graph or read source files on demand.
package agent

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/webong/ext/pkg/ext-go/engine"
	"github.com/webong/ext/pkg/ext-go/engine/guest/author"
	"github.com/webong/ext/pkg/ext-go/engine/transport/inprocess"
	"github.com/webong/ext/pkg/ext-go/engine/transport/jsonline"
	"github.com/webong/ext/res/system"
	"github.com/webong/ext/res/system/graph"
	"github.com/webong/ext/res/system/network"
	"github.com/webong/vigilante/internal/deps"
	"github.com/webong/vigilante/internal/repo"
)

const (
	ContractName    = "vigilante.agent"
	ContractVersion = "v1"
	OperationTriage = "triage-flow"

	ReverseContractName    = "vigilante.host"
	ReverseContractVersion = "v1"
	ReverseOpQueryGraph    = "query-graph"
	ReverseOpReadSource    = "read-source"
)

// PacketEvent represents a non-blocking mirrored packet or L7 request sample
// cloned off the primary network stack.
type PacketEvent struct {
	FlowID         string            `json:"flow_id"`
	Timestamp      time.Time         `json:"timestamp"`
	Protocol       string            `json:"protocol"` // "tcp", "udp", "http"
	SrcAddr        string            `json:"src_addr"`
	DstAddr        string            `json:"dst_addr"`
	TargetAddr     string            `json:"target_addr"` // Upstream backend address
	Method         string            `json:"method,omitempty"`
	Path           string            `json:"path,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	PayloadPreview string            `json:"payload_preview,omitempty"`
	PayloadBytes   int               `json:"payload_bytes"`
}

// OSContext summarizes the host OS state discovered via github.com/webong/ext/res/system.
type OSContext struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	ShellCount   int    `json:"shell_count"`
	MountCount   int    `json:"mount_count"`
	ProcessCount int    `json:"process_count"`
}

// ServerProcessContext summarizes the owning server process discovered via
// system.InspectProcess.
type ServerProcessContext struct {
	PID         int      `json:"pid"`
	ParentPID   int      `json:"parent_pid"`
	Name        string   `json:"name"`
	Executable  string   `json:"executable"`
	StartID     string   `json:"start_id"`
	Owner       string   `json:"owner,omitempty"`
	OpenSockets []string `json:"open_sockets,omitempty"`
	MappedLibs  []string `json:"mapped_libs,omitempty"`
}

// CodebaseContext summarizes the target repository or codebase pointed to by
// vigilante (-repo), including the matched route handler and relevant code sinks.
type CodebaseContext struct {
	Source        string             `json:"source"`
	Commit        string             `json:"commit,omitempty"`
	TreeDigest    string             `json:"tree_digest"`
	FileCount     int                `json:"file_count"`
	Languages     []string           `json:"languages,omitempty"`
	MatchedRoute  *repo.RouteHandler `json:"matched_route,omitempty"`
	RelevantSinks []repo.CodeSink    `json:"relevant_sinks,omitempty"`
}

// EnrichedEnvelope bundles the mirrored packet with the live OS, Server,
// Network Topology, Application Dependency Graph, and Codebase/Repository Context.
type EnrichedEnvelope struct {
	Event           PacketEvent          `json:"event"`
	TriggerReason   string               `json:"trigger_reason"`
	OS              OSContext            `json:"os"`
	ServerProcess   ServerProcessContext `json:"server_process"`
	NetworkTopology network.Snapshot     `json:"network_topology"`
	DependencyGraph deps.Graph           `json:"dependency_graph"`
	Codebase        *CodebaseContext     `json:"codebase,omitempty"`
	GraphRevision   uint64               `json:"graph_revision"`
}

// Verdict is returned by the agent after analyzing the EnrichedEnvelope.
type Verdict struct {
	FlowID               string   `json:"flow_id"`
	Severity             string   `json:"severity"` // "info", "low", "medium", "high", "critical"
	Action               string   `json:"action"`   // "observe", "alert", "flag-cve-reachability", "recommend-block"
	Summary              string   `json:"summary"`
	ReachableDeps        []string `json:"reachable_deps,omitempty"`
	MatchedAdvisories    []string `json:"matched_advisories,omitempty"`
	MatchedHandler       string   `json:"matched_handler,omitempty"` // e.g. "cmd/server/main.go:42"
	InspectedSource      string   `json:"inspected_source,omitempty"`
	ReverseGraphQueried  bool     `json:"reverse_graph_queried,omitempty"`
	ReverseObservedNodes int      `json:"reverse_observed_nodes,omitempty"`
	Recommendations      []string `json:"recommendations,omitempty"`
}

// GraphQueryInput is sent by the agent over a reverse call to inspect the host's
// live ext.system or vigilante.net graph store during triage.
type GraphQueryInput struct {
	Namespace string `json:"namespace"`
	Kind      string `json:"kind,omitempty"`
	Limit     int    `json:"limit"`
}

// GraphQueryOutput is returned by the host to the agent during a reverse call.
type GraphQueryOutput struct {
	Namespace   string   `json:"namespace"`
	VertexCount int      `json:"vertex_count"`
	SampleIDs   []string `json:"sample_ids,omitempty"`
}

// SourceReadInput is sent by the agent over a reverse call to read a source file
// snippet from the indexed repository during triage.
type SourceReadInput struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

// SourceReadOutput returns the requested source code snippet to the agent.
type SourceReadOutput struct {
	File    string `json:"file"`
	Snippet string `json:"snippet"`
}

// TriageMethod returns the typed ext.plugin/v1 method definition for flow triage.
func TriageMethod() author.Method[EnrichedEnvelope, Verdict] {
	return author.Method[EnrichedEnvelope, Verdict]{
		Contract: engine.ContractRef{
			Name:    ContractName,
			Version: ContractVersion,
		},
		Operation: engine.Operation{
			Name:    OperationTriage,
			Surface: "observation",
		},
	}
}

// ReverseQueryGraphMethod returns the typed reverse host method that allows an
// agent to query the live ext graph store while a triage call is in flight.
func ReverseQueryGraphMethod() author.Method[GraphQueryInput, GraphQueryOutput] {
	return author.Method[GraphQueryInput, GraphQueryOutput]{
		Contract: engine.ContractRef{
			Name:    ReverseContractName,
			Version: ReverseContractVersion,
		},
		Operation: engine.Operation{
			Name:    ReverseOpQueryGraph,
			Surface: "observation",
		},
	}
}

// ReverseReadSourceMethod returns the typed reverse host method that allows an
// agent to inspect source lines in the target repository during triage.
func ReverseReadSourceMethod() author.Method[SourceReadInput, SourceReadOutput] {
	return author.Method[SourceReadInput, SourceReadOutput]{
		Contract: engine.ContractRef{
			Name:    ReverseContractName,
			Version: ReverseContractVersion,
		},
		Operation: engine.Operation{
			Name:    ReverseOpReadSource,
			Surface: "observation",
		},
	}
}

// AgentIdentity returns the pinned ext.plugin/v1 identity for the built-in agent.
func AgentIdentity() engine.Identity {
	return engine.Identity{
		ID:       "vigilante/secops-agent",
		Revision: "v1.2.0",
		Version:  "1.2.0",
	}
}

// BuildGuest constructs the ext.plugin/v1 Guest with reverse host call declarations.
func BuildGuest(handler Handler) (engine.Descriptor, *engine.Guest, error) {
	if handler == nil {
		handler = DefaultBuiltInHandler
	}
	reg, err := author.New(AgentIdentity())
	if err != nil {
		return engine.Descriptor{}, nil, err
	}
	method := TriageMethod()
	if err := author.Register(reg, method, func(ctx context.Context, _ engine.Request, env EnrichedEnvelope) (Verdict, error) {
		return handler(ctx, env)
	}); err != nil {
		return engine.Descriptor{}, nil, err
	}

	allow := func(context.Context, engine.Request) error { return nil }
	desc, guestOpts, err := reg.Snapshot(author.Options{
		Authorize:       allow,
		MaxCallDuration: 15 * time.Second,
	})
	if err != nil {
		return engine.Descriptor{}, nil, err
	}

	revGraph := ReverseQueryGraphMethod()
	revSource := ReverseReadSourceMethod()
	desc.Reverse = []engine.Contract{
		{
			ContractRef: revGraph.Contract,
			Operations: []engine.Operation{
				revGraph.Operation,
				revSource.Operation,
			},
		},
	}

	guest, err := engine.NewGuest(desc, guestOpts)
	if err != nil {
		return engine.Descriptor{}, nil, err
	}
	return desc, guest, nil
}

// ServeStdio runs the agent as an out-of-process ext.plugin/v1 JSON-line guest
// over conn (such as stdin/stdout or a local TCP socket).
func ServeStdio(ctx context.Context, conn io.ReadWriteCloser, handler Handler) error {
	_, guest, err := BuildGuest(handler)
	if err != nil {
		_ = conn.Close()
		return err
	}
	return jsonline.ServeGuest(ctx, conn, guest)
}

// BuildHostReverseOptions builds the ReverseOptions that allow an agent to call
// vigilante.host@v1/query-graph and vigilante.host@v1/read-source during triage.
func BuildHostReverseOptions(store graph.Store, repoIdx *repo.Index) *engine.ReverseOptions {
	if store == nil && repoIdx == nil {
		return nil
	}
	revGraph := ReverseQueryGraphMethod()
	revSource := ReverseReadSourceMethod()

	return &engine.ReverseOptions{
		Authorize: func(_ context.Context, req engine.Request) error {
			if req.Contract == revGraph.Contract &&
				(req.Operation == revGraph.Operation.Name || req.Operation == revSource.Operation.Name) {
				return nil
			}
			return engine.ErrDenied
		},
		Handle: func(ctx context.Context, req engine.Request) (json.RawMessage, error) {
			switch req.Operation {
			case revGraph.Operation.Name:
				if store == nil {
					return nil, &engine.RemoteError{Code: "unavailable", Message: "graph store unavailable"}
				}
				var in GraphQueryInput
				if err := engine.Decode(req.Payload, &in); err != nil {
					return nil, &engine.RemoteError{Code: "invalid_input", Message: "invalid graph query input"}
				}
				ns := in.Namespace
				if ns == "" {
					ns = system.Namespace
				}
				limit := in.Limit
				if limit <= 0 || limit > 256 {
					limit = 32
				}
				vertices, err := store.QueryVertices(ctx, graph.VertexQuery{
					Namespace: ns,
					Kind:      in.Kind,
					Limit:     limit,
				})
				if err != nil {
					return nil, err
				}
				sample := make([]string, 0, min(len(vertices), 8))
				for i := 0; i < len(vertices) && i < 8; i++ {
					sample = append(sample, vertices[i].ID)
				}
				out := GraphQueryOutput{
					Namespace:   ns,
					VertexCount: len(vertices),
					SampleIDs:   sample,
				}
				return json.Marshal(out)

			case revSource.Operation.Name:
				if repoIdx == nil {
					return nil, &engine.RemoteError{Code: "unavailable", Message: "no repository indexed"}
				}
				var in SourceReadInput
				if err := engine.Decode(req.Payload, &in); err != nil {
					return nil, &engine.RemoteError{Code: "invalid_input", Message: "invalid source read input"}
				}
				snippet, err := repoIdx.ReadSnippet(in.File, in.StartLine, in.EndLine)
				if err != nil {
					return nil, &engine.RemoteError{Code: "read_failed", Message: "cannot read source snippet"}
				}
				return json.Marshal(SourceReadOutput{
					File:    in.File,
					Snippet: snippet,
				})

			default:
				return nil, engine.ErrUnsupported
			}
		},
	}
}

// Handler is the function signature for an agent evaluating an EnrichedEnvelope.
type Handler func(context.Context, EnrichedEnvelope) (Verdict, error)

// Runner executes an arbitrary command and returns its combined output. The
// CLI agent uses this to shell out to an external LLM/agent binary; tests
// inject fakes. A non-zero exit or non-nil error is surfaced as a triage error.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Gateway manages a verified ext.plugin/v1 session to a local or remote agent.
type Gateway struct {
	session *engine.Session
	method  author.Method[EnrichedEnvelope, Verdict]
	closeFn func(context.Context) error
}

// NewInProcessGateway constructs an in-process ext.plugin/v1 guest and opens a
// verified host session to it with reverse graph and codebase access.
func NewInProcessGateway(ctx context.Context, store graph.Store, repoIdx *repo.Index, handler Handler) (*Gateway, error) {
	desc, guest, err := BuildGuest(handler)
	if err != nil {
		return nil, err
	}

	backend, err := inprocess.New(guest)
	if err != nil {
		return nil, err
	}

	session, err := engine.Open(ctx, desc, engine.Options{
		Verify: func(_ context.Context, actual engine.Descriptor) error {
			return engine.MatchHandshake(desc, actual)
		},
		Authorize: func(_ context.Context, req engine.Request) error {
			_, err := desc.Lookup(req.Contract, req.Operation)
			return err
		},
		Connect: func(context.Context, engine.Descriptor) (engine.Backend, error) {
			return backend, nil
		},
		Reverse: BuildHostReverseOptions(store, repoIdx),
	})
	if err != nil {
		_ = backend.Close()
		return nil, err
	}

	return &Gateway{
		session: session,
		method:  TriageMethod(),
	}, nil
}

// NewSessionGateway wraps an existing engine.Session (such as a jsonline or
// HashiCorp gRPC subprocess supervised by res/system/supervisor).
func NewSessionGateway(session *engine.Session, closeFn func(context.Context) error) *Gateway {
	return &Gateway{
		session: session,
		method:  TriageMethod(),
		closeFn: closeFn,
	}
}

// Triage dispatches the enriched packet + system dependency graph to the agent.
func (g *Gateway) Triage(ctx context.Context, env EnrichedEnvelope) (Verdict, error) {
	return author.Call(ctx, g.session, g.method, env)
}

// Close gracefully drains and closes the underlying plugin session and any
// supervised process.
func (g *Gateway) Close(ctx context.Context) error {
	if g == nil {
		return nil
	}
	var err error
	if g.session != nil {
		err = g.session.Close(ctx)
	}
	if g.closeFn != nil {
		if cErr := g.closeFn(ctx); err == nil {
			err = cErr
		}
	}
	return err
}

// DefaultBuiltInHandler correlates packet payloads and HTTP paths against the
// server process identity, open sockets, loaded module dependency graph, matched
// CVE advisories, and indexed codebase route handlers/sinks. On high-severity
// events, it queries the live ext.system graph and reads the target source file
// snippet via reverse callbacks.
func DefaultBuiltInHandler(ctx context.Context, env EnrichedEnvelope) (Verdict, error) {
	verdict := Verdict{
		FlowID:   env.Event.FlowID,
		Severity: "info",
		Action:   "observe",
		Summary:  "Normal flow correlated with process and dependency graph",
	}

	var reachable []string
	for _, dep := range env.DependencyGraph.Dependencies {
		reachable = append(reachable, dep.Ecosystem+":"+dep.Path+"@"+dep.Version)
	}
	if len(reachable) > 12 {
		reachable = reachable[:12]
	}
	verdict.ReachableDeps = reachable

	for _, adv := range env.DependencyGraph.Vulnerabilities {
		verdict.MatchedAdvisories = append(verdict.MatchedAdvisories,
			adv.ID+" ("+adv.Package+"@"+adv.Version+", fix: "+adv.FixedIn+")")
	}

	if env.Codebase != nil && env.Codebase.MatchedRoute != nil {
		mr := env.Codebase.MatchedRoute
		verdict.MatchedHandler = mr.File + ":" + itoa(mr.Line)
	}

	lowerPath := strings.ToLower(env.Event.Path)
	lowerPayload := strings.ToLower(env.Event.PayloadPreview)
	combined := lowerPath + " " + lowerPayload

	switch {
	case strings.Contains(combined, "../") || strings.Contains(combined, "/etc/passwd") || strings.Contains(combined, "..\\"):
		verdict.Severity = "high"
		verdict.Action = "alert"
		verdict.Summary = "Path traversal attempt targeting process " + env.ServerProcess.Name + " (" + env.ServerProcess.Executable + ")"
		verdict.Recommendations = []string{
			"Verify filesystem mount isolation on " + env.OS.Hostname,
			"Audit file-serving handlers in module " + env.DependencyGraph.MainModule,
		}
	case strings.Contains(combined, "jndi:") || strings.Contains(combined, "select ") || strings.Contains(combined, "union ") || strings.Contains(combined, "<script"):
		verdict.Severity = "critical"
		verdict.Action = "flag-cve-reachability"
		verdict.Summary = "Injection payload detected on socket owned by PID " + itoa(env.ServerProcess.PID) + " (" + env.ServerProcess.Name + ")"
		verdict.Recommendations = []string{
			"Cross-check active dependency graph (" + itoa(len(env.DependencyGraph.Dependencies)) + " modules) for parser/query sinks",
			"Block source " + env.Event.SrcAddr + " at ingress firewall if anomalous",
		}
	case len(verdict.MatchedAdvisories) > 0:
		verdict.Severity = "high"
		verdict.Action = "flag-cve-reachability"
		verdict.Summary = "Traffic reached PID " + itoa(env.ServerProcess.PID) + " (" + env.ServerProcess.Name + ") with " + itoa(len(verdict.MatchedAdvisories)) + " vulnerable dependency advisories"
		verdict.Recommendations = []string{
			"Upgrade vulnerable dependencies exposed on " + env.Event.DstAddr,
		}
	case env.TriggerReason == "new-unseen-process-socket":
		verdict.Severity = "low"
		verdict.Action = "observe"
		verdict.Summary = "First mirrored flow mapped to PID " + itoa(env.ServerProcess.PID) + " (" + env.ServerProcess.Name + ") with " + itoa(len(env.DependencyGraph.Dependencies)) + " dependencies"
	}

	if verdict.MatchedHandler != "" {
		verdict.Summary += " [handler: " + verdict.MatchedHandler + "]"
	}

	// If severity is high/critical and the host offers reverse callbacks, actively
	// query the live ext.system graph AND inspect the relevant source file snippet.
	if (verdict.Severity == "high" || verdict.Severity == "critical") && engine.ReverseFrom(ctx) != nil {
		revCaller := engine.ReverseFrom(ctx)
		if revOut, err := author.Call(ctx, revCaller, ReverseQueryGraphMethod(), GraphQueryInput{
			Namespace: system.Namespace,
			Kind:      system.Namespace + "/process-resource",
			Limit:     64,
		}); err == nil {
			verdict.ReverseGraphQueried = true
			verdict.ReverseObservedNodes = revOut.VertexCount
		}

		var targetFile string
		var targetLine int
		if env.Codebase != nil {
			if env.Codebase.MatchedRoute != nil {
				targetFile = env.Codebase.MatchedRoute.File
				targetLine = env.Codebase.MatchedRoute.Line
			} else if len(env.Codebase.RelevantSinks) > 0 {
				targetFile = env.Codebase.RelevantSinks[0].File
				targetLine = env.Codebase.RelevantSinks[0].Line
			}
		}
		if targetFile != "" {
			start := targetLine - 3
			if start < 1 {
				start = 1
			}
			if srcOut, err := author.Call(ctx, revCaller, ReverseReadSourceMethod(), SourceReadInput{
				File:      targetFile,
				StartLine: start,
				EndLine:   targetLine + 6,
			}); err == nil && srcOut.Snippet != "" {
				verdict.InspectedSource = strings.TrimSpace(srcOut.Snippet)
				verdict.Recommendations = append(verdict.Recommendations,
					"Review source handler at "+targetFile+":"+itoa(targetLine))
			}
		}
	}

	return verdict, nil
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
