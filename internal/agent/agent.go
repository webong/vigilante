// Package agent implements the typed ext.plugin/v1 contract and gateway for
// dispatching mirrored network flows enriched with OS, server, and application
// dependency graphs to a security/triage agent.
package agent

import (
	"context"
	"strings"
	"time"

	"github.com/webong/ext/pkg/ext-go/engine"
	"github.com/webong/ext/pkg/ext-go/engine/guest/author"
	"github.com/webong/ext/pkg/ext-go/engine/transport/inprocess"
	"github.com/webong/ext/res/system"
	"github.com/webong/ext/res/system/network"
	"github.com/webong/vigilante/internal/deps"
)

const (
	ContractName    = "vigilante.agent"
	ContractVersion = "v1"
	OperationTriage = "triage-flow"
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
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	ShellCount  int    `json:"shell_count"`
	MountCount  int    `json:"mount_count"`
	ProcessCount int   `json:"process_count"`
}

// ServerProcessContext summarizes the owning server process discovered via
// system.InspectProcess.
type ServerProcessContext struct {
	PID          int      `json:"pid"`
	ParentPID    int      `json:"parent_pid"`
	Name         string   `json:"name"`
	Executable   string   `json:"executable"`
	StartID      string   `json:"start_id"`
	Owner        string   `json:"owner,omitempty"`
	OpenSockets  []string `json:"open_sockets,omitempty"`
	MappedLibs   []string `json:"mapped_libs,omitempty"`
}

// EnrichedEnvelope bundles the mirrored packet with the live OS, Server,
// Network Topology, and Application Dependency Graph.
type EnrichedEnvelope struct {
	Event            PacketEvent          `json:"event"`
	TriggerReason    string               `json:"trigger_reason"`
	OS               OSContext            `json:"os"`
	ServerProcess    ServerProcessContext `json:"server_process"`
	NetworkTopology  network.Snapshot     `json:"network_topology"`
	DependencyGraph  deps.Graph           `json:"dependency_graph"`
	GraphRevision    uint64               `json:"graph_revision"`
}

// Verdict is returned by the agent after analyzing the EnrichedEnvelope.
type Verdict struct {
	FlowID          string   `json:"flow_id"`
	Severity        string   `json:"severity"` // "info", "low", "medium", "high", "critical"
	Action          string   `json:"action"`   // "observe", "alert", "flag-cve-reachability", "recommend-block"
	Summary         string   `json:"summary"`
	ReachableDeps   []string `json:"reachable_deps,omitempty"`
	Recommendations []string `json:"recommendations,omitempty"`
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

// Handler is the function signature for an agent evaluating an EnrichedEnvelope.
type Handler func(context.Context, EnrichedEnvelope) (Verdict, error)

// Gateway manages a verified ext.plugin/v1 session to a local or remote agent.
type Gateway struct {
	session *engine.Session
	method  author.Method[EnrichedEnvelope, Verdict]
}

// NewInProcessGateway constructs an in-process ext.plugin/v1 guest and opens a
// verified host session to it. If handler is nil, DefaultBuiltInHandler is used.
func NewInProcessGateway(ctx context.Context, handler Handler) (*Gateway, error) {
	if handler == nil {
		handler = DefaultBuiltInHandler
	}
	id := engine.Identity{
		ID:       "vigilante/builtin-secops-agent",
		Revision: "v1.0.0",
		Version:  "1.0.0",
	}
	reg, err := author.New(id)
	if err != nil {
		return nil, err
	}
	method := TriageMethod()
	if err := author.Register(reg, method, func(ctx context.Context, _ engine.Request, env EnrichedEnvelope) (Verdict, error) {
		return handler(ctx, env)
	}); err != nil {
		return nil, err
	}

	allow := func(context.Context, engine.Request) error { return nil }
	guest, err := reg.Guest(author.Options{
		Authorize:       allow,
		MaxCallDuration: 15 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	backend, err := inprocess.New(guest)
	if err != nil {
		return nil, err
	}

	desc := reg.Descriptor()
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
	})
	if err != nil {
		_ = backend.Close()
		return nil, err
	}

	return &Gateway{
		session: session,
		method:  method,
	}, nil
}

// NewSessionGateway wraps an existing engine.Session (such as a jsonline or
// HashiCorp gRPC subprocess supervised by res/system/supervisor).
func NewSessionGateway(session *engine.Session) *Gateway {
	return &Gateway{
		session: session,
		method:  TriageMethod(),
	}
}

// Triage dispatches the enriched packet + system dependency graph to the agent.
func (g *Gateway) Triage(ctx context.Context, env EnrichedEnvelope) (Verdict, error) {
	return author.Call(ctx, g.session, g.method, env)
}

// Close gracefully drains and closes the underlying plugin session.
func (g *Gateway) Close(ctx context.Context) error {
	if g == nil || g.session == nil {
		return nil
	}
	return g.session.Close(ctx)
}

// DefaultBuiltInHandler correlates packet payloads and HTTP paths against the
// server process identity, open sockets, and loaded module dependency graph.
func DefaultBuiltInHandler(_ context.Context, env EnrichedEnvelope) (Verdict, error) {
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
	case env.TriggerReason == "new-unseen-process-socket":
		verdict.Severity = "low"
		verdict.Action = "observe"
		verdict.Summary = "First mirrored flow mapped to PID " + itoa(env.ServerProcess.PID) + " (" + env.ServerProcess.Name + ") with " + itoa(len(env.DependencyGraph.Dependencies)) + " dependencies"
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

// Ensure unused import check for system is satisfied via type reference if needed.
var _ = system.Namespace
