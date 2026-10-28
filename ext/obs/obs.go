// Package obs is Vigilante's observability plugin, authored as a genuine
// ext.plugin/v1 plugin (the same contract model as the triage agent). It
// declares three typed operations — summary, alerts, dashboard — on the
// vigilante.obs@v1 contract and runs behind an engine.Session. The host
// bridges incoming HTTP requests onto those session calls, so the dashboard
// and query API are served by a real ext plugin, not an ad-hoc handler.
//
// Alerts stay in the core JSONL alert store (obs reads it via alert.Reader);
// obs owns the query API, HTML dashboard, and per-severity metrics.
//
// This package lives under ext/ because it is an ext plugin, not core wiring.
package obs

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/webong/ext/pkg/ext-go/engine"
	"github.com/webong/ext/pkg/ext-go/engine/guest/author"
	"github.com/webong/ext/pkg/ext-go/engine/transport/inprocess"
	"github.com/webong/vigilante/internal/alert"
)

const (
	ContractName    = "vigilante.obs"
	ContractVersion = "v1"

	OpSummary   = "summary"
	OpAlerts    = "alerts"
	OpActions   = "actions"
	OpActors    = "actors"
	OpDashboard = "dashboard"
)

// SummaryInput is the (empty) filter for the summary operation.
type SummaryInput struct{}

// SummaryOutput is the aggregate observability view.
type SummaryOutput struct {
	AlertsBySeverity map[string]int `json:"alerts_by_severity"`
	Queue            QueueCounters  `json:"queue"`
	Stored           uint64         `json:"stored"`
	Delivered        uint64         `json:"delivered"`
	Failed           uint64         `json:"failed"`
}

// QueueCounters mirrors the mirror-queue stats.
type QueueCounters struct {
	Enqueued   uint64 `json:"enqueued"`
	Dropped    uint64 `json:"dropped"`
	SampledOut uint64 `json:"sampled_out"`
}

// AlertsInput filters the alerts operation.
type AlertsInput struct {
	Severity string `json:"severity,omitempty"` // minimum severity filter
	Limit    int    `json:"limit,omitempty"`    // newest-N (default 100, max 1000)
}

// AlertsOutput is a page of recent alerts, newest first.
type AlertsOutput struct {
	Count  int            `json:"count"`
	Alerts []alert.Record `json:"alerts"`
}

// ActionsInput is the (empty) filter for the actions operation.
type ActionsInput struct{}

// ActionParam mirrors one executor argument for generated UIs.
type ActionParam struct {
	Name     string `json:"name"`
	Label    string `json:"label,omitempty"`
	Type     string `json:"type,omitempty"`
	Required bool   `json:"required,omitempty"`
	Default  string `json:"default,omitempty"`
}

// ActionCapability is the read view of one registered action.
type ActionCapability struct {
	ID          string        `json:"id"`
	Label       string        `json:"label"`
	Description string        `json:"description,omitempty"`
	Scopes      []string      `json:"scopes"`
	DefaultTTL  time.Duration `json:"default_ttl,omitempty"`
	MaxTTL      time.Duration `json:"max_ttl,omitempty"`
	Reversible  bool          `json:"reversible"`
	Destructive bool          `json:"destructive,omitempty"`
	Params      []ActionParam `json:"params,omitempty"`
}

// ActiveDecision is the read view of a decision currently in force.
type ActiveDecision struct {
	ID      string    `json:"id"`
	Action  string    `json:"action"`
	Scope   string    `json:"scope"`
	Target  string    `json:"target"`
	Reason  string    `json:"reason,omitempty"`
	Actor   string    `json:"actor,omitempty"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires,omitempty"`
}

// ActionDecision is the read view of one audited decision.
type ActionDecision struct {
	ID        string    `json:"id"`
	Action    string    `json:"action"`
	Label     string    `json:"label,omitempty"`
	Scope     string    `json:"scope"`
	Target    string    `json:"target"`
	Actor     string    `json:"actor,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	Operator  string    `json:"operator,omitempty"`
	Status    string    `json:"status"`
	RevertRef string    `json:"revert_ref,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	StartedAt time.Time `json:"started_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// ActionsOutput is the action surface: what is available, what is in force, and
// what has been decided. It is data, not markup — consumers render it however
// they like.
type ActionsOutput struct {
	Capabilities []ActionCapability `json:"capabilities"`
	Active       []ActiveDecision   `json:"active"`
	Decisions    []ActionDecision   `json:"decisions"`
}

// ActorsInput filters the actors operation.
type ActorsInput struct {
	Suspicious bool `json:"suspicious,omitempty"` // only actors at/above the risk threshold
	Limit      int  `json:"limit,omitempty"`      // top-N by risk (default 100)
}

// Actor is the read view of one aggregated actor.
type Actor struct {
	Key         string         `json:"key"`
	IP          string         `json:"ip"`
	Fingerprint string         `json:"tls_fingerprint,omitempty"`
	UserAgent   string         `json:"user_agent,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	FirstSeen   time.Time      `json:"first_seen"`
	LastSeen    time.Time      `json:"last_seen"`
	Requests    int            `json:"requests"`
	BySeverity  map[string]int `json:"by_severity"`
	Verdicts    map[string]int `json:"verdicts"`
	LastVerdict string         `json:"last_verdict,omitempty"`
	LastSummary string         `json:"last_summary,omitempty"`
	Risk        int            `json:"risk"`
	Suspicious  bool           `json:"suspicious"`
}

// ActorsOutput is the actor surface: who is doing what, ordered by risk.
type ActorsOutput struct {
	Count      int     `json:"count"`
	Suspicious int     `json:"suspicious"`
	Actors     []Actor `json:"actors"`
}

// DashboardInput is unused; present for contract completeness.
type DashboardInput struct{}

// DashboardOutput carries the rendered HTML.
type DashboardOutput struct {
	HTML string `json:"html"`
}

// Identity returns the pinned ext.plugin/v1 identity for the obs plugin.
func Identity() engine.Identity {
	return engine.Identity{ID: "vigilante/obs", Revision: "v1.0.0", Version: "1.0.0"}
}

// SummaryMethod returns the typed ext.plugin/v1 method for the summary op.
func SummaryMethod() author.Method[SummaryInput, SummaryOutput] {
	return author.Method[SummaryInput, SummaryOutput]{
		Contract:  engine.ContractRef{Name: ContractName, Version: ContractVersion},
		Operation: engine.Operation{Name: OpSummary, Surface: "observation"},
	}
}

// AlertsMethod returns the typed ext.plugin/v1 method for the alerts op.
func AlertsMethod() author.Method[AlertsInput, AlertsOutput] {
	return author.Method[AlertsInput, AlertsOutput]{
		Contract:  engine.ContractRef{Name: ContractName, Version: ContractVersion},
		Operation: engine.Operation{Name: OpAlerts, Surface: "observation"},
	}
}

// ActionsMethod returns the typed ext.plugin/v1 method for the actions op.
func ActionsMethod() author.Method[ActionsInput, ActionsOutput] {
	return author.Method[ActionsInput, ActionsOutput]{
		Contract:  engine.ContractRef{Name: ContractName, Version: ContractVersion},
		Operation: engine.Operation{Name: OpActions, Surface: "observation"},
	}
}

// ActorsMethod returns the typed ext.plugin/v1 method for the actors op.
func ActorsMethod() author.Method[ActorsInput, ActorsOutput] {
	return author.Method[ActorsInput, ActorsOutput]{
		Contract:  engine.ContractRef{Name: ContractName, Version: ContractVersion},
		Operation: engine.Operation{Name: OpActors, Surface: "observation"},
	}
}

// DashboardMethod returns the typed ext.plugin/v1 method for the dashboard op.
func DashboardMethod() author.Method[DashboardInput, DashboardOutput] {
	return author.Method[DashboardInput, DashboardOutput]{
		Contract:  engine.ContractRef{Name: ContractName, Version: ContractVersion},
		Operation: engine.Operation{Name: OpDashboard, Surface: "observation"},
	}
}

// Service implements the observation operations. It reads from the core alert
// store and an optional action view and never writes to either.
type Service struct {
	reader     alert.Reader
	stats      func() QueueCounters
	storeStats func() (stored, delivered, failed uint64)
	actions    func() ActionsOutput
	actors     func(ActorsInput) ActorsOutput
}

// NewService wires the obs service to an alert reader and optional counters.
func NewService(reader alert.Reader, stats func() QueueCounters, storeStats func() (uint64, uint64, uint64)) *Service {
	return &Service{reader: reader, stats: stats, storeStats: storeStats}
}

// SetActions attaches the action read view (capabilities + decisions). It is
// optional: without it the actions operation returns empty lists.
func (s *Service) SetActions(view func() ActionsOutput) {
	if s != nil {
		s.actions = view
	}
}

// SetActors attaches the actor read view. Optional; without it the actors
// operation returns empty lists.
func (s *Service) SetActors(view func(ActorsInput) ActorsOutput) {
	if s != nil {
		s.actors = view
	}
}

// Summary implements OpSummary.
func (s *Service) Summary(_ context.Context, _ engine.Request, _ SummaryInput) (SummaryOutput, error) {
	out := SummaryOutput{AlertsBySeverity: map[string]int{}}
	if s.reader != nil {
		for sev, n := range s.reader.CountBySeverity() {
			out.AlertsBySeverity[string(sev)] = n
		}
	}
	if s.stats != nil {
		out.Queue = s.stats()
	}
	if s.storeStats != nil {
		out.Stored, out.Delivered, out.Failed = s.storeStats()
	}
	return out, nil
}

// Alerts implements OpAlerts.
func (s *Service) Alerts(_ context.Context, _ engine.Request, in AlertsInput) (AlertsOutput, error) {
	limit := in.Limit
	if limit <= 0 {
		limit = 100
	}
	var recs []alert.Record
	var err error
	if s.reader != nil {
		recs, err = s.reader.Recent(alert.Severity(strings.ToLower(in.Severity)), limit)
	}
	if err != nil {
		return AlertsOutput{}, err
	}
	if recs == nil {
		recs = []alert.Record{}
	}
	return AlertsOutput{Count: len(recs), Alerts: recs}, nil
}

// Actions implements OpActions. It returns the action read view, or empty
// lists when no action view is attached.
func (s *Service) Actions(_ context.Context, _ engine.Request, _ ActionsInput) (ActionsOutput, error) {
	var out ActionsOutput
	if s != nil && s.actions != nil {
		out = s.actions()
	}
	if out.Capabilities == nil {
		out.Capabilities = []ActionCapability{}
	}
	if out.Active == nil {
		out.Active = []ActiveDecision{}
	}
	if out.Decisions == nil {
		out.Decisions = []ActionDecision{}
	}
	return out, nil
}

// Actors implements OpActors. It returns the actor read view, or empty lists
// when no actor view is attached.
func (s *Service) Actors(_ context.Context, _ engine.Request, in ActorsInput) (ActorsOutput, error) {
	var out ActorsOutput
	if s != nil && s.actors != nil {
		out = s.actors(in)
	}
	if out.Actors == nil {
		out.Actors = []Actor{}
	}
	return out, nil
}

// Dashboard implements OpDashboard.
func (s *Service) Dashboard(_ context.Context, _ engine.Request, _ DashboardInput) (DashboardOutput, error) {
	return DashboardOutput{HTML: s.renderDashboard()}, nil
}

// BuildGuest constructs the ext.plugin/v1 Guest for the obs plugin: it
// registers the typed operations on a Descriptor and returns the guest plus
// descriptor, ready to back an in-process engine session (or be served over
// jsonline as an out-of-process plugin).
func BuildGuest(svc *Service) (engine.Descriptor, *engine.Guest, error) {
	if svc == nil {
		return engine.Descriptor{}, nil, fmt.Errorf("obs: service is required")
	}
	reg, err := author.New(Identity())
	if err != nil {
		return engine.Descriptor{}, nil, err
	}
	if err := author.Register(reg, SummaryMethod(), svc.Summary); err != nil {
		return engine.Descriptor{}, nil, err
	}
	if err := author.Register(reg, AlertsMethod(), svc.Alerts); err != nil {
		return engine.Descriptor{}, nil, err
	}
	if err := author.Register(reg, ActionsMethod(), svc.Actions); err != nil {
		return engine.Descriptor{}, nil, err
	}
	if err := author.Register(reg, ActorsMethod(), svc.Actors); err != nil {
		return engine.Descriptor{}, nil, err
	}
	if err := author.Register(reg, DashboardMethod(), svc.Dashboard); err != nil {
		return engine.Descriptor{}, nil, err
	}
	desc, opts, err := reg.Snapshot(author.Options{
		Authorize:       func(context.Context, engine.Request) error { return nil },
		MaxCallDuration: 10 * time.Second,
	})
	if err != nil {
		return engine.Descriptor{}, nil, err
	}
	guest, err := engine.NewGuest(desc, opts)
	if err != nil {
		return engine.Descriptor{}, nil, err
	}
	return desc, guest, nil
}

// renderDashboard builds the self-contained HTML status page.
func (s *Service) renderDashboard() string {
	var rows, counts strings.Builder
	if s.reader != nil {
		bySev := s.reader.CountBySeverity()
		for _, sev := range []alert.Severity{alert.SeverityCritical, alert.SeverityHigh, alert.SeverityMedium, alert.SeverityLow, alert.SeverityInfo} {
			if n := bySev[sev]; n > 0 {
				fmt.Fprintf(&counts, "<span class='pill sev %s'>%s %d</span>", sev, sev, n)
			}
		}
		if recs, err := s.reader.Recent("", 50); err == nil {
			for _, rec := range recs {
				ts := rec.Timestamp
				if ts.IsZero() {
					ts = time.Now()
				}
				fmt.Fprintf(&rows,
					"<tr><td class='sev %s'>%s</td><td>%s</td><td class='m'>%s</td><td>%s</td><td class='t'>%s</td></tr>",
					esc(string(rec.Severity)), esc(string(rec.Severity)),
					esc(rec.Action), esc(rec.Method+" "+rec.Path),
					esc(rec.SrcAddr), esc(ts.Format("15:04:05")))
			}
		}
	}
	if rows.Len() == 0 {
		rows.WriteString("<tr><td colspan='5' class='empty'>no alerts yet</td></tr>")
	}
	return fmt.Sprintf(dashboardHTML, counts.String(), rows.String())
}

// Bridge exposes the obs plugin over HTTP by dispatching requests onto a live
// engine.Session running the obs plugin. This is the host-side seam: it maps
// HTTP paths to the plugin's typed operations rather than reimplementing
// them, so the dashboard and API genuinely execute the ext plugin.
//
// Mounted surface (relative to wherever the host mounts it):
//
//	"" | summary   -> session call obs summary
//	alerts         -> session call obs alerts (?severity=&limit=)
//	dashboard      -> session call obs dashboard (HTML)
type Bridge struct {
	session *engine.Session
}

// NewBridge wraps an engine session running the obs plugin.
func NewBridge(session *engine.Session) *Bridge { return &Bridge{session: session} }

// Open builds the obs ext guest, opens an in-process engine session to it, and
// returns the session plus an HTTP bridge that dispatches onto it. This is the
// host's one-call entrypoint: call Close when shutting down.
func Open(ctx context.Context, svc *Service) (*engine.Session, *Bridge, func(context.Context) error, error) {
	desc, guest, err := BuildGuest(svc)
	if err != nil {
		return nil, nil, nil, err
	}
	backend, err := inprocess.New(guest)
	if err != nil {
		return nil, nil, nil, err
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
	})
	if err != nil {
		_ = backend.Close()
		return nil, nil, nil, err
	}
	closeFn := func(ctx context.Context) error {
		err := session.Close(ctx)
		if cErr := backend.Close(); err == nil {
			err = cErr
		}
		return err
	}
	return session, NewBridge(session), closeFn, nil
}

// ServeHTTP routes to the appropriate plugin operation.
func (b *Bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/"), "/")
	switch {
	case path == "" || path == "summary" || path == "dashboard" && r.URL.Query().Get("format") == "json":
		out, err := author.Call(ctx, b.session, SummaryMethod(), SummaryInput{})
		writeJSON(w, out, err)
	case path == "alerts":
		in := AlertsInput{Severity: strings.ToLower(r.URL.Query().Get("severity"))}
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				in.Limit = n
			}
		}
		out, err := author.Call(ctx, b.session, AlertsMethod(), in)
		writeJSON(w, out, err)
	case path == "actions":
		out, err := author.Call(ctx, b.session, ActionsMethod(), ActionsInput{})
		writeJSON(w, out, err)
	case path == "actors":
		in := ActorsInput{Suspicious: r.URL.Query().Get("suspicious") == "true" || r.URL.Query().Get("suspicious") == "1"}
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				in.Limit = n
			}
		}
		out, err := author.Call(ctx, b.session, ActorsMethod(), in)
		writeJSON(w, out, err)
	case path == "dashboard":
		out, err := author.Call(ctx, b.session, DashboardMethod(), DashboardInput{})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(out.HTML))
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

const dashboardHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Vigilante</title>
<style>
:root{--bg:#0e1116;--fg:#e6edf3;--mut:#8b949e;--card:#161b22;--line:#30363d}
*{box-sizing:border-box}
body{margin:0;font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
header{padding:16px 20px;border-bottom:1px solid var(--line);display:flex;gap:12px;align-items:center}
h1{font-size:16px;margin:0;font-weight:600}
main{padding:20px}
.pill{padding:3px 9px;border-radius:999px;font-size:12px;background:var(--card);border:1px solid var(--line);margin-right:6px}
.sev.critical{color:#ff7b72}.sev.high{color:#ffa657}.sev.medium{color:#e3b341}.sev.low{color:#7ee787}.sev.info{color:#79c0ff}
table{width:100%%;border-collapse:collapse;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:8px 12px;border-bottom:1px solid var(--line);font-size:13px}
th{color:var(--mut);font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.05em}
td.m{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
td.t{color:var(--mut)}
.empty{color:var(--mut);text-align:center;padding:24px}
a{color:#58a6ff}
</style></head><body>
<header><h1>Vigilante</h1><div>%s</div>
<div style="margin-left:auto"><a href="alerts">alerts</a> · <a href="summary">summary</a> · <a href="/metrics">metrics</a></div></header>
<main>
<table><thead><tr><th>Severity</th><th>Action</th><th>Request</th><th>Source</th><th>Time</th></tr></thead>
<tbody>%s</tbody></table>
</main></body></html>`

func esc(s string) string { return html.EscapeString(s) }
