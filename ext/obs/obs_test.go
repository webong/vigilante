package obs

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/webong/ext/pkg/ext-go/engine"
	"github.com/webong/vigilante/internal/alert"
)

// newTestStore writes a couple of alerts and returns a Store satisfying Reader.
func newTestStore(t *testing.T) *alert.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	s, err := alert.Open(alert.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	s.Record(alert.Record{FlowID: "f1", Severity: alert.SeverityCritical, Action: "recommend-block", Method: "GET", Path: "/admin"})
	s.Record(alert.Record{FlowID: "f2", Severity: alert.SeverityHigh, Action: "alert", Method: "POST", Path: "/login"})
	s.Record(alert.Record{FlowID: "f3", Severity: alert.SeverityInfo, Action: "observe", Method: "GET", Path: "/health"})
	return s
}

// TestActionsWithView verifies the action view maps through the operation.
func TestActionsWithView(t *testing.T) {
	svc := NewService(nil, nil, nil)
	svc.SetActions(func() ActionsOutput {
		return ActionsOutput{
			Capabilities: []ActionCapability{{ID: "block", Label: "Block", Scopes: []string{"ip"}, Reversible: true}},
			Active:       []ActiveDecision{{ID: "d1", Action: "block", Scope: "ip", Target: "203.0.113.9"}},
			Decisions:    []ActionDecision{{ID: "d1", Action: "block", Status: "applied"}},
		}
	})
	out, err := svc.Actions(context.Background(), engine.Request{}, ActionsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Capabilities) != 1 || out.Capabilities[0].ID != "block" {
		t.Fatalf("capabilities = %+v", out.Capabilities)
	}
	if len(out.Active) != 1 || out.Active[0].Target != "203.0.113.9" {
		t.Fatalf("active = %+v", out.Active)
	}
	if len(out.Decisions) != 1 || out.Decisions[0].Status != "applied" {
		t.Fatalf("decisions = %+v", out.Decisions)
	}
}

// TestActionsWithoutViewReturnsEmpty verifies a nil view yields empty arrays.
func TestActionsWithoutViewReturnsEmpty(t *testing.T) {
	out, err := NewService(nil, nil, nil).Actions(context.Background(), engine.Request{}, ActionsInput{})
	if err != nil {
		t.Fatal(err)
	}
	if out.Capabilities == nil || out.Active == nil || out.Decisions == nil {
		t.Fatal("expected non-nil empty slices")
	}
}

// TestActorsWithView verifies the actor view maps through the operation and its
// input filter is passed along.
func TestActorsWithView(t *testing.T) {
	svc := NewService(nil, nil, nil)
	var got ActorsInput
	svc.SetActors(func(in ActorsInput) ActorsOutput {
		got = in
		return ActorsOutput{
			Count:      1,
			Suspicious: 1,
			Actors:     []Actor{{Key: "203.0.113.9", Risk: 60, Suspicious: true}},
		}
	})
	out, err := svc.Actors(context.Background(), engine.Request{}, ActorsInput{Suspicious: true, Limit: 7})
	if err != nil {
		t.Fatal(err)
	}
	if !got.Suspicious || got.Limit != 7 {
		t.Fatalf("filter not passed: %+v", got)
	}
	if len(out.Actors) != 1 || out.Actors[0].Key != "203.0.113.9" {
		t.Fatalf("actors = %+v", out.Actors)
	}
}

// TestExtPluginEndToEnd runs the whole path: Service -> BuildGuest -> engine
// session -> HTTP bridge -> typed operation round-trip.
func TestExtPluginEndToEnd(t *testing.T) {
	store := newTestStore(t)
	svc := NewService(store, func() QueueCounters {
		return QueueCounters{Enqueued: 42, Dropped: 1, SampledOut: 7}
	}, func() (uint64, uint64, uint64) { return store.Stats() })

	ctx := context.Background()
	_, bridge, closeFn, err := Open(ctx, svc)
	if err != nil {
		t.Fatalf("Open ext plugin: %v", err)
	}
	defer func() { _ = closeFn(ctx) }()

	t.Run("dashboard HTML via session", func(t *testing.T) {
		rr := httptest.NewRecorder()
		bridge.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/dashboard", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d", rr.Code)
		}
		body := rr.Body.String()
		if !strings.Contains(body, "<!doctype html>") || !strings.Contains(body, "critical") {
			t.Fatalf("dashboard HTML missing content: %.200s", body)
		}
	})

	t.Run("alerts JSON via session", func(t *testing.T) {
		rr := httptest.NewRecorder()
		bridge.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/alerts?limit=10", nil))
		var out AlertsOutput
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, rr.Body.String())
		}
		if out.Count != 3 || len(out.Alerts) != 3 {
			t.Fatalf("count = %d, want 3", out.Count)
		}
		// Newest first: f3 (info) recorded last.
		if out.Alerts[0].FlowID != "f3" {
			t.Fatalf("newest first violated: first = %s", out.Alerts[0].FlowID)
		}
	})

	t.Run("alerts severity filter via session", func(t *testing.T) {
		rr := httptest.NewRecorder()
		bridge.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/alerts?severity=high", nil))
		var out AlertsOutput
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.Count != 2 {
			t.Fatalf("severity>=high count = %d, want 2", out.Count)
		}
	})

	t.Run("summary via session", func(t *testing.T) {
		rr := httptest.NewRecorder()
		bridge.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/summary", nil))
		var out SummaryOutput
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, rr.Body.String())
		}
		if out.AlertsBySeverity["critical"] != 1 || out.AlertsBySeverity["high"] != 1 {
			t.Fatalf("severity counts = %v", out.AlertsBySeverity)
		}
		if out.Queue.Enqueued != 42 || out.Queue.Dropped != 1 {
			t.Fatalf("queue counters = %+v", out.Queue)
		}
	})

	t.Run("actions via session", func(t *testing.T) {
		rr := httptest.NewRecorder()
		bridge.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/actions", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d", rr.Code)
		}
		var out ActionsOutput
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, rr.Body.String())
		}
		// No action view attached: the operation must return empty lists, not
		// null, so a client can iterate without nil-checks.
		if out.Capabilities == nil || out.Active == nil || out.Decisions == nil {
			t.Fatalf("expected empty arrays, got nil: %+v", out)
		}
	})

	t.Run("actors via session", func(t *testing.T) {
		rr := httptest.NewRecorder()
		bridge.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/actors?limit=5", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("status = %d", rr.Code)
		}
		var out ActorsOutput
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, rr.Body.String())
		}
		if out.Actors == nil {
			t.Fatal("expected empty actors array, not null")
		}
	})

	t.Run("unknown path 404", func(t *testing.T) {
		rr := httptest.NewRecorder()
		bridge.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/nope", nil))
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rr.Code)
		}
	})
	_ = io.Discard
}

// TestBuildGuestDescriptor checks the ext Descriptor advertises the obs contract.
func TestBuildGuestDescriptor(t *testing.T) {
	desc, _, err := BuildGuest(NewService(nil, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if desc.Identity.ID != "vigilante/obs" {
		t.Fatalf("identity = %q", desc.Identity.ID)
	}
	found := false
	for _, c := range desc.Contracts {
		if c.Name == ContractName && c.Version == ContractVersion {
			if len(c.Operations) != 5 {
				t.Fatalf("ops = %d, want 5", len(c.Operations))
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("contract %s@%s not in descriptor", ContractName, ContractVersion)
	}
}
