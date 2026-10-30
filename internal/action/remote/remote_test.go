package remote

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/webong/vigilante/internal/action"
	"github.com/webong/vigilante/internal/decision"
)

type recorded struct {
	method string
	path   string
	body   []byte
	auth   string
}

type recorder struct {
	mu   sync.Mutex
	reqs []recorded
}

func (r *recorder) handler(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.reqs = append(r.reqs, recorded{
		method: req.Method,
		path:   req.URL.Path,
		body:   body,
		auth:   req.Header.Get("Authorization"),
	})
	r.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"id":"waf-rule-42"}`))
}

func (r *recorder) snapshot() []recorded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recorded(nil), r.reqs...)
}

func TestExecuteCallsRemoteAndCapturesHandle(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(rec.handler))
	defer srv.Close()

	ex, err := New(Options{
		ID:      "notify",
		URL:     srv.URL + "/zones/{target}/rules",
		Headers: map[string]string{"Authorization": "Bearer secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := ex.Execute(context.Background(), action.Request{
		Action: "notify",
		Scope:  decision.ScopeIP,
		Target: "203.0.113.9",
		Reason: "agent verdict",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.RevertRef != "waf-rule-42" {
		t.Fatalf("revert ref = %q, want the remote id", res.RevertRef)
	}
	reqs := rec.snapshot()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d, want 1", len(reqs))
	}
	if reqs[0].path != "/zones/203.0.113.9/rules" {
		t.Fatalf("path = %q, want the substituted target", reqs[0].path)
	}
	if reqs[0].auth != "Bearer secret" {
		t.Fatalf("auth = %q", reqs[0].auth)
	}
	var payload map[string]any
	if err := json.Unmarshal(reqs[0].body, &payload); err != nil {
		t.Fatalf("body is not JSON: %v (%s)", err, reqs[0].body)
	}
	if payload["target"] != "203.0.113.9" {
		t.Fatalf("payload target = %v", payload["target"])
	}
}

func TestExecuteUsesBodyTemplate(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(rec.handler))
	defer srv.Close()

	ex, err := New(Options{
		ID:           "notify",
		URL:          srv.URL + "/rules",
		BodyTemplate: `{"mode":"block","target":"{target}","note":"{reason}"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ex.Execute(context.Background(), action.Request{Target: "203.0.113.9", Reason: "scanner"}); err != nil {
		t.Fatal(err)
	}
	got := string(rec.snapshot()[0].body)
	if got != `{"mode":"block","target":"203.0.113.9","note":"scanner"}` {
		t.Fatalf("body = %s", got)
	}
}

func TestDryRunMakesNoRequest(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(rec.handler))
	defer srv.Close()

	ex, err := New(Options{ID: "notify", URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	res, err := ex.Execute(context.Background(), action.Request{Target: "203.0.113.9", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Detail == "" {
		t.Fatal("dry run should describe the call")
	}
	if len(rec.snapshot()) != 0 {
		t.Fatal("dry run must not reach the remote")
	}
}

func TestRevertCallsRevertURLWithRef(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewServer(http.HandlerFunc(rec.handler))
	defer srv.Close()

	ex, err := New(Options{ID: "notify", URL: srv.URL + "/rules", RevertURL: srv.URL + "/rules/{ref}"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ex.Revert(context.Background(), action.Decision{
		Action:    "notify",
		Target:    "203.0.113.9",
		RevertRef: "waf-rule-42",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	reqs := rec.snapshot()
	if len(reqs) != 1 || reqs[0].method != http.MethodDelete {
		t.Fatalf("requests = %+v, want one DELETE", reqs)
	}
	if reqs[0].path != "/rules/waf-rule-42" {
		t.Fatalf("revert path = %q", reqs[0].path)
	}
}

func TestNon2xxIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusForbidden)
	}))
	defer srv.Close()

	ex, err := New(Options{ID: "notify", URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ex.Execute(context.Background(), action.Request{Target: "203.0.113.9"}); err == nil {
		t.Fatal("a 403 should surface as an error")
	}
}

func TestValidationAndCapability(t *testing.T) {
	if _, err := New(Options{ID: "x"}); err == nil {
		t.Fatal("url is required")
	}
	if _, err := New(Options{URL: "http://example.test"}); err == nil {
		t.Fatal("id is required")
	}

	ex, err := New(Options{
		ID:         "notify",
		URL:        "http://example.test",
		RevertURL:  "http://example.test/{ref}",
		DefaultTTL: time.Hour,
		Scopes:     []decision.Scope{decision.ScopeIP, decision.ScopeActor},
	})
	if err != nil {
		t.Fatal(err)
	}
	cap := ex.Capability()
	if !cap.Reversible || cap.ID != "notify" || cap.Label != "notify" {
		t.Fatalf("unexpected capability: %+v", cap)
	}
	if !cap.SupportsScope(decision.ScopeActor) || cap.SupportsScope(decision.ScopeGlobal) {
		t.Fatal("scope set should be honored")
	}
}
