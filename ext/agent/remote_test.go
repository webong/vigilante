package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/webong/vigilante/internal/deps"
)

func TestRemoteHandlerReceivesSelfContainedEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer test-token" || r.Header.Get("X-Vigilante-Contract") != "vigilante.agent/v1" {
			t.Errorf("unexpected request: method=%s auth=%q contract=%q", r.Method, r.Header.Get("Authorization"), r.Header.Get("X-Vigilante-Contract"))
		}
		var env EnrichedEnvelope
		if err := json.NewDecoder(r.Body).Decode(&env); err != nil {
			t.Error(err)
		}
		if env.Event.FlowID != "f1" || env.ServerProcess.PID != 42 || len(env.Codebase.SourceExcerpts) != 1 || len(env.AdvisoryResearch.Candidates) != 1 {
			t.Errorf("incomplete envelope: %+v", env)
		}
		_, _ = w.Write([]byte(`{"flow_id":"f1","severity":"high","action":"review-route","summary":"needs review","findings":[{"subject":"handler","claim":"exposed","evidence":["route maps to source"]}]}`))
	}))
	defer server.Close()
	handler, err := NewRemoteHandler(RemoteOptions{URL: server.URL, Token: "test-token"})
	if err != nil {
		t.Fatal(err)
	}
	env := EnrichedEnvelope{
		Event: PacketEvent{FlowID: "f1"}, ServerProcess: ServerProcessContext{PID: 42},
		Codebase:         &CodebaseContext{SourceExcerpts: []SourceExcerpt{{File: "server.go", StartLine: 12, Text: "func handler()"}}},
		AdvisoryResearch: &AdvisoryResearch{Status: "ready", Candidates: []AdvisoryCandidate{{Package: "example", Version: "1.0.0", Advisories: []deps.OSVAdvisory{{ID: "TEST-1"}}}}},
	}
	v, err := handler(context.Background(), env)
	if err != nil || v.Action != "review-route" || len(v.Findings) != 1 {
		t.Fatalf("remote verdict: %+v, %v", v, err)
	}
}

func TestRemoteHandlerRejectsInsecureAndMismatchedResponses(t *testing.T) {
	if _, err := NewRemoteHandler(RemoteOptions{URL: "http://example.com/triage"}); err == nil {
		t.Fatal("non-loopback HTTP should be rejected")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"flow_id":"other","severity":"high","action":"alert","summary":"wrong flow"}`))
	}))
	defer server.Close()
	handler, err := NewRemoteHandler(RemoteOptions{URL: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler(context.Background(), EnrichedEnvelope{Event: PacketEvent{FlowID: "f1"}}); err == nil {
		t.Fatal("mismatched flow response should be rejected")
	}
}

func TestRemoteHandlerDoesNotForwardContextThroughRedirect(t *testing.T) {
	var forwarded atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded.Store(true) }))
	defer destination.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	handler, err := NewRemoteHandler(RemoteOptions{URL: source.URL})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := handler(context.Background(), EnrichedEnvelope{Event: PacketEvent{FlowID: "f1"}}); err == nil || forwarded.Load() {
		t.Fatalf("redirect followed or accepted: forwarded=%v err=%v", forwarded.Load(), err)
	}
}

func TestRemoteHandlerAcceptsDeliveryWithoutVerdict(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
	}{
		{http.StatusAccepted, `{"job_id":"queued-1"}`},
		{http.StatusNoContent, ""},
		{http.StatusOK, ""},
		{http.StatusOK, `{"status":"stored"}`},
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		handler, err := NewRemoteHandler(RemoteOptions{URL: server.URL})
		if err != nil {
			t.Fatal(err)
		}
		v, err := handler(context.Background(), EnrichedEnvelope{Event: PacketEvent{FlowID: "f1"}})
		server.Close()
		if err != nil || v.Severity != "" || v.Action != "" || v.Summary != "" {
			t.Fatalf("status %d body %q: verdict=%+v err=%v", tc.status, tc.body, v, err)
		}
	}
}
