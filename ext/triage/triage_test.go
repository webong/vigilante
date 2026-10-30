package triage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/webong/vigilante/internal/flow"
	"github.com/webong/vigilante/internal/history"
	"github.com/webong/vigilante/internal/identity"
)

type fakeProvider struct {
	text  string
	model string
	err   error
}

func (f *fakeProvider) Complete(ctx context.Context, system, user string, schema json.RawMessage) (string, string, error) {
	return f.text, f.model, f.err
}

func TestTriageParsesVerdictAndClampsBounds(t *testing.T) {
	f := &fakeProvider{
		text:  `{"classification":"ai_agent","risk":150,"confidence":1.5,"summary":"suspicious","evidence":["asks markdown"],"recommended_action":"challenge","scope":"ip","ttl_minutes":99999}`,
		model: "openrouter/auto",
	}
	tg := New(f, "openrouter/auto")

	in := Input{
		IP:             "203.0.113.10",
		TLSFingerprint: "t13d1516h2",
		Rules:          RuleResult{Score: 60, Class: "automation", Signals: []RuleSignal{{Code: "accepts_markdown", Weight: 15, Detail: "asks for markdown"}}},
		Requests: []Request{
			{Timestamp: time.Now().UTC(), Method: "GET", Path: "/", Status: 200, DurationMS: 1000},
		},
	}
	v, err := tg.Triage(context.Background(), in)
	if err != nil {
		t.Fatalf("triage: %v", err)
	}
	if v.Classification != "ai_agent" {
		t.Errorf("classification=%q", v.Classification)
	}
	if v.Risk != 100 {
		t.Errorf("risk=%d (want clamped 100)", v.Risk)
	}
	if v.Confidence != 1 {
		t.Errorf("confidence=%g (want clamped 1)", v.Confidence)
	}
	if v.TTLMinutes != 10080 {
		t.Errorf("ttl_minutes=%d (want clamped 10080)", v.TTLMinutes)
	}
	if v.Model != "openrouter/auto" {
		t.Errorf("model=%q", v.Model)
	}
}

func TestTriagePropagatesProviderError(t *testing.T) {
	f := &fakeProvider{err: errors.New("upstream down")}
	tg := New(f, "m")
	_, err := tg.Triage(context.Background(), Input{})
	if err == nil || err.Error() != "upstream down" {
		t.Errorf("expected provider error, got %v", err)
	}
}

func TestRenderContainsActorFields(t *testing.T) {
	in := Input{
		IP:       "203.0.113.10",
		Identity: Identity{Verified: "Googlebot"},
		Rules:    RuleResult{Score: 40, Class: "crawler"},
		Requests: []Request{
			{Timestamp: time.Now().UTC(), Method: "GET", Path: "/index.html", Status: 200, UserAgent: "Mozilla/5.0", Headers: map[string]string{"Accept": "text/html", "Sec-Fetch-Mode": "navigate"}},
		},
		TotalRequests: 500,
	}
	payload, err := render(in)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(payload, "203.0.113.10") {
		t.Errorf("payload missing ip")
	}
	if !strings.Contains(payload, "Googlebot") {
		t.Errorf("payload missing identity")
	}
	if !strings.Contains(payload, "/index.html") {
		t.Errorf("payload missing request path")
	}
	if !strings.Contains(payload, "last 1 of 500") {
		t.Errorf("payload missing trimmed count")
	}
	if !strings.Contains(payload, "<actor>") {
		t.Errorf("payload missing actor wrapper")
	}
}

func TestNewInputTrimsToRecentRequests(t *testing.T) {
	base := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	flows := make([]history.Flow, MaxRequests+20)
	for i := range flows {
		flows[i] = history.Flow{Event: flow.Event{Timestamp: base.Add(time.Duration(i) * time.Second), Path: "/p", Duration: 250 * time.Millisecond}}
	}
	in := NewInput("203.0.113.1", "fp", identity.Result{Failed: "Googlebot"}, RuleResult{Score: 30}, flows)
	if in.TotalRequests != MaxRequests+20 || len(in.Requests) != MaxRequests {
		t.Fatalf("total=%d sent=%d", in.TotalRequests, len(in.Requests))
	}
	if !in.Requests[0].Timestamp.Equal(base.Add(20*time.Second)) || in.Requests[0].DurationMS != 250 {
		t.Fatalf("first sent=%+v, want the oldest of the most recent %d", in.Requests[0], MaxRequests)
	}
	if in.Identity.Failed != "Googlebot" {
		t.Fatalf("identity=%+v", in.Identity)
	}
}
