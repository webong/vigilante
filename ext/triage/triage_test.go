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
		Identity:       identity.Result{},
		Rules:          RuleResult{Score: 60, Class: "automation", Signals: []RuleSignal{{Code: "accepts_markdown", Weight: 15, Detail: "asks for markdown"}}},
		Requests: []history.Flow{
			{Event: flow.Event{Timestamp: time.Now().UTC(), Method: "GET", Path: "/", Status: 200, Duration: time.Second}},
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
		Identity: identity.Result{Verified: "Googlebot"},
		Rules:    RuleResult{Score: 40, Class: "crawler"},
		Requests: []history.Flow{
			{Event: flow.Event{Timestamp: time.Now().UTC(), Method: "GET", Path: "/index.html", Status: 200, UserAgent: "Mozilla/5.0", Headers: map[string]string{"Accept": "text/html", "Sec-Fetch-Mode": "navigate"}}},
		},
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
	if !strings.Contains(payload, "<actor>") {
		t.Errorf("payload missing actor wrapper")
	}
}
