package triage

import (
	"context"
	"testing"
	"time"

	"github.com/webong/vigilante/internal/flow"
	"github.com/webong/vigilante/internal/history"
)

func TestClientRoundTripsThroughPlugin(t *testing.T) {
	f := &fakeProvider{
		text:  `{"classification":"scanner","risk":90,"confidence":0.9,"summary":"probing","evidence":["/.env"],"recommended_action":"block","scope":"ip","ttl_minutes":60}`,
		model: "test/model",
	}
	ctx := context.Background()
	c, err := Open(ctx, New(f, "test/model"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer c.Close(ctx)

	var svc Service = c
	v, err := svc.Triage(ctx, Input{
		IP:       "203.0.113.7",
		Rules:    RuleResult{Score: 70, Class: "scanner", Signals: []RuleSignal{{Code: "attack", Weight: 40}}},
		Requests: []history.Flow{{Event: flow.Event{Timestamp: time.Now().UTC(), Method: "GET", Path: "/.env", Status: 404, Headers: map[string]string{"Accept": "*/*"}}}},
	})
	if err != nil {
		t.Fatalf("triage: %v", err)
	}
	if v.Action != "block" || v.Risk != 90 || v.Model != "test/model" || len(v.Evidence) != 1 {
		t.Fatalf("verdict=%+v", v)
	}
	if svc.Model() != "test/model" {
		t.Fatalf("model=%q", svc.Model())
	}
}
