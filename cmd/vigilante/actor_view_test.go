package main

import (
	"context"
	"testing"

	"github.com/webong/vigilante/ext/obs"
	"github.com/webong/vigilante/internal/actor"
	"github.com/webong/vigilante/internal/flow"
)

func TestActorView(t *testing.T) {
	idx := actor.NewIndex(actor.DefaultWindow, 100)
	_ = idx.Ingest(context.Background(), flow.Event{
		FlowID:   "f1",
		SrcAddr:  "203.0.113.9:443",
		Severity: "critical",
		Verdict:  "alert",
		Summary:  "Path traversal attempt",
	})
	_ = idx.Ingest(context.Background(), flow.Event{
		FlowID:   "f2",
		SrcAddr:  "198.51.100.7:443",
		Severity: "info",
		Verdict:  "observe",
	})

	out := actorView(idx, obs.ActorsInput{Limit: 10})
	if out.Count != 2 {
		t.Fatalf("count = %d, want 2", out.Count)
	}
	if len(out.Actors) != 2 {
		t.Fatalf("actors = %d, want 2", len(out.Actors))
	}
	first := out.Actors[0]
	if first.Key != "203.0.113.9" || first.Risk == 0 {
		t.Fatalf("highest-risk actor should be first: %+v", first)
	}
	if !containsTag(first.Tags, "path-traversal") {
		t.Fatalf("tags = %v, want path-traversal", first.Tags)
	}
}

func TestActorViewSuspiciousFilterAndLimit(t *testing.T) {
	idx := actor.NewIndex(actor.DefaultWindow, 100)
	for i := 0; i < 4; i++ { // 4 criticals => risk 80 >= 50
		_ = idx.Ingest(context.Background(), flow.Event{
			FlowID: "c", SrcAddr: "203.0.113.9:1", Severity: "critical", Verdict: "alert",
		})
	}
	_ = idx.Ingest(context.Background(), flow.Event{
		FlowID: "i", SrcAddr: "198.51.100.7:1", Severity: "info", Verdict: "observe",
	})

	out := actorView(idx, obs.ActorsInput{Suspicious: true, Limit: 100})
	if out.Suspicious != 1 {
		t.Fatalf("suspicious = %d, want 1", out.Suspicious)
	}
	if len(out.Actors) != 1 || !out.Actors[0].Suspicious {
		t.Fatalf("filtered actors = %+v", out.Actors)
	}

	limited := actorView(idx, obs.ActorsInput{Limit: 1})
	if len(limited.Actors) != 1 {
		t.Fatalf("limit actors = %d, want 1", len(limited.Actors))
	}
}

func TestActorViewNilIndex(t *testing.T) {
	out := actorView(nil, obs.ActorsInput{})
	if out.Actors == nil || out.Count != 0 {
		t.Fatalf("nil index should map to empty actors: %+v", out)
	}
}

func containsTag(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
