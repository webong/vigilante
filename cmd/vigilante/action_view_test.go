package main

import (
	"context"
	"testing"

	blockaction "github.com/webong/vigilante/ext/action/block"
	"github.com/webong/vigilante/internal/action"
	"github.com/webong/vigilante/internal/block"
	"github.com/webong/vigilante/internal/decision"
)

// TestActionView locks the mapping from the action registry to the obs read
// model: what is available, what is in force, and what has been decided.
func TestActionView(t *testing.T) {
	enc, err := block.New(block.Options{Mode: block.ModeLog})
	if err != nil {
		t.Fatal(err)
	}
	reg := action.New(action.Options{Set: decision.NewSet(), Allow: []string{"block"}})
	if err := reg.Register(blockaction.New(enc)); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Execute(context.Background(), action.Request{
		Action:    "block",
		Scope:     decision.ScopeIP,
		Target:    "203.0.113.9:443",
		Reason:    "test",
		Confirmed: true,
	}); err != nil {
		t.Fatal(err)
	}

	view := actionView(reg)
	if len(view.Capabilities) != 1 || view.Capabilities[0].ID != "block" || !view.Capabilities[0].Reversible {
		t.Fatalf("capabilities = %+v", view.Capabilities)
	}
	if len(view.Active) != 1 {
		t.Fatalf("active = %+v, want 1", view.Active)
	}
	if view.Active[0].Target != "203.0.113.9" {
		t.Fatalf("active target = %q, want the normalized IP", view.Active[0].Target)
	}
	if len(view.Decisions) != 1 || view.Decisions[0].Status != "applied" {
		t.Fatalf("decisions = %+v", view.Decisions)
	}
}

func TestActionViewNilRegistryIsEmpty(t *testing.T) {
	view := actionView(nil)
	if view.Capabilities == nil || view.Active == nil || view.Decisions == nil {
		t.Fatal("a nil registry must map to non-nil empty slices")
	}
}
