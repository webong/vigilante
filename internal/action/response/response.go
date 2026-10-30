// Package responseaction exposes optional HTTP responses through the action registry.
package responseaction

import (
	"context"
	"fmt"

	"github.com/webong/vigilante/internal/action"
	"github.com/webong/vigilante/internal/decision"
)

type Executor struct{ kind string }

func New(kind string) *Executor {
	if kind != "challenge" && kind != "rate_limit" {
		return nil
	}
	return &Executor{kind: kind}
}
func (e *Executor) Capability() action.Capability {
	return action.Capability{ID: e.kind, Label: e.kind, Description: "In-process HTTP " + e.kind, Scopes: []decision.Scope{decision.ScopeIP, decision.ScopeCIDR, decision.ScopeActor, decision.ScopeFingerprint}, Reversible: true, Destructive: true}
}
func (e *Executor) Execute(_ context.Context, req action.Request) (action.Result, error) {
	if req.DryRun {
		return action.Result{Detail: "dry-run: would " + e.kind + " " + req.Target}, nil
	}
	return action.Result{Detail: e.kind + " enabled for " + req.Target}, nil
}
func (e *Executor) Revert(_ context.Context, d action.Decision) error {
	if d.Action != e.kind {
		return fmt.Errorf("response action: mismatched decision")
	}
	return nil
}
