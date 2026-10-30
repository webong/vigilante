// Package executor is the vigilante.action@v1 ext.plugin/v1 contract: it lets
// an action executor (a WAF, a CDN rule, a ticketing or paging integration) run
// as a plugin guest, in process or out of process under res/system/supervisor.
//
// Plugin executors never bypass the host. The host-side Client implements
// action.Executor and is registered with action.Registry like any built-in, so
// the allowlist, dry-run, scope validation, confirmation, TTL clamp, audit and
// revert all still apply. A guest only ever sees requests the registry has
// already approved.
//
// The wire types here are public so a guest in another module, or another
// language, can implement the contract without importing vigilante's core.
// Durations cross the wire as whole seconds.
package executor

import (
	"context"
	"time"

	"github.com/webong/vigilante/internal/action"
	"github.com/webong/vigilante/internal/decision"
)

const (
	ContractName      = "vigilante.action"
	ContractVersion   = "v1"
	OperationDescribe = "describe"
	OperationExecute  = "execute"
	OperationRevert   = "revert"
)

// Param describes one optional executor argument for generated UIs.
type Param struct {
	Name     string `json:"name"`
	Label    string `json:"label,omitempty"`
	Type     string `json:"type,omitempty"`
	Required bool   `json:"required,omitempty"`
	Default  string `json:"default,omitempty"`
}

// Capability declares what the guest's action does. It is a declaration, not
// a grant: the host's allowlist decides whether it may run.
type Capability struct {
	ID                string   `json:"id"`
	Label             string   `json:"label"`
	Description       string   `json:"description,omitempty"`
	Scopes            []string `json:"scopes"`
	DefaultTTLSeconds int64    `json:"default_ttl_seconds,omitempty"`
	MaxTTLSeconds     int64    `json:"max_ttl_seconds,omitempty"`
	Reversible        bool     `json:"reversible"`
	Destructive       bool     `json:"destructive,omitempty"`
	Params            []Param  `json:"params,omitempty"`
}

// Request is one approved action invocation. Guests must honor DryRun.
type Request struct {
	ID         string            `json:"id,omitempty"`
	Action     string            `json:"action"`
	Scope      string            `json:"scope"`
	Target     string            `json:"target"`
	Actor      string            `json:"actor,omitempty"`
	TTLSeconds int64             `json:"ttl_seconds,omitempty"`
	Reason     string            `json:"reason,omitempty"`
	Operator   string            `json:"operator,omitempty"`
	Confirmed  bool              `json:"confirmed,omitempty"`
	DryRun     bool              `json:"dry_run,omitempty"`
	Evidence   map[string]string `json:"evidence,omitempty"`
}

// Result returns the remote-side handle used for revert.
type Result struct {
	RevertRef string `json:"revert_ref,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Decision is the applied decision the host asks the guest to undo.
type Decision struct {
	ID        string    `json:"id"`
	Action    string    `json:"action"`
	Scope     string    `json:"scope"`
	Target    string    `json:"target"`
	Actor     string    `json:"actor,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	RevertRef string    `json:"revert_ref,omitempty"`
	StartedAt time.Time `json:"started_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// Describe is the empty input of the describe operation.
type Describe struct{}

// Reverted is the empty output of the revert operation.
type Reverted struct{}

// Executor is what a guest implements.
type Executor interface {
	Capability() Capability
	Execute(ctx context.Context, req Request) (Result, error)
	Revert(ctx context.Context, d Decision) error
}

// FromAction adapts a core executor so it can be served as a guest, which is
// how the built-ins can run out of process and how tests exercise the wire.
func FromAction(e action.Executor) Executor { return actionGuest{e} }

type actionGuest struct{ e action.Executor }

func (g actionGuest) Capability() Capability { return wireCapability(g.e.Capability()) }

func (g actionGuest) Execute(ctx context.Context, req Request) (Result, error) {
	res, err := g.e.Execute(ctx, coreRequest(req))
	return Result{RevertRef: res.RevertRef, Detail: res.Detail}, err
}

func (g actionGuest) Revert(ctx context.Context, d Decision) error {
	return g.e.Revert(ctx, coreDecision(d))
}

func wireCapability(c action.Capability) Capability {
	out := Capability{
		ID: c.ID, Label: c.Label, Description: c.Description,
		DefaultTTLSeconds: seconds(c.DefaultTTL), MaxTTLSeconds: seconds(c.MaxTTL),
		Reversible: c.Reversible, Destructive: c.Destructive,
	}
	for _, s := range c.Scopes {
		out.Scopes = append(out.Scopes, string(s))
	}
	for _, p := range c.Params {
		out.Params = append(out.Params, Param(p))
	}
	return out
}

func coreCapability(c Capability) action.Capability {
	out := action.Capability{
		ID: c.ID, Label: c.Label, Description: c.Description,
		DefaultTTL: duration(c.DefaultTTLSeconds), MaxTTL: duration(c.MaxTTLSeconds),
		Reversible: c.Reversible, Destructive: c.Destructive,
	}
	for _, s := range c.Scopes {
		out.Scopes = append(out.Scopes, decision.Scope(s))
	}
	for _, p := range c.Params {
		out.Params = append(out.Params, action.Param(p))
	}
	return out
}

func wireRequest(r action.Request) Request {
	return Request{
		ID: r.ID, Action: r.Action, Scope: string(r.Scope), Target: r.Target, Actor: r.Actor,
		TTLSeconds: seconds(r.TTL), Reason: r.Reason, Operator: r.Operator,
		Confirmed: r.Confirmed, DryRun: r.DryRun, Evidence: r.Evidence,
	}
}

func coreRequest(r Request) action.Request {
	return action.Request{
		ID: r.ID, Action: r.Action, Scope: decision.Scope(r.Scope), Target: r.Target, Actor: r.Actor,
		TTL: duration(r.TTLSeconds), Reason: r.Reason, Operator: r.Operator,
		Confirmed: r.Confirmed, DryRun: r.DryRun, Evidence: r.Evidence,
	}
}

func wireDecision(d action.Decision) Decision {
	return Decision{
		ID: d.ID, Action: d.Action, Scope: string(d.Scope), Target: d.Target, Actor: d.Actor,
		Reason: d.Reason, RevertRef: d.RevertRef, StartedAt: d.StartedAt, ExpiresAt: d.ExpiresAt,
	}
}

func coreDecision(d Decision) action.Decision {
	return action.Decision{
		ID: d.ID, Action: d.Action, Scope: decision.Scope(d.Scope), Target: d.Target, Actor: d.Actor,
		Reason: d.Reason, RevertRef: d.RevertRef, StartedAt: d.StartedAt, ExpiresAt: d.ExpiresAt,
		Status: action.StatusApplied,
	}
}

func seconds(d time.Duration) int64  { return int64(d / time.Second) }
func duration(s int64) time.Duration { return time.Duration(s) * time.Second }
