// Package action is the host's response contract: it turns a detection into an
// enforceable action without teaching the core what any particular action is.
//
// An Executor is the unit of extension. The built-in block executor wraps the
// firewall enforcer; a remote executor speaks HTTP to anything with an API
// (a WAF, a load balancer, a ticketing system, an on-call pager). Third parties
// add one by implementing the interface and registering it, exactly like an
// obs or agent plugin.
//
// The host keeps the authority: it owns the allowlist, the dry-run switch, the
// TTL ceiling, the confirmation requirement, the audit log, and the decision
// snapshot the request path reads. A capability is a declaration, not a grant.
package action

import (
	"context"
	"errors"
	"time"

	"github.com/webong/vigilante/internal/decision"
)

// Param describes one optional executor argument for generated UIs.
type Param struct {
	Name     string `json:"name"`
	Label    string `json:"label,omitempty"`
	Type     string `json:"type,omitempty"` // "string", "duration", "bool", "select"
	Required bool   `json:"required,omitempty"`
	Default  string `json:"default,omitempty"`
}

// Capability is what an executor can do. The console renders its "Act now"
// panel from the union of registered capabilities, so a new action needs no UI
// change.
type Capability struct {
	ID          string           `json:"id"`
	Label       string           `json:"label"`
	Description string           `json:"description,omitempty"`
	Scopes      []decision.Scope `json:"scopes"`
	// DefaultTTL is applied when the request carries no duration.
	DefaultTTL time.Duration `json:"default_ttl,omitempty"`
	// MaxTTL caps how long the action may stay in force (0 = host ceiling).
	MaxTTL time.Duration `json:"max_ttl,omitempty"`
	// Reversible means Revert undoes the change on the remote side.
	Reversible bool `json:"reversible"`
	// Destructive means the action changes availability; hosts should require
	// confirmation.
	Destructive bool    `json:"destructive,omitempty"`
	Params      []Param `json:"params,omitempty"`
}

// SupportsScope reports whether the capability may be applied at scope.
func (c Capability) SupportsScope(scope decision.Scope) bool {
	if len(c.Scopes) == 0 {
		return scope == decision.ScopeIP
	}
	for _, s := range c.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// Request is one action invocation. The host fills Scope/Target from the actor
// it is acting on; Operator and Confirmed come from the human (or the agent,
// with an explicit operator label).
type Request struct {
	// ID is optional; the registry assigns one when empty.
	ID        string            `json:"id,omitempty"`
	Action    string            `json:"action"`
	Scope     decision.Scope    `json:"scope"`
	Target    string            `json:"target"`
	Actor     string            `json:"actor,omitempty"`
	TTL       time.Duration     `json:"ttl,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	Operator  string            `json:"operator,omitempty"`
	Confirmed bool              `json:"confirmed,omitempty"`
	DryRun    bool              `json:"dry_run,omitempty"`
	Evidence  map[string]string `json:"evidence,omitempty"`
}

// Result is what an executor reports back: a handle for revert and a
// human-readable description.
type Result struct {
	// RevertRef is the remote-side handle (a firewall address, a WAF rule ID).
	RevertRef string `json:"revert_ref,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Status is a decision's lifecycle state.
type Status string

const (
	StatusApplied  Status = "applied"
	StatusDryRun   Status = "dry-run"
	StatusFailed   Status = "failed"
	StatusReverted Status = "reverted"
)

// Decision is the audit record of one action.
type Decision struct {
	ID         string         `json:"id"`
	Action     string         `json:"action"`
	Label      string         `json:"label,omitempty"`
	Scope      decision.Scope `json:"scope"`
	Target     string         `json:"target"`
	Actor      string         `json:"actor,omitempty"`
	Reason     string         `json:"reason,omitempty"`
	Operator   string         `json:"operator,omitempty"`
	Status     Status         `json:"status"`
	RevertRef  string         `json:"revert_ref,omitempty"`
	Detail     string         `json:"detail,omitempty"`
	StartedAt  time.Time      `json:"started_at"`
	ExpiresAt  time.Time      `json:"expires_at,omitempty"`
	RevertedAt time.Time      `json:"reverted_at,omitempty"`
}

// Executor performs and undoes one class of action.
type Executor interface {
	Capability() Capability
	// Execute applies the action. Implementations must honor req.DryRun by
	// reporting what they would do without touching anything.
	Execute(ctx context.Context, req Request) (Result, error)
	// Revert undoes a previously applied decision. It is only called for
	// decisions the host recorded as applied.
	Revert(ctx context.Context, d Decision) error
}

// Host-side errors.
var (
	ErrUnsupported          = errors.New("action: unsupported action")
	ErrDenied               = errors.New("action: action not allowed by host policy")
	ErrInvalidRequest       = errors.New("action: invalid request")
	ErrConfirmationRequired = errors.New("action: this action requires explicit confirmation")
	ErrNotRevertible        = errors.New("action: decision is not revertible")
)
