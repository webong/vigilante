package action

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/webong/vigilante/internal/decision"
)

// Options configures the host registry. The zero value denies every action;
// callers must opt in with Allow.
type Options struct {
	// Set receives applied decisions so the request path can enforce them.
	// A nil set still records and executes actions, but nothing is enforced.
	Set *decision.Set
	// Allow is the explicit list of action IDs the host permits. Empty denies
	// everything: a request path never gets to run an action just because an
	// executor is registered.
	Allow []string
	// DryRun forces every action into dry-run regardless of the request.
	DryRun bool
	// DefaultTTL applies when neither the request nor the capability sets one.
	DefaultTTL time.Duration
	// MaxTTL is the host ceiling on how long any action may stay in force.
	MaxTTL time.Duration
	// MaxDecisions bounds the in-memory audit trail (default 500).
	MaxDecisions int
	// Now overrides the clock (tests).
	Now func() time.Time
	// OnDecision is called after each decision is recorded. It must not block.
	OnDecision func(Decision)
	// OnRevert is called after each revert attempt with its error.
	OnRevert func(Decision, error)
}

// Registry is the host-side action authority: it validates, executes, records,
// enforces, and reverts decisions.
type Registry struct {
	opts Options

	mu        sync.Mutex
	executors map[string]Executor
	order     []string
	decisions map[string]*Decision
	audit     []string
	seq       atomic.Uint64
}

// New builds a registry from opts.
func New(opts Options) *Registry {
	if opts.MaxDecisions <= 0 {
		opts.MaxDecisions = 500
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.DefaultTTL <= 0 {
		opts.DefaultTTL = time.Hour
	}
	return &Registry{
		opts:      opts,
		executors: map[string]Executor{},
		decisions: map[string]*Decision{},
	}
}

// Register adds an executor. A capability without an ID is rejected, and so is
// registering the same ID twice.
func (r *Registry) Register(e Executor) error {
	if e == nil {
		return fmt.Errorf("%w: nil executor", ErrInvalidRequest)
	}
	cap := e.Capability()
	if cap.ID == "" {
		return fmt.Errorf("%w: executor has no capability id", ErrInvalidRequest)
	}
	for _, s := range cap.Scopes {
		if !s.Valid() {
			return fmt.Errorf("%w: capability %q has unknown scope %q", ErrInvalidRequest, cap.ID, s)
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.executors[cap.ID]; exists {
		return fmt.Errorf("%w: action %q already registered", ErrInvalidRequest, cap.ID)
	}
	r.executors[cap.ID] = e
	r.order = append(r.order, cap.ID)
	return nil
}

// Capabilities returns every registered capability in registration order.
func (r *Registry) Capabilities() []Capability {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Capability, 0, len(r.order))
	for _, id := range r.order {
		out = append(out, r.executors[id].Capability())
	}
	return out
}

// Allowed reports whether the host permits the action.
func (r *Registry) Allowed(id string) bool {
	for _, a := range r.opts.Allow {
		if a == id {
			return true
		}
	}
	return false
}

// Execute validates req against the host policy, runs the executor, records the
// decision, and (when applied) publishes it to the enforcement snapshot.
func (r *Registry) Execute(ctx context.Context, req Request) (Decision, error) {
	if req.Action == "" {
		return Decision{}, fmt.Errorf("%w: action is required", ErrInvalidRequest)
	}

	r.mu.Lock()
	exec, ok := r.executors[req.Action]
	r.mu.Unlock()
	if !ok {
		return Decision{}, fmt.Errorf("%w: %q", ErrUnsupported, req.Action)
	}
	if !r.Allowed(req.Action) {
		return Decision{}, fmt.Errorf("%w: %q (allow: %v)", ErrDenied, req.Action, r.opts.Allow)
	}

	cap := exec.Capability()
	scope := req.Scope
	if scope == "" {
		scope = decision.ScopeIP
	}
	if !scope.Valid() {
		return Decision{}, fmt.Errorf("%w: unknown scope %q", ErrInvalidRequest, scope)
	}
	if !cap.SupportsScope(scope) {
		return Decision{}, fmt.Errorf("%w: %q does not support scope %q", ErrInvalidRequest, req.Action, scope)
	}
	if req.Target == "" && scope != decision.ScopeGlobal {
		return Decision{}, fmt.Errorf("%w: target is required for %s scope", ErrInvalidRequest, scope)
	}
	// Destructive actions need an explicit human act: either the confirmation
	// bit, or an operator label that is not the automation identity.
	if cap.Destructive && !req.Confirmed && (req.Operator == "" || req.Operator == "auto") {
		return Decision{}, fmt.Errorf("%w: %q", ErrConfirmationRequired, req.Action)
	}

	now := r.opts.Now().UTC()
	ttl := r.effectiveTTL(cap, req.TTL)
	d := Decision{
		ID:        r.nextID(req.Action, now),
		Action:    req.Action,
		Label:     cap.Label,
		Scope:     scope,
		Target:    req.Target,
		Actor:     req.Actor,
		Reason:    req.Reason,
		Operator:  req.Operator,
		StartedAt: now,
	}
	if ttl > 0 {
		d.ExpiresAt = now.Add(ttl)
	}

	dryRun := r.opts.DryRun || req.DryRun
	req.ID = d.ID
	req.Scope = scope
	req.DryRun = dryRun

	runCtx := ctx
	if runCtx == nil {
		runCtx = context.Background()
	}
	res, err := exec.Execute(runCtx, req)
	switch {
	case err != nil:
		d.Status = StatusFailed
		d.Detail = err.Error()
	case dryRun:
		d.Status = StatusDryRun
		d.Detail = res.Detail
	default:
		d.Status = StatusApplied
		d.RevertRef = res.RevertRef
		d.Detail = res.Detail
	}

	if d.Status == StatusApplied && r.opts.Set != nil {
		entry := decision.Entry{
			ID:      d.ID,
			Action:  d.Action,
			Scope:   d.Scope,
			Target:  d.Target,
			Reason:  d.Reason,
			Actor:   d.Actor,
			Created: d.StartedAt,
			Expires: d.ExpiresAt,
		}
		if putErr := r.opts.Set.Put(entry); putErr != nil {
			// The action ran but cannot be enforced; surface it rather than
			// pretending the decision is in force, and undo the external side.
			d.Status = StatusFailed
			d.Detail = putErr.Error()
			err = putErr
			if cap.Reversible {
				_ = exec.Revert(ctx, d)
			}
		}
	}

	rec := r.record(d)
	if r.opts.OnDecision != nil {
		r.opts.OnDecision(rec)
	}
	return rec, err
}

// Revert undoes a decision by ID and removes it from the enforcement snapshot.
func (r *Registry) Revert(ctx context.Context, id string) (Decision, error) {
	r.mu.Lock()
	existing, ok := r.decisions[id]
	if !ok {
		r.mu.Unlock()
		return Decision{}, fmt.Errorf("%w: unknown decision %q", ErrInvalidRequest, id)
	}
	d := *existing
	exec, hasExec := r.executors[d.Action]
	r.mu.Unlock()

	if d.Status != StatusApplied && d.Status != StatusFailed {
		return d, fmt.Errorf("%w: decision %q is %s", ErrNotRevertible, id, d.Status)
	}
	if r.opts.Set != nil {
		r.opts.Set.Remove(id)
	}

	var err error
	if hasExec {
		cap := exec.Capability()
		if cap.Reversible {
			runCtx := ctx
			if runCtx == nil {
				runCtx = context.Background()
			}
			err = exec.Revert(runCtx, d)
		} else if d.Detail == "" {
			d.Detail = "reverted locally; action is not reversible on the remote side"
		}
	}
	if err == nil {
		d.Status = StatusReverted
		d.RevertedAt = r.opts.Now().UTC()
	}
	rec := r.record(d)
	if r.opts.OnRevert != nil {
		r.opts.OnRevert(rec, err)
	}
	return rec, err
}

// Reap reverts every expired decision and returns how many were reverted.
func (r *Registry) Reap(ctx context.Context) int {
	if r.opts.Set == nil {
		return 0
	}
	n := 0
	for _, entry := range r.opts.Set.Sweep() {
		if _, err := r.Revert(ctx, entry.ID); err == nil {
			n++
		}
	}
	return n
}

// StartReaper runs Reap on an interval until ctx is cancelled. It returns a
// function that stops the goroutine and waits for it.
func (r *Registry) StartReaper(ctx context.Context, interval time.Duration) func() {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stop:
				return
			case <-t.C:
				r.Reap(ctx)
			}
		}
	}()
	return func() {
		close(stop)
		<-done
	}
}

// Decisions returns the audit trail, newest first.
func (r *Registry) Decisions() []Decision {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Decision, 0, len(r.audit))
	for i := len(r.audit) - 1; i >= 0; i-- {
		if d, ok := r.decisions[r.audit[i]]; ok {
			out = append(out, *d)
		}
	}
	return out
}

// Active returns the decisions currently in force in the snapshot.
func (r *Registry) Active() []decision.Entry {
	if r.opts.Set == nil {
		return nil
	}
	active := r.opts.Set.Active()
	sort.Slice(active, func(i, j int) bool { return active[i].Created.Before(active[j].Created) })
	return active
}

// effectiveTTL clamps a requested duration against the capability and host
// ceilings. Zero means "no expiry".
func (r *Registry) effectiveTTL(cap Capability, requested time.Duration) time.Duration {
	ttl := requested
	if ttl == 0 {
		ttl = cap.DefaultTTL
	}
	if ttl == 0 {
		ttl = r.opts.DefaultTTL
	}
	if ttl < 0 {
		ttl = 0
	}
	ceiling := cap.MaxTTL
	if ceiling > 0 && r.opts.MaxTTL > 0 && r.opts.MaxTTL < ceiling {
		ceiling = r.opts.MaxTTL
	}
	if ceiling == 0 {
		ceiling = r.opts.MaxTTL
	}
	if ceiling > 0 && ttl > ceiling {
		ttl = ceiling
	}
	return ttl
}

// record stores d in the audit trail, trimming the oldest entries.
func (r *Registry) record(d Decision) Decision {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.decisions[d.ID]; !ok {
		r.audit = append(r.audit, d.ID)
	} else {
		// Revert updates the existing decision in place.
		idx := -1
		for i, id := range r.audit {
			if id == d.ID {
				idx = i
				break
			}
		}
		if idx >= 0 {
			r.audit = append(r.audit[:idx], r.audit[idx+1:]...)
			r.audit = append(r.audit, d.ID)
		}
	}
	copied := d
	r.decisions[d.ID] = &copied
	for len(r.audit) > r.opts.MaxDecisions {
		oldest := r.audit[0]
		r.audit = r.audit[1:]
		delete(r.decisions, oldest)
	}
	return copied
}

func (r *Registry) nextID(action string, now time.Time) string {
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	return fmt.Sprintf("%s-%d-%s", action, now.UnixNano(), hex.EncodeToString(buf[:]))
}
