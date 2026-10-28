package action

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/webong/vigilante/internal/decision"
)

type fakeExec struct {
	cap      Capability
	executed []Request
	reverts  []Decision
	err      error
}

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *clock {
	return &clock{t: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
}

func (f *fakeExec) Capability() Capability { return f.cap }

func (f *fakeExec) Execute(_ context.Context, req Request) (Result, error) {
	f.executed = append(f.executed, req)
	if f.err != nil {
		return Result{}, f.err
	}
	return Result{RevertRef: "ref-" + req.Target, Detail: "applied"}, nil
}

func (f *fakeExec) Revert(_ context.Context, d Decision) error {
	f.reverts = append(f.reverts, d)
	return f.err
}

func newRegistry(t *testing.T, execs ...*fakeExec) (*Registry, *decision.Set) {
	t.Helper()
	set := decision.NewSet()
	r := New(Options{
		Set:        set,
		Allow:      []string{"block", "notify"},
		MaxTTL:     2 * time.Hour,
		DefaultTTL: time.Hour,
	})
	for _, e := range execs {
		if err := r.Register(e); err != nil {
			t.Fatalf("Register: %v", err)
		}
	}
	return r, set
}

func blockCap() Capability {
	return Capability{ID: "block", Label: "Block", Scopes: []decision.Scope{decision.ScopeIP}, Reversible: true}
}

func TestExecuteAppliesAndEnforces(t *testing.T) {
	ex := &fakeExec{cap: blockCap()}
	r, set := newRegistry(t, ex)

	d, err := r.Execute(context.Background(), Request{Action: "block", Target: "203.0.113.9", Reason: "test"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if d.Status != StatusApplied {
		t.Fatalf("status = %s, want applied", d.Status)
	}
	if d.ExpiresAt.IsZero() {
		t.Fatal("applied decision should expire")
	}
	if len(ex.executed) != 1 {
		t.Fatalf("executor calls = %d, want 1", len(ex.executed))
	}
	if _, ok := set.Lookup("203.0.113.9", "", ""); !ok {
		t.Fatal("applied decision should be in the enforcement snapshot")
	}
}

func TestExecuteRejectsUnknownAndDisallowed(t *testing.T) {
	ex := &fakeExec{cap: blockCap()}
	r, _ := newRegistry(t, ex)

	if _, err := r.Execute(context.Background(), Request{Action: "warp", Target: "203.0.113.9"}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("want ErrUnsupported, got %v", err)
	}
	if _, err := r.Execute(context.Background(), Request{Action: "block"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("want ErrInvalidRequest for missing target, got %v", err)
	}

	// Register but do not allowlist.
	other := &fakeExec{cap: Capability{ID: "exfil", Scopes: []decision.Scope{decision.ScopeIP}}}
	if err := r.Register(other); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Execute(context.Background(), Request{Action: "exfil", Target: "203.0.113.9"}); !errors.Is(err, ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	if len(other.executed) != 0 {
		t.Fatal("a denied action must never reach the executor")
	}
}

func TestExecuteScopeAndConfirmation(t *testing.T) {
	ex := &fakeExec{cap: blockCap()}
	r, _ := newRegistry(t, ex)

	if _, err := r.Execute(context.Background(), Request{Action: "block", Scope: decision.ScopeCIDR, Target: "203.0.113.0/24"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("want an error for an unsupported scope, got %v", err)
	}

	ex.cap.Destructive = true
	if _, err := r.Execute(context.Background(), Request{Action: "block", Target: "203.0.113.9"}); !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("want ErrConfirmationRequired, got %v", err)
	}
	if _, err := r.Execute(context.Background(), Request{Action: "block", Target: "203.0.113.9", Operator: "auto"}); !errors.Is(err, ErrConfirmationRequired) {
		t.Fatalf("automation without confirmation should be refused, got %v", err)
	}
	if _, err := r.Execute(context.Background(), Request{Action: "block", Target: "203.0.113.9", Confirmed: true}); err != nil {
		t.Fatalf("confirmed action should run: %v", err)
	}
}

func TestDryRunDoesNotEnforce(t *testing.T) {
	ex := &fakeExec{cap: blockCap()}
	r, set := newRegistry(t, ex)

	d, err := r.Execute(context.Background(), Request{Action: "block", Target: "203.0.113.9", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != StatusDryRun {
		t.Fatalf("status = %s, want dry-run", d.Status)
	}
	if len(ex.executed) != 1 || !ex.executed[0].DryRun {
		t.Fatal("executor must be told it is a dry run")
	}
	if set.Len() != 0 {
		t.Fatal("a dry run must not enter the enforcement snapshot")
	}
}

func TestHostDryRunOverridesRequest(t *testing.T) {
	ex := &fakeExec{cap: blockCap()}
	set := decision.NewSet()
	r := New(Options{Set: set, Allow: []string{"block"}, DryRun: true})
	if err := r.Register(ex); err != nil {
		t.Fatal(err)
	}
	d, err := r.Execute(context.Background(), Request{Action: "block", Target: "203.0.113.9"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != StatusDryRun || set.Len() != 0 {
		t.Fatalf("host dry-run must win: status=%s entries=%d", d.Status, set.Len())
	}
}

func TestTTLClampedToHostCeiling(t *testing.T) {
	ex := &fakeExec{cap: Capability{ID: "block", Scopes: []decision.Scope{decision.ScopeIP}, DefaultTTL: 48 * time.Hour}}
	r, _ := newRegistry(t, ex)
	d, err := r.Execute(context.Background(), Request{Action: "block", Target: "203.0.113.9", TTL: 48 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if got := d.ExpiresAt.Sub(d.StartedAt); got != 2*time.Hour {
		t.Fatalf("ttl = %s, want the 2h host ceiling", got)
	}
}

func TestRevertRemovesAndUndoes(t *testing.T) {
	ex := &fakeExec{cap: blockCap()}
	r, set := newRegistry(t, ex)

	d, err := r.Execute(context.Background(), Request{Action: "block", Target: "203.0.113.9"})
	if err != nil {
		t.Fatal(err)
	}
	out, err := r.Revert(context.Background(), d.ID)
	if err != nil {
		t.Fatalf("Revert: %v", err)
	}
	if out.Status != StatusReverted {
		t.Fatalf("status = %s, want reverted", out.Status)
	}
	if len(ex.reverts) != 1 || ex.reverts[0].ID != d.ID {
		t.Fatal("executor revert was not called with the decision")
	}
	if set.Len() != 0 {
		t.Fatal("revert should remove the snapshot entry")
	}
	if _, err := r.Revert(context.Background(), d.ID); !errors.Is(err, ErrNotRevertible) {
		t.Fatalf("second revert should report ErrNotRevertible, got %v", err)
	}
}

func TestReapRevertsExpired(t *testing.T) {
	c := newClock()
	ex := &fakeExec{cap: blockCap()}
	set := decision.NewSetWithClock(c.now)
	r := New(Options{Set: set, Allow: []string{"block"}, Now: c.now, DefaultTTL: time.Minute})
	if err := r.Register(ex); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Execute(context.Background(), Request{Action: "block", Target: "203.0.113.9"}); err != nil {
		t.Fatal(err)
	}
	c.advance(2 * time.Minute)
	if n := r.Reap(context.Background()); n != 1 {
		t.Fatalf("Reap() = %d, want 1", n)
	}
	if len(ex.reverts) != 1 {
		t.Fatalf("reverts = %d, want 1", len(ex.reverts))
	}
	if set.Len() != 0 {
		t.Fatal("expired decision should be gone")
	}
}

func TestAuditTrailIsNewestFirstAndBounded(t *testing.T) {
	ex := &fakeExec{cap: blockCap()}
	set := decision.NewSet()
	r := New(Options{Set: set, Allow: []string{"block"}, MaxDecisions: 3})
	if err := r.Register(ex); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"} {
		if _, err := r.Execute(context.Background(), Request{Action: "block", Target: ip}); err != nil {
			t.Fatal(err)
		}
	}
	all := r.Decisions()
	if len(all) != 3 {
		t.Fatalf("audit length = %d, want 3", len(all))
	}
	if all[0].Target != "203.0.113.4" {
		t.Fatalf("newest = %q, want 203.0.113.4", all[0].Target)
	}
}

func TestExecutorErrorIsRecorded(t *testing.T) {
	ex := &fakeExec{cap: blockCap(), err: errors.New("remote down")}
	r, set := newRegistry(t, ex)
	d, err := r.Execute(context.Background(), Request{Action: "block", Target: "203.0.113.9"})
	if err == nil {
		t.Fatal("expected the executor error to surface")
	}
	if d.Status != StatusFailed {
		t.Fatalf("status = %s, want failed", d.Status)
	}
	if set.Len() != 0 {
		t.Fatal("a failed action must not enforce")
	}
}
