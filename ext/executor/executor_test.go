package executor

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/webong/ext/res/system/graph"
	"github.com/webong/vigilante/internal/action"
	"github.com/webong/vigilante/internal/decision"
)

// TestMain doubles as a supervised guest: Launch re-executes this binary with
// IPCEnv set, and it serves a fake executor instead of running tests.
func TestMain(m *testing.M) {
	if addr := os.Getenv(IPCEnv); addr != "" {
		if err := RunWorkerIPC(context.Background(), addr, &fakeGuest{}); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type fakeGuest struct {
	mu       sync.Mutex
	executed []Request
	reverted []Decision
}

func (f *fakeGuest) Capability() Capability {
	return Capability{
		ID: "waf_rule", Label: "WAF rule", Scopes: []string{"ip", "cidr"},
		DefaultTTLSeconds: 600, MaxTTLSeconds: 3600, Reversible: true,
	}
}

func (f *fakeGuest) Execute(_ context.Context, req Request) (Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.executed = append(f.executed, req)
	if req.DryRun {
		return Result{Detail: "would add rule"}, nil
	}
	return Result{RevertRef: "rule-" + req.Target, Detail: "rule added"}, nil
}

func (f *fakeGuest) Revert(_ context.Context, d Decision) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reverted = append(f.reverted, d)
	return nil
}

func TestPluginExecutorKeepsHostRails(t *testing.T) {
	ctx := context.Background()
	g := &fakeGuest{}
	c, err := Open(ctx, g)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer c.Close(ctx)

	cap := c.Capability()
	if cap.ID != "waf_rule" || cap.DefaultTTL != 10*time.Minute || !cap.SupportsScope(decision.ScopeCIDR) {
		t.Fatalf("capability=%+v", cap)
	}

	set := decision.NewSet()
	reg := action.New(action.Options{Set: set, Allow: []string{"waf_rule"}, MaxTTL: 30 * time.Minute})
	if err := reg.Register(c); err != nil {
		t.Fatalf("register: %v", err)
	}

	// Scope the guest did not declare is rejected by the host before the guest sees it.
	if _, err := reg.Execute(ctx, action.Request{Action: "waf_rule", Scope: decision.ScopeFingerprint, Target: "abc", Operator: "alice"}); err == nil {
		t.Fatal("undeclared scope executed")
	}
	d, err := reg.Execute(ctx, action.Request{Action: "waf_rule", Scope: decision.ScopeIP, Target: "203.0.113.9", TTL: 2 * time.Hour, Operator: "alice"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if d.Status != action.StatusApplied || d.RevertRef != "rule-203.0.113.9" {
		t.Fatalf("decision=%+v", d)
	}
	if got := len(g.executed); got != 1 {
		t.Fatalf("guest saw %d requests, want 1", got)
	}
	// The host clamps the TTL to its ceiling before the request crosses the wire.
	if ttl := g.executed[0].TTLSeconds; ttl != int64((30*time.Minute)/time.Second) {
		t.Fatalf("guest ttl=%ds, want host-clamped 1800s", ttl)
	}
	if _, err := reg.Revert(ctx, d.ID); err != nil {
		t.Fatalf("revert: %v", err)
	}
	if len(g.reverted) != 1 || g.reverted[0].RevertRef != "rule-203.0.113.9" {
		t.Fatalf("reverted=%+v", g.reverted)
	}
}

func TestLaunchSupervisedGuest(t *testing.T) {
	if testing.Short() {
		t.Skip("spawns a process")
	}
	ctx := context.Background()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	c, err := Launch(ctx, LaunchOptions{Store: graph.NewMemory(), Command: self})
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	defer c.Close(ctx)
	if c.Capability().ID != "waf_rule" {
		t.Fatalf("capability=%+v", c.Capability())
	}
	res, err := c.Execute(ctx, action.Request{Action: "waf_rule", Scope: decision.ScopeIP, Target: "198.51.100.4", DryRun: true})
	if err != nil || res.Detail != "would add rule" || res.RevertRef != "" {
		t.Fatalf("dry run res=%+v err=%v", res, err)
	}
}
