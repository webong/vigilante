package blockaction

import (
	"context"
	"net"
	"testing"

	"github.com/webong/vigilante/internal/action"
	"github.com/webong/vigilante/internal/block"
)

func newExecutor(t *testing.T) (*Executor, *[]string) {
	t.Helper()
	var calls []string
	enc, err := block.New(block.Options{
		Mode: block.ModeLog,
		OnBlock: func(ip net.IP, rule string) {
			calls = append(calls, "block:"+ip.String()+"/"+rule)
		},
		OnUnblock: func(ip net.IP) {
			calls = append(calls, "unblock:"+ip.String())
		},
	})
	if err != nil {
		t.Fatalf("block.New: %v", err)
	}
	return New(enc), &calls
}

func TestExecuteBlocksHostPort(t *testing.T) {
	ex, calls := newExecutor(t)
	res, err := ex.Execute(context.Background(), action.Request{Action: "block", Target: "203.0.113.9:443", Reason: "agent-verdict"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if res.RevertRef != "203.0.113.9" {
		t.Fatalf("revert ref = %q, want the bare IP", res.RevertRef)
	}
	if len(*calls) != 1 || (*calls)[0] != "block:203.0.113.9/agent-verdict" {
		t.Fatalf("calls = %v, want one block", *calls)
	}
}

func TestExecuteDryRunTouchesNothing(t *testing.T) {
	ex, calls := newExecutor(t)
	res, err := ex.Execute(context.Background(), action.Request{Action: "block", Target: "203.0.113.9", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 0 {
		t.Fatalf("dry run made %d enforcement calls", len(*calls))
	}
	if res.Detail == "" {
		t.Fatal("dry run should explain what it would do")
	}
}

func TestExecuteRejectsBadTargets(t *testing.T) {
	ex, _ := newExecutor(t)
	for _, target := range []string{"", "not-an-ip", "example.com:443"} {
		if _, err := ex.Execute(context.Background(), action.Request{Target: target}); err == nil {
			t.Errorf("target %q should be rejected", target)
		}
	}
	if _, err := ex.Execute(context.Background(), action.Request{Target: "127.0.0.1"}); err == nil {
		t.Fatal("loopback must be refused by the enforcer")
	}
}

func TestRevertUnblocks(t *testing.T) {
	ex, calls := newExecutor(t)
	if err := ex.Revert(context.Background(), action.Decision{
		Action:    "block",
		Target:    "203.0.113.9",
		RevertRef: "203.0.113.9",
	}); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	if len(*calls) != 1 || (*calls)[0] != "unblock:203.0.113.9" {
		t.Fatalf("calls = %v, want one unblock", *calls)
	}
}

func TestCapability(t *testing.T) {
	ex, _ := newExecutor(t)
	cap := ex.Capability()
	if cap.ID != "block" || !cap.Reversible || !cap.Destructive {
		t.Fatalf("unexpected capability: %+v", cap)
	}
	if cap.DefaultTTL != 0 || cap.MaxTTL != 0 {
		t.Fatal("TTL policy belongs to the host, not the executor")
	}
}
