package gate_test

import (
	"context"
	"net"
	"net/http"
	"testing"

	"github.com/webong/vigilante/internal/action"
	blockaction "github.com/webong/vigilante/internal/action/block"
	"github.com/webong/vigilante/internal/block"
	"github.com/webong/vigilante/internal/decision"
	"github.com/webong/vigilante/internal/flow"
	"github.com/webong/vigilante/internal/gate"
)

// TestFlowToDecisionToGate exercises the whole loop the architecture promises:
// a published flow is triaged by a sink, the sink asks the host to act, the
// decision enters the snapshot, and the request gate enforces it — then a
// revert releases it.
func TestFlowToDecisionToGate(t *testing.T) {
	set := decision.NewSet()
	var blocks, unblocks int
	enforcer, err := block.New(block.Options{
		Mode:      block.ModeLog,
		OnBlock:   func(net.IP, string) { blocks++ },
		OnUnblock: func(net.IP) { unblocks++ },
	})
	if err != nil {
		t.Fatal(err)
	}

	reg := action.New(action.Options{Set: set, Allow: []string{"block"}})
	if err := reg.Register(blockaction.New(enforcer)); err != nil {
		t.Fatal(err)
	}

	decided := make(chan action.Decision, 1)
	sink := flow.SinkFunc(func(ctx context.Context, ev flow.Event) error {
		d, err := reg.Execute(ctx, action.Request{
			Action:    "block",
			Scope:     decision.ScopeIP,
			Target:    ev.SrcAddr,
			Reason:    "integration:" + ev.Severity,
			Operator:  "vigilante/test",
			Confirmed: true,
		})
		if err != nil {
			return err
		}
		decided <- d
		return nil
	})

	pub := flow.NewPublisher([]flow.Sink{sink}, 8, 1)
	pub.Publish(flow.Event{FlowID: "f1", Severity: "critical", SrcAddr: "203.0.113.9:443"})
	if err := pub.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	var d action.Decision
	select {
	case d = <-decided:
	default:
		t.Fatal("sink never ran")
	}
	if d.Status != action.StatusApplied {
		t.Fatalf("decision status = %s, want applied", d.Status)
	}
	if blocks != 1 {
		t.Fatalf("enforcer blocks = %d, want 1", blocks)
	}

	gateFn := gate.New(gate.Options{Set: set})
	if got := gateFn(requestFrom("203.0.113.9:5555")); got != "block" {
		t.Fatalf("gate = %q, want block", got)
	}
	if got := gateFn(requestFrom("198.51.100.10:5555")); got != "allow" {
		t.Fatalf("gate = %q, want allow for an unrelated address", got)
	}

	if _, err := reg.Revert(context.Background(), d.ID); err != nil {
		t.Fatalf("Revert: %v", err)
	}
	if unblocks != 1 {
		t.Fatalf("enforcer unblocks = %d, want 1", unblocks)
	}
	if got := gateFn(requestFrom("203.0.113.9:5555")); got != "allow" {
		t.Fatalf("gate = %q after revert, want allow", got)
	}
}

func TestStaticPolicyStillWins(t *testing.T) {
	set := decision.NewSet()
	gateFn := gate.New(gate.Options{
		Set: set,
		Policy: func(*http.Request) string {
			return "deny"
		},
	})
	if got := gateFn(requestFrom("203.0.113.9:1")); got != "deny" {
		t.Fatalf("gate = %q, want the static deny", got)
	}
}

func requestFrom(remote string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.RemoteAddr = remote
	return r
}
