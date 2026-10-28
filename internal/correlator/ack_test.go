package correlator

import (
	"context"
	"testing"

	"github.com/webong/ext/res/system"
	"github.com/webong/ext/res/system/graph"
	"github.com/webong/vigilante/ext/agent"
)

func TestAcknowledgedAgentDoesNotCreateHostVerdict(t *testing.T) {
	ctx := context.Background()
	store := graph.NewMemory()
	defer store.Close()
	sys, err := system.New(store)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := agent.NewInProcessGateway(ctx, store, nil, func(context.Context, agent.EnrichedEnvelope) (agent.Verdict, error) {
		return agent.Verdict{}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close(ctx)
	called := false
	c, err := New(Options{SystemGraph: sys, Gateway: gw, OnVerdict: func(agent.EnrichedEnvelope, agent.Verdict) { called = true }})
	if err != nil {
		t.Fatal(err)
	}
	v, err := c.ProcessPacket(ctx, agent.PacketEvent{FlowID: "f1", Protocol: "http", SrcAddr: "127.0.0.1:1234", DstAddr: "127.0.0.1:8080"})
	if err != nil || called || v.Action != "" || v.Severity != "" {
		t.Fatalf("acknowledgement became a verdict: %+v, called=%v, err=%v", v, called, err)
	}
}
