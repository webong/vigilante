package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/webong/ext/pkg/ext-go/engine"
	"github.com/webong/ext/pkg/ext-go/engine/guest/author"
	"github.com/webong/ext/res/system/graph"
	"github.com/webong/vigilante/internal/deps"
)

func TestAgentCanResearchAdvisoriesThroughHost(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"vulns":[{"id":"TEST-1","summary":"example advisory"}]}`))
	}))
	defer server.Close()
	previous := defaultOSVClient
	defaultOSVClient = &deps.OSVClient{URL: server.URL}
	defer func() { defaultOSVClient = previous }()

	ctx := context.Background()
	handler := func(ctx context.Context, env EnrichedEnvelope) (Verdict, error) {
		out, err := author.Call(ctx, engine.ReverseFrom(ctx), ReverseLookupAdvisoriesMethod(), AdvisoryLookupInput{
			Ecosystem: "npm", Name: "example", Version: "1.0.0",
		})
		if err != nil {
			return Verdict{}, err
		}
		return Verdict{FlowID: env.Event.FlowID, Severity: "low", Action: "review", Summary: "agent investigated advisory", Findings: []Finding{{Subject: "example@1.0.0", Claim: "advisory present", Sources: []string{out.Advisories[0].URL}}}}, nil
	}
	gw, err := NewInProcessGateway(ctx, graph.NewMemory(), nil, handler)
	if err != nil {
		t.Fatal(err)
	}
	defer gw.Close(ctx)
	v, err := gw.Triage(ctx, EnrichedEnvelope{Event: PacketEvent{FlowID: "f1"}})
	if err != nil || len(v.Findings) != 1 || v.Findings[0].Sources[0] != "https://osv.dev/vulnerability/TEST-1" {
		t.Fatalf("triage: %+v, %v", v, err)
	}
}

func TestBuiltInDoesNotClaimVulnerabilityReachability(t *testing.T) {
	env := EnrichedEnvelope{
		Event:           PacketEvent{FlowID: "f2", Path: "/health"},
		DependencyGraph: deps.Graph{Vulnerabilities: []deps.Advisory{{ID: "TEST-1", Package: "example"}}},
	}
	v, err := DefaultBuiltInHandler(context.Background(), env)
	if err != nil || v.Severity != "info" || len(v.ReachableDeps) != 0 || len(v.MatchedAdvisories) != 0 {
		t.Fatalf("built-in inferred a vulnerability: %+v, %v", v, err)
	}
	env.Event.Path = "/files/%2e%2e%2fsecret"
	v, err = DefaultBuiltInHandler(context.Background(), env)
	if err != nil || v.Severity != "high" || len(v.Findings) != 1 {
		t.Fatalf("encoded traversal not detected: %+v, %v", v, err)
	}
}
