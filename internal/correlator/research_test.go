package correlator

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/webong/vigilante/ext/agent"
	"github.com/webong/vigilante/internal/deps"
)

func TestResearchSnapshotIsIncludedAndCached(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls%2 == 1 {
			_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"TEST-1"}]}]}`))
		} else {
			_, _ = w.Write([]byte(`{"vulns":[{"id":"TEST-1","summary":"full detail"}]}`))
		}
	}))
	defer server.Close()
	c := &Correlator{advisoryClient: &deps.OSVClient{BatchURL: server.URL, URL: server.URL}, research: make(map[string]*researchEntry)}
	proc := ProcessEntry{Process: agent.ServerProcessContext{PID: 42, StartID: "start"}, Deps: deps.Graph{Dependencies: []deps.Module{{Ecosystem: "npm", Path: "express", Version: "4.18.2"}}}}
	for i := 0; i < 2; i++ {
		got := c.researchSnapshot(context.Background(), proc)
		if got.Status != "ready" || got.CheckedCount != 1 || len(got.Candidates) != 1 || got.Candidates[0].Advisories[0].ID != "TEST-1" {
			t.Fatalf("research: %+v", got)
		}
	}
	if calls != 2 {
		t.Fatalf("expected one batch and one detail request, got %d", calls)
	}
}
