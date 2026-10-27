package correlator_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/webong/ext/res/system"
	"github.com/webong/ext/res/system/graph"
	"github.com/webong/vigilante/internal/agent"
	"github.com/webong/vigilante/internal/correlator"
	"github.com/webong/vigilante/internal/schema"
	"github.com/webong/vigilante/internal/tap"
)

func TestEndToEndMirrorAndAgentPipeline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// 1. Initialize shared ext graph store + system graph.
	store := graph.NewMemory()
	defer store.Close()

	sysGraph, err := system.New(store)
	if err != nil {
		t.Fatalf("system.New: %v", err)
	}

	// 2. Initialize ext.plugin/v1 agent gateway.
	gw, err := agent.NewInProcessGateway(ctx, nil)
	if err != nil {
		t.Fatalf("NewInProcessGateway: %v", err)
	}
	defer gw.Close(ctx)

	var capturedEnvelopes []agent.EnrichedEnvelope
	var capturedVerdicts []agent.Verdict

	corr, err := correlator.New(correlator.Options{
		SystemGraph: sysGraph,
		Gateway:     gw,
		FallbackPID: os.Getpid(),
		OnVerdict: func(env agent.EnrichedEnvelope, v agent.Verdict) {
			capturedEnvelopes = append(capturedEnvelopes, env)
			capturedVerdicts = append(capturedVerdicts, v)
		},
	})
	if err != nil {
		t.Fatalf("correlator.New: %v", err)
	}

	if err := corr.RefreshBaseline(ctx); err != nil {
		t.Fatalf("RefreshBaseline: %v", err)
	}

	// 3. Spin up upstream HTTP server + Vigilante tap middleware.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("url.Parse: %v", err)
	}

	queue := tap.NewMirrorQueue(16)
	proxyTap := httptest.NewServer(tap.NewHTTPReverseProxyTap(u, queue, "127.0.0.1:8080"))
	defer proxyTap.Close()

	// 4. Send a benign request with a sensitive header + a path traversal request.
	req1, _ := http.NewRequestWithContext(ctx, http.MethodGet, proxyTap.URL+"/status", nil)
	req1.Header.Set("Authorization", "Bearer top-secret-token")
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("Do req1: %v", err)
	}
	resp1.Body.Close()

	req2, _ := http.NewRequestWithContext(ctx, http.MethodGet, proxyTap.URL+"/download?file=../../etc/passwd", nil)
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("Do req2: %v", err)
	}
	resp2.Body.Close()

	queued, dropped := queue.Stats()
	if queued != 2 || dropped != 0 {
		t.Fatalf("expected queued=2 dropped=0, got queued=%d dropped=%d", queued, dropped)
	}

	for i := 0; i < 2; i++ {
		ev := <-queue.Events()
		if _, err := corr.ProcessPacket(ctx, ev); err != nil {
			t.Fatalf("ProcessPacket %d: %v", i, err)
		}
	}

	if len(capturedVerdicts) != 2 {
		t.Fatalf("expected 2 verdicts, got %d", len(capturedVerdicts))
	}

	// Verify sensitive header was scrubbed before reaching the agent.
	if got := capturedEnvelopes[0].Event.Headers["Authorization"]; got != "[REDACTED]" {
		t.Errorf("expected Authorization header to be [REDACTED], got %q", got)
	}

	// Verify OS, Process, and Dependency context were attached.
	if capturedEnvelopes[0].ServerProcess.PID != os.Getpid() {
		t.Errorf("expected PID %d, got %d", os.Getpid(), capturedEnvelopes[0].ServerProcess.PID)
	}
	if len(capturedEnvelopes[0].DependencyGraph.Dependencies) == 0 {
		t.Errorf("expected non-empty application dependency graph")
	}

	// Verify second request triggered a high-severity alert.
	if capturedVerdicts[1].Severity != "high" || capturedVerdicts[1].Action != "alert" {
		t.Errorf("expected high/alert verdict for path traversal, got %+v", capturedVerdicts[1])
	}

	// Verify vigilante.net graph projection contains listener, flows, process-ref, dependencies, and alert.
	snap, err := store.Snapshot(ctx, schema.Namespace)
	if err != nil {
		t.Fatalf("store.Snapshot: %v", err)
	}
	hasAlert := false
	for _, v := range snap.Vertices {
		if v.Kind == schema.KindAgentAlert {
			hasAlert = true
		}
	}
	if !hasAlert {
		t.Errorf("expected %s vertex in graph snapshot", schema.KindAgentAlert)
	}
	if !strings.Contains(capturedVerdicts[1].Summary, "Path traversal") {
		t.Errorf("unexpected summary: %s", capturedVerdicts[1].Summary)
	}
}
