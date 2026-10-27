package correlator_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/webong/ext/res/system"
	"github.com/webong/ext/res/system/graph"
	"github.com/webong/ext/res/system/supervisor"
	"github.com/webong/vigilante/internal/agent"
	"github.com/webong/vigilante/internal/correlator"
	"github.com/webong/vigilante/internal/deps"
	"github.com/webong/vigilante/internal/repo"
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

	// 2. Index a sample codebase directory with route handlers and file/SQL sinks.
	repoDir := t.TempDir()
	sampleServerCode := `package main

import (
	"net/http"
	"os"
)

func main() {
	http.HandleFunc("/status", handleStatus)
	http.HandleFunc("/download", handleDownload)
}

func handleDownload(w http.ResponseWriter, r *http.Request) {
	data, _ := os.ReadFile(r.URL.Query().Get("file"))
	w.Write(data)
}
`
	if err := os.WriteFile(filepath.Join(repoDir, "server.go"), []byte(sampleServerCode), 0600); err != nil {
		t.Fatal(err)
	}

	repoIdx, err := repo.Open(ctx, repoDir)
	if err != nil {
		t.Fatalf("repo.Open: %v", err)
	}
	defer repoIdx.Close()

	// 3. Initialize ext.plugin/v1 agent gateway with Reverse Host Graph + Source Read support.
	gw, err := agent.NewInProcessGateway(ctx, store, repoIdx, nil)
	if err != nil {
		t.Fatalf("NewInProcessGateway: %v", err)
	}
	defer gw.Close(ctx)

	var capturedEnvelopes []agent.EnrichedEnvelope
	var capturedVerdicts []agent.Verdict

	corr, err := correlator.New(correlator.Options{
		SystemGraph: sysGraph,
		Gateway:     gw,
		Repo:        repoIdx,
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

	// 4. Spin up upstream HTTP server + Vigilante tap middleware.
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

	// 5. Send a benign request with a sensitive header + a path traversal request hitting /download.
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

	// Verify second request triggered a high-severity alert, matched the /download route in server.go,
	// AND executed both reverse host calls (query-graph and read-source).
	if capturedVerdicts[1].Severity != "high" || capturedVerdicts[1].Action != "alert" {
		t.Errorf("expected high/alert verdict for path traversal, got %+v", capturedVerdicts[1])
	}
	if capturedVerdicts[1].MatchedHandler != "server.go:10" {
		t.Errorf("expected MatchedHandler server.go:10, got %q", capturedVerdicts[1].MatchedHandler)
	}
	if !strings.Contains(capturedVerdicts[1].InspectedSource, `http.HandleFunc("/download", handleDownload)`) {
		t.Errorf("expected agent to read source snippet via reverse call, got %q", capturedVerdicts[1].InspectedSource)
	}
	if !capturedVerdicts[1].ReverseGraphQueried || capturedVerdicts[1].ReverseObservedNodes == 0 {
		t.Errorf("expected agent to execute reverse host graph query on high-severity alert, got queried=%v nodes=%d",
			capturedVerdicts[1].ReverseGraphQueried, capturedVerdicts[1].ReverseObservedNodes)
	}

	// Verify vigilante.net graph projection contains codebase, route-handler, listener, flows, process-ref, dependencies, and alert.
	snap, err := store.Snapshot(ctx, schema.Namespace)
	if err != nil {
		t.Fatalf("store.Snapshot: %v", err)
	}
	hasAlert := false
	hasCodebase := false
	hasRoute := false
	for _, v := range snap.Vertices {
		switch v.Kind {
		case schema.KindAgentAlert:
			hasAlert = true
		case schema.KindCodebase:
			hasCodebase = true
		case schema.KindRouteHandler:
			hasRoute = true
		}
	}
	if !hasAlert || !hasCodebase || !hasRoute {
		t.Errorf("expected alert=%v codebase=%v route=%v in graph snapshot", hasAlert, hasCodebase, hasRoute)
	}
	if !strings.Contains(capturedVerdicts[1].Summary, "Path traversal") {
		t.Errorf("unexpected summary: %s", capturedVerdicts[1].Summary)
	}
}

func TestSupervisedOutOfProcessAgentAndReverseQuery(t *testing.T) {
	if os.Getenv("VIGILANTE_TEST_WORKER") == "1" {
		ipc := os.Getenv("VIGILANTE_AGENT_IPC")
		if err := agent.RunWorkerIPC(context.Background(), ipc, nil); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	store := graph.NewMemory()
	defer store.Close()

	sysGraph, err := system.New(store)
	if err != nil {
		t.Fatalf("system.New: %v", err)
	}
	// Observe current process so ext.system has process-resource nodes for reverse queries.
	if snap, err := system.InspectProcess(ctx, os.Getpid(), system.ProcessOptions{MaxResources: 128, Timeout: 3 * time.Second}); err == nil {
		_ = sysGraph.ObserveProcesses(ctx, snap)
	}

	// Launch this test binary as a supervised agent subprocess via ext/res/system/supervisor.
	testExe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	secretResolved := false
	gw, sup, err := agent.NewSupervisedGateway(ctx, agent.SupervisedOptions{
		Store:   store,
		Command: testExe,
		Args:    []string{"-test.run=^TestSupervisedOutOfProcessAgentAndReverseQuery$"},
		Environment: map[string]string{
			"VIGILANTE_TEST_WORKER": "1",
		},
		SecretRefs: map[string]supervisor.SecretReference{
			"LLM_API_KEY": {Scope: "keychain", ID: "vigilante-agent-key"},
		},
		SecretResolver: func(_ context.Context, ref supervisor.SecretReference) (string, error) {
			if ref.Scope == "keychain" && ref.ID == "vigilante-agent-key" {
				secretResolved = true
				return "sk-ephemeral-resolved-secret", nil
			}
			return "", os.ErrNotExist
		},
		RequireChecksum: true,
	})
	if err != nil {
		t.Fatalf("NewSupervisedGateway: %v", err)
	}
	defer gw.Close(ctx)
	defer sup.Close(ctx)

	if !secretResolved {
		t.Errorf("expected supervisor SecretResolver to be called for LLM_API_KEY")
	}

	verdict, err := gw.Triage(ctx, agent.EnrichedEnvelope{
		Event: agent.PacketEvent{
			FlowID: "flow-supervised-1",
			Method: "GET",
			Path:   "/../../etc/passwd",
		},
		ServerProcess: agent.ServerProcessContext{
			PID:        os.Getpid(),
			Name:       "vigilante-test",
			Executable: testExe,
		},
	})
	if err != nil {
		t.Fatalf("supervised gw.Triage: %v", err)
	}
	if verdict.Severity != "high" || !verdict.ReverseGraphQueried || verdict.ReverseObservedNodes == 0 {
		t.Errorf("expected high severity and reverse graph query over jsonline IPC, got %+v", verdict)
	}
}

func TestMultiEcosystemLockfilesAndAdvisoryMatching(t *testing.T) {
	tmp := t.TempDir()

	// Write sample package-lock.json with vulnerable express 4.18.2 and lodash 4.17.20
	pkgLock := `{
  "name": "payments-service",
  "packages": {
    "node_modules/express": { "version": "4.18.2" },
    "node_modules/lodash": { "version": "4.17.20" }
  }
}`
	if err := os.WriteFile(filepath.Join(tmp, "package-lock.json"), []byte(pkgLock), 0600); err != nil {
		t.Fatal(err)
	}

	// Write sample Cargo.lock and requirements.txt
	cargoLock := `[[package]]
name = "tokio"
version = "1.38.0"
`
	if err := os.WriteFile(filepath.Join(tmp, "Cargo.lock"), []byte(cargoLock), 0600); err != nil {
		t.Fatal(err)
	}

	reqTxt := "urllib3==2.0.5\nrequests>=2.31.0\n"
	if err := os.WriteFile(filepath.Join(tmp, "requirements.txt"), []byte(reqTxt), 0600); err != nil {
		t.Fatal(err)
	}

	g := deps.Inspect("", tmp, []string{"/usr/lib/libSystem.B.dylib"})
	if g.MainModule != "payments-service" {
		t.Errorf("expected MainModule payments-service, got %q", g.MainModule)
	}
	if len(g.Dependencies) < 5 {
		t.Fatalf("expected at least 5 dependencies across npm/cargo/pypi/shared-lib, got %d", len(g.Dependencies))
	}
	if len(g.Vulnerabilities) != 3 {
		t.Fatalf("expected 3 matched CVE advisories (express, lodash, urllib3), got %d: %+v", len(g.Vulnerabilities), g.Vulnerabilities)
	}
}
