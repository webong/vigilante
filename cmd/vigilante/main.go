// Command vigilante brings an agent into the network stack by mirroring incoming
// HTTP/TCP traffic into a non-blocking pipeline, enriching each flow with OS,
// server process, network topology, application dependency graphs, and indexed
// GitHub/local codebase context via github.com/webong/ext, and dispatching it
// to an ext.plugin/v1 agent.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/webong/ext/res/system"
	"github.com/webong/ext/res/system/graph"
	"github.com/webong/ext/res/system/supervisor"
	"github.com/webong/vigilante/internal/agent"
	"github.com/webong/vigilante/internal/correlator"
	"github.com/webong/vigilante/internal/repo"
	"github.com/webong/vigilante/internal/schema"
	"github.com/webong/vigilante/internal/tap"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "vigilante:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("vigilante", flag.ContinueOnError)
	fs.SetOutput(out)

	mode := fs.String("mode", "demo", "Execution mode: demo, http, tcp, or agent-worker")
	listenAddr := fs.String("listen", "127.0.0.1:8080", "Address for vigilante middleware to listen on")
	targetAddr := fs.String("target", "http://127.0.0.1:9000", "Upstream server URL (for http) or host:port (for tcp)")
	repoTarget := fs.String("repo", ".", "Git repo target to index for codebase awareness: any host URL (https/ssh/git/file://, scp-like git@host:path), owner/repo or host/owner/repo shorthand, or a local path")
	repoRef := fs.String("repo-ref", "", "Branch or tag to shallow-clone for -repo (empty = remote default branch)")
	repoUser := fs.String("repo-user", "", "HTTPS username for private -repo clones (default: x-access-token, or VIGILANTE_GIT_USER)")
	repoToken := fs.String("repo-token", "", "HTTPS auth token for private -repo clones (prefer the VIGILANTE_GIT_TOKEN env var to keep it out of argv)")
	repoSSHKey := fs.String("repo-ssh-key", "", "Path to an SSH private key for private ssh:// or git@ clones of -repo (default: VIGILANTE_GIT_SSH_KEY env var / ssh-agent)")
	graphFile := fs.String("graph-file", "", "Optional path to persist the ext + vigilante graph JSON store")
	queueSize := fs.Int("queue-size", 256, "Bounded packet mirror ring-buffer capacity")
	supervisedAgent := fs.Bool("supervised-agent", false, "Launch agent out-of-process via ext/res/system/supervisor + jsonline IPC")
	agentIPC := fs.String("agent-ipc", "", "Internal IPC address when running in -mode agent-worker")

	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if *mode == "agent-worker" {
		if *agentIPC == "" {
			return fmt.Errorf("-agent-ipc is required for -mode agent-worker")
		}
		return agent.RunWorkerIPC(ctx, *agentIPC, nil)
	}

	var store graph.Store
	var err error
	if *graphFile != "" {
		store, err = graph.OpenFile(*graphFile)
		if err != nil {
			return fmt.Errorf("open graph file: %w", err)
		}
	} else {
		store = graph.NewMemory()
	}
	defer store.Close()

	sysGraph, err := system.New(store)
	if err != nil {
		return fmt.Errorf("init ext.system graph: %w", err)
	}

	var repoIdx *repo.Index
	if *repoTarget != "" {
		repoOpts := repo.Options{
			Ref:    *repoRef,
			User:   firstNonEmpty(*repoUser, os.Getenv("VIGILANTE_GIT_USER")),
			Token:  firstNonEmpty(*repoToken, os.Getenv("VIGILANTE_GIT_TOKEN")),
			SSHKey: firstNonEmpty(*repoSSHKey, os.Getenv("VIGILANTE_GIT_SSH_KEY")),
		}
		fmt.Fprintf(out, "[vigilante] indexing codebase repository %q...", *repoTarget)
		sshTarget := strings.HasPrefix(*repoTarget, "git@") || strings.HasPrefix(*repoTarget, "ssh://")
		switch {
		case repoOpts.Token != "" && !sshTarget:
			fmt.Fprintln(out, " (auth: HTTPS token via GIT_ASKPASS helper)")
		case repoOpts.SSHKey != "" && sshTarget:
			fmt.Fprintf(out, " (auth: ssh key %s)\n", repoOpts.SSHKey)
		default:
			fmt.Fprintln(out, " (auth: configured git credential helpers / ssh-agent)")
		}
		repoIdx, err = repo.OpenWithOptions(ctx, *repoTarget, repoOpts)
		if err != nil {
			return fmt.Errorf("index repo %q: %w", *repoTarget, err)
		}
		defer repoIdx.Close()
		snap := repoIdx.Snapshot()
		fmt.Fprintf(out, "[vigilante] codebase indexed: %d files, %d routes, %d sinks (commit %s, tree %s...)\n",
			snap.FileCount, len(snap.Routes), len(snap.Sinks), snap.Commit, shortHash(snap.TreeDigest))
	}

	var gw *agent.Gateway
	if *supervisedAgent {
		fmt.Fprintln(out, "[vigilante] starting out-of-process supervised agent via github.com/webong/ext/res/system/supervisor...")
		gw, _, err = agent.NewSupervisedGateway(ctx, agent.SupervisedOptions{
			Store:           store,
			Repo:            repoIdx,
			RequireChecksum: true,
		})
	} else {
		gw, err = agent.NewInProcessGateway(ctx, store, repoIdx, nil)
	}
	if err != nil {
		return fmt.Errorf("init ext.plugin/v1 agent gateway: %w", err)
	}
	defer gw.Close(context.Background())

	corr, err := correlator.New(correlator.Options{
		SystemGraph: sysGraph,
		Gateway:     gw,
		Repo:        repoIdx,
		FallbackPID: os.Getpid(),
		OnVerdict: func(env agent.EnrichedEnvelope, v agent.Verdict) {
			printVerdict(out, env, v)
		},
	})
	if err != nil {
		return fmt.Errorf("init correlator: %w", err)
	}

	fmt.Fprintln(out, "[vigilante] scanning OS, processes, and network topology via github.com/webong/ext/res/system...")
	if err := corr.RefreshBaseline(ctx); err != nil {
		return fmt.Errorf("refresh baseline: %w", err)
	}

	switch *mode {
	case "demo":
		return runDemo(ctx, out, corr, store, *supervisedAgent)
	case "http":
		return runHTTPProxy(ctx, out, corr, *listenAddr, *targetAddr, *queueSize)
	case "tcp":
		return runTCPProxy(ctx, out, corr, *listenAddr, *targetAddr, *queueSize)
	default:
		return fmt.Errorf("unsupported mode %q (choose demo, http, tcp, or agent-worker)", *mode)
	}
}

func runDemo(ctx context.Context, out io.Writer, corr *correlator.Correlator, store graph.Store, supervised bool) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/api/v1/files", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"file":%q}`, r.URL.Query().Get("name"))
	})
	mux.HandleFunc("/api/v1/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"authenticated":false}`))
	})

	upstream := httptest.NewServer(mux)
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		return err
	}

	queue := tap.NewMirrorQueue(64)
	middlewareServer := httptest.NewServer(tap.NewHTTPReverseProxyTap(upstreamURL, queue, "127.0.0.1:0"))
	defer middlewareServer.Close()

	fmt.Fprintf(out, "[vigilante] demo middleware active -> mirroring traffic to upstream %s\n\n", upstreamURL.Host)

	client := &http.Client{Timeout: 5 * time.Second}
	requests := []struct {
		method string
		path   string
		body   string
		header map[string]string
	}{
		{
			method: http.MethodGet,
			path:   "/api/v1/health",
			header: map[string]string{"Authorization": "Bearer super-secret-jwt"},
		},
		{
			method: http.MethodGet,
			path:   "/api/v1/files?name=../../../../etc/passwd",
		},
		{
			method: http.MethodPost,
			path:   "/api/v1/login",
			body:   `{"username":"admin' UNION SELECT password FROM users--"}`,
		},
	}

	for _, reqSpec := range requests {
		req, err := http.NewRequestWithContext(ctx, reqSpec.method, middlewareServer.URL+reqSpec.path, strings.NewReader(reqSpec.body))
		if err != nil {
			return err
		}
		for k, v := range reqSpec.header {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	queued, _ := queue.Stats()
	for i := uint64(0); i < queued; i++ {
		ev := <-queue.Events()
		if _, err := corr.ProcessPacket(ctx, ev); err != nil {
			return err
		}
	}

	vigSnap, err := store.Snapshot(ctx, schema.Namespace)
	if err != nil {
		return err
	}
	sysSnap, err := store.Snapshot(ctx, system.Namespace)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "\n[vigilante] graph summary:\n")
	fmt.Fprintf(out, "  • %s namespace: %d vertices, %d edges (revision %d)\n",
		sysSnap.Namespace, len(sysSnap.Vertices), len(sysSnap.Edges), sysSnap.Revision)
	fmt.Fprintf(out, "  • %s namespace: %d vertices, %d edges (revision %d)\n",
		vigSnap.Namespace, len(vigSnap.Vertices), len(vigSnap.Edges), vigSnap.Revision)
	if supervised {
		if rtSnap, err := store.Snapshot(ctx, supervisor.RuntimeNamespace); err == nil {
			fmt.Fprintf(out, "  • %s namespace: %d vertices, %d edges (revision %d)\n",
				rtSnap.Namespace, len(rtSnap.Vertices), len(rtSnap.Edges), rtSnap.Revision)
		}
	}
	return nil
}

func runHTTPProxy(ctx context.Context, out io.Writer, corr *correlator.Correlator, listenAddr, targetRaw string, queueSize int) error {
	if !strings.Contains(targetRaw, "://") {
		targetRaw = "http://" + targetRaw
	}
	targetURL, err := url.Parse(targetRaw)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	queue := tap.NewMirrorQueue(queueSize)
	queue.Drain(ctx, 2, func(ctx context.Context, ev agent.PacketEvent) {
		_, _ = corr.ProcessPacket(ctx, ev)
	})

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: tap.NewHTTPReverseProxyTap(targetURL, queue, listenAddr),
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	fmt.Fprintf(out, "[vigilante] HTTP tap listening on %s -> forwarding to %s\n", listenAddr, targetURL.String())
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func runTCPProxy(ctx context.Context, out io.Writer, corr *correlator.Correlator, listenAddr, targetAddr string, queueSize int) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	queue := tap.NewMirrorQueue(queueSize)
	queue.Drain(ctx, 2, func(ctx context.Context, ev agent.PacketEvent) {
		_, _ = corr.ProcessPacket(ctx, ev)
	})

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	fmt.Fprintf(out, "[vigilante] TCP tap listening on %s -> forwarding to %s\n", listenAddr, targetAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func(c net.Conn) {
			_ = tap.ProxyTCPConn(ctx, c, listenAddr, targetAddr, queue)
		}(conn)
	}
}

func printVerdict(out io.Writer, env agent.EnrichedEnvelope, v agent.Verdict) {
	record := map[string]any{
		"flow_id":                v.FlowID,
		"trigger":                env.TriggerReason,
		"severity":               v.Severity,
		"action":                 v.Action,
		"summary":                v.Summary,
		"method":                 env.Event.Method,
		"path":                   env.Event.Path,
		"os":                     env.OS.OS + "/" + env.OS.Arch,
		"hostname":               env.OS.Hostname,
		"server_pid":             env.ServerProcess.PID,
		"server_process":         env.ServerProcess.Name,
		"dep_count":              len(env.DependencyGraph.Dependencies),
		"net_interfaces":         len(env.NetworkTopology.Interfaces),
		"graph_revision":         env.GraphRevision,
		"reverse_graph_queried":  v.ReverseGraphQueried,
		"reverse_observed_nodes": v.ReverseObservedNodes,
	}
	if v.MatchedHandler != "" {
		record["matched_handler"] = v.MatchedHandler
	}
	if v.InspectedSource != "" {
		record["inspected_source"] = v.InspectedSource
	}
	if len(v.MatchedAdvisories) > 0 {
		record["matched_advisories"] = v.MatchedAdvisories
	}
	if len(v.Recommendations) > 0 {
		record["recommendations"] = v.Recommendations
	}
	encoded, _ := json.MarshalIndent(record, "", "  ")
	fmt.Fprintln(out, string(encoded))
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
