// Command vigilante brings an agent into the network stack by mirroring incoming
// HTTP/TCP traffic into a non-blocking pipeline, enriching each flow with OS,
// server process, network topology, and application dependency graphs via
// github.com/webong/ext, and dispatching it to an ext.plugin/v1 agent.
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
	"github.com/webong/vigilante/internal/agent"
	"github.com/webong/vigilante/internal/correlator"
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

	mode := fs.String("mode", "demo", "Execution mode: demo, http, or tcp")
	listenAddr := fs.String("listen", "127.0.0.1:8080", "Address for vigilante middleware to listen on")
	targetAddr := fs.String("target", "http://127.0.0.1:9000", "Upstream server URL (for http) or host:port (for tcp)")
	graphFile := fs.String("graph-file", "", "Optional path to persist the ext + vigilante graph JSON store")
	queueSize := fs.Int("queue-size", 256, "Bounded packet mirror ring-buffer capacity")

	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

	gw, err := agent.NewInProcessGateway(ctx, nil)
	if err != nil {
		return fmt.Errorf("init ext.plugin/v1 agent gateway: %w", err)
	}
	defer gw.Close(context.Background())

	corr, err := correlator.New(correlator.Options{
		SystemGraph: sysGraph,
		Gateway:     gw,
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
		return runDemo(ctx, out, corr, store)
	case "http":
		return runHTTPProxy(ctx, out, corr, *listenAddr, *targetAddr, *queueSize)
	case "tcp":
		return runTCPProxy(ctx, out, corr, *listenAddr, *targetAddr, *queueSize)
	default:
		return fmt.Errorf("unsupported mode %q (choose demo, http, or tcp)", *mode)
	}
}

func runDemo(ctx context.Context, out io.Writer, corr *correlator.Correlator, store graph.Store) error {
	// Start a local demo upstream HTTP application server.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"status":"ok","path":%q}`, r.URL.Path)
	}))
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

	// Process mirrored events synchronously in demo mode so output is deterministic.
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
		"flow_id":        v.FlowID,
		"trigger":        env.TriggerReason,
		"severity":       v.Severity,
		"action":         v.Action,
		"summary":        v.Summary,
		"method":         env.Event.Method,
		"path":           env.Event.Path,
		"os":             env.OS.OS + "/" + env.OS.Arch,
		"hostname":       env.OS.Hostname,
		"server_pid":     env.ServerProcess.PID,
		"server_process": env.ServerProcess.Name,
		"dep_count":      len(env.DependencyGraph.Dependencies),
		"net_interfaces": len(env.NetworkTopology.Interfaces),
		"graph_revision": env.GraphRevision,
	}
	if len(v.Recommendations) > 0 {
		record["recommendations"] = v.Recommendations
	}
	encoded, _ := json.MarshalIndent(record, "", "  ")
	fmt.Fprintln(out, string(encoded))
}
