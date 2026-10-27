// Package gateway adapts Vigilante's mirror tap to act as the relay handler for
// an ingress built on github.com/webong/gateway (Spinner). Spinner owns the
// public listener, forwarding, and (optionally) the PHP Planner; Vigilante
// observes every proxied request non-blockingly and dispatches enriched flows
// to its ext.plugin/v1 agent.
//
// The adapter intentionally mirrors Spinner's configuration surface (port,
// upstream forwarding, TLS, planner endpoint, body limits, worker pool) instead
// of importing github.com/webong/gateway/pkg/spinner, which is a separate Go
// module with local replace directives and heavy runtime dependencies
// (arranger/bridge/automation). Deploy it as a companion process or embed it
// via the exported handler builders.
package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/webong/vigilante/internal/agent"
	"github.com/webong/vigilante/internal/tap"
)

// Options configures a Vigilante-backed Spinner-style ingress.
type Options struct {
	// ListenAddr is the public listener, e.g. ":8080".
	ListenAddr string
	// TargetURL is the upstream origin to forward to, e.g. "http://127.0.0.1:3000".
	TargetURL string
	// PlannerURL optionally points at a webong/gateway Planner for route
	// decisions; when empty, traffic is forwarded straight to TargetURL.
	PlannerURL string
	// InternalToken authenticates requests to the Planner (Spinner parity).
	InternalToken string
	// TLSCertFile / TLSKeyFile enable HTTPS on the public listener.
	TLSCertFile string
	TLSKeyFile  string
	// MaxBodyBytes caps the mirrored body preview (Spinner MaxBodySize parity).
	MaxBodyBytes int
	// QueueSize is the mirror ring-buffer capacity.
	QueueSize int
	// Workers drains the mirror queue into the observer callback.
	Workers int
}

// Server is a Vigilante ingress: Spinner-compatible listener semantics with
// the Vigilante mirror tap as the relay observation point.
type Server struct {
	opts     Options
	queue    *tap.MirrorQueue
	relay    http.Handler
	httpSrv  *http.Server
	observed atomic.Uint64
	// extraMetrics, when set, appends additional metric lines to /metrics
	// (e.g. alert store counters).
	extraMetrics func(http.ResponseWriter)
}

// SetExtraMetrics registers a callback that writes additional metric lines to
// the /metrics endpoint.
func (s *Server) SetExtraMetrics(fn func(http.ResponseWriter)) {
	s.extraMetrics = fn
}

// NewServer builds the ingress. observe is invoked for every mirrored request.
func NewServer(opts Options, observe func(context.Context, agent.PacketEvent)) (*Server, error) {
	if opts.ListenAddr == "" {
		return nil, fmt.Errorf("gateway: listen address is required")
	}
	if opts.TargetURL == "" {
		return nil, fmt.Errorf("gateway: target URL is required")
	}
	targetURL, err := url.Parse(opts.TargetURL)
	if err != nil {
		return nil, fmt.Errorf("gateway: invalid target URL: %w", err)
	}

	queueSize := opts.QueueSize
	if queueSize <= 0 {
		queueSize = 256
	}
	queue := tap.NewMirrorQueue(queueSize)

	s := &Server{opts: opts, queue: queue}
	s.relay = s.buildRelay(targetURL)

	workers := opts.Workers
	if workers <= 0 {
		workers = 2
	}
	if observe != nil {
		queue.Drain(context.Background(), workers, func(ctx context.Context, ev agent.PacketEvent) {
			s.observed.Add(1)
			observe(ctx, ev)
		})
	}

	s.httpSrv = &http.Server{
		Addr:         opts.ListenAddr,
		Handler:      s.handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return s, nil
}

// handler composes health endpoints with the Vigilante relay (Spinner parity:
// /health, /ready, /metrics on the Go host in every mode).
func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		queued, dropped := s.queue.Stats()
		fmt.Fprintf(w, "vigilante_queue_enqueued_total %d\nvigilante_queue_dropped_total %d\nvigilante_requests_observed_total %d\n",
			queued, dropped, s.observed.Load())
		if s.extraMetrics != nil {
			s.extraMetrics(w)
		}
	})
	mux.Handle("/", s.relay)
	return mux
}

// buildRelay forwards each request to the upstream target while cloning it into
// the mirror queue (redacting sensitive headers, bounding the body preview).
// When a Planner is configured the request is first offered to the Planner for
// a route decision; a Planner failure falls back to direct forwarding.
func (s *Server) buildRelay(targetURL *url.URL) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}
	listen := s.opts.ListenAddr
	target := targetURL.Host

	if s.opts.PlannerURL == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tap.PreviewRequest(s.queue, r, listen, target)
			proxy.ServeHTTP(w, r)
		})
	}

	plannerURL := strings.TrimRight(s.opts.PlannerURL, "/")
	client := &http.Client{Timeout: 5 * time.Second}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tap.PreviewRequest(s.queue, r, listen, target)

		// Spinner bridge parity: consult the Planner for a route plan first.
		// The plan itself only influences upstream selection; the original
		// request is forwarded regardless so a Planner outage never blocks
		// traffic (fail-open, consistent with the mirror queue posture).
		planReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
			plannerURL+"/_internal/gateway/plan", r.Body)
		if err == nil {
			planReq.Header = r.Header.Clone()
			planReq.Header.Set("X-Gateway-Internal-Token", s.opts.InternalToken)
			planReq.Header.Set("Content-Type", "application/json")
			if resp, perr := client.Do(planReq); perr == nil {
				_ = resp.Body.Close()
			}
		}
		proxy.ServeHTTP(w, r)
	})
}

// ListenAndServe starts the ingress, terminating TLS when cert/key are set.
func (s *Server) ListenAndServe() error {
	if s.opts.TLSCertFile != "" && s.opts.TLSKeyFile != "" {
		s.httpSrv.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		return s.httpSrv.ListenAndServeTLS(s.opts.TLSCertFile, s.opts.TLSKeyFile)
	}
	return s.httpSrv.ListenAndServe()
}

// Shutdown gracefully stops the ingress.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpSrv.Shutdown(ctx)
}

// Queue exposes the mirror queue for callers that need stats or to drain it
// with their own correlator.
func (s *Server) Queue() *tap.MirrorQueue {
	return s.queue
}
