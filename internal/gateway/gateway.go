// Package gateway provides Vigilante's ingress layer. It has two postures:
//
//   - local: Vigilante owns the public listener and forwarding, optionally
//     consulting an upstream route planner for decisions.
//   - external: Vigilante attaches to an existing ingress/gateway process at
//     ExternalURL and mirrors the traffic it carries (the peer keeps owning
//     the listener and routing).
//
// The package is deliberately vendor-neutral: it does not depend on any
// specific gateway product. Vigilante's mirror tap is the relay observation
// point in both postures, dispatching enriched flows to its ext.plugin/v1
// agent.
package gateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/webong/vigilante/ext/agent"
	"github.com/webong/vigilante/ext/tap"
)

// Mode selects how Vigilante's ingress relates to a peer gateway/ingress.
//
// Vigilante does not depend on any specific gateway product. It supports two
// runtime postures: attach to an existing ingress process (external), or run
// Vigilante's own ingress (local).
type Mode string

const (
	// ModeLocal runs Vigilante's own built-in ingress — no external ingress
	// process required. Vigilante owns the gateway and can consult a route
	// planner via PlannerURL for decisions.
	ModeLocal Mode = "local"
	// ModeExternal attaches to an already-running ingress/gateway process at
	// ExternalURL: that peer keeps owning the public listener and routing, and
	// Vigilante's mirror tap observes the traffic flowing through it. This is
	// the recommended posture when you already run a gateway.
	ModeExternal Mode = "external"
)

// ParseMode validates a gateway posture string.
func ParseMode(s string) (Mode, error) {
	switch Mode(strings.ToLower(strings.TrimSpace(s))) {
	case "", ModeLocal, "embedded": // "embedded" accepted as a legacy alias for local
		return ModeLocal, nil
	case ModeExternal, "companion": // "companion" accepted as a legacy alias for external
		return ModeExternal, nil
	default:
		return "", fmt.Errorf("gateway: unknown posture %q (local, external:<url>)", s)
	}
}

// Options configures Vigilante's ingress.
type Options struct {
	Mode Mode
	// ListenAddr is the public listener (local mode), e.g. ":8080".
	ListenAddr string
	// ExternalURL is the endpoint of an existing ingress/gateway process
	// (external mode), e.g. "http://gw.internal:5001". Traffic is
	// observed/forwarded there.
	ExternalURL string
	// TargetURL is the upstream origin to forward to, e.g. "http://127.0.0.1:3000".
	TargetURL string
	// PlannerURL optionally points at an upstream route planner for decisions;
	// when empty, traffic is forwarded straight to TargetURL.
	PlannerURL string
	// InternalToken authenticates requests to the route planner.
	InternalToken string
	// TLSCertFile / TLSKeyFile enable HTTPS on the public listener.
	TLSCertFile string
	TLSKeyFile  string
	// MaxBodyBytes caps the mirrored body preview.
	MaxBodyBytes int
	// QueueSize is the mirror ring-buffer capacity.
	QueueSize int
	// Workers drains the mirror queue into the observer callback.
	Workers int
}

// Server is Vigilante's ingress: listener semantics with the Vigilante mirror
// tap as the relay observation point.
type Server struct {
	opts     Options
	queue    *tap.MirrorQueue
	relay    http.Handler
	httpSrv  *http.Server
	observed atomic.Uint64
	// extraMetrics, when set, appends additional metric lines to /metrics
	// (e.g. alert store counters).
	extraMetrics func(http.ResponseWriter)
	// mounts holds optional path->handler mounts (e.g. the obs plugin bridge)
	// added after construction; read at request time by the lazy handler.
	mu       sync.RWMutex
	mount    map[string]http.Handler
	baseOnce sync.Once
	baseH    http.Handler
}

// SetExtraMetrics registers a callback that writes additional metric lines to
// the /metrics endpoint.
func (s *Server) SetExtraMetrics(fn func(http.ResponseWriter)) {
	s.extraMetrics = fn
}

// SetHandlerMount mounts an additional handler at prefix (e.g. "/obs") on the
// ingress mux. Safe to call after NewServer; takes effect on subsequent
// requests. Stripping of the prefix is the caller's responsibility.
func (s *Server) SetHandlerMount(prefix string, h http.Handler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mount == nil {
		s.mount = map[string]http.Handler{}
	}
	s.mount[prefix] = h
}

// NewServer builds the ingress. observe is invoked for every mirrored request.
func NewServer(opts Options, observe func(context.Context, agent.PacketEvent)) (*Server, error) {
	mode, err := ParseMode(string(opts.Mode))
	if err != nil {
		return nil, err
	}
	opts.Mode = mode

	// External mode attaches to an existing ingress endpoint; there is no
	// local listener to own, so ListenAddr/TargetURL requirements differ.
	if mode == ModeExternal {
		if opts.ExternalURL == "" && opts.TargetURL == "" {
			return nil, fmt.Errorf("gateway: external posture requires an external endpoint or target URL")
		}
	} else {
		if opts.ListenAddr == "" {
			return nil, fmt.Errorf("gateway: listen address is required")
		}
		if opts.TargetURL == "" {
			return nil, fmt.Errorf("gateway: target URL is required")
		}
	}

	// Resolve the forward destination: external forwards to the existing
	// ingress (so its router/planner still owns routing); local mode
	// forwards to the configured upstream target.
	forwardRaw := opts.TargetURL
	if mode == ModeExternal && opts.ExternalURL != "" {
		forwardRaw = opts.ExternalURL
	}
	forwardURL, err := url.Parse(forwardRaw)
	if err != nil {
		return nil, fmt.Errorf("gateway: invalid forward URL %q: %w", forwardRaw, err)
	}

	queueSize := opts.QueueSize
	if queueSize <= 0 {
		queueSize = 256
	}
	queue := tap.NewMirrorQueue(queueSize)

	s := &Server{opts: opts, queue: queue}
	s.relay = s.buildRelay(forwardURL)

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
		Handler:      s,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return s, nil
}

// ServeHTTP implements http.Handler: it checks registered mounts (obs plugin)
// first, then falls back to the composed status+relay mux.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	mounts := s.mount
	s.mu.RUnlock()
	for prefix, h := range mounts {
		if r.URL.Path == prefix || strings.HasPrefix(r.URL.Path, prefix+"/") {
			http.StripPrefix(prefix, h).ServeHTTP(w, r)
			return
		}
	}
	s.base().ServeHTTP(w, r)
}

// base lazily composes the status+relay mux exactly once per server.
func (s *Server) base() http.Handler {
	s.baseOnce.Do(func() { s.baseH = s.handler() })
	return s.baseH
}

// handler composes health endpoints with the Vigilante relay (/health,
// /ready, /metrics on the Go host in every mode).
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

		// Consult the route planner for a plan first. The plan only influences
		// upstream selection; the original request is forwarded regardless so a
		// planner outage never blocks traffic (fail-open, consistent with the
		// mirror queue posture).
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

// Mode returns the configured ingress mode.
func (s *Server) Mode() Mode { return s.opts.Mode }

// ListenAndServe starts the ingress, terminating TLS when cert/key are set.
// External mode has no local listener (it observes an existing ingress), so
// it is a no-op that blocks until ctx cancellation via Shutdown.
func (s *Server) ListenAndServe() error {
	if s.opts.Mode == ModeExternal {
		// Nothing to serve locally; the observer queue is already draining.
		// Block forever until Shutdown is called.
		<-make(chan struct{})
		return nil
	}
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
