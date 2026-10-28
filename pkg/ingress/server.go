package ingress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Server exposes a Decider over HTTP for ingress hosts that cannot link Go
// code (nginx, Traefik's Yaegi plugins, OpenResty/Lua, Envoy ext_authz, ...).
//
// Endpoints:
//
//	POST /v1/decide   JSON RequestMeta -> JSON Decision (always 200)
//	POST /v1/check    -> 204 allow, 403 deny/block (for nginx auth_request)
//	POST /v1/observe  -> 202 accepted (for nginx mirror; never blocks traffic)
//	GET  /healthz     -> 200 "ok"
//	GET  /ready       -> 200 "ready"
//	GET  /metrics     -> Prometheus text
type Server struct {
	decider *Decider
	handler http.Handler
	srv     *http.Server
}

// NewServer builds a sidecar around d listening on addr (e.g. ":9090").
// An empty addr still builds the handler; call Handler to mount it yourself.
func NewServer(d *Decider, addr string) *Server {
	s := &Server{decider: d}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/decide", s.handleDecide)
	mux.HandleFunc("/v1/check", s.handleCheck)
	mux.HandleFunc("/v1/observe", s.handleObserve)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ready")
	})
	mux.HandleFunc("/metrics", s.handleMetrics)
	s.handler = mux
	s.srv = &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return s
}

// Handler returns the sidecar mux for embedding in another server.
func (s *Server) Handler() http.Handler { return s.handler }

// Addr returns the configured listen address.
func (s *Server) Addr() string { return s.srv.Addr }

// ListenAndServe blocks serving the sidecar.
func (s *Server) ListenAndServe() error {
	if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Shutdown gracefully stops the sidecar.
func (s *Server) Shutdown(ctx context.Context) error { return s.srv.Shutdown(ctx) }

func (s *Server) handleDecide(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	meta, err := metaFromSidecarRequest(r)
	if err != nil {
		http.Error(w, "invalid request descriptor", http.StatusBadRequest)
		return
	}
	decision := s.decider.Decide(meta)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(decision)
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	meta, err := metaFromSidecarRequest(r)
	if err != nil {
		// Fail open on a malformed descriptor: an ingress must not become a
		// self-inflicted outage because a header was missing.
		w.WriteHeader(http.StatusNoContent)
		return
	}
	switch s.decider.Decide(meta).Action {
	case Deny, Block:
		w.WriteHeader(http.StatusForbidden)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleObserve(w http.ResponseWriter, r *http.Request) {
	if meta, err := metaFromSidecarRequest(r); err == nil {
		s.decider.Observe(meta)
	}
	w.WriteHeader(http.StatusAccepted)
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	st := s.decider.Stats()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "vigilante_ingress_observed_total %d\n", st.Observed)
	fmt.Fprintf(w, "vigilante_ingress_denied_total %d\n", st.Denied)
	fmt.Fprintf(w, "vigilante_ingress_blocked_total %d\n", st.Blocked)
	if q := s.decider.Queue(); q != nil {
		queued, dropped := q.Stats()
		fmt.Fprintf(w, "vigilante_queue_enqueued_total %d\n", queued)
		fmt.Fprintf(w, "vigilante_queue_dropped_total %d\n", dropped)
		fmt.Fprintf(w, "vigilante_queue_sampled_out_total %d\n", q.SampledOut())
	}
}

// metaFromSidecarRequest accepts either a JSON RequestMeta body (used by
// Traefik and custom clients) or proxy headers (used by nginx auth_request and
// mirror), which carry no body.
func metaFromSidecarRequest(r *http.Request) (RequestMeta, error) {
	meta := MetaFromRequest(r)

	if r.Body != nil && r.ContentLength != 0 {
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			return meta, err
		}
		_ = r.Body.Close()
		if len(body) > 0 {
			var explicit RequestMeta
			if err := json.Unmarshal(body, &explicit); err == nil && explicit.Method != "" {
				return explicit, nil
			}
			meta.BodyPreview = string(body)
			meta.BodyBytes = len(body)
		}
	}

	if meta.Method == "" || meta.Path == "" {
		return meta, errors.New("describe the request in a JSON body or X-Original-URI header")
	}
	return meta, nil
}
