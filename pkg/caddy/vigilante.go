// Package vigilante is a Caddy HTTP handler module that runs Vigilante's
// request-policy and mirror pipeline inside Caddy.
//
// Build it into Caddy with xcaddy:
//
//	xcaddy build --with github.com/webong/vigilante/pkg/caddy
//
// Caddyfile:
//
//	vigilante {
//		policy /etc/vigilante/policy.yaml
//		mirror http://127.0.0.1:9090
//	}
//
// JSON config uses the module id http.handlers.vigilante.
package vigilante

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"github.com/webong/vigilante/internal/policy"
	"github.com/webong/vigilante/pkg/ingress"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("vigilante", parseCaddyfile)
}

// Middleware enforces Vigilante policy on every request before it reaches the
// upstream, and optionally mirrors each request to a Vigilante sidecar for
// full agent triage.
type Middleware struct {
	// Policy is the path to a Vigilante policy file (YAML or JSON). Required
	// unless Endpoint is set.
	Policy string `json:"policy,omitempty"`
	// Endpoint delegates the decision to a running Vigilante sidecar
	// (e.g. "http://127.0.0.1:9090"). When set, Policy is ignored and the
	// sidecar owns policy and agent triage.
	Endpoint string `json:"endpoint,omitempty"`
	// Mirror is an optional sidecar base URL that receives every request on
	// /v1/observe for observation, independent of the decision path.
	Mirror string `json:"mirror,omitempty"`
	// FailOpen forwards the request when the sidecar is unreachable. Default true.
	FailOpen *bool `json:"fail_open,omitempty"`
	// Timeout bounds one sidecar decision. Default 50ms: a blocking middleware
	// must fail open in a blink, not stall the request for seconds.
	Timeout caddy.Duration `json:"timeout,omitempty"`
	// Token is sent as "Authorization: Bearer <token>" when the sidecar
	// requires authentication.
	Token string `json:"token,omitempty"`

	logger      *zap.Logger
	decider     *ingress.Decider
	client      *http.Client
	failOpen    bool
	policyWatch context.CancelFunc
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.vigilante",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// Provision prepares the decider or sidecar client.
func (m *Middleware) Provision(ctx caddy.Context) error {
	m.logger = ctx.Logger()
	m.failOpen = true
	if m.FailOpen != nil {
		m.failOpen = *m.FailOpen
	}

	timeout := time.Duration(m.Timeout)
	if timeout <= 0 {
		timeout = 50 * time.Millisecond
	}
	if m.Endpoint != "" || m.Mirror != "" {
		m.client = &http.Client{Timeout: timeout}
	}

	if m.Endpoint != "" {
		return nil
	}

	cfg := ingress.Config{}
	if m.Policy != "" {
		engine, err := policy.Load(m.Policy)
		if err != nil {
			return fmt.Errorf("vigilante: load policy %q: %w", m.Policy, err)
		}
		// Reload the file when it changes so a rule edit needs no Caddy reload
		// (which would briefly drop connections at the listener).
		engine.SetReloadHook(func(err error) {
			if err != nil {
				m.logger.Error("vigilante policy reload failed; keeping previous rules",
					zap.String("policy", m.Policy), zap.Error(err))
				return
			}
			m.logger.Info("vigilante policy reloaded", zap.String("policy", m.Policy))
		})
		watchCtx, cancel := context.WithCancel(ctx.Context)
		engine.Watch(watchCtx, 2*time.Second)
		m.policyWatch = cancel
		cfg.Policy = engine
	}
	m.decider = ingress.New(cfg)
	return nil
}

// Cleanup stops the policy file watcher when Caddy unloads the module.
func (m *Middleware) Cleanup() error {
	if m.policyWatch != nil {
		m.policyWatch()
		m.policyWatch = nil
	}
	return nil
}

// Validate checks that the module has a decision source.
func (m *Middleware) Validate() error {
	if m.Endpoint == "" && m.Policy == "" {
		return fmt.Errorf("vigilante: one of 'policy' or 'endpoint' is required")
	}
	return nil
}

// ServeHTTP enforces the decision before handing off to the next handler.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	meta := ingress.MetaFromRequest(r)
	decision := m.decide(r.Context(), meta)

	if m.Mirror != "" {
		m.mirror(meta)
	}

	switch decision.Action {
	case ingress.Deny, ingress.Block:
		m.logger.Debug("vigilante rejected request",
			zap.String("method", meta.Method),
			zap.String("path", meta.Path),
			zap.String("action", string(decision.Action)),
			zap.String("rule", decision.Rule),
		)
		w.WriteHeader(http.StatusForbidden)
		return nil
	}
	return next.ServeHTTP(w, r)
}

// decide prefers the in-process engine, then the sidecar, then fail-open.
func (m *Middleware) decide(ctx context.Context, meta ingress.RequestMeta) ingress.Decision {
	if m.decider != nil {
		return m.decider.Decide(meta)
	}

	body, err := json.Marshal(meta)
	if err != nil {
		return m.fallback(err)
	}
	url := strings.TrimRight(m.Endpoint, "/") + "/v1/decide"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return m.fallback(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if m.Token != "" {
		req.Header.Set("Authorization", "Bearer "+m.Token)
	}

	resp, err := m.client.Do(req)
	if err != nil {
		return m.fallback(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return ingress.Decision{Action: ingress.Deny, Reason: "sidecar rejected credentials"}
	}
	if resp.StatusCode != http.StatusOK {
		return m.fallback(fmt.Errorf("sidecar returned %s", resp.Status))
	}
	var d ingress.Decision
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&d); err != nil {
		return m.fallback(err)
	}
	return d
}

func (m *Middleware) fallback(err error) ingress.Decision {
	m.logger.Warn("vigilante decision unavailable", zap.Error(err), zap.Bool("fail_open", m.failOpen))
	if m.failOpen {
		return ingress.Decision{Action: ingress.Allow, Reason: "fail-open"}
	}
	return ingress.Decision{Action: ingress.Deny, Reason: "fail-closed"}
}

// mirror posts the observation asynchronously so the hot path never waits.
func (m *Middleware) mirror(meta ingress.RequestMeta) {
	if m.client == nil {
		return
	}
	body, err := json.Marshal(meta)
	if err != nil {
		return
	}
	url := strings.TrimRight(m.Mirror, "/") + "/v1/observe"
	go func() {
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := m.client.Do(req)
		if err != nil {
			return
		}
		_ = resp.Body.Close()
	}()
}

// UnmarshalCaddyfile parses the `vigilante { ... }` directive.
func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}
		for d.NextBlock(0) {
			switch d.Val() {
			case "policy":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Policy = d.Val()
			case "endpoint":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Endpoint = d.Val()
			case "mirror":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Mirror = d.Val()
			case "fail_open":
				if !d.NextArg() {
					return d.ArgErr()
				}
				raw, err := strconv.ParseBool(d.Val())
				if err != nil {
					return d.Errf("invalid fail_open %q: %v", d.Val(), err)
				}
				m.FailOpen = &raw
			case "timeout":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := time.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid timeout %q: %v", d.Val(), err)
				}
				m.Timeout = caddy.Duration(dur)
			case "token":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.Token = d.Val()
			default:
				return d.Errf("unrecognized vigilante option %q", d.Val())
			}
		}
	}
	return nil
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Middleware
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return &m, nil
}

var _ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
var _ caddy.Provisioner = (*Middleware)(nil)
var _ caddy.Validator = (*Middleware)(nil)
var _ caddy.CleanerUpper = (*Middleware)(nil)
var _ caddyfile.Unmarshaler = (*Middleware)(nil)
