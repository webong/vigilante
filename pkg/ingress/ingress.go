// Package ingress is the vendor-neutral decision core shared by Vigilante's
// ingress adapters (Caddy, Traefik, nginx, or any other proxy). It turns a
// request descriptor into an allow/deny/block decision using the same policy
// engine and mirror pipeline as the standalone Vigilante gateway, and can run
// as a small HTTP sidecar for hosts that cannot link Go code.
//
// Adapters should not re-implement policy or redaction: they describe the
// request with RequestMeta and call Decide (in-process) or POST /v1/decide
// (sidecar).
package ingress

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/webong/vigilante/ext/agent"
	"github.com/webong/vigilante/ext/tap"
	"github.com/webong/vigilante/internal/policy"
)

// Action is the enforcement decision returned to an ingress adapter.
type Action string

const (
	// Allow forwards the request (default posture).
	Allow Action = "allow"
	// Deny rejects the request without mirroring it (403).
	Deny Action = "deny"
	// Block mirrors the request for triage, then rejects it (403).
	Block Action = "block"
)

// RequestMeta is the host-independent description of one inbound request.
// Adapters populate what their proxy exposes; everything is optional except
// Method and Path.
type RequestMeta struct {
	Method      string            `json:"method"`
	Path        string            `json:"path"`
	Query       string            `json:"query,omitempty"`
	Host        string            `json:"host,omitempty"`
	RemoteAddr  string            `json:"remote_addr,omitempty"`
	Scheme      string            `json:"scheme,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	BodyPreview string            `json:"body_preview,omitempty"`
	BodyBytes   int               `json:"body_bytes,omitempty"`
}

// Decision is the verdict an adapter acts on.
type Decision struct {
	Action Action `json:"action"`
	Rule   string `json:"rule,omitempty"`
	Reason string `json:"reason,omitempty"`
	// Cacheable reports that the decision depends only on method, host, path,
	// query, and client address — never on a header. An adapter may then reuse
	// it for other requests with the same coarse key until its own TTL expires.
	Cacheable bool `json:"cacheable,omitempty"`
}

// Allowed reports whether the request may be forwarded.
func (d Decision) Allowed() bool { return d.Action == Allow }

// Config wires a Decider to optional policy and observation.
type Config struct {
	// Policy is the compiled rule engine. Nil means default-allow.
	Policy *policy.Engine
	// Queue receives a redacted observation for every request. Nil disables
	// in-process observation.
	Queue *tap.MirrorQueue
	// ListenAddr / TargetAddr label observations (the public and upstream
	// addresses) so the correlator can attribute the flow.
	ListenAddr string
	TargetAddr string
	// CacheTTL memoizes decisions for repeat requests with the same method,
	// host, path, query, and client address. Zero disables the cache. A
	// header-sensitive policy is never cached.
	CacheTTL time.Duration
	// CacheSize bounds cached decisions (default 4096).
	CacheSize int
}

// Decider evaluates requests against policy and feeds the mirror pipeline.
// It is safe for concurrent use.
type Decider struct {
	cfg      Config
	cache    *decisionCache
	observed atomic.Uint64
	denied   atomic.Uint64
	blocked  atomic.Uint64
}

// New builds a Decider.
func New(cfg Config) *Decider {
	return &Decider{
		cfg:   cfg,
		cache: newDecisionCache(cfg.CacheTTL, cfg.CacheSize),
	}
}

// Policy returns the configured engine (may be nil).
func (d *Decider) Policy() *policy.Engine { return d.cfg.Policy }

// Queue returns the configured mirror queue (may be nil).
func (d *Decider) Queue() *tap.MirrorQueue { return d.cfg.Queue }

// Decide evaluates meta and, for block/allow, mirrors the observation. Denied
// requests are not mirrored (they never reach the application).
//
// When the configured policy is cacheable and Config.CacheTTL is set, a repeat
// request with the same coarse key reuses the verdict but still mirrors the
// observation, so triage never sees a gap.
func (d *Decider) Decide(meta RequestMeta) Decision {
	d.observed.Add(1)

	if d.cfg.Policy == nil {
		d.Observe(meta)
		return Decision{Action: Allow, Cacheable: true}
	}

	epoch := d.cfg.Policy.Epoch()
	cacheable := d.cache != nil && d.cfg.Policy.DecisionCacheable()
	var key string
	if cacheable {
		// A reload invalidates the cache wholesale: the salt changes and every
		// old entry is dropped rather than lingering for its TTL.
		d.cache.syncEpoch(epoch)
		key = cacheKey(meta)
		if cached, ok := d.cache.get(key); ok {
			// A reload can land between reading the epoch and the cache lookup.
			// Reuse the entry only while the policy still names the same snapshot.
			if d.cfg.Policy.Epoch() == epoch {
				d.note(cached.Action)
				if cached.Action != Deny {
					d.Observe(meta)
				}
				return cached
			}
		}
	}

	v, evalEpoch, evalCacheable := d.cfg.Policy.EvaluateSnapshot(meta.Request())
	var dec Decision
	switch v.Action {
	case policy.ActionDeny:
		dec = Decision{Action: Deny, Rule: v.Rule, Reason: "denied by policy"}
	case policy.ActionBlock:
		// Mirror first so triage sees the offending request, then reject.
		d.Observe(meta)
		dec = Decision{Action: Block, Rule: v.Rule, Reason: "blocked by policy"}
	default:
		d.Observe(meta)
		dec = Decision{Action: Allow, Rule: v.Rule}
	}
	dec.Cacheable = evalCacheable
	if d.cache != nil && evalCacheable {
		if key == "" {
			key = cacheKey(meta)
		}
		d.cache.syncEpoch(evalEpoch)
		// Do not let a verdict from the previous snapshot enter the new epoch.
		if d.cfg.Policy.Epoch() == evalEpoch {
			d.cache.put(key, dec)
		}
	}
	d.note(dec.Action)
	return dec
}

func (d *Decider) note(action Action) {
	switch action {
	case Deny:
		d.denied.Add(1)
	case Block:
		d.blocked.Add(1)
	}
}

// Observe enqueues a redacted observation without making a decision. It is the
// primitive for proxies that only mirror traffic (nginx's mirror module).
func (d *Decider) Observe(meta RequestMeta) {
	if d.cfg.Queue == nil {
		return
	}
	ev := agent.PacketEvent{
		ObservationSource: "ingress",
		Visibility:        "application-plaintext",
		Timestamp:         time.Now().UTC(),
		Protocol:          "http",
		SrcAddr:           meta.RemoteAddr,
		DstAddr:           d.cfg.ListenAddr,
		TargetAddr:        d.cfg.TargetAddr,
		Method:            meta.Method,
		Path:              meta.Path,
		Headers:           meta.Headers,
		PayloadPreview:    meta.BodyPreview,
		PayloadBytes:      meta.BodyBytes,
	}
	if meta.Query != "" {
		ev.Path += "?" + meta.Query
	}
	ev.Redact()
	d.cfg.Queue.Enqueue(ev)
}

// Stats reports counters for /metrics.
type Stats struct {
	Observed uint64 `json:"observed"`
	Denied   uint64 `json:"denied"`
	Blocked  uint64 `json:"blocked"`
	Cached   int    `json:"cached"`
}

// Stats returns a snapshot of decision counters.
func (d *Decider) Stats() Stats {
	return Stats{
		Observed: d.observed.Load(),
		Denied:   d.denied.Load(),
		Blocked:  d.blocked.Load(),
		Cached:   d.cache.len(),
	}
}

// Request builds a synthetic *http.Request for policy evaluation only. It is
// never served, so it carries no body.
func (m RequestMeta) Request() *http.Request {
	path := m.Path
	if path == "" {
		path = "/"
	}
	u := &url.URL{Path: path, RawQuery: m.Query}
	req := &http.Request{
		Method:     m.Method,
		URL:        u,
		Host:       m.Host,
		RemoteAddr: m.RemoteAddr,
		Header:     make(http.Header, len(m.Headers)),
	}
	if req.Method == "" {
		req.Method = http.MethodGet
	}
	for k, v := range m.Headers {
		req.Header.Set(k, v)
	}
	return req
}

// ClientIP normalizes the best available client address for policy matching.
func (m RequestMeta) ClientIP() net.IP {
	return policy.SourceIP(m.Request())
}

// MaxPreviewBytes bounds how much request body a sidecar reads when it must
// describe the request itself.
const MaxPreviewBytes = 1024

// MetaFromRequest describes an inbound *http.Request for adapters that sit in
// front of a real request (Caddy, or a sidecar receiving forwarded requests).
// It reads at most MaxPreviewBytes of the body and restores it, and prefers
// proxy-supplied origin headers over the hop-by-hop view.
func MetaFromRequest(r *http.Request) RequestMeta {
	meta := RequestMeta{
		Method:     r.Method,
		Path:       r.URL.Path,
		Query:      r.URL.RawQuery,
		Host:       r.Host,
		RemoteAddr: r.RemoteAddr,
		Scheme:     "http",
	}
	if r.TLS != nil {
		meta.Scheme = "https"
	}

	// Prefer the original request as seen by the front proxy.
	if v := header(r, "X-Original-Method"); v != "" {
		meta.Method = v
	}
	if v := header(r, "X-Original-URI"); v != "" {
		if p, q, ok := strings.Cut(v, "?"); ok {
			meta.Path, meta.Query = p, q
		} else {
			meta.Path = v
		}
	} else if v := header(r, "X-Forwarded-Uri"); v != "" {
		if p, q, ok := strings.Cut(v, "?"); ok {
			meta.Path, meta.Query = p, q
		} else {
			meta.Path = v
		}
	}
	if v := header(r, "X-Forwarded-Host"); v != "" {
		meta.Host = v
	}
	if v := header(r, "X-Forwarded-Proto"); v != "" {
		meta.Scheme = v
	}

	// Client address: first X-Forwarded-For hop, then X-Real-IP, then socket.
	if v := header(r, "X-Forwarded-For"); v != "" {
		first, _, _ := strings.Cut(v, ",")
		meta.RemoteAddr = strings.TrimSpace(first)
	} else if v := header(r, "X-Real-IP"); v != "" {
		meta.RemoteAddr = strings.TrimSpace(v)
	}

	if len(r.Header) > 0 {
		meta.Headers = make(map[string]string, len(r.Header))
		for k, vals := range r.Header {
			meta.Headers[k] = strings.Join(vals, ", ")
		}
	}

	return meta
}

func header(r *http.Request, name string) string {
	if v := r.Header.Get(name); v != "" {
		return v
	}
	return ""
}
