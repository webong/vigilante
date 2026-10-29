// Package traefik is a Traefik middleware plugin that asks a Vigilante
// sidecar for an allow/deny/block decision before forwarding a request.
//
// Traefik loads plugins through Yaegi (interpreted Go), so this file is
// deliberately self-contained: standard library only, no Vigilante imports.
// The decision comes from the sidecar's POST /v1/decide endpoint, which runs
// the same policy engine and agent pipeline as the standalone gateway.
//
// Install: copy this directory to a Traefik plugin Git repository (or use the
// experimental `localPlugins` setting), then:
//
//	http:
//	  middlewares:
//	    vigilante:
//	      plugin:
//	        vigilante:
//	          endpoint: http://127.0.0.1:9090
//	          timeoutMs: 50
//	          failOpen: true
//	          cacheTTL: 1
package traefik

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config is the Traefik plugin configuration.
type Config struct {
	// Endpoint is the Vigilante sidecar base URL (e.g. http://127.0.0.1:9090).
	Endpoint string `json:"endpoint,omitempty"`
	// Timeout bounds one decision call, in seconds. This is the legacy field:
	// leave it zero and use TimeoutMs, which defaults to 50ms.
	Timeout int `json:"timeout,omitempty"`
	// TimeoutMs bounds one decision call, in milliseconds. Default 50. A
	// blocking middleware must never wait seconds to fail open: a slow sidecar
	// should cost a blink, not a stall.
	TimeoutMs int `json:"timeoutMs,omitempty"`
	// FailOpen forwards the request when the sidecar is unreachable.
	// Default true so a sidecar outage never takes the site down.
	FailOpen *bool `json:"failOpen,omitempty"`
	// CacheTTL reuses "allow" decisions for the same method, host, path, query,
	// and client address for this many seconds. Default 1. Zero disables it.
	// Only cacheable decisions (no header-dependent rules) and only allows are
	// cached, so tightening a policy takes effect within one TTL.
	CacheTTL int `json:"cacheTTL,omitempty"`
	// CacheSize bounds cached decisions. Default 4096.
	CacheSize int `json:"cacheSize,omitempty"`
	// Token is sent as "Authorization: Bearer <token>" when the sidecar
	// requires authentication.
	Token string `json:"token,omitempty"`
	// ForwardHeaders are request headers sent to the sidecar so header-based
	// policy rules work. Default ["User-Agent", "Content-Type", "X-Forwarded-Proto"].
	ForwardHeaders []string `json:"forwardHeaders,omitempty"`
}

// CreateConfig returns the plugin defaults.
func CreateConfig() *Config {
	failOpen := true
	return &Config{
		TimeoutMs:      50,
		FailOpen:       &failOpen,
		CacheTTL:       1,
		CacheSize:      4096,
		ForwardHeaders: []string{"User-Agent", "Content-Type", "X-Forwarded-Proto"},
	}
}

type requestMeta struct {
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	Query      string            `json:"query,omitempty"`
	Host       string            `json:"host,omitempty"`
	RemoteAddr string            `json:"remote_addr,omitempty"`
	Scheme     string            `json:"scheme,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
}

type decision struct {
	Action    string `json:"action"`
	Rule      string `json:"rule,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Cacheable bool   `json:"cacheable,omitempty"`
}

// Vigilante is the Traefik middleware handler.
type Vigilante struct {
	next           http.Handler
	endpoint       string
	client         *http.Client
	failOpen       bool
	token          string
	forwardHeaders []string
	cache          *decisionCache
}

// New builds the middleware. Traefik calls it once per configured instance.
func New(_ context.Context, next http.Handler, config *Config, _ string) (http.Handler, error) {
	if next == nil {
		return nil, errors.New("vigilante: next handler is required")
	}
	if config == nil {
		config = CreateConfig()
	}
	endpoint := strings.TrimRight(strings.TrimSpace(config.Endpoint), "/")
	if endpoint == "" {
		return nil, errors.New("vigilante: endpoint is required")
	}

	timeout := 50 * time.Millisecond
	switch {
	case config.Timeout > 0:
		timeout = time.Duration(config.Timeout) * time.Second
	case config.TimeoutMs > 0:
		timeout = time.Duration(config.TimeoutMs) * time.Millisecond
	}
	failOpen := true
	if config.FailOpen != nil {
		failOpen = *config.FailOpen
	}
	headers := config.ForwardHeaders
	if len(headers) == 0 {
		headers = []string{"User-Agent", "Content-Type", "X-Forwarded-Proto"}
	}

	return &Vigilante{
		next:           next,
		endpoint:       endpoint,
		client:         &http.Client{Timeout: timeout},
		failOpen:       failOpen,
		token:          strings.TrimSpace(config.Token),
		forwardHeaders: headers,
		cache: newDecisionCache(
			time.Duration(config.CacheTTL)*time.Second,
			config.CacheSize,
		),
	}, nil
}

func (v *Vigilante) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	d := v.decide(req)
	if d.Action == "deny" || d.Action == "block" {
		http.Error(rw, "forbidden", http.StatusForbidden)
		return
	}
	v.next.ServeHTTP(rw, req)
}

func (v *Vigilante) decide(req *http.Request) decision {
	meta := v.metaFor(req)

	if v.cache != nil {
		if cached, ok := v.cache.get(meta); ok {
			return cached
		}
	}

	d := v.ask(req.Context(), meta)
	// Only an allow is cached, and only when the sidecar says the verdict did
	// not depend on a header. A deny is always asked again so tightening a
	// policy is immediate.
	if v.cache != nil && d.Cacheable && d.Action == "allow" {
		v.cache.put(meta, d)
	}
	return d
}

func (v *Vigilante) metaFor(req *http.Request) requestMeta {
	meta := requestMeta{
		Method:     req.Method,
		Path:       req.URL.Path,
		Query:      req.URL.RawQuery,
		Host:       req.Host,
		RemoteAddr: req.RemoteAddr,
		Scheme:     "http",
	}
	if req.TLS != nil {
		meta.Scheme = "https"
	}
	if forwarded := req.Header.Get("X-Forwarded-For"); forwarded != "" {
		if i := strings.IndexByte(forwarded, ','); i >= 0 {
			meta.RemoteAddr = strings.TrimSpace(forwarded[:i])
		} else {
			meta.RemoteAddr = strings.TrimSpace(forwarded)
		}
	}
	if len(v.forwardHeaders) > 0 {
		meta.Headers = make(map[string]string, len(v.forwardHeaders))
		for _, name := range v.forwardHeaders {
			if value := req.Header.Get(name); value != "" {
				meta.Headers[name] = value
			}
		}
	}
	return meta
}

func (v *Vigilante) ask(ctx context.Context, meta requestMeta) decision {
	body, err := json.Marshal(meta)
	if err != nil {
		return v.fallback()
	}

	call, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint+"/v1/decide", bytes.NewReader(body))
	if err != nil {
		return v.fallback()
	}
	call.Header.Set("Content-Type", "application/json")
	if v.token != "" {
		call.Header.Set("Authorization", "Bearer "+v.token)
	}

	resp, err := v.client.Do(call)
	if err != nil {
		return v.fallback()
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		// Misconfigured token: fail closed rather than silently allowing.
		return decision{Action: "deny", Reason: "sidecar rejected credentials"}
	default:
		return v.fallback()
	}

	var d decision
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&d); err != nil {
		return v.fallback()
	}
	return d
}

func (v *Vigilante) fallback() decision {
	if v.failOpen {
		return decision{Action: "allow", Reason: "fail-open"}
	}
	return decision{Action: "deny", Reason: "fail-closed"}
}

// decisionCache is a bounded TTL cache of allow decisions.
type decisionCache struct {
	mu    sync.Mutex
	items map[string]cacheEntry
	max   int
	ttl   time.Duration
}

type cacheEntry struct {
	decision decision
	expires  time.Time
}

func newDecisionCache(ttl time.Duration, max int) *decisionCache {
	if ttl <= 0 {
		return nil
	}
	if max <= 0 {
		max = 4096
	}
	return &decisionCache{items: make(map[string]cacheEntry, 64), max: max, ttl: ttl}
}

func (c *decisionCache) get(meta requestMeta) (decision, bool) {
	if c == nil {
		return decision{}, false
	}
	key := meta.cacheKey()
	c.mu.Lock()
	item, ok := c.items[key]
	c.mu.Unlock()
	if !ok || time.Now().After(item.expires) {
		return decision{}, false
	}
	return item.decision, true
}

func (c *decisionCache) put(meta requestMeta, d decision) {
	if c == nil {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) >= c.max {
		for k, item := range c.items {
			if now.After(item.expires) {
				delete(c.items, k)
			}
		}
		for k := range c.items {
			if len(c.items) < c.max {
				break
			}
			delete(c.items, k)
		}
	}
	c.items[meta.cacheKey()] = cacheEntry{
		decision: d,
		expires:  now.Add(c.ttl),
	}
}

func (m requestMeta) cacheKey() string {
	return m.Method + "\x00" + strings.ToLower(m.Host) + "\x00" + m.Path + "\x00" +
		m.Query + "\x00" + clientKey(m.RemoteAddr)
}

// clientKey is the full client address. Collapsing to a /24 would let an allow
// cached for one address mask a narrower deny rule for a neighbour.
func clientKey(addr string) string {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return strings.ToLower(strings.TrimSpace(host))
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}
