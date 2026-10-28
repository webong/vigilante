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
//	          timeout: 2
//	          failOpen: true
package traefik

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
)

// Config is the Traefik plugin configuration.
type Config struct {
	// Endpoint is the Vigilante sidecar base URL (e.g. http://127.0.0.1:9090).
	Endpoint string `json:"endpoint,omitempty"`
	// Timeout bounds one decision call, in seconds. Default 2.
	Timeout int `json:"timeout,omitempty"`
	// FailOpen forwards the request when the sidecar is unreachable.
	// Default true so a sidecar outage never takes the site down.
	FailOpen *bool `json:"failOpen,omitempty"`
}

// CreateConfig returns the plugin defaults.
func CreateConfig() *Config {
	failOpen := true
	return &Config{Timeout: 2, FailOpen: &failOpen}
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
	Action string `json:"action"`
	Rule   string `json:"rule,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// Vigilante is the Traefik middleware handler.
type Vigilante struct {
	next     http.Handler
	endpoint string
	client   *http.Client
	failOpen bool
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

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 2
	}
	failOpen := true
	if config.FailOpen != nil {
		failOpen = *config.FailOpen
	}

	return &Vigilante{
		next:     next,
		endpoint: endpoint,
		client:   &http.Client{Timeout: time.Duration(timeout) * time.Second},
		failOpen: failOpen,
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

	body, err := json.Marshal(meta)
	if err != nil {
		return v.fallback()
	}

	ctx, cancel := context.WithTimeout(req.Context(), v.client.Timeout)
	defer cancel()

	call, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint+"/v1/decide", bytes.NewReader(body))
	if err != nil {
		return v.fallback()
	}
	call.Header.Set("Content-Type", "application/json")

	resp, err := v.client.Do(call)
	if err != nil {
		return v.fallback()
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
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
