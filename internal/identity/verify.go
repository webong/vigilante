// Package identity verifies claimed crawler and signed AI-agent identities.
// Network lookups run only in the asynchronous analysis pipeline.
package identity

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/webong/vigilante/internal/flow"
)

type Result struct {
	Verified string `json:"verified,omitempty"`
	Failed   string `json:"failed,omitempty"`
}
type Resolver interface {
	LookupAddr(context.Context, string) ([]string, error)
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}
type Verifier struct {
	wba      *WebBotAuth
	resolver Resolver
	mu       sync.Mutex
	dns      map[string]entry
}
type entry struct {
	result Result
	at     time.Time
}

func New(client HTTPClient, resolver Resolver) *Verifier {
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return &Verifier{wba: NewWebBotAuth(client), resolver: resolver, dns: map[string]entry{}}
}
func (v *Verifier) Identify(ctx context.Context, ev flow.Event) Result {
	if v == nil {
		return Result{}
	}
	h := header(ev.Headers, "signature-input")
	if h != "" {
		origin, err := v.wba.Verify(ctx, ev)
		switch {
		case err == nil:
			return Result{Verified: strings.TrimPrefix(origin, "https://") + " (Web Bot Auth signature)"}
		case errors.Is(err, ErrNoSignature):
		case errors.Is(err, ErrDirectoryUnavailable):
			return Result{}
		default:
			return Result{Failed: "Web Bot Auth signature failed: " + err.Error()}
		}
	}
	agent, ok := claimedAgent(ev.UserAgent)
	if !ok || len(agent.domains) == 0 {
		return Result{}
	}
	ip := clientIP(ev.SrcAddr)
	if ip == "" {
		return Result{}
	}
	key := ip + "|" + agent.token
	v.mu.Lock()
	cached, ok := v.dns[key]
	v.mu.Unlock()
	if ok && time.Since(cached.at) < 6*time.Hour {
		return cached.result
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result, cacheable := v.reverseDNS(ctx, ip, agent)
	if cacheable {
		v.mu.Lock()
		v.dns[key] = entry{result: result, at: time.Now()}
		v.mu.Unlock()
	}
	return result
}
func (v *Verifier) reverseDNS(ctx context.Context, ip string, a agent) (Result, bool) {
	names, err := v.resolver.LookupAddr(ctx, ip)
	var dnsErr *net.DNSError
	if err != nil && !(errors.As(err, &dnsErr) && dnsErr.IsNotFound) {
		return Result{}, false
	}
	want := strings.Join(a.domains, " or ")
	if len(names) == 0 {
		return Result{Failed: fmt.Sprintf("Claims to be %s but %s has no reverse DNS; expected %s", a.token, ip, want)}, true
	}
	for _, name := range names {
		host := strings.TrimSuffix(strings.ToLower(name), ".")
		if !slices.ContainsFunc(a.domains, func(d string) bool { return host == d || strings.HasSuffix(host, "."+d) }) {
			continue
		}
		addrs, err := v.resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return Result{}, false
		}
		for _, addr := range addrs {
			if addr.IP.String() == ip {
				return Result{Verified: a.token + " via reverse DNS (" + host + ")"}, true
			}
		}
	}
	return Result{Failed: fmt.Sprintf("Claims to be %s but %s resolves to %s, not %s", a.token, ip, names[0], want)}, true
}

type agent struct {
	token   string
	kind    string
	domains []string
}

var knownAgents = []agent{
	{token: "Googlebot", kind: "search", domains: []string{"googlebot.com", "google.com"}}, {token: "Google-CloudVertexBot", kind: "ai", domains: []string{"google.com"}},
	{token: "bingbot", kind: "search", domains: []string{"search.msn.com"}}, {token: "Applebot", kind: "search", domains: []string{"applebot.apple.com"}},
	{token: "YandexBot", kind: "search", domains: []string{"yandex.ru", "yandex.net", "yandex.com"}}, {token: "Baiduspider", kind: "search", domains: []string{"baidu.com", "baidu.jp"}},
	{token: "DuckDuckBot", kind: "search"}, {token: "Amazonbot", kind: "ai", domains: []string{"crawl.amazonbot.amazon"}},
	{token: "GPTBot", kind: "ai"}, {token: "OAI-SearchBot", kind: "ai"}, {token: "ChatGPT-User", kind: "ai"}, {token: "ChatGPT Agent", kind: "ai"},
	{token: "ClaudeBot", kind: "ai"}, {token: "Claude-SearchBot", kind: "ai"}, {token: "Claude-User", kind: "ai"}, {token: "PerplexityBot", kind: "ai"},
	{token: "Perplexity-User", kind: "ai"}, {token: "MistralAI-User", kind: "ai"}, {token: "DuckAssistBot", kind: "ai"}, {token: "meta-externalagent", kind: "ai"},
	{token: "Bytespider", kind: "ai"}, {token: "CCBot", kind: "ai"}, {token: "cohere-ai", kind: "ai"}, {token: "Diffbot", kind: "ai"},
}

func claimedAgent(ua string) (agent, bool) {
	for _, a := range knownAgents {
		if strings.Contains(strings.ToLower(ua), strings.ToLower(a.token)) {
			return a, true
		}
	}
	return agent{}, false
}
func IsAI(ua string) bool { a, ok := claimedAgent(ua); return ok && a.kind == "ai" }
func header(h map[string]string, key string) string {
	for k, v := range h {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}
func clientIP(s string) string {
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	ip := net.ParseIP(strings.Trim(s, "[]"))
	if ip == nil {
		return ""
	}
	return ip.String()
}
