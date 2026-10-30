package main

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/webong/vigilante/internal/history"
	"github.com/webong/vigilante/internal/identity"
	httpResponse "github.com/webong/vigilante/internal/response"
)

type runtimeKey struct{}

func responseFromContext(ctx context.Context) httpResponse.Handler {
	h, _ := ctx.Value(runtimeKey{}).(httpResponse.Handler)
	return h
}
func withResponseRuntime(ctx context.Context, h httpResponse.Handler) context.Context {
	return context.WithValue(ctx, runtimeKey{}, h)
}

type httpGate struct{ gate func(*http.Request) string }

func (g httpGate) Decide(r *http.Request) string {
	if g.gate == nil {
		return "allow"
	}
	return g.gate(r)
}
func optionalVerifier(enabled bool) *identity.Verifier {
	if !enabled {
		return nil
	}
	return identity.New(nil, nil)
}
func runHistoryMaintenance(ctx context.Context, store *history.Store, retention time.Duration) {
	if retention <= 0 {
		retention = 7 * 24 * time.Hour
	}
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = store.Prune(ctx, time.Now().Add(-retention))
		}
	}
}
func parseTrustedProxies(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			addr, err := netip.ParseAddr(part)
			if err != nil {
				return nil, err
			}
			part = addr.String() + "/" + strconv.Itoa(addr.BitLen())
		}
		prefix, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, err
		}
		out = append(out, prefix.Masked())
	}
	return out, nil
}
func trustedRequest(r *http.Request, trusted []netip.Prefix) *http.Request {
	if len(trusted) == 0 {
		return r
	}
	ip := clientIP(r.RemoteAddr)
	if !trustedIP(ip, trusted) {
		return r
	}
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		hop := strings.TrimSpace(hops[i])
		if !trustedIP(hop, trusted) {
			clone := r.Clone(r.Context())
			clone.RemoteAddr = net.JoinHostPort(hop, "0")
			return clone
		}
	}
	return r
}
func trustedIP(raw string, trusted []netip.Prefix) bool {
	ip, err := netip.ParseAddr(strings.Trim(raw, "[]"))
	if err != nil {
		return false
	}
	for _, prefix := range trusted {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
func clientIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err == nil {
		return host
	}
	return strings.Trim(addr, "[]")
}
