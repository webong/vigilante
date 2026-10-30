// Package response provides optional in-process HTTP responses to decisions.
// Detection and storage are deliberately outside this package.
package response

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Gate interface{ Decide(*http.Request) string }
type Handler struct {
	Challenge *Challenger
	Limits    *Limiter
}

func (h Handler) Wrap(next http.Handler, gate Gate) http.Handler {
	return h.WrapWith(next, h, gate)
}
func (h Handler) WrapWith(next http.Handler, responses Handler, gate Gate) http.Handler {
	h = responses
	if h.Challenge == nil && h.Limits == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gate == nil {
			next.ServeHTTP(w, r)
			return
		}
		ip := ClientIP(r)
		if h.Challenge != nil && r.URL.Path == ChallengePath {
			h.Challenge.Verify(w, r, ip, time.Now())
			return
		}
		switch gate.Decide(r) {
		case "challenge":
			if h.Challenge == nil {
				http.Error(w, "challenge unavailable", http.StatusForbidden)
				return
			}
			if !h.Challenge.Passed(r, ip, time.Now()) {
				h.Challenge.Serve(w, r, ip, time.Now())
				return
			}
		case "rate_limit":
			if h.Limits == nil || !h.Limits.Allow(gateKey(gate, r), ip, time.Now()) {
				w.Header().Set("Retry-After", "60")
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

type decisionGate interface {
	Decision(*http.Request) (id string, rpm int)
}

func gateKey(g Gate, r *http.Request) string {
	if d, ok := g.(decisionGate); ok {
		id, _ := d.Decision(r)
		return id
	}
	return "rate_limit"
}
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return strings.Trim(host, "[]")
}

type bucket struct {
	tokens float64
	last   time.Time
}
type Limiter struct {
	mu      sync.Mutex
	RPM     int
	buckets map[string]bucket
}

func NewLimiter(rpm int) *Limiter {
	if rpm <= 0 {
		rpm = 60
	}
	return &Limiter{RPM: rpm, buckets: map[string]bucket{}}
}
func (l *Limiter) Allow(key, ip string, now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	k := key + "|" + ip
	b, ok := l.buckets[k]
	rate := float64(l.RPM)
	if !ok {
		b = bucket{tokens: rate, last: now}
	}
	b.tokens = min(rate, b.tokens+now.Sub(b.last).Minutes()*rate)
	b.last = now
	if b.tokens < 1 {
		l.buckets[k] = b
		return false
	}
	b.tokens--
	l.buckets[k] = b
	if len(l.buckets) > 10000 {
		for k, v := range l.buckets {
			if now.Sub(v.last) > time.Hour {
				delete(l.buckets, k)
			}
		}
	}
	return true
}
