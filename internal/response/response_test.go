package response

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type gateFunc func(*http.Request) string

func (f gateFunc) Decide(r *http.Request) string { return f(r) }
func TestChallengeAndPass(t *testing.T) {
	c := NewChallenger()
	h := Handler{Challenge: c}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler := h.Wrap(next, gateFunc(func(*http.Request) string { return "challenge" }))
	r := httptest.NewRequest(http.MethodGet, "http://example.test/private", nil)
	r.RemoteAddr = "203.0.113.5:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("challenge status=%d", w.Code)
	}
	token := c.sign("pass", "203.0.113.5", time.Now().Add(time.Hour))
	r = httptest.NewRequest(http.MethodGet, "http://example.test/private", nil)
	r.RemoteAddr = "203.0.113.5:1234"
	r.AddCookie(&http.Cookie{Name: "vigilante_pass", Value: token})
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("passed status=%d", w.Code)
	}
}
func TestRateLimit(t *testing.T) {
	l := NewLimiter(1)
	now := time.Now()
	if !l.Allow("d", "ip", now) {
		t.Fatal("first request denied")
	}
	if l.Allow("d", "ip", now) {
		t.Fatal("second request allowed")
	}
	if !l.Allow("d", "ip", now.Add(time.Minute)) {
		t.Fatal("bucket did not refill")
	}
}
func TestDisabledResponsesPassThrough(t *testing.T) {
	h := Handler{}
	handler := h.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }), gateFunc(func(*http.Request) string { return "challenge" }))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != 204 {
		t.Fatalf("status=%d", w.Code)
	}
}
