package tap

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/webong/vigilante/internal/agent"
)

func TestPreviewRequestRedactsSecrets(t *testing.T) {
	q := NewMirrorQueue(8)
	req := httptest.NewRequest(http.MethodGet,
		"http://x/api?token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	req.Body = io.NopCloser(strings.NewReader(`{"password":"hunter2supersecret"}`))
	PreviewRequest(q, req, ":8080", "app:3000")

	ev := <-q.Events()
	if strings.Contains(ev.Path, "eyJhbGciOiJIUzI1NiJ9") {
		t.Fatalf("path leaks JWT: %s", ev.Path)
	}
	if !strings.Contains(ev.Path, "token=") || !strings.Contains(ev.Path, "[REDACTED]") {
		t.Fatalf("redacted query malformed: %s", ev.Path)
	}
	if strings.Contains(ev.PayloadPreview, "hunter2supersecret") {
		t.Fatalf("body preview leaks password: %s", ev.PayloadPreview)
	}
	if !strings.Contains(ev.PayloadPreview, "password") {
		t.Fatalf("preview should keep key name: %s", ev.PayloadPreview)
	}
	// Body must be restored for the real handler.
	if ev.PayloadBytes == 0 {
		t.Fatal("payload bytes not recorded")
	}
}

func TestSamplingZeroRateMirrorsAll(t *testing.T) {
	q := NewMirrorQueue(8)
	q.SetSampleRate(0) // disabled
	for i := 0; i < 5; i++ {
		if !q.Enqueue(agent.PacketEvent{FlowID: "f"}) {
			t.Fatal("event should enqueue when sampling disabled")
		}
	}
	if q.SampledOut() != 0 {
		t.Fatalf("sampledOut = %d, want 0", q.SampledOut())
	}
}

func TestSamplingLowRateSkips(t *testing.T) {
	q := NewMirrorQueue(10000)
	q.SetSampleRate(0.1)
	queued, skipped := 0, 0
	const n = 2000
	for i := 0; i < n; i++ {
		if q.Enqueue(agent.PacketEvent{FlowID: "f"}) {
			queued++
		} else {
			skipped++
		}
	}
	// ~10% queued; assert it's far from 100% and >0.
	if queued == 0 || queued > n/3 {
		t.Fatalf("queued=%d skipped=%d out of %d (expect roughly 10%%)", queued, skipped, n)
	}
	if q.SampledOut() != uint64(skipped) {
		t.Fatalf("sampledOut=%d want %d", q.SampledOut(), skipped)
	}
}

func TestHTTPMiddlewareGateDeniesWithoutMirroring(t *testing.T) {
	q := NewMirrorQueue(8)
	gate := func(*http.Request) string { return "deny" }
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("denied request must not reach upstream")
	})
	h := HTTPMiddlewareGate(next, q, ":8080", "app:3000", gate)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://x/x", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d", rec.Code)
	}
	if len(q.Events()) != 0 {
		t.Fatal("denied request should not be mirrored")
	}
	_ = context.Background
}
