package status

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/webong/vigilante/ext/tap"
)

func TestHealthzAndMetrics(t *testing.T) {
	q := tap.NewMirrorQueue(8)
	// Enqueue one event through the real preview path.
	req := httptest.NewRequest(http.MethodGet, "http://x/healthz", nil)
	req.RemoteAddr = "203.0.113.5:1234"
	tap.PreviewRequest(q, req, ":8080", "app:3000")
	alert := func() (uint64, uint64, uint64) { return 5, 4, 1 }

	srv := httptest.NewServer(Handler(q, alert))
	defer srv.Close()

	for _, path := range []string{"/healthz", "/health", "/ready"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status = %d", path, resp.StatusCode)
		}
		if path != "/ready" && strings.TrimSpace(string(body)) != "ok" {
			t.Fatalf("%s body = %q", path, body)
		}
	}

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	text := string(body)
	for _, want := range []string{
		"vigilante_queue_enqueued_total 1",
		"vigilante_alerts_stored_total 5",
		"vigilante_alerts_delivered_total 4",
		"vigilante_alerts_failed_total 1",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("metrics missing %q:\n%s", want, text)
		}
	}
}

func TestMetricsWithoutAlertStore(t *testing.T) {
	q := tap.NewMirrorQueue(4)
	srv := httptest.NewServer(Handler(q, nil))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "vigilante_queue_enqueued_total 0") {
		t.Fatalf("metrics = %q", body)
	}
	if strings.Contains(string(body), "vigilante_alerts_") {
		t.Fatal("alert metrics present without a store")
	}
}
