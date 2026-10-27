// Package status provides the shared /healthz and /metrics HTTP endpoints for
// every vigilante mode (http, tcp, middleware, spinner). It aggregates queue
// counters and optional alert-store counters in one place.
package status

import (
	"fmt"
	"net/http"

	"github.com/webong/vigilante/internal/tap"
)

// AlertStats reports alert store counters (nil-safe).
type AlertStats func() (stored, delivered, failed uint64)

// Handler serves /healthz and /metrics for the given mirror queue.
// alert may be nil when no alert store is configured.
func Handler(queue *tap.MirrorQueue, alert AlertStats) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	// Spinner parity: keep /health and /ready as aliases.
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		var queued, dropped uint64
		if queue != nil {
			queued, dropped = queue.Stats()
		}
		fmt.Fprintf(w, "vigilante_queue_enqueued_total %d\nvigilante_queue_dropped_total %d\n", queued, dropped)
		if alert != nil {
			stored, delivered, failed := alert()
			fmt.Fprintf(w, "vigilante_alerts_stored_total %d\nvigilante_alerts_delivered_total %d\nvigilante_alerts_failed_total %d\n",
				stored, delivered, failed)
		}
	})
	return mux
}
