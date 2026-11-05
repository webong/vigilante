package fleet

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/webong/vigilante/internal/decision"
	"github.com/webong/vigilante/internal/flow"
	"github.com/webong/vigilante/internal/history"
)

// ServerOptions configures the central fleet server endpoints (/v1/ingest and
// /v1/decisions).
type ServerOptions struct {
	// Store is the central history store holding the sensor registry and
	// egress evidence. Required.
	Store *history.Store
	// Publish hands each sanitized flow.Event to the server's flow pipeline
	// (publisher or sink). When nil, events are written directly to Store.
	Publish func(context.Context, flow.Event) error
	// Decisions is the server's active fleet decision snapshot.
	Decisions *decision.Set
	// RatePerMinute caps requests per sensor per minute (default 600).
	RatePerMinute int
	// Now overrides the wall clock in tests.
	Now func() time.Time
}

// Server serves /v1/ingest and /v1/decisions for authenticated sensors.
type Server struct {
	store     *history.Store
	publish   func(context.Context, flow.Event) error
	decisions *decision.Set
	rpm       int
	now       func() time.Time

	mu      sync.Mutex
	windows map[int64]*rateWindow
}

type rateWindow struct {
	minute int64
	count  int
}

// NewServer constructs a fleet Server.
func NewServer(opts ServerOptions) *Server {
	nowFn := opts.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	rpm := opts.RatePerMinute
	if rpm <= 0 {
		rpm = 600
	}
	pub := opts.Publish
	if pub == nil && opts.Store != nil {
		pub = opts.Store.Ingest
	}
	return &Server{
		store:     opts.Store,
		publish:   pub,
		decisions: opts.Decisions,
		rpm:       rpm,
		now:       nowFn,
		windows:   map[int64]*rateWindow{},
	}
}

// Register mounts /v1/ingest and /v1/decisions on mux.
func (s *Server) Register(mux *http.ServeMux) {
	mux.Handle("/v1/ingest", s)
	mux.Handle("/v1/decisions", s)
}

// ServeHTTP dispatches /v1/ingest and /v1/decisions after authenticating the
// sensor key and checking the per-sensor rate limit.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	sensor, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	if !s.allowRate(sensor.ID) {
		writeError(w, http.StatusTooManyRequests, "sensor rate limit exceeded")
		return
	}
	switch r.URL.Path {
	case "/v1/ingest":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleIngest(w, r, sensor)
	case "/v1/decisions":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		s.handleDecisions(w, r, sensor)
	default:
		writeError(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (history.Sensor, bool) {
	if s == nil || s.store == nil {
		writeError(w, http.StatusServiceUnavailable, "sensor store unavailable")
		return history.Sensor{}, false
	}
	rawKey := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if rawKey == "" {
		rawKey = strings.TrimSpace(r.Header.Get("X-Vigilante-Sensor-Key"))
	}
	hash, err := HashKey(rawKey)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="vigilante-sensor"`)
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return history.Sensor{}, false
	}
	sensor, err := s.store.LookupSensorByHash(r.Context(), hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="vigilante-sensor"`)
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return history.Sensor{}, false
		}
		writeError(w, http.StatusInternalServerError, "sensor lookup failed")
		return history.Sensor{}, false
	}
	return sensor, true
}

func (s *Server) allowRate(sensorID int64) bool {
	minute := s.now().UTC().Unix() / 60
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.windows[sensorID]
	if !ok || w.minute != minute {
		s.windows[sensorID] = &rateWindow{minute: minute, count: 1}
		return true
	}
	if w.count >= s.rpm {
		return false
	}
	w.count++
	return true
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request, sensor history.Sensor) {
	limited := http.MaxBytesReader(w, r.Body, MaxCompressedBytes)
	defer limited.Close()

	var reader io.Reader = limited
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("Content-Encoding")), "gzip") {
		gz, err := gzip.NewReader(limited)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid gzip body")
			return
		}
		defer gz.Close()
		reader = gz
	}

	raw, err := io.ReadAll(io.LimitReader(reader, MaxDecompressedBytes+1))
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "compressed batch exceeds limit")
			return
		}
		writeError(w, http.StatusBadRequest, "failed to read batch body")
		return
	}
	if len(raw) > MaxDecompressedBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "decompressed batch exceeds limit")
		return
	}

	var batch Batch
	if err := json.Unmarshal(raw, &batch); err != nil {
		writeError(w, http.StatusBadRequest, "invalid batch JSON")
		return
	}
	if len(batch.Events)+len(batch.Egress) > MaxBatchItems {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("batch exceeds %d items", MaxBatchItems))
		return
	}

	now := s.now().UTC()
	accepted := 0
	invalid := 0

	for _, ev := range batch.Events {
		clean, ok := SanitizeEvent(ev, sensor.ID, now)
		if !ok {
			invalid++
			continue
		}
		if s.publish != nil {
			if err := s.publish(r.Context(), clean); err != nil {
				invalid++
				continue
			}
		}
		accepted++
	}

	hasEgress := false
	for _, eg := range batch.Egress {
		clean, ok := SanitizeEgress(eg, sensor.ID, now)
		if !ok {
			invalid++
			continue
		}
		if err := s.store.RecordEgress(r.Context(), clean); err != nil {
			invalid++
			continue
		}
		hasEgress = true
		accepted++
	}

	_ = s.store.TouchSensor(r.Context(), sensor.ID, now, int64(batch.Dropped)+int64(invalid), hasEgress)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(IngestResponse{
		Accepted: accepted,
		Dropped:  invalid,
	})
}

func (s *Server) handleDecisions(w http.ResponseWriter, r *http.Request, sensor history.Sensor) {
	now := s.now().UTC()
	_ = s.store.TouchSensor(r.Context(), sensor.ID, now, 0, false)

	var entries []decision.Entry
	if s.decisions != nil {
		entries = s.decisions.Active()
	}
	if entries == nil {
		entries = []decision.Entry{}
	}
	etag := computeETag(entries)
	if matchETag(r.Header.Get("If-None-Match"), etag) {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return
	}

	payload, err := json.Marshal(Decisions{ETag: etag, Entries: entries})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode decisions failed")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("ETag", etag)
	if strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = gz.Write(payload)
		_ = gz.Close()
		return
	}
	_, _ = w.Write(payload)
}

func computeETag(entries []decision.Entry) string {
	h := sha256.New()
	for _, e := range entries {
		fmt.Fprintf(h, "%s|%s|%s|%s|%d\n", e.ID, e.Action, e.Scope, e.Target, e.Expires.UnixMilli())
	}
	return `"` + hex.EncodeToString(h.Sum(nil)[:16]) + `"`
}

func matchETag(header, etag string) bool {
	for _, part := range strings.Split(header, ",") {
		cand := strings.TrimSpace(part)
		cand = strings.TrimPrefix(cand, "W/")
		if cand == etag || cand == "*" {
			return true
		}
	}
	return false
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
