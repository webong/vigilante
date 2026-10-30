// Package alert persists vigilante verdicts and (optionally) delivers them to
// external receivers. Storage is an append-only JSONL file with size-based
// rotation; delivery is pluggable:
//
//   - "none": store only (default).
//   - "webhook": POST each alert as JSON to a URL — either directly, or
//     through a webong/gateway Planner (POST /vigilante/alerts) so Gateway's
//     subscriber relays handle fan-out, retries, and queuing.
//
// Delivery failures never block the hot path: they are logged and counted.
package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Severity ranks a verdict for filtering and delivery thresholds.
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

// rank maps severities to an orderable integer (higher = more severe).
func rank(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// Record is one persisted/delivered alert.
type Finding struct {
	Subject    string   `json:"subject"`
	Claim      string   `json:"claim"`
	Evidence   []string `json:"evidence,omitempty"`
	Sources    []string `json:"sources,omitempty"`
	Confidence string   `json:"confidence,omitempty"`
}

type Record struct {
	Timestamp      time.Time         `json:"timestamp"`
	FlowID         string            `json:"flow_id"`
	Severity       Severity          `json:"severity"`
	Action         string            `json:"action"`
	Summary        string            `json:"summary,omitempty"`
	Method         string            `json:"method,omitempty"`
	Path           string            `json:"path,omitempty"`
	SrcAddr        string            `json:"src_addr,omitempty"`
	TargetAddr     string            `json:"target_addr,omitempty"`
	UserAgent      string            `json:"user_agent,omitempty"`
	TLSFingerprint string            `json:"tls_fingerprint,omitempty"`
	Protocol       string            `json:"protocol,omitempty"`
	Host           string            `json:"host,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	Status         int               `json:"status,omitempty"`
	Duration       time.Duration     `json:"duration,omitempty"`
	BytesIn        int64             `json:"bytes_in,omitempty"`
	BytesOut       int64             `json:"bytes_out,omitempty"`
	Signals        []string          `json:"signals,omitempty"`
	Rule           string            `json:"policy_rule,omitempty"` // policy rule that triggered, if any
	Handler        string            `json:"matched_handler,omitempty"`
	Advisories     []string          `json:"matched_advisories,omitempty"`
	Findings       []Finding         `json:"findings,omitempty"`
}

// Reader reads persisted alerts for consumers (dashboards, APIs, exporters).
// It is satisfied by *Store. The store file is append-only, so a Reader can
// tail it cheaply; implementations may cache the byte offset.
type Reader interface {
	// Recent returns up to limit of the newest records, optionally filtered by
	// a minimum severity. Newest first.
	Recent(minSeverity Severity, limit int) ([]Record, error)
	// CountBySeverity returns the total stored record count grouped by severity.
	CountBySeverity() map[Severity]int
}

// Options configures the Store.
type Options struct {
	// Path is the JSONL alert file (required for persistence).
	Path string
	// MaxBytes triggers rotation when exceeded (default 10 MiB); rotated files
	// are kept as Path.1, Path.2, ... up to KeepFiles.
	MaxBytes int64
	// KeepFiles is the number of rotated files to retain (default 3).
	KeepFiles int
	// MinSeverity filters which verdicts are recorded/delivered
	// (default: record everything).
	MinSeverity Severity
	// DeliverURL, when set, POSTs each qualifying record as JSON.
	DeliverURL string
	// PlannerURL, when set with DeliverURL, routes delivery through the
	// webong/gateway Planner ingress (POST PlannerURL/vigilante/alerts) so
	// Gateway subscriber relays own fan-out/retries. InternalToken authenticates.
	PlannerURL    string
	InternalToken string
	// HTTPClient overrides the delivery client (tests).
	HTTPClient *http.Client
	// OnError is invoked for store/delivery errors (logging seam).
	OnError func(error)
	// DeliverAttempts is the max delivery attempts per record including the
	// first (default 3; 1 disables retries).
	DeliverAttempts int
	// DeliverBackoff is the base delay between delivery retries; it doubles
	// per attempt (default 250ms, capped at 4s).
	DeliverBackoff time.Duration
}

// Store persists and optionally delivers alerts.
type Store struct {
	opts Options
	mu   sync.Mutex
	f    *os.File
	size int64
	// delivered/failed/stored counters for /metrics.
	delivered uint64
	failed    uint64
	stored    uint64
}

// Open creates/opens the alert store.
func Open(opts Options) (*Store, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("alert: store path is required")
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = 10 << 20
	}
	if opts.KeepFiles <= 0 {
		opts.KeepFiles = 3
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if opts.DeliverAttempts <= 0 {
		opts.DeliverAttempts = 3
	}
	if opts.DeliverBackoff <= 0 {
		opts.DeliverBackoff = 250 * time.Millisecond
	}
	if dir := filepath.Dir(opts.Path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("alert: create store dir: %w", err)
		}
	}
	s := &Store{opts: opts}
	if err := s.openFile(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) openFile() error {
	f, err := os.OpenFile(s.opts.Path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("alert: open store: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	s.f = f
	s.size = info.Size()
	return nil
}

// Record persists rec (subject to MinSeverity) and delivers it when a
// delivery target is configured. It never returns an error to the caller:
// persistence/delivery problems are reported via OnError.
func (s *Store) Record(rec Record) {
	if s == nil {
		return
	}
	if s.opts.MinSeverity != "" && rank(rec.Severity) < rank(s.opts.MinSeverity) {
		return
	}
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	}

	s.mu.Lock()
	line, err := json.Marshal(rec)
	if err == nil {
		if _, werr := s.f.Write(append(line, '\n')); werr != nil {
			s.err(fmt.Errorf("alert: write: %w", werr))
		} else {
			s.size += int64(len(line) + 1)
			s.stored++
			if s.size >= s.opts.MaxBytes {
				s.rotateLocked()
			}
		}
	}
	s.mu.Unlock()

	if s.opts.DeliverURL != "" {
		s.deliver(rec)
	}
}

// deliver POSTs the record, preferring the Planner route when configured.
// It retries transient failures with exponential backoff up to DeliverAttempts,
// counting failures only after all attempts are exhausted. Retries never block
// the caller beyond the per-attempt client timeout.
func (s *Store) deliver(rec Record) {
	body, err := json.Marshal(rec)
	if err != nil {
		s.err(fmt.Errorf("alert: marshal for delivery: %w", err))
		return
	}
	url := s.opts.DeliverURL
	if s.opts.PlannerURL != "" {
		url = fmt.Sprintf("%s/vigilante/alerts", trimRightSlash(s.opts.PlannerURL))
	}

	backoff := s.opts.DeliverBackoff
	var lastErr error
	for attempt := 1; attempt <= s.opts.DeliverAttempts; attempt++ {
		if ok := s.deliverOnce(url, body); ok {
			s.mu.Lock()
			s.delivered++
			s.mu.Unlock()
			return
		}
		lastErr = errDelivery
		if attempt < s.opts.DeliverAttempts {
			time.Sleep(backoff)
			if backoff < 4*time.Second {
				backoff *= 2
			}
		}
	}
	s.mu.Lock()
	s.failed++
	s.mu.Unlock()
	s.err(fmt.Errorf("alert: deliver failed after %d attempts: %w", s.opts.DeliverAttempts, lastErr))
}

// errDelivery is the sentinel for a single failed attempt (real cause logged).
var errDelivery = fmt.Errorf("delivery attempt failed")

// deliverOnce makes a single POST attempt; returns true on 2xx.
func (s *Store) deliverOnce(url string, body []byte) bool {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		s.err(fmt.Errorf("alert: build request: %w", err))
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	if s.opts.InternalToken != "" {
		req.Header.Set("X-Gateway-Internal-Token", s.opts.InternalToken)
	}
	resp, err := s.opts.HTTPClient.Do(req)
	if err != nil {
		s.err(fmt.Errorf("alert: deliver attempt: %w", err))
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode >= 300 {
		s.err(fmt.Errorf("alert: deliver attempt status %d", resp.StatusCode))
		return false
	}
	return true
}

// rotateLocked renames the current file to .1 (shifting older ones out).
// Caller must hold s.mu.
func (s *Store) rotateLocked() {
	_ = s.f.Close()
	for i := s.opts.KeepFiles - 1; i >= 1; i-- {
		from := fmt.Sprintf("%s.%d", s.opts.Path, i)
		to := fmt.Sprintf("%s.%d", s.opts.Path, i+1)
		_ = os.Rename(from, to)
	}
	_ = os.Rename(s.opts.Path, s.opts.Path+".1")
	_ = os.Remove(fmt.Sprintf("%s.%d", s.opts.Path, s.opts.KeepFiles+1))
	s.size = 0
	_ = s.openFile()
}

// Stats returns stored/delivered/failed counters for /metrics.
func (s *Store) Stats() (stored, delivered, failed uint64) {
	if s == nil {
		return 0, 0, 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stored, s.delivered, s.failed
}

// Recent returns up to limit of the newest stored records (newest first),
// optionally filtered by a minimum severity. It reads the current store file
// (the rotated generations are older, so only the active file is scanned).
func (s *Store) Recent(minSeverity Severity, limit int) ([]Record, error) {
	if s == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	s.mu.Lock()
	path := s.opts.Path
	s.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	minRank := rank(minSeverity)
	var out []Record
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	// Walk newest-first.
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var rec Record
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue
		}
		if minSeverity != "" && rank(rec.Severity) < minRank {
			continue
		}
		out = append(out, rec)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// CountBySeverity returns the total stored record count grouped by severity.
func (s *Store) CountBySeverity() map[Severity]int {
	counts := map[Severity]int{}
	// Read all records (cap high enough for a status page; rotated files are
	// excluded, matching Recent).
	recs, err := s.Recent("", 100000)
	if err != nil {
		return counts
	}
	for _, r := range recs {
		counts[r.Severity]++
	}
	return counts
}

// Close flushes and closes the store.
func (s *Store) Close() error {
	if s == nil || s.f == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	err := s.f.Close()
	s.f = nil
	return err
}

func (s *Store) err(err error) {
	if s.opts.OnError != nil {
		s.opts.OnError(err)
	}
}

func trimRightSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}
