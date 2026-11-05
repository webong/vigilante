// Package fleet implements the ADR 0004 sensor/server split protocol (/v1).
//
// Sensors triage each flow locally with host, process, and repository context
// and ship the resulting flow.Event batches to a central server over
// POST /v1/ingest. Sensors poll GET /v1/decisions with If-None-Match to keep a
// local in-memory fleet decision.Set in sync without putting network calls on
// the request path.
package fleet

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/webong/vigilante/internal/alert"
	"github.com/webong/vigilante/internal/decision"
	"github.com/webong/vigilante/internal/flow"
	"github.com/webong/vigilante/internal/history"
	"github.com/webong/vigilante/internal/redact"
)

const (
	// KeyPrefix identifies a Vigilante sensor key.
	KeyPrefix = "vg_"

	// Wire bounds enforced by /v1/ingest.
	MaxCompressedBytes   = 4 << 20  // 4 MiB compressed body
	MaxDecompressedBytes = 16 << 20 // 16 MiB decompressed JSON
	MaxBatchItems        = 1000     // max events + egress items per batch

	// Timestamp sanitization window relative to server receipt time.
	maxPastSkew   = 24 * time.Hour
	maxFutureSkew = 5 * time.Minute
)

// ErrInvalidKey is returned when a sensor key is missing or malformed.
var ErrInvalidKey = errors.New("fleet: invalid sensor key")

// GenerateKey mints a new random vg_-prefixed sensor key and its SHA-256 hex
// digest. The plaintext key is shown to the operator once; only the hash is
// persisted.
func GenerateKey() (plain, hash string, err error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("fleet: generate key: %w", err)
	}
	plain = KeyPrefix + hex.EncodeToString(buf)
	sum := sha256.Sum256([]byte(plain))
	return plain, hex.EncodeToString(sum[:]), nil
}

// HashKey validates a vg_-prefixed sensor key and returns its SHA-256 hex
// digest.
func HashKey(plain string) (string, error) {
	plain = strings.TrimSpace(plain)
	if !strings.HasPrefix(plain, KeyPrefix) || len(plain) < len(KeyPrefix)+16 {
		return "", ErrInvalidKey
	}
	sum := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(sum[:]), nil
}

// ValidateServerURL parses rawURL and enforces HTTPS unless the host is a
// loopback address or insecure is explicitly enabled (-server-insecure).
func ValidateServerURL(rawURL string, insecure bool) (*url.URL, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, errors.New("fleet: server URL is required")
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("fleet: invalid server URL %q", rawURL)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return nil, fmt.Errorf("fleet: unsupported server scheme %q (use https or http)", u.Scheme)
	}
	if scheme == "http" && !insecure && !isLoopbackHost(u.Host) {
		return nil, fmt.Errorf("fleet: refusing plain-HTTP server URL %q on non-loopback host (use https:// or pass -server-insecure)", rawURL)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}

func isLoopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Batch is the wire payload POSTed by a sensor to /v1/ingest.
type Batch struct {
	Events  []flow.Event     `json:"events,omitempty"`
	Egress  []history.Egress `json:"egress,omitempty"`
	Dropped uint64           `json:"dropped,omitempty"`
}

// IngestResponse is returned by /v1/ingest.
type IngestResponse struct {
	Accepted int `json:"accepted"`
	Dropped  int `json:"dropped"`
}

// Decisions is the wire payload returned by GET /v1/decisions.
type Decisions struct {
	ETag    string           `json:"etag"`
	Entries []decision.Entry `json:"entries"`
}

// SanitizeEvent validates and normalises an untrusted flow.Event from a sensor
// batch, stamping it with the authenticated sensorID. It returns false when
// the event must be discarded (e.g. unparseable source IP).
func SanitizeEvent(ev flow.Event, sensorID int64, now time.Time) (flow.Event, bool) {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	if decision.NormalizeIP(ev.SrcAddr) == "" {
		return flow.Event{}, false
	}
	ev.SensorID = sensorID
	ev.Timestamp = sanitizeTimestamp(ev.Timestamp, now)
	ev.FlowID = clip(strings.TrimSpace(ev.FlowID), 128)
	if ev.FlowID == "" {
		ev.FlowID = fmt.Sprintf("s%d-%d", sensorID, now.UnixNano())
	}
	ev.Severity = normalizeSeverity(ev.Severity)
	ev.Verdict = normalizeVerdict(ev.Verdict)
	ev.Summary = clip(ev.Summary, 1024)
	ev.Method = clip(strings.ToUpper(strings.TrimSpace(ev.Method)), 16)
	ev.Path = clip(ev.Path, 2048)
	ev.SrcAddr = clip(strings.TrimSpace(ev.SrcAddr), 128)
	ev.TargetAddr = clip(strings.TrimSpace(ev.TargetAddr), 256)
	ev.UserAgent = clip(ev.UserAgent, 512)
	ev.TLSFingerprint = clip(strings.TrimSpace(ev.TLSFingerprint), 128)
	ev.JA4 = clip(strings.TrimSpace(ev.JA4), 128)
	ev.Protocol = clip(strings.TrimSpace(ev.Protocol), 32)
	ev.Host = clip(strings.TrimSpace(ev.Host), 255)
	ev.Handler = clip(ev.Handler, 256)
	if ev.Status < 0 || ev.Status > 999 {
		ev.Status = 0
	}
	if ev.Duration < 0 {
		ev.Duration = 0
	}
	if ev.BytesIn < 0 {
		ev.BytesIn = 0
	}
	if ev.BytesOut < 0 {
		ev.BytesOut = 0
	}
	if len(ev.Headers) > 0 {
		redacted := redact.Headers(ev.Headers)
		cleaned := make(map[string]string, min(len(redacted), 64))
		count := 0
		for k, v := range redacted {
			if count >= 64 {
				break
			}
			k = clip(strings.TrimSpace(k), 128)
			if k == "" {
				continue
			}
			if isSensitiveHeader(k) {
				cleaned[k] = redact.Placeholder
			} else {
				cleaned[k] = clip(v, 1024)
			}
			count++
		}
		ev.Headers = cleaned
	}
	ev.Advisories = clipStringSlice(ev.Advisories, 32, 128)
	ev.Recommendations = clipStringSlice(ev.Recommendations, 32, 512)
	ev.Signals = clipStringSlice(ev.Signals, 32, 256)
	if len(ev.Findings) > 32 {
		ev.Findings = ev.Findings[:32]
	}
	if len(ev.Findings) > 0 {
		findings := make([]alert.Finding, len(ev.Findings))
		for i, f := range ev.Findings {
			findings[i] = alert.Finding{
				Subject:    clip(f.Subject, 128),
				Claim:      clip(f.Claim, 256),
				Evidence:   clipStringSlice(f.Evidence, 16, 512),
				Sources:    clipStringSlice(f.Sources, 16, 128),
				Confidence: clip(f.Confidence, 32),
			}
		}
		ev.Findings = findings
	}
	return ev, true
}

// SanitizeEgress validates and normalises an outbound TCP record from a sensor
// batch, stamping it with the authenticated sensorID.
func SanitizeEgress(eg history.Egress, sensorID int64, now time.Time) (history.Egress, bool) {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	ip := net.ParseIP(strings.TrimSpace(eg.DstIP))
	if ip == nil {
		return history.Egress{}, false
	}
	eg.ID = 0
	eg.SensorID = sensorID
	eg.DstIP = ip.String()
	eg.TS = sanitizeTimestamp(eg.TS, now)
	eg.Comm = clip(strings.TrimSpace(eg.Comm), 64)
	if eg.Comm == "" {
		eg.Comm = "unknown"
	}
	if eg.Count <= 0 {
		eg.Count = 1
	}
	return eg, true
}

func sanitizeTimestamp(ts, now time.Time) time.Time {
	if ts.IsZero() {
		return now
	}
	if ts.Before(now.Add(-maxPastSkew)) || ts.After(now.Add(maxFutureSkew)) {
		return now
	}
	return ts.UTC()
}

func normalizeSeverity(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return "info"
	}
}

func normalizeVerdict(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "allow", "observe", "log", "alert", "deny", "block", "recommend-block", "challenge", "rate_limit":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return "observe"
	}
}

func isSensitiveHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token":
		return true
	default:
		return false
	}
}

func clip(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

func clipStringSlice(in []string, maxItems, maxLen int) []string {
	if len(in) == 0 {
		return nil
	}
	if len(in) > maxItems {
		in = in[:maxItems]
	}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if trimmed := clip(strings.TrimSpace(s), maxLen); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
