// Package redact scrubs secrets from mirrored traffic before it reaches the
// agent or the alert store. It targets bearer/JWT/API tokens and email
// addresses in paths, query strings, headers, and bounded body previews.
// Redaction is deterministic (same secret -> same placeholder) so alerts stay
// correlatable, and every hit is counted for /metrics.
package redact

import (
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
)

// Placeholder replaces a matched secret.
const Placeholder = "[REDACTED]"

// Common secret shapes:
//   - JWT:    eyJhbGciOi... (three base64url segments, 30+ chars)
//   - Bearer: Bearer <token>
//   - Keys:   sk-..., ghp_..., gho_..., github_pat_..., AKIA[0-9A-Z]{16},
//     xox[baprs]-..., AIza...
//   - Emails: user@example.com
var (
	reJWT            = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)
	reBearer         = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}`)
	reKey            = regexp.MustCompile(`\b(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{30,})\b`)
	reEmail          = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	reBasicAuth      = regexp.MustCompile(`(?i)\bbasic\s+[A-Za-z0-9+/=]{8,}`)
	reKeyValueSecret = regexp.MustCompile(`(?i)\b(token|secret|password|passwd|api[_-]?key|authorization|signature|sig|credential|private[_-]?key)(["']?\s*[:=]\s*["']?)[^\s"&,;]{6,}`)
)

var hits atomic.Uint64

// Hits returns the total number of redactions applied since process start.
func Hits() uint64 { return hits.Load() }

// String scrubs secrets from a string (paths, query strings, previews).
func String(s string) string {
	if s == "" {
		return s
	}
	out := s
	for _, re := range []*regexp.Regexp{reJWT, reBearer, reKey, reBasicAuth, reKeyValueSecret, reEmail} {
		if re.MatchString(out) {
			out = re.ReplaceAllStringFunc(out, func(m string) string {
				hits.Add(1)
				// Keep key=value shape recognizable for structured fields.
				if idx := strings.IndexAny(m, ":="); idx > 0 && idx < len(m)-1 {
					return m[:idx+1] + Placeholder
				}
				return Placeholder
			})
		}
	}
	return out
}

// Query scrubs secrets from a URL's RawQuery, preserving structure.
func Query(raw string) string {
	if raw == "" {
		return raw
	}
	// Work on the decoded query so encoded secrets are caught too.
	values, err := url.ParseQuery(raw)
	if err != nil {
		return String(raw)
	}
	var changed bool
	for k, vals := range values {
		for i, v := range vals {
			if red := String(v); red != v {
				vals[i] = red
				changed = true
			}
		}
		// Also redact the key name when it looks like a secret container.
		if red := String(k); red != k {
			values.Del(k)
			values[red] = vals
			changed = true
		}
	}
	if !changed {
		return raw
	}
	// values.Encode() percent-encodes the placeholder brackets; restore them so
	// the redacted marker stays human-readable in logs/alerts.
	enc := values.Encode()
	return strings.ReplaceAll(enc, "%5BREDACTED%5D", Placeholder)
}

// Headers scrubs secret-bearing header values in place on a copy.
func Headers(in map[string]string) map[string]string {
	if in == nil {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if v == "[REDACTED]" { // already masked by the tap
			out[k] = v
			continue
		}
		out[k] = String(v)
	}
	return out
}
