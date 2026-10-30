package triage

import (
	"github.com/webong/vigilante/internal/history"
	"github.com/webong/vigilante/internal/identity"
)

// NewInput builds the wire Input from core types on the host side. flows are
// oldest first, as history.Store.Flows returns them; only the last
// MaxRequests cross the plugin boundary.
func NewInput(ip, fingerprint string, id identity.Result, rules RuleResult, flows []history.Flow) Input {
	in := Input{
		IP:             ip,
		TLSFingerprint: fingerprint,
		Identity:       Identity{Verified: id.Verified, Failed: id.Failed},
		Rules:          rules,
		TotalRequests:  len(flows),
	}
	if len(flows) > MaxRequests {
		flows = flows[len(flows)-MaxRequests:]
	}
	in.Requests = make([]Request, len(flows))
	for i, f := range flows {
		in.Requests[i] = Request{
			Timestamp:  f.Timestamp,
			Method:     f.Method,
			Path:       f.Path,
			Host:       f.Host,
			Status:     f.Status,
			DurationMS: f.Duration.Seconds() * 1000,
			Verdict:    f.Verdict,
			Severity:   f.Severity,
			UserAgent:  f.UserAgent,
			Headers:    f.Headers,
		}
	}
	return in
}
