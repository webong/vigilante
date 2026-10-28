// Package gate composes the static policy gate with the live decision snapshot.
//
// Static policy is evaluated first: an explicit deny/block rule always wins, so
// a stale or absent snapshot can never loosen a configured rule. Only when the
// policy allows the request does the snapshot get consulted, and it only ever
// makes the outcome stricter (deny/block), never more permissive.
package gate

import (
	"net"
	"net/http"

	"github.com/webong/vigilante/ext/tap"
	"github.com/webong/vigilante/internal/decision"
)

// Options configures the composed gate. All fields are optional.
type Options struct {
	// Policy is the static policy gate (may be nil).
	Policy tap.PolicyGate
	// Set is the live decision snapshot (may be nil).
	Set *decision.Set
	// Actor derives an actor key from the request (default: client IP).
	Actor func(*http.Request) string
	// Fingerprint derives a fingerprint key (TLS/JA3) from the request. The
	// default has no fingerprint source and returns "".
	Fingerprint func(*http.Request) string
	// OnHit observes each snapshot hit (metrics, audit).
	OnHit func(decision.Entry)
}

// New returns a tap.PolicyGate that combines static policy with the snapshot.
func New(opts Options) tap.PolicyGate {
	return func(r *http.Request) string {
		if r == nil {
			return "allow"
		}
		if opts.Policy != nil {
			if v := opts.Policy(r); v != "" && v != "allow" {
				return v
			}
		}
		if opts.Set == nil {
			return "allow"
		}
		ip := clientIP(r)
		actor := ""
		if opts.Actor != nil {
			actor = opts.Actor(r)
		}
		if actor == "" {
			actor = ip
		}
		fingerprint := ""
		if opts.Fingerprint != nil {
			fingerprint = opts.Fingerprint(r)
		}
		entry, ok := opts.Set.Lookup(ip, actor, fingerprint)
		if !ok {
			return "allow"
		}
		if opts.OnHit != nil {
			opts.OnHit(entry)
		}
		switch entry.Action {
		case "deny", "block":
			return entry.Action
		default:
			// The tap only understands allow/deny/block. Anything else (for
			// example a challenge the ingress cannot serve) fails closed: a
			// decision is in force, so do not forward.
			return "block"
		}
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	return ""
}
