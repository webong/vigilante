// Package blockaction is the built-in action executor: it applies a decision to
// the host firewall through internal/block.
//
// It is the reference implementation of the action contract. Everything it does
// (dry-run, TTL, revert, audit) is provided by internal/action; the executor
// only maps a decision onto the enforcer and back.
package blockaction

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/webong/vigilante/internal/action"
	"github.com/webong/vigilante/internal/block"
	"github.com/webong/vigilante/internal/decision"
)

// Executor applies blocks with a block.Enforcer.
type Executor struct {
	enc *block.Enforcer
}

// New wraps enc. It returns nil when enc is nil.
func New(enc *block.Enforcer) *Executor {
	if enc == nil {
		return nil
	}
	return &Executor{enc: enc}
}

// Capability implements action.Executor.
func (e *Executor) Capability() action.Capability {
	return action.Capability{
		ID:          "block",
		Label:       "Block",
		Description: "Drop traffic from the target at the host firewall (iptables/nft, or log-only).",
		Scopes:      []decision.Scope{decision.ScopeIP},
		Reversible:  true,
		Destructive: true,
	}
}

// Execute implements action.Executor.
func (e *Executor) Execute(ctx context.Context, req action.Request) (action.Result, error) {
	ip, err := parseIP(req.Target)
	if err != nil {
		return action.Result{}, err
	}
	rule := req.Reason
	if rule == "" {
		rule = "action:block"
	}
	if req.DryRun {
		return action.Result{Detail: "dry-run: would block " + ip.String()}, nil
	}
	if err := e.enc.Block(ctx, ip, rule); err != nil {
		return action.Result{}, err
	}
	return action.Result{RevertRef: ip.String(), Detail: "blocked " + ip.String()}, nil
}

// Revert implements action.Executor.
func (e *Executor) Revert(ctx context.Context, d action.Decision) error {
	target := d.RevertRef
	if target == "" {
		target = d.Target
	}
	ip, err := parseIP(target)
	if err != nil {
		return err
	}
	return e.enc.Unblock(ctx, ip)
}

// parseIP accepts a bare address or host:port and rejects non-IPs.
func parseIP(target string) (net.IP, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("block action: target is required")
	}
	if host, _, err := net.SplitHostPort(target); err == nil {
		target = host
	}
	ip := net.ParseIP(strings.Trim(target, "[]"))
	if ip == nil {
		return nil, fmt.Errorf("block action: target %q is not an IP address", target)
	}
	return ip, nil
}
