// Package block enforces source-IP blocks decided by policy verdicts. It
// supports three modes:
//
//   - "log" (default): record the block without touching the network — safe
//     dry-run for evaluation and CI.
//   - "iptables": manage a dedicated chain (default VIGILANTE) referenced from
//     INPUT, adding a DROP rule for the source address.
//   - "nft": manage a dedicated table/chain (inet filter / vigilante) with a
//     drop verdict for the source address.
//
// Enforcers are intentionally small and testable: command execution goes
// through a Runner seam so tests never touch the real firewall.
package block

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"
)

// Mode selects the enforcement backend.
type Mode string

const (
	// ModeLog records blocks without enforcing them (dry-run default).
	ModeLog Mode = "log"
	// ModeIPTables enforces via iptables-restore-style commands.
	ModeIPTables Mode = "iptables"
	// ModeNFT enforces via nftables.
	ModeNFT Mode = "nft"
)

// Options configures an Enforcer.
type Options struct {
	Mode Mode
	// Chain is the iptables/nft chain name (default "VIGILANTE").
	Chain string
	// Timeout bounds each firewall command (default 5s).
	Timeout time.Duration
	// Runner executes firewall commands; nil uses exec.CommandContext.
	Runner Runner
	// OnBlock is invoked after each successful (or logged) block.
	OnBlock func(ip net.IP, rule string)
}

// Runner executes a command and returns its combined output.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// Enforcer applies block decisions.
type Enforcer struct {
	opts Options
	// ready tracks whether the chain/table has been provisioned.
	provisioned bool
}

// New creates an Enforcer for the given mode.
func New(opts Options) (*Enforcer, error) {
	switch opts.Mode {
	case "", ModeLog:
		opts.Mode = ModeLog
	case ModeIPTables, ModeNFT:
	default:
		return nil, fmt.Errorf("block: unknown mode %q (log, iptables, nft)", opts.Mode)
	}
	if opts.Chain == "" {
		opts.Chain = "VIGILANTE"
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.Runner == nil {
		opts.Runner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return exec.CommandContext(ctx, name, args...).CombinedOutput()
		}
	}
	return &Enforcer{opts: opts}, nil
}

// Block enforces a drop for the source IP (idempotent). rule names the policy
// rule that triggered the block, for logging.
func (e *Enforcer) Block(ctx context.Context, ip net.IP, rule string) error {
	if ip == nil || ip.IsUnspecified() {
		return fmt.Errorf("block: refusing to block unspecified address (rule %q)", rule)
	}
	if ip.IsLoopback() {
		// Never firewall the local host off from itself.
		return fmt.Errorf("block: refusing to block loopback address %s (rule %q)", ip, rule)
	}

	if e.opts.Mode == ModeLog {
		if e.opts.OnBlock != nil {
			e.opts.OnBlock(ip, rule)
		}
		return nil
	}

	cmdCtx, cancel := context.WithTimeout(ctx, e.opts.Timeout)
	defer cancel()

	if !e.provisioned {
		if err := e.provision(cmdCtx); err != nil {
			return err
		}
		e.provisioned = true
	}

	if err := e.addDrop(cmdCtx, ip); err != nil {
		return err
	}
	if e.opts.OnBlock != nil {
		e.opts.OnBlock(ip, rule)
	}
	return nil
}

// provision creates the dedicated chain/table if missing.
func (e *Enforcer) provision(ctx context.Context) error {
	switch e.opts.Mode {
	case ModeIPTables:
		// Create chain, then ensure INPUT jumps to it (idempotent -C check).
		if _, err := e.opts.Runner(ctx, "iptables", "-N", e.opts.Chain); err != nil && !containsExists(err) {
			// Chain may already exist; -N errors are tolerated below.
		}
		out, err := e.opts.Runner(ctx, "iptables", "-C", "INPUT", "-j", e.opts.Chain)
		_ = out
		if err != nil {
			if _, err2 := e.opts.Runner(ctx, "iptables", "-I", "INPUT", "-j", e.opts.Chain); err2 != nil {
				return fmt.Errorf("block: provision iptables chain %q: %w", e.opts.Chain, err2)
			}
		}
		return nil
	case ModeNFT:
		// Create table + chain if missing (nft errors when they exist; tolerate).
		_, _ = e.opts.Runner(ctx, "nft", "add", "table", "inet", e.opts.Chain)
		_, err := e.opts.Runner(ctx, "nft", "add", "chain", "inet", e.opts.Chain, e.opts.Chain,
			"{ type filter hook input priority 0 ; }")
		if err != nil && !containsExists(err) {
			return fmt.Errorf("block: provision nft chain: %w", err)
		}
		return nil
	}
	return nil
}

// addDrop installs a DROP rule for the IP in the dedicated chain.
func (e *Enforcer) addDrop(ctx context.Context, ip net.IP) error {
	switch e.opts.Mode {
	case ModeIPTables:
		// Idempotent: skip if the rule already exists.
		if _, err := e.opts.Runner(ctx, "iptables", "-C", e.opts.Chain, "-s", ip.String(), "-j", "DROP"); err == nil {
			return nil
		}
		out, err := e.opts.Runner(ctx, "iptables", "-A", e.opts.Chain, "-s", ip.String(), "-j", "DROP")
		if err != nil {
			return fmt.Errorf("block: iptables add %s: %w (%s)", ip, err, strings.TrimSpace(string(out)))
		}
		return nil
	case ModeNFT:
		// nft add rule is not idempotent; check via list first.
		out, err := e.opts.Runner(ctx, "nft", "list", "chain", "inet", e.opts.Chain, e.opts.Chain)
		if err == nil && strings.Contains(string(out), ip.String()) {
			return nil
		}
		out, err = e.opts.Runner(ctx, "nft", "add", "rule", "inet", e.opts.Chain, e.opts.Chain,
			"ip", "saddr", ip.String(), "drop")
		if err != nil {
			return fmt.Errorf("block: nft add %s: %w (%s)", ip, err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	return nil
}

// Mode returns the configured mode.
func (e *Enforcer) Mode() Mode { return e.opts.Mode }

// containsExists reports whether an error message indicates an already-exists
// condition (iptables/nft both phrase it that way).
func containsExists(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "exists") || strings.Contains(msg, "file exists")
}
