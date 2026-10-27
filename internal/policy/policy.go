// Package policy evaluates request-level allow/deny/block rules for the
// Vigilante gateway. Rules are declarative (YAML/JSON) and evaluated before a
// request is forwarded: an allow verdict short-circuits further rules, a deny
// returns 403, and a block mirrors the request then hands the source address
// to an Enforcer (dry-run log, nftables, or iptables).
package policy

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
)

// Action is the verdict of a matching rule.
type Action string

const (
	// ActionAllow short-circuits evaluation: the request is forwarded.
	ActionAllow Action = "allow"
	// ActionDeny rejects the request with 403 without mirroring it.
	ActionDeny Action = "deny"
	// ActionBlock mirrors the request, then enforces a block on the source.
	ActionBlock Action = "block"
)

// Rule matches a subset of requests and assigns an Action.
type Rule struct {
	// Name is a human-readable identifier used in logs and metrics.
	Name string `json:"name" yaml:"name"`
	// Action defaults to "deny" when empty.
	Action Action `json:"action" yaml:"action"`
	// Methods restricts the rule to these HTTP methods (empty = any).
	Methods []string `json:"methods,omitempty" yaml:"methods,omitempty"`
	// Hosts restricts the rule to these request hosts (empty = any).
	Hosts []string `json:"hosts,omitempty" yaml:"hosts,omitempty"`
	// Paths are glob-style path patterns matched against URL.Path
	// (e.g. "/admin/*", "/api/v1/files"). Empty = any path.
	Paths []string `json:"paths,omitempty" yaml:"paths,omitempty"`
	// PathPrefixes are literal path prefixes (e.g. "/.git/").
	PathPrefixes []string `json:"path_prefixes,omitempty" yaml:"path_prefixes,omitempty"`
	// CIDRs restricts the rule to these source IP networks (empty = any).
	CIDRs []string `json:"cidrs,omitempty" yaml:"cidrs,omitempty"`
}

// Config is the on-disk policy document.
type Config struct {
	// Rules are evaluated in order; the first match wins.
	Rules []Rule `json:"rules" yaml:"rules"`
	// DenyCIDRs are always-denied source networks (applied before rules).
	DenyCIDRs []string `json:"deny_cidrs,omitempty" yaml:"deny_cidrs,omitempty"`
}

// Engine holds parsed rules and deny networks.
type Engine struct {
	rules    []Rule
	denyNets []*net.IPNet
	compiled bool
}

// NewEngine compiles a Config into an Engine.
func NewEngine(cfg Config) (*Engine, error) {
	e := &Engine{}
	for _, c := range cfg.DenyCIDRs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("policy: invalid deny_cidr %q: %w", c, err)
		}
		e.denyNets = append(e.denyNets, n)
	}
	for i, r := range cfg.Rules {
		if r.Action == "" {
			r.Action = ActionDeny
		}
		switch r.Action {
		case ActionAllow, ActionDeny, ActionBlock:
		default:
			return nil, fmt.Errorf("policy: rule %d (%q): invalid action %q", i, r.Name, r.Action)
		}
		for _, c := range r.CIDRs {
			if _, _, err := net.ParseCIDR(strings.TrimSpace(c)); err != nil {
				return nil, fmt.Errorf("policy: rule %q: invalid cidr %q: %w", r.Name, c, err)
			}
		}
		e.rules = append(e.rules, r)
	}
	e.compiled = true
	return e, nil
}

// Load reads a YAML or JSON policy file.
func Load(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", path, err)
	}
	return Parse(data)
}

// Parse accepts YAML or JSON policy documents.
func Parse(data []byte) (*Engine, error) {
	cfg, err := decodeConfig(data)
	if err != nil {
		return nil, err
	}
	return NewEngine(cfg)
}

// Verdict is the result of evaluating a request.
type Verdict struct {
	Action Action
	Rule   string // matched rule name, if any
}

// Evaluate returns the first matching rule's verdict, or allow when nothing
// matches (default-allow posture: deny is opt-in per rule or via deny_cidrs).
func (e *Engine) Evaluate(r *http.Request) Verdict {
	if e == nil || !e.compiled {
		return Verdict{Action: ActionAllow}
	}
	srcIP := SourceIP(r)
	for _, n := range e.denyNets {
		if n.Contains(srcIP) {
			return Verdict{Action: ActionDeny, Rule: "deny_cidr"}
		}
	}
	for _, rule := range e.rules {
		if ruleMatches(rule, r, srcIP) {
			return Verdict{Action: rule.Action, Rule: rule.Name}
		}
	}
	return Verdict{Action: ActionAllow}
}

func ruleMatches(rule Rule, r *http.Request, srcIP net.IP) bool {
	if len(rule.Methods) > 0 {
		ok := false
		for _, m := range rule.Methods {
			if strings.EqualFold(strings.TrimSpace(m), r.Method) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(rule.Hosts) > 0 {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.ToLower(host)
		ok := false
		for _, h := range rule.Hosts {
			if strings.EqualFold(strings.TrimSpace(h), host) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(rule.Paths) > 0 {
		ok := false
		for _, p := range rule.Paths {
			if matchGlobPath(strings.TrimSpace(p), r.URL.Path) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(rule.PathPrefixes) > 0 {
		ok := false
		for _, p := range rule.PathPrefixes {
			if strings.HasPrefix(r.URL.Path, strings.TrimSpace(p)) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(rule.CIDRs) > 0 {
		ok := false
		for _, c := range rule.CIDRs {
			if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil && n.Contains(srcIP) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// matchGlobPath supports "*" (within a segment) and "**" (across segments).
func matchGlobPath(pattern, value string) bool {
	if pattern == "**" {
		return true
	}
	parts := strings.Split(pattern, "/")
	vparts := strings.Split(value, "/")
	return matchParts(parts, vparts)
}

func matchParts(pattern, value []string) bool {
	if len(pattern) == 0 {
		return len(value) == 0
	}
	if pattern[0] == "**" {
		for i := 0; i <= len(value); i++ {
			if matchParts(pattern[1:], value[i:]) {
				return true
			}
		}
		return false
	}
	if len(value) == 0 {
		return false
	}
	if segMatch(pattern[0], value[0]) {
		return matchParts(pattern[1:], value[1:])
	}
	return false
}

func segMatch(pattern, seg string) bool {
	if pattern == "*" {
		return true
	}
	ok, err := path.Match(pattern, seg)
	return err == nil && ok
}

// SourceIP extracts the client IP from a request's RemoteAddr.
func SourceIP(r *http.Request) net.IP {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	return net.ParseIP(strings.TrimSpace(host))
}
