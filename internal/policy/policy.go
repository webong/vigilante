// Package policy evaluates request-level allow/deny/block rules for the
// Vigilante gateway. Rules are declarative (YAML/JSON) and evaluated before a
// request is forwarded: an allow verdict short-circuits further rules, a deny
// returns 403, and a block mirrors the request then hands the source address
// to an Enforcer (dry-run log, nftables, or iptables).
//
// An Engine is a stable, concurrency-safe handle to a compiled rule set. It can
// be reloaded in place (Reload, or Watch for a policy file), so a rule change
// never requires restarting a process that owns a listener.
package policy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
//
// Every list is ANDed with the others: a rule matches only when all configured
// dimensions match. Within one dimension the values are ORed. An empty
// dimension is a wildcard. Allow rules short-circuit, so list an allow rule
// before a broader deny rule to carve out an exception.
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
	// Headers matches request headers as "Name=glob" (e.g.
	// "X-Forwarded-Proto=https"). Header names are case-insensitive; values
	// are matched with a case-insensitive glob.
	Headers []string `json:"headers,omitempty" yaml:"headers,omitempty"`
	// HeaderPrefixes matches request headers as "Name=literal-prefix".
	// It is the cheap, allocation-free form for common cases such as
	// "User-Agent=sqlmap".
	HeaderPrefixes []string `json:"header_prefixes,omitempty" yaml:"header_prefixes,omitempty"`
	// UserAgents matches the User-Agent header with a case-insensitive glob
	// (e.g. "*sqlmap*", "Nikto*").
	UserAgents []string `json:"user_agents,omitempty" yaml:"user_agents,omitempty"`
	// Queries matches the raw query string with a case-insensitive glob
	// (e.g. "*union select*").
	Queries []string `json:"queries,omitempty" yaml:"queries,omitempty"`
	// Not negates a nested matcher. The nested fields use the same AND/OR
	// semantics as the outer rule; name and action are ignored. For example,
	// a broad admin rule can exclude requests from a trusted CIDR.
	Not *Rule `json:"not,omitempty" yaml:"not,omitempty"`
}

// Config is the on-disk policy document.
type Config struct {
	// Rules are evaluated in order; the first match wins.
	Rules []Rule `json:"rules" yaml:"rules"`
	// DenyCIDRs are always-denied source networks (applied before rules).
	DenyCIDRs []string `json:"deny_cidrs,omitempty" yaml:"deny_cidrs,omitempty"`
}

// compiled is the immutable state swapped in by Reload.
type compiled struct {
	rules    []Rule
	denyNets []*net.IPNet
	epoch    int64
	// headerSensitive is true when any rule depends on a request header.
	// Decisions are then not safe to cache on (method, host, path, query,
	// client address) alone.
	headerSensitive bool
}

// Engine holds compiled rules and deny networks behind an atomic pointer, so a
// reload swaps the whole rule set without tearing a concurrent evaluation.
type Engine struct {
	path   string // file path when loaded from disk ("" for inline)
	source []byte // original document, for Reload of inline policies

	state      atomic.Pointer[compiled]
	lastReload atomic.Int64 // UnixNano of last successful load
	lastErr    atomic.Pointer[string]

	reloadMu sync.Mutex
	hookMu   sync.Mutex
	hook     func(error)
}

// NewEngine compiles a Config into an Engine.
func NewEngine(cfg Config) (*Engine, error) {
	st, err := compile(cfg)
	if err != nil {
		return nil, err
	}
	e := &Engine{}
	st.epoch = 1
	e.state.Store(st)
	e.lastReload.Store(time.Now().UnixNano())
	return e, nil
}

func compile(cfg Config) (*compiled, error) {
	st := &compiled{}
	for _, c := range cfg.DenyCIDRs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			return nil, fmt.Errorf("policy: invalid deny_cidr %q: %w", c, err)
		}
		st.denyNets = append(st.denyNets, n)
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
		headerSensitive, err := validateMatchers(r, r.Name, 0)
		if err != nil {
			return nil, err
		}
		if headerSensitive {
			st.headerSensitive = true
		}
		st.rules = append(st.rules, r)
	}
	return st, nil
}

func validateMatchers(r Rule, name string, depth int) (bool, error) {
	if depth > 8 {
		return false, fmt.Errorf("policy: rule %q: not matcher nesting exceeds 8 levels", name)
	}
	for _, c := range r.CIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(c)); err != nil {
			return false, fmt.Errorf("policy: rule %q: invalid cidr %q: %w", name, c, err)
		}
	}
	for _, spec := range append(append([]string{}, r.Headers...), r.HeaderPrefixes...) {
		header, _, ok := strings.Cut(spec, "=")
		if !ok || strings.TrimSpace(header) == "" {
			return false, fmt.Errorf("policy: rule %q: header matcher %q must be \"Name=value\"", name, spec)
		}
	}
	headerSensitive := len(r.Headers)+len(r.HeaderPrefixes)+len(r.UserAgents) > 0
	if r.Not != nil {
		if !hasMatchers(*r.Not) {
			return false, fmt.Errorf("policy: rule %q: not matcher must contain at least one match field", name)
		}
		nestedSensitive, err := validateMatchers(*r.Not, name, depth+1)
		if err != nil {
			return false, err
		}
		headerSensitive = headerSensitive || nestedSensitive
	}
	return headerSensitive, nil
}

func hasMatchers(r Rule) bool {
	return len(r.Methods)+len(r.Hosts)+len(r.Paths)+len(r.PathPrefixes)+len(r.CIDRs)+
		len(r.Headers)+len(r.HeaderPrefixes)+len(r.UserAgents)+len(r.Queries) > 0 || r.Not != nil
}

// Load reads a YAML or JSON policy file and enables Reload/Watch for it.
func Load(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("policy: read %s: %w", path, err)
	}
	cfg, err := decodeConfig(data)
	if err != nil {
		return nil, err
	}
	st, err := compile(cfg)
	if err != nil {
		return nil, err
	}
	e := &Engine{path: path, source: data}
	st.epoch = 1
	e.state.Store(st)
	e.lastReload.Store(time.Now().UnixNano())
	return e, nil
}

// Parse accepts YAML or JSON policy documents. The returned Engine can still be
// reloaded from the same in-memory document with Reload.
func Parse(data []byte) (*Engine, error) {
	cfg, err := decodeConfig(data)
	if err != nil {
		return nil, err
	}
	st, err := compile(cfg)
	if err != nil {
		return nil, err
	}
	e := &Engine{source: append([]byte(nil), data...)}
	st.epoch = 1
	e.state.Store(st)
	e.lastReload.Store(time.Now().UnixNano())
	return e, nil
}

// Verdict is the result of evaluating a request.
type Verdict struct {
	Action Action
	Rule   string // matched rule name, if any
}

// Evaluate returns the first matching rule's verdict, or allow when nothing
// matches (default-allow posture: deny is opt-in per rule or via deny_cidrs).
// It is safe for concurrent use and reflects the most recent successful reload.
func (e *Engine) Evaluate(r *http.Request) Verdict {
	verdict, _, _ := e.EvaluateSnapshot(r)
	return verdict
}

// EvaluateSnapshot evaluates a request against one immutable policy snapshot
// and returns that snapshot's epoch and cache safety. Callers that cache
// decisions can verify the epoch before reusing or storing a verdict.
func (e *Engine) EvaluateSnapshot(r *http.Request) (Verdict, int64, bool) {
	st := e.current()
	if st == nil {
		return Verdict{Action: ActionAllow}, 0, true
	}
	srcIP := SourceIP(r)
	for _, n := range st.denyNets {
		if srcIP != nil && n.Contains(srcIP) {
			return Verdict{Action: ActionDeny, Rule: "deny_cidr"}, st.epoch, !st.headerSensitive
		}
	}
	for _, rule := range st.rules {
		if ruleMatches(rule, r, srcIP) {
			return Verdict{Action: rule.Action, Rule: rule.Name}, st.epoch, !st.headerSensitive
		}
	}
	return Verdict{Action: ActionAllow}, st.epoch, !st.headerSensitive
}

func (e *Engine) current() *compiled {
	if e == nil {
		return nil
	}
	return e.state.Load()
}

// DecisionCacheable reports whether a verdict can be reused for a different
// request that shares method, host, path, query, and client address. It is
// false when any rule inspects a request header, because those values are not
// part of that coarse key.
func (e *Engine) DecisionCacheable() bool {
	st := e.current()
	return st == nil || !st.headerSensitive
}

// RuleCount returns the number of compiled rules.
func (e *Engine) RuleCount() int {
	st := e.current()
	if st == nil {
		return 0
	}
	return len(st.rules)
}

// Reload re-reads the policy source and swaps the compiled rules atomically.
// On a parse error the previous rules stay in force and the error is recorded
// (LastReload/ReloadError) and passed to the reload hook.
func (e *Engine) Reload() error {
	if e == nil {
		return fmt.Errorf("policy: reload on nil engine")
	}
	e.reloadMu.Lock()
	err := e.reload()
	e.reloadMu.Unlock()
	e.notify(err)
	return err
}

func (e *Engine) reload() error {
	data := e.source
	if e.path != "" {
		b, err := os.ReadFile(e.path)
		if err != nil {
			return e.reloadFailed(fmt.Errorf("policy: reload %s: %w", e.path, err))
		}
		data = b
	}
	if len(data) == 0 {
		return e.reloadFailed(fmt.Errorf("policy: nothing to reload"))
	}
	cfg, err := decodeConfig(data)
	if err != nil {
		return e.reloadFailed(fmt.Errorf("policy: reload: %w", err))
	}
	st, err := compile(cfg)
	if err != nil {
		return e.reloadFailed(fmt.Errorf("policy: reload: %w", err))
	}
	st.epoch = e.Epoch() + 1
	e.state.Store(st)
	e.source = append([]byte(nil), data...)
	e.lastReload.Store(time.Now().UnixNano())
	e.lastErr.Store(nil)
	return nil
}

func (e *Engine) reloadFailed(err error) error {
	msg := err.Error()
	e.lastErr.Store(&msg)
	return err
}

// Epoch identifies the currently loaded rule set. It changes on every
// successful reload and lets a cache detect that its entries are stale.
func (e *Engine) Epoch() int64 {
	st := e.current()
	if st == nil {
		return 0
	}
	return st.epoch
}

// LastReload reports when the policy was last compiled successfully.
func (e *Engine) LastReload() time.Time {
	if e == nil {
		return time.Time{}
	}
	ns := e.lastReload.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// ReloadError returns the most recent reload error, or nil.
func (e *Engine) ReloadError() error {
	if e == nil {
		return nil
	}
	if p := e.lastErr.Load(); p != nil {
		return fmt.Errorf("%s", *p)
	}
	return nil
}

// SetReloadHook registers a callback invoked after every reload attempt.
func (e *Engine) SetReloadHook(fn func(error)) {
	if e == nil {
		return
	}
	e.hookMu.Lock()
	e.hook = fn
	e.hookMu.Unlock()
}

func (e *Engine) notify(err error) {
	e.hookMu.Lock()
	fn := e.hook
	e.hookMu.Unlock()
	if fn != nil {
		fn(err)
	}
}

// Watch reloads the policy file whenever it changes on disk. It is a no-op for
// inline policies and when interval <= 0. The first tick establishes the
// baseline, so it never reloads an unchanged file.
func (e *Engine) Watch(ctx context.Context, interval time.Duration) {
	if e == nil || e.path == "" {
		return
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	go func() {
		var mod time.Time
		var size int64
		if fi, err := os.Stat(e.path); err == nil {
			mod, size = fi.ModTime(), fi.Size()
		}
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				fi, err := os.Stat(e.path)
				if err != nil {
					continue
				}
				if fi.ModTime().Equal(mod) && fi.Size() == size {
					continue
				}
				mod, size = fi.ModTime(), fi.Size()
				_ = e.Reload()
			}
		}
	}()
}

func ruleMatches(rule Rule, r *http.Request, srcIP net.IP) bool {
	if rule.Not != nil && ruleMatches(*rule.Not, r, srcIP) {
		return false
	}
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
			if _, n, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil && srcIP != nil && n.Contains(srcIP) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(rule.Headers) > 0 {
		ok := false
		for _, spec := range rule.Headers {
			if matchHeaderGlob(r, spec) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(rule.HeaderPrefixes) > 0 {
		ok := false
		for _, spec := range rule.HeaderPrefixes {
			if matchHeaderPrefix(r, spec) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(rule.UserAgents) > 0 {
		ua := strings.ToLower(r.UserAgent())
		ok := false
		for _, p := range rule.UserAgents {
			if wildcardMatch(strings.ToLower(strings.TrimSpace(p)), ua) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	if len(rule.Queries) > 0 {
		// Match the raw query and a decoded, space-separated form so a rule
		// author can write "*union select*" without caring whether the client
		// sent '+' or '%20'.
		candidates := queryCandidates(r.URL.RawQuery)
		ok := false
		for _, p := range rule.Queries {
			pattern := strings.ToLower(strings.TrimSpace(p))
			for _, candidate := range candidates {
				if wildcardMatch(pattern, candidate) {
					ok = true
					break
				}
			}
			if ok {
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// queryCandidates returns the raw query plus a decoded variant (percent escapes
// resolved and '+' treated as a space), lower-cased and de-duplicated.
func queryCandidates(raw string) []string {
	if raw == "" {
		return nil
	}
	lower := strings.ToLower(raw)
	out := []string{lower}
	decoded := strings.ReplaceAll(raw, "+", " ")
	if unescaped, err := url.QueryUnescape(decoded); err == nil {
		decoded = unescaped
	}
	if d := strings.ToLower(decoded); d != lower {
		out = append(out, d)
	}
	return out
}

// matchHeaderGlob matches "Name=glob" against a request header.
func matchHeaderGlob(r *http.Request, spec string) bool {
	name, pattern, ok := strings.Cut(spec, "=")
	if !ok {
		return false
	}
	value := r.Header.Get(strings.TrimSpace(name))
	if value == "" {
		return false
	}
	return wildcardMatch(strings.ToLower(strings.TrimSpace(pattern)), strings.ToLower(value))
}

// matchHeaderPrefix matches "Name=prefix" against a request header.
func matchHeaderPrefix(r *http.Request, spec string) bool {
	name, prefix, ok := strings.Cut(spec, "=")
	if !ok {
		return false
	}
	value := r.Header.Get(strings.TrimSpace(name))
	if value == "" {
		return false
	}
	return strings.HasPrefix(
		strings.ToLower(value),
		strings.ToLower(strings.TrimSpace(prefix)),
	)
}

// wildcardMatch reports whether value matches a glob where '*' matches any
// run of characters and '?' matches one. Case handling is the caller's job.
func wildcardMatch(pattern, value string) bool {
	pi, vi := 0, 0
	star, mark := -1, 0
	for vi < len(value) {
		switch {
		case pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == value[vi]):
			pi++
			vi++
		case pi < len(pattern) && pattern[pi] == '*':
			star = pi
			mark = vi
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			vi = mark
		default:
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
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
