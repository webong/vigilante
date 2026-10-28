// Package decision holds the host's live enforcement snapshot: the set of
// actions currently in force, keyed by the scope they apply to (a client IP, a
// CIDR, an actor, a TLS/JA fingerprint, or everything).
//
// The core consults this snapshot on the request path; stateful plugins (a
// console, an operator UI, an external WAF bridge) write into it. Every entry
// is time-bounded or explicitly removed, so a crashed or wedged plugin can
// never leave the core enforcing a stale rule forever: the snapshot expires on
// its own and the registry that owns the decision reverts the external side.
//
// The package is deliberately tiny and allocation-light. Lookup is O(1) for
// exact keys and O(n) over the (small) CIDR list.
package decision

import (
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// Scope names what a decision is keyed by.
type Scope string

const (
	// ScopeIP applies to one client address.
	ScopeIP Scope = "ip"
	// ScopeCIDR applies to a client address inside a network.
	ScopeCIDR Scope = "cidr"
	// ScopeActor applies to an opaque actor key derived by the host
	// (for example "ip+tls-fingerprint").
	ScopeActor Scope = "actor"
	// ScopeFingerprint applies to a TLS/JA fingerprint regardless of address.
	ScopeFingerprint Scope = "fingerprint"
	// ScopeGlobal applies to every request.
	ScopeGlobal Scope = "global"
)

// Valid reports whether s is a known scope.
func (s Scope) Valid() bool {
	switch s {
	case ScopeIP, ScopeCIDR, ScopeActor, ScopeFingerprint, ScopeGlobal:
		return true
	}
	return false
}

// ErrInvalidEntry is returned by Set.Put for a malformed decision.
var ErrInvalidEntry = errors.New("decision: invalid entry")

// Entry is one decision in force.
type Entry struct {
	ID      string    `json:"id"`
	Action  string    `json:"action"` // "block", "deny", "challenge", ...
	Scope   Scope     `json:"scope"`
	Target  string    `json:"target"`
	Reason  string    `json:"reason,omitempty"`
	Actor   string    `json:"actor,omitempty"`
	Created time.Time `json:"created"`
	// Expires is the end of the decision's life. Zero means the entry stays
	// until it is explicitly removed.
	Expires time.Time `json:"expires,omitempty"`
}

func (e Entry) expired(now time.Time) bool {
	return !e.Expires.IsZero() && !now.Before(e.Expires)
}

// Key renders the entry's lookup key. Two entries with the same key cannot be
// active at once; the newest wins.
func (e Entry) Key() string { return string(e.Scope) + ":" + e.Target }

// Set is a concurrency-safe collection of active decisions.
type Set struct {
	mu      sync.RWMutex
	entries map[string]Entry
	now     func() time.Time
}

// NewSet returns an empty set backed by the wall clock.
func NewSet() *Set { return NewSetWithClock(time.Now) }

// NewSetWithClock returns an empty set using now as its clock (tests).
func NewSetWithClock(now func() time.Time) *Set {
	if now == nil {
		now = time.Now
	}
	return &Set{entries: map[string]Entry{}, now: now}
}

// Put validates and inserts e, replacing any entry with the same key.
func (s *Set) Put(e Entry) error {
	if s == nil {
		return fmt.Errorf("%w: nil set", ErrInvalidEntry)
	}
	if e.ID == "" {
		return fmt.Errorf("%w: missing id", ErrInvalidEntry)
	}
	if e.Action == "" {
		return fmt.Errorf("%w: missing action", ErrInvalidEntry)
	}
	if !e.Scope.Valid() {
		return fmt.Errorf("%w: unknown scope %q", ErrInvalidEntry, e.Scope)
	}
	switch e.Scope {
	case ScopeGlobal:
		e.Target = "*"
	case ScopeIP:
		host := NormalizeIP(e.Target)
		if host == "" {
			return fmt.Errorf("%w: target %q is not an IP address", ErrInvalidEntry, e.Target)
		}
		e.Target = host
	case ScopeCIDR:
		if _, _, err := net.ParseCIDR(e.Target); err != nil {
			return fmt.Errorf("%w: target %q is not a CIDR: %v", ErrInvalidEntry, e.Target, err)
		}
	case ScopeActor, ScopeFingerprint:
		if strings.TrimSpace(e.Target) == "" {
			return fmt.Errorf("%w: %s scope needs a target", ErrInvalidEntry, e.Scope)
		}
	}
	if e.Created.IsZero() {
		e.Created = s.now().UTC()
	}
	s.mu.Lock()
	s.entries[e.Key()] = e
	s.mu.Unlock()
	return nil
}

// Remove drops the entry with the given decision ID, reporting whether one was
// present.
func (s *Set) Remove(id string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.entries {
		if e.ID == id {
			delete(s.entries, k)
			return true
		}
	}
	return false
}

// Lookup returns the first active decision matching the request context, in
// decreasing specificity: exact IP, actor, fingerprint, CIDR, global.
//
// Identity keys (actor, fingerprint) outrank a network range because they
// describe the actual actor, while a CIDR describes a population that may
// contain it.
func (s *Set) Lookup(ip, actor, fingerprint string) (Entry, bool) {
	if s == nil {
		return Entry{}, false
	}
	now := s.now()
	s.mu.RLock()
	defer s.mu.RUnlock()

	host := NormalizeIP(ip)
	if host != "" {
		if e, ok := s.entries[string(ScopeIP)+":"+host]; ok && !e.expired(now) {
			return e, true
		}
	}
	if actor != "" {
		if e, ok := s.entries[string(ScopeActor)+":"+actor]; ok && !e.expired(now) {
			return e, true
		}
	}
	if fingerprint != "" {
		if e, ok := s.entries[string(ScopeFingerprint)+":"+fingerprint]; ok && !e.expired(now) {
			return e, true
		}
	}
	if host != "" {
		parsed := net.ParseIP(host)
		for _, e := range s.entries {
			if e.Scope != ScopeCIDR || e.expired(now) {
				continue
			}
			_, network, err := net.ParseCIDR(e.Target)
			if err == nil && parsed != nil && network.Contains(parsed) {
				return e, true
			}
		}
	}
	if e, ok := s.entries[string(ScopeGlobal)+":*"]; ok && !e.expired(now) {
		return e, true
	}
	return Entry{}, false
}

// SecondsUntilExpiry reports how long e stays in force (0 = no expiry, negative
// = already expired).
func (s *Set) SecondsUntilExpiry(e Entry) time.Duration {
	if e.Expires.IsZero() {
		return 0
	}
	return e.Expires.Sub(s.now())
}

// Active returns the non-expired entries, oldest first.
func (s *Set) Active() []Entry {
	if s == nil {
		return nil
	}
	now := s.now()
	s.mu.RLock()
	out := make([]Entry, 0, len(s.entries))
	for _, e := range s.entries {
		if !e.expired(now) {
			out = append(out, e)
		}
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Created.Equal(out[j].Created) {
			return out[i].ID < out[j].ID
		}
		return out[i].Created.Before(out[j].Created)
	})
	return out
}

// Sweep removes and returns every expired entry.
func (s *Set) Sweep() []Entry {
	if s == nil {
		return nil
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	var expired []Entry
	for k, e := range s.entries {
		if e.expired(now) {
			expired = append(expired, e)
			delete(s.entries, k)
		}
	}
	return expired
}

// Len reports how many entries are stored, including not-yet-swept expired
// ones.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// NormalizeIP strips a port and validates the host part, returning "" when the
// value is not an IP.
func NormalizeIP(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		addr = host
	}
	ip := net.ParseIP(strings.Trim(addr, "[]"))
	if ip == nil {
		return ""
	}
	return ip.String()
}
