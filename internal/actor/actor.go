// Package actor aggregates triaged flows into actors and scores them.
//
// It is a stateful flow.Sink: it lives out of the request path, consumes the
// same flow events the alert store does, and keeps a bounded in-memory index of
// who has been doing what. The core stays stateless; this package is the state,
// and it is exposed only as data (see docs/adr/0003).
//
// An actor is keyed by address, and by address+fingerprint when a TLS
// fingerprint is present, so the same NAT'd client with different client
// profiles stays distinct. Risk is a transparent, decaying score: every flow
// adds severity-weighted points that fall out of a sliding window, so a quiet
// actor's score drops back to zero on its own.
package actor

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/webong/vigilante/internal/decision"
	"github.com/webong/vigilante/internal/flow"
)

// Risk weights by severity. They are intentionally simple and documented so the
// number means something; see RiskWindow and RiskThreshold.
var severityWeight = map[string]int{
	"info":     1,
	"low":      2,
	"medium":   5,
	"high":     10,
	"critical": 20,
}

// Defaults.
const (
	DefaultWindow    = 24 * time.Hour
	DefaultThreshold = 50
	DefaultMaxActors = 10000
)

// AI-agent user-agent fragments used to tag automation.
var aiAgentUAFragments = []string{
	"gptbot", "claudebot", "perplexitybot", "anthropic", "openai",
	"chatgpt", "oai-searchbot", "ccbot", "bytespider", "amazonbot",
	"meta-externalagent", "ai2bot", "cohere", "mistral", "gemini",
}

// Actor is the read model for one keyed client.
type Actor struct {
	Key         string         `json:"key"`
	IP          string         `json:"ip"`
	Fingerprint string         `json:"tls_fingerprint,omitempty"`
	UserAgent   string         `json:"user_agent,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	FirstSeen   time.Time      `json:"first_seen"`
	LastSeen    time.Time      `json:"last_seen"`
	Requests    int            `json:"requests"`
	BySeverity  map[string]int `json:"by_severity"`
	Verdicts    map[string]int `json:"verdicts"`
	LastVerdict string         `json:"last_verdict,omitempty"`
	LastSummary string         `json:"last_summary,omitempty"`
	Risk        int            `json:"risk"`
	Suspicious  bool           `json:"suspicious"`
}

type riskEvent struct {
	t      time.Time
	weight int
}

type actor struct {
	Actor
	tags map[string]bool
	risk []riskEvent
}

// Index is a concurrency-safe, bounded actor index.
type Index struct {
	mu        sync.Mutex
	now       func() time.Time
	window    time.Duration
	threshold int
	max       int
	actors    map[string]*actor
	order     []string // insertion order for deterministic listing
}

// NewIndex returns an empty index with the given window and actor cap. Zero
// values fall back to the defaults.
func NewIndex(window time.Duration, maxActors int) *Index {
	return NewIndexWithClock(window, maxActors, time.Now)
}

// NewIndexWithClock uses now as the clock (tests).
func NewIndexWithClock(window time.Duration, maxActors int, now func() time.Time) *Index {
	if window <= 0 {
		window = DefaultWindow
	}
	if maxActors <= 0 {
		maxActors = DefaultMaxActors
	}
	if now == nil {
		now = time.Now
	}
	return &Index{
		now:       now,
		window:    window,
		threshold: DefaultThreshold,
		max:       maxActors,
		actors:    map[string]*actor{},
	}
}

// SetRiskThreshold changes the suspicious-flag threshold (default 50).
func (i *Index) SetRiskThreshold(n int) {
	i.mu.Lock()
	defer i.mu.Unlock()
	if n <= 0 {
		n = DefaultThreshold
	}
	i.threshold = n
}

// Ingest implements flow.Sink: it folds one triaged flow into its actor.
func (i *Index) Ingest(_ context.Context, ev flow.Event) error {
	i.mu.Lock()
	defer i.mu.Unlock()

	now := i.now().UTC()
	if ev.Timestamp.IsZero() {
		ev.Timestamp = now
	}
	key := ActorKey(ev.SrcAddr, ev.TLSFingerprint)

	a, ok := i.actors[key]
	if !ok {
		if len(i.actors) >= i.max {
			i.evictLocked()
		}
		a = &actor{
			Actor: Actor{
				Key:         key,
				IP:          decision.NormalizeIP(ev.SrcAddr),
				Fingerprint: ev.TLSFingerprint,
				FirstSeen:   ev.Timestamp,
				BySeverity:  map[string]int{},
				Verdicts:    map[string]int{},
			},
			tags: map[string]bool{},
		}
		i.actors[key] = a
		i.order = append(i.order, key)
	}

	a.Requests++
	if ev.Timestamp.Before(a.FirstSeen) {
		a.FirstSeen = ev.Timestamp
	}
	if ev.Timestamp.After(a.LastSeen) {
		a.LastSeen = ev.Timestamp
	}
	if ev.UserAgent != "" {
		a.UserAgent = ev.UserAgent
	}
	if ev.TLSFingerprint != "" {
		a.Fingerprint = ev.TLSFingerprint
	}
	if ev.Severity != "" {
		a.BySeverity[ev.Severity]++
	}
	if ev.Verdict != "" {
		a.Verdicts[ev.Verdict]++
		a.LastVerdict = ev.Verdict
	}
	if ev.Summary != "" {
		a.LastSummary = ev.Summary
	}
	for _, t := range TagsFor(ev) {
		a.tags[t] = true
	}

	if w := severityWeight[ev.Severity]; w > 0 {
		a.risk = append(a.risk, riskEvent{t: ev.Timestamp, weight: w})
	}
	a.Actor.Risk = i.recompute(a)
	a.Actor.Suspicious = a.Actor.Risk >= i.threshold
	a.Actor.Tags = tagSlice(a.tags)
	return nil
}

// Snapshot returns actors sorted by risk (desc), then recency (desc).
func (i *Index) Snapshot() []Actor {
	i.mu.Lock()
	defer i.mu.Unlock()
	out := make([]Actor, 0, len(i.actors))
	for _, k := range i.order {
		a, ok := i.actors[k]
		if !ok {
			continue
		}
		a.Actor.Risk = i.recompute(a)
		a.Actor.Suspicious = a.Actor.Risk >= i.threshold
		a.Actor.Tags = tagSlice(a.tags)
		out = append(out, a.Actor)
	}
	sort.Slice(out, func(x, y int) bool {
		if out[x].Risk != out[y].Risk {
			return out[x].Risk > out[y].Risk
		}
		if !out[x].LastSeen.Equal(out[y].LastSeen) {
			return out[x].LastSeen.After(out[y].LastSeen)
		}
		return out[x].Key < out[y].Key
	})
	return out
}

// Count reports how many actors are indexed.
func (i *Index) Count() int {
	i.mu.Lock()
	defer i.mu.Unlock()
	return len(i.actors)
}

// recompute prunes expired risk events and sums the remainder. Callers hold the
// lock.
func (i *Index) recompute(a *actor) int {
	cutoff := i.now().UTC().Add(-i.window)
	kept := a.risk[:0]
	total := 0
	for _, e := range a.risk {
		if e.t.Before(cutoff) {
			continue
		}
		kept = append(kept, e)
		total += e.weight
	}
	a.risk = kept
	return total
}

// evictLocked drops the least-recently-seen actor to stay within the cap.
// Callers hold the lock.
func (i *Index) evictLocked() {
	var victim string
	var oldest time.Time
	for k, a := range i.actors {
		if victim == "" || a.LastSeen.Before(oldest) {
			victim = k
			oldest = a.LastSeen
		}
	}
	if victim != "" {
		delete(i.actors, victim)
		for idx, k := range i.order {
			if k == victim {
				i.order = append(i.order[:idx], i.order[idx+1:]...)
				break
			}
		}
	}
}

// ActorKey derives the stable key for an actor from an address and fingerprint.
func ActorKey(srcAddr, fingerprint string) string {
	ip := decision.NormalizeIP(srcAddr)
	fp := strings.TrimSpace(fingerprint)
	if ip == "" {
		if fp == "" {
			return "unknown"
		}
		return "fp:" + fp
	}
	if fp == "" {
		return ip
	}
	return ip + "|" + fp
}

// TagsFor derives stable tags from a flow. It is pure and exposed for testing.
func TagsFor(ev flow.Event) []string {
	var tags []string
	summary := strings.ToLower(ev.Summary)
	path := strings.ToLower(ev.Path)
	switch {
	case strings.Contains(summary, "path traversal") || strings.Contains(path, "../") || strings.Contains(path, "..\\"):
		tags = append(tags, "path-traversal")
	case strings.Contains(summary, "injection") || strings.Contains(path, "union ") || strings.Contains(path, "select "):
		tags = append(tags, "injection")
	}
	if len(ev.Advisories) > 0 {
		tags = append(tags, "cve")
	}
	ua := strings.ToLower(ev.UserAgent)
	for _, frag := range aiAgentUAFragments {
		if strings.Contains(ua, frag) {
			tags = append(tags, "ai-agent")
			break
		}
	}
	return tags
}

func tagSlice(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
