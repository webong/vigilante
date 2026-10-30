package behavior

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/webong/vigilante/ext/triage"
	"github.com/webong/vigilante/internal/actor"
	"github.com/webong/vigilante/internal/decision"
	"github.com/webong/vigilante/internal/flow"
	"github.com/webong/vigilante/internal/history"
	"github.com/webong/vigilante/internal/identity"
)

type Store interface {
	Ingest(context.Context, flow.Event) error
	Flows(context.Context, string, time.Time, int) ([]history.Flow, error)
	Analyze(context.Context, history.Actor) error
	Suggest(context.Context, history.Suggestion) error
}
type Sink struct {
	Store    Store
	Verifier *identity.Verifier
	Window   time.Duration
	MinScore int
	// Triager, when set, sends actors whose rule score falls in the triage
	// band to a language model before a suggestion is written.
	Triager        triage.Service
	TriageMinScore int
	triaged        *triageState
}

// triageState remembers when each actor was last sent to the model so a flood
// of requests from one actor does not burn the hourly LLM budget.
type triageState struct {
	mu      sync.Mutex
	triaged map[string]time.Time
}

// EnsureTriaged initializes the per-actor dedup state so a flood of requests
// from one actor does not burn the hourly LLM budget. Call once after
// constructing the Sink.
func (s *Sink) EnsureTriaged() {
	if s.triaged == nil {
		s.triaged = &triageState{triaged: map[string]time.Time{}}
	}
}

func (s *Sink) recentlyTriaged(key string) bool {
	s.triaged.mu.Lock()
	defer s.triaged.mu.Unlock()
	t, ok := s.triaged.triaged[key]
	if !ok {
		return false
	}
	return time.Since(t) < time.Hour
}
func (s *Sink) markTriaged(key string) {
	s.triaged.mu.Lock()
	defer s.triaged.mu.Unlock()
	s.triaged.triaged[key] = time.Now()
}

func (s Sink) Ingest(ctx context.Context, ev flow.Event) error {
	if s.Store == nil {
		return nil
	}
	if err := s.Store.Ingest(ctx, ev); err != nil {
		return err
	}
	if s.Window <= 0 {
		s.Window = 24 * time.Hour
	}
	flows, err := s.Store.Flows(ctx, actorKey(ev), time.Now().Add(-s.Window), 2000)
	if err != nil {
		return nil
	}
	id := identity.Result{}
	if s.Verifier != nil {
		id = s.Verifier.Identify(ctx, ev)
	}
	result := Analyze(flows, id)
	signals := make([]string, 0, len(result.Signals))
	for _, signal := range result.Signals {
		signals = append(signals, signal.Detail)
	}
	verified := id.Verified
	if id.Failed != "" {
		verified = id.Failed
	}
	a := history.Actor{Key: actorKey(ev), Class: result.Class, Risk: result.Score, Signals: signals, Identity: verified}
	if err := s.Store.Analyze(ctx, a); err != nil {
		return err
	}
	if s.MinScore <= 0 {
		s.MinScore = 80
	}
	if s.Triager != nil && s.triageApplies(result.Score) && !s.recentlyTriaged(a.Key) {
		s.markTriaged(a.Key)
		if suggested, err := s.triageSuggest(ctx, ev, flows, id, result, a.Key); err == nil && suggested {
			return nil
		}
	}
	if result.Score < s.MinScore {
		return nil
	}
	action := "rate_limit"
	if result.Score >= 100 || result.Class == "impersonator" || result.Class == "scanner" {
		action = "block"
	} else if result.Score >= 80 {
		action = "challenge"
	}
	reason := fmt.Sprintf("Behavior score %d (%s)", result.Score, result.Class)
	for i, signal := range result.Signals {
		if i == 3 {
			break
		}
		reason += "; " + signal.Detail
	}
	sum := sha256.Sum256([]byte(a.Key))
	return s.Store.Suggest(ctx, history.Suggestion{ID: "behavior-" + hex.EncodeToString(sum[:8]), ActorKey: a.Key, Action: action, Scope: decision.ScopeIP, Target: identityIP(ev.SrcAddr), Reason: reason})
}
func actorKey(ev flow.Event) string { return actor.ActorKey(ev.SrcAddr, ev.TLSFingerprint) }
func identityIP(addr string) string { return decision.NormalizeIP(addr) }

func (s Sink) triageApplies(score int) bool {
	lo := s.TriageMinScore
	if lo <= 0 {
		lo = 25
	}
	return score >= lo && score < s.MinScore
}

func (s Sink) triageSuggest(ctx context.Context, ev flow.Event, flows []history.Flow, id identity.Result, result Result, actorKey string) (bool, error) {
	in := triage.NewInput(decision.NormalizeIP(ev.SrcAddr), ev.TLSFingerprint, id, triage.RuleResult{
		Score:   result.Score,
		Class:   result.Class,
		Signals: ruleSignals(result.Signals),
	}, flows)
	verdict, err := s.Triager.Triage(ctx, in)
	if err != nil {
		return false, err
	}
	action, scope, target := decisionFromVerdict(verdict, ev.SrcAddr, ev.TLSFingerprint)
	if action == "" {
		return false, nil
	}
	reason := fmt.Sprintf("LLM triage: %s (risk %d, %s)", verdict.Summary, verdict.Risk, verdict.Classification)
	if len(verdict.Evidence) > 0 {
		reason += "; " + strings.Join(verdict.Evidence, "; ")
	}
	sum := sha256.Sum256([]byte("triage-" + actorKey))
	return true, s.Store.Suggest(ctx, history.Suggestion{
		ID:       "triage-" + hex.EncodeToString(sum[:8]),
		ActorKey: actorKey,
		Action:   action,
		Scope:    scope,
		Target:   target,
		Reason:   reason,
	})
}

func ruleSignals(signals []Signal) []triage.RuleSignal {
	out := make([]triage.RuleSignal, 0, len(signals))
	for _, s := range signals {
		out = append(out, triage.RuleSignal{Code: s.Code, Weight: s.Weight, Detail: s.Detail})
	}
	return out
}

func decisionFromVerdict(v triage.Verdict, srcAddr, fingerprint string) (action string, scope decision.Scope, target string) {
	switch v.Action {
	case "block":
		return "block", decision.ScopeIP, decision.NormalizeIP(srcAddr)
	case "challenge":
		if v.Scope == "fingerprint" && fingerprint != "" {
			return "challenge", decision.ScopeFingerprint, fingerprint
		}
		return "challenge", decision.ScopeIP, decision.NormalizeIP(srcAddr)
	case "rate_limit":
		return "rate_limit", decision.ScopeIP, decision.NormalizeIP(srcAddr)
	}
	return "", "", ""
}
