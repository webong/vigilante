// Package obs
package obs

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/webong/vigilante/ext/triage"
	"github.com/webong/vigilante/internal/action"
	"github.com/webong/vigilante/internal/decision"
	"github.com/webong/vigilante/internal/history"
	"github.com/webong/vigilante/internal/identity"
)

// --- dashboard session ------------------------------------------------------

const sessionCookie = "vigilante_session"
const sessionTTL = 7 * 24 * time.Hour

func (e Extension) sessionKey() []byte {
	h := hmac.New(sha256.New, []byte(e.Token))
	h.Write([]byte("vigilante-session-v1"))
	return h.Sum(nil)
}

func (e Extension) signSession(exp time.Time) string {
	buf := binary.BigEndian.AppendUint64(nil, uint64(exp.Unix()))
	m := hmac.New(sha256.New, e.sessionKey())
	m.Write(buf)
	return base64.RawURLEncoding.EncodeToString(append(buf, m.Sum(nil)...))
}

func (e Extension) authenticatedSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil || len(raw) != 8+sha256.Size {
		return false
	}
	m := hmac.New(sha256.New, e.sessionKey())
	m.Write(raw[:8])
	exp := time.Unix(int64(binary.BigEndian.Uint64(raw[:8])), 0)
	return hmac.Equal(raw[8:], m.Sum(nil)) && time.Now().Before(exp)
}

func (e Extension) setSessionCookie(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

func (e Extension) authorized(r *http.Request) bool {
	if e.authenticatedSession(r) {
		return true
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		token = r.Header.Get("X-Vigilante-Token")
	}
	return subtleCompare([]byte(token), []byte(e.Token))
}

func subtleCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// --- actor id hashing -------------------------------------------------------

func actorID(key string) int64 {
	sum := sha256.Sum256([]byte(key))
	return int64(binary.BigEndian.Uint64(sum[:8]))
}

// --- dashboard API ----------------------------------------------------------

func (e Extension) dashboardAPI(w http.ResponseWriter, r *http.Request, rest string) {
	if !e.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="vigilante"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	parts := strings.Split(rest, "/")
	switch {
	case parts[0] == "session" && len(parts) == 1 && r.Method == http.MethodGet:
		extensionJSON(w, map[string]bool{"authenticated": true}, nil)
	case parts[0] == "login" && len(parts) == 1 && r.Method == http.MethodPost:
		e.dashboardLogin(w, r)
	case parts[0] == "logout" && len(parts) == 1 && r.Method == http.MethodPost:
		e.setSessionCookie(w, r, "", -1)
		extensionJSON(w, map[string]bool{"authenticated": false}, nil)
	case parts[0] == "overview" && len(parts) == 1 && r.Method == http.MethodGet:
		e.dashboardOverview(w, r)
	case parts[0] == "actors" && len(parts) == 1 && r.Method == http.MethodGet:
		e.dashboardActors(w, r)
	case parts[0] == "actors" && len(parts) == 2 && r.Method == http.MethodGet:
		id, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			http.Error(w, "invalid actor id", http.StatusBadRequest)
			return
		}
		e.dashboardActor(w, r, id)
	case parts[0] == "actors" && len(parts) == 3 && parts[2] == "triage" && r.Method == http.MethodPost:
		id, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			http.Error(w, "invalid actor id", http.StatusBadRequest)
			return
		}
		e.dashboardTriage(w, r, id)
	case parts[0] == "actors" && len(parts) == 3 && parts[2] == "dismiss" && r.Method == http.MethodPost:
		id, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			http.Error(w, "invalid actor id", http.StatusBadRequest)
			return
		}
		e.dashboardDismiss(w, r, id)
	case parts[0] == "decisions" && len(parts) == 1 && r.Method == http.MethodGet:
		e.dashboardDecisions(w, r)
	case parts[0] == "decisions" && len(parts) == 1 && r.Method == http.MethodPost:
		e.dashboardCreateDecision(w, r)
	case parts[0] == "decisions" && len(parts) == 3 && r.Method == http.MethodPost:
		e.dashboardTransition(w, r, parts[1], parts[2])
	case parts[0] == "egress" && len(parts) == 1 && r.Method == http.MethodGet:
		e.dashboardEgress(w, r)
	case parts[0] == "sensors" && len(parts) == 1 && r.Method == http.MethodGet:
		extensionJSON(w, []dashboardSensor{}, nil)
	case parts[0] == "sensors" && len(parts) == 1 && r.Method == http.MethodPost:
		e.dashboardCreateSensor(w, r)
	case parts[0] == "sensors" && len(parts) == 2 && r.Method == http.MethodDelete:
		id, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			http.Error(w, "invalid sensor id", http.StatusBadRequest)
			return
		}
		e.dashboardDeleteSensor(w, r, id)
	default:
		http.NotFound(w, r)
	}
}

func (e Extension) dashboardLogin(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if !subtleCompare([]byte(req.Token), []byte(e.Token)) {
		http.Error(w, "wrong token", http.StatusUnauthorized)
		return
	}
	e.setSessionCookie(w, r, e.signSession(time.Now().Add(sessionTTL)), int(sessionTTL.Seconds()))
	extensionJSON(w, map[string]bool{"authenticated": true}, nil)
}

// --- dashboard types --------------------------------------------------------

type dashboardActor struct {
	ID          int64             `json:"id"`
	IP          string            `json:"ip"`
	JA4         string            `json:"ja4"`
	UA          string            `json:"ua"`
	FirstSeen   string            `json:"first_seen"`
	LastSeen    string            `json:"last_seen"`
	Requests    int               `json:"requests"`
	RuleScore   int               `json:"rule_score"`
	Class       string            `json:"class"`
	Signals     []dashboardSignal `json:"signals"`
	Verified    string            `json:"verified"`
	Triage      *dashboardVerdict `json:"triage"`
	TriageScore *int              `json:"triage_score"`
	TriagedAt   *string           `json:"triaged_at"`
	Risk        int               `json:"risk"`
	DismissedAt *string           `json:"dismissed_at"`
}

type dashboardSignal struct {
	Code   string `json:"code"`
	Weight int    `json:"weight"`
	Detail string `json:"detail"`
}

type dashboardVerdict struct {
	Classification    string   `json:"classification"`
	Risk              int      `json:"risk"`
	Confidence        float64  `json:"confidence"`
	Summary           string   `json:"summary"`
	Evidence          []string `json:"evidence"`
	RecommendedAction string   `json:"recommended_action"`
	Scope             string   `json:"scope"`
	TTLMinutes        int      `json:"ttl_minutes"`
	Model             string   `json:"model"`
}

type dashboardRequest struct {
	TS         string            `json:"ts"`
	IP         string            `json:"ip"`
	Method     string            `json:"method"`
	Host       string            `json:"host"`
	Path       string            `json:"path"`
	Query      string            `json:"query,omitempty"`
	Proto      string            `json:"proto"`
	Status     int               `json:"status"`
	DurationMS float64           `json:"duration_ms"`
	BytesIn    int64             `json:"bytes_in"`
	BytesOut   int64             `json:"bytes_out"`
	UA         string            `json:"ua,omitempty"`
	Referer    string            `json:"referer,omitempty"`
	Headers    []string          `json:"headers,omitempty"`
	Hints      map[string]string `json:"hints,omitempty"`
	JA4        string            `json:"ja4,omitempty"`
	Action     string            `json:"action"`
}

type dashboardDecision struct {
	ID         int64                `json:"id"`
	ActorID    *int64               `json:"actor_id"`
	IP         string               `json:"ip"`
	JA4        string               `json:"ja4"`
	Kind       string               `json:"kind"`
	RPM        int                  `json:"rpm"`
	TTLMinutes int                  `json:"ttl_minutes"`
	Reason     string               `json:"reason"`
	Source     string               `json:"source"`
	Status     string               `json:"status"`
	CreatedAt  string               `json:"created_at"`
	DecidedAt  *string              `json:"decided_at"`
	ExpiresAt  *string              `json:"expires_at"`
	Actor      *dashboardActorBrief `json:"actor,omitempty"`
}

type dashboardActorBrief struct {
	UA    string `json:"ua"`
	Class string `json:"class"`
	Risk  int    `json:"risk"`
}

type dashboardOverview struct {
	Stats dashboardOverviewStats `json:"stats"`
	LLM   string                 `json:"llm"`
}

type dashboardOverviewStats struct {
	Requests24h      int64            `json:"requests_24h"`
	Actors24h        int64            `json:"actors_24h"`
	Bands            map[string]int64 `json:"bands"`
	Agents24h        int64            `json:"agents_24h"`
	PendingDecisions int64            `json:"pending_decisions"`
	ActiveDecisions  int64            `json:"active_decisions"`
	FlaggedEgress    int64            `json:"flagged_egress"`
}

type dashboardEgress struct {
	ID          int64    `json:"id"`
	SensorID    int64    `json:"sensor_id"`
	Comm        string   `json:"comm"`
	UID         uint32   `json:"uid"`
	DstIP       string   `json:"dst_ip"`
	DstPort     uint16   `json:"dst_port"`
	FirstSeen   string   `json:"first_seen"`
	LastSeen    string   `json:"last_seen"`
	Connections int64    `json:"connections"`
	LastPID     uint32   `json:"last_pid"`
	Flags       []string `json:"flags"`
}

type dashboardSensor struct {
	ID          int64   `json:"id"`
	Name        string  `json:"name"`
	CreatedAt   string  `json:"created_at"`
	LastSeenAt  *string `json:"last_seen_at"`
	EgressSince *string `json:"egress_since"`
	Dropped     int64   `json:"dropped"`
}

// --- dashboard handlers -----------------------------------------------------

func (e Extension) dashboardOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := time.Now()
	day := now.Add(-24 * time.Hour)

	actors, err := e.History.Actors(ctx, 1000)
	if err != nil {
		extensionJSON(w, nil, err)
		return
	}
	decisions, err := e.History.Suggestions(ctx, "")
	if err != nil {
		extensionJSON(w, nil, err)
		return
	}
	egress, err := e.History.Egress(ctx, day, 1000)
	if err != nil {
		extensionJSON(w, nil, err)
		return
	}

	var requests24h, actors24h, agents24h int64
	bands := map[string]int64{"hostile": 0, "suspicious": 0, "watch": 0, "benign": 0}
	pendingDecisions := int64(0)
	activeDecisions := int64(0)
	flaggedEgress := int64(0)

	for _, a := range actors {
		if a.LastSeen.After(day) {
			actors24h++
			if strings.Contains(strings.ToLower(a.UserAgent), "gpt") ||
				strings.Contains(strings.ToLower(a.UserAgent), "claude") ||
				strings.Contains(strings.ToLower(a.UserAgent), "bot") {
				agents24h++
			}
			switch {
			case a.Risk >= 80:
				bands["hostile"]++
			case a.Risk >= 50:
				bands["suspicious"]++
			case a.Risk >= 20:
				bands["watch"]++
			default:
				bands["benign"]++
			}
		}
	}
	for _, d := range decisions {
		if d.Status == "pending" {
			pendingDecisions++
		} else if d.Status == "approved" {
			activeDecisions++
		}
	}
	for range egress {
		flaggedEgress++
	}

	llm := ""
	if e.Triager != nil {
		llm = e.Triager.Model()
	}

	out := dashboardOverview{
		Stats: dashboardOverviewStats{
			Requests24h:      requests24h,
			Actors24h:        actors24h,
			Bands:            bands,
			Agents24h:        agents24h,
			PendingDecisions: pendingDecisions,
			ActiveDecisions:  activeDecisions,
			FlaggedEgress:    flaggedEgress,
		},
		LLM: llm,
	}
	extensionJSON(w, out, nil)
}

func actorKeyToIPJA4(key string) (ip, ja4 string) {
	parts := strings.SplitN(key, "|", 2)
	ip = parts[0]
	if len(parts) > 1 {
		ja4 = parts[1]
	}
	return
}

func ruleSignals(details []string) []triage.RuleSignal {
	out := make([]triage.RuleSignal, 0, len(details))
	for _, d := range details {
		out = append(out, triage.RuleSignal{Code: signalCode(d), Weight: 0, Detail: d})
	}
	return out
}

func signalCode(detail string) string {
	code := strings.ToLower(strings.ReplaceAll(strings.ReplaceAll(detail, " ", "_"), "/", "_"))
	if len(code) > 40 {
		code = code[:40]
	}
	return code
}

func (e Extension) dashboardActors(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	filter := r.URL.Query().Get("filter")
	actors, err := e.History.Actors(ctx, 300)
	if err != nil {
		extensionJSON(w, nil, err)
		return
	}
	out := make([]dashboardActor, 0, len(actors))
	for _, a := range actors {
		switch filter {
		case "suspicious":
			if a.Risk < 50 || a.Identity != "" {
				continue
			}
		case "agents":
			ua := strings.ToLower(a.UserAgent)
			if !strings.Contains(ua, "gpt") && !strings.Contains(ua, "claude") && !strings.Contains(ua, "bot") {
				continue
			}
		case "verified":
			if a.Identity == "" {
				continue
			}
		case "dismissed":
			// vigilante doesn't track dismissals separately
			continue
		default: // all
			if a.Identity != "" {
				continue
			}
		}
		ip, ja4 := actorKeyToIPJA4(a.Key)
		signals := make([]dashboardSignal, 0, len(a.Signals))
		for _, s := range a.Signals {
			signals = append(signals, dashboardSignal{Code: signalCode(s), Weight: 0, Detail: s})
		}
		out = append(out, dashboardActor{
			ID:          actorID(a.Key),
			IP:          ip,
			JA4:         ja4,
			UA:          a.UserAgent,
			FirstSeen:   a.FirstSeen.UTC().Format(time.RFC3339),
			LastSeen:    a.LastSeen.UTC().Format(time.RFC3339),
			Requests:    a.Requests,
			RuleScore:   a.Risk,
			Class:       a.Class,
			Signals:     signals,
			Verified:    a.Identity,
			Triage:      nil,
			Risk:        a.Risk,
			DismissedAt: nil,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Risk != out[j].Risk {
			return out[i].Risk > out[j].Risk
		}
		return out[i].LastSeen > out[j].LastSeen
	})
	extensionJSON(w, out, nil)
}

func (e Extension) dashboardActor(w http.ResponseWriter, r *http.Request, id int64) {
	ctx := r.Context()
	// Find the actor by matching hashed ID.
	actors, err := e.History.Actors(ctx, 1000)
	if err != nil {
		extensionJSON(w, nil, err)
		return
	}
	var found *history.Actor
	for i := range actors {
		if actorID(actors[i].Key) == id {
			found = &actors[i]
			break
		}
	}
	if found == nil {
		extensionJSON(w, nil, errors.New("actor not found"))
		return
	}
	ip, ja4 := actorKeyToIPJA4(found.Key)
	flows, err := e.History.Flows(ctx, found.Key, time.Time{}, 300)
	if err != nil {
		extensionJSON(w, nil, err)
		return
	}
	requests := make([]dashboardRequest, 0, len(flows))
	for _, f := range flows {
		path, query := splitQuery(f.Path)
		requests = append(requests, dashboardRequest{
			TS:         f.Timestamp.UTC().Format(time.RFC3339),
			IP:         f.SrcAddr,
			Method:     f.Method,
			Host:       f.Host,
			Path:       path,
			Query:      query,
			Proto:      f.Protocol,
			Status:     f.Status,
			DurationMS: f.Duration.Seconds() * 1000,
			BytesIn:    f.BytesIn,
			BytesOut:   f.BytesOut,
			UA:         f.UserAgent,
			Headers:    headerSlice(f.Headers),
			JA4:        f.JA4,
			Action:     f.Verdict,
		})
	}
	suggestions, err := e.History.Suggestions(ctx, "")
	if err != nil {
		extensionJSON(w, nil, err)
		return
	}
	var decisions []dashboardDecision
	for _, s := range suggestions {
		if s.ActorKey == found.Key {
			decisions = append(decisions, suggestionToDecision(s))
		}
	}
	extensionJSON(w, map[string]any{
		"actor": dashboardActor{
			ID:          actorID(found.Key),
			IP:          ip,
			JA4:         ja4,
			UA:          found.UserAgent,
			FirstSeen:   found.FirstSeen.UTC().Format(time.RFC3339),
			LastSeen:    found.LastSeen.UTC().Format(time.RFC3339),
			Requests:    found.Requests,
			RuleScore:   found.Risk,
			Class:       found.Class,
			Signals:     signalDetails(found.Signals),
			Verified:    found.Identity,
			Triage:      nil,
			Risk:        found.Risk,
			DismissedAt: nil,
		},
		"requests":  requests,
		"decisions": decisions,
	}, nil)
}

func splitQuery(path string) (string, string) {
	if i := strings.IndexByte(path, '?'); i >= 0 {
		return path[:i], path[i+1:]
	}
	return path, ""
}

func headerSlice(h map[string]string) []string {
	if len(h) == 0 {
		return nil
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%s: %s", k, h[k]))
	}
	return out
}

func signalDetails(details []string) []dashboardSignal {
	out := make([]dashboardSignal, 0, len(details))
	for _, d := range details {
		out = append(out, dashboardSignal{Code: signalCode(d), Weight: 0, Detail: d})
	}
	return out
}

func suggestionToDecision(s history.Suggestion) dashboardDecision {
	id := actorID(s.ID)
	source := "rules"
	if strings.HasPrefix(s.ID, "triage-") {
		source = "llm"
	}
	ip, ja4 := actorKeyToIPJA4(s.ActorKey)
	var actorIDPtr *int64
	if s.ActorKey != "" {
		v := actorID(s.ActorKey)
		actorIDPtr = &v
	}
	var decidedAt, expiresAt *string
	if s.ResolvedAt != nil {
		t := s.ResolvedAt.UTC().Format(time.RFC3339)
		decidedAt = &t
	}
	return dashboardDecision{
		ID:         id,
		ActorID:    actorIDPtr,
		IP:         ip,
		JA4:        ja4,
		Kind:       s.Action,
		RPM:        0,
		TTLMinutes: 0,
		Reason:     s.Reason,
		Source:     source,
		Status:     s.Status,
		CreatedAt:  s.CreatedAt.UTC().Format(time.RFC3339),
		DecidedAt:  decidedAt,
		ExpiresAt:  expiresAt,
	}
}

func (e Extension) dashboardTriage(w http.ResponseWriter, r *http.Request, id int64) {
	if e.Triager == nil {
		http.Error(w, "LLM triage is not configured", http.StatusServiceUnavailable)
		return
	}
	ctx := r.Context()
	actors, err := e.History.Actors(ctx, 1000)
	if err != nil {
		extensionJSON(w, nil, err)
		return
	}
	var found *history.Actor
	for i := range actors {
		if actorID(actors[i].Key) == id {
			found = &actors[i]
			break
		}
	}
	if found == nil {
		extensionJSON(w, nil, errors.New("actor not found"))
		return
	}
	flows, err := e.History.Flows(ctx, found.Key, time.Now().Add(-24*time.Hour), 2000)
	if err != nil {
		extensionJSON(w, nil, err)
		return
	}
	ip, _ := actorKeyToIPJA4(found.Key)
	in := triage.NewInput(ip, found.Fingerprint, identity.Result{Verified: found.Identity}, triage.RuleResult{
		Score:   found.Risk,
		Class:   found.Class,
		Signals: ruleSignals(found.Signals),
	}, flows)
	verdict, err := e.Triager.Triage(ctx, in)
	if err != nil {
		extensionJSON(w, nil, err)
		return
	}
	extensionJSON(w, dashboardVerdict{
		Classification:    verdict.Classification,
		Risk:              verdict.Risk,
		Confidence:        verdict.Confidence,
		Summary:           verdict.Summary,
		Evidence:          verdict.Evidence,
		RecommendedAction: verdict.Action,
		Scope:             verdict.Scope,
		TTLMinutes:        verdict.TTLMinutes,
		Model:             verdict.Model,
	}, nil)
}

func (e Extension) dashboardDismiss(w http.ResponseWriter, r *http.Request, id int64) {
	// Vigilante's history store doesn't track dismissals as a separate concept;
	// rejecting a suggestion is the closest equivalent.
	actors, err := e.History.Actors(r.Context(), 1000)
	if err != nil {
		extensionJSON(w, nil, err)
		return
	}
	for _, a := range actors {
		if actorID(a.Key) == id {
			suggestions, err := e.History.Suggestions(r.Context(), "pending")
			if err != nil {
				extensionJSON(w, nil, err)
				return
			}
			for _, s := range suggestions {
				if s.ActorKey == a.Key {
					if _, err := e.History.ResolveSuggestion(r.Context(), s.ID, "rejected", ""); err != nil {
						extensionJSON(w, nil, err)
						return
					}
					extensionJSON(w, map[string]bool{"dismissed": true}, nil)
					return
				}
			}
			http.Error(w, "no pending suggestion for actor", http.StatusNotFound)
			return
		}
	}
	http.Error(w, "actor not found", http.StatusNotFound)
}

func (e Extension) dashboardDecisions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	suggestions, err := e.History.Suggestions(ctx, "")
	if err != nil {
		extensionJSON(w, nil, err)
		return
	}
	out := make([]dashboardDecision, 0, len(suggestions))
	for _, s := range suggestions {
		out = append(out, suggestionToDecision(s))
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt > out[j].CreatedAt
	})
	extensionJSON(w, out, nil)
}

func (e Extension) dashboardCreateDecision(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req struct {
		ActorID    *int64 `json:"actor_id"`
		IP         string `json:"ip"`
		JA4        string `json:"ja4"`
		Kind       string `json:"kind"`
		RPM        int    `json:"rpm"`
		TTLMinutes int    `json:"ttl_minutes"`
		Reason     string `json:"reason"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Kind != "block" && req.Kind != "challenge" && req.Kind != "rate_limit" {
		http.Error(w, "kind must be block, challenge or rate_limit", http.StatusBadRequest)
		return
	}
	if req.TTLMinutes < 1 || req.TTLMinutes > 60*24*90 {
		http.Error(w, "ttl_minutes must be between 1 and 129600", http.StatusBadRequest)
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "Manual decision"
	}
	ip, _ := actorKeyToIPJA4(req.JA4)
	if req.IP != "" {
		ip = req.IP
	}
	s := history.Suggestion{
		ID: "manual-" + hex.EncodeToString(randBytes(8)), ActorKey: ip + "|" + req.JA4,
		Action: req.Kind,
		Scope:  decision.ScopeIP,
		Target: ip,
		Reason: reason,
		Status: "approved",
	}
	if err := e.History.Suggest(r.Context(), s); err != nil {
		extensionJSON(w, nil, err)
		return
	}
	if e.Actions != nil {
		_, err := e.Actions.Execute(r.Context(), action.Request{
			Action: req.Kind,
			Scope:  decision.ScopeIP,
			Target: ip,
			Actor:  ip,
			Reason: reason,
		})
		if err != nil {
			extensionJSON(w, nil, err)
			return
		}
	}
	extensionJSON(w, suggestionToDecision(s), nil)
}

func (e Extension) dashboardTransition(w http.ResponseWriter, r *http.Request, idStr, verb string) {
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.Error(w, "invalid decision id", http.StatusBadRequest)
		return
	}
	var status string
	switch verb {
	case "approve":
		status = "approved"
	case "reject":
		status = "rejected"
	case "revoke":
		status = "revoked"
	default:
		http.NotFound(w, r)
		return
	}
	suggestions, err := e.History.Suggestions(r.Context(), "")
	if err != nil {
		extensionJSON(w, nil, err)
		return
	}
	var found *history.Suggestion
	for i := range suggestions {
		if actorID(suggestions[i].ID) == id {
			found = &suggestions[i]
			break
		}
	}
	if found == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if verb == "approve" && e.Actions != nil {
		ip, _ := actorKeyToIPJA4(found.ActorKey)
		_, err := e.Actions.Execute(r.Context(), action.Request{
			Action: found.Action,
			Scope:  found.Scope,
			Target: found.Target,
			Actor:  ip,
			Reason: found.Reason,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
	}
	out, err := e.History.ResolveSuggestion(r.Context(), found.ID, status, found.DecisionID)
	if err != nil {
		extensionJSON(w, nil, err)
		return
	}
	extensionJSON(w, suggestionToDecision(out), nil)
}

func (e Extension) dashboardEgress(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	since := time.Now().Add(-24 * time.Hour)
	if h := r.URL.Query().Get("hours"); h != "" {
		if n, err := strconv.Atoi(h); err == nil && n > 0 {
			since = time.Now().Add(-time.Duration(n) * time.Hour)
		}
	}
	egress, err := e.History.Egress(ctx, since, 500)
	if err != nil {
		extensionJSON(w, nil, err)
		return
	}
	out := make([]dashboardEgress, 0, len(egress))
	for _, eg := range egress {
		flags := []string{}
		out = append(out, dashboardEgress{
			ID:          int64(0), // egress IDs are DB auto-increment, not exposed
			SensorID:    0,
			Comm:        eg.Comm,
			UID:         eg.UID,
			DstIP:       eg.DstIP,
			DstPort:     eg.DstPort,
			FirstSeen:   eg.TS.UTC().Format(time.RFC3339),
			LastSeen:    eg.TS.UTC().Format(time.RFC3339),
			Connections: int64(eg.Count),
			LastPID:     eg.PID,
			Flags:       flags,
		})
	}
	extensionJSON(w, out, nil)
}

func (e Extension) dashboardCreateSensor(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}
	key := "vk_" + hex.EncodeToString(randBytes(24))
	s := dashboardSensor{
		ID:        0,
		Name:      name,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		Dropped:   0,
	}
	extensionJSON(w, map[string]any{"sensor": s, "key": key}, nil)
}

func (e Extension) dashboardDeleteSensor(w http.ResponseWriter, r *http.Request, id int64) {
	http.Error(w, "sensors are not persisted in this mode", http.StatusNotImplemented)
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil
	}
	return b
}
