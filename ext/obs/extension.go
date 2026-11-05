package obs

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/webong/vigilante/internal/action"
	"github.com/webong/vigilante/internal/decision"
	"github.com/webong/vigilante/internal/fleet"
	"github.com/webong/vigilante/internal/history"
)

// Extension serves durable history and human review as REST data alongside
// the read-only obs plugin. Every endpoint requires the operator token. The
// operator console is the separate lookout plugin (ext/lookout).
type Extension struct {
	History *history.Store
	Actions *action.Registry
	Token   string
}

func (e Extension) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e.Token == "" {
		http.Error(w, "operator token is not configured", http.StatusServiceUnavailable)
		return
	}
	if !e.authorized(r) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="vigilante"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/obs/"), "/")
	if e.History == nil {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	switch {
	case path == "history/actors" && r.Method == http.MethodGet:
		out, err := e.History.Actors(ctx, queryLimit(r))
		extensionJSON(w, out, err)
	case strings.HasPrefix(path, "history/actors/") && r.Method == http.MethodGet:
		key, err := url.PathUnescape(strings.TrimPrefix(path, "history/actors/"))
		if err != nil {
			http.Error(w, "invalid actor", http.StatusBadRequest)
			return
		}
		a, err := e.History.Actor(ctx, key)
		if err != nil {
			extensionJSON(w, nil, err)
			return
		}
		flows, err := e.History.Flows(ctx, key, time.Time{}, 500)
		extensionJSON(w, map[string]any{"actor": a, "flows": flows}, err)
	case path == "history/flows" && r.Method == http.MethodGet:
		out, err := e.History.Flows(ctx, r.URL.Query().Get("actor"), time.Time{}, queryLimit(r))
		extensionJSON(w, out, err)
	case path == "history/review" && r.Method == http.MethodGet:
		out, err := e.History.Suggestions(ctx, r.URL.Query().Get("status"))
		extensionJSON(w, out, err)
	case strings.HasPrefix(path, "history/review/") && r.Method == http.MethodPost:
		e.resolve(w, r, strings.TrimPrefix(path, "history/review/"))
	case path == "history/egress" && r.Method == http.MethodGet:
		since := time.Now().Add(-24 * time.Hour)
		if h := r.URL.Query().Get("hours"); h != "" {
			var hours int
			if _, err := fmt.Sscanf(h, "%d", &hours); err == nil && hours > 0 {
				since = time.Now().Add(-time.Duration(hours) * time.Hour)
			}
		}
		out, err := e.History.Egress(ctx, since, queryLimit(r))
		extensionJSON(w, out, err)
	case path == "history/sensors" && r.Method == http.MethodGet:
		out, err := e.History.Sensors(ctx)
		extensionJSON(w, out, err)
	case path == "history/sensors" && r.Method == http.MethodPost:
		e.createSensor(w, r)
	case strings.HasPrefix(path, "history/sensors/") && r.Method == http.MethodDelete:
		id, err := strconv.ParseInt(strings.TrimPrefix(path, "history/sensors/"), 10, 64)
		if err != nil {
			http.Error(w, "invalid sensor id", http.StatusBadRequest)
			return
		}
		if err := e.History.DeleteSensor(ctx, id); err != nil {
			extensionJSON(w, nil, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func (e Extension) createSensor(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.Name) == "" {
		http.Error(w, "sensor name is required", http.StatusBadRequest)
		return
	}
	plain, hash, err := fleet.GenerateKey()
	if err != nil {
		extensionJSON(w, nil, err)
		return
	}
	sensor, err := e.History.CreateSensor(r.Context(), req.Name, hash)
	if err != nil {
		extensionJSON(w, nil, err)
		return
	}
	extensionJSON(w, map[string]any{"sensor": sensor, "key": plain}, nil)
}

func (e Extension) resolve(w http.ResponseWriter, r *http.Request, id string) {
	var verb string
	parts := strings.Split(id, "/")
	if len(parts) != 2 {
		http.NotFound(w, r)
		return
	}
	id, verb = parts[0], parts[1]
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
	if verb == "revoke" {
		out, err := e.revoke(r.Context(), id)
		extensionJSON(w, out, err)
		return
	}
	pending, err := e.History.Suggestions(r.Context(), "pending")
	if err != nil {
		extensionJSON(w, nil, err)
		return
	}
	var found *history.Suggestion
	for i := range pending {
		if pending[i].ID == id {
			found = &pending[i]
			break
		}
	}
	if found == nil {
		extensionJSON(w, nil, sql.ErrNoRows)
		return
	}
	decisionID := ""
	if verb == "approve" {
		if e.Actions == nil {
			http.Error(w, "action registry unavailable", http.StatusServiceUnavailable)
			return
		}
		d, err := e.Actions.Execute(r.Context(), action.Request{Action: found.Action, Scope: found.Scope, Target: found.Target, Actor: found.ActorKey, Reason: found.Reason, Operator: "vigilante/operator", Confirmed: true})
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		decisionID = d.ID
	}
	out, err := e.History.ResolveSuggestion(r.Context(), id, status, decisionID)
	extensionJSON(w, out, err)
}
func (e Extension) revoke(ctx context.Context, id string) (history.Suggestion, error) {
	all, err := e.History.Suggestions(ctx, "")
	if err != nil {
		return history.Suggestion{}, err
	}
	for _, s := range all {
		if s.ID == id && s.DecisionID != "" {
			if e.Actions == nil {
				return history.Suggestion{}, errors.New("action registry unavailable")
			}
			if _, err = e.Actions.Revert(ctx, s.DecisionID); err != nil {
				return history.Suggestion{}, err
			}
			return e.History.ResolveSuggestion(ctx, id, "revoked", s.DecisionID)
		}
	}
	return history.Suggestion{}, sql.ErrNoRows
}
func queryLimit(r *http.Request) int {
	limit := 100
	_, _ = fmt.Sscanf(r.URL.Query().Get("limit"), "%d", &limit)
	return limit
}
func extensionJSON(w http.ResponseWriter, v any, err error) {
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, sql.ErrNoRows) {
			status = http.StatusNotFound
		}
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(v)
}

// Compile-time check that extension scopes continue to use the core contract.
var _ = decision.ScopeIP

func (e Extension) authorized(r *http.Request) bool {
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		token = r.Header.Get("X-Vigilante-Token")
	}
	return e.Token != "" && subtle.ConstantTimeCompare([]byte(token), []byte(e.Token)) == 1
}
