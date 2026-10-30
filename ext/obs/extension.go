package obs

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/webong/vigilante/ext/triage"
	"github.com/webong/vigilante/internal/action"
	"github.com/webong/vigilante/internal/decision"
	"github.com/webong/vigilante/internal/history"
	"github.com/webong/vigilante/web"
)

// Extension serves durable history and human review alongside the existing
// read-only obs plugin, plus the web dashboard API. Every endpoint requires
// the configured operator token or a valid dashboard session.
type Extension struct {
	History *history.Store
	Actions *action.Registry
	Triager triage.Service
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
	if strings.HasPrefix(path, "api/") {
		e.dashboardAPI(w, r, strings.TrimPrefix(path, "api/"))
		return
	}
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
			fmt.Sscanf(h, "%d", new(int))
		}
		out, err := e.History.Egress(ctx, since, queryLimit(r))
		extensionJSON(w, out, err)
	default:
		e.serveSPA(w, r)
	}
}

// serveSPA serves the built dashboard from the embedded dist directory. Any
// path that is not an API or history route falls back to index.html so the
// single-page app's client-side routes survive a reload.
func (e Extension) serveSPA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	files := http.FileServerFS(web.UI())
	p := strings.TrimPrefix(r.URL.Path, "/obs/")
	if p != "" && p != "obs" {
		if f, err := web.UI().Open(p); err == nil {
			f.Close()
			if strings.HasPrefix(p, "assets/") {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			}
			files.ServeHTTP(w, r)
			return
		}
	}
	index, err := fs.ReadFile(web.UI(), "index.html")
	if err != nil {
		http.Error(w, "dashboard not built: run `bun run build` in web/", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(index))
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
