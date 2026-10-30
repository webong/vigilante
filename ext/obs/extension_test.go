package obs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/webong/vigilante/internal/action"
	responseaction "github.com/webong/vigilante/internal/action/response"
	"github.com/webong/vigilante/internal/decision"
	"github.com/webong/vigilante/internal/history"
)

func TestExtensionRequiresAuthAndApproves(t *testing.T) {
	s, err := history.Open(filepath.Join(t.TempDir(), "h.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Suggest(context.Background(), history.Suggestion{ID: "s1", ActorKey: "203.0.113.8", Action: "challenge", Scope: decision.ScopeIP, Target: "203.0.113.8"}); err != nil {
		t.Fatal(err)
	}
	set := decision.NewSet()
	registry := action.New(action.Options{Set: set, Allow: []string{"challenge"}})
	if err := registry.Register(responseaction.New("challenge")); err != nil {
		t.Fatal(err)
	}
	handler := NewExtensionBridge(Extension{History: s, Actions: registry, Token: "secret"}, nil)
	r := httptest.NewRequest("POST", "/history/review/s1/approve", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated=%d", w.Code)
	}
	r = httptest.NewRequest("POST", "/history/review/s1/approve", nil)
	r.Header.Set("Authorization", "Bearer secret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("approve=%d %s", w.Code, w.Body)
	}
	if _, ok := set.Lookup("203.0.113.8", "", ""); !ok {
		t.Fatal("approved decision not enforced")
	}
	r = httptest.NewRequest("POST", "/history/review/s1/revoke", nil)
	r.Header.Set("X-Vigilante-Token", "secret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("revoke=%d %s", w.Code, w.Body)
	}
	var out history.Suggestion
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || out.Status != "revoked" {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}
