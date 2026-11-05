package lookout

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/webong/vigilante/ext/triage"
	"github.com/webong/vigilante/internal/action"
	blockaction "github.com/webong/vigilante/internal/action/block"
	responseaction "github.com/webong/vigilante/internal/action/response"
	"github.com/webong/vigilante/internal/block"
	"github.com/webong/vigilante/internal/decision"
	"github.com/webong/vigilante/internal/flow"
	"github.com/webong/vigilante/internal/history"
)

type mockTriager struct {
	model string
}

func (m mockTriager) Model() string { return m.model }
func (m mockTriager) Triage(ctx context.Context, in triage.Input) (triage.Verdict, error) {
	return triage.Verdict{Model: m.model, Classification: "malicious", Risk: 90, Action: "block"}, nil
}

func setupLookoutTest(t *testing.T, token string) (*Bridge, *history.Store, *action.Registry, *decision.Set) {
	t.Helper()
	s, err := history.Open(filepath.Join(t.TempDir(), "lookout-test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	set := decision.NewSet()
	registry := action.New(action.Options{Set: set, Allow: []string{"block", "challenge", "rate_limit"}})
	enforcer, err := block.New(block.Options{Mode: "log"})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(blockaction.New(enforcer)); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(responseaction.New("challenge")); err != nil {
		t.Fatal(err)
	}

	host := CoreHost{
		History: s,
		Actions: registry,
		Triager: mockTriager{model: "test-model"},
	}

	bridge, closeFn, err := Open(context.Background(), Options{Token: token}, host)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = closeFn(context.Background()) })

	return bridge, s, registry, set
}

func TestLookoutContract(t *testing.T) {
	id := GuestIdentity()
	if id.ID != "vigilante/lookout" {
		t.Fatalf("unexpected id: %s", id.ID)
	}
	desc, guest, err := BuildGuest(Options{Token: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if guest == nil {
		t.Fatal("expected non-nil guest")
	}
	if len(desc.Reverse) != 1 || desc.Reverse[0].Name != ConsoleContractName {
		t.Fatalf("unexpected reverse contracts: %+v", desc.Reverse)
	}
}

func TestLookoutAuthAndSession(t *testing.T) {
	bridge, _, _, _ := setupLookoutTest(t, "op-secret")

	// 1. Unauthenticated session check
	req := httptest.NewRequest(http.MethodGet, "/api/session", nil)
	rec := httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("session code = %d", rec.Code)
	}
	var sessResp struct {
		Authenticated bool `json:"authenticated"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sessResp); err != nil || sessResp.Authenticated {
		t.Fatalf("expected unauthenticated session: %+v, err: %v", sessResp, err)
	}

	// 2. Unauthenticated access to protected route fails
	req = httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	rec = httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for overview, got %d", rec.Code)
	}

	// 3. Login with wrong token
	loginBody, _ := json.Marshal(map[string]string{"token": "wrong-token"})
	req = httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(loginBody))
	rec = httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for bad login, got %d", rec.Code)
	}

	// 4. Login with correct token
	loginBody, _ = json.Marshal(map[string]string{"token": "op-secret"})
	req = httptest.NewRequest(http.MethodPost, "/api/login", bytes.NewReader(loginBody))
	rec = httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for login, got %d, body: %s", rec.Code, rec.Body.String())
	}
	cookie := rec.Header().Get("Set-Cookie")
	if cookie == "" || !strings.Contains(cookie, sessionCookie) {
		t.Fatalf("expected session cookie, got %q", cookie)
	}

	// Extract cookie value for subsequent requests
	cookieVal := rec.Result().Cookies()[0]

	// 5. Check session with cookie
	req = httptest.NewRequest(http.MethodGet, "/api/session", nil)
	req.AddCookie(cookieVal)
	rec = httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	if err := json.Unmarshal(rec.Body.Bytes(), &sessResp); err != nil || !sessResp.Authenticated {
		t.Fatalf("expected authenticated session: %+v, err: %v", sessResp, err)
	}

	// 6. Access protected route with cookie
	req = httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.AddCookie(cookieVal)
	rec = httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for overview with cookie, got %d: %s", rec.Code, rec.Body.String())
	}
	var ov dashboardOverview
	if err := json.Unmarshal(rec.Body.Bytes(), &ov); err != nil {
		t.Fatalf("failed to decode overview: %v", err)
	}
	if ov.LLM != "test-model" {
		t.Fatalf("expected llm model 'test-model', got %q", ov.LLM)
	}

	// 7. Access protected route with Bearer token
	req = httptest.NewRequest(http.MethodGet, "/api/overview", nil)
	req.Header.Set("Authorization", "Bearer op-secret")
	rec = httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for overview with Bearer, got %d", rec.Code)
	}

	// 8. Logout clears cookie
	req = httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	rec = httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for logout, got %d", rec.Code)
	}
}

func TestLookoutActorsAndDecisions(t *testing.T) {
	bridge, store, _, set := setupLookoutTest(t, "op-secret")
	ctx := context.Background()

	// Seed a flow and an actor
	now := time.Now()
	err := store.Ingest(ctx, flow.Event{
		FlowID:    "flow-1",
		Timestamp: now,
		SrcAddr:   "198.51.100.42",
		Method:    "GET",
		Host:      "example.com",
		Path:      "/secret",
		Verdict:   "block",
		JA4:       "t13d1516h2",
		UserAgent: "BadBot/1.0",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = store.Analyze(ctx, history.Actor{
		Key:       "198.51.100.42|t13d1516h2",
		IP:        "198.51.100.42",
		UserAgent: "BadBot/1.0",
		FirstSeen: now,
		LastSeen:  now,
		Requests:  1,
		Class:     "bot",
		Risk:      90,
		Signals:   []string{"high_rate"},
	})
	if err != nil {
		t.Fatal(err)
	}

	authHeader := "Bearer op-secret"

	// 1. List actors
	req := httptest.NewRequest(http.MethodGet, "/api/actors?filter=all", nil)
	req.Header.Set("Authorization", authHeader)
	rec := httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("actors code = %d: %s", rec.Code, rec.Body.String())
	}
	var actors []dashboardActor
	if err := json.Unmarshal(rec.Body.Bytes(), &actors); err != nil {
		t.Fatalf("unmarshal actors: %v", err)
	}
	if len(actors) == 0 {
		t.Fatal("expected at least 1 actor")
	}
	targetActor := actors[0]
	if targetActor.IP != "198.51.100.42" {
		t.Fatalf("actor IP = %q, want 198.51.100.42", targetActor.IP)
	}

	// 2. Fetch actor detail
	actorURL := fmt.Sprintf("/api/actors/%d", targetActor.ID)
	req = httptest.NewRequest(http.MethodGet, actorURL, nil)
	req.Header.Set("Authorization", authHeader)
	rec = httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("actor detail code = %d: %s", rec.Code, rec.Body.String())
	}
	var detail struct {
		Actor    dashboardActor     `json:"actor"`
		Requests []dashboardRequest `json:"requests"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("unmarshal actor detail: %v", err)
	}
	if len(detail.Requests) == 0 {
		t.Fatal("expected actor requests")
	}

	// 3. Create a manual decision (e.g. block)
	decBody, _ := json.Marshal(map[string]any{
		"actor_id":    targetActor.ID,
		"ip":          targetActor.IP,
		"ja4":         targetActor.JA4,
		"kind":        "block",
		"ttl_minutes": 60,
		"reason":      "testing block",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/decisions", bytes.NewReader(decBody))
	req.Header.Set("Authorization", authHeader)
	rec = httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create decision code = %d: %s", rec.Code, rec.Body.String())
	}
	var createdDec dashboardDecision
	if err := json.Unmarshal(rec.Body.Bytes(), &createdDec); err != nil {
		t.Fatalf("unmarshal created decision: %v", err)
	}
	if createdDec.Status != "approved" {
		t.Fatalf("expected approved status, got %s", createdDec.Status)
	}

	// Verify the decision was enforced in the decision.Set
	if _, ok := set.Lookup(targetActor.IP, "", ""); !ok {
		t.Fatalf("expected %s to be blocked in decision.Set", targetActor.IP)
	}

	// 4. List decisions
	req = httptest.NewRequest(http.MethodGet, "/api/decisions", nil)
	req.Header.Set("Authorization", authHeader)
	rec = httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("decisions code = %d: %s", rec.Code, rec.Body.String())
	}
	var decisions []dashboardDecision
	if err := json.Unmarshal(rec.Body.Bytes(), &decisions); err != nil {
		t.Fatalf("unmarshal decisions: %v", err)
	}
	if len(decisions) == 0 {
		t.Fatal("expected at least 1 decision")
	}

	// 5. Revoke the decision
	revokeURL := fmt.Sprintf("/api/decisions/%d/revoke", createdDec.ID)
	req = httptest.NewRequest(http.MethodPost, revokeURL, nil)
	req.Header.Set("Authorization", authHeader)
	rec = httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke decision code = %d: %s", rec.Code, rec.Body.String())
	}
	var revokedDec dashboardDecision
	if err := json.Unmarshal(rec.Body.Bytes(), &revokedDec); err != nil {
		t.Fatalf("unmarshal revoked decision: %v", err)
	}
	if revokedDec.Status != "revoked" {
		t.Fatalf("expected revoked status, got %s", revokedDec.Status)
	}

	// Verify it was removed from decision.Set
	if _, ok := set.Lookup(targetActor.IP, "", ""); ok {
		t.Fatalf("expected %s to no longer be blocked in decision.Set", targetActor.IP)
	}
}

func TestLookoutTriage(t *testing.T) {
	bridge, store, _, _ := setupLookoutTest(t, "op-secret")
	ctx := context.Background()

	now := time.Now()
	err := store.Ingest(ctx, flow.Event{
		FlowID:         "flow-1",
		Timestamp:      now,
		SrcAddr:        "198.51.100.42",
		Method:         "GET",
		Host:           "example.com",
		Path:           "/admin",
		Verdict:        "block",
		TLSFingerprint: "t13d1516h2",
	})
	if err != nil {
		t.Fatal(err)
	}
	actorKey := "198.51.100.42|t13d1516h2"
	err = store.Analyze(ctx, history.Actor{
		Key:       actorKey,
		IP:        "198.51.100.42",
		FirstSeen: now,
		LastSeen:  now,
		Requests:  1,
		Risk:      75,
	})
	if err != nil {
		t.Fatal(err)
	}

	id := actorID(actorKey)
	triageURL := fmt.Sprintf("/api/actors/%d/triage", id)
	req := httptest.NewRequest(http.MethodPost, triageURL, nil)
	req.Header.Set("Authorization", "Bearer op-secret")
	rec := httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("triage code = %d: %s", rec.Code, rec.Body.String())
	}
	var verdict dashboardVerdict
	if err := json.Unmarshal(rec.Body.Bytes(), &verdict); err != nil {
		t.Fatalf("unmarshal verdict: %v", err)
	}
	if verdict.Classification != "malicious" || verdict.Model != "test-model" {
		t.Fatalf("unexpected verdict: %+v", verdict)
	}
}

func TestLookoutEgressAndSensors(t *testing.T) {
	bridge, store, _, _ := setupLookoutTest(t, "op-secret")
	ctx := context.Background()

	// Seed egress
	err := store.RecordEgress(ctx, history.Egress{
		TS:      time.Now(),
		Comm:    "curl",
		UID:     1000,
		PID:     12345,
		DstIP:   "93.184.216.34",
		DstPort: 443,
		Count:   5,
	})
	if err != nil {
		t.Fatal(err)
	}

	authHeader := "Bearer op-secret"

	// 1. Egress
	req := httptest.NewRequest(http.MethodGet, "/api/egress", nil)
	req.Header.Set("Authorization", authHeader)
	rec := httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("egress code = %d: %s", rec.Code, rec.Body.String())
	}
	var egressList []dashboardEgress
	if err := json.Unmarshal(rec.Body.Bytes(), &egressList); err != nil {
		t.Fatalf("unmarshal egress: %v", err)
	}
	if len(egressList) == 0 {
		t.Fatal("expected egress records")
	}

	// 2. Sensors endpoints (create, list, delete)
	req = httptest.NewRequest(http.MethodPost, "/api/sensors", strings.NewReader(`{"name":"edge-us-east-1"}`))
	req.Header.Set("Authorization", authHeader)
	rec = httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sensors create code = %d, body = %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Sensor dashboardSensor `json:"sensor"`
		Key    string          `json:"key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal created sensor: %v", err)
	}
	if created.Sensor.Name != "edge-us-east-1" || !strings.HasPrefix(created.Key, "vg_") {
		t.Fatalf("unexpected created sensor: %+v", created)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	req.Header.Set("Authorization", authHeader)
	rec = httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("sensors list code = %d", rec.Code)
	}
	var listed []dashboardSensor
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("unmarshal listed sensors: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != created.Sensor.ID {
		t.Fatalf("unexpected listed sensors: %+v", listed)
	}

	req = httptest.NewRequest(http.MethodDelete, fmt.Sprintf("/api/sensors/%d", created.Sensor.ID), nil)
	req.Header.Set("Authorization", authHeader)
	rec = httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("sensors delete code = %d, want 204", rec.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/sensors", nil)
	req.Header.Set("Authorization", authHeader)
	rec = httptest.NewRecorder()
	bridge.ServeHTTP(rec, req)
	if err := json.Unmarshal(rec.Body.Bytes(), &listed); err != nil || len(listed) != 0 {
		t.Fatalf("expected 0 sensors after delete, got %+v (err=%v)", listed, err)
	}
}

func TestLookoutSPAAndUnbuiltFallback(t *testing.T) {
	bridge, _, _, _ := setupLookoutTest(t, "op-secret")

	// Built UI serves index.html at root and client-side routes.
	for _, path := range []string{"/", "/visitors", "/sensors"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		bridge.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s code = %d, want 200", path, rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "<!doctype html>") && !strings.Contains(rec.Body.String(), "<html") {
			t.Fatalf("GET %s body missing HTML shell: %s", path, rec.Body.String())
		}
	}

	// Unbuilt UI fallback returns 404 with build guidance.
	unbuilt := &Console{token: "op-secret", ui: fstest.MapFS{}}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	unbuilt.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "console not built") {
		t.Fatalf("expected 404 unbuilt guidance, got %d: %s", rec.Code, rec.Body.String())
	}
}
