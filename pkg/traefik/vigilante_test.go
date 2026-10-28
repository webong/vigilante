package traefik

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServeHTTPEnforcesDecision(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/decide" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"deny","rule":"deny-admin"}`))
	}))
	defer sidecar.Close()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})

	h, err := New(context.Background(), next, &Config{Endpoint: sidecar.URL}, "vigilante")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/users", nil))

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if nextCalled {
		t.Fatal("next handler must not run for a denied request")
	}
}

func TestServeHTTPForwardsAndFailsOpen(t *testing.T) {
	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusTeapot)
	})

	// Unreachable endpoint + default failOpen=true must forward.
	h, err := New(context.Background(), next, &Config{Endpoint: "http://127.0.0.1:1"}, "vigilante")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/users", nil))

	if !nextCalled {
		t.Fatal("expected fail-open to forward to next")
	}
	if rr.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want next handler's 418", rr.Code)
	}
}

func TestNewRequiresEndpoint(t *testing.T) {
	if _, err := New(context.Background(), http.NewServeMux(), &Config{}, "vigilante"); err == nil {
		t.Fatal("expected an error when endpoint is empty")
	}
}
