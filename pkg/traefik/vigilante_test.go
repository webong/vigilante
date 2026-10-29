package traefik

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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

func TestCacheReusesAllowAcrossRequests(t *testing.T) {
	var calls int32
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow","cacheable":true}`))
	}))
	defer sidecar.Close()

	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	cfg := CreateConfig()
	cfg.Endpoint = sidecar.URL
	h, err := New(context.Background(), next, cfg, "vigilante")
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/users", nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("request %d status = %d", i, rr.Code)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("sidecar calls = %d, want 1 (cached allow)", got)
	}
}

func TestDenyIsNeverCached(t *testing.T) {
	var calls int32
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"deny","cacheable":true,"rule":"deny-admin"}`))
	}))
	defer sidecar.Close()

	cfg := CreateConfig()
	cfg.Endpoint = sidecar.URL
	h, err := New(context.Background(), http.NewServeMux(), cfg, "vigilante")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin", nil))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("request %d status = %d, want 403", i, rr.Code)
		}
	}
	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("sidecar calls = %d, want 3 (deny re-asked every time)", got)
	}
}

func TestSendsBearerToken(t *testing.T) {
	var got string
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow"}`))
	}))
	defer sidecar.Close()

	cfg := CreateConfig()
	cfg.Endpoint = sidecar.URL
	cfg.Token = "t0k"
	h, err := New(context.Background(), http.NewServeMux(), cfg, "vigilante")
	if err != nil {
		t.Fatal(err)
	}
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if got != "Bearer t0k" {
		t.Fatalf("Authorization = %q, want Bearer t0k", got)
	}
}

func TestUnauthorizedSidecarFailsClosedEvenWithFailOpen(t *testing.T) {
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer sidecar.Close()

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	cfg := CreateConfig() // failOpen defaults to true
	cfg.Endpoint = sidecar.URL
	h, err := New(context.Background(), next, cfg, "vigilante")
	if err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if nextCalled || rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d nextCalled = %v, want a closed failure on bad credentials", rr.Code, nextCalled)
	}
}
