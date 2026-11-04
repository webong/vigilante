package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/webong/vigilante/ext/lookout"
	"github.com/webong/vigilante/internal/history"
)

func TestLookoutMountInWithStatus(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "history.db")
	hStore, err := history.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer hStore.Close()

	bridge, closeFn, err := lookout.Open(context.Background(), lookout.Options{Token: "test-token"}, lookout.CoreHost{
		History: hStore,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = closeFn(context.Background()) }()

	handler := withStatus(http.NotFoundHandler(), nil, nil, nil, bridge, nil)

	// 1. Session route under /lookout/api/session
	req := httptest.NewRequest(http.MethodGet, "/lookout/api/session", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /lookout/api/session, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Overview route requires auth
	req = httptest.NewRequest(http.MethodGet, "/lookout/api/overview", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for /lookout/api/overview without auth, got %d", rec.Code)
	}

	// 3. Overview route with Bearer token
	req = httptest.NewRequest(http.MethodGet, "/lookout/api/overview", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /lookout/api/overview with Bearer, got %d: %s", rec.Code, rec.Body.String())
	}
}
