package codebase

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/webong/ext/res/system/graph"
)

func TestInProcessPluginSession(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	src := `package main
import (
	"net/http"
	"os"
)
func main() {
	http.HandleFunc("/api/v1/items", handleItems)
}
func handleItems(w http.ResponseWriter, r *http.Request) {
	_, _ = os.ReadFile(r.URL.Query().Get("f"))
}
`
	if err := os.WriteFile(filepath.Join(dir, "server.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}

	idx, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	client, err := OpenPlugin(ctx, idx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close(ctx) }()

	snap := client.Snapshot()
	if snap.FileCount != 1 || len(snap.Routes) != 1 || len(snap.Sinks) != 1 {
		t.Fatalf("unexpected snapshot: %+v", snap)
	}

	route, ok := client.MatchRoute("GET", "/api/v1/items?f=test")
	if !ok || route.File != "server.go" || route.Line != 7 {
		t.Fatalf("unexpected route match: ok=%v route=%+v", ok, route)
	}

	snippet, err := client.ReadSnippet("server.go", 6, 11)
	if err != nil || !strings.Contains(snippet, "handleItems") {
		t.Fatalf("unexpected snippet: %q, err=%v", snippet, err)
	}
}

func TestSupervisedCodebasePlugin(t *testing.T) {
	if os.Getenv("VIGILANTE_TEST_CODEBASE_WORKER") == "1" {
		dir := os.Getenv("VIGILANTE_TEST_CODEBASE_DIR")
		idx, err := Open(context.Background(), dir)
		if err != nil {
			os.Exit(2)
		}
		defer idx.Close()
		if err := RunWorkerIPC(context.Background(), os.Getenv(IPCEnv), idx); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.go"), []byte("package main\nimport \"net/http\"\nfunc init() { http.HandleFunc(\"/ping\", nil) }\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	store := graph.NewMemory()
	defer store.Close()

	client, err := Launch(ctx, LaunchOptions{
		Store:   store,
		Command: exe,
		Args:    []string{"-test.run=^TestSupervisedCodebasePlugin$"},
		Environment: map[string]string{
			"VIGILANTE_TEST_CODEBASE_WORKER": "1",
			"VIGILANTE_TEST_CODEBASE_DIR":    dir,
		},
	})
	if err != nil {
		t.Fatalf("Launch: %v", err)
	}
	defer func() { _ = client.Close(ctx) }()

	if client.Snapshot().FileCount != 1 {
		t.Fatalf("expected 1 indexed file, got %+v", client.Snapshot())
	}
	r, ok := client.MatchRoute("GET", "/ping")
	if !ok || r.File != "app.go" {
		t.Fatalf("expected /ping match over jsonline IPC, got ok=%v route=%+v", ok, r)
	}
}
