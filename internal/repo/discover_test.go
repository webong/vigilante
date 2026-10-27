package repo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPortOf(t *testing.T) {
	cases := map[string]string{
		"http://127.0.0.1:9000": "9000",
		"https://example.com":   "",
		"127.0.0.1:8080":        "8080",
		"localhost:3000":        "3000",
		"8080":                  "8080",
		"":                      "",
		"example.com":           "",
	}
	for in, want := range cases {
		if got := portOf(in); got != want {
			t.Errorf("portOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsSourceRoot(t *testing.T) {
	git := t.TempDir()
	if err := os.Mkdir(filepath.Join(git, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !isSourceRoot(git) {
		t.Error("dir with .git should be a source root")
	}
	mod := t.TempDir()
	if err := os.WriteFile(filepath.Join(mod, "go.mod"), []byte("module x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !isSourceRoot(mod) {
		t.Error("dir with go.mod should be a source root")
	}
	empty := t.TempDir()
	if isSourceRoot(empty) {
		t.Error("empty dir should not be a source root")
	}
}

func TestSourceRootFromWalksUp(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(root, "cmd", "app")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := sourceRootFrom(nested); got != root {
		t.Errorf("sourceRootFrom(%q) = %q, want %q", nested, got, root)
	}
}

func TestDiscoverRootNoPortYieldsEmpty(t *testing.T) {
	// A URL with no discoverable listening process must yield "" (no guess).
	if got := DiscoverRoot(context.Background(), "https://example.com"); got != "" {
		t.Errorf("DiscoverRoot(no local port) = %q, want empty", got)
	}
	if got := DiscoverRoot(context.Background(), ""); got != "" {
		t.Errorf("DiscoverRoot(empty) = %q, want empty", got)
	}
}
