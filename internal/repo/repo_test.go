package repo

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestNormalizeRepoURL(t *testing.T) {
	t.Setenv("VIGILANTE_GIT_HOST", "")
	tests := []struct {
		in, want string
	}{
		{"https://github.com/webong/ext", "https://github.com/webong/ext"},
		{"ssh://git@gitlab.internal/team/repo.git", "ssh://git@gitlab.internal/team/repo.git"},
		{"git@github.com:webong/ext.git", "git@github.com:webong/ext.git"},
		{"git@bitbucket.org:team/repo.git", "git@bitbucket.org:team/repo.git"},
		{"git://git.sv.gnu.org/foo.git", "git://git.sv.gnu.org/foo.git"},
		{"file:///srv/git/repo.git", "file:///srv/git/repo.git"},
		{"github.com/webong/ext", "https://github.com/webong/ext"},
		{"gitlab.com/group/project", "https://gitlab.com/group/project"},
		{"gitea.internal/team/repo", "https://gitea.internal/team/repo"},
		{"webong/ext", "https://github.com/webong/ext"},
		{"webong/ext/", "https://github.com/webong/ext"},
		{"./local/dir", "./local/dir"},
		{"/abs/path", "/abs/path"},
	}
	for _, tc := range tests {
		if got := normalizeRepoURL(tc.in); got != tc.want {
			t.Errorf("normalizeRepoURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeRepoURLDefaultHostOverride(t *testing.T) {
	t.Setenv("VIGILANTE_GIT_HOST", "gitlab.com")
	if got := normalizeRepoURL("webong/ext"); got != "https://gitlab.com/webong/ext" {
		t.Fatalf("normalizeRepoURL with VIGILANTE_GIT_HOST=gitlab.com = %q", got)
	}
}

func TestSanitizeURL(t *testing.T) {
	if got := sanitizeURL("https://user:secret@example.com/owner/repo"); strings.Contains(got, "secret") || !strings.Contains(got, "***") {
		t.Fatalf("sanitizeURL leaked credentials: %q", got)
	}
	if got := sanitizeURL("git@example.com:owner/repo"); got != "git@example.com:owner/repo" {
		t.Fatalf("sanitizeURL modified scp-like URL: %q", got)
	}
}

func TestCloneErrorSuffixHints(t *testing.T) {
	httpsOut := []byte("fatal: could not read Username for 'https://github.com': terminal prompts disabled")
	if s := cloneErrorSuffix(httpsOut, "https://github.com/x/y"); !strings.Contains(s, "VIGILANTE_GIT_TOKEN") {
		t.Fatalf("https auth hint missing token guidance: %q", s)
	}
	sshOut := []byte("git@github.com: Permission denied (publickey).")
	if s := cloneErrorSuffix(sshOut, "git@github.com:x/y"); !strings.Contains(s, "ssh") {
		t.Fatalf("ssh auth hint missing ssh guidance: %q", s)
	}
}

func TestWriteAskPass(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("askpass helper requires /bin/sh")
	}
	script, cleanup, err := writeAskPass()
	if err != nil {
		t.Fatalf("writeAskPass: %v", err)
	}
	defer cleanup()

	cmd := exec.Command(script, "Username for 'https://example.com':")
	cmd.Env = append(os.Environ(), "VIGILANTE_GIT_USER=svc-user", "VIGILANTE_GIT_TOKEN=super-secret-token")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("askpass helper failed: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "svc-user" {
		t.Fatalf("askpass username prompt returned %q, want svc-user", got)
	}

	cmd = exec.Command(script, "Password for 'https://svc-user@example.com':")
	cmd.Env = append(os.Environ(), "VIGILANTE_GIT_USER=svc-user", "VIGILANTE_GIT_TOKEN=super-secret-token")
	out, err = cmd.Output()
	if err != nil {
		t.Fatalf("askpass helper failed: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "super-secret-token" {
		t.Fatalf("askpass password prompt returned %q", got)
	}
}

func TestBuildSSHCommand(t *testing.T) {
	key := "/etc/ssh/vigilante_ed25519"
	got := buildSSHCommand("git@gitlab.internal:team/repo.git", Options{SSHKey: key})
	want := "ssh -i '/etc/ssh/vigilante_ed25519' -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
	if got != want {
		t.Fatalf("buildSSHCommand = %q, want %q", got, want)
	}
	if got := buildSSHCommand("git@host:repo", Options{}); got != "" {
		t.Fatalf("no options should yield empty GIT_SSH_COMMAND, got %q", got)
	}
	if got := buildSSHCommand("https://host/repo", Options{SSHKey: key}); got != "" {
		t.Fatalf("ssh key must be ignored for https remotes, got %q", got)
	}
	custom := buildSSHCommand("ssh://git@host/repo", Options{SSHKey: key, SSHCommand: "ssh -F /dev/null"})
	if !strings.Contains(custom, "-F /dev/null") || !strings.Contains(custom, key) {
		t.Fatalf("custom SSHCommand not preserved: %q", custom)
	}
	if got := shellQuote("it's a key"); got != `'it'\''s a key'` {
		t.Fatalf("shellQuote = %q", got)
	}
}



func TestOpenLocalDir(t *testing.T) {
	dir := t.TempDir()
	src := `package main
import "net/http"
func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/widgets", func(w http.ResponseWriter, r *http.Request) {})
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	idx, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatalf("Open(local dir): %v", err)
	}
	defer idx.Close()

	snap := idx.Snapshot()
	if snap.FileCount != 1 {
		t.Fatalf("FileCount = %d, want 1", snap.FileCount)
	}
	if len(snap.Routes) != 1 || snap.Routes[0].Pattern != "/api/v1/widgets" {
		t.Fatalf("routes = %+v, want /api/v1/widgets", snap.Routes)
	}
	if snap.Source != dir {
		t.Fatalf("Source = %q, want %q", snap.Source, dir)
	}
}

func TestOpenLocalGitClone(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	srcDir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = srcDir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Vigilante Test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Vigilante Test", "GIT_COMMITTER_EMAIL=test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v (%s)", args, err, out)
		}
	}
	run("init", "-q")
	if err := os.WriteFile(filepath.Join(srcDir, "handler.go"), []byte("package app\nfunc Handle() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", ".")
	run("commit", "-q", "-m", "init")

	// file:// forces a real (non-hardlink) clone through the remote code path.
	idx, err := OpenWithOptions(context.Background(), "file://"+srcDir, Options{})
	if err != nil {
		t.Fatalf("Open(file:// clone): %v", err)
	}
	defer idx.Close()

	snap := idx.Snapshot()
	if snap.FileCount == 0 {
		t.Fatal("cloned snapshot has no files")
	}
	if snap.LocalRoot == srcDir {
		t.Fatal("clone was not made into an isolated checkout")
	}
	if snap.Commit == "" {
		t.Fatal("cloned snapshot missing commit")
	}
}

func TestOpenCloneAuthHint(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	// An unreachable https remote fails fast; the error must be actionable.
	_, err := OpenWithOptions(context.Background(), "https://vigilante.invalid/private/repo.git", Options{})
	if err == nil {
		t.Fatal("expected clone of unreachable host to fail")
	}
}

func TestReadSnippetJailsRoot(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	idx, err := Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer idx.Close()

	if _, err := idx.ReadSnippet("../../etc/passwd", 1, 10); err == nil {
		t.Fatal("ReadSnippet allowed path traversal")
	}
	if _, err := idx.ReadSnippet("a.go", 1, 1); err != nil {
		t.Fatalf("ReadSnippet valid file failed: %v", err)
	}
}
