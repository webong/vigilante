// Package repo clones or indexes a local directory or any remote Git repository
// (any host: GitHub, GitLab, Bitbucket, Gitea, self-hosted, ssh://, scp-like
// git@host:path, file://, local paths) so that mirrored network flows can be
// correlated directly with source files, route handlers, and security-sensitive
// code sinks, and so the agent can read source files on demand over
// ext.plugin/v1 reverse host calls. Private repositories are supported through
// HTTPS tokens (via a private GIT_ASKPASS helper), configured git credential
// helpers, or ssh-agent.
package repo

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

const (
	MaxIndexedFiles = 2048
	MaxFileReadSize = 64 << 10 // 64 KiB max snippet returned to agent
)

// RouteHandler represents an HTTP/RPC route endpoint discovered in source code.
type RouteHandler struct {
	Method  string `json:"method,omitempty"` // "GET", "POST", "ANY", etc.
	Pattern string `json:"pattern"`          // e.g. "/api/v1/files"
	Handler string `json:"handler,omitempty"`
	File    string `json:"file"` // slash-separated relative path
	Line    int    `json:"line"`
}

// CodeSink represents a security-sensitive operation (SQL query, file read,
// command execution) discovered in the codebase.
type CodeSink struct {
	Category string `json:"category"` // "filesystem", "sql", "exec", "deserialization"
	Symbol   string `json:"symbol"`   // e.g. "os.Open", "db.Query", "exec.Command"
	File     string `json:"file"`
	Line     int    `json:"line"`
	Snippet  string `json:"snippet"`
}

// Snapshot summarizes the indexed codebase for the agent.
type Snapshot struct {
	Source      string         `json:"source"`       // Original URL or path passed to -repo
	LocalRoot   string         `json:"local_root"`   // Local filesystem checkout path
	Commit      string         `json:"commit,omitempty"`
	TreeDigest  string         `json:"tree_digest"`  // Deterministic SHA-256 over indexed files
	FileCount   int            `json:"file_count"`
	Languages   []string       `json:"languages,omitempty"`
	Routes      []RouteHandler `json:"routes,omitempty"`
	Sinks       []CodeSink     `json:"sinks,omitempty"`
}

// Index holds the indexed codebase and allows safe, root-jailed source reading.
type Index struct {
	snapshot Snapshot
	cleanup  func() error
}

// Options controls how a repository target is resolved and cloned.
type Options struct {
	// Ref optionally names a branch or tag to shallow-clone (empty = remote default branch).
	Ref string
	// User is the HTTPS username used when Token is set (default "x-access-token").
	User string
	// Token authenticates HTTPS clones of private repositories on any Git host.
	// On POSIX it is handed to git through a private temporary GIT_ASKPASS helper,
	// never on the command line or persisted in .git/config; on Windows it is
	// embedded as URL userinfo instead. SSH targets ignore Token and rely on
	// ssh-agent / SSHCommand.
	Token string
	// AskPass optionally names an external GIT_ASKPASS program, overriding Token.
	AskPass string
	// SSHCommand optionally sets GIT_SSH_COMMAND for ssh:// or git@host:path targets.
	SSHCommand string
	// SSHKey optionally names an SSH private key file to use for ssh:// or
	// git@host:path clones (independent of ssh-agent). The clone is made with
	// IdentitiesOnly=yes and StrictHostKeyChecking=accept-new so unattended
	// indexing neither stalls on a host-key prompt nor offers unrelated agent keys.
	SSHKey string
}

// Open resolves target (a local directory, a full git URL on any host —
// https/ssh/git/file/scp-like git@host:path — or a shorthand like
// "owner/repo" or "gitlab.com/group/project"), clones it shallowly if remote,
// and indexes its routes, sinks, and file tree digest.
func Open(ctx context.Context, target string) (*Index, error) {
	return OpenWithOptions(ctx, target, Options{})
}

// OpenWithOptions is Open with explicit clone and authentication options.
func OpenWithOptions(ctx context.Context, target string, opts Options) (*Index, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("empty repository target")
	}

	var localRoot string
	var cleanup func() error

	if info, err := os.Stat(target); err == nil && info.IsDir() {
		abs, err := filepath.Abs(target)
		if err != nil {
			return nil, err
		}
		localRoot = abs
	} else {
		var err error
		localRoot, cleanup, err = cloneRemote(ctx, target, opts)
		if err != nil {
			return nil, err
		}
	}

	snap, err := scanDirectory(ctx, sanitizeURL(target), localRoot)
	if err != nil {
		if cleanup != nil {
			_ = cleanup()
		}
		return nil, err
	}

	return &Index{
		snapshot: snap,
		cleanup:  cleanup,
	}, nil
}

// cloneRemote shallow-clones an arbitrary Git URL (any host, https/ssh/scp/file)
// into a temporary checkout and returns its root plus a cleanup function.
// Authentication is injected through GIT_ASKPASS / GIT_SSH_COMMAND / the
// caller's own credential helpers or ssh-agent — never written to disk.
func cloneRemote(ctx context.Context, target string, opts Options) (string, func() error, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return "", nil, fmt.Errorf("git is required to clone %q but was not found in PATH: %w", sanitizeURL(target), err)
	}

	cloneURL := normalizeRepoURL(target)

	tmpDir, err := os.MkdirTemp("", "vigilante-repo-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp repo dir: %w", err)
	}
	cleanup := func() error { return os.RemoveAll(tmpDir) }

	cloneCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()

	args := []string{"clone", "--depth", "1"}
	if ref := strings.TrimSpace(opts.Ref); ref != "" {
		args = append(args, "--branch", ref)
	}
	args = append(args, cloneURL, tmpDir)

	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	if key := strings.TrimSpace(opts.SSHKey); key != "" && isSSHRemote(cloneURL) {
		if _, err := os.Stat(key); err != nil {
			_ = cleanup()
			return "", nil, fmt.Errorf("ssh key %q: %w", key, err)
		}
	}
	if sshCmd := buildSSHCommand(cloneURL, opts); sshCmd != "" {
		env = append(env, "GIT_SSH_COMMAND="+sshCmd)
	}

	token := strings.TrimSpace(opts.Token)
	var askPassCleanup func() error
	if askPass := strings.TrimSpace(opts.AskPass); askPass != "" {
		env = append(env, "GIT_ASKPASS="+askPass)
	} else if token != "" && isHTTPSRemote(cloneURL) {
		user := strings.TrimSpace(opts.User)
		if user == "" {
			user = defaultTokenUser(cloneURL)
		}
		if runtime.GOOS == "windows" {
			// No portable /bin/sh for a helper script: embed credentials in the URL.
			if u, uerr := url.Parse(cloneURL); uerr == nil && u.User == nil {
				u.User = url.UserPassword(user, token)
				cloneURL = u.String()
				args[len(args)-2] = cloneURL
			}
		} else {
			script, scleanup, serr := writeAskPass()
			if serr != nil {
				_ = cleanup()
				return "", nil, fmt.Errorf("create askpass helper: %w", serr)
			}
			askPassCleanup = scleanup
			// Disable configured credential helpers so the explicit token wins,
			// and keep the token out of argv/.git/config via the helper env.
			args = append([]string{"-c", "credential.helper="}, args...)
			env = append(env,
				"GIT_ASKPASS="+script,
				"VIGILANTE_GIT_USER="+user,
				"VIGILANTE_GIT_TOKEN="+token,
			)
		}
	}

	cmd := exec.CommandContext(cloneCtx, "git", args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if askPassCleanup != nil {
		_ = askPassCleanup()
	}
	if err != nil {
		_ = cleanup()
		msg := redactSecret(string(out), token)
		return "", nil, fmt.Errorf("git clone %s: %w%s (%s)", sanitizeURL(cloneURL), err,
			cloneErrorSuffix(out, cloneURL), strings.TrimSpace(msg))
	}
	return tmpDir, cleanup, nil
}

// Snapshot returns a copy of the indexed codebase metadata.
func (idx *Index) Snapshot() Snapshot {
	if idx == nil {
		return Snapshot{}
	}
	s := idx.snapshot
	s.Languages = append([]string(nil), s.Languages...)
	s.Routes = append([]RouteHandler(nil), s.Routes...)
	s.Sinks = append([]CodeSink(nil), s.Sinks...)
	return s
}

// MatchRoute finds the best-matching RouteHandler for an incoming HTTP path.
func (idx *Index) MatchRoute(method, reqPath string) (RouteHandler, bool) {
	if idx == nil || reqPath == "" {
		return RouteHandler{}, false
	}
	if qIdx := strings.IndexByte(reqPath, '?'); qIdx >= 0 {
		reqPath = reqPath[:qIdx]
	}
	method = strings.ToUpper(strings.TrimSpace(method))

	var best RouteHandler
	bestScore := -1

	for _, r := range idx.snapshot.Routes {
		if !routeMatchesPath(r.Pattern, reqPath) {
			continue
		}
		score := len(r.Pattern)
		if r.Method != "" && r.Method != "ANY" {
			if method != "" && r.Method == method {
				score += 100
			} else if method != "" && r.Method != method {
				continue
			}
		}
		if score > bestScore {
			bestScore = score
			best = r
		}
	}
	return best, bestScore >= 0
}

// ReadSnippet safely reads a line range from a relative file path inside the
// indexed repository root, preventing path traversal or symlink escape.
func (idx *Index) ReadSnippet(relPath string, startLine, endLine int) (string, error) {
	if idx == nil || idx.snapshot.LocalRoot == "" {
		return "", fmt.Errorf("no repository indexed")
	}
	cleaned := filepath.Clean(filepath.FromSlash(relPath))
	if cleaned == "." || strings.HasPrefix(cleaned, "..") || filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("invalid relative repository path %q", relPath)
	}
	fullPath := filepath.Join(idx.snapshot.LocalRoot, cleaned)
	relCheck, err := filepath.Rel(idx.snapshot.LocalRoot, fullPath)
	if err != nil || strings.HasPrefix(relCheck, "..") {
		return "", fmt.Errorf("repository path escapes root")
	}
	info, err := os.Lstat(fullPath)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("repository file %q is not a regular file", relPath)
	}

	f, err := os.Open(fullPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if startLine <= 0 {
		startLine = 1
	}
	if endLine <= 0 || endLine < startLine {
		endLine = startLine + 40
	}
	if endLine-startLine > 120 {
		endLine = startLine + 120
	}

	var b strings.Builder
	scanner := bufio.NewScanner(io.LimitReader(f, MaxFileReadSize))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		if lineNo < startLine {
			continue
		}
		if lineNo > endLine {
			break
		}
		fmt.Fprintf(&b, "%4d: %s\n", lineNo, scanner.Text())
	}
	return b.String(), scanner.Err()
}

// Close removes any temporary cloned checkout.
func (idx *Index) Close() error {
	if idx == nil || idx.cleanup == nil {
		return nil
	}
	return idx.cleanup()
}

// normalizeRepoURL resolves a target string into a concrete Git remote URL for
// any host: full URLs (https://, ssh://, git://, file://) and scp-like
// git@host:path pass through unchanged; "host/owner/repo" shorthands (with a
// dotted host, e.g. gitlab.com/group/project) become https URLs; bare
// "owner/repo" shorthand maps to VIGILANTE_GIT_HOST (default github.com).
func normalizeRepoURL(target string) string {
	target = strings.TrimRight(strings.TrimSpace(target), "/")
	if target == "" {
		return target
	}
	// Full URL (https/ssh/git/file/...) or scp-like git@host:path.
	if strings.Contains(target, "://") || strings.HasPrefix(target, "git@") {
		return target
	}
	parts := strings.Split(target, "/")
	// host/owner/repo shorthand for any host, e.g. "gitlab.com/group/project".
	if len(parts) == 3 && strings.Contains(parts[0], ".") && !strings.HasPrefix(parts[0], ".") && parts[0] != "" {
		return "https://" + target
	}
	// owner/repo shorthand -> configurable default host.
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" &&
		!strings.HasPrefix(parts[0], ".") && !strings.HasPrefix(parts[0], "/") {
		return "https://" + defaultRepoHost() + "/" + target
	}
	return target
}

// defaultRepoHost returns the host used for bare owner/repo shorthands.
func defaultRepoHost() string {
	if host := strings.TrimSpace(os.Getenv("VIGILANTE_GIT_HOST")); host != "" {
		return strings.TrimRight(host, "/")
	}
	return "github.com"
}

// isHTTPSRemote reports whether a remote URL uses the https scheme.
func isHTTPSRemote(remote string) bool {
	return strings.HasPrefix(remote, "https://")
}

// isSSHRemote reports whether a remote URL uses the ssh transport
// (ssh:// scheme or scp-like git@host:path syntax).
func isSSHRemote(remote string) bool {
	return strings.HasPrefix(remote, "ssh://") || strings.HasPrefix(remote, "git@")
}

// buildSSHCommand assembles GIT_SSH_COMMAND for ssh remotes, optionally forcing
// a specific private key (Options.SSHKey) with IdentitiesOnly and non-interactive
// host-key acceptance so unattended clones neither stall on a host-key prompt
// nor offer unrelated ssh-agent identities. Returns "" when no ssh command is
// needed (caller falls back to git's default ssh invocation).
func buildSSHCommand(remote string, opts Options) string {
	base := strings.TrimSpace(opts.SSHCommand)
	if base == "" {
		base = "ssh"
	}
	key := strings.TrimSpace(opts.SSHKey)
	if key == "" || !isSSHRemote(remote) {
		if strings.TrimSpace(opts.SSHCommand) == "" {
			return ""
		}
		return base
	}
	return fmt.Sprintf("%s -i %s -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new",
		base, shellQuote(key))
}

// shellQuote wraps s in single quotes for safe embedding in GIT_SSH_COMMAND.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// defaultTokenUser picks a sensible HTTPS username for token-based auth.
func defaultTokenUser(remote string) string {
	host := ""
	if u, err := url.Parse(remote); err == nil {
		host = u.Host
	}
	if strings.Contains(host, "gitlab") {
		return "oauth2"
	}
	return "x-access-token" // accepted by GitHub, Gitea, and most Git hosts
}

// sanitizeURL strips embedded credentials from a URL for safe logging, graph
// projection, and JSON verdict output.
func sanitizeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return raw
	}
	// Rebuild without userinfo (url.User would percent-encode the placeholder).
	u.User = nil
	s := u.String()
	if i := strings.Index(s, "://"); i >= 0 {
		return s[:i+len("://")] + "***@" + s[i+len("://"):]
	}
	return "***@" + s
}

// redactSecret removes a secret (e.g. a token echoed by git) from text.
func redactSecret(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "***")
}

// writeAskPass creates a private POSIX helper script for GIT_ASKPASS so the
// token never appears in argv, process listings, or .git/config. It reads the
// credentials from VIGILANTE_GIT_USER / VIGILANTE_GIT_TOKEN, which are passed
// only to the git child process.
func writeAskPass() (string, func() error, error) {
	dir, err := os.MkdirTemp("", "vigilante-askpass-*")
	if err != nil {
		return "", nil, err
	}
	script := filepath.Join(dir, "askpass.sh")
	body := "#!/bin/sh\n" +
		"case \"$1\" in\n" +
		"  [Uu]sername*) printf '%s\\n' \"$VIGILANTE_GIT_USER\" ;;\n" +
		"  *)            printf '%s\\n' \"$VIGILANTE_GIT_TOKEN\" ;;\n" +
		"esac\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", nil, err
	}
	return script, func() error { return os.RemoveAll(dir) }, nil
}

// cloneErrorSuffix turns raw git output into an actionable hint for auth or
// access failures on private repositories.
func cloneErrorSuffix(out []byte, cloneURL string) string {
	low := strings.ToLower(string(out))
	switch {
	case strings.Contains(low, "could not read username"),
		strings.Contains(low, "authentication failed"),
		strings.Contains(low, "invalid username or password"),
		strings.Contains(low, "incorrect username or password"),
		strings.Contains(low, "terminal prompts disabled"),
		strings.Contains(low, "could not read password"):
		if strings.HasPrefix(cloneURL, "ssh://") || strings.HasPrefix(cloneURL, "git@") {
			return ": ssh target — configure ssh-agent / ~/.ssh keys (or GIT_SSH_COMMAND) with access to the repository"
		}
		return ": private https target — pass -repo-token (or VIGILANTE_GIT_TOKEN), or configure a git credential helper (`gh auth login`, `git config --global credential.helper osxkeychain`)"
	case strings.Contains(low, "permission denied") && strings.Contains(low, "publickey"):
		return ": ssh publickey auth failed — load a key with `ssh-add` or set GIT_SSH_COMMAND"
	case strings.Contains(low, "repository not found"):
		return ": repository not found, or the credentials lack access (verify the token has read access to this repository)"
	}
	return ""
}

func routeMatchesPath(pattern, reqPath string) bool {
	if pattern == reqPath {
		return true
	}
	// Strip Go 1.22 method prefix in pattern if present, e.g. "GET /api/v1/files"
	if _, rest, ok := strings.Cut(pattern, " "); ok && strings.HasPrefix(rest, "/") {
		pattern = strings.TrimSpace(rest)
	}
	if pattern == reqPath {
		return true
	}
	if strings.HasSuffix(pattern, "/") && strings.HasPrefix(reqPath, pattern) {
		return true
	}
	// Match prefix up to parameter placeholder (:id or {id})
	if idx := strings.IndexAny(pattern, ":{*"); idx > 0 {
		prefix := pattern[:idx]
		if strings.HasPrefix(reqPath, prefix) {
			return true
		}
	}
	if strings.HasPrefix(reqPath, pattern+"/") {
		return true
	}
	return false
}

var (
	// Matches Go mux/http.HandleFunc("/path", handler) or r.Get("/path", ...)
	reRouteCall = regexp.MustCompile(`(?i)\b(?:HandleFunc|Handle|Get|Post|Put|Delete|Patch|Route)\s*\(\s*["'\x60]((?:[A-Z]+\s+)?/[^"'\x60]*)["'\x60](?:\s*,\s*([a-zA-Z0-9_.]+))?`)
	// Matches Python @app.route("/path") or @router.get("/path")
	rePyRoute = regexp.MustCompile(`(?i)@(?:app|router|bp)\.(?:route|get|post|put|delete|patch)\s*\(\s*["'](/[^"']*)["']`)
	// Matches Path comparison in custom handlers, e.g. r.URL.Path == "/api/v1/files" or strings.HasPrefix(r.URL.Path, "/api/")
	rePathString = regexp.MustCompile(`["'](/[a-zA-Z0-9_./-]+)["']`)
)

type sinkPattern struct {
	category string
	symbol   string
	re       *regexp.Regexp
}

var sinkPatterns = []sinkPattern{
	{category: "filesystem", symbol: "os.Open/ReadFile", re: regexp.MustCompile(`\b(?:os\.(?:Open|OpenFile|ReadFile)|ioutil\.ReadFile|fs\.readFile|fs\.readFileSync|open\s*\()`)},
	{category: "sql", symbol: "sql.Query/Exec", re: regexp.MustCompile(`\b(?:\.(?:Query|QueryRow|QueryContext|Exec|ExecContext|Raw)\s*\(|cursor\.execute\s*\()`)},
	{category: "exec", symbol: "exec.Command", re: regexp.MustCompile(`\b(?:exec\.Command|exec\.CommandContext|child_process\.exec|subprocess\.(?:Popen|run|call))`)},
}

func scanDirectory(ctx context.Context, source, root string) (Snapshot, error) {
	snap := Snapshot{
		Source:    source,
		LocalRoot: root,
		Commit:    readGitCommit(ctx, root),
	}

	langSet := map[string]bool{}
	hasher := sha256.New()

	var relFiles []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if name == ".git" || name == "node_modules" || name == "vendor" || name == ".venv" || name == "dist" || name == "build" {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if len(relFiles) >= MaxIndexedFiles {
			return fs.SkipAll
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		relFiles = append(relFiles, filepath.ToSlash(rel))
		return nil
	})

	sort.Strings(relFiles)
	snap.FileCount = len(relFiles)

	for _, rel := range relFiles {
		full := filepath.Join(root, filepath.FromSlash(rel))
		ext := strings.ToLower(filepath.Ext(rel))
		switch ext {
		case ".go":
			langSet["go"] = true
		case ".js", ".ts", ".mjs", ".cjs":
			langSet["javascript/typescript"] = true
		case ".py":
			langSet["python"] = true
		case ".rs":
			langSet["rust"] = true
		}

		f, err := os.Open(full)
		if err != nil {
			continue
		}
		fileHash := sha256.New()
		_, _ = io.Copy(fileHash, io.LimitReader(f, 2<<20))
		_ = f.Close()
		fmt.Fprintf(hasher, "./%s %s\n", rel, hex.EncodeToString(fileHash.Sum(nil)))

		if isSourceFile(ext) {
			scanSourceFile(full, rel, &snap)
		}
	}

	snap.TreeDigest = hex.EncodeToString(hasher.Sum(nil))
	for lang := range langSet {
		snap.Languages = append(snap.Languages, lang)
	}
	sort.Strings(snap.Languages)
	return snap, nil
}

func isSourceFile(ext string) bool {
	switch ext {
	case ".go", ".js", ".ts", ".py", ".rs":
		return true
	}
	return false
}

func scanSourceFile(fullPath, relPath string, snap *Snapshot) {
	f, err := os.Open(fullPath)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(io.LimitReader(f, 512<<10))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if m := reRouteCall.FindStringSubmatch(line); len(m) >= 2 && len(snap.Routes) < 128 {
			method, pattern := splitMethodPattern(m[1])
			handler := ""
			if len(m) >= 3 {
				handler = m[2]
			}
			snap.Routes = append(snap.Routes, RouteHandler{
				Method:  method,
				Pattern: pattern,
				Handler: handler,
				File:    relPath,
				Line:    lineNo,
			})
		} else if m := rePyRoute.FindStringSubmatch(line); len(m) >= 2 && len(snap.Routes) < 128 {
			snap.Routes = append(snap.Routes, RouteHandler{
				Method:  "ANY",
				Pattern: m[1],
				File:    relPath,
				Line:    lineNo,
			})
		} else if strings.Contains(line, "URL.Path") || strings.Contains(line, "req.url") {
			if m := rePathString.FindStringSubmatch(line); len(m) >= 2 && len(snap.Routes) < 128 {
				snap.Routes = append(snap.Routes, RouteHandler{
					Method:  "ANY",
					Pattern: m[1],
					File:    relPath,
					Line:    lineNo,
				})
			}
		}

		if len(snap.Sinks) < 128 {
			for _, sp := range sinkPatterns {
				if sp.re.MatchString(line) {
					snippet := trimmed
					if len(snippet) > 160 {
						snippet = snippet[:160]
					}
					snap.Sinks = append(snap.Sinks, CodeSink{
						Category: sp.category,
						Symbol:   sp.symbol,
						File:     relPath,
						Line:     lineNo,
						Snippet:  snippet,
					})
					break
				}
			}
		}
	}
}

func splitMethodPattern(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if m, rest, ok := strings.Cut(raw, " "); ok && strings.HasPrefix(rest, "/") {
		return strings.ToUpper(m), strings.TrimSpace(rest)
	}
	return "ANY", raw
}

func readGitCommit(ctx context.Context, dir string) string {
	cCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cCtx, "git", "-C", dir, "rev-parse", "--short=12", "HEAD")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
