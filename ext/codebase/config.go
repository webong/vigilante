package codebase

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/webong/ext/res/system/graph"
)

// Config holds the configuration contributed to Vigilante by the codebase
// mapping extension. Codebase mapping is off by default: it activates only when
// repo, codebase, or codebase_plugin is configured on the CLI or in a config
// file.
type Config struct {
	Enabled *bool  `yaml:"codebase" json:"codebase"`
	Repo    string `yaml:"repo" json:"repo"`
	Ref     string `yaml:"repo_ref" json:"repo_ref"`
	User    string `yaml:"repo_user" json:"repo_user"`
	Token   string `yaml:"repo_token" json:"repo_token"`
	SSHKey  string `yaml:"repo_ssh_key" json:"repo_ssh_key"`
	Plugin  string `yaml:"codebase_plugin" json:"codebase_plugin"`
}

// FlagState holds the command-line flag bindings registered by the codebase
// extension on Vigilante's FlagSet.
type FlagState struct {
	Enabled bool
	Repo    string
	Ref     string
	User    string
	Token   string
	SSHKey  string
	Plugin  string
}

// KnownKeys returns the top-level YAML/JSON config keys owned by this extension.
func KnownKeys() []string {
	return []string{
		"codebase",
		"codebase_plugin",
		"repo",
		"repo_ref",
		"repo_ssh_key",
		"repo_token",
		"repo_user",
	}
}

// BindFlags registers the codebase extension's CLI flags on fs.
func BindFlags(fs *flag.FlagSet) *FlagState {
	s := &FlagState{}
	fs.BoolVar(&s.Enabled, "codebase", false, "Enable the codebase mapping ext plugin (vigilante.codebase@v1); defaults -repo to auto when unset")
	fs.StringVar(&s.Plugin, "codebase-plugin", "", "vigilante.codebase@v1 plugin binary to launch under the supervisor")
	fs.StringVar(&s.Repo, "repo", "", "Git repo target to index for codebase awareness (enables ext/codebase): any host URL, owner/repo or host/owner/repo shorthand, a local path, or \"auto\" to discover from -target")
	fs.StringVar(&s.Ref, "repo-ref", "", "Branch or tag to shallow-clone for -repo (empty = remote default branch)")
	fs.StringVar(&s.User, "repo-user", "", "HTTPS username for private -repo clones (default: x-access-token, or VIGILANTE_GIT_USER)")
	fs.StringVar(&s.Token, "repo-token", "", "HTTPS auth token for private -repo clones (prefer the VIGILANTE_GIT_TOKEN env var to keep it out of argv)")
	fs.StringVar(&s.SSHKey, "repo-ssh-key", "", "Path to an SSH private key for private ssh:// or git@ clones of -repo (default: VIGILANTE_GIT_SSH_KEY env var / ssh-agent)")
	return s
}

// Resolve applies explicitly set CLI flags over the config-file values.
func Resolve(set map[string]bool, flags *FlagState, cfg Config) Config {
	out := cfg
	if flags == nil {
		return out
	}
	if set["codebase"] {
		b := flags.Enabled
		out.Enabled = &b
	}
	if set["codebase-plugin"] {
		out.Plugin = flags.Plugin
	}
	if set["repo"] {
		out.Repo = flags.Repo
		if flags.Repo == "" && !set["codebase"] {
			b := false
			out.Enabled = &b
		}
	}
	if set["repo-ref"] {
		out.Ref = flags.Ref
	}
	if set["repo-user"] {
		out.User = flags.User
	}
	if set["repo-token"] {
		out.Token = flags.Token
	}
	if set["repo-ssh-key"] {
		out.SSHKey = flags.SSHKey
	}
	return out
}

// Merge overlays keys present in src (from a later config file) onto dst.
// A `codebase` key replaces the codebase configuration as a whole, while flat
// `repo_*` / `codebase_plugin` keys replace their respective fields.
func Merge(dst *Config, src Config, keys map[string]bool) {
	if keys["codebase"] {
		*dst = src
	}
	if keys["codebase_plugin"] {
		dst.Plugin = src.Plugin
	}
	if keys["repo"] {
		dst.Repo = src.Repo
	}
	if keys["repo_ref"] {
		dst.Ref = src.Ref
	}
	if keys["repo_user"] {
		dst.User = src.User
	}
	if keys["repo_token"] {
		dst.Token = src.Token
	}
	if keys["repo_ssh_key"] {
		dst.SSHKey = src.SSHKey
	}
}

// jsonCodebase is the structured `codebase: { ... }` shape.
type jsonCodebase struct {
	Enabled *bool  `json:"enabled"`
	Repo    string `json:"repo"`
	Ref     string `json:"ref"`
	User    string `json:"user"`
	Token   string `json:"token"`
	SSHKey  string `json:"ssh_key"`
	Plugin  string `json:"plugin"`
}

// DecodeJSON extracts and validates codebase configuration keys from raw,
// removing the keys it consumes so the caller's strict JSON decoder only sees
// core keys.
func DecodeJSON(raw map[string]json.RawMessage, dst *Config) error {
	if cbRaw, ok := raw["codebase"]; ok {
		delete(raw, "codebase")
		if err := decodeCodebaseJSON(cbRaw, dst); err != nil {
			return err
		}
	}
	for _, item := range []struct {
		key string
		 field *string
	}{
		{"codebase_plugin", &dst.Plugin},
		{"repo", &dst.Repo},
		{"repo_ref", &dst.Ref},
		{"repo_user", &dst.User},
		{"repo_token", &dst.Token},
		{"repo_ssh_key", &dst.SSHKey},
	} {
		if v, ok := raw[item.key]; ok {
			delete(raw, item.key)
			var s string
			if err := json.Unmarshal(v, &s); err != nil {
				return fmt.Errorf("config: %s: %w", item.key, err)
			}
			*item.field = s
		}
	}
	return nil
}

func decodeCodebaseJSON(raw json.RawMessage, dst *Config) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	switch trimmed[0] {
	case 't', 'f':
		var b bool
		if err := json.Unmarshal(trimmed, &b); err != nil {
			return fmt.Errorf("config: codebase: %w", err)
		}
		dst.Enabled = &b
		return nil
	case '"':
		var repo string
		if err := json.Unmarshal(trimmed, &repo); err != nil {
			return fmt.Errorf("config: codebase: %w", err)
		}
		dst.Repo = repo
		b := repo != ""
		dst.Enabled = &b
		return nil
	case '{':
		var jc jsonCodebase
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&jc); err != nil {
			return fmt.Errorf("config: codebase: %w", err)
		}
		applyBlock(dst, jc.Enabled, jc.Repo, jc.Ref, jc.User, jc.Token, jc.SSHKey, jc.Plugin)
		return nil
	default:
		return fmt.Errorf("config: codebase must be a bool, a repository string, or an inline object")
	}
}

// DecodeYAML handles a top-level YAML key if it belongs to the codebase
// extension. captureBlock is invoked only when `codebase:` has an empty inline
// value and expects an indented block.
func DecodeYAML(key, val string, captureBlock func() (string, error), dst *Config) (bool, error) {
	switch key {
	case "codebase":
		if val == "" {
			block, err := captureBlock()
			if err != nil {
				return true, fmt.Errorf("config: codebase: %w", err)
			}
			return true, applyYAMLBlock(block, dst)
		}
		if b, err := strconv.ParseBool(val); err == nil {
			dst.Enabled = &b
			return true, nil
		}
		dst.Repo = val
		b := true
		dst.Enabled = &b
		return true, nil
	case "codebase_plugin":
		dst.Plugin = val
		return true, nil
	case "repo":
		dst.Repo = val
		return true, nil
	case "repo_ref":
		dst.Ref = val
		return true, nil
	case "repo_user":
		dst.User = val
		return true, nil
	case "repo_token":
		dst.Token = val
		return true, nil
	case "repo_ssh_key":
		dst.SSHKey = val
		return true, nil
	default:
		return false, nil
	}
}

func applyYAMLBlock(block string, dst *Config) error {
	var enabled *bool
	var repo, ref, user, token, sshKey, plugin string
	for _, raw := range strings.Split(block, "\n") {
		line := strings.TrimSpace(stripComment(raw))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			return fmt.Errorf("config: codebase: malformed line %q", line)
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		switch k {
		case "enabled":
			b, err := strconv.ParseBool(v)
			if err != nil {
				return fmt.Errorf("config: codebase.enabled: expected bool, got %q", v)
			}
			enabled = &b
		case "repo":
			repo = v
		case "ref", "repo_ref":
			ref = v
		case "user", "repo_user":
			user = v
		case "token", "repo_token":
			token = v
		case "ssh_key", "repo_ssh_key":
			sshKey = v
		case "plugin", "codebase_plugin":
			plugin = v
		default:
			return fmt.Errorf("config: codebase: unknown key %q", k)
		}
	}
	applyBlock(dst, enabled, repo, ref, user, token, sshKey, plugin)
	return nil
}

func applyBlock(dst *Config, enabled *bool, repo, ref, user, token, sshKey, plugin string) {
	if enabled != nil {
		dst.Enabled = enabled
	} else if repo != "" || plugin != "" {
		b := true
		dst.Enabled = &b
	}
	if repo != "" {
		dst.Repo = repo
	}
	if ref != "" {
		dst.Ref = ref
	}
	if user != "" {
		dst.User = user
	}
	if token != "" {
		dst.Token = token
	}
	if sshKey != "" {
		dst.SSHKey = sshKey
	}
	if plugin != "" {
		dst.Plugin = plugin
	}
}

func stripComment(val string) string {
	inQuote := byte(0)
	for i := 0; i < len(val); i++ {
		c := val[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		if c == '"' || c == '\'' {
			inQuote = c
			continue
		}
		if c == '#' && i > 0 && (val[i-1] == ' ' || val[i-1] == '\t') {
			return strings.TrimSpace(val[:i])
		}
	}
	return val
}

// OpenFromConfig starts the codebase mapping extension when configured. When
// disabled or unconfigured, it returns (nil, nil, nil) so Vigilante runs
// without codebase indexing.
func OpenFromConfig(ctx context.Context, out io.Writer, cfg Config, mode, target string, store graph.Store) (Service, func(context.Context) error, error) {
	if cfg.Enabled != nil && !*cfg.Enabled {
		return nil, nil, nil
	}

	if pluginCmd := strings.TrimSpace(cfg.Plugin); pluginCmd != "" {
		client, err := Launch(ctx, LaunchOptions{
			Store:   store,
			Command: pluginCmd,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("launch codebase plugin %s: %w", pluginCmd, err)
		}
		snap := client.Snapshot()
		fmt.Fprintf(out, "[vigilante] codebase plugin active: %s (%d files, %d routes, %d sinks; ext.plugin/v1 vigilante.codebase@v1)\n",
			pluginCmd, snap.FileCount, len(snap.Routes), len(snap.Sinks))
		return client, client.Close, nil
	}

	repoTarget := strings.TrimSpace(cfg.Repo)
	if repoTarget == "" && cfg.Enabled != nil && *cfg.Enabled {
		repoTarget = "auto"
	}
	if mode == "server" && cfg.Repo == "" {
		return nil, nil, nil
	}
	if repoTarget == "" {
		return nil, nil, nil
	}

	if mode != "server" && strings.EqualFold(repoTarget, "auto") {
		target = strings.TrimSpace(target)
		if root := DiscoverRoot(ctx, target); root != "" {
			fmt.Fprintf(out, "[vigilante] discovered codebase root %s for target %s\n", root, target)
			repoTarget = root
		} else {
			label := target
			if label == "" {
				label = "none"
			}
			fmt.Fprintf(out, "[vigilante] auto repo discovery found no source root for %s; codebase context disabled\n", label)
			return nil, nil, nil
		}
	}

	opts := Options{
		Ref:    cfg.Ref,
		User:   firstNonEmpty(cfg.User, os.Getenv("VIGILANTE_GIT_USER")),
		Token:  firstNonEmpty(cfg.Token, os.Getenv("VIGILANTE_GIT_TOKEN")),
		SSHKey: firstNonEmpty(cfg.SSHKey, os.Getenv("VIGILANTE_GIT_SSH_KEY")),
	}
	fmt.Fprintf(out, "[vigilante] indexing codebase repository %q...", repoTarget)
	sshTarget := strings.HasPrefix(repoTarget, "git@") || strings.HasPrefix(repoTarget, "ssh://")
	switch {
	case opts.Token != "" && !sshTarget:
		fmt.Fprintln(out, " (auth: HTTPS token via GIT_ASKPASS helper)")
	case opts.SSHKey != "" && sshTarget:
		fmt.Fprintf(out, " (auth: ssh key %s)\n", opts.SSHKey)
	default:
		fmt.Fprintln(out, " (auth: configured git credential helpers / ssh-agent)")
	}
	idx, err := OpenWithOptions(ctx, repoTarget, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("index repo %q: %w", repoTarget, err)
	}

	client, err := OpenPlugin(ctx, idx)
	if err != nil {
		_ = idx.Close()
		return nil, nil, fmt.Errorf("open codebase plugin: %w", err)
	}
	closeFn := func(cCtx context.Context) error {
		return errors.Join(client.Close(cCtx), idx.Close())
	}
	snap := client.Snapshot()
	digest := snap.TreeDigest
	if len(digest) > 12 {
		digest = digest[:12]
	}
	fmt.Fprintf(out, "[vigilante] codebase plugin active: %d files, %d routes, %d sinks (commit %s, tree %s...; ext.plugin/v1 vigilante.codebase@v1)\n",
		snap.FileCount, len(snap.Routes), len(snap.Sinks), snap.Commit, digest)
	return client, closeFn, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
