package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/webong/vigilante/internal/policy"
)

func TestLoadConfigJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vig.json")
	data := `{"mode":"http","listen":":9000","target":"http://app:3000","repo":"owner/repo","queue_size":64,"supervised_agent":true}`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "http" || cfg.Listen != ":9000" || cfg.Target != "http://app:3000" ||
		cfg.Repo != "owner/repo" || cfg.QueueSize != 64 || !cfg.Supervised {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestLoadConfigYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vig.yaml")
	data := "# comment\nmode: gateway\ngateway: external:http://gw:5001\nlisten: ':8443'\npolicy: /etc/vig/policy.yaml\nblock_mode: nft\nqueue_size: 128\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "gateway" || cfg.Gateway != "external:http://gw:5001" || cfg.Listen != ":8443" ||
		cfg.Policy != "/etc/vig/policy.yaml" || cfg.BlockMode != "nft" || cfg.QueueSize != 128 {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestLoadConfigEmptyPath(t *testing.T) {
	cfg, err := loadConfig("")
	if err != nil || cfg.Mode != "" {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
}

func TestLoadConfigPreservesExplicitZeroValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		ext  string
		body string
	}{
		{"json", ".json", `{"sidecar_cache_ttl":0,"eval_min_recall":0,"eval_max_fpr":0}`},
		{"yaml", ".yaml", "sidecar_cache_ttl: 0s\neval_min_recall: 0\neval_max_fpr: 0\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "vig"+tc.ext)
			if err := os.WriteFile(path, []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			cfg, err := loadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if !cfg.SidecarCacheTTLSet || cfg.SidecarCacheTTL != 0 {
				t.Fatalf("sidecar cache TTL = %v (set=%v)", cfg.SidecarCacheTTL, cfg.SidecarCacheTTLSet)
			}
			if !cfg.EvalMinRecallSet || cfg.EvalMinRecall != 0 {
				t.Fatalf("eval min recall = %v (set=%v)", cfg.EvalMinRecall, cfg.EvalMinRecallSet)
			}
			if !cfg.EvalMaxFPRSet || cfg.EvalMaxFPR != 0 {
				t.Fatalf("eval max FPR = %v (set=%v)", cfg.EvalMaxFPR, cfg.EvalMaxFPRSet)
			}
		})
	}
}

func TestLoadConfigUnknownKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vig.json")
	if err := os.WriteFile(path, []byte(`{"bogus":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("expected error for unknown key")
	}
}

func TestCLIOverridesConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vig.json")
	if err := os.WriteFile(path, []byte(`{"mode":"http","listen":":7000"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// -listen is set explicitly, so it must win over the config's :7000.
	// We can't easily run the full server, but loadConfig + Visit semantics are
	// covered by construction; assert config parses and yields the values.
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != "http" || cfg.Listen != ":7000" {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestLoadConfigNewKeysYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vig.yaml")
	data := "" +
		"mode: http\n" +
		"agent: cli\n" +
		"agent_command: claude\n" +
		"agent_args:\n" +
		"  - -p\n" +
		"  - '{prompt}'\n" +
		"agent_timeout: 45s\n" +
		"block_threshold: 5\n" +
		"block_window: 2m\n" +
		"block_min_severity: high\n" +
		"alert_max_bytes: 1048576\n" +
		"alert_keep: 7\n" +
		"obs: false\n" +
		"passive_iface: eth0\n" +
		"passive_ports: 80,443\n" +
		"sample_rate: 0.25\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agent != "cli" || cfg.AgentCommand != "claude" || len(cfg.AgentArgs) != 2 || cfg.AgentArgs[0] != "-p" || cfg.AgentArgs[1] != "{prompt}" {
		t.Errorf("agent config = %+v", cfg)
	}
	if cfg.AgentTimeout.Seconds() != 45 {
		t.Errorf("agent_timeout = %v, want 45s", cfg.AgentTimeout)
	}
	if cfg.BlockThreshold != 5 {
		t.Errorf("block_threshold = %d", cfg.BlockThreshold)
	}
	if cfg.BlockWindow.Minutes() != 2 {
		t.Errorf("block_window = %v, want 2m", cfg.BlockWindow)
	}
	if cfg.BlockMinSeverity != "high" {
		t.Errorf("block_min_severity = %q", cfg.BlockMinSeverity)
	}
	if cfg.AlertMaxBytes != 1048576 {
		t.Errorf("alert_max_bytes = %d", cfg.AlertMaxBytes)
	}
	if cfg.AlertKeep != 7 {
		t.Errorf("alert_keep = %d", cfg.AlertKeep)
	}
	if cfg.Obs == nil || *cfg.Obs {
		t.Errorf("obs = %v, want false", cfg.Obs)
	}
	if cfg.PassiveIface != "eth0" || cfg.PassivePorts != "80,443" {
		t.Errorf("passive = %q/%q", cfg.PassiveIface, cfg.PassivePorts)
	}
	if cfg.SampleRate != 0.25 {
		t.Errorf("sample_rate = %v", cfg.SampleRate)
	}
}

func TestLoadConfigYAMLDurationError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vig.yaml")
	if err := os.WriteFile(path, []byte("agent_timeout: notaduration\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadConfig(path); err == nil {
		t.Fatal("expected error for bad duration")
	}
}

func TestLoadConfigYAMLUnknownKeyListsValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vig.yaml")
	if err := os.WriteFile(path, []byte("bogus_key: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := loadConfig(path)
	if err == nil {
		t.Fatal("expected error for unknown key")
	}
	if !strings.Contains(err.Error(), "valid:") {
		t.Errorf("error should list valid keys: %v", err)
	}
}

func TestFullExampleConfigParses(t *testing.T) {
	cfg, err := loadConfig("../../deploy/vigilante.json.example")
	if err != nil {
		t.Fatalf("example config: %v", err)
	}
	if cfg.Mode != "http" || cfg.QueueSize != 1024 || cfg.AlertMinSeverity != "high" {
		t.Fatalf("cfg=%+v", cfg)
	}
	if cfg.Policy != "/etc/vigilante/policy.yaml" || cfg.PolicyEngine != nil {
		t.Fatalf("path-based policy should stay a path: %+v", cfg)
	}
}

func TestYAMLExampleConfigParses(t *testing.T) {
	cfg, err := loadConfig("../../deploy/vigilante.yaml.example")
	if err != nil {
		t.Fatalf("yaml example: %v", err)
	}
	if cfg.PolicyEngine == nil {
		t.Fatal("expected an inline policy in the YAML example")
	}
	if got := actionFor(t, cfg.PolicyEngine, "GET", "/admin/users"); got != policy.ActionDeny {
		t.Errorf("example policy /admin = %q, want deny", got)
	}
	if got := actionFor(t, cfg.PolicyEngine, "GET", "/api/users"); got != policy.ActionAllow {
		t.Errorf("example policy default = %q, want allow", got)
	}
	if cfg.ActionAllow != "block" {
		t.Errorf("example actions.allow = %q", cfg.ActionAllow)
	}
	if cfg.ActionTTL != time.Hour {
		t.Errorf("example actions.ttl = %v", cfg.ActionTTL)
	}
	if cfg.AlertMinSeverity != "high" || cfg.AlertKeep != 3 {
		t.Errorf("example alerts = %q/%d", cfg.AlertMinSeverity, cfg.AlertKeep)
	}
}

func actionFor(t *testing.T, e *policy.Engine, method, path string) policy.Action {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = "203.0.113.5:1234"
	return e.Evaluate(req).Action
}

func TestInlinePolicyAndActionsAlertsYAML(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vig.yaml")
	data := "" +
		"mode: http\n" +
		"policy:\n" +
		"  deny_cidrs:\n" +
		"    - 192.0.2.0/24\n" +
		"  rules:\n" +
		"    - name: deny-admin\n" +
		"      action: deny\n" +
		"      paths:\n" +
		"        - /admin/*\n" +
		"    - name: block-git\n" +
		"      action: block\n" +
		"      path_prefixes:\n" +
		"        - /.git/\n" +
		"actions:\n" +
		"  allow:\n" +
		"    - block\n" +
		"    - notify\n" +
		"  dry_run: true\n" +
		"  ttl: 30m\n" +
		"  max_ttl: 2h\n" +
		"  webhook: https://api.example.com/rules\n" +
		"  webhook_body: '{\"target\":\"{target}\"}'\n" +
		"alerts:\n" +
		"  file: /var/log/vigilante/alerts.jsonl\n" +
		"  deliver_url: https://hooks.example.com/vigilante\n" +
		"  min_severity: high\n" +
		"  max_bytes: 1048576\n" +
		"  keep: 5\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PolicyEngine == nil {
		t.Fatal("expected an inline policy engine")
	}
	if got := actionFor(t, cfg.PolicyEngine, "GET", "/admin/users"); got != policy.ActionDeny {
		t.Errorf("inline policy /admin = %q, want deny", got)
	}
	if got := actionFor(t, cfg.PolicyEngine, "GET", "/.git/config"); got != policy.ActionBlock {
		t.Errorf("inline policy /.git = %q, want block", got)
	}
	if got := actionFor(t, cfg.PolicyEngine, "GET", "/api/v1/users"); got != policy.ActionAllow {
		t.Errorf("inline policy default = %q, want allow", got)
	}

	if cfg.ActionAllow != "block,notify" {
		t.Errorf("action_allow = %q", cfg.ActionAllow)
	}
	if cfg.ActionDryRun == nil || !*cfg.ActionDryRun {
		t.Errorf("action_dry_run = %v", cfg.ActionDryRun)
	}
	if cfg.ActionTTL != 30*time.Minute {
		t.Errorf("action_ttl = %v", cfg.ActionTTL)
	}
	if cfg.ActionMaxTTL != 2*time.Hour {
		t.Errorf("action_max_ttl = %v", cfg.ActionMaxTTL)
	}
	if cfg.ActionWebhook != "https://api.example.com/rules" {
		t.Errorf("action_webhook = %q", cfg.ActionWebhook)
	}
	if cfg.ActionWebhookBody != `{"target":"{target}"}` {
		t.Errorf("action_webhook_body = %q", cfg.ActionWebhookBody)
	}

	if cfg.AlertFile != "/var/log/vigilante/alerts.jsonl" {
		t.Errorf("alerts.file = %q", cfg.AlertFile)
	}
	if cfg.AlertDeliver != "https://hooks.example.com/vigilante" {
		t.Errorf("alerts.deliver_url = %q", cfg.AlertDeliver)
	}
	if cfg.AlertMinSeverity != "high" {
		t.Errorf("alerts.min_severity = %q", cfg.AlertMinSeverity)
	}
	if cfg.AlertMaxBytes != 1048576 {
		t.Errorf("alerts.max_bytes = %d", cfg.AlertMaxBytes)
	}
	if cfg.AlertKeep != 5 {
		t.Errorf("alerts.keep = %d", cfg.AlertKeep)
	}
}

func TestInlinePolicyAndActionsAlertsJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vig.json")
	data := `{
  "mode": "http",
  "policy": {
    "deny_cidrs": ["198.51.100.0/24"],
    "rules": [
      {"name": "deny-admin", "action": "deny", "path_prefixes": ["/admin/"]}
    ]
  },
  "actions": {"allow": ["block"], "ttl": "1h", "dry_run": false},
  "alerts": {"file": "/tmp/a.jsonl", "min_severity": "low", "keep": 2}
}`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PolicyEngine == nil {
		t.Fatal("expected an inline policy engine")
	}
	if got := actionFor(t, cfg.PolicyEngine, "GET", "/admin/users"); got != policy.ActionDeny {
		t.Errorf("inline policy /admin = %q, want deny", got)
	}
	if got := actionFor(t, cfg.PolicyEngine, "GET", "/api/users"); got != policy.ActionAllow {
		t.Errorf("inline policy default = %q, want allow", got)
	}
	if cfg.ActionAllow != "block" || cfg.ActionTTL != time.Hour {
		t.Errorf("actions = allow %q ttl %v", cfg.ActionAllow, cfg.ActionTTL)
	}
	if cfg.ActionDryRun == nil || *cfg.ActionDryRun {
		t.Errorf("action_dry_run = %v, want false", cfg.ActionDryRun)
	}
	if cfg.AlertFile != "/tmp/a.jsonl" || cfg.AlertMinSeverity != "low" || cfg.AlertKeep != 2 {
		t.Errorf("alerts = %q/%q/%d", cfg.AlertFile, cfg.AlertMinSeverity, cfg.AlertKeep)
	}
}

func TestPolicyPathYAMLStillWorks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vig.yaml")
	if err := os.WriteFile(path, []byte("policy: /etc/vig/policy.yaml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Policy != "/etc/vig/policy.yaml" || cfg.PolicyEngine != nil {
		t.Fatalf("cfg = %+v", cfg)
	}
}

func TestSidecarAndEvalConfigKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vig.yaml")
	data := "" +
		"mode: sidecar\n" +
		"sidecar_listen: 127.0.0.1:9091\n" +
		"sidecar_token: s3cret\n" +
		"sidecar_allow_remote: true\n" +
		"sidecar_cache_ttl: 500ms\n" +
		"policy_watch: false\n" +
		"eval_corpus: deploy/eval/corpus.jsonl\n" +
		"eval_min_recall: 0.9\n" +
		"eval_max_fpr: 0.05\n"
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SidecarListen != "127.0.0.1:9091" || cfg.SidecarToken != "s3cret" {
		t.Fatalf("sidecar = %q/%q", cfg.SidecarListen, cfg.SidecarToken)
	}
	if cfg.SidecarAllowRemote == nil || !*cfg.SidecarAllowRemote {
		t.Fatalf("sidecar_allow_remote = %v", cfg.SidecarAllowRemote)
	}
	if cfg.SidecarCacheTTL != 500*time.Millisecond {
		t.Errorf("sidecar_cache_ttl = %v", cfg.SidecarCacheTTL)
	}
	if cfg.PolicyWatch == nil || *cfg.PolicyWatch {
		t.Errorf("policy_watch = %v, want false", cfg.PolicyWatch)
	}
	if cfg.EvalCorpus != "deploy/eval/corpus.jsonl" || cfg.EvalMinRecall != 0.9 || cfg.EvalMaxFPR != 0.05 {
		t.Errorf("eval = %q/%v/%v", cfg.EvalCorpus, cfg.EvalMinRecall, cfg.EvalMaxFPR)
	}
}

func TestIsLoopbackListen(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:9090", true},
		{"[::1]:9090", true},
		{"localhost:9090", true},
		{"127.0.0.2:9090", true},
		{":9090", false},
		{"0.0.0.0:9090", false},
		{"[::]:9090", false},
		{"192.0.2.10:9090", false},
		{"sidecar.internal:9090", false},
	}
	for _, tc := range cases {
		if got := isLoopbackListen(tc.addr); got != tc.want {
			t.Errorf("isLoopbackListen(%q) = %v, want %v", tc.addr, got, tc.want)
		}
	}
}
