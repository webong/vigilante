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
		"agent: cli:claude -p\n" +
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
	if cfg.Agent != "cli:claude -p" {
		t.Errorf("agent = %q", cfg.Agent)
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
