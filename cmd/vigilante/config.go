package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/webong/vigilante/internal/policy"
)

// Config is the config file (-config, YAML or JSON) supplying defaults for any
// flag not explicitly set on the command line. CLI flags always win over config
// values. Keys use the `yaml` tag (snake_case); types are coerced automatically
// (string/int/float/bool/duration), and unknown keys are rejected so typos
// surface immediately.
//
// Anything you would otherwise pass on the CLI can live here, so setup is a
// single file instead of a long command line. Policy, actions, and alerts may
// be declared inline:
//
//	policy:
//	  rules:
//	    - name: block-admin
//	      action: deny
//	      paths:
//	        - /admin/*
//	actions:
//	  allow:
//	    - block
//	alerts:
//	  file: /var/log/vigilante/alerts.jsonl
//	  min_severity: high
//
// `policy:` also still accepts a path string, and the flat `action_*` /
// `alert_*` keys remain supported.
type Config struct {
	// Mode: demo | http | tcp | middleware | gateway | passive | sidecar | agent-worker
	Mode string `yaml:"mode" json:"mode"`
	// Agent: builtin | cli:<cmd> | remote:<https-url> | supervised
	Agent        string   `yaml:"agent" json:"agent"`
	AgentCommand string   `yaml:"agent_command" json:"agent_command"`
	AgentArgs    []string `yaml:"agent_args" json:"agent_args"`
	AgentInput   string   `yaml:"agent_input" json:"agent_input"`
	AgentDir     string   `yaml:"agent_dir" json:"agent_dir"`
	// Gateway posture: local | external:<url>
	Gateway string `yaml:"gateway" json:"gateway"`

	Listen string `yaml:"listen" json:"listen"`
	// SidecarListen is the listen address for -mode sidecar (ingress decision API).
	SidecarListen string `yaml:"sidecar_listen" json:"sidecar_listen"`
	// SidecarToken requires bearer auth on the sidecar's decision endpoints.
	// Required when SidecarListen is not loopback.
	SidecarToken string `yaml:"sidecar_token" json:"sidecar_token"`
	// SidecarAllowRemote permits a non-loopback sidecar bind. Off by default
	// so a misconfigured address cannot expose policy decisions to the network.
	SidecarAllowRemote *bool `yaml:"sidecar_allow_remote" json:"sidecar_allow_remote"`
	// SidecarCacheTTL memoizes decisions for repeat coarse-key requests.
	SidecarCacheTTL    time.Duration `yaml:"sidecar_cache_ttl" json:"sidecar_cache_ttl"`
	SidecarCacheTTLSet bool          `yaml:"-" json:"-"`
	Target             string        `yaml:"target" json:"target"`

	Repo       string `yaml:"repo" json:"repo"`
	RepoRef    string `yaml:"repo_ref" json:"repo_ref"`
	RepoUser   string `yaml:"repo_user" json:"repo_user"`
	RepoToken  string `yaml:"repo_token" json:"repo_token"`
	RepoSSHKey string `yaml:"repo_ssh_key" json:"repo_ssh_key"`

	TLSCert string `yaml:"tls_cert" json:"tls_cert"`
	TLSKey  string `yaml:"tls_key" json:"tls_key"`

	PlannerURL   string `yaml:"planner_url" json:"planner_url"`
	PlannerToken string `yaml:"planner_token" json:"planner_token"`

	// Policy is a path to a policy file. An inline `policy:` block instead sets
	// PolicyEngine and leaves Policy empty.
	Policy       string         `yaml:"policy" json:"policy"`
	PolicyEngine *policy.Engine `yaml:"-" json:"-"`
	// PolicyWatch reloads a file-based policy when it changes on disk, and on
	// SIGHUP. Default true.
	PolicyWatch *bool `yaml:"policy_watch" json:"policy_watch"`

	// EvalCorpus is the labelled corpus used by -mode eval.
	EvalCorpus string `yaml:"eval_corpus" json:"eval_corpus"`
	// EvalJSON emits the eval report as one JSON object instead of a table.
	EvalJSON *bool `yaml:"eval_json" json:"eval_json"`
	// EvalMinRecall / EvalMaxFPR gate -mode eval. Zero/one disable the gate.
	EvalMinRecall    float64 `yaml:"eval_min_recall" json:"eval_min_recall"`
	EvalMinRecallSet bool    `yaml:"-" json:"-"`
	EvalMaxFPR       float64 `yaml:"eval_max_fpr" json:"eval_max_fpr"`
	EvalMaxFPRSet    bool    `yaml:"-" json:"-"`

	BlockMode        string        `yaml:"block_mode" json:"block_mode"`
	BlockChain       string        `yaml:"block_chain" json:"block_chain"`
	BlockThreshold   int           `yaml:"block_threshold" json:"block_threshold"`
	BlockWindow      time.Duration `yaml:"block_window" json:"block_window"`
	BlockMinSeverity string        `yaml:"block_min_severity" json:"block_min_severity"`

	ActionAllow         string        `yaml:"action_allow" json:"action_allow"`
	ActionDryRun        *bool         `yaml:"action_dry_run" json:"action_dry_run"`
	ActionTTL           time.Duration `yaml:"action_ttl" json:"action_ttl"`
	ActionMaxTTL        time.Duration `yaml:"action_max_ttl" json:"action_max_ttl"`
	ActionWebhook       string        `yaml:"action_webhook" json:"action_webhook"`
	ActionWebhookBody   string        `yaml:"action_webhook_body" json:"action_webhook_body"`
	ActionWebhookRevert string        `yaml:"action_webhook_revert" json:"action_webhook_revert"`
	ActionWebhookToken  string        `yaml:"action_webhook_token" json:"action_webhook_token"`

	AlertFile        string `yaml:"alert_file" json:"alert_file"`
	AlertDeliver     string `yaml:"alert_deliver_url" json:"alert_deliver_url"`
	AlertMinSeverity string `yaml:"alert_min_severity" json:"alert_min_severity"`
	AlertMaxBytes    int64  `yaml:"alert_max_bytes" json:"alert_max_bytes"`
	AlertKeep        int    `yaml:"alert_keep" json:"alert_keep"`

	// Actor aggregation (served as data at /obs/actors).
	ActorWindow        time.Duration `yaml:"actor_window" json:"actor_window"`
	ActorRiskThreshold int           `yaml:"actor_risk_threshold" json:"actor_risk_threshold"`
	ActorMax           int           `yaml:"actor_max" json:"actor_max"`

	GraphFile    string        `yaml:"graph_file" json:"graph_file"`
	QueueSize    int           `yaml:"queue_size" json:"queue_size"`
	SampleRate   float64       `yaml:"sample_rate" json:"sample_rate"`
	AgentTimeout time.Duration `yaml:"agent_timeout" json:"agent_timeout"`
	Obs          *bool         `yaml:"obs" json:"obs"`
	Supervised   bool          `yaml:"supervised_agent" json:"supervised_agent"`

	PassiveIface string `yaml:"passive_iface" json:"passive_iface"`
	PassivePorts string `yaml:"passive_ports" json:"passive_ports"`
}

// loadConfig reads a JSON or YAML config file; an empty path returns an empty
// config.
func loadConfig(path string) (Config, error) {
	if path == "" {
		return Config{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return Config{}, nil
	}
	if trimmed[0] == '{' {
		return decodeJSON(trimmed)
	}
	return decodeYAML(trimmed)
}

// decodeJSON parses a JSON config, rejecting unknown fields so typos surface.
// The structured `policy`, `actions`, and `alerts` objects are decoded
// separately (they accept richer shapes than the flat keys).
func decodeJSON(data []byte) (Config, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return Config{}, fmt.Errorf("config: invalid JSON: %w", err)
	}

	policyRaw := raw["policy"]
	delete(raw, "policy")
	actionsRaw := raw["actions"]
	delete(raw, "actions")
	alertsRaw := raw["alerts"]
	delete(raw, "alerts")

	rest, err := json.Marshal(raw)
	if err != nil {
		return Config{}, fmt.Errorf("config: invalid JSON: %w", err)
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(rest))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("config: invalid JSON: %w", err)
	}
	_, c.SidecarCacheTTLSet = raw["sidecar_cache_ttl"]
	_, c.EvalMinRecallSet = raw["eval_min_recall"]
	_, c.EvalMaxFPRSet = raw["eval_max_fpr"]

	if len(policyRaw) > 0 {
		if err := c.setPolicyJSON(policyRaw); err != nil {
			return Config{}, err
		}
	}
	if len(actionsRaw) > 0 {
		if err := c.setActionsJSON(actionsRaw); err != nil {
			return Config{}, err
		}
	}
	if len(alertsRaw) > 0 {
		if err := c.setAlertsJSON(alertsRaw); err != nil {
			return Config{}, err
		}
	}
	return c, nil
}

// jsonActions is the inline `actions:` shape.
type jsonActions struct {
	Allow         []string `json:"allow"`
	DryRun        *bool    `json:"dry_run"`
	TTL           string   `json:"ttl"`
	MaxTTL        string   `json:"max_ttl"`
	Webhook       string   `json:"webhook"`
	WebhookBody   string   `json:"webhook_body"`
	WebhookRevert string   `json:"webhook_revert"`
	WebhookToken  string   `json:"webhook_token"`
}

// jsonAlerts is the inline `alerts:` shape.
type jsonAlerts struct {
	File        string `json:"file"`
	DeliverURL  string `json:"deliver_url"`
	MinSeverity string `json:"min_severity"`
	MaxBytes    int64  `json:"max_bytes"`
	Keep        int    `json:"keep"`
}

// setPolicyJSON accepts either `"policy": "path"` or `"policy": { ... }`.
func (c *Config) setPolicyJSON(raw json.RawMessage) error {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil
	}
	switch trimmed[0] {
	case '"':
		var path string
		if err := json.Unmarshal(trimmed, &path); err != nil {
			return fmt.Errorf("config: policy: %w", err)
		}
		c.Policy = path
		return nil
	case '{':
		var pc policy.Config
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&pc); err != nil {
			return fmt.Errorf("config: policy: %w", err)
		}
		engine, err := policy.NewEngine(pc)
		if err != nil {
			return fmt.Errorf("config: policy: %w", err)
		}
		c.PolicyEngine = engine
		return nil
	default:
		return fmt.Errorf("config: policy must be a file path string or an inline object")
	}
}

func (c *Config) setActionsJSON(raw json.RawMessage) error {
	var a jsonActions
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return fmt.Errorf("config: actions: %w", err)
	}
	return c.applyActions(a.Allow, a.DryRun, a.TTL, a.MaxTTL, a.Webhook, a.WebhookBody, a.WebhookRevert, a.WebhookToken)
}

func (c *Config) setAlertsJSON(raw json.RawMessage) error {
	var a jsonAlerts
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return fmt.Errorf("config: alerts: %w", err)
	}
	return c.applyAlerts(a.File, a.DeliverURL, a.MinSeverity, a.MaxBytes, a.Keep)
}

// applyActions copies inline action settings onto the flat fields they
// correspond to. Empty values are left unset so flat keys and CLI flags win.
func (c *Config) applyActions(allow []string, dryRun *bool, ttl, maxTTL, webhook, body, revert, token string) error {
	if len(allow) > 0 {
		c.ActionAllow = strings.Join(allow, ",")
	}
	if dryRun != nil {
		c.ActionDryRun = dryRun
	}
	if ttl != "" {
		d, err := time.ParseDuration(ttl)
		if err != nil {
			return fmt.Errorf("config: actions.ttl: expected duration (e.g. 1h), got %q", ttl)
		}
		c.ActionTTL = d
	}
	if maxTTL != "" {
		d, err := time.ParseDuration(maxTTL)
		if err != nil {
			return fmt.Errorf("config: actions.max_ttl: expected duration (e.g. 24h), got %q", maxTTL)
		}
		c.ActionMaxTTL = d
	}
	if webhook != "" {
		c.ActionWebhook = webhook
	}
	if body != "" {
		c.ActionWebhookBody = body
	}
	if revert != "" {
		c.ActionWebhookRevert = revert
	}
	if token != "" {
		c.ActionWebhookToken = token
	}
	return nil
}

// applyAlerts copies inline alert settings onto the flat fields.
func (c *Config) applyAlerts(file, deliver, minSeverity string, maxBytes int64, keep int) error {
	if file != "" {
		c.AlertFile = file
	}
	if deliver != "" {
		c.AlertDeliver = deliver
	}
	if minSeverity != "" {
		c.AlertMinSeverity = minSeverity
	}
	if maxBytes != 0 {
		c.AlertMaxBytes = maxBytes
	}
	if keep != 0 {
		c.AlertKeep = keep
	}
	return nil
}

// decodeYAML parses a "key: value" YAML document into Config by mapping `yaml`
// struct tags to fields and coercing values to each field's type. Nested blocks
// are supported only for the structured `policy`, `actions`, and `alerts`
// sections; everything else is flat (use JSON for arbitrary nesting).
func decodeYAML(data []byte) (Config, error) {
	var c Config
	rv := reflect.ValueOf(&c).Elem()
	rt := rv.Type()
	byKey := map[string]int{}
	for i := 0; i < rt.NumField(); i++ {
		key := strings.Split(rt.Field(i).Tag.Get("yaml"), ",")[0]
		if key != "" && key != "-" {
			byKey[key] = i
		}
	}
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	lines := strings.Split(string(data), "\n")
	for i := 0; i < len(lines); i++ {
		raw := lines[i]
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if indent := leadingSpaces(raw); indent > 0 {
			return Config{}, fmt.Errorf("config: unexpected indentation at %q", line)
		}

		key, val, ok := strings.Cut(line, ":")
		if !ok {
			return Config{}, fmt.Errorf("config: malformed line %q", line)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		val = strings.Trim(val, `"'`)
		// Strip a trailing inline comment (space + # ...), but not a '#' inside
		// a quoted value or part of a value like a URL fragment.
		if i := indexComment(val); i >= 0 {
			val = strings.TrimSpace(val[:i])
			val = strings.Trim(val, `"'`)
		}

		if key == "agent_args" && val == "" {
			block, next, err := captureBlock(lines, i+1)
			if err != nil {
				return Config{}, fmt.Errorf("config: agent_args: %w", err)
			}
			i = next - 1
			for _, rawArg := range strings.Split(block, "\n") {
				arg := strings.TrimSpace(stripInlineComment(rawArg))
				if arg == "" {
					continue
				}
				if !strings.HasPrefix(arg, "- ") {
					return Config{}, fmt.Errorf("config: agent_args: expected list item, got %q", arg)
				}
				c.AgentArgs = append(c.AgentArgs, strings.Trim(strings.TrimSpace(strings.TrimPrefix(arg, "- ")), `"'`))
			}
			continue
		}
		// Structured sections take an indented block.
		if val == "" && (key == "policy" || key == "actions" || key == "alerts") {
			block, next, err := captureBlock(lines, i+1)
			if err != nil {
				return Config{}, fmt.Errorf("config: %s: %w", key, err)
			}
			i = next - 1
			switch key {
			case "policy":
				engine, err := policy.Parse([]byte(block))
				if err != nil {
					return Config{}, fmt.Errorf("config: policy: %w", err)
				}
				c.PolicyEngine = engine
			case "actions":
				if err := c.applyActionsYAML(block); err != nil {
					return Config{}, err
				}
			case "alerts":
				if err := c.applyAlertsYAML(block); err != nil {
					return Config{}, err
				}
			}
			continue
		}

		idx, found := byKey[key]
		if !found {
			return Config{}, fmt.Errorf("config: unknown key %q (valid: %s)", key, strings.Join(keys, ", "))
		}
		if err := setField(rv.Field(idx), rt.Field(idx), val); err != nil {
			return Config{}, fmt.Errorf("config: %s: %w", key, err)
		}
		switch key {
		case "sidecar_cache_ttl":
			c.SidecarCacheTTLSet = true
		case "eval_min_recall":
			c.EvalMinRecallSet = true
		case "eval_max_fpr":
			c.EvalMaxFPRSet = true
		}
	}
	return c, nil
}

// captureBlock collects the indented lines starting at start and returns the
// dedented block plus the index of the first line that is not part of it.
func captureBlock(lines []string, start int) (string, int, error) {
	var block []string
	minIndent := -1
	i := start
	for ; i < len(lines); i++ {
		raw := lines[i]
		if strings.TrimSpace(raw) == "" {
			block = append(block, "")
			continue
		}
		indent := leadingSpaces(raw)
		if indent == 0 {
			break
		}
		if minIndent < 0 || indent < minIndent {
			minIndent = indent
		}
		block = append(block, raw)
	}
	if minIndent < 0 {
		return "", i, fmt.Errorf("expected an indented block")
	}
	var b strings.Builder
	for _, line := range block {
		if len(line) >= minIndent {
			b.WriteString(line[minIndent:])
		}
		b.WriteByte('\n')
	}
	return b.String(), i, nil
}

// applyActionsYAML parses the `actions:` block.
//
//	actions:
//	  allow:
//	    - block
//	    - notify
//	  dry_run: false
//	  ttl: 1h
//	  max_ttl: 24h
func (c *Config) applyActionsYAML(block string) error {
	allow, dryRun, ttl, maxTTL, webhook, body, revert, token := []string{}, (*bool)(nil), "", "", "", "", "", ""
	lines := strings.Split(block, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(stripInlineComment(lines[i]))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			return fmt.Errorf("config: actions: malformed line %q", line)
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'"`)
		if val == "" {
			// A block list (only `allow` takes one).
			if key != "allow" {
				return fmt.Errorf("config: actions: %q requires a value", key)
			}
			for i+1 < len(lines) {
				next := strings.TrimSpace(stripInlineComment(lines[i+1]))
				if next == "" || strings.HasPrefix(next, "#") {
					i++
					continue
				}
				if !strings.HasPrefix(next, "- ") && next != "-" {
					break
				}
				allow = append(allow, strings.Trim(strings.TrimSpace(strings.TrimPrefix(next, "- ")), `"'"`))
				i++
			}
			continue
		}
		switch key {
		case "allow":
			allow = append(allow, parseFlowList(val)...)
		case "dry_run":
			b, err := strconv.ParseBool(val)
			if err != nil {
				return fmt.Errorf("config: actions.dry_run: expected bool, got %q", val)
			}
			dryRun = &b
		case "ttl":
			ttl = val
		case "max_ttl":
			maxTTL = val
		case "webhook":
			webhook = val
		case "webhook_body":
			body = val
		case "webhook_revert":
			revert = val
		case "webhook_token":
			token = val
		default:
			return fmt.Errorf("config: actions: unknown key %q", key)
		}
	}
	return c.applyActions(allow, dryRun, ttl, maxTTL, webhook, body, revert, token)
}

// applyAlertsYAML parses the `alerts:` block.
//
//	alerts:
//	  file: /var/log/vigilante/alerts.jsonl
//	  deliver_url: https://hooks.example.com/vigilante
//	  min_severity: high
//	  max_bytes: 10485760
//	  keep: 3
func (c *Config) applyAlertsYAML(block string) error {
	var file, deliver, minSeverity string
	var maxBytes int64
	var keep int
	for _, raw := range strings.Split(block, "\n") {
		line := strings.TrimSpace(stripInlineComment(raw))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			return fmt.Errorf("config: alerts: malformed line %q", line)
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'"`)
		switch key {
		case "file":
			file = val
		case "deliver_url":
			deliver = val
		case "min_severity":
			minSeverity = val
		case "max_bytes":
			n, err := strconv.ParseInt(val, 10, 64)
			if err != nil {
				return fmt.Errorf("config: alerts.max_bytes: expected integer, got %q", val)
			}
			maxBytes = n
		case "keep":
			n, err := strconv.Atoi(val)
			if err != nil {
				return fmt.Errorf("config: alerts.keep: expected integer, got %q", val)
			}
			keep = n
		default:
			return fmt.Errorf("config: alerts: unknown key %q", key)
		}
	}
	return c.applyAlerts(file, deliver, minSeverity, maxBytes, keep)
}

// parseFlowList accepts either `[a, b]` or `a, b` and returns the items.
func parseFlowList(val string) []string {
	val = strings.TrimSpace(val)
	if strings.HasPrefix(val, "[") && strings.HasSuffix(val, "]") {
		val = val[1 : len(val)-1]
	}
	if val == "" {
		return nil
	}
	out := []string{}
	for _, part := range strings.Split(val, ",") {
		part = strings.Trim(strings.TrimSpace(part), `"'"`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func leadingSpaces(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}

// stripInlineComment removes a trailing " # ..." comment, preserving '#' in
// quotes and URL fragments.
func stripInlineComment(s string) string {
	if i := indexComment(s); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// indexComment returns the index of a trailing inline " #..." comment in a
// scalar value, or -1. It ignores '#' that is part of the value (URL fragments,
// no leading space) and quoted strings.
func indexComment(val string) int {
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
			return i
		}
	}
	return -1
}

// setField coerces a string value into the field's type.
func setField(fv reflect.Value, ft reflect.StructField, val string) error {
	switch ft.Type.Kind() {
	case reflect.String:
		fv.SetString(val)
	case reflect.Bool:
		b, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("expected bool, got %q", val)
		}
		fv.SetBool(b)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if ft.Type == reflect.TypeOf(time.Duration(0)) {
			d, err := time.ParseDuration(val)
			if err != nil {
				return fmt.Errorf("expected duration (e.g. 30s, 1m), got %q", val)
			}
			fv.SetInt(int64(d))
			return nil
		}
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			return fmt.Errorf("expected integer, got %q", val)
		}
		fv.SetInt(n)
	case reflect.Float32, reflect.Float64:
		fl, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return fmt.Errorf("expected number, got %q", val)
		}
		fv.SetFloat(fl)
	case reflect.Ptr:
		// *bool optional flag: allocate and set.
		b, err := strconv.ParseBool(val)
		if err != nil {
			return fmt.Errorf("expected bool, got %q", val)
		}
		p := reflect.New(fv.Type().Elem())
		p.Elem().SetBool(b)
		fv.Set(p)
	default:
		return fmt.Errorf("unsupported field type %s", ft.Type)
	}
	return nil
}
