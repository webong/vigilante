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
)

// Config is the config file (-config, YAML or JSON) supplying defaults for any
// flag not explicitly set on the command line. CLI flags always win over config
// values. Keys use the `yaml` tag (snake_case); types are coerced automatically
// (string/int/float/bool/duration), and unknown keys are rejected so typos
// surface immediately.
//
// Anything you would otherwise pass on the CLI can live here, so setup is a
// single file instead of a long command line.
type Config struct {
	// Mode: demo | http | tcp | middleware | gateway | passive | sidecar | agent-worker
	Mode string `yaml:"mode" json:"mode"`
	// Agent: builtin | cli:<cmd> | supervised
	Agent string `yaml:"agent" json:"agent"`
	// Gateway posture: local | external:<url>
	Gateway string `yaml:"gateway" json:"gateway"`

	Listen string `yaml:"listen" json:"listen"`
	// SidecarListen is the listen address for -mode sidecar (ingress decision API).
	SidecarListen string `yaml:"sidecar_listen" json:"sidecar_listen"`
	Target        string `yaml:"target" json:"target"`

	Repo       string `yaml:"repo" json:"repo"`
	RepoRef    string `yaml:"repo_ref" json:"repo_ref"`
	RepoUser   string `yaml:"repo_user" json:"repo_user"`
	RepoToken  string `yaml:"repo_token" json:"repo_token"`
	RepoSSHKey string `yaml:"repo_ssh_key" json:"repo_ssh_key"`

	TLSCert string `yaml:"tls_cert" json:"tls_cert"`
	TLSKey  string `yaml:"tls_key" json:"tls_key"`

	PlannerURL   string `yaml:"planner_url" json:"planner_url"`
	PlannerToken string `yaml:"planner_token" json:"planner_token"`

	Policy string `yaml:"policy" json:"policy"`

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

	ActorWindow        time.Duration `yaml:"actor_window" json:"actor_window"`
	ActorRiskThreshold int           `yaml:"actor_risk_threshold" json:"actor_risk_threshold"`
	ActorMax           int           `yaml:"actor_max" json:"actor_max"`

	AlertFile        string `yaml:"alert_file" json:"alert_file"`
	AlertDeliver     string `yaml:"alert_deliver_url" json:"alert_deliver_url"`
	AlertMinSeverity string `yaml:"alert_min_severity" json:"alert_min_severity"`
	AlertMaxBytes    int64  `yaml:"alert_max_bytes" json:"alert_max_bytes"`
	AlertKeep        int    `yaml:"alert_keep" json:"alert_keep"`

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
func decodeJSON(data []byte) (Config, error) {
	var c Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("config: invalid JSON: %w", err)
	}
	return c, nil
}

// decodeYAML parses a flat "key: value" YAML document into Config by mapping
// `yaml` struct tags to fields and coercing values to each field's type.
// Nested structures/lists are not supported here (use JSON for those).
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

	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			return Config{}, fmt.Errorf("config: malformed line %q", line)
		}
		key = strings.TrimSpace(key)
		val = strings.Trim(strings.TrimSpace(val), `"'`)
		// Strip a trailing inline comment (space + # ...), but not a '#' inside
		// a quoted value or part of a value like a URL fragment.
		if i := indexComment(val); i >= 0 {
			val = strings.TrimSpace(val[:i])
			val = strings.Trim(val, `"'`)
		}
		idx, found := byKey[key]
		if !found {
			return Config{}, fmt.Errorf("config: unknown key %q (valid: %s)", key, strings.Join(keys, ", "))
		}
		if err := setField(rv.Field(idx), rt.Field(idx), val); err != nil {
			return Config{}, fmt.Errorf("config: %s: %w", key, err)
		}
	}
	return c, nil
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
