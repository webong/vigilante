package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config is the optional config file (-config) that supplies defaults for any
// flag not explicitly set on the command line. JSON is handled natively; the
// same minimal YAML subset used by the policy parser is accepted. CLI flags
// always win over config values.
type Config struct {
	Mode         string `json:"mode" yaml:"mode"`
	Listen       string `json:"listen" yaml:"listen"`
	Target       string `json:"target" yaml:"target"`
	Repo         string `json:"repo" yaml:"repo"`
	RepoRef      string `json:"repo_ref" yaml:"repo_ref"`
	RepoUser     string `json:"repo_user" yaml:"repo_user"`
	RepoToken    string `json:"repo_token" yaml:"repo_token"`
	RepoSSHKey   string `json:"repo_ssh_key" yaml:"repo_ssh_key"`
	TLSCert      string `json:"tls_cert" yaml:"tls_cert"`
	TLSKey       string `json:"tls_key" yaml:"tls_key"`
	PlannerURL   string `json:"planner_url" yaml:"planner_url"`
	PlannerToken string `json:"planner_token" yaml:"planner_token"`
	Policy       string `json:"policy" yaml:"policy"`
	BlockMode    string `json:"block_mode" yaml:"block_mode"`
	BlockChain   string `json:"block_chain" yaml:"block_chain"`
	AlertFile    string `json:"alert_file" yaml:"alert_file"`
	AlertDeliver string `json:"alert_deliver_url" yaml:"alert_deliver_url"`
	AlertMinSev  string `json:"alert_min_severity" yaml:"alert_min_severity"`
	QueueSize    int    `json:"queue_size" yaml:"queue_size"`
	Supervised   bool   `json:"supervised_agent" yaml:"supervised_agent"`
}

// loadConfig reads a JSON or YAML config file; missing file with an empty
// path returns an empty config.
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
		var c Config
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			return Config{}, fmt.Errorf("config: invalid JSON: %w", err)
		}
		return c, nil
	}
	return decodeSimpleYAML(trimmed)
}

// decodeSimpleYAML parses flat "key: value" lines (no nesting) — enough for
// the config file shape. Lists/objects belong in JSON.
func decodeSimpleYAML(data []byte) (Config, error) {
	var c Config
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
		switch key {
		case "mode":
			c.Mode = val
		case "listen":
			c.Listen = val
		case "target":
			c.Target = val
		case "repo":
			c.Repo = val
		case "repo_ref":
			c.RepoRef = val
		case "repo_user":
			c.RepoUser = val
		case "repo_token":
			c.RepoToken = val
		case "repo_ssh_key":
			c.RepoSSHKey = val
		case "tls_cert":
			c.TLSCert = val
		case "tls_key":
			c.TLSKey = val
		case "planner_url":
			c.PlannerURL = val
		case "planner_token":
			c.PlannerToken = val
		case "policy":
			c.Policy = val
		case "block_mode":
			c.BlockMode = val
		case "block_chain":
			c.BlockChain = val
		case "alert_file":
			c.AlertFile = val
		case "alert_deliver_url":
			c.AlertDeliver = val
		case "alert_min_severity":
			c.AlertMinSev = val
		case "queue_size":
			n, err := strconv.Atoi(val)
			if err != nil {
				return Config{}, fmt.Errorf("config: queue_size: %w", err)
			}
			c.QueueSize = n
		case "supervised_agent":
			b, err := strconv.ParseBool(val)
			if err != nil {
				return Config{}, fmt.Errorf("config: supervised_agent: %w", err)
			}
			c.Supervised = b
		default:
			return Config{}, fmt.Errorf("config: unknown key %q", key)
		}
	}
	return c, nil
}
