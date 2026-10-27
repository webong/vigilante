package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// decodeConfig parses a policy document. JSON is handled natively; YAML is
// supported through a minimal line-oriented subset (top-level keys, list items
// with "- ", and "key: value" pairs) so no external dependency is required.
// For complex YAML, export the document as JSON.
func decodeConfig(data []byte) (Config, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return Config{}, nil
	}
	if trimmed[0] == '{' || trimmed[0] == '[' {
		var cfg Config
		if err := json.Unmarshal(trimmed, &cfg); err != nil {
			return Config{}, fmt.Errorf("policy: invalid JSON: %w", err)
		}
		return cfg, nil
	}
	return decodeYAMLSubset(trimmed)
}

// decodeYAMLSubset understands the policy document shape:
//
//	deny_cidrs:
//	  - 10.0.0.0/8
//	rules:
//	  - name: block-admin
//	    action: block
//	    paths:
//	      - /admin/*
func decodeYAMLSubset(data []byte) (Config, error) {
	var cfg Config
	lines := strings.Split(string(data), "\n")

	var current *Rule
	inRules := false
	inDeny := false
	pendingField := "" // list field that subsequent "- item" lines append to

	flushRule := func() {
		if current != nil {
			cfg.Rules = append(cfg.Rules, *current)
			current = nil
		}
	}

	for _, raw := range lines {
		line := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))

		if indent == 0 {
			flushRule()
			inRules, inDeny = false, false
			key, val, _ := strings.Cut(trimmed, ":")
			key = strings.TrimSpace(key)
			val = strings.TrimSpace(val)
			switch key {
			case "rules":
				inRules = true
			case "deny_cidrs":
				inDeny = true
				if val != "" {
					cfg.DenyCIDRs = append(cfg.DenyCIDRs, strings.Trim(val, `"'`))
				}
			default:
				return Config{}, fmt.Errorf("policy: unsupported top-level key %q", key)
			}
			continue
		}

		if strings.HasPrefix(trimmed, "- ") || trimmed == "-" {
			item := strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
			switch {
			case inRules:
				if item == "" {
					continue
				}
				if pendingField != "" && !strings.Contains(item, ":") {
					// Nested list item for the pending field (e.g. "- /admin/*").
					if err := appendField(current, pendingField, strings.Trim(item, `"'`)); err != nil {
						return Config{}, err
					}
					continue
				}
				// Inline "- key: value" starts a new rule.
				flushRule()
				pendingField = ""
				current = &Rule{}
				if err := applyRuleField(current, item); err != nil {
					return Config{}, err
				}
			case inDeny:
				if item != "" {
					cfg.DenyCIDRs = append(cfg.DenyCIDRs, strings.Trim(item, `"'`))
				}
			default:
				return Config{}, fmt.Errorf("policy: list item outside a known section: %q", trimmed)
			}
			continue
		}

		// "key: value" inside a section.
		key, val, _ := strings.Cut(trimmed, ":")
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if inDeny {
			if key != "deny_cidrs" {
				return Config{}, fmt.Errorf("policy: unexpected key %q under deny_cidrs", key)
			}
			if val != "" {
				cfg.DenyCIDRs = append(cfg.DenyCIDRs, strings.Trim(val, `"'`))
			}
			continue
		}
		if !inRules {
			return Config{}, fmt.Errorf("policy: key %q outside a known section", key)
		}
		if current == nil {
			current = &Rule{}
		}
		// Nested list header ("paths:") with no inline value: the following
		// "- item" lines are appended to that field via pendingField.
		if val == "" {
			switch key {
			case "methods", "hosts", "paths", "path_prefixes", "cidrs":
				pendingField = key
				continue
			default:
				return Config{}, fmt.Errorf("policy: unsupported rule key %q", key)
			}
		}
		pendingField = ""
		if err := applyRuleField(current, key+": "+val); err != nil {
			return Config{}, err
		}
	}
	flushRule()
	return cfg, nil
}

// applyRuleField sets a single "key: value" field on a rule. List fields with
// an inline scalar value are appended (used by "- key: value" rule starts).
func applyRuleField(r *Rule, kv string) error {
	key, val, ok := strings.Cut(kv, ":")
	if !ok {
		return fmt.Errorf("policy: malformed field %q", kv)
	}
	key = strings.TrimSpace(key)
	val = strings.Trim(strings.TrimSpace(val), `"'`)
	return appendField(r, key, val)
}

// appendField appends val to the named list field (or sets scalar fields).
func appendField(r *Rule, key, val string) error {
	switch key {
	case "name":
		r.Name = val
	case "action":
		r.Action = Action(val)
	case "methods":
		r.Methods = append(r.Methods, val)
	case "hosts":
		r.Hosts = append(r.Hosts, val)
	case "paths":
		r.Paths = append(r.Paths, val)
	case "path_prefixes":
		r.PathPrefixes = append(r.PathPrefixes, val)
	case "cidrs":
		r.CIDRs = append(r.CIDRs, val)
	default:
		return fmt.Errorf("policy: unsupported rule key %q", key)
	}
	return nil
}
