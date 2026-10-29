package policy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestEvaluateAllowByDefault(t *testing.T) {
	e, err := NewEngine(Config{})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://x/anything", nil)
	r.RemoteAddr = "203.0.113.7:1234"
	if v := e.Evaluate(r); v.Action != ActionAllow {
		t.Fatalf("default verdict = %v, want allow", v)
	}
}

func TestDenyPathRule(t *testing.T) {
	e, err := Parse([]byte(`
rules:
  - name: block-admin
    action: deny
    paths:
      - /admin/*
`))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://x/admin/secret", nil)
	if v := e.Evaluate(r); v.Action != ActionDeny || v.Rule != "block-admin" {
		t.Fatalf("verdict = %+v, want deny/block-admin", v)
	}
	r2 := httptest.NewRequest(http.MethodGet, "http://x/public", nil)
	if v := e.Evaluate(r2); v.Action != ActionAllow {
		t.Fatalf("non-matching path verdict = %v, want allow", v)
	}
}

func TestDenyCIDRBeforeRules(t *testing.T) {
	e, err := Parse([]byte(`
deny_cidrs:
  - 10.0.0.0/8
rules:
  - name: allow-everything
    action: allow
`))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	r.RemoteAddr = "10.1.2.3:9999"
	if v := e.Evaluate(r); v.Action != ActionDeny || v.Rule != "deny_cidr" {
		t.Fatalf("verdict = %+v, want deny/deny_cidr", v)
	}
}

func TestBlockRuleByMethodAndPrefix(t *testing.T) {
	e, err := Parse([]byte(`
rules:
  - name: block-git
    action: block
    methods:
      - GET
    path_prefixes:
      - /.git/
`))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://x/.git/config", nil)
	if v := e.Evaluate(r); v.Action != ActionBlock {
		t.Fatalf("verdict = %+v, want block", v)
	}
	r2 := httptest.NewRequest(http.MethodPost, "http://x/.git/config", nil)
	if v := e.Evaluate(r2); v.Action != ActionAllow {
		t.Fatalf("POST verdict = %v, want allow (method mismatch)", v)
	}
}

func TestJSONPolicy(t *testing.T) {
	e, err := Parse([]byte(`{"rules":[{"name":"r1","action":"deny","hosts":["evil.example"]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://evil.example/x", nil)
	r.Host = "evil.example"
	if v := e.Evaluate(r); v.Action != ActionDeny {
		t.Fatalf("verdict = %v, want deny", v)
	}
}

func TestInvalidActionRejected(t *testing.T) {
	if _, err := NewEngine(Config{Rules: []Rule{{Name: "bad", Action: "drop"}}}); err == nil {
		t.Fatal("expected error for invalid action")
	}
}

func TestGlobDoubleStar(t *testing.T) {
	e, err := Parse([]byte(`
rules:
  - name: deep
    action: deny
    paths:
      - /api/**/secret
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/api/secret", "/api/v1/secret", "/api/a/b/c/secret"} {
		r := httptest.NewRequest(http.MethodGet, "http://x"+p, nil)
		if v := e.Evaluate(r); v.Action != ActionDeny {
			t.Fatalf("%s verdict = %v, want deny", p, v)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "http://x/api/v1/other", nil)
	if v := e.Evaluate(r); v.Action != ActionAllow {
		t.Fatalf("non-match verdict = %v, want allow", v)
	}
}

func TestHeaderUserAgentAndQueryRules(t *testing.T) {
	e, err := Parse([]byte(`
rules:
  - name: block-sqlmap
    action: block
    user_agents:
      - "*sqlmap*"
      - Nikto*
  - name: require-https
    action: deny
    headers:
      - x-forwarded-proto=http
  - name: leaky-key
    action: deny
    header_prefixes:
      - x-api-key=sk_live_
  - name: injection-query
    action: block
    queries:
      - "*union select*"
      - "*jndi:*"
`))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name   string
		header map[string]string
		query  string
		want   Action
		rule   string
	}{
		{"sqlmap-ua", map[string]string{"User-Agent": "sqlmap/1.7.2#stable"}, "", ActionBlock, "block-sqlmap"},
		{"nikto-ua", map[string]string{"User-Agent": "Nikto/2.1.6"}, "", ActionBlock, "block-sqlmap"},
		{"browser-ua", map[string]string{"User-Agent": "Mozilla/5.0"}, "", ActionAllow, ""},
		{"plain-http", map[string]string{"X-Forwarded-Proto": "http"}, "", ActionDeny, "require-https"},
		{"https", map[string]string{"X-Forwarded-Proto": "https"}, "", ActionAllow, ""},
		{"live-key", map[string]string{"X-Api-Key": "sk_live_abc"}, "", ActionDeny, "leaky-key"},
		{"test-key", map[string]string{"X-Api-Key": "sk_test_abc"}, "", ActionAllow, ""},
		{"union", nil, "q=1+union+select+2", ActionBlock, "injection-query"},
		{"jndi", nil, "x=${jndi:ldap://evil/a}", ActionBlock, "injection-query"},
		{"benign-query", nil, "q=how+to+select+a+union+representative", ActionAllow, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://x/search", nil)
			if tc.query != "" {
				req.URL.RawQuery = tc.query
			}
			for k, v := range tc.header {
				req.Header.Set(k, v)
			}
			got := e.Evaluate(req)
			if got.Action != tc.want {
				t.Fatalf("action = %v, want %v", got.Action, tc.want)
			}
			if tc.rule != "" && got.Rule != tc.rule {
				t.Fatalf("rule = %q, want %q", got.Rule, tc.rule)
			}
		})
	}
}

func TestDecisionCacheableDependsOnHeaderRules(t *testing.T) {
	pathOnly, err := Parse([]byte("rules:\n  - name: a\n    action: deny\n    paths:\n      - /admin/*\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !pathOnly.DecisionCacheable() {
		t.Fatal("path-only policy should be cacheable")
	}

	headerAware, err := Parse([]byte("rules:\n  - name: b\n    action: deny\n    headers:\n      - x-role=admin\n"))
	if err != nil {
		t.Fatal(err)
	}
	if headerAware.DecisionCacheable() {
		t.Fatal("header-aware policy must not be cacheable")
	}
}

func TestInvalidHeaderMatcherRejected(t *testing.T) {
	if _, err := Parse([]byte("rules:\n  - name: bad\n    headers:\n      - no-equals-sign\n")); err == nil {
		t.Fatal("expected an error for a header matcher without '='")
	}
}

func TestNotMatcherYAMLAndJSON(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  string
	}{
		{
			name: "yaml",
			doc: `rules:
  - name: deny-admin-outside-office
    action: deny
    paths:
      - /admin/*
    not:
      cidrs:
        - 10.0.0.0/8
`,
		},
		{
			name: "json",
			doc:  `{"rules":[{"name":"deny-admin-outside-office","action":"deny","paths":["/admin/*"],"not":{"cidrs":["10.0.0.0/8"]}}]}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, err := Parse([]byte(tc.doc))
			if err != nil {
				t.Fatal(err)
			}
			office := httptest.NewRequest(http.MethodGet, "http://x/admin/users", nil)
			office.RemoteAddr = "10.1.2.3:1234"
			if got := e.Evaluate(office); got.Action != ActionAllow {
				t.Fatalf("trusted address = %+v, want allow", got)
			}
			external := httptest.NewRequest(http.MethodGet, "http://x/admin/users", nil)
			external.RemoteAddr = "203.0.113.5:1234"
			if got := e.Evaluate(external); got.Action != ActionDeny {
				t.Fatalf("external address = %+v, want deny", got)
			}
		})
	}
}

func TestNotHeaderMatcherDisablesDecisionCaching(t *testing.T) {
	e, err := Parse([]byte(`{"rules":[{"name":"deny-non-health","action":"deny","not":{"headers":["X-Probe=true"]}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if e.DecisionCacheable() {
		t.Fatal("a header matcher nested under not must disable coarse decision caching")
	}
}

func TestEmptyNotMatcherRejected(t *testing.T) {
	if _, err := Parse([]byte(`{"rules":[{"name":"bad","action":"deny","not":{}}]}`)); err == nil {
		t.Fatal("expected an error for an empty not matcher")
	}
}

func TestReloadSwapsRulesAndKeepsOldOnError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	write := func(body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write("rules:\n  - name: first\n    action: deny\n    paths:\n      - /admin/*\n")
	e, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://x/admin/users", nil)
	if v := e.Evaluate(req); v.Action != ActionDeny || v.Rule != "first" {
		t.Fatalf("initial verdict = %+v", v)
	}

	write("rules:\n  - name: second\n    action: block\n    paths:\n      - /admin/*\n")
	if err := e.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if v := e.Evaluate(req); v.Action != ActionBlock || v.Rule != "second" {
		t.Fatalf("reloaded verdict = %+v", v)
	}

	// A broken file must not widen access: the previous rules stay in force.
	write("rules:\n  - name: broken\n    action: explode\n")
	if err := e.Reload(); err == nil {
		t.Fatal("expected a reload error")
	}
	if v := e.Evaluate(req); v.Action != ActionBlock || v.Rule != "second" {
		t.Fatalf("verdict after failed reload = %+v, want previous rules", v)
	}
	if e.ReloadError() == nil {
		t.Fatal("ReloadError should report the failure")
	}
	if e.RuleCount() != 1 {
		t.Fatalf("rule count = %d", e.RuleCount())
	}
}

func TestReloadInlineDocument(t *testing.T) {
	e, err := Parse([]byte("rules:\n  - name: only\n    action: allow\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Reload(); err != nil {
		t.Fatalf("inline reload: %v", err)
	}
	if e.LastReload().IsZero() {
		t.Fatal("LastReload should be set")
	}
}
