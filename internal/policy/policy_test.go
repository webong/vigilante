package policy

import (
	"net/http"
	"net/http/httptest"
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
