package redact

import (
	"net/url"
	"strings"
	"testing"
)

func TestStringRedactsJWT(t *testing.T) {
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	in := "GET /api?token=" + jwt
	out := String(in)
	if strings.Contains(out, jwt) {
		t.Fatalf("JWT not redacted: %s", out)
	}
	if !strings.Contains(out, Placeholder) {
		t.Fatalf("placeholder missing: %s", out)
	}
}

func TestStringRedactsAPIKeys(t *testing.T) {
	cases := map[string]string{
		"key=sk-abcdefghijklmnop":                "sk-abcdefghijklmnop",
		"pat=ghp_abcdefghij1234567890abcdefghij": "ghp_abcdefghij1234567890abcdefghij",
		"aws=AKIAIOSFODNN7EXAMPLE":               "AKIAIOSFODNN7EXAMPLE",
		"slack=xoxb-1234567890-abcdef":           "xoxb-1234567890-abcdef",
		"bearer abcdef1234567890":                "bearer abcdef1234567890",
	}
	for in, secret := range cases {
		out := String(in)
		if strings.Contains(out, secret) {
			t.Errorf("secret %q not redacted in %q -> %q", secret, in, out)
		}
	}
}

func TestStringRedactsEmails(t *testing.T) {
	out := String("user alice@example.com logged in")
	if strings.Contains(out, "alice@example.com") {
		t.Fatalf("email not redacted: %s", out)
	}
}

func TestStringRedactsKeyValueSecrets(t *testing.T) {
	out := String(`{"password":"hunter2supersecret"}`)
	if strings.Contains(out, "hunter2supersecret") {
		t.Fatalf("password not redacted: %s", out)
	}
	if !strings.Contains(out, "password") {
		t.Fatalf("key name should remain: %s", out)
	}
}

func TestStringLeavesOrdinaryText(t *testing.T) {
	in := "/api/v1/files?name=report.pdf"
	if out := String(in); out != in {
		t.Fatalf("ordinary text changed: %q -> %q", in, out)
	}
}

func TestQueryRedactsPreservingStructure(t *testing.T) {
	raw := "page=2&token=eyJhbGciOiJIUzI1NiJ9.aaaaaaaaaaaa.bbbbbbbbbbbb&q=search"
	out := Query(raw)
	if strings.Contains(out, "eyJhbGciOiJIUzI1NiJ9") {
		t.Fatalf("token survived: %s", out)
	}
	// page and q must survive.
	values, err := url.ParseQuery(out)
	if err != nil {
		t.Fatalf("redacted query unparseable: %v", err)
	}
	if values.Get("page") != "2" || values.Get("q") != "search" {
		t.Fatalf("non-secret params lost: %s", out)
	}
}

func TestHeadersLeavesMaskedAndRedacts(t *testing.T) {
	in := map[string]string{
		"Authorization": "[REDACTED]",
		"X-Api-Key":     "sk-abcdefghijklmnop",
		"Accept":        "application/json",
	}
	out := Headers(in)
	if out["Authorization"] != "[REDACTED]" {
		t.Fatalf("masked header changed: %q", out["Authorization"])
	}
	if strings.Contains(out["X-Api-Key"], "sk-abcdefghijklmnop") {
		t.Fatalf("api key not redacted: %q", out["X-Api-Key"])
	}
	if out["Accept"] != "application/json" {
		t.Fatalf("ordinary header changed: %q", out["Accept"])
	}
}
