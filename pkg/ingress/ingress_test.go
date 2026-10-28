package ingress

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/webong/vigilante/ext/tap"
	"github.com/webong/vigilante/internal/policy"
)

func testPolicy(t *testing.T) *policy.Engine {
	t.Helper()
	engine, err := policy.NewEngine(policy.Config{
		DenyCIDRs: []string{"198.51.100.0/24"},
		Rules: []policy.Rule{
			{Name: "deny-admin", Action: policy.ActionDeny, PathPrefixes: []string{"/admin/"}},
			{Name: "block-git", Action: policy.ActionBlock, PathPrefixes: []string{"/.git/"}},
			{Name: "allow-health", Action: policy.ActionAllow, Paths: []string{"/healthz"}},
		},
	})
	if err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}
	return engine
}

func TestDecideActions(t *testing.T) {
	q := tap.NewMirrorQueue(8)
	d := New(Config{Policy: testPolicy(t), Queue: q})

	cases := []struct {
		name string
		meta RequestMeta
		want Action
		rule string
	}{
		{"allow-default", RequestMeta{Method: "GET", Path: "/api/v1/users", RemoteAddr: "203.0.113.5:1111"}, Allow, ""},
		{"allow-explicit", RequestMeta{Method: "GET", Path: "/healthz", RemoteAddr: "203.0.113.5:1111"}, Allow, "allow-health"},
		{"deny-path", RequestMeta{Method: "GET", Path: "/admin/users", RemoteAddr: "203.0.113.5:1111"}, Deny, "deny-admin"},
		{"block-path", RequestMeta{Method: "GET", Path: "/.git/config", RemoteAddr: "203.0.113.5:1111"}, Block, "block-git"},
		{"deny-cidr", RequestMeta{Method: "GET", Path: "/api", RemoteAddr: "198.51.100.7:2222"}, Deny, "deny_cidr"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := d.Decide(tc.meta)
			if got.Action != tc.want {
				t.Fatalf("action = %q, want %q", got.Action, tc.want)
			}
			if tc.rule != "" && got.Rule != tc.rule {
				t.Fatalf("rule = %q, want %q", got.Rule, tc.rule)
			}
		})
	}

	// deny must not mirror; block and allow must.
	blocked := 0
	for {
		select {
		case <-q.Events():
			blocked++
			continue
		default:
		}
		break
	}
	if blocked != 3 { // allow-default, allow-explicit, block-path
		t.Fatalf("mirrored events = %d, want 3 (deny is not mirrored)", blocked)
	}
}

func TestDefaultAllowWithoutPolicy(t *testing.T) {
	d := New(Config{})
	if got := d.Decide(RequestMeta{Method: "GET", Path: "/anything"}); got.Action != Allow {
		t.Fatalf("action = %q, want allow", got.Action)
	}
}

func TestObserveRedactsSecrets(t *testing.T) {
	q := tap.NewMirrorQueue(4)
	d := New(Config{Queue: q})

	d.Observe(RequestMeta{
		Method:      "POST",
		Path:        "/login",
		Query:       "token=ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		RemoteAddr:  "203.0.113.9:4444",
		BodyPreview: `{"password":"hunter2"}`,
		BodyBytes:   20,
	})

	select {
	case ev := <-q.Events():
		if strings.Contains(ev.Path, "ghp_abcdefghijklmnopqrstuvwxyz0123456789") {
			t.Fatalf("query token was not redacted: %q", ev.Path)
		}
		if strings.Contains(ev.PayloadPreview, "hunter2") {
			t.Fatalf("body secret was not redacted: %q", ev.PayloadPreview)
		}
	case <-time.After(time.Second):
		t.Fatal("expected a mirrored event")
	}
}

func TestSidecarEndpoints(t *testing.T) {
	q := tap.NewMirrorQueue(8)
	d := New(Config{Policy: testPolicy(t), Queue: q})
	srv := httptest.NewServer(NewServer(d, "").Handler())
	defer srv.Close()

	// /v1/check: 204 allow, 403 deny/block.
	for _, tc := range []struct {
		uri    string
		method string
		want   int
	}{
		{"/api/v1/users", "GET", http.StatusNoContent},
		{"/admin/users", "GET", http.StatusForbidden},
		{"/.git/config", "GET", http.StatusForbidden},
	} {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/check", nil)
		req.Header.Set("X-Original-URI", tc.uri)
		req.Header.Set("X-Original-Method", tc.method)
		req.Header.Set("X-Forwarded-For", "203.0.113.5")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("check %s: %v", tc.uri, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Fatalf("check %s: status %d, want %d", tc.uri, resp.StatusCode, tc.want)
		}
	}

	// /v1/decide: JSON in, JSON out.
	body := `{"method":"GET","path":"/admin/users","remote_addr":"203.0.113.5:1234"}`
	resp, err := http.Post(srv.URL+"/v1/decide", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	defer resp.Body.Close()
	var decision Decision
	if err := json.NewDecoder(resp.Body).Decode(&decision); err != nil {
		t.Fatalf("decode decision: %v", err)
	}
	if decision.Action != Deny || decision.Rule != "deny-admin" {
		t.Fatalf("decision = %+v, want deny/deny-admin", decision)
	}

	// /v1/observe: 202, mirrors without a decision.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/observe", nil)
	req.Header.Set("X-Original-URI", "/api/v1/orders")
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusAccepted {
		t.Fatalf("observe status = %d, want 202", resp2.StatusCode)
	}
}

func TestMetaFromRequestPrefersProxyHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ignored", nil)
	req.RemoteAddr = "10.0.0.1:5555"
	req.Header.Set("X-Original-URI", "/api/v1/items?page=2")
	req.Header.Set("X-Original-Method", "DELETE")
	req.Header.Set("X-Forwarded-For", "203.0.113.42, 10.0.0.9")
	req.Header.Set("X-Forwarded-Host", "api.example.com")

	meta := MetaFromRequest(req)
	if meta.Method != "DELETE" || meta.Path != "/api/v1/items" || meta.Query != "page=2" {
		t.Fatalf("unexpected meta: %+v", meta)
	}
	if meta.RemoteAddr != "203.0.113.42" {
		t.Fatalf("remote addr = %q, want first X-Forwarded-For hop", meta.RemoteAddr)
	}
	if meta.Host != "api.example.com" {
		t.Fatalf("host = %q", meta.Host)
	}
}
