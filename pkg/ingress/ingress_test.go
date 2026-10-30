package ingress

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/webong/vigilante/internal/policy"
	"github.com/webong/vigilante/pkg/tap"
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

func TestDecisionCacheReusesVerdictButStillMirrors(t *testing.T) {
	q := tap.NewMirrorQueue(16)
	d := New(Config{Policy: testPolicy(t), Queue: q, CacheTTL: time.Minute, CacheSize: 8})
	meta := RequestMeta{Method: "GET", Path: "/api/v1/users", RemoteAddr: "203.0.113.5:1111"}

	first := d.Decide(meta)
	if first.Action != Allow || !first.Cacheable {
		t.Fatalf("first decision = %+v, want cacheable allow", first)
	}
	second := d.Decide(meta)
	if second.Action != Allow || second.Rule != first.Rule {
		t.Fatalf("second decision = %+v, want the cached allow", second)
	}
	if got := d.Stats().Cached; got != 1 {
		t.Fatalf("cached entries = %d, want 1", got)
	}
	if got := d.Stats().Observed; got != 2 {
		t.Fatalf("observed = %d, want 2", got)
	}
	// A cache hit must still mirror, or triage would see a gap in the traffic.
	mirrored := 0
	for {
		select {
		case <-q.Events():
			mirrored++
			continue
		default:
		}
		break
	}
	if mirrored != 2 {
		t.Fatalf("mirrored events = %d, want 2", mirrored)
	}
}

func TestHeaderSensitivePolicyIsNotCached(t *testing.T) {
	engine, err := policy.NewEngine(policy.Config{Rules: []policy.Rule{{
		Name:       "block-scanner",
		Action:     policy.ActionBlock,
		UserAgents: []string{"*sqlmap*"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	d := New(Config{Policy: engine, CacheTTL: time.Minute})
	meta := RequestMeta{Method: "GET", Path: "/", RemoteAddr: "203.0.113.5:1111"}
	if got := d.Decide(meta); got.Cacheable {
		t.Fatalf("header-sensitive decision marked cacheable: %+v", got)
	}
	if got := d.Stats().Cached; got != 0 {
		t.Fatalf("cached entries = %d, want 0", got)
	}
}

func TestCacheableMetadataDoesNotRequireLocalCache(t *testing.T) {
	d := New(Config{Policy: testPolicy(t)})
	got := d.Decide(RequestMeta{Method: "GET", Path: "/api/v1/users", RemoteAddr: "203.0.113.5:1111"})
	if !got.Cacheable {
		t.Fatalf("decision = %+v, want cacheable metadata for an external proxy cache", got)
	}
	if d.Stats().Cached != 0 {
		t.Fatal("a disabled local cache must remain empty")
	}
}

func TestReloadInvalidatesDecisionCache(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	body := "rules:\n  - name: first\n    action: allow\n    paths:\n      - /admin/*\n"
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	d := New(Config{Policy: engine, CacheTTL: time.Minute})
	meta := RequestMeta{Method: "GET", Path: "/admin/users", RemoteAddr: "203.0.113.5:1111"}
	if got := d.Decide(meta); got.Action != Allow || !got.Cacheable {
		t.Fatalf("pre-reload decision = %+v", got)
	}

	if err := os.WriteFile(path, []byte("rules:\n  - name: second\n    action: deny\n    paths:\n      - /admin/*\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := engine.Reload(); err != nil {
		t.Fatal(err)
	}
	if got := d.Decide(meta); got.Action != Deny {
		t.Fatalf("post-reload decision = %+v, want deny (stale cache must not survive)", got)
	}
}

func TestSidecarTokenAuth(t *testing.T) {
	d := New(Config{Policy: testPolicy(t), Queue: tap.NewMirrorQueue(4)})
	srv := NewServer(d, "")
	srv.SetToken("s3cret")
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/check", nil)
	req.Header.Set("X-Original-URI", "/api/v1/users")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", resp.StatusCode)
	}

	// Probes stay open for container liveness checks.
	resp, err = http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/v1/check", nil)
	req.Header.Set("X-Original-URI", "/api/v1/users")
	req.Header.Set("Authorization", "Bearer s3cret")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("authenticated status = %d, want 204", resp.StatusCode)
	}
}

func TestSidecarReloadEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(path, []byte("rules:\n  - name: first\n    action: deny\n    paths:\n      - /admin/*\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	engine, err := policy.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(NewServer(New(Config{Policy: engine}), "").Handler())
	defer ts.Close()

	if err := os.WriteFile(path, []byte("rules:\n  - name: second\n    action: block\n    paths:\n      - /admin/*\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(ts.URL+"/-/reload", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reload status = %d, want 200", resp.StatusCode)
	}

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/decide", strings.NewReader(`{"method":"GET","path":"/admin/users"}`))
	req.Header.Set("Content-Type", "application/json")
	dec, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer dec.Body.Close()
	var decision Decision
	if err := json.NewDecoder(dec.Body).Decode(&decision); err != nil {
		t.Fatal(err)
	}
	if decision.Action != Block || decision.Rule != "second" {
		t.Fatalf("decision = %+v, want block/second", decision)
	}
}

func TestCacheKeyUsesFullClientAddress(t *testing.T) {
	// A neighbouring address in the same /24 must not inherit a cached allow:
	// a narrow deny_cidr has to win even while the cache is warm.
	engine, err := policy.NewEngine(policy.Config{DenyCIDRs: []string{"203.0.113.9/32"}})
	if err != nil {
		t.Fatal(err)
	}
	d := New(Config{Policy: engine, CacheTTL: time.Minute})

	allowed := RequestMeta{Method: "GET", Path: "/", RemoteAddr: "203.0.113.5:1111"}
	if got := d.Decide(allowed); got.Action != Allow {
		t.Fatalf("neighbour decision = %+v, want allow", got)
	}
	denied := RequestMeta{Method: "GET", Path: "/", RemoteAddr: "203.0.113.9:2222"}
	if got := d.Decide(denied); got.Action != Deny {
		t.Fatalf("denied-neighbour decision = %+v, want deny (no cross-address cache reuse)", got)
	}
}
