package gate

import (
	"net/http"
	"testing"

	"github.com/webong/vigilante/internal/decision"
)

func request(remote string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.RemoteAddr = remote
	return r
}

func TestPolicyWinsOverSnapshot(t *testing.T) {
	set := decision.NewSet()
	if err := set.Put(decision.Entry{ID: "allow-everyone", Action: "allow", Scope: decision.ScopeGlobal}); err != nil {
		t.Fatal(err)
	}
	gate := New(Options{
		Policy: func(*http.Request) string { return "deny" },
		Set:    set,
	})
	if got := gate(request("203.0.113.9:1234")); got != "deny" {
		t.Fatalf("gate = %q, want deny from static policy", got)
	}
}

func TestSnapshotBlocksWhenPolicyAllows(t *testing.T) {
	set := decision.NewSet()
	if err := set.Put(decision.Entry{ID: "d1", Action: "block", Scope: decision.ScopeIP, Target: "203.0.113.9"}); err != nil {
		t.Fatal(err)
	}
	var hits int
	gate := New(Options{
		Policy: func(*http.Request) string { return "allow" },
		Set:    set,
		OnHit:  func(decision.Entry) { hits++ },
	})
	if got := gate(request("203.0.113.9:5555")); got != "block" {
		t.Fatalf("gate = %q, want block", got)
	}
	if hits != 1 {
		t.Fatalf("OnHit calls = %d, want 1", hits)
	}
	if got := gate(request("198.51.100.7:5555")); got != "allow" {
		t.Fatalf("gate = %q, want allow for an unlisted address", got)
	}
}

func TestSnapshotOnlyGate(t *testing.T) {
	set := decision.NewSet()
	if err := set.Put(decision.Entry{ID: "d1", Action: "deny", Scope: decision.ScopeCIDR, Target: "10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	gate := New(Options{Set: set})
	if got := gate(request("10.2.3.4:80")); got != "deny" {
		t.Fatalf("gate = %q, want deny", got)
	}
	if got := gate(request("192.0.2.1:80")); got != "allow" {
		t.Fatalf("gate = %q, want allow", got)
	}
}

func TestChallengeFailsClosed(t *testing.T) {
	set := decision.NewSet()
	if err := set.Put(decision.Entry{ID: "d1", Action: "challenge", Scope: decision.ScopeIP, Target: "203.0.113.9"}); err != nil {
		t.Fatal(err)
	}
	if got := New(Options{Set: set})(request("203.0.113.9:1")); got != "block" {
		t.Fatalf("gate = %q, want block (fail closed)", got)
	}
}

func TestActorChannelBlocksAcrossAddresses(t *testing.T) {
	set := decision.NewSet()
	if err := set.Put(decision.Entry{ID: "d1", Action: "block", Scope: decision.ScopeActor, Target: "actor-7"}); err != nil {
		t.Fatal(err)
	}
	gate := New(Options{
		Set:   set,
		Actor: func(*http.Request) string { return "actor-7" },
	})
	if got := gate(request("198.51.100.1:1")); got != "block" {
		t.Fatalf("gate = %q, want block via actor scope", got)
	}
}

func TestNilRequestAllows(t *testing.T) {
	if got := New(Options{})(nil); got != "allow" {
		t.Fatalf("gate = %q, want allow", got)
	}
}

func TestDualSetStrictestWins(t *testing.T) {
	local := decision.NewSet()
	remote := decision.NewSet()

	// Local rate_limit vs Remote block -> block wins
	if err := local.Put(decision.Entry{ID: "l1", Action: "rate_limit", Scope: decision.ScopeIP, Target: "203.0.113.10"}); err != nil {
		t.Fatal(err)
	}
	if err := remote.Put(decision.Entry{ID: "r1", Action: "block", Scope: decision.ScopeIP, Target: "203.0.113.10"}); err != nil {
		t.Fatal(err)
	}
	// Local challenge vs Remote rate_limit -> challenge wins
	if err := local.Put(decision.Entry{ID: "l2", Action: "challenge", Scope: decision.ScopeIP, Target: "203.0.113.11"}); err != nil {
		t.Fatal(err)
	}
	if err := remote.Put(decision.Entry{ID: "r2", Action: "rate_limit", Scope: decision.ScopeIP, Target: "203.0.113.11"}); err != nil {
		t.Fatal(err)
	}
	// Remote-only decision
	if err := remote.Put(decision.Entry{ID: "r3", Action: "challenge", Scope: decision.ScopeIP, Target: "203.0.113.12"}); err != nil {
		t.Fatal(err)
	}

	var hitID string
	gate := New(Options{
		Set:       local,
		Remote:    remote,
		Responses: map[string]bool{"challenge": true, "rate_limit": true},
		OnHit:     func(e decision.Entry) { hitID = e.ID },
	})

	if got := gate(request("203.0.113.10:1234")); got != "block" || hitID != "r1" {
		t.Fatalf("gate = %q (hit %q), want block (hit r1)", got, hitID)
	}
	if got := gate(request("203.0.113.11:1234")); got != "challenge" || hitID != "l2" {
		t.Fatalf("gate = %q (hit %q), want challenge (hit l2)", got, hitID)
	}
	if got := gate(request("203.0.113.12:1234")); got != "challenge" || hitID != "r3" {
		t.Fatalf("gate = %q (hit %q), want challenge (hit r3)", got, hitID)
	}

	// Replacing remote set never erases local decisions.
	remote.Replace(nil)
	if got := gate(request("203.0.113.10:1234")); got != "rate_limit" || hitID != "l1" {
		t.Fatalf("after remote clear: gate = %q (hit %q), want rate_limit (hit l1)", got, hitID)
	}
}
