package decision

import (
	"net"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *clock { return &clock{t: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)} }

func TestPutNormalizesIPAndPort(t *testing.T) {
	s := NewSet()
	err := s.Put(Entry{ID: "d1", Action: "block", Scope: ScopeIP, Target: "203.0.113.9:443"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	e, ok := s.Lookup("203.0.113.9", "", "")
	if !ok {
		t.Fatal("expected a hit for the normalized IP")
	}
	if e.ID != "d1" {
		t.Fatalf("got decision %q, want d1", e.ID)
	}
	if e.Created.IsZero() {
		t.Fatal("Created should default to now")
	}
}

func TestPutRejectsInvalidEntries(t *testing.T) {
	s := NewSet()
	cases := []Entry{
		{Action: "block", Scope: ScopeIP, Target: "203.0.113.9"},
		{ID: "d", Scope: ScopeIP, Target: "203.0.113.9"},
		{ID: "d", Action: "block", Scope: ScopeIP, Target: "not-an-ip"},
		{ID: "d", Action: "block", Scope: ScopeCIDR, Target: "203.0.113.0"},
		{ID: "d", Action: "block", Scope: Scope("nope"), Target: "203.0.113.9"},
		{ID: "d", Action: "block", Scope: ScopeActor, Target: ""},
	}
	for i, c := range cases {
		if err := s.Put(c); err == nil {
			t.Errorf("case %d: expected an error for %+v", i, c)
		}
	}
}

func TestLookupPrecedence(t *testing.T) {
	s := NewSet()
	mustPut := func(e Entry) {
		t.Helper()
		if err := s.Put(e); err != nil {
			t.Fatalf("Put %+v: %v", e, err)
		}
	}
	mustPut(Entry{ID: "global", Action: "block", Scope: ScopeGlobal})
	mustPut(Entry{ID: "fp", Action: "block", Scope: ScopeFingerprint, Target: "ja3-abc"})
	mustPut(Entry{ID: "actor", Action: "block", Scope: ScopeActor, Target: "1.2.3.4/ja3-abc"})
	mustPut(Entry{ID: "cidr", Action: "block", Scope: ScopeCIDR, Target: "10.0.0.0/8"})
	mustPut(Entry{ID: "ip", Action: "block", Scope: ScopeIP, Target: "10.1.2.3"})

	cases := []struct {
		name, ip, actor, fp, want string
	}{
		{"exact ip", "10.1.2.3", "", "", "ip"},
		{"cidr", "10.9.9.9", "", "", "cidr"},
		{"actor", "10.1.2.4", "1.2.3.4/ja3-abc", "", "actor"},
		{"fingerprint", "10.1.2.4", "", "ja3-abc", "fp"},
		{"global", "192.0.2.1", "", "", "global"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, ok := s.Lookup(tc.ip, tc.actor, tc.fp)
			if !ok {
				t.Fatal("expected a hit")
			}
			if e.ID != tc.want {
				t.Fatalf("got %q, want %q", e.ID, tc.want)
			}
		})
	}
}

func TestLookupMissesOutsideCIDR(t *testing.T) {
	s := NewSet()
	if err := s.Put(Entry{ID: "cidr", Action: "block", Scope: ScopeCIDR, Target: "10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup("192.0.2.1", "", ""); ok {
		t.Fatal("192.0.2.1 must not match 10.0.0.0/8")
	}
}

func TestExpiryAndSweep(t *testing.T) {
	c := newClock()
	s := NewSetWithClock(c.now)
	if err := s.Put(Entry{ID: "short", Action: "block", Scope: ScopeIP, Target: "203.0.113.9", Expires: c.t.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Lookup("203.0.113.9", "", ""); !ok {
		t.Fatal("expected a hit before expiry")
	}
	c.advance(2 * time.Minute)
	if _, ok := s.Lookup("203.0.113.9", "", ""); ok {
		t.Fatal("expired entry must not match")
	}
	if got := len(s.Active()); got != 0 {
		t.Fatalf("Active() = %d, want 0", got)
	}
	expired := s.Sweep()
	if len(expired) != 1 || expired[0].ID != "short" {
		t.Fatalf("Sweep() = %+v, want the short entry", expired)
	}
	if s.Len() != 0 {
		t.Fatalf("Len() = %d after sweep, want 0", s.Len())
	}
}

func TestZeroExpiryNeverExpires(t *testing.T) {
	c := newClock()
	s := NewSetWithClock(c.now)
	if err := s.Put(Entry{ID: "forever", Action: "block", Scope: ScopeIP, Target: "203.0.113.9"}); err != nil {
		t.Fatal(err)
	}
	c.advance(100 * 365 * 24 * time.Hour)
	if _, ok := s.Lookup("203.0.113.9", "", ""); !ok {
		t.Fatal("a zero-expiry entry must stay in force")
	}
}

func TestRemove(t *testing.T) {
	s := NewSet()
	_ = s.Put(Entry{ID: "d1", Action: "block", Scope: ScopeIP, Target: "203.0.113.9"})
	if !s.Remove("d1") {
		t.Fatal("Remove should report true for a present entry")
	}
	if s.Remove("d1") {
		t.Fatal("Remove should report false the second time")
	}
	if _, ok := s.Lookup("203.0.113.9", "", ""); ok {
		t.Fatal("removed entry must not match")
	}
}

func TestNormalizeIP(t *testing.T) {
	cases := map[string]string{
		"203.0.113.9:443":  "203.0.113.9",
		"203.0.113.9":      "203.0.113.9",
		"[2001:db8::1]:80": "2001:db8::1",
		"2001:db8::1":      "2001:db8::1",
		"localhost":        "",
		"":                 "",
	}
	for in, want := range cases {
		if got := NormalizeIP(in); got != want {
			t.Errorf("NormalizeIP(%q) = %q, want %q", in, got, want)
		}
	}
	if ip := net.ParseIP(NormalizeIP("203.0.113.9")); ip == nil {
		t.Fatal("normalized value should still parse")
	}
}
