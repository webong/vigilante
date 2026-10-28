package actor

import (
	"context"
	"testing"
	"time"

	"github.com/webong/vigilante/internal/flow"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newClock() *clock {
	return &clock{t: time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)}
}

func ev(src string, sev string, at time.Time) flow.Event {
	return flow.Event{Timestamp: at, SrcAddr: src, Severity: sev, Verdict: "alert"}
}

func TestActorKey(t *testing.T) {
	cases := []struct {
		src, fp, want string
	}{
		{"203.0.113.9:443", "", "203.0.113.9"},
		{"203.0.113.9:443", "ja3-abc", "203.0.113.9|ja3-abc"},
		{"", "", "unknown"},
		{"", "ja3-abc", "fp:ja3-abc"},
	}
	for _, c := range cases {
		if got := ActorKey(c.src, c.fp); got != c.want {
			t.Errorf("ActorKey(%q,%q) = %q, want %q", c.src, c.fp, got, c.want)
		}
	}
}

func TestIngestAggregatesByActor(t *testing.T) {
	c := newClock()
	idx := NewIndexWithClock(time.Hour, 100, c.now)

	_ = idx.Ingest(context.Background(), ev("203.0.113.9:443", "critical", c.t))
	c.advance(time.Minute)
	_ = idx.Ingest(context.Background(), ev("203.0.113.9:444", "high", c.t))
	// A different fingerprint is a different actor, even from the same NAT IP.
	c.advance(time.Minute)
	_ = idx.Ingest(context.Background(), flow.Event{
		Timestamp: c.t, SrcAddr: "203.0.113.9:445", Severity: "low",
		TLSFingerprint: "ja3-abc", Verdict: "observe", UserAgent: "GPTBot/1.0",
	})

	if idx.Count() != 2 {
		t.Fatalf("actor count = %d, want 2", idx.Count())
	}

	snap := idx.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot = %d, want 2", len(snap))
	}
	first := snap[0]
	if first.Key != "203.0.113.9" || first.Requests != 2 {
		t.Fatalf("first actor = %+v", first)
	}
	if first.Risk != severityWeight["critical"]+severityWeight["high"] {
		t.Fatalf("risk = %d, want %d", first.Risk, severityWeight["critical"]+severityWeight["high"])
	}
	if first.BySeverity["critical"] != 1 || first.BySeverity["high"] != 1 {
		t.Fatalf("by_severity = %v", first.BySeverity)
	}

	fp := snap[1]
	if fp.Key != "203.0.113.9|ja3-abc" || fp.Fingerprint != "ja3-abc" {
		t.Fatalf("fingerprint actor = %+v", fp)
	}
	if !contains(fp.Tags, "ai-agent") {
		t.Fatalf("expected ai-agent tag, got %v", fp.Tags)
	}
	if contains(fp.Tags, "ai-agent") && fp.Risk != severityWeight["low"] {
		t.Fatalf("low severity risk = %d", fp.Risk)
	}
}

func TestRiskDecaysOutOfWindow(t *testing.T) {
	c := newClock()
	idx := NewIndexWithClock(time.Hour, 100, c.now)

	_ = idx.Ingest(context.Background(), ev("203.0.113.9:1", "critical", c.t))
	if got := idx.Snapshot()[0].Risk; got != severityWeight["critical"] {
		t.Fatalf("risk before decay = %d", got)
	}
	c.advance(2 * time.Hour)
	if got := idx.Snapshot()[0].Risk; got != 0 {
		t.Fatalf("risk after decay = %d, want 0", got)
	}
}

func TestSuspiciousThreshold(t *testing.T) {
	c := newClock()
	idx := NewIndexWithClock(time.Hour, 100, c.now)

	for i := 0; i < 3; i++ { // 3 criticals = 60 > 50
		_ = idx.Ingest(context.Background(), ev("203.0.113.9:1", "critical", c.t))
		c.advance(time.Second)
	}
	got := idx.Snapshot()[0]
	if !got.Suspicious || got.Risk != 3*severityWeight["critical"] {
		t.Fatalf("actor = %+v, want suspicious at risk %d", got, 3*severityWeight["critical"])
	}
}

func TestTagsFor(t *testing.T) {
	ua := flow.Event{UserAgent: "Mozilla/5.0 (compatible; ClaudeBot/1.0)", Summary: "Path traversal attempt"}
	if tags := TagsFor(ua); !contains(tags, "path-traversal") || !contains(tags, "ai-agent") {
		t.Fatalf("tags = %v", tags)
	}
	inj := flow.Event{Path: "/x?q=1 UNION SELECT", Summary: "Injection payload"}
	if tags := TagsFor(inj); !contains(tags, "injection") {
		t.Fatalf("tags = %v", tags)
	}
	cve := flow.Event{Advisories: []string{"CVE-2024-0001"}}
	if tags := TagsFor(cve); !contains(tags, "cve") {
		t.Fatalf("tags = %v", tags)
	}
}

func TestEvictionStaysBounded(t *testing.T) {
	c := newClock()
	idx := NewIndexWithClock(time.Hour, 2, c.now)

	for i, ip := range []string{"203.0.113.1:1", "203.0.113.2:1", "203.0.113.3:1"} {
		_ = idx.Ingest(context.Background(), ev(ip, "info", c.t.Add(time.Duration(i)*time.Second)))
	}
	if idx.Count() != 2 {
		t.Fatalf("count = %d, want 2 (bounded)", idx.Count())
	}
	// The oldest (203.0.113.1) must be evicted.
	for _, a := range idx.Snapshot() {
		if a.IP == "203.0.113.1" {
			t.Fatal("oldest actor should have been evicted")
		}
	}
}

func contains(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
