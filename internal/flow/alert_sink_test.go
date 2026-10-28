package flow

import (
	"context"
	"testing"
	"time"

	"github.com/webong/vigilante/internal/alert"
)

type memStore struct{ recs []alert.Record }

func (m *memStore) Record(r alert.Record) { m.recs = append(m.recs, r) }

func TestAlertSinkMapsEveryField(t *testing.T) {
	store := &memStore{}
	ts := time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)
	err := AlertSink{Store: store}.Ingest(context.Background(), Event{
		Timestamp:      ts,
		FlowID:         "flow-1",
		Severity:       "high",
		Verdict:        "alert",
		Summary:        "scanner",
		Method:         "GET",
		Path:           "/.env",
		SrcAddr:        "203.0.113.9:5000",
		TargetAddr:     "127.0.0.1:8080",
		UserAgent:      "zgrab/0.x",
		TLSFingerprint: "ja3-abc",
		Signals:        []string{"accepts_markdown"},
		Handler:        "cmd/server/main.go:42",
		Advisories:     []string{"CVE-2024-0001"},
		Findings:       []alert.Finding{{Subject: "example@1.0.0", Claim: "advisory present", Sources: []string{"https://osv.dev/vulnerability/TEST-1"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(store.recs) != 1 {
		t.Fatalf("records = %d, want 1", len(store.recs))
	}
	got := store.recs[0]
	if got.FlowID != "flow-1" || got.Severity != alert.SeverityHigh || got.Action != "alert" {
		t.Fatalf("unexpected record: %+v", got)
	}
	if got.UserAgent != "zgrab/0.x" || got.TLSFingerprint != "ja3-abc" {
		t.Fatalf("actor fields dropped: %+v", got)
	}
	if !got.Timestamp.Equal(ts) {
		t.Fatalf("timestamp = %s, want %s", got.Timestamp, ts)
	}
	if len(got.Findings) != 1 || got.Findings[0].Claim != "advisory present" {
		t.Fatalf("findings dropped: %+v", got.Findings)
	}
}

func TestAlertSinkWithoutStoreIsNoop(t *testing.T) {
	if err := (AlertSink{}).Ingest(context.Background(), Event{}); err != nil {
		t.Fatalf("nil store should be a no-op, got %v", err)
	}
}
