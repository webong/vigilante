package history

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/webong/vigilante/internal/decision"
	"github.com/webong/vigilante/internal/flow"
)

func TestStorePersistsHistoryAndReview(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		if err := s.Ingest(ctx, flow.Event{FlowID: string(rune('a' + i)), Timestamp: now.Add(time.Duration(i) * time.Second), SrcAddr: "203.0.113.8:1234", Method: "GET", Path: "/docs", Headers: map[string]string{"Accept": "text/html"}, Status: 200}); err != nil {
			t.Fatal(err)
		}
	}
	a, err := s.Actor(ctx, "203.0.113.8")
	if err != nil {
		t.Fatal(err)
	}
	if a.Requests != 3 {
		t.Fatalf("requests=%d", a.Requests)
	}
	flows, err := s.Flows(ctx, a.Key, time.Time{}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 2 || flows[0].FlowID != "b" {
		t.Fatalf("newest window=%+v", flows)
	}
	a.Class = "automation"
	a.Risk = 40
	a.Signals = []string{"test"}
	if err := s.Analyze(ctx, a); err != nil {
		t.Fatal(err)
	}
	suggestion := Suggestion{ID: "s1", ActorKey: a.Key, Action: "challenge", Scope: decision.ScopeIP, Target: a.IP}
	if err := s.Suggest(ctx, suggestion); err != nil {
		t.Fatal(err)
	}
	if err := s.Suggest(ctx, suggestion); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveSuggestion(ctx, "s1", "approved", "d1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveSuggestion(ctx, "s1", "revoked", ""); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a, err = s.Actor(ctx, "203.0.113.8")
	if err != nil || a.Class != "automation" {
		t.Fatalf("actor=%+v err=%v", a, err)
	}
	if err := s.RecordEgress(ctx, Egress{TS: now, Comm: "app", DstIP: "198.51.100.2", DstPort: 443, Count: 2}); err != nil {
		t.Fatal(err)
	}
	out, err := s.Egress(ctx, now.Add(-time.Minute), 10)
	if err != nil || len(out) != 1 {
		t.Fatalf("egress=%+v err=%v", out, err)
	}
	if err := s.Prune(ctx, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	flows, err = s.Flows(ctx, "", time.Time{}, 10)
	if err != nil || len(flows) != 0 {
		t.Fatalf("pruned=%+v err=%v", flows, err)
	}
}

func TestStoreSensorsLifecycle(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "sensors.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()

	sn, err := s.CreateSensor(ctx, "edge-1", "hash-1")
	if err != nil {
		t.Fatal(err)
	}
	if sn.ID <= 0 || sn.Name != "edge-1" || sn.LastSeenAt != nil || sn.EgressSince != nil {
		t.Fatalf("created sensor = %+v", sn)
	}

	got, err := s.LookupSensorByHash(ctx, "hash-1")
	if err != nil || got.ID != sn.ID {
		t.Fatalf("lookup = %+v, err = %v", got, err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	if err := s.TouchSensor(ctx, sn.ID, now, 7, true); err != nil {
		t.Fatal(err)
	}
	if err := s.Ingest(ctx, flow.Event{FlowID: "f-sensor-1", Timestamp: now, SrcAddr: "198.51.100.77:443", Method: "GET", Path: "/", SensorID: sn.ID}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordEgress(ctx, Egress{SensorID: sn.ID, TS: now, Comm: "nginx", DstIP: "93.184.216.34", DstPort: 443, Count: 1}); err != nil {
		t.Fatal(err)
	}

	list, err := s.Sensors(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("sensors = %+v, err = %v", list, err)
	}
	if list[0].Dropped != 7 || list[0].LastSeenAt == nil || list[0].EgressSince == nil {
		t.Fatalf("touched sensor = %+v", list[0])
	}

	if err := s.DeleteSensor(ctx, sn.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupSensorByHash(ctx, "hash-1"); err == nil {
		t.Fatal("expected deleted sensor key hash lookup to fail")
	}
	flows, err := s.Flows(ctx, "", time.Time{}, 10)
	if err != nil || len(flows) != 0 {
		t.Fatalf("expected sensor flows deleted, got %+v (err=%v)", flows, err)
	}
	eg, err := s.Egress(ctx, now.Add(-time.Minute), 10)
	if err != nil || len(eg) != 0 {
		t.Fatalf("expected sensor egress deleted, got %+v (err=%v)", eg, err)
	}
}
