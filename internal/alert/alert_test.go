package alert

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestStorePersistsJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	s, err := Open(Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.Record(Record{FlowID: "f1", Severity: SeverityHigh, Action: "alert", Summary: "sqli"})
	s.Record(Record{FlowID: "f2", Severity: SeverityCritical, Action: "recommend-block"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	var rec Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.FlowID != "f1" || rec.Severity != SeverityHigh || rec.Timestamp.IsZero() {
		t.Fatalf("record = %+v", rec)
	}
	stored, _, _ := s.Stats()
	if stored != 2 {
		t.Fatalf("stored = %d, want 2", stored)
	}
}

func TestMinSeverityFilter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	s, err := Open(Options{Path: path, MinSeverity: SeverityHigh})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.Record(Record{FlowID: "low", Severity: SeverityLow})
	s.Record(Record{FlowID: "crit", Severity: SeverityCritical})

	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), `"flow_id":"low"`) {
		t.Fatal("low-severity record should be filtered")
	}
	if !strings.Contains(string(data), `"flow_id":"crit"`) {
		t.Fatal("critical record should be stored")
	}
}

func TestRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alerts.jsonl")
	s, err := Open(Options{Path: path, MaxBytes: 200, KeepFiles: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	for i := 0; i < 50; i++ {
		s.Record(Record{FlowID: "f", Severity: SeverityInfo, Summary: strings.Repeat("x", 50)})
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("rotated file missing: %v", err)
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Fatal("keep-files bound violated (file .3 should not exist)")
	}
}

func TestDeliverDirect(t *testing.T) {
	var got atomic.Value // holds body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.Store(string(b))
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	s, err := Open(Options{
		Path:       filepath.Join(t.TempDir(), "a.jsonl"),
		DeliverURL: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.Record(Record{FlowID: "f9", Severity: SeverityCritical, Action: "recommend-block"})

	body, _ := got.Load().(string)
	if !strings.Contains(body, `"flow_id":"f9"`) {
		t.Fatalf("delivered body = %q", body)
	}
	_, delivered, failed := s.Stats()
	if delivered != 1 || failed != 0 {
		t.Fatalf("delivered=%d failed=%d", delivered, failed)
	}
}

func TestDeliverViaPlannerRoute(t *testing.T) {
	var path atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path.Store(r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s, err := Open(Options{
		Path:          filepath.Join(t.TempDir(), "a.jsonl"),
		DeliverURL:    "http://unused.example", // overridden by PlannerURL
		PlannerURL:    srv.URL + "/",
		InternalToken: "tok123",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.Record(Record{FlowID: "fp", Severity: SeverityHigh})

	if p, _ := path.Load().(string); p != "/vigilante/alerts" {
		t.Fatalf("planner path = %q, want /vigilante/alerts", p)
	}
}

func TestDeliveryFailureCountedNotFatal(t *testing.T) {
	s, err := Open(Options{
		Path:       filepath.Join(t.TempDir(), "a.jsonl"),
		DeliverURL: "http://127.0.0.1:1", // closed port
		OnError:    func(error) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.Record(Record{FlowID: "fx", Severity: SeverityHigh})
	_, delivered, failed := s.Stats()
	if delivered != 0 || failed != 1 {
		t.Fatalf("delivered=%d failed=%d, want 0/1", delivered, failed)
	}
}

func TestSeverityRankOrdering(t *testing.T) {
	if !(rank(SeverityCritical) > rank(SeverityHigh) &&
		rank(SeverityHigh) > rank(SeverityMedium) &&
		rank(SeverityMedium) > rank(SeverityLow) &&
		rank(SeverityLow) > rank(SeverityInfo)) {
		t.Fatal("severity ranks not ordered")
	}
	_ = time.Now // keep time import if unused elsewhere
}
