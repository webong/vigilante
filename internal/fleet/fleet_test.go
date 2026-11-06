package fleet

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/webong/vigilante/internal/block"
	"github.com/webong/vigilante/internal/decision"
	"github.com/webong/vigilante/internal/flow"
	"github.com/webong/vigilante/internal/gate"
	"github.com/webong/vigilante/internal/history"
)

func TestKeyGenerationAndHashing(t *testing.T) {
	plain, hash, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(plain, KeyPrefix) {
		t.Fatalf("key %q missing prefix %q", plain, KeyPrefix)
	}
	got, err := HashKey(plain)
	if err != nil {
		t.Fatal(err)
	}
	if got != hash {
		t.Fatalf("hash mismatch: got %q, want %q", got, hash)
	}
	if _, err := HashKey("vk_wrong_prefix_1234567890"); err == nil {
		t.Fatal("expected error for non-vg_ prefix")
	}
	if _, err := HashKey("vg_short"); err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestValidateServerURL(t *testing.T) {
	if _, err := ValidateServerURL("https://vigilante.example.com", false); err != nil {
		t.Fatalf("expected https URL allowed: %v", err)
	}
	if _, err := ValidateServerURL("http://127.0.0.1:8080", false); err != nil {
		t.Fatalf("expected loopback http allowed: %v", err)
	}
	if _, err := ValidateServerURL("http://localhost:8080", false); err != nil {
		t.Fatalf("expected localhost http allowed: %v", err)
	}
	if _, err := ValidateServerURL("http://vigilante.example.com:8080", false); err == nil {
		t.Fatal("expected non-loopback plain http to be refused without -server-insecure")
	}
	if _, err := ValidateServerURL("http://vigilante.example.com:8080", true); err != nil {
		t.Fatalf("expected non-loopback plain http allowed with insecure=true: %v", err)
	}
}

func TestSanitizeEventAndEgress(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)

	// Invalid IP is rejected.
	if _, ok := SanitizeEvent(flow.Event{SrcAddr: "not-an-ip"}, 7, now); ok {
		t.Fatal("expected invalid SrcAddr to be rejected")
	}

	// Out-of-window timestamp is reset to receipt time; sensor ID is stamped;
	// unknown severity/verdict normalised; sensitive headers redacted.
	ev, ok := SanitizeEvent(flow.Event{
		Timestamp: now.Add(-48 * time.Hour),
		SrcAddr:   "203.0.113.5:443",
		Severity:  "UNKNOWN_SEV",
		Verdict:   "WEIRD_VERDICT",
		Method:    "get",
		Path:      strings.Repeat("a", 5000),
		Headers: map[string]string{
			"Authorization": "Bearer secret",
			"User-Agent":    "TestAgent/1.0",
		},
		SensorID: 999, // untrusted sensor-supplied ID must be overwritten
	}, 42, now)
	if !ok {
		t.Fatal("expected valid event")
	}
	if ev.SensorID != 42 {
		t.Fatalf("SensorID = %d, want 42", ev.SensorID)
	}
	if !ev.Timestamp.Equal(now) {
		t.Fatalf("Timestamp = %v, want receipt time %v", ev.Timestamp, now)
	}
	if ev.Severity != "info" {
		t.Fatalf("Severity = %q, want info", ev.Severity)
	}
	if ev.Verdict != "observe" {
		t.Fatalf("Verdict = %q, want observe", ev.Verdict)
	}
	if ev.Method != "GET" {
		t.Fatalf("Method = %q, want GET", ev.Method)
	}
	if len(ev.Path) != 2048 {
		t.Fatalf("len(Path) = %d, want 2048", len(ev.Path))
	}
	if ev.Headers["Authorization"] == "Bearer secret" {
		t.Fatal("expected Authorization header to be redacted")
	}

	// Egress sanitization
	if _, ok := SanitizeEgress(history.Egress{DstIP: "bad-ip"}, 42, now); ok {
		t.Fatal("expected invalid egress DstIP to be rejected")
	}
	eg, ok := SanitizeEgress(history.Egress{
		TS:      now.Add(10 * time.Minute), // > +5m skew
		DstIP:   "93.184.216.34",
		DstPort: 443,
		Comm:    "curl",
		Count:   0,
	}, 42, now)
	if !ok {
		t.Fatal("expected valid egress")
	}
	if eg.SensorID != 42 || !eg.TS.Equal(now) || eg.Count != 1 {
		t.Fatalf("sanitized egress = %+v", eg)
	}
}

func TestEndToEndServerAndTwoSensors(t *testing.T) {
	ctx := context.Background()
	store, err := history.Open(filepath.Join(t.TempDir(), "fleet.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	serverDecisions := decision.NewSet()
	fleetSrv := NewServer(ServerOptions{
		Store:     store,
		Decisions: serverDecisions,
	})
	mux := http.NewServeMux()
	fleetSrv.Register(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Register two sensors.
	key1, hash1, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s1, err := store.CreateSensor(ctx, "edge-1", hash1)
	if err != nil {
		t.Fatal(err)
	}
	key2, hash2, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	s2, err := store.CreateSensor(ctx, "edge-2", hash2)
	if err != nil {
		t.Fatal(err)
	}

	remote1 := decision.NewSet()
	uplink1, err := NewUplink(UplinkOptions{
		ServerURL: ts.URL,
		SensorKey: key1,
		Remote:    remote1,
	})
	if err != nil {
		t.Fatal(err)
	}

	remote2 := decision.NewSet()
	uplink2, err := NewUplink(UplinkOptions{
		ServerURL: ts.URL,
		SensorKey: key2,
		Remote:    remote2,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Both sensors observe requests from the same actor IP across instances.
	now := time.Now().UTC()
	_ = uplink1.Ingest(ctx, flow.Event{
		FlowID:         "flow-s1",
		Timestamp:      now,
		SrcAddr:        "198.51.100.88:5000",
		Method:         "GET",
		Path:           "/.env",
		Severity:       "high",
		Verdict:        "alert",
		TLSFingerprint: "ja4_abc",
	})
	uplink1.RecordEgress(history.Egress{
		TS:      now,
		Comm:    "node",
		PID:     101,
		UID:     1000,
		DstIP:   "93.184.216.34",
		DstPort: 443,
		Count:   3,
	})
	_ = uplink2.Ingest(ctx, flow.Event{
		FlowID:         "flow-s2",
		Timestamp:      now.Add(time.Second),
		SrcAddr:        "198.51.100.88:5001",
		Method:         "GET",
		Path:           "/wp-admin",
		Severity:       "high",
		Verdict:        "alert",
		TLSFingerprint: "ja4_abc",
	})

	if err := uplink1.Flush(ctx); err != nil {
		t.Fatalf("uplink1 flush: %v", err)
	}
	if err := uplink2.Flush(ctx); err != nil {
		t.Fatalf("uplink2 flush: %v", err)
	}

	// Verify both flows aggregated into the single actor on the central server.
	actor, err := store.Actor(ctx, "198.51.100.88|ja4_abc")
	if err != nil {
		t.Fatalf("central actor lookup: %v", err)
	}
	if actor.Requests != 2 {
		t.Fatalf("actor.Requests = %d, want 2", actor.Requests)
	}
	flows, err := store.Flows(ctx, actor.Key, time.Time{}, 10)
	if err != nil || len(flows) != 2 {
		t.Fatalf("flows = %+v, err = %v", flows, err)
	}
	if flows[0].SensorID != s1.ID || flows[1].SensorID != s2.ID {
		t.Fatalf("expected sensor IDs %d and %d, got %d and %d", s1.ID, s2.ID, flows[0].SensorID, flows[1].SensorID)
	}

	// Verify sensor check-in & egress_since on sensor 1.
	sensors, err := store.Sensors(ctx)
	if err != nil || len(sensors) != 2 {
		t.Fatalf("sensors = %+v, err = %v", sensors, err)
	}
	if sensors[0].LastSeenAt == nil || sensors[0].EgressSince == nil {
		t.Fatalf("sensor 1 expected last_seen_at and egress_since set: %+v", sensors[0])
	}
	if sensors[1].LastSeenAt == nil || sensors[1].EgressSince != nil {
		t.Fatalf("sensor 2 expected last_seen_at set and egress_since nil: %+v", sensors[1])
	}

	// Apply a central fleet block decision on the server.
	if err := serverDecisions.Put(decision.Entry{
		ID:      "fleet-block-1",
		Action:  "block",
		Scope:   decision.ScopeIP,
		Target:  "198.51.100.88",
		Reason:  "fleet-wide block",
		Expires: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}

	// Poll decisions on both sensors.
	if err := uplink1.PollOnce(ctx); err != nil {
		t.Fatalf("uplink1 poll: %v", err)
	}
	if err := uplink2.PollOnce(ctx); err != nil {
		t.Fatalf("uplink2 poll: %v", err)
	}

	// Second poll with unchanged decisions hits 304 Not Modified and preserves state.
	if err := uplink1.PollOnce(ctx); err != nil {
		t.Fatalf("uplink1 second poll (304): %v", err)
	}

	// Both sensors enforce the fleet decision alongside their local decision sets.
	local1 := decision.NewSet()
	_ = local1.Put(decision.Entry{ID: "local-rate", Action: "rate_limit", Scope: decision.ScopeIP, Target: "198.51.100.88"})
	gate1 := gate.New(gate.Options{
		Set:       local1,
		Remote:    remote1,
		Responses: map[string]bool{"rate_limit": true},
	})
	gate2 := gate.New(gate.Options{
		Set:    decision.NewSet(),
		Remote: remote2,
	})

	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.RemoteAddr = "198.51.100.88:44321"
	if got := gate1(req); got != "block" {
		t.Fatalf("sensor 1 gate = %q, want block (strictest of local rate_limit and fleet block)", got)
	}
	if got := gate2(req); got != "block" {
		t.Fatalf("sensor 2 gate = %q, want block", got)
	}

	// Revoking sensor 2's key immediately denies its next upload.
	if err := store.DeleteSensor(ctx, s2.ID); err != nil {
		t.Fatal(err)
	}
	_ = uplink2.Ingest(ctx, flow.Event{FlowID: "flow-s2-after", SrcAddr: "198.51.100.88:5002"})
	if err := uplink2.Flush(ctx); err == nil {
		t.Fatal("expected revoked sensor key upload to fail with 401")
	}
}

func TestUplinkFirewallReconciliation(t *testing.T) {
	ctx := context.Background()
	store, err := history.Open(filepath.Join(t.TempDir(), "fw.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	serverDecisions := decision.NewSet()
	fleetSrv := NewServer(ServerOptions{Store: store, Decisions: serverDecisions})
	mux := http.NewServeMux()
	fleetSrv.Register(mux)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	key, hash, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateSensor(ctx, "fw-sensor", hash); err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	blocked := map[string]bool{}
	enforcer, err := block.New(block.Options{
		Mode: block.ModeLog,
		OnBlock: func(ip net.IP, _ string) {
			mu.Lock()
			blocked[ip.String()] = true
			mu.Unlock()
		},
		OnUnblock: func(ip net.IP) {
			mu.Lock()
			delete(blocked, ip.String())
			mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	localSet := decision.NewSet()
	remoteSet := decision.NewSet()
	uplink, err := NewUplink(UplinkOptions{
		ServerURL: ts.URL,
		SensorKey: key,
		Remote:    remoteSet,
		Local:     localSet,
		Enforcer:  enforcer,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Add two fleet IP blocks on server and poll.
	_ = serverDecisions.Put(decision.Entry{ID: "fb-1", Action: "block", Scope: decision.ScopeIP, Target: "203.0.113.50", Reason: "scan"})
	_ = serverDecisions.Put(decision.Entry{ID: "fb-2", Action: "block", Scope: decision.ScopeIP, Target: "203.0.113.51", Reason: "brute"})
	if err := uplink.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if !blocked["203.0.113.50"] || !blocked["203.0.113.51"] {
		t.Fatalf("expected both IPs blocked in local firewall, got %v", blocked)
	}
	mu.Unlock()

	// 2. Also locally block 203.0.113.50, then remove both from the server.
	_ = localSet.Put(decision.Entry{ID: "lb-1", Action: "block", Scope: decision.ScopeIP, Target: "203.0.113.50"})
	serverDecisions.Remove("fb-1")
	serverDecisions.Remove("fb-2")
	if err := uplink.PollOnce(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	if !blocked["203.0.113.50"] {
		t.Fatal("expected locally blocked IP 203.0.113.50 to remain blocked in firewall")
	}
	if blocked["203.0.113.51"] {
		t.Fatal("expected revoked fleet IP 203.0.113.51 to be unblocked in firewall")
	}
	mu.Unlock()
}
