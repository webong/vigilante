package block

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestLogModeNeverExecutes(t *testing.T) {
	var calls int
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		calls++
		return nil, nil
	}
	var gotIP net.IP
	var gotRule string
	e, err := New(Options{
		Mode:   ModeLog,
		Runner: runner,
		OnBlock: func(ip net.IP, rule string) {
			gotIP, gotRule = ip, rule
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Block(context.Background(), net.ParseIP("203.0.113.9"), "r1"); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("log mode executed %d commands, want 0", calls)
	}
	if gotIP.String() != "203.0.113.9" || gotRule != "r1" {
		t.Fatalf("OnBlock got %s/%s", gotIP, gotRule)
	}
}

func TestRefusesLoopbackAndUnspecified(t *testing.T) {
	e, err := New(Options{Mode: ModeLog})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Block(context.Background(), net.ParseIP("127.0.0.1"), "r"); err == nil {
		t.Fatal("expected loopback refusal")
	}
	if err := e.Block(context.Background(), net.IPv4zero, "r"); err == nil {
		t.Fatal("expected unspecified refusal")
	}
	if err := e.Block(context.Background(), nil, "r"); err == nil {
		t.Fatal("expected nil refusal")
	}
}

func TestIPTablesProvisionAndAddDrop(t *testing.T) {
	var cmds [][]string
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		cmds = append(cmds, append([]string{name}, args...))
		// -C (check) fails so the code takes the add path; everything else ok.
		if len(args) > 0 && args[0] == "-C" {
			return nil, errFake{"no such rule"}
		}
		return nil, nil
	}
	e, err := New(Options{Mode: ModeIPTables, Chain: "VIG", Runner: runner, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Block(context.Background(), net.ParseIP("198.51.100.4"), "r"); err != nil {
		t.Fatal(err)
	}
	joined := ""
	for _, c := range cmds {
		joined += strings.Join(c, " ") + "\n"
	}
	if !strings.Contains(joined, "iptables -N VIG") {
		t.Fatalf("missing chain creation:\n%s", joined)
	}
	if !strings.Contains(joined, "iptables -A VIG -s 198.51.100.4 -j DROP") {
		t.Fatalf("missing drop rule:\n%s", joined)
	}
}

func TestIPTablesIdempotentSkipsExistingRule(t *testing.T) {
	var adds int
	runner := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if len(args) > 0 && args[0] == "-C" && len(args) > 1 && args[1] == "VIG" {
			return nil, nil // rule exists
		}
		if len(args) > 0 && args[0] == "-A" {
			adds++
		}
		return nil, nil
	}
	e, err := New(Options{Mode: ModeIPTables, Chain: "VIG", Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Block(context.Background(), net.ParseIP("198.51.100.4"), "r"); err != nil {
		t.Fatal(err)
	}
	if adds != 0 {
		t.Fatalf("added %d duplicate rules, want 0", adds)
	}
}

func TestThresholdFiresOnceAtCount(t *testing.T) {
	var fires int
	enc, err := New(Options{
		Mode:    ModeLog,
		OnBlock: func(net.IP, string) { fires++ },
	})
	if err != nil {
		t.Fatal(err)
	}
	th := NewThreshold(ThresholdConfig{Count: 3, Window: time.Minute, MinSeverity: "high"}, enc)
	if th == nil {
		t.Fatal("threshold should not be nil")
	}
	ctx := context.Background()
	src := "203.0.113.10:5555"

	// Two high verdicts: no block yet.
	if th.Observe(ctx, src, "high") {
		t.Fatal("fired before threshold")
	}
	if th.Observe(ctx, src, "critical") {
		t.Fatal("fired before threshold")
	}
	// Third qualifying verdict crosses.
	if !th.Observe(ctx, src, "high") {
		t.Fatal("expected block on 3rd")
	}
	// Fourth does not re-fire.
	if th.Observe(ctx, src, "high") {
		t.Fatal("should not re-fire after crossing")
	}
	if fires != 1 {
		t.Fatalf("fires = %d, want 1", fires)
	}
}

func TestThresholdRespectsMinSeverity(t *testing.T) {
	enc, _ := New(Options{Mode: ModeLog})
	th := NewThreshold(ThresholdConfig{Count: 2, Window: time.Minute, MinSeverity: "high"}, enc)
	ctx := context.Background()
	src := "203.0.113.11:1"
	// info verdicts don't count.
	th.Observe(ctx, src, "info")
	th.Observe(ctx, src, "info")
	th.Observe(ctx, src, "info")
	// now a high — still only 1 qualifying.
	if th.Observe(ctx, src, "high") {
		t.Fatal("low-severity hits should not count toward a high threshold")
	}
}

func TestThresholdSkipsLoopback(t *testing.T) {
	enc, _ := New(Options{Mode: ModeLog})
	th := NewThreshold(ThresholdConfig{Count: 1, Window: time.Minute}, enc)
	ctx := context.Background()
	if th.Observe(ctx, "127.0.0.1:8080", "critical") {
		t.Fatal("loopback must never be threshold-blocked")
	}
}

func TestNewThresholdDisabledWhenCountZero(t *testing.T) {
	enc, _ := New(Options{Mode: ModeLog})
	if NewThreshold(ThresholdConfig{Count: 0}, enc) != nil {
		t.Fatal("count 0 should yield nil (disabled)")
	}
	if NewThreshold(ThresholdConfig{Count: 3}, nil) != nil {
		t.Fatal("nil enforcer should yield nil")
	}
}

func TestUnknownModeRejected(t *testing.T) {
	if _, err := New(Options{Mode: "waffle"}); err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

type errFake struct{ msg string }

func (e errFake) Error() string { return e.msg }
