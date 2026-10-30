package behavior

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/webong/vigilante/internal/flow"
	"github.com/webong/vigilante/internal/history"
	"github.com/webong/vigilante/internal/identity"
)

func codes(r Result) []string {
	var out []string
	for _, s := range r.Signals {
		out = append(out, s.Code)
	}
	return out
}
func TestBehaviorDetectsSequences(t *testing.T) {
	start := time.Now().UTC()
	var flows []history.Flow
	for i := 0; i < 40; i++ {
		flows = append(flows, history.Flow{Event: event(start.Add(time.Duration(i)*500*time.Millisecond), fmt.Sprintf("/api/users/%d", i), "python-requests/2.32")})
	}
	r := Analyze(flows, identity.Result{})
	for _, want := range []string{"id_enumeration", "machine_timing", "automation_ua"} {
		if !slices.Contains(codes(r), want) {
			t.Errorf("missing %s in %v", want, codes(r))
		}
	}
}
func TestBehaviorVerifiedAndImpersonatedBots(t *testing.T) {
	f := []history.Flow{{Event: event(time.Now(), "/", "Googlebot/2.1")}}
	if r := Analyze(f, identity.Result{Verified: "Googlebot"}); r.Class != "verified_bot" || r.Score > 5 {
		t.Fatalf("%+v", r)
	}
	if r := Analyze(f, identity.Result{Failed: "wrong network"}); r.Class != "impersonator" || r.Score < 80 {
		t.Fatalf("%+v", r)
	}
}
func TestParallelAssetsAreNotClockwork(t *testing.T) {
	now := time.Now()
	var flows []history.Flow
	for i := 0; i < 20; i++ {
		flows = append(flows, history.Flow{Event: event(now, fmt.Sprintf("/%d.png", i), "")})
	}
	if slices.Contains(codes(Analyze(flows, identity.Result{})), "machine_timing") {
		t.Fatal("parallel burst flagged")
	}
}
func event(ts time.Time, path, ua string) flow.Event {
	return flow.Event{Timestamp: ts, Method: "GET", Path: path, UserAgent: ua, Headers: map[string]string{}}
}
