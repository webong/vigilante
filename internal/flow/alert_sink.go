package flow

import (
	"context"
	"time"

	"github.com/webong/vigilante/internal/alert"
)

// Recorder is the subset of the alert store the sink needs.
type Recorder interface {
	Record(alert.Record)
}

// AlertSink persists every published flow in the JSONL alert store. It is the
// baseline sink: durable, replayable, and independent of any stateful console.
type AlertSink struct {
	Store Recorder
}

// Ingest implements Sink.
func (s AlertSink) Ingest(_ context.Context, ev Event) error {
	if s.Store == nil {
		return nil
	}
	ts := ev.Timestamp
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	s.Store.Record(alert.Record{
		Timestamp:      ts,
		FlowID:         ev.FlowID,
		Severity:       alert.Severity(ev.Severity),
		Action:         ev.Verdict,
		Summary:        ev.Summary,
		Method:         ev.Method,
		Path:           ev.Path,
		SrcAddr:        ev.SrcAddr,
		TargetAddr:     ev.TargetAddr,
		UserAgent:      ev.UserAgent,
		TLSFingerprint: ev.TLSFingerprint,
		Signals:        ev.Signals,
		Handler:        ev.Handler,
		Advisories:     ev.Advisories,
		Findings:       ev.Findings,
	})
	return nil
}
