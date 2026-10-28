// Package flow is the core's publication contract: one enriched, triaged flow
// leaves the stateless pipeline and any number of sinks may consume it.
//
// The core never waits for a sink. Publication uses a bounded queue; when the
// queue is full the event is dropped and counted, exactly like the mirror
// queue, so a slow or wedged consumer can never exert backpressure on live
// traffic.
//
// This is the seam a stateful console uses: it implements Sink, aggregates
// actors, and pushes decisions back through internal/action. It is also why the
// core stays stateless — replay and durable state live on the sink side.
package flow

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

// Event is one triaged flow. It carries detection output, not payloads: the
// preview is already redacted by the tap.
type Event struct {
	Timestamp       time.Time `json:"timestamp"`
	FlowID          string    `json:"flow_id"`
	Severity        string    `json:"severity"`
	Verdict         string    `json:"verdict"`
	Summary         string    `json:"summary,omitempty"`
	Method          string    `json:"method,omitempty"`
	Path            string    `json:"path,omitempty"`
	SrcAddr         string    `json:"src_addr,omitempty"`
	TargetAddr      string    `json:"target_addr,omitempty"`
	UserAgent       string    `json:"user_agent,omitempty"`
	TLSFingerprint  string    `json:"tls_fingerprint,omitempty"`
	Handler         string    `json:"matched_handler,omitempty"`
	Advisories      []string  `json:"matched_advisories,omitempty"`
	Recommendations []string  `json:"recommendations,omitempty"`
	Signals         []string  `json:"signals,omitempty"`
}

// Sink consumes published events. It may block; the publisher isolates that
// from the caller.
type Sink interface {
	Ingest(ctx context.Context, ev Event) error
}

// SinkFunc adapts a function to Sink.
type SinkFunc func(ctx context.Context, ev Event) error

// Ingest implements Sink.
func (f SinkFunc) Ingest(ctx context.Context, ev Event) error { return f(ctx, ev) }

// ErrClosed is returned by Close when the drain deadline is exceeded.
var ErrClosed = errors.New("flow: publisher closed before draining")

// Publisher fans events out to sinks over a bounded queue.
type Publisher struct {
	sinks   []Sink
	ch      chan Event
	workers int

	published atomic.Uint64
	dropped   atomic.Uint64
	delivered atomic.Uint64
	failed    atomic.Uint64
	closed    atomic.Bool

	wg   sync.WaitGroup
	once sync.Once
}

// NewPublisher starts workers consuming from a queue of depth queue. Workers
// and queue are clamped to at least one.
func NewPublisher(sinks []Sink, queue, workers int) *Publisher {
	if queue <= 0 {
		queue = 256
	}
	if workers <= 0 {
		workers = 1
	}
	p := &Publisher{
		sinks:   append([]Sink(nil), sinks...),
		ch:      make(chan Event, queue),
		workers: workers,
	}
	for i := 0; i < workers; i++ {
		p.wg.Add(1)
		go p.work()
	}
	return p
}

// Publish enqueues ev without blocking. It returns false when the event was
// dropped because the queue is full or the publisher is closed.
func (p *Publisher) Publish(ev Event) bool {
	if p == nil {
		return false
	}
	if p.closed.Load() {
		p.dropped.Add(1)
		return false
	}
	select {
	case p.ch <- ev:
		p.published.Add(1)
		return true
	default:
		p.dropped.Add(1)
		return false
	}
}

// Stats returns published, dropped, delivered, and failed counts.
func (p *Publisher) Stats() (published, dropped, delivered, failed uint64) {
	if p == nil {
		return
	}
	return p.published.Load(), p.dropped.Load(), p.delivered.Load(), p.failed.Load()
}

// Close stops accepting events, drains the queue, and waits for workers or ctx.
func (p *Publisher) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	p.once.Do(func() {
		p.closed.Store(true)
		close(p.ch)
	})
	done := make(chan struct{})
	go func() {
		p.wg.Wait()
		close(done)
	}()
	if ctx == nil {
		<-done
		return nil
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ErrClosed
	}
}

func (p *Publisher) work() {
	defer p.wg.Done()
	for ev := range p.ch {
		for _, s := range p.sinks {
			if s == nil {
				continue
			}
			if err := s.Ingest(context.Background(), ev); err != nil {
				p.failed.Add(1)
				continue
			}
			p.delivered.Add(1)
		}
	}
}

// MultiSink fans one event out to several sinks, reporting the first error.
func MultiSink(sinks ...Sink) Sink {
	return SinkFunc(func(ctx context.Context, ev Event) error {
		var first error
		for _, s := range sinks {
			if s == nil {
				continue
			}
			if err := s.Ingest(ctx, ev); err != nil && first == nil {
				first = err
			}
		}
		return first
	})
}
