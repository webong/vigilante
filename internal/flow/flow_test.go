package flow

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type collector struct {
	mu     sync.Mutex
	events []Event
	err    error
}

func (c *collector) Ingest(_ context.Context, ev Event) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
	return c.err
}

func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

func TestPublisherDelivers(t *testing.T) {
	c := &collector{}
	p := NewPublisher([]Sink{c}, 8, 1)
	for i := 0; i < 3; i++ {
		if !p.Publish(Event{FlowID: "f", Summary: "s"}) {
			t.Fatal("Publish should succeed with an empty queue")
		}
	}
	if err := p.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if c.count() != 3 {
		t.Fatalf("received %d events, want 3", c.count())
	}
	published, dropped, delivered, failed := p.Stats()
	if published != 3 || dropped != 0 || delivered != 3 || failed != 0 {
		t.Fatalf("stats = %d/%d/%d/%d, want 3/0/3/0", published, dropped, delivered, failed)
	}
}

func TestPublisherDropsInsteadOfBlocking(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	blocking := SinkFunc(func(context.Context, Event) error {
		select {
		case started <- struct{}{}:
		default:
		}
		<-release
		return nil
	})
	p := NewPublisher([]Sink{blocking}, 1, 1)
	// Wait until the worker has taken the first event, then the queue can hold
	// exactly one more.
	p.Publish(Event{FlowID: "first"})
	<-started
	p.Publish(Event{FlowID: "queued"})

	done := make(chan struct{})
	go func() {
		for i := 0; i < 20; i++ {
			p.Publish(Event{FlowID: "overflow"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Publish blocked; it must never block the caller")
	}
	_, dropped, _, _ := p.Stats()
	if dropped == 0 {
		t.Fatal("expected dropped events when the queue is full")
	}
	close(release)
	_ = p.Close(context.Background())
}

func TestPublisherCountsSinkFailures(t *testing.T) {
	c := &collector{err: errors.New("boom")}
	p := NewPublisher([]Sink{c}, 4, 1)
	p.Publish(Event{FlowID: "f"})
	if err := p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, _, delivered, failed := p.Stats()
	if delivered != 0 || failed != 1 {
		t.Fatalf("delivered/failed = %d/%d, want 0/1", delivered, failed)
	}
}

func TestPublishAfterCloseDrops(t *testing.T) {
	p := NewPublisher(nil, 2, 1)
	_ = p.Close(context.Background())
	if p.Publish(Event{}) {
		t.Fatal("Publish after Close must report false")
	}
	_, dropped, _, _ := p.Stats()
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
}

func TestNilPublisherIsSafe(t *testing.T) {
	var p *Publisher
	if p.Publish(Event{}) {
		t.Fatal("nil Publisher should report false")
	}
	if err := p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	published, dropped, delivered, failed := p.Stats()
	if published|dropped|delivered|failed != 0 {
		t.Fatal("nil Publisher stats should be zero")
	}
}

func TestMultiSinkFansOut(t *testing.T) {
	a, b := &collector{}, &collector{}
	p := NewPublisher([]Sink{MultiSink(a, b)}, 4, 1)
	p.Publish(Event{FlowID: "f"})
	if err := p.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.count() != 1 || b.count() != 1 {
		t.Fatalf("fan-out = %d/%d, want 1/1", a.count(), b.count())
	}
}

func TestBrokerStreamsAndDropsWithoutBlocking(t *testing.T) {
	b := NewBroker(2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	highCh := b.Subscribe(ctx, "high")
	allCh := b.Subscribe(ctx, "")

	_ = b.Ingest(ctx, Event{FlowID: "low-1", Severity: "low"})
	_ = b.Ingest(ctx, Event{FlowID: "high-1", Severity: "high"})
	_ = b.Ingest(ctx, Event{FlowID: "crit-1", Severity: "critical"})
	// Overflow allCh (capacity 2) without reading.
	_ = b.Ingest(ctx, Event{FlowID: "info-overflow", Severity: "info"})

	ev1 := <-highCh
	ev2 := <-highCh
	if ev1.FlowID != "high-1" || ev2.FlowID != "crit-1" {
		t.Fatalf("highCh got %q, %q", ev1.FlowID, ev2.FlowID)
	}
	if b.Dropped() == 0 {
		t.Fatal("expected dropped count > 0 on overflowed subscriber")
	}

	cancel()
	// Drain and verify channel closes on ctx cancellation.
	for range allCh {
	}
}
