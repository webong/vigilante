package flow

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
)

// Broker is a non-blocking pub/sub flow.Sink for live event streaming (SSE /
// WebSocket consumers, ADR 0003 §5). Slow subscribers drop events from their
// own bounded buffer rather than applying backpressure to the publisher or
// other subscribers.
type Broker struct {
	bufSize int
	mu      sync.RWMutex
	subs    map[*subscriber]struct{}
	dropped atomic.Uint64
}

type subscriber struct {
	ch      chan Event
	minRank int
}

// NewBroker constructs a live flow Broker with per-subscriber channel capacity
// bufSize (default 64).
func NewBroker(bufSize int) *Broker {
	if bufSize <= 0 {
		bufSize = 64
	}
	return &Broker{
		bufSize: bufSize,
		subs:    map[*subscriber]struct{}{},
	}
}

// Ingest implements Sink. It broadcasts ev to all matching subscribers without
// blocking.
func (b *Broker) Ingest(_ context.Context, ev Event) error {
	if b == nil {
		return nil
	}
	rank := severityRank(ev.Severity)
	b.mu.RLock()
	defer b.mu.RUnlock()
	for sub := range b.subs {
		if rank < sub.minRank {
			continue
		}
		select {
		case sub.ch <- ev:
		default:
			b.dropped.Add(1)
		}
	}
	return nil
}

// Subscribe registers a live event stream filtered by minSeverity ("" or "info"
// receives all events). The returned channel is closed when ctx is canceled.
func (b *Broker) Subscribe(ctx context.Context, minSeverity string) <-chan Event {
	ch := make(chan Event, max(1, b.bufSize))
	if b == nil {
		close(ch)
		return ch
	}
	sub := &subscriber{
		ch:      ch,
		minRank: severityRank(minSeverity),
	}
	b.mu.Lock()
	b.subs[sub] = struct{}{}
	b.mu.Unlock()

	go func() {
		<-ctx.Done()
		b.mu.Lock()
		delete(b.subs, sub)
		close(sub.ch)
		b.mu.Unlock()
	}()
	return ch
}

// Dropped returns the total number of events dropped across slow subscribers.
func (b *Broker) Dropped() uint64 {
	if b == nil {
		return 0
	}
	return b.dropped.Load()
}

func severityRank(sev string) int {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}
