package correlator

import (
	"context"
	"fmt"
	"time"

	"github.com/webong/vigilante/ext/agent"
)

type researchEntry struct {
	snapshot agent.AdvisoryResearch
	updated  time.Time
	done     chan struct{}
}

// researchSnapshot gathers current advisory candidates once per process. The
// first mirrored flow may wait up to five seconds, but primary traffic never
// waits on this pipeline. Concurrent flows share the same lookup.
func (c *Correlator) researchSnapshot(ctx context.Context, proc ProcessEntry) *agent.AdvisoryResearch {
	if proc.Process.PID <= 0 {
		return nil
	}
	key := fmt.Sprintf("%d:%s", proc.Process.PID, proc.Process.StartID)
	now := time.Now()
	c.mu.Lock()
	entry, ok := c.research[key]
	if ok {
		ttl := 15 * time.Minute
		if entry.snapshot.Status == "error" {
			ttl = time.Minute
		}
		if entry.snapshot.Status == "pending" {
			done := entry.done
			c.mu.Unlock()
			select {
			case <-done:
			case <-ctx.Done():
				return &agent.AdvisoryResearch{Status: "pending"}
			}
			c.mu.RLock()
			copy := entry.snapshot
			c.mu.RUnlock()
			return &copy
		}
		if now.Sub(entry.updated) < ttl {
			copy := entry.snapshot
			c.mu.Unlock()
			return &copy
		}
		delete(c.research, key)
	}
	if len(c.research) >= 128 {
		for key, old := range c.research {
			if old.snapshot.Status != "pending" && now.Sub(old.updated) > 15*time.Minute {
				delete(c.research, key)
			}
		}
		if len(c.research) >= 128 {
			c.mu.Unlock()
			return &agent.AdvisoryResearch{Status: "error", Error: "advisory research capacity reached"}
		}
	}
	entry = &researchEntry{snapshot: agent.AdvisoryResearch{Status: "pending"}, updated: now, done: make(chan struct{})}
	c.research[key] = entry
	c.mu.Unlock()

	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	matches, checked, skipped, err := c.advisoryClient.LookupBatch(lookupCtx, proc.Deps.Dependencies)
	cancel()
	result := agent.AdvisoryResearch{CheckedAt: time.Now().UTC(), CheckedCount: checked, SkippedCount: skipped}
	if err != nil {
		result.Status = "error"
		result.Error = err.Error()
	} else {
		result.Status = "ready"
		for _, match := range matches {
			result.Candidates = append(result.Candidates, agent.AdvisoryCandidate{
				Ecosystem:       match.Module.Ecosystem,
				Package:         match.Module.Path,
				Version:         match.Module.Version,
				Advisories:      match.Advisories,
				DetailsComplete: match.DetailsComplete,
			})
		}
	}
	c.mu.Lock()
	entry.snapshot = result
	entry.updated = time.Now()
	close(entry.done)
	c.mu.Unlock()
	return &result
}
