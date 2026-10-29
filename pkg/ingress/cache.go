package ingress

import (
	"net"
	"strings"
	"sync"
	"time"
)

// decisionCache is a bounded, TTL-limited memo of decisions. It exists so a
// proxy in front of the sidecar can avoid a decision round trip on hot,
// repetitive traffic (health checks, the same asset requested by the same
// client) without ever caching a verdict that depended on a header.
//
// Only decisions the policy engine marks cacheable are stored; see
// policy.Engine.DecisionCacheable.
type decisionCache struct {
	mu    sync.Mutex
	items map[string]cacheItem
	max   int
	ttl   time.Duration
	epoch int64
}

type cacheItem struct {
	decision Decision
	expires  time.Time
}

func newDecisionCache(ttl time.Duration, max int) *decisionCache {
	if ttl <= 0 {
		return nil
	}
	if max <= 0 {
		max = 4096
	}
	return &decisionCache{items: make(map[string]cacheItem, 64), max: max, ttl: ttl}
}

// syncEpoch drops every cached decision when the policy epoch changes (a
// successful reload). It is a no-op on an unchanged epoch.
func (c *decisionCache) syncEpoch(epoch int64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.epoch != epoch {
		c.epoch = epoch
		clear(c.items)
	}
	c.mu.Unlock()
}

func (c *decisionCache) get(key string) (Decision, bool) {
	if c == nil {
		return Decision{}, false
	}
	c.mu.Lock()
	item, ok := c.items[key]
	c.mu.Unlock()
	if !ok {
		return Decision{}, false
	}
	if time.Now().After(item.expires) {
		return Decision{}, false
	}
	return item.decision, true
}

func (c *decisionCache) put(key string, d Decision) {
	if c == nil {
		return
	}
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) >= c.max {
		for k, item := range c.items {
			if now.After(item.expires) {
				delete(c.items, k)
			}
		}
		// Still full and nothing expired: drop arbitrary entries. A cache miss
		// is always safe, so eviction policy only affects cost, not correctness.
		for k := range c.items {
			if len(c.items) < c.max {
				break
			}
			delete(c.items, k)
		}
	}
	c.items[key] = cacheItem{decision: d, expires: now.Add(c.ttl)}
}

func (c *decisionCache) len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// cacheKey is the coarse identity of a request. It includes every dimension a
// policy rule may inspect except headers, which is why a header-sensitive
// engine refuses to cache at all.
func cacheKey(m RequestMeta) string {
	var b strings.Builder
	b.Grow(len(m.Method) + len(m.Host) + len(m.Path) + len(m.Query) + 24)
	b.WriteString(m.Method)
	b.WriteByte(0)
	b.WriteString(strings.ToLower(m.Host))
	b.WriteByte(0)
	b.WriteString(m.Path)
	b.WriteByte(0)
	b.WriteString(m.Query)
	b.WriteByte(0)
	b.WriteString(clientKey(m.ClientIP()))
	return b.String()
}

// clientKey is the full client address. It deliberately does not collapse to a
// prefix: a /24 key would let an allow cached for one address mask a narrower
// deny_cidr or rule cidr for its neighbour.
func clientKey(ip net.IP) string {
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}
