// Package throttle is a per-key token-bucket rate limiter with a bounded,
// self-cleaning map. The spoke uses it to cap how many events any one source
// can generate, so a repetitive bot flood on any open port cannot fill the
// disk queue, the network or the database.
package throttle

import (
	"math"
	"sync"
	"time"
)

// Bucket rate-limits by string key (e.g. a client address).
type Bucket struct {
	burst  float64
	refill float64 // tokens per second
	max    int

	mu sync.Mutex
	m  map[string]*entry
}

type entry struct {
	tokens float64
	last   time.Time
}

// New builds a bucket allowing burst events, then one more every refill
// interval, tracking at most maxKeys keys. A non-positive burst returns nil,
// which Allow treats as "no limit".
func New(burst int, refill time.Duration, maxKeys int) *Bucket {
	if burst <= 0 {
		return nil
	}
	if maxKeys <= 0 {
		maxKeys = 8192
	}
	rps := 0.0
	if refill > 0 {
		rps = 1 / refill.Seconds()
	}
	return &Bucket{burst: float64(burst), refill: rps, max: maxKeys, m: map[string]*entry{}}
}

// Allow spends a token for key and reports whether it was available.
func (b *Bucket) Allow(key string, now time.Time) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.m[key]
	if e == nil {
		if len(b.m) >= b.max {
			b.evict(now)
		}
		b.m[key] = &entry{tokens: b.burst - 1, last: now}
		return true
	}
	e.tokens = math.Min(b.burst, e.tokens+now.Sub(e.last).Seconds()*b.refill)
	e.last = now
	if e.tokens >= 1 {
		e.tokens--
		return true
	}
	return false
}

// evict drops fully refilled (idle) keys, or the least recently seen if none
// are idle, so the map stays bounded. The caller holds the lock.
func (b *Bucket) evict(now time.Time) {
	var oldest string
	var oldestAt time.Time
	dropped := false
	for k, e := range b.m {
		if math.Min(b.burst, e.tokens+now.Sub(e.last).Seconds()*b.refill) >= b.burst {
			delete(b.m, k)
			dropped = true
		} else if oldestAt.IsZero() || e.last.Before(oldestAt) {
			oldest, oldestAt = k, e.last
		}
	}
	if !dropped && !oldestAt.IsZero() {
		delete(b.m, oldest)
	}
}

// Sweep removes idle keys; call it periodically so memory tracks active keys.
func (b *Bucket) Sweep(now time.Time) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, e := range b.m {
		if math.Min(b.burst, e.tokens+now.Sub(e.last).Seconds()*b.refill) >= b.burst {
			delete(b.m, k)
		}
	}
}
