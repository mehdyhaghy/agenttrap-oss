package relay

import (
	"math"
	"net/netip"
	"sync"
	"time"
)

// limiter throttles connections per source address with a token bucket, so a
// brute-force flood on a decoy port cannot tie up the backend or fill the
// event store. Every relayed decoy (SSH, and later the database and cache
// facades) sits behind a relay, so this is the one place that protects them
// all, at the cheapest point: a dropped connection never reaches the decoy,
// costs no handshake and records no event.
//
// The first burst of connections from a source still passes through, so the
// decoy captures the useful intelligence (client version, tried usernames and
// passwords, key fingerprints); only the sustained flood beyond that is shed.
type limiter struct {
	burst  float64 // bucket capacity
	refill float64 // tokens added per second
	max    int     // most sources tracked at once
	exempt []netip.Prefix

	mu      sync.Mutex
	buckets map[netip.Addr]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// newLimiter builds a limiter. A non-positive burst disables it (allow all).
func newLimiter(burst int, refill time.Duration, maxSources int, exempt []netip.Prefix) *limiter {
	if burst <= 0 {
		return nil
	}
	if maxSources <= 0 {
		maxSources = 4096
	}
	rps := 0.0
	if refill > 0 {
		rps = 1 / refill.Seconds()
	}
	return &limiter{burst: float64(burst), refill: rps, max: maxSources, exempt: exempt, buckets: map[netip.Addr]*bucket{}}
}

// allow reports whether a connection from ip may proceed, spending one token.
func (l *limiter) allow(ip netip.Addr, now time.Time) bool {
	if l == nil {
		return true
	}
	ip = ip.Unmap()
	for _, p := range l.exempt {
		if p.Contains(ip) {
			return true
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[ip]
	if b == nil {
		if len(l.buckets) >= l.max {
			l.evict(now)
		}
		l.buckets[ip] = &bucket{tokens: l.burst - 1, last: now}
		return true
	}
	b.tokens = math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.refill)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// evict drops fully refilled (idle) buckets; if none are idle it drops the
// least recently seen, so the map stays bounded under many distinct sources.
// The caller holds the lock.
func (l *limiter) evict(now time.Time) {
	var oldest netip.Addr
	var oldestAt time.Time
	dropped := false
	for ip, b := range l.buckets {
		full := math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.refill)
		if full >= l.burst {
			delete(l.buckets, ip)
			dropped = true
		} else if oldestAt.IsZero() || b.last.Before(oldestAt) {
			oldest, oldestAt = ip, b.last
		}
	}
	if !dropped && !oldestAt.IsZero() {
		delete(l.buckets, oldest)
	}
}

// sweep periodically removes idle buckets so memory tracks active sources, not
// every address ever seen.
func (l *limiter) sweep(now time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for ip, b := range l.buckets {
		if math.Min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.refill) >= l.burst {
			delete(l.buckets, ip)
		}
	}
}
