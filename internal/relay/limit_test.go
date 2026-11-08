package relay

import (
	"net/netip"
	"testing"
	"time"
)

func TestLimiterBurstThenRefill(t *testing.T) {
	l := newLimiter(3, time.Minute, 100, nil)
	ip := netip.MustParseAddr("203.0.113.7")
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !l.allow(ip, now) {
			t.Fatalf("burst connection %d denied", i)
		}
	}
	if l.allow(ip, now) {
		t.Fatal("connection past burst was allowed")
	}
	// One token comes back after the refill interval.
	if !l.allow(ip, now.Add(time.Minute)) {
		t.Fatal("no token after refill")
	}
	if l.allow(ip, now.Add(time.Minute)) {
		t.Fatal("second token before its refill")
	}
	// A different source has its own bucket.
	if !l.allow(netip.MustParseAddr("203.0.113.8"), now) {
		t.Fatal("independent source denied")
	}
}

func TestLimiterDisabledAndExempt(t *testing.T) {
	if newLimiter(0, time.Minute, 100, nil) != nil {
		t.Fatal("burst 0 should disable the limiter")
	}
	var nilLim *limiter
	if !nilLim.allow(netip.MustParseAddr("203.0.113.9"), time.Now()) {
		t.Fatal("nil limiter must allow all")
	}
	l := newLimiter(1, time.Hour, 100, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	op := netip.MustParseAddr("10.1.2.3")
	for i := 0; i < 5; i++ {
		if !l.allow(op, time.Now()) {
			t.Fatal("exempt source was throttled")
		}
	}
}

func TestLimiterEvictsWhenFull(t *testing.T) {
	l := newLimiter(5, time.Minute, 4, nil)
	now := time.Now()
	// Fill with idle sources (one token spent, then let them refill).
	for i := 0; i < 4; i++ {
		l.allow(netip.AddrFrom4([4]byte{198, 51, 100, byte(i)}), now)
	}
	// Later, all four have refilled to full; a fifth source triggers eviction.
	l.allow(netip.MustParseAddr("198.51.100.200"), now.Add(time.Hour))
	if len(l.buckets) > 4 {
		t.Fatalf("map grew past max: %d", len(l.buckets))
	}
}
