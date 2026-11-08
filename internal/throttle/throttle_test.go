package throttle

import (
	"testing"
	"time"
)

func TestBucketBurstAndRefill(t *testing.T) {
	b := New(3, time.Second, 100)
	now := time.Now()
	for i := 0; i < 3; i++ {
		if !b.Allow("k", now) {
			t.Fatalf("burst %d denied", i)
		}
	}
	if b.Allow("k", now) {
		t.Fatal("allowed past burst")
	}
	if !b.Allow("k", now.Add(time.Second)) {
		t.Fatal("no token after refill")
	}
	if b.Allow("other", now) != true {
		t.Fatal("independent key denied")
	}
}

func TestBucketNilAllowsAll(t *testing.T) {
	if New(0, time.Second, 10) != nil {
		t.Fatal("burst 0 should disable")
	}
	var b *Bucket
	for i := 0; i < 100; i++ {
		if !b.Allow("k", time.Now()) {
			t.Fatal("nil bucket must allow all")
		}
	}
}

func TestBucketBounded(t *testing.T) {
	b := New(5, time.Second, 4)
	now := time.Now()
	for i := 0; i < 50; i++ {
		b.Allow(string(rune('a'+i%50)), now.Add(time.Duration(i)*time.Hour))
	}
	if len(b.m) > 4 {
		t.Fatalf("map grew past max: %d", len(b.m))
	}
}
