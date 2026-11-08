package spoke

import (
	"testing"
	"time"

	"agenttrap/internal/events"
)

type capture struct{ evs []events.Event }

func (c *capture) Record(ev events.Event) { c.evs = append(c.evs, ev) }

func (c *capture) count(kind string) int {
	n := 0
	for _, e := range c.evs {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

func TestLimitRecorderThrottlesBulkTraffic(t *testing.T) {
	cap := &capture{}
	r := newLimitRecorder(cap, 10, time.Hour) // 10 then ~none within the test
	r.every = 50
	for i := 0; i < 1000; i++ {
		r.Record(events.Event{Kind: events.KindRequest, Source: "1.2.3.4", Path: "/wp-login.php"})
	}
	// The 10 burst requests get through; the rest are suppressed and rolled up.
	if got := cap.count(events.KindRequest); got != 10 {
		t.Fatalf("recorded %d bulk requests, want 10", got)
	}
	if got := cap.count(events.KindThrottled); got == 0 {
		t.Fatal("no rollup event emitted for the flood")
	}
	// The last rollup carries a large suppressed count.
	var last events.Event
	for _, e := range cap.evs {
		if e.Kind == events.KindThrottled {
			last = e
		}
	}
	if n, _ := last.Detail["suppressed"].(int); n < 900 {
		t.Fatalf("rollup suppressed count too low: %v", last.Detail["suppressed"])
	}
}

func TestLimitRecorderNeverDropsHighSignal(t *testing.T) {
	cap := &capture{}
	r := newLimitRecorder(cap, 5, time.Hour)
	// Exhaust the burst with plain traffic.
	for i := 0; i < 20; i++ {
		r.Record(events.Event{Kind: events.KindRequest, Source: "9.9.9.9"})
	}
	// High-signal events must always be recorded, even past the budget.
	r.Record(events.Event{Kind: events.KindCanaryUsed, Source: "9.9.9.9", CanarySlot: "provider_key_vllm"})
	r.Record(events.Event{Kind: events.KindAuth, Source: "9.9.9.9", CredentialSHA256: "deadbeef"})
	r.Record(events.Event{Kind: events.KindCanaryExposed, Source: "9.9.9.9", CanarySlot: "redis_session_token"})
	if got := cap.count(events.KindCanaryUsed); got != 1 {
		t.Fatalf("canary_used dropped: %d", got)
	}
	if got := cap.count(events.KindAuth); got != 1 {
		t.Fatalf("auth dropped: %d", got)
	}
	if got := cap.count(events.KindCanaryExposed); got != 1 {
		t.Fatalf("canary_exposed dropped: %d", got)
	}
}

func TestLimitRecorderPerSourceBudget(t *testing.T) {
	cap := &capture{}
	r := newLimitRecorder(cap, 5, time.Hour)
	for i := 0; i < 100; i++ {
		r.Record(events.Event{Kind: events.KindRequest, Source: "flood"})
	}
	// A different source keeps its own full budget.
	for i := 0; i < 5; i++ {
		r.Record(events.Event{Kind: events.KindRequest, Source: "quiet"})
	}
	quiet := 0
	for _, e := range cap.evs {
		if e.Source == "quiet" && e.Kind == events.KindRequest {
			quiet++
		}
	}
	if quiet != 5 {
		t.Fatalf("quiet source throttled by another source's flood: %d/5", quiet)
	}
}
