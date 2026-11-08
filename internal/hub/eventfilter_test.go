package hub

import (
	"testing"
	"time"

	"agenttrap/internal/events"
)

func TestMatchEventRange(t *testing.T) {
	base := time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)
	ev := events.Event{Time: base, Source: "1.2.3.4", Kind: "request", Surface: "aws"}
	f := EventFilter{Since: base.Add(-time.Hour), Until: base.Add(time.Hour)}
	if !matchEvent(ev, f) {
		t.Fatal("event inside [since,until] should match")
	}
	if matchEvent(events.Event{Time: base.Add(2 * time.Hour)}, f) {
		t.Fatal("event after until must not match")
	}
	if matchEvent(events.Event{Time: base.Add(-2 * time.Hour)}, f) {
		t.Fatal("event before since must not match")
	}
	// Zero Until means no upper bound.
	open := EventFilter{Since: base.Add(-time.Hour)}
	if !matchEvent(events.Event{Time: base.Add(72 * time.Hour)}, open) {
		t.Fatal("zero Until should not bound above")
	}
}
