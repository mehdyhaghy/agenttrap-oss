package spoke

import (
	"context"
	"sync"
	"time"

	"agenttrap/internal/events"
	"agenttrap/internal/throttle"
)

// recorder is what the facade records events into (the disk queue implements it).
type recorder interface {
	Record(events.Event)
}

// limitRecorder caps how many events a single source can generate, so a
// repetitive bot flood on any open port cannot fill the disk queue, the
// network to the hub or the database. High-signal events (a canary shown or
// used, a credential, a login, a form) are never dropped; only bulk traffic
// beyond a per-source budget is. Suppressed events are counted and rolled up
// into one periodic "throttled" event, so the flood is still visible as a
// single row instead of thousands.
type limitRecorder struct {
	inner  recorder
	bucket *throttle.Bucket
	every  int // emit a rollup every N suppressed events per source

	mu         sync.Mutex
	suppressed map[string]int
}

func newLimitRecorder(inner recorder, burst int, refill time.Duration) *limitRecorder {
	return &limitRecorder{
		inner:      inner,
		bucket:     throttle.New(burst, refill, 16384),
		every:      500,
		suppressed: map[string]int{},
	}
}

func (r *limitRecorder) Record(ev events.Event) {
	if highSignal(ev) || r.bucket.Allow(ev.Source, time.Now()) {
		r.flush(ev.Source)
		r.inner.Record(ev)
		return
	}
	r.mu.Lock()
	r.suppressed[ev.Source]++
	n := r.suppressed[ev.Source]
	if len(r.suppressed) > 16384 {
		// Bound memory: forget the smallest counters under extreme fan-out.
		for k, c := range r.suppressed {
			if c <= 1 {
				delete(r.suppressed, k)
			}
		}
	}
	r.mu.Unlock()
	if n%r.every == 0 {
		r.inner.Record(rollup(ev, n))
	}
}

// flush emits a final rollup for a source that is being recorded again, so the
// tail of a burst is not lost, and clears its counter.
func (r *limitRecorder) flush(source string) {
	r.mu.Lock()
	n := r.suppressed[source]
	if n%r.every != 0 && n > 0 {
		delete(r.suppressed, source)
		r.mu.Unlock()
		return // counted but below the rollup step; the periodic rollup covers it
	}
	delete(r.suppressed, source)
	r.mu.Unlock()
}

// highSignal marks events that must always be recorded regardless of volume.
func highSignal(ev events.Event) bool {
	if ev.CanarySlot != "" || ev.CredentialSHA256 != "" {
		return true
	}
	switch ev.Kind {
	case events.KindAuth, events.KindCanaryUsed, events.KindCanaryExposed, events.KindForm:
		return true
	}
	return false
}

// rollup is a single event standing in for suppressed bulk traffic from a source.
func rollup(ev events.Event, n int) events.Event {
	return events.Event{
		ID:       events.NewID(),
		Time:     time.Now().UTC(),
		Protocol: ev.Protocol,
		Surface:  ev.Surface,
		Kind:     events.KindThrottled,
		Source:   ev.Source,
		Detail:   map[string]any{"op": "throttled", "suppressed": n, "last_path": ev.Path, "last_kind": ev.Kind},
	}
}

// sweepBucket drops idle sources from the bucket on an interval.
func sweepBucket(ctx context.Context, b *throttle.Bucket, refill time.Duration) {
	every := refill * 8
	if every < time.Minute {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			b.Sweep(now)
		}
	}
}
