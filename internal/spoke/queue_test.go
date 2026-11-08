package spoke

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"agenttrap/internal/events"
)

func TestQueueSurvivesHubOutage(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	q, _ := NewQueue(dir, 100, log)
	q.Record(events.Event{ID: events.NewID(), Kind: events.KindRequest})
	if err := q.Flush(); err != nil {
		t.Fatal(err)
	}
	down := func(context.Context, events.Batch) error { return errors.New("hub down") }
	if err := q.Ship(context.Background(), down); err == nil {
		t.Fatal("expected failure")
	}
	if q.Len() != 1 {
		t.Fatalf("batch lost while hub down: %d", q.Len())
	}

	// A restarted spoke finds the batch on disk and ships it with the same ID.
	q2, _ := NewQueue(dir, 100, log)
	var got []events.Batch
	ok := func(_ context.Context, b events.Batch) error { got = append(got, b); return nil }
	if err := q2.Ship(context.Background(), ok); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Events) != 1 || q2.Len() != 0 {
		t.Fatalf("unexpected ship result: %d batches, %d left", len(got), q2.Len())
	}
}

func TestQueueCap(t *testing.T) {
	q, _ := NewQueue(t.TempDir(), 3, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for range 5 {
		q.Record(events.Event{ID: events.NewID()})
		_ = q.Flush()
	}
	if q.Len() != 3 {
		t.Fatalf("cap not enforced: %d", q.Len())
	}
}

// A batch the hub refuses for good must not hold back the batches after it.
func TestQueueRejectedBatchDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	q, _ := NewQueue(dir, 100, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var ids []string
	for range 3 {
		ev := events.Event{ID: events.NewID()}
		ids = append(ids, ev.ID)
		q.Record(ev)
		_ = q.Flush()
	}
	var shipped []string
	send := func(_ context.Context, b events.Batch) error {
		if b.Events[0].ID == ids[0] {
			return fmt.Errorf("%w: hub /v1/events: 422", ErrRejected)
		}
		shipped = append(shipped, b.Events[0].ID)
		return nil
	}
	if err := q.Ship(context.Background(), send); err != nil {
		t.Fatal(err)
	}
	if len(shipped) != 2 || q.Len() != 0 {
		t.Fatalf("later batches blocked: shipped %d, %d left", len(shipped), q.Len())
	}
	kept, _ := os.ReadDir(filepath.Join(dir, rejectedDir))
	if len(kept) != 1 {
		t.Fatalf("rejected batch not kept for inspection: %d", len(kept))
	}
}

// A quiet spoke still tells the hub it is alive, and reports its queue.
func TestQueueHeartbeatAndDepth(t *testing.T) {
	q, _ := NewQueue(t.TempDir(), 100, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var got []events.Batch
	send := func(_ context.Context, b events.Batch) error { got = append(got, b); return nil }
	if err := q.Ship(context.Background(), send); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || len(got[0].Events) != 0 {
		t.Fatalf("no heartbeat from an idle spoke: %+v", got)
	}
	if err := q.Ship(context.Background(), send); err != nil || len(got) != 1 {
		t.Fatalf("heartbeat repeated within the interval: %d", len(got))
	}

	got = nil
	for range 2 {
		q.Record(events.Event{ID: events.NewID()})
		_ = q.Flush()
	}
	if err := q.Ship(context.Background(), send); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].QueueDepth != 2 || got[1].QueueDepth != 1 {
		t.Fatalf("queue depth not reported: %+v", got)
	}
}
