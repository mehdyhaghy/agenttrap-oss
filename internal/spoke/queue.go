package spoke

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"agenttrap/internal/events"
)

// Queue buffers events on disk so nothing is lost while the hub is
// unreachable. Each file is one batch; a file is deleted only after the hub
// acknowledges it, and batch IDs are stable so resends are idempotent.
type Queue struct {
	dir      string
	maxFiles int
	log      *slog.Logger

	mu      sync.Mutex
	pending []events.Event

	lastSent time.Time // last batch (or heartbeat) the hub accepted
}

const flushSize = 200

// ErrRejected marks a batch the hub refused as unacceptable (not a transient
// failure). Retrying it would block every later batch forever.
var ErrRejected = errors.New("batch rejected by hub")

// rejectedDir holds refused batches for inspection, capped at maxRejected.
const (
	rejectedDir = "rejected"
	maxRejected = 500
)

// heartbeatEvery is how long the spoke stays silent before it tells the hub
// it is alive with an empty batch, so a quiet spoke is not mistaken for a
// broken one.
const heartbeatEvery = 5 * time.Minute

func NewQueue(dir string, maxFiles int, log *slog.Logger) (*Queue, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Queue{dir: dir, maxFiles: maxFiles, log: log}, nil
}

// Record adds an event. It never blocks on the network.
func (q *Queue) Record(ev events.Event) {
	q.mu.Lock()
	q.pending = append(q.pending, ev)
	full := len(q.pending) >= flushSize
	q.mu.Unlock()
	if full {
		if err := q.Flush(); err != nil {
			q.log.Error("queue flush failed", "err", err)
		}
	}
}

// Flush writes pending events to a new batch file.
func (q *Queue) Flush() error {
	q.mu.Lock()
	evs := q.pending
	q.pending = nil
	q.mu.Unlock()
	if len(evs) == 0 {
		return nil
	}
	b := events.Batch{ID: events.NewID(), Events: evs}
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	name := strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + b.ID + ".json"
	tmp := filepath.Join(q.dir, "."+name+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(q.dir, name)); err != nil {
		return err
	}
	q.enforceCap()
	return nil
}

func (q *Queue) files() []string {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") && !strings.HasPrefix(e.Name(), ".") {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names) // names start with a nanosecond timestamp
	return names
}

func (q *Queue) enforceCap() {
	names := q.files()
	for len(names) > q.maxFiles {
		q.log.Warn("queue full, dropping oldest batch", "file", names[0])
		_ = os.Remove(filepath.Join(q.dir, names[0]))
		names = names[1:]
	}
}

// reject moves a refused batch out of the shipping queue so later batches
// can flow, keeping it on disk for inspection.
func (q *Queue) reject(name string, cause error) {
	dir := filepath.Join(q.dir, rejectedDir)
	q.log.Error("hub rejected batch; set aside", "file", name, "err", cause)
	if err := os.MkdirAll(dir, 0o700); err != nil || os.Rename(filepath.Join(q.dir, name), filepath.Join(dir, name)) != nil {
		_ = os.Remove(filepath.Join(q.dir, name))
		return
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	for len(names) > maxRejected {
		_ = os.Remove(filepath.Join(dir, names[0]))
		names = names[1:]
	}
}

// Len returns the number of batches waiting on disk.
func (q *Queue) Len() int { return len(q.files()) }

// Ship sends queued batches in order until one fails, then a heartbeat if
// nothing reached the hub for heartbeatEvery.
func (q *Queue) Ship(ctx context.Context, send func(context.Context, events.Batch) error) error {
	names := q.files()
	held := q.held()
	for i, name := range names {
		path := filepath.Join(q.dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var b events.Batch
		if err := json.Unmarshal(data, &b); err != nil {
			q.log.Error("dropping corrupt batch", "file", name, "err", err)
			_ = os.Remove(path)
			continue
		}
		b.QueueDepth, b.HeldOnSpoke = len(names)-i, held
		if err := send(ctx, b); err != nil {
			if errors.Is(err, ErrRejected) {
				q.reject(name, err)
				held++
				continue
			}
			return err
		}
		q.lastSent = time.Now()
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	if time.Since(q.lastSent) >= heartbeatEvery {
		if err := send(ctx, events.Batch{ID: events.NewID(), HeldOnSpoke: held}); err != nil {
			return err
		}
		q.lastSent = time.Now()
	}
	return nil
}

// held counts the batches set aside after the hub refused them.
func (q *Queue) held() int {
	entries, _ := os.ReadDir(filepath.Join(q.dir, rejectedDir))
	return len(entries)
}

// Run flushes and ships on an interval, backing off while the hub is down.
func (q *Queue) Run(ctx context.Context, interval time.Duration, send func(context.Context, events.Batch) error) {
	backoff := interval
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := q.Flush(); err != nil {
				q.log.Error("final flush failed", "err", err)
			}
			return
		case <-timer.C:
		}
		if err := q.Flush(); err != nil {
			q.log.Error("queue flush failed", "err", err)
		}
		if err := q.Ship(ctx, send); err != nil {
			q.log.Warn("shipping to hub failed; will retry", "err", err, "queued_batches", q.Len())
			backoff = min(backoff*2, time.Minute)
		} else {
			backoff = interval
		}
		timer.Reset(backoff)
	}
}
