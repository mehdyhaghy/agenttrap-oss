package hub

import (
	"context"
	"fmt"
	"slices"
	"time"
)

// Ingest health: a stalled pipeline once went unnoticed for 15 hours because
// nothing distinguished "no attackers" from "no events arriving". The hub
// records what it sees of every spoke's shipping, and HealthReport turns that
// into problems the digest, dashboard and alert mail surface.
const (
	failAlertAfter  = 3                // consecutive refused shipments (~3 min of retries)
	backlogAlert    = 30               // batches waiting on a spoke
	silentAfter     = 15 * time.Minute // spokes heartbeat every 5 minutes
	rejectedWindow  = 24 * time.Hour
	maxErrorPreview = 200
)

type spokeIngest struct {
	lastContact, lastOK, firstFailure time.Time
	lastError                         string
	failures                          int // consecutive, since the last success
	rejected                          []time.Time
	queueDepth, heldOnSpoke           int
}

// SpokeIngest is one spoke's shipping state as the hub sees it.
type SpokeIngest struct {
	SpokeID         string     `json:"spoke_id"`
	Status          string     `json:"status"` // ok, failing, backlog, silent, rejected
	LastContact     *time.Time `json:"last_contact,omitempty"`
	LastOK          *time.Time `json:"last_ok,omitempty"`
	FailingSince    *time.Time `json:"failing_since,omitempty"`
	LastError       string     `json:"last_error,omitempty"`
	Failures        int        `json:"failures"`
	QueueDepth      int        `json:"queue_depth"`
	HeldOnSpoke     int        `json:"held_on_spoke"`
	RejectedLast24h int        `json:"rejected_24h"`
}

// IngestHealth is the answer to "are events reaching the hub?".
type IngestHealth struct {
	OK        bool          `json:"ok"`
	Problems  []string      `json:"problems"`
	Spokes    []SpokeIngest `json:"spokes"`
	CheckedAt time.Time     `json:"checked_at"`
}

func (h *Hub) ingestState(spokeID string) *spokeIngest {
	if h.ingest == nil {
		h.ingest = map[string]*spokeIngest{}
	}
	s := h.ingest[spokeID]
	if s == nil {
		s = &spokeIngest{}
		h.ingest[spokeID] = s
	}
	return s
}

// noteShipment records one /v1/events call. rejected marks a batch refused
// for good (the spoke sets it aside); err is nil on success.
func (h *Hub) noteShipment(spokeID string, depth, held int, err error, rejected bool) {
	now := time.Now()
	h.ingMu.Lock()
	defer h.ingMu.Unlock()
	s := h.ingestState(spokeID)
	s.lastContact = now
	s.queueDepth, s.heldOnSpoke = depth, held
	switch {
	case err == nil:
		s.lastOK, s.failures, s.firstFailure, s.lastError = now, 0, time.Time{}, ""
	case rejected:
		// The spoke moves on, so this is not a stall, but every one is an
		// ingest bug worth reading.
		s.rejected = append(s.rejected, now)
		s.lastError = clipErr(err)
	default:
		if s.failures == 0 {
			s.firstFailure = now
		}
		s.failures++
		s.lastError = clipErr(err)
	}
}

func clipErr(err error) string {
	msg := err.Error()
	if len(msg) > maxErrorPreview {
		msg = truncate(msg, maxErrorPreview) + "…"
	}
	return msg
}

// HealthReport evaluates every active spoke's shipping.
func (h *Hub) HealthReport(ctx context.Context) (IngestHealth, error) {
	spokes, err := h.store.ListSpokes(ctx)
	if err != nil {
		return IngestHealth{}, err
	}
	now := time.Now()
	out := IngestHealth{OK: true, Problems: []string{}, Spokes: []SpokeIngest{}, CheckedAt: now.UTC()}
	h.ingMu.Lock()
	defer h.ingMu.Unlock()
	for _, sp := range spokes {
		if sp.Revoked {
			continue
		}
		s := h.ingestState(sp.ID)
		s.rejected = slices.DeleteFunc(s.rejected, func(t time.Time) bool { return now.Sub(t) > rejectedWindow })
		r := SpokeIngest{SpokeID: sp.ID, Status: "ok", LastError: s.lastError, Failures: s.failures,
			QueueDepth: s.queueDepth, HeldOnSpoke: s.heldOnSpoke, RejectedLast24h: len(s.rejected)}
		r.LastContact, r.LastOK, r.FailingSince = timePtr(s.lastContact), timePtr(s.lastOK), timePtr(s.firstFailure)

		// Before any contact this run, the spoke's own last-seen stamp
		// (every authenticated call) stands in, so a hub restart does not
		// hide a spoke that went quiet earlier.
		contact := s.lastContact
		if contact.IsZero() && sp.LastSeen != nil {
			contact = *sp.LastSeen
		}
		var problem string
		switch {
		case s.failures >= failAlertAfter:
			r.Status = "failing"
			problem = fmt.Sprintf("spoke %s: events are not being stored — %d shipments refused since %s UTC (%s)",
				sp.ID, s.failures, s.firstFailure.UTC().Format("Jan 2 15:04"), s.lastError)
		case now.Sub(h.started) > silentAfter && now.Sub(contact) > silentAfter:
			r.Status = "silent"
			since := "since the hub started"
			if !contact.IsZero() {
				since = "since " + contact.UTC().Format("Jan 2 15:04") + " UTC"
			}
			problem = fmt.Sprintf("spoke %s: no contact %s — spoke down or cannot reach the hub", sp.ID, since)
		case s.queueDepth >= backlogAlert:
			r.Status = "backlog"
			problem = fmt.Sprintf("spoke %s: %d event batches waiting to be shipped", sp.ID, s.queueDepth)
		case len(s.rejected) > 0:
			r.Status = "rejected"
			problem = fmt.Sprintf("spoke %s: %d batch(es) refused as unstorable in the last 24h and set aside on the spoke (%s)",
				sp.ID, len(s.rejected), s.lastError)
		}
		if problem != "" {
			out.OK = false
			out.Problems = append(out.Problems, problem)
		}
		out.Spokes = append(out.Spokes, r)
	}
	return out, nil
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}
