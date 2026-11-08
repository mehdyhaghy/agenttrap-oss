package hub

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func healthHub(t *testing.T, spokes ...string) *Hub {
	t.Helper()
	st := NewMemStore()
	for _, id := range spokes {
		if err := st.CreateSpoke(context.Background(), id, []byte("seed")); err != nil {
			t.Fatal(err)
		}
	}
	return &Hub{store: st, started: time.Now().Add(-time.Hour)}
}

func statusOf(t *testing.T, h *Hub, id string) (string, IngestHealth) {
	t.Helper()
	hr, err := h.HealthReport(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range hr.Spokes {
		if s.SpokeID == id {
			return s.Status, hr
		}
	}
	t.Fatalf("spoke %s missing from report", id)
	return "", hr
}

func TestIngestHealth(t *testing.T) {
	h := healthHub(t, "s1")
	h.noteShipment("s1", 1, 0, nil, false)
	if st, hr := statusOf(t, h, "s1"); st != "ok" || !hr.OK || len(hr.Problems) != 0 {
		t.Fatalf("healthy spoke reported %s: %v", st, hr.Problems)
	}

	// The 22P05 stall: the same batch refused with a 500 minute after minute.
	stall := errors.New("ERROR: unsupported Unicode escape sequence (SQLSTATE 22P05)")
	for range failAlertAfter - 1 {
		h.noteShipment("s1", 5, 0, stall, false)
	}
	if st, _ := statusOf(t, h, "s1"); st != "ok" {
		t.Fatalf("alerted before %d failures: %s", failAlertAfter, st)
	}
	h.noteShipment("s1", 6, 0, stall, false)
	st, hr := statusOf(t, h, "s1")
	if st != "failing" || hr.OK || !strings.Contains(hr.Problems[0], "22P05") {
		t.Fatalf("stall not reported: %s %v", st, hr.Problems)
	}

	// Recovery clears it.
	h.noteShipment("s1", 0, 0, nil, false)
	if st, _ := statusOf(t, h, "s1"); st != "ok" {
		t.Fatalf("recovery not seen: %s", st)
	}

	h.noteShipment("s1", backlogAlert, 0, nil, false)
	if st, _ := statusOf(t, h, "s1"); st != "backlog" {
		t.Fatalf("backlog not reported: %s", st)
	}

	h.noteShipment("s1", 1, 0, nil, false)
	h.noteShipment("s1", 1, 1, errors.New("bad batch"), true)
	if st, _ := statusOf(t, h, "s1"); st != "rejected" {
		t.Fatalf("rejection not reported: %s", st)
	}
}

func TestIngestHealthSilentSpoke(t *testing.T) {
	h := healthHub(t, "quiet", "revoked")
	_ = h.store.RevokeSpoke(context.Background(), "revoked")
	st, hr := statusOf(t, h, "quiet")
	if st != "silent" || !strings.Contains(hr.Problems[0], "since the hub started") {
		t.Fatalf("never-seen spoke not silent: %s %v", st, hr.Problems)
	}
	if len(hr.Spokes) != 1 {
		t.Fatalf("revoked spoke should be ignored: %+v", hr.Spokes)
	}

	h.noteShipment("quiet", 0, 0, nil, false)
	h.ingest["quiet"].lastContact = time.Now().Add(-silentAfter - time.Minute)
	if st, _ := statusOf(t, h, "quiet"); st != "silent" {
		t.Fatalf("stale spoke not silent: %s", st)
	}

	// Just after a hub restart nothing is judged silent yet.
	fresh := healthHub(t, "new")
	fresh.started = time.Now()
	if st, _ := statusOf(t, fresh, "new"); st != "ok" {
		t.Fatalf("grace period ignored: %s", st)
	}
}
