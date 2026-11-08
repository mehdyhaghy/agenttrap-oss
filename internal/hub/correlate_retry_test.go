package hub

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"agenttrap/internal/correlate"
	"agenttrap/internal/events"
	"agenttrap/internal/pki"
	"agenttrap/personas"
)

// flakyStore fails the first incident save, as a database blip would.
type flakyStore struct {
	Store
	failures int
}

func (s *flakyStore) SaveIncident(ctx context.Context, inc *correlate.Incident) error {
	if s.failures > 0 {
		s.failures--
		return errors.New("connection reset")
	}
	return s.Store.SaveIncident(ctx, inc)
}

// Events are stored before they are correlated. If correlation fails, the
// spoke resends the batch; the resend inserts nothing new, and those events
// must still open their incident.
func TestIngestRetryCorrelatesStoredEvents(t *testing.T) {
	dir := t.TempDir()
	if err := pki.Init(dir); err != nil {
		t.Fatal(err)
	}
	issuer, err := pki.LoadIssuer(dir)
	if err != nil {
		t.Fatal(err)
	}
	st := &flakyStore{Store: NewMemStore(), failures: 1}
	h, err := New(Config{ServerNames: []string{"localhost"}, AdminToken: strings.Repeat("a", 32)},
		st, issuer, personas.DemoGPU, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := st.CreateSpoke(ctx, "s1", []byte("seed")); err != nil {
		t.Fatal(err)
	}
	step := h.pack.Chain[0]
	batch := []events.Event{{ID: events.NewID(), Time: time.Now(), Protocol: "http", Surface: "api",
		Kind: step.Kind, CanarySlot: step.Slot, Source: "203.0.113.9"}}

	if _, err := h.Ingest(ctx, "s1", slices.Clone(batch)); err == nil {
		t.Fatal("expected the first attempt to fail")
	}
	if inc, _ := st.IncidentBySource(ctx, "203.0.113.9"); inc != nil {
		t.Fatalf("incident saved despite the failure: %+v", inc)
	}
	if _, err := h.Ingest(ctx, "s1", slices.Clone(batch)); err != nil {
		t.Fatalf("resend failed: %v", err)
	}
	inc, err := st.IncidentBySource(ctx, "203.0.113.9")
	if err != nil || inc == nil || !slices.Contains(inc.Stages, step.Stage) {
		t.Fatalf("resent batch never correlated: %+v %v", inc, err)
	}
}
