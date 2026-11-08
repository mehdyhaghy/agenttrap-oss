package digest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIngestAlertLifecycle(t *testing.T) {
	health := `{"ok":true,"problems":[],"spokes":[{"spoke_id":"s1","status":"ok"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(health))
	}))
	defer srv.Close()
	c := &Client{BaseURL: srv.URL}
	state := filepath.Join(t.TempDir(), "ingest-alert.json")
	now := time.Now()
	check := func(at time.Time) *Alert {
		t.Helper()
		a, err := IngestAlert(context.Background(), c, "DemoGPU", state, at)
		if err != nil {
			t.Fatal(err)
		}
		if a != nil {
			if err := a.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		return a
	}

	if a := check(now); a != nil {
		t.Fatalf("healthy hub alerted: %s", a.Subject)
	}
	health = `{"ok":false,"problems":["spoke s1: events are not being stored — 3 shipments refused (22P05)"],"spokes":[{"spoke_id":"s1","status":"failing"}]}`
	a := check(now)
	if a == nil || !strings.Contains(a.Subject, "Ingestion problem — spoke s1: events are not being stored") || !strings.Contains(a.Text, "22P05") {
		t.Fatalf("stall not mailed: %+v", a)
	}
	if a := check(now.Add(5 * time.Minute)); a != nil {
		t.Fatalf("mailed again within the reminder interval: %s", a.Subject)
	}
	if a := check(now.Add(alertRemind)); a == nil || !strings.Contains(a.Subject, "Still failing") {
		t.Fatalf("no reminder: %+v", a)
	}
	health = `{"ok":true,"problems":[],"spokes":[{"spoke_id":"s1","status":"ok"}]}`
	if a := check(now.Add(alertRemind + time.Minute)); a == nil || !strings.Contains(a.Subject, "recovered") {
		t.Fatalf("no recovery mail: %+v", a)
	}
	if a := check(now.Add(alertRemind + 2*time.Minute)); a != nil {
		t.Fatalf("recovery mailed twice: %s", a.Subject)
	}
}

func TestIngestAlertHubDown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Close() // nothing listening
	a, err := IngestAlert(context.Background(), &Client{BaseURL: srv.URL}, "DemoGPU", filepath.Join(t.TempDir(), "s.json"), time.Now())
	if err != nil || a == nil || !strings.Contains(a.Text, "unreachable") {
		t.Fatalf("unreachable hub not alerted: %+v %v", a, err)
	}
}

// An uncommitted alert (the mail failed to send) is offered again.
func TestIngestAlertRetriesUnsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":false,"problems":["spoke s1: no contact"],"spokes":[{"spoke_id":"s1","status":"silent"}]}`))
	}))
	defer srv.Close()
	state := filepath.Join(t.TempDir(), "s.json")
	for range 2 {
		if a, _ := IngestAlert(context.Background(), &Client{BaseURL: srv.URL}, "DemoGPU", state, time.Now()); a == nil {
			t.Fatal("unsent alert not retried")
		}
	}
}
