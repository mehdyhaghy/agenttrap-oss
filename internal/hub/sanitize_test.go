package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"agenttrap/internal/events"
)

// A NUL anywhere in an event once blocked all ingestion (SQLSTATE 22P05).
func nulEvent() events.Event {
	return events.Event{
		ID: events.NewID(), Time: time.Now(), Protocol: "http", Surface: "www", Kind: events.KindRequest,
		Source: "198.51.100.7", UserAgent: "fuzz\x00er", Path: "/a\x00b", Method: "GET",
		Detail: map[string]any{
			"body":    "x\x00y\xff",
			"k\x00ey": []any{"\x00", map[string]any{"deep": "\x00"}},
			"n":       1.5,
		},
	}
}

func TestSanitizeEventRemovesNUL(t *testing.T) {
	ev := nulEvent()
	sanitizeEvent(&ev)
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte(`\u0000`)) || bytes.ContainsRune(b, 0) {
		t.Fatalf("NUL survived: %s", b)
	}
	if ev.UserAgent != "fuzz␀er" || ev.Detail["body"] != "x␀y�" {
		t.Fatalf("NUL not made visible: %q %q", ev.UserAgent, ev.Detail["body"])
	}
	if _, ok := ev.Detail["k␀ey"]; !ok {
		t.Fatalf("detail key not cleaned: %v", ev.Detail)
	}
	if ev.Detail["n"] != 1.5 {
		t.Fatal("non-string value changed")
	}
}

func TestCleanJSONEscapedNUL(t *testing.T) {
	clean := []byte(`{"a":"plain"}`)
	if got := cleanJSON(clean); !bytes.Equal(got, clean) {
		t.Fatalf("clean JSON rewritten: %s", got)
	}
	got := cleanJSON([]byte(`{"a":"x\u0000y","n":12345678901234567890}`))
	if bytes.Contains(got, []byte(`\u0000`)) || !json.Valid(got) {
		t.Fatalf("escaped NUL survived: %s", got)
	}
	if !bytes.Contains(got, []byte(`12345678901234567890`)) {
		t.Fatalf("number precision lost: %s", got)
	}
}

// TestPGIngestNUL runs the real insert path when AGENTTRAP_TEST_PG holds a DSN
// for a throwaway database.
func TestPGIngestNUL(t *testing.T) {
	dsn := os.Getenv("AGENTTRAP_TEST_PG")
	if dsn == "" {
		t.Skip("AGENTTRAP_TEST_PG not set")
	}
	ctx := context.Background()
	st, err := OpenPG(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	spoke := "nul-" + events.NewID()[:8]
	if err := st.CreateSpoke(ctx, spoke, []byte("seed")); err != nil {
		t.Fatal(err)
	}

	raw := nulEvent()
	raw.SpokeID = spoke
	if _, err := st.InsertEvents(ctx, []events.Event{raw}); !isDataError(err) {
		t.Fatalf("unsanitized NUL: want a data error, got %v", err)
	}
	ev := nulEvent()
	ev.SpokeID = spoke
	sanitizeEvent(&ev)
	if _, err := st.InsertEvents(ctx, []events.Event{ev}); err != nil {
		t.Fatalf("sanitized event rejected: %v", err)
	}
}

// Hour buckets come from date_trunc, which follows the session zone; the
// store pins it to UTC even when the database server runs in another zone.
func TestPGSessionUTC(t *testing.T) {
	dsn := os.Getenv("AGENTTRAP_TEST_PG")
	if dsn == "" {
		t.Skip("AGENTTRAP_TEST_PG not set")
	}
	st, err := OpenPG(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var tz string
	var bucket time.Time
	if err := st.pool.QueryRow(context.Background(),
		`SELECT current_setting('TimeZone'), date_trunc('hour', '2026-01-01 10:45:00+00'::timestamptz)`).Scan(&tz, &bucket); err != nil {
		t.Fatal(err)
	}
	if tz != "UTC" || !bucket.Equal(time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)) {
		t.Fatalf("session zone %s, bucket %s", tz, bucket)
	}
}
