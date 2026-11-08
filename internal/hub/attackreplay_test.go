package hub

import (
	"context"
	"os"
	"testing"
	"time"

	"agenttrap/internal/classify"
	"agenttrap/internal/events"
	"agenttrap/internal/geo"
)

func TestReplayStep(t *testing.T) {
	for _, c := range []struct {
		span, want time.Duration
	}{
		{time.Hour, time.Minute},
		{24 * time.Hour, 10 * time.Minute},
		{7 * 24 * time.Hour, time.Hour},
		{30 * 24 * time.Hour, 6 * time.Hour},
		{90 * 24 * time.Hour, 12 * time.Hour},
		{400 * 24 * time.Hour, 24 * time.Hour},
	} {
		if got := replayStep(c.span); got != c.want {
			t.Errorf("span %s: step %s, want %s", c.span, got, c.want)
		}
	}
}

func TestBuildReplay(t *testing.T) {
	locs := map[string]geo.Location{
		"1.2.3.4":  {CountryCode: "GB", Country: "United Kingdom", City: "London", Lat: 51.5, Lon: -0.1},
		"1.2.3.5":  {CountryCode: "GB", Country: "United Kingdom", City: "London", Lat: 51.5, Lon: -0.1},
		"5.6.7.8":  {CountryCode: "DE", Country: "Germany", City: "Frankfurt", Lat: 50.1, Lon: 8.7},
		"10.0.0.5": {CountryCode: "US", City: "Ops", Lat: 1, Lon: 1},
	}
	lookup := func(ip string) (geo.Location, bool) { l, ok := locs[ip]; return l, ok }
	actors := []classify.Actor{
		{Source: "1.2.3.4", Class: classify.Scanner, Score: 20},
		{Source: "1.2.3.5", Class: classify.RogueAgent, Score: 80},
		{Source: "5.6.7.8", Class: classify.AIAgent, Score: 55},
		{Source: "9.9.9.9", Class: classify.Scanner, Score: 10},    // no geo: histogram only
		{Source: "10.0.0.5", Class: classify.Operator, Score: 100}, // never shown
	}
	since := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	step := time.Hour
	at := func(h int) time.Time { return since.Add(time.Duration(h) * step) }
	buckets := []SourceBucket{
		{"1.2.3.4", at(0), 5},
		{"1.2.3.5", at(0), 2},
		{"1.2.3.5", at(2), 3},
		{"5.6.7.8", at(2), 1},
		{"9.9.9.9", at(1), 7},
		{"10.0.0.5", at(1), 50},
		{"1.2.3.4", at(9), 1}, // outside the 4 frames
	}
	out := AttackReplay{Frames: 4}
	buildReplay(&out, since, step, actors, buckets, nil, lookup)

	if want := []int{7, 7, 4, 0}; !equalInts(out.Activity, want) {
		t.Fatalf("activity %v, want %v (operator excluded, unlocated included)", out.Activity, want)
	}
	if len(out.Places) != 2 || out.Mapped != 3 || out.Actors != 4 {
		t.Fatalf("places %d mapped %d actors %d", len(out.Places), out.Mapped, out.Actors)
	}
	if len(out.Cells) != 3 {
		t.Fatalf("cells %+v", out.Cells)
	}
	london0 := out.Cells[0]
	if london0.Frame != 0 || london0.Actors != 2 || london0.Events != 7 || london0.New != 2 ||
		london0.TopClass != classify.RogueAgent || london0.Score != 80 {
		t.Fatalf("London frame 0: %+v", london0)
	}
	// Frame 2: the rogue agent returns to London (not new), Frankfurt appears (new).
	for _, c := range out.Cells[1:] {
		if c.Frame != 2 {
			t.Fatalf("unexpected frame: %+v", c)
		}
		place := out.Places[c.Place].City
		if (place == "London" && c.New != 0) || (place == "Frankfurt" && c.New != 1) {
			t.Fatalf("new-actor marking wrong: %s %+v", place, c)
		}
	}
	if out.Cells[1].Score > out.Cells[2].Score {
		t.Fatal("within a frame the worst place must come last")
	}

	// A class filter keeps only those actors, in the histogram too.
	only := AttackReplay{Frames: 4}
	buildReplay(&only, since, step, actors, buckets, map[string]bool{classify.AIAgent: true}, lookup)
	if !equalInts(only.Activity, []int{0, 0, 1, 0}) || len(only.Cells) != 1 {
		t.Fatalf("class filter: %v %+v", only.Activity, only.Cells)
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestSourceActivityStores(t *testing.T) {
	since := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	evs := []events.Event{
		{ID: events.NewID(), SpokeID: "s1", Time: since.Add(5 * time.Minute), Source: "a", Kind: "request"},
		{ID: events.NewID(), SpokeID: "s1", Time: since.Add(59 * time.Minute), Source: "a", Kind: "request"},
		{ID: events.NewID(), SpokeID: "s1", Time: since.Add(61 * time.Minute), Source: "a", Kind: "request"},
		{ID: events.NewID(), SpokeID: "s1", Time: since.Add(-time.Minute), Source: "a", Kind: "request"},
		{ID: events.NewID(), SpokeID: "s1", Time: since.Add(2 * time.Hour), Source: "a", Kind: "request"}, // == until: excluded
	}
	check := func(t *testing.T, st Store) {
		t.Helper()
		ctx := context.Background()
		if err := st.CreateSpoke(ctx, "s1", []byte("seed")); err != nil {
			t.Fatal(err)
		}
		if _, err := st.InsertEvents(ctx, evs); err != nil {
			t.Fatal(err)
		}
		got, err := st.SourceActivity(ctx, since, since.Add(2*time.Hour), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		counts := map[time.Time]int{}
		for _, b := range got {
			if b.Source == "a" {
				counts[b.Start.UTC()] = b.Events
			}
		}
		if counts[since] != 2 || counts[since.Add(time.Hour)] != 1 || len(counts) != 2 {
			t.Fatalf("buckets %v", counts)
		}
	}
	t.Run("mem", func(t *testing.T) { check(t, NewMemStore()) })
	t.Run("pg", func(t *testing.T) {
		dsn := os.Getenv("AGENTTRAP_TEST_PG")
		if dsn == "" {
			t.Skip("AGENTTRAP_TEST_PG not set")
		}
		st, err := OpenPG(context.Background(), dsn)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		check(t, st)
	})
}
