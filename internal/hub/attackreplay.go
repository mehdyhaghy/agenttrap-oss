package hub

import (
	"context"
	"slices"
	"time"

	"agenttrap/internal/classify"
	"agenttrap/internal/geo"
)

// The attack-map replay plays a range back frame by frame. One request returns
// the whole range already bucketed, so playback, seeking and speed changes run
// in the browser without further round trips.

// replayFrames is the frame count the step size aims for: enough to see a
// campaign unfold, few enough to play through in about a minute.
const replayFrames = 180

var replaySteps = []time.Duration{
	time.Minute, 2 * time.Minute, 5 * time.Minute, 10 * time.Minute, 15 * time.Minute, 30 * time.Minute,
	time.Hour, 2 * time.Hour, 3 * time.Hour, 6 * time.Hour, 12 * time.Hour, 24 * time.Hour,
}

// replayStep picks the smallest round step that keeps the range within
// replayFrames frames.
func replayStep(span time.Duration) time.Duration {
	for _, s := range replaySteps {
		if span/s <= replayFrames {
			return s
		}
	}
	return replaySteps[len(replaySteps)-1]
}

// ReplayPlace is a location that shows activity at some point in the replay.
type ReplayPlace struct {
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	City        string  `json:"city,omitempty"`
	Country     string  `json:"country,omitempty"`
	CountryCode string  `json:"country_code,omitempty"`
}

// ReplayCell is one place's activity in one frame.
type ReplayCell struct {
	Frame    int      `json:"f"`
	Place    int      `json:"p"`             // index into places
	Actors   int      `json:"a"`             // distinct actors active here in this frame
	Events   int      `json:"e"`             // their events in this frame
	New      int      `json:"n"`             // actors seen for the first time in the range
	Score    int      `json:"s"`             // highest agent-likeness score among them
	TopClass string   `json:"c"`             // class of that actor
	Sources  []string `json:"src,omitempty"` // a few of them, for the tooltip
}

// AttackReplay is the attack map over time.
type AttackReplay struct {
	Enabled     bool          `json:"enabled"`
	Attribution string        `json:"attribution"`
	Since       time.Time     `json:"since"`
	Until       time.Time     `json:"until"`
	StepSeconds int           `json:"step_seconds"`
	Frames      int           `json:"frames"`
	Activity    []int         `json:"activity"` // events per frame, located or not: the histogram under the map
	Places      []ReplayPlace `json:"places"`
	Cells       []ReplayCell  `json:"cells"` // ordered by frame
	Actors      int           `json:"actors"`
	Mapped      int           `json:"mapped"`
}

// AttackReplay buckets non-operator activity in [since, until) into frames.
func (h *Hub) AttackReplay(ctx context.Context, since, until time.Time, classes map[string]bool) (AttackReplay, error) {
	out := AttackReplay{Attribution: geo.AttributionText, Since: since.UTC(), Until: until.UTC(),
		Activity: []int{}, Places: []ReplayPlace{}, Cells: []ReplayCell{}}
	if h.geo == nil {
		return out, nil
	}
	out.Enabled = true
	step := replayStep(until.Sub(since))
	// Frames start on round boundaries (whole hours, ten minutes, ...), so
	// their labels read as clock times rather than "now minus a week".
	since = since.Truncate(step)
	out.Since = since.UTC()
	out.StepSeconds = int(step / time.Second)
	out.Frames = int((until.Sub(since) + step - 1) / step)
	actors, _, err := h.Analyze(ctx, since)
	if err != nil {
		return out, err
	}
	buckets, err := h.store.SourceActivity(ctx, since, until, step)
	if err != nil {
		return out, err
	}
	buildReplay(&out, since, step, actors, buckets, classes, h.geo.Lookup)
	return out, nil
}

func buildReplay(out *AttackReplay, since time.Time, step time.Duration, actors []classify.Actor,
	buckets []SourceBucket, classes map[string]bool, lookup func(string) (geo.Location, bool)) {
	out.Activity = make([]int, out.Frames)
	byActor := make(map[string]*classify.Actor, len(actors))
	for i := range actors {
		a := &actors[i]
		if a.Class == classify.Operator || (len(classes) > 0 && !classes[a.Class]) {
			continue
		}
		byActor[a.Source] = a
	}
	// Every located source's place, and the frame it first appears in.
	placeOf := map[string]int{}
	placeIdx := map[string]int{}
	first := map[string]int{}
	type cellKey struct{ frame, place int }
	cells := map[cellKey]*ReplayCell{}
	for _, b := range buckets {
		a := byActor[b.Source]
		frame := int(b.Start.Sub(since) / step)
		if a == nil || frame < 0 || frame >= out.Frames {
			continue
		}
		out.Activity[frame] += b.Events
		p, seen := placeOf[b.Source]
		if !seen {
			p = -1
			if loc, ok := lookup(b.Source); ok {
				key := loc.CountryCode + "|" + loc.City
				idx, known := placeIdx[key]
				if !known {
					idx = len(out.Places)
					placeIdx[key] = idx
					out.Places = append(out.Places, ReplayPlace{Lat: loc.Lat, Lon: loc.Lon, City: loc.City,
						Country: loc.Country, CountryCode: loc.CountryCode})
				}
				p = idx
			}
			placeOf[b.Source] = p
		}
		if p < 0 {
			continue
		}
		if f, ok := first[b.Source]; !ok || frame < f {
			first[b.Source] = frame
		}
		c := cells[cellKey{frame, p}]
		if c == nil {
			c = &ReplayCell{Frame: frame, Place: p}
			cells[cellKey{frame, p}] = c
		}
		c.Actors++
		c.Events += b.Events
		if a.Score >= c.Score || c.TopClass == "" { // the worst actor defines the colour
			c.Score, c.TopClass = a.Score, a.Class
		}
		if len(c.Sources) < 4 {
			c.Sources = append(c.Sources, b.Source)
		}
	}
	for src, f := range first {
		cells[cellKey{f, placeOf[src]}].New++
	}
	out.Actors = len(byActor)
	out.Mapped = len(first)
	for _, c := range cells {
		out.Cells = append(out.Cells, *c)
	}
	// By frame; within a frame the worst last, so it draws on top.
	slices.SortFunc(out.Cells, func(x, y ReplayCell) int {
		if x.Frame != y.Frame {
			return x.Frame - y.Frame
		}
		if x.Score != y.Score {
			return x.Score - y.Score
		}
		return x.Place - y.Place
	})
}
