// Package correlate turns canary events into incidents using deterministic,
// explicit chain rules. Behavioral scoring comes later (spec §12).
package correlate

import (
	"slices"
	"time"

	"agenttrap/internal/events"
	"agenttrap/internal/worldpack"
)

// Incident is one actor's progress through a canary chain. Actors are keyed by
// source address in v1.
type Incident struct {
	ID         int64     `json:"id"`
	Source     string    `json:"source"`
	Spokes     []string  `json:"spokes"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Stages     []int     `json:"stages"`
	Score      int       `json:"score"`
	Severity   string    `json:"severity"`
	CrossSpoke bool      `json:"cross_spoke"`
	// OutOfBand is set when a canary was used by a source that was never
	// shown it: the credential travelled from somewhere else.
	OutOfBand bool `json:"out_of_band"`
	// Relayed is set when a per-exposure canary was issued to one address
	// and used from another: the same actor on different infrastructure.
	Relayed bool `json:"relayed"`
}

// Match returns the chain step an event satisfies, if any.
func Match(chain []worldpack.ChainStep, ev events.Event) (worldpack.ChainStep, bool) {
	if ev.CanarySlot == "" {
		return worldpack.ChainStep{}, false
	}
	for _, step := range chain {
		if step.Kind == ev.Kind && step.Slot == ev.CanarySlot {
			return step, true
		}
	}
	return worldpack.ChainStep{}, false
}

// Apply records step for ev on inc and recomputes the score. originSpoke is
// the spoke that issued the canary; exposedToSource reports whether this source
// was ever shown that canary.
func Apply(inc *Incident, chain []worldpack.ChainStep, step worldpack.ChainStep, ev events.Event, originSpoke string, exposedToSource bool) {
	if to, _ := ev.Detail["exposed_to"].(string); to != "" && to != ev.Source && ev.Kind == events.KindCanaryUsed {
		inc.Relayed = true
	}
	if inc.FirstSeen.IsZero() || ev.Time.Before(inc.FirstSeen) {
		inc.FirstSeen = ev.Time
	}
	if ev.Time.After(inc.LastSeen) {
		inc.LastSeen = ev.Time
	}
	if inc.Source == "" {
		inc.Source = ev.Source
	}
	if !slices.Contains(inc.Spokes, ev.SpokeID) {
		inc.Spokes = append(inc.Spokes, ev.SpokeID)
	}
	if !slices.Contains(inc.Stages, step.Stage) {
		inc.Stages = append(inc.Stages, step.Stage)
		slices.Sort(inc.Stages)
	}
	if ev.Kind == events.KindCanaryUsed {
		if originSpoke != "" && originSpoke != ev.SpokeID {
			inc.CrossSpoke = true
		}
		if !exposedToSource {
			inc.OutOfBand = true
		}
	}
	inc.Score = 0
	for _, s := range chain {
		if slices.Contains(inc.Stages, s.Stage) {
			inc.Score += s.Score
		}
	}
	if inc.CrossSpoke || inc.OutOfBand || inc.Relayed {
		inc.Score += 20
	}
	inc.Severity = Severity(inc.Score)
}

// Severity maps a score to a label.
func Severity(score int) string {
	switch {
	case score >= 50:
		return "critical"
	case score >= 25:
		return "high"
	case score >= 15:
		return "medium"
	default:
		return "low"
	}
}
