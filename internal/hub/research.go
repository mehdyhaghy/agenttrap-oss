package hub

import (
	"context"
	"slices"
	"strings"
	"time"

	"agenttrap/internal/campaign"
	"agenttrap/internal/classify"
	"agenttrap/internal/cluster"
	"agenttrap/internal/events"
)

// Research is the cross-actor analysis: behavioral clusters, correlated
// campaigns and how well each deception works.
type Research struct {
	Since     time.Time           `json:"since"`
	Clusters  []cluster.Cluster   `json:"clusters"`
	Campaigns []campaign.Campaign `json:"campaigns"`
	Deception Deception           `json:"deception"`
}

// Deception measures the adaptive deception layer (see adapters/demogpu
// adaptive.go): which lure wordings get the honey tools called, whether
// depth-gated hints are followed, and which honey surfaces are touched.
type Deception struct {
	Lures []LureStat `json:"lures"`
	// Hints: addresses shown a depth-gated hint, and how many of them went
	// on to the ops agent or the service account afterwards.
	HintsShown    int            `json:"hints_shown"`
	HintsFollowed int            `json:"hints_followed"`
	HoneyScopes   map[string]int `json:"honey_scopes"` // scope -> addresses that requested it
	DecoyAgent    int            `json:"decoy_agent"`  // addresses that messaged the ops agent
	HoneyTools    int            `json:"honey_tools"`  // addresses that called an admin-only honey tool
	Depth         map[int]int    `json:"depth"`        // chain stage -> addresses that reached it
}

// LureStat is one wording of one honey description.
type LureStat struct {
	Family  string  `json:"family"`
	Variant string  `json:"variant"`
	Text    string  `json:"text"`
	Shown   int     `json:"shown"`  // addresses that listed tools with this wording
	Called  int     `json:"called"` // of those, addresses that called the tool
	Rate    float64 `json:"rate"`
}

// Research runs the full analysis for the window.
func (h *Hub) Research(ctx context.Context, since time.Time) (Research, error) {
	a, err := h.analyze(ctx, since)
	if err != nil {
		return Research{}, err
	}
	return Research{Since: since, Clusters: a.clusters, Campaigns: a.campaigns,
		Deception: h.deception(a.actors, a.bySource)}, nil
}

type analysis struct {
	actors    []classify.Actor
	sessions  []classify.Session
	clusters  []cluster.Cluster
	campaigns []campaign.Campaign
	bySource  map[string][]events.Event
}

// correlateResearch adds clusters and campaigns to classified actors.
func correlateResearch(a *analysis) {
	a.clusters = cluster.Build(a.actors, a.bySource)
	cluster.Assign(a.actors, a.clusters)
	a.campaigns = campaign.Correlate(a.actors)
	campaign.Assign(a.actors, a.campaigns)
}

func (h *Hub) deception(actors []classify.Actor, bySource map[string][]events.Event) Deception {
	d := Deception{HoneyScopes: map[string]int{}, Depth: map[int]int{}}
	type lk struct{ family, variant string }
	shown := map[lk]map[string]bool{}
	called := map[lk]map[string]bool{}
	for _, a := range actors {
		if a.Class == classify.Operator {
			continue
		}
		f := a.Features
		for _, sc := range f.HoneyScopes {
			d.HoneyScopes[sc]++
		}
		if f.DecoyAgentCalls > 0 {
			d.DecoyAgent++
		}
		if f.HoneyTools > 0 {
			d.HoneyTools++
		}
		for st := 1; st <= f.MaxStage; st++ {
			d.Depth[st]++
		}
		var hintAt time.Time
		followed := false
		for _, ev := range bySource[a.Source] {
			if ev.Kind == events.KindToolCall {
				if m, ok := ev.Detail["lures"].(map[string]any); ok {
					for fam, v := range m {
						if vs, _ := v.(string); vs != "" {
							k := lk{fam, vs}
							if shown[k] == nil {
								shown[k] = map[string]bool{}
							}
							shown[k][a.Source] = true
						}
					}
				}
				if m, ok := ev.Detail["lures"].(map[string]string); ok { // events not yet round-tripped through JSON
					for fam, vs := range m {
						k := lk{fam, vs}
						if shown[k] == nil {
							shown[k] = map[string]bool{}
						}
						shown[k][a.Source] = true
					}
				}
				tool, _ := ev.Detail["tool"].(string)
				if v, _ := ev.Detail["lure"].(string); v != "" && tool != "" && ev.Detail["rpc_error"] == nil {
					k := lk{tool, v}
					if called[k] == nil {
						called[k] = map[string]bool{}
					}
					called[k][a.Source] = true
				}
				if _, ok := ev.Detail["adapted"].(string); ok && hintAt.IsZero() {
					hintAt = ev.Time
				}
			}
			if !hintAt.IsZero() && ev.Time.After(hintAt) &&
				(ev.Detail["agent"] == "ops" || ev.CanarySlot == "service_account_secret") {
				followed = true
			}
		}
		if !hintAt.IsZero() {
			d.HintsShown++
			if followed {
				d.HintsFollowed++
			}
		}
	}
	texts := map[lk]string{}
	for fam, vs := range h.pack.Lures {
		for _, v := range vs {
			texts[lk{fam, v.ID}] = v.Text
			if shown[lk{fam, v.ID}] == nil {
				shown[lk{fam, v.ID}] = map[string]bool{}
			}
		}
	}
	for k, srcs := range shown {
		st := LureStat{Family: k.family, Variant: k.variant, Text: texts[k], Shown: len(srcs)}
		for s := range called[k] {
			if srcs[s] {
				st.Called++
			}
		}
		if st.Shown > 0 {
			st.Rate = float64(st.Called) / float64(st.Shown)
		}
		d.Lures = append(d.Lures, st)
	}
	slices.SortFunc(d.Lures, func(a, b LureStat) int {
		if c := strings.Compare(a.Family, b.Family); c != 0 {
			return c
		}
		return strings.Compare(a.Variant, b.Variant)
	})
	return d
}
