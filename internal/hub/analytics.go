package hub

import (
	"cmp"
	"context"
	"encoding/json"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	"agenttrap/internal/events"
	"agenttrap/internal/worldpack"
)

// Overview is the dashboard summary for a time window.
type Overview struct {
	Since           time.Time      `json:"since"`
	Totals          Totals         `json:"totals"`
	Severity        map[string]int `json:"severity"` // incidents active in the window
	Funnel          []FunnelStage  `json:"funnel"`
	Timeline        []TimeBucket   `json:"timeline"`
	TopSources      []SourceStat   `json:"top_sources"`
	TopFingerprints []Fingerprint  `json:"top_fingerprints"`
	TopUserAgents   []UserAgent    `json:"top_user_agents"`
	TopPaths        []PathStat     `json:"top_paths"`
	// Exploits counts attacks on known vulnerabilities that honeypot modules
	// recognized, per module and attack, most attempts first.
	Exploits []ExploitStat `json:"exploits"`
}

// ExploitStat is one module's attack in the window: payloads sent
// (stage "exploit"), probes for a vulnerable target, and how many sources.
type ExploitStat struct {
	Module   string    `json:"module"`
	Attack   string    `json:"attack"`
	CVEs     []string  `json:"cves"`
	Attempts int       `json:"attempts"`
	Probes   int       `json:"probes"`
	Sources  int       `json:"sources"`
	LastSeen time.Time `json:"last_seen"`
}

type Totals struct {
	Events       int `json:"events"`
	Requests     int `json:"requests"`
	Sources      int `json:"sources"`
	TLSHellos    int `json:"tls_hellos"`
	Fingerprints int `json:"fingerprints"`
	CanaryUses   int `json:"canary_uses"`
}

type FunnelStage struct {
	Stage   int    `json:"stage"`
	Name    string `json:"name"`
	Sources int    `json:"sources"`
}

type TimeBucket struct {
	Time     time.Time `json:"time"`
	Requests int       `json:"requests"`
	Sources  int       `json:"sources"`
}

type SourceStat struct {
	Source    string    `json:"source"`
	Events    int       `json:"events"`
	LastSeen  time.Time `json:"last_seen"`
	UserAgent string    `json:"user_agent"`
}

type Fingerprint struct {
	JA4       string `json:"ja4"`
	Sources   int    `json:"sources"`
	Requests  int    `json:"requests"`
	UserAgent string `json:"user_agent"`
}

type UserAgent struct {
	UserAgent string `json:"user_agent"`
	Requests  int    `json:"requests"`
	Sources   int    `json:"sources"`
}

type PathStat struct {
	Surface  string `json:"surface"`
	Path     string `json:"path"`
	Requests int    `json:"requests"`
	Sources  int    `json:"sources"`
}

const topN = 10

// Overview computes the summary in memory. PGStore does the same in SQL.
func (m *MemStore) Overview(_ context.Context, since time.Time, chain []worldpack.ChainStep, exclude []netip.Prefix) (Overview, error) {
	o := Overview{Since: since, Severity: map[string]int{}}
	m.mu.Lock()
	evs := slices.DeleteFunc(slices.Clone(m.events), func(ev events.Event) bool { return InPrefixes(ev.Source, exclude) })
	for _, inc := range m.incidents {
		if !inc.LastSeen.Before(since) && !InPrefixes(inc.Source, exclude) {
			o.Severity[inc.Severity]++
		}
	}
	m.mu.Unlock()

	type agg struct {
		n       int
		sources map[string]bool
		last    time.Time
		ua      string
	}
	newAgg := func() *agg { return &agg{sources: map[string]bool{}} }
	sources := map[string]*agg{}
	fps := map[string]*agg{}
	uas := map[string]*agg{}
	paths := map[[2]string]*agg{}
	buckets := map[time.Time]*agg{}
	stageSources := map[int]map[string]bool{} // by chain step index
	allSources := map[string]bool{}
	allFPs := map[string]bool{}
	type exploitAgg struct {
		ExploitStat
		cves    map[string]bool
		sources map[string]bool
	}
	exploits := map[[2]string]*exploitAgg{}

	for _, ev := range evs {
		if ev.Time.Before(since) {
			continue
		}
		o.Totals.Events++
		allSources[ev.Source] = true
		s := sources[ev.Source]
		if s == nil {
			s = newAgg()
			sources[ev.Source] = s
		}
		s.n++
		if ev.Time.After(s.last) {
			s.last = ev.Time
			if ev.UserAgent != "" {
				s.ua = ev.UserAgent
			}
		}
		for si, st := range chain {
			if st.Kind == ev.Kind && st.Slot == ev.CanarySlot && !ev.FromModule() {
				if stageSources[si] == nil {
					stageSources[si] = map[string]bool{}
				}
				stageSources[si][ev.Source] = true
			}
		}
		switch ev.Kind {
		case events.KindTLSHello:
			o.Totals.TLSHellos++
			if ja4, _ := ev.Detail["ja4"].(string); ja4 != "" {
				allFPs[ja4] = true
			}
		case events.KindCanaryUsed:
			o.Totals.CanaryUses++
		case events.KindExploit:
			mod, _ := ev.Detail["module"].(string)
			attack, _ := ev.Detail["attack"].(string)
			k := [2]string{mod, attack}
			x := exploits[k]
			if x == nil {
				x = &exploitAgg{ExploitStat: ExploitStat{Module: mod, Attack: attack}, cves: map[string]bool{}, sources: map[string]bool{}}
				exploits[k] = x
			}
			if ev.Detail["stage"] == "exploit" {
				x.Attempts++
			} else {
				x.Probes++
			}
			x.sources[ev.Source] = true
			if ev.Time.After(x.LastSeen) {
				x.LastSeen = ev.Time
			}
			for _, c := range detailStrings(ev.Detail["cve"]) {
				x.cves[c] = true
			}
		case events.KindRequest:
			o.Totals.Requests++
			h := ev.Time.Truncate(time.Hour)
			b := buckets[h]
			if b == nil {
				b = newAgg()
				buckets[h] = b
			}
			b.n++
			b.sources[ev.Source] = true
			if ja4, _ := ev.Detail["ja4"].(string); ja4 != "" {
				f := fps[ja4]
				if f == nil {
					f = newAgg()
					f.ua = ev.UserAgent
					fps[ja4] = f
				}
				f.n++
				f.sources[ev.Source] = true
			}
			u := uas[ev.UserAgent]
			if u == nil {
				u = newAgg()
				uas[ev.UserAgent] = u
			}
			u.n++
			u.sources[ev.Source] = true
			pk := [2]string{ev.Surface, stripQuery(ev.Path)}
			p := paths[pk]
			if p == nil {
				p = newAgg()
				paths[pk] = p
			}
			p.n++
			p.sources[ev.Source] = true
		}
	}
	o.Totals.Sources = len(allSources)
	o.Totals.Fingerprints = len(allFPs)
	for si, st := range chain {
		o.Funnel = append(o.Funnel, FunnelStage{Stage: st.Stage, Name: st.Name, Sources: len(stageSources[si])})
	}
	for t, b := range buckets {
		o.Timeline = append(o.Timeline, TimeBucket{Time: t, Requests: b.n, Sources: len(b.sources)})
	}
	slices.SortFunc(o.Timeline, func(a, b TimeBucket) int { return a.Time.Compare(b.Time) })
	for k, s := range sources {
		o.TopSources = append(o.TopSources, SourceStat{Source: k, Events: s.n, LastSeen: s.last, UserAgent: s.ua})
	}
	slices.SortFunc(o.TopSources, func(a, b SourceStat) int { return cmp.Or(b.Events-a.Events, strings.Compare(a.Source, b.Source)) })
	for k, f := range fps {
		o.TopFingerprints = append(o.TopFingerprints, Fingerprint{JA4: k, Sources: len(f.sources), Requests: f.n, UserAgent: f.ua})
	}
	slices.SortFunc(o.TopFingerprints, func(a, b Fingerprint) int {
		return cmp.Or(b.Sources-a.Sources, b.Requests-a.Requests, strings.Compare(a.JA4, b.JA4))
	})
	for k, u := range uas {
		o.TopUserAgents = append(o.TopUserAgents, UserAgent{UserAgent: k, Requests: u.n, Sources: len(u.sources)})
	}
	slices.SortFunc(o.TopUserAgents, func(a, b UserAgent) int {
		return cmp.Or(b.Requests-a.Requests, strings.Compare(a.UserAgent, b.UserAgent))
	})
	for k, p := range paths {
		o.TopPaths = append(o.TopPaths, PathStat{Surface: k[0], Path: k[1], Requests: p.n, Sources: len(p.sources)})
	}
	slices.SortFunc(o.TopPaths, func(a, b PathStat) int { return cmp.Or(b.Requests-a.Requests, strings.Compare(a.Path, b.Path)) })
	for _, x := range exploits {
		x.Sources = len(x.sources)
		x.CVEs = slices.Sorted(maps.Keys(x.cves))
		o.Exploits = append(o.Exploits, x.ExploitStat)
	}
	sortExploits(o.Exploits)
	o.TopSources = head(o.TopSources)
	o.TopFingerprints = head(o.TopFingerprints)
	o.TopUserAgents = head(o.TopUserAgents)
	o.TopPaths = head(o.TopPaths)
	return o, nil
}

func sortExploits(xs []ExploitStat) {
	slices.SortFunc(xs, func(a, b ExploitStat) int {
		return cmp.Or(b.Attempts-a.Attempts, b.Probes-a.Probes, strings.Compare(a.Module, b.Module), strings.Compare(a.Attack, b.Attack))
	})
}

// detailStrings reads a string list from event detail, which arrives as
// []any after a JSON round trip and as []string from in-process producers.
func detailStrings(v any) []string {
	switch v := v.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		if v != "" {
			return []string{v}
		}
	}
	return nil
}

func head[T any](s []T) []T {
	if len(s) > topN {
		return s[:topN]
	}
	return s
}

func stripQuery(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		return p[:i]
	}
	return p
}

func matchEvent(ev events.Event, f EventFilter) bool {
	return (f.Source == "" || ev.Source == f.Source) &&
		(f.Kind == "" || ev.Kind == f.Kind) &&
		(f.Surface == "" || ev.Surface == f.Surface) &&
		(f.Since.IsZero() || !ev.Time.Before(f.Since)) &&
		(f.Until.IsZero() || ev.Time.Before(f.Until))
}

// InPrefixes reports whether source is an address inside any of prefixes.
func InPrefixes(source string, prefixes []netip.Prefix) bool {
	addr, err := netip.ParseAddr(source)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	return slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(addr) })
}

// flattenChunks joins chunk arrays into one ordered list of rrweb events.
func flattenChunks(chunks [][]byte) ([]json.RawMessage, error) {
	var out []json.RawMessage
	for _, c := range chunks {
		var evs []json.RawMessage
		if err := json.Unmarshal(c, &evs); err != nil {
			continue // a malformed chunk loses only itself
		}
		out = append(out, evs...)
	}
	return out, nil
}
