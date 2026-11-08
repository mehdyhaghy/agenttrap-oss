package hub

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"agenttrap/internal/correlate"
	"agenttrap/internal/events"
)

// MemStore is an in-memory Store for tests and local experiments.
type MemStore struct {
	replays   []ReplayChunk
	operators []Operator
	rdns      map[string]SourceRDNS
	mu        sync.Mutex
	spokes    map[string]*Spoke
	tokens    map[string]*memToken
	canaries  map[string][2]string
	events    []events.Event
	eventIDs  map[string]bool
	incidents map[string]*correlate.Incident
	nextInc   int64
}

type memToken struct {
	spokeID string
	expires time.Time
	used    bool
}

func NewMemStore() *MemStore {
	return &MemStore{
		spokes:    map[string]*Spoke{},
		tokens:    map[string]*memToken{},
		canaries:  map[string][2]string{},
		eventIDs:  map[string]bool{},
		incidents: map[string]*correlate.Incident{},
	}
}

func (m *MemStore) CreateSpoke(_ context.Context, id string, seed []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.spokes[id]; ok {
		return errors.New("spoke already exists")
	}
	m.spokes[id] = &Spoke{ID: id, CreatedAt: time.Now(), CanarySeed: slices.Clone(seed)}
	return nil
}

func (m *MemStore) GetSpoke(_ context.Context, id string) (Spoke, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.spokes[id]
	if !ok {
		return Spoke{}, ErrNotFound
	}
	return *s, nil
}

func (m *MemStore) ListSpokes(context.Context) ([]Spoke, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Spoke, 0, len(m.spokes))
	for _, s := range m.spokes {
		out = append(out, *s)
	}
	slices.SortFunc(out, func(a, b Spoke) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out, nil
}

func (m *MemStore) RevokeSpoke(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.spokes[id]
	if !ok {
		return ErrNotFound
	}
	s.Revoked = true
	return nil
}

func (m *MemStore) TouchSpoke(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.spokes[id]; ok {
		s.LastSeen = &at
	}
	return nil
}

func (m *MemStore) CreateEnrollToken(_ context.Context, hash, spokeID string, expires time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[hash] = &memToken{spokeID: spokeID, expires: expires}
	return nil
}

func (m *MemStore) ConsumeEnrollToken(_ context.Context, hash string, now time.Time) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[hash]
	if !ok || t.used || now.After(t.expires) {
		return "", ErrNotFound
	}
	t.used = true
	return t.spokeID, nil
}

func (m *MemStore) AddCanaries(_ context.Context, spokeID string, hashes map[string]string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for h, slot := range hashes {
		m.canaries[h] = [2]string{spokeID, slot}
	}
	return nil
}

func (m *MemStore) LookupCanary(_ context.Context, hash string) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.canaries[hash]
	if !ok {
		return "", "", ErrNotFound
	}
	return c[0], c[1], nil
}

func (m *MemStore) InsertEvents(_ context.Context, evs []events.Event) ([]events.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var fresh []events.Event
	for _, ev := range evs {
		if m.eventIDs[ev.ID] {
			continue
		}
		m.eventIDs[ev.ID] = true
		m.events = append(m.events, ev)
		fresh = append(fresh, ev)
	}
	return fresh, nil
}

func (m *MemStore) ListEvents(_ context.Context, f EventFilter) ([]events.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []events.Event
	for i := len(m.events) - 1; i >= 0; i-- {
		ev := m.events[i]
		if !matchEvent(ev, f) {
			continue
		}
		out = append(out, ev)
		if f.Limit > 0 && len(out) == f.Limit {
			break
		}
	}
	return out, nil
}

func (m *MemStore) WasExposed(_ context.Context, source, originSpoke, slot string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ev := range m.events {
		if ev.Kind == events.KindCanaryExposed && ev.Source == source && ev.SpokeID == originSpoke && ev.CanarySlot == slot {
			return true, nil
		}
	}
	return false, nil
}

func (m *MemStore) IncidentBySource(_ context.Context, source string) (*correlate.Incident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	inc, ok := m.incidents[source]
	if !ok {
		return nil, nil
	}
	c := *inc
	c.Spokes = slices.Clone(inc.Spokes)
	c.Stages = slices.Clone(inc.Stages)
	return &c, nil
}

func (m *MemStore) SaveIncident(_ context.Context, inc *correlate.Incident) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if inc.ID == 0 {
		m.nextInc++
		inc.ID = m.nextInc
	}
	c := *inc
	m.incidents[inc.Source] = &c
	return nil
}

func (m *MemStore) ListIncidents(_ context.Context, limit int) ([]correlate.Incident, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]correlate.Incident, 0, len(m.incidents))
	for _, inc := range m.incidents {
		out = append(out, *inc)
	}
	slices.SortFunc(out, func(a, b correlate.Incident) int { return b.LastSeen.Compare(a.LastSeen) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemStore) EventsSince(ctx context.Context, since time.Time, limit int) ([]events.Event, error) {
	return m.EventsBetween(ctx, since, time.Time{}, limit)
}

func (m *MemStore) OldestEvent(context.Context) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var t time.Time
	for _, ev := range m.events {
		if t.IsZero() || ev.Time.Before(t) {
			t = ev.Time
		}
	}
	return t, nil
}

// EventsBetween returns events in [from, to); a zero to means no bound.
func (m *MemStore) EventsBetween(_ context.Context, from, to time.Time, limit int) ([]events.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []events.Event
	for _, ev := range m.events {
		if !ev.Time.Before(from) && (to.IsZero() || ev.Time.Before(to)) {
			out = append(out, ev)
		}
	}
	slices.SortStableFunc(out, func(a, b events.Event) int {
		if a.Source != b.Source {
			return strings.Compare(a.Source, b.Source)
		}
		return a.Time.Compare(b.Time)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *MemStore) FindExposure(_ context.Context, id string) (events.Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ev := range m.events {
		if ev.Kind == events.KindCanaryExposed && ev.Detail["exposure_id"] == id {
			return ev, nil
		}
	}
	return events.Event{}, ErrNotFound
}

func (m *MemStore) ListOperators(context.Context) ([]Operator, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.operators), nil
}

func (m *MemStore) AddOperator(_ context.Context, o Operator) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.operators = slices.DeleteFunc(m.operators, func(x Operator) bool { return x.CIDR == o.CIDR })
	o.CreatedAt = time.Now()
	m.operators = append(m.operators, o)
	return nil
}

func (m *MemStore) RemoveOperator(_ context.Context, cidr string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := len(m.operators)
	m.operators = slices.DeleteFunc(m.operators, func(x Operator) bool { return x.CIDR == cidr })
	if len(m.operators) == n {
		return ErrNotFound
	}
	return nil
}

func (m *MemStore) DeleteIncidentsIn(_ context.Context, p netip.Prefix) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for src := range m.incidents {
		if InPrefixes(src, []netip.Prefix{p}) {
			delete(m.incidents, src)
			n++
		}
	}
	return n, nil
}

func (m *MemStore) SaveRDNS(_ context.Context, r SourceRDNS) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rdns == nil {
		m.rdns = map[string]SourceRDNS{}
	}
	r.CheckedAt = time.Now()
	m.rdns[r.Source] = r
	return nil
}

func (m *MemStore) RDNSFor(_ context.Context, sources []string) (map[string]SourceRDNS, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]SourceRDNS{}
	for _, s := range sources {
		if r, ok := m.rdns[s]; ok {
			out[s] = r
		}
	}
	return out, nil
}

func (m *MemStore) SaveReplayChunks(_ context.Context, chunks []ReplayChunk) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range chunks {
		if !slices.ContainsFunc(m.replays, func(x ReplayChunk) bool { return x.ViewID == c.ViewID && x.Seq == c.Seq }) {
			m.replays = append(m.replays, c)
		}
	}
	return nil
}

func (m *MemStore) ListReplays(_ context.Context, source string, _ int) ([]ReplaySummary, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	byView := map[string]*ReplaySummary{}
	var order []string
	for _, c := range m.replays {
		if source != "" && c.Source != source {
			continue
		}
		v, ok := byView[c.ViewID]
		if !ok {
			v = &ReplaySummary{ViewID: c.ViewID, Source: c.Source, Surface: c.Surface, Start: c.Time, End: c.Time}
			byView[c.ViewID] = v
			order = append(order, c.ViewID)
		}
		v.Chunks++
		v.Bytes += len(c.Data)
		if c.Time.After(v.End) {
			v.End = c.Time
		}
	}
	out := make([]ReplaySummary, 0, len(order))
	for _, id := range order {
		out = append(out, *byView[id])
	}
	return out, nil
}

func (m *MemStore) GetReplay(_ context.Context, viewID string) ([]json.RawMessage, error) {
	m.mu.Lock()
	var chunks []ReplayChunk
	for _, c := range m.replays {
		if c.ViewID == viewID {
			chunks = append(chunks, c)
		}
	}
	m.mu.Unlock()
	slices.SortFunc(chunks, func(a, b ReplayChunk) int { return a.Seq - b.Seq })
	raw := make([][]byte, len(chunks))
	for i, c := range chunks {
		raw[i] = c.Data
	}
	return flattenChunks(raw)
}

func (m *MemStore) SourceActivity(_ context.Context, since, until time.Time, step time.Duration) ([]SourceBucket, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	type key struct {
		src string
		at  int64
	}
	counts := map[key]int{}
	for _, ev := range m.events {
		if ev.Time.Before(since) || !ev.Time.Before(until) {
			continue
		}
		counts[key{ev.Source, int64(ev.Time.Sub(since) / step)}]++
	}
	out := make([]SourceBucket, 0, len(counts))
	for k, n := range counts {
		out = append(out, SourceBucket{Source: k.src, Start: since.Add(time.Duration(k.at) * step), Events: n})
	}
	return out, nil
}
