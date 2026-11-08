package hub

import (
	"context"
	"slices"
	"time"

	"agenttrap/internal/classify"
	"agenttrap/internal/events"
	"agenttrap/internal/graph"
)

// Linker is the link graph (see package graph).
type Linker interface {
	Merge(ctx context.Context, edges []graph.Edge) error
	SetClasses(ctx context.Context, cs []graph.Classified) error
	Links(ctx context.Context) (map[string][]graph.Link, error)
	Empty(ctx context.Context) (bool, error)
}

// SetGraph enables the link graph.
func (h *Hub) SetGraph(g Linker) { h.graph = g }

const (
	graphInterval = 2 * time.Minute
	graphCatchUp  = 48 * time.Hour   // folded in at startup when the graph has data
	graphOverlap  = 10 * time.Minute // re-read recent events: merges are idempotent
	graphClassWin = 24 * time.Hour
	graphRebuild  = 30 * 24 * time.Hour // class window after a full rebuild
	graphSlice    = 24 * time.Hour      // rebuild step
)

// RunGraph folds events into the link graph, records each source's class
// and refreshes the links that Analyze attaches to actors. An empty graph
// (new install, or a database restored from backup, which leaves the graph
// out) is rebuilt from every stored event first.
func (h *Hub) RunGraph(ctx context.Context) {
	if h.graph == nil {
		return
	}
	for {
		if err := h.catchUpGraph(ctx); err == nil {
			break
		} else {
			h.log.Warn("graph rebuild failed; retrying", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(graphInterval):
		}
	}
	since := time.Now().Add(-graphOverlap)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(graphInterval):
		}
		start := time.Now()
		if err := h.syncGraph(ctx, since, time.Now(), graphClassWin); err != nil {
			h.log.Warn("graph sync failed", "err", err)
			continue
		}
		since = start.Add(-graphOverlap)
	}
}

// catchUpGraph folds history into the graph a day at a time: everything
// when the graph is empty, else the last graphCatchUp.
func (h *Hub) catchUpGraph(ctx context.Context) error {
	empty, err := h.graph.Empty(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	from, classWin := now.Add(-graphCatchUp), graphClassWin
	if empty {
		oldest, err := h.store.OldestEvent(ctx)
		if err != nil {
			return err
		}
		if oldest.IsZero() {
			return nil
		}
		from, classWin = oldest, graphRebuild
		h.log.Info("rebuilding link graph", "from", oldest.UTC().Format(time.RFC3339))
	}
	for t := from; t.Before(now); t = t.Add(graphSlice) {
		end := t.Add(graphSlice)
		if end.After(now) {
			end = now.Add(time.Second)
		}
		if err := h.mergeEvents(ctx, t, end); err != nil {
			return err
		}
	}
	return h.refreshLinks(ctx, classWin)
}

func (h *Hub) mergeEvents(ctx context.Context, from, to time.Time) error {
	evs, err := h.store.EventsBetween(ctx, from, to, maxClassifyEvents)
	if err != nil {
		return err
	}
	evs = slices.DeleteFunc(evs, func(ev events.Event) bool { _, op := h.operatorFor(ev.Source); return op })
	return h.graph.Merge(ctx, graph.EdgesFrom(evs))
}

func (h *Hub) syncGraph(ctx context.Context, from, to time.Time, classWindow time.Duration) error {
	if err := h.mergeEvents(ctx, from, to); err != nil {
		return err
	}
	return h.refreshLinks(ctx, classWindow)
}

// refreshLinks stores recent classes on source nodes and reloads links.
func (h *Hub) refreshLinks(ctx context.Context, classWindow time.Duration) error {
	actors, _, err := h.Analyze(ctx, time.Now().Add(-classWindow))
	if err != nil {
		return err
	}
	var cs []graph.Classified
	for _, a := range actors {
		if a.Class != classify.Operator {
			cs = append(cs, graph.Classified{Source: a.Source, Class: a.Class, Seen: a.LastSeen.UTC().Format(time.RFC3339)})
		}
	}
	if err := h.graph.SetClasses(ctx, cs); err != nil {
		return err
	}
	found, err := h.graph.Links(ctx)
	if err != nil {
		return err
	}
	links := make(map[string][]classify.Link, len(found))
	for src, ls := range found {
		if _, op := h.operatorFor(src); op {
			continue
		}
		for _, l := range ls {
			links[src] = append(links[src], classify.Link{Agent: l.Agent, Class: l.Class, Seen: l.Seen, Via: l.Via})
		}
	}
	h.linkMu.Lock()
	h.links, h.linksAt = links, time.Now()
	h.linkMu.Unlock()
	return nil
}

// SyncGraph runs one sync pass over events since the given time.
func (h *Hub) SyncGraph(ctx context.Context, since time.Time) error {
	if h.graph == nil {
		return nil
	}
	return h.syncGraph(ctx, since, time.Now().Add(time.Second), time.Since(since))
}
