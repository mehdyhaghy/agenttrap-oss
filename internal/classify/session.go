package classify

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"agenttrap/internal/events"
)

// Session is one client seen from several addresses, such as an agent
// platform spreading a task across egress IPs.
type Session struct {
	ID        string    `json:"id"`
	Members   []string  `json:"members"`
	Links     []string  `json:"links"` // why the addresses were joined
	Class     string    `json:"class"`
	Score     int       `json:"score"`
	Reasons   []string  `json:"reasons"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	UserAgent string    `json:"user_agent,omitempty"`
}

// sessionWindow is how close in time two addresses' activity must be to be
// joined on client identity alone.
const sessionWindow = 60 * time.Second

// GroupSessions joins actors that are one client seen from several addresses
// and classifies each group as a whole. evs holds each source's events.
// Members are upgraded to their session's class when it ranks higher. It
// returns sessions with at least two members, most interesting first.
func GroupSessions(actors []Actor, evs map[string][]events.Event) []Session {
	n := len(actors)
	idx := make(map[string]int, n)
	for i, a := range actors {
		idx[a.Source] = i
	}
	parent := make([]int, n)
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		for parent[i] != i {
			parent[i] = parent[parent[i]]
			i = parent[i]
		}
		return i
	}
	links := map[[2]int]string{}
	join := func(a, b int, why string) {
		if a == b {
			return
		}
		ra, rb := find(a), find(b)
		if ra != rb {
			parent[ra] = rb
		}
		key := [2]int{min(a, b), max(a, b)}
		if _, ok := links[key]; !ok {
			links[key] = why
		}
	}

	// 1. Hard links: a key revealed to one address and used from another, or
	// an agent ID issued to one address and sent from another.
	// Likewise an OAuth client registered at one address, or an A2A context
	// issued to one address, and used from another.
	agentIssuer := map[string]int{}
	clientIssuer := map[string]int{}
	contextIssuer := map[string]int{}
	for src, list := range evs {
		for _, ev := range list {
			if id, _ := ev.Detail["agent_id"].(string); id != "" && ev.Kind == events.KindToolCall {
				agentIssuer[id] = idx[src]
			}
			if op, _ := ev.Detail["op"].(string); op == "oauth_register" {
				if id, _ := ev.Detail["client_id"].(string); id != "" {
					clientIssuer[id] = idx[src]
				}
			}
			if id, _ := ev.Detail["issued_context"].(string); id != "" {
				contextIssuer[id] = idx[src]
			}
		}
	}
	for src, list := range evs {
		i, ok := idx[src]
		if !ok {
			continue
		}
		for _, ev := range list {
			if to, _ := ev.Detail["exposed_to"].(string); to != "" && ev.Kind == events.KindCanaryUsed {
				if j, ok := idx[to]; ok {
					join(i, j, "used a key revealed to the other address")
				}
			}
			if id, _ := ev.Detail["agent_id"].(string); id != "" && ev.Kind == events.KindRequest {
				if j, ok := agentIssuer[id]; ok {
					join(i, j, "sent an agent ID issued to the other address")
				}
			}
			if op, _ := ev.Detail["op"].(string); op != "oauth_register" && ev.Kind == events.KindToolCall {
				if id, _ := ev.Detail["client_id"].(string); id != "" {
					if j, ok := clientIssuer[id]; ok {
						join(i, j, "used an OAuth client registered by the other address")
					}
				}
			}
			if id, _ := ev.Detail["context_id"].(string); id != "" {
				if j, ok := contextIssuer[id]; ok {
					join(i, j, "continued an A2A conversation started by the other address")
				}
			}
		}
	}

	// 2. Same client at the same moment: identical user agent and TLS stack,
	// activity within sessionWindow. Common browser user agents also need a
	// shared network to avoid joining unrelated people.
	// The crawler verdict is part of the key: a verified crawler and an
	// impersonator share a user agent but are never the same client.
	type key struct{ ua, tls, check string }
	buckets := map[key][]int{}
	for i, a := range actors {
		if len(a.UserAgents) == 0 || a.Class == Operator {
			continue
		}
		k := key{a.UserAgents[0], tlsStack(a.JA4), a.CrawlerCheck}
		buckets[k] = append(buckets[k], i)
	}
	for k, members := range buckets {
		if len(members) < 2 {
			continue
		}
		sort.Slice(members, func(x, y int) bool { return actors[members[x]].FirstSeen.Before(actors[members[y]].FirstSeen) })
		distinctive := isDistinctive(actors[members[0]].Features.DeclaredAs)
		for x := 0; x < len(members); x++ {
			for y := x + 1; y < len(members); y++ {
				a, b := actors[members[x]], actors[members[y]]
				if b.FirstSeen.Sub(a.LastSeen) > sessionWindow {
					break // sorted by first seen: later members start even later
				}
				why := ""
				switch {
				case sameNet24(a.Source, b.Source):
					why = "same client (user agent and TLS stack) from the same /24 within a minute"
				case a.Network != "" && a.Network == b.Network && !strings.Contains(a.Network, "residential"):
					why = "same client (user agent and TLS stack) on " + a.Network + " within a minute"
				case distinctive:
					why = "same distinctive client (user agent and TLS stack) within a minute"
				}
				if why != "" {
					if k.tls == "" {
						why = strings.Replace(why, " and TLS stack", "", 1)
					}
					join(members[x], members[y], why)
				}
			}
		}
	}

	// Collect groups.
	groups := map[int][]int{}
	for i := range actors {
		groups[find(i)] = append(groups[find(i)], i)
	}
	rank := map[string]int{}
	for i, c := range Order {
		rank[c] = i
	}
	var sessions []Session
	for _, members := range groups {
		if len(members) < 2 {
			continue
		}
		slices.SortFunc(members, func(x, y int) int { return strings.Compare(actors[x].Source, actors[y].Source) })
		var all []events.Event
		s := Session{}
		for _, m := range members {
			a := actors[m]
			s.Members = append(s.Members, a.Source)
			all = append(all, evs[a.Source]...)
			if s.FirstSeen.IsZero() || a.FirstSeen.Before(s.FirstSeen) {
				s.FirstSeen = a.FirstSeen
			}
			if a.LastSeen.After(s.LastSeen) {
				s.LastSeen = a.LastSeen
			}
			if s.UserAgent == "" && len(a.UserAgents) > 0 {
				s.UserAgent = a.UserAgents[0]
			}
		}
		s.ID = "s-" + s.Members[0]
		seen := map[string]bool{}
		for k, why := range links {
			if find(k[0]) == find(members[0]) && !seen[why] {
				seen[why] = true
				s.Links = append(s.Links, why)
			}
		}
		slices.Sort(s.Links)
		whole := Classify(s.ID, all)
		// Hard links already made members rogue; keep the strongest class
		// among non-operator members. A session of only our own addresses
		// is operator traffic.
		s.Class, s.Score, s.Reasons = whole.Class, whole.Score, whole.Reasons
		operators := 0
		for _, m := range members {
			if actors[m].Class == Operator {
				operators++
				continue
			}
			if rank[actors[m].Class] < rank[s.Class] {
				s.Class = actors[m].Class
			}
			s.Score = max(s.Score, actors[m].Score)
		}
		if operators == len(members) {
			s.Class, s.Score = Operator, 0
			s.Reasons = []string{"all addresses are operator addresses"}
		}
		for _, m := range members {
			a := &actors[m]
			if a.Class == Operator {
				continue
			}
			if rank[s.Class] < rank[a.Class] {
				a.Class = s.Class
				a.Confidence = whole.Confidence
				lead := s.Reasons
				if len(lead) > 2 {
					lead = lead[:2]
				}
				a.Reasons = append([]string{fmt.Sprintf("part of a session across %d addresses: %s", len(members), strings.Join(lead, "; "))}, a.Reasons...)
			}
			a.SessionID = s.ID
			a.SessionSize = len(members)
		}
		sessions = append(sessions, s)
	}
	slices.SortFunc(sessions, func(a, b Session) int {
		if rank[a.Class] != rank[b.Class] {
			return rank[a.Class] - rank[b.Class]
		}
		if len(a.Members) != len(b.Members) {
			return len(b.Members) - len(a.Members)
		}
		return b.LastSeen.Compare(a.LastSeen)
	})
	return sessions
}

// tlsStack is the part of a JA4 that identifies the client's TLS library
// (protocol, version, counts and cipher hash), or "" without one.
func tlsStack(ja4 []string) string {
	if len(ja4) == 0 {
		return ""
	}
	parts := strings.SplitN(ja4[0], "_", 3)
	if len(parts) < 2 {
		return ja4[0]
	}
	return parts[0] + "_" + parts[1]
}

// isDistinctive reports whether a declared client type is specific enough
// that two addresses using it at the same moment are likely one client.
func isDistinctive(declared string) bool {
	switch declared {
	case "ai_agent", "crawler", "scanner", "other":
		return true
	}
	return false
}

func sameNet24(a, b string) bool {
	x, err1 := netip.ParseAddr(a)
	y, err2 := netip.ParseAddr(b)
	if err1 != nil || err2 != nil || x.Is4() != y.Is4() {
		return false
	}
	bits := 24
	if !x.Is4() {
		bits = 48
	}
	px, _ := x.Prefix(bits)
	py, _ := y.Prefix(bits)
	return px == py
}
