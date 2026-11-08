// Package campaign correlates agent activity into campaigns: sets of
// addresses and sessions that are one operation, across time, spokes and
// infrastructure. It joins agents through every link the hub already has:
// sessions (relayed keys, shared agent IDs and OAuth clients, the same client
// at the same moment), the link graph (shared keys, credentials, prompts,
// registered names, webhooks), a shared declared identity, and behavioral
// clusters. Behavior alone is never enough: two members of a behavioral
// cluster join only when they also share a declared identity or client
// software, since one popular agent build is used by many unrelated people.
package campaign

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"

	"agenttrap/internal/classify"
)

// Campaign is one correlated operation.
type Campaign struct {
	ID         string    `json:"id"`
	Members    []string  `json:"members"`
	Sessions   []string  `json:"sessions,omitempty"`
	Clusters   []string  `json:"clusters,omitempty"`
	Classes    []string  `json:"classes"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	MaxStage   int       `json:"max_stage"`
	Severity   string    `json:"severity"`
	Score      int       `json:"score"`
	Networks   []string  `json:"networks,omitempty"`
	Identities []string  `json:"identities,omitempty"`
	Frameworks []string  `json:"frameworks,omitempty"`
	Joins      []string  `json:"joins"` // why members were joined, one line per reason
	Summary    string    `json:"summary"`
}

// eligible reports whether an actor can be part of a campaign: anything
// that used a planted key, and agents with real agent behavior. Declared and
// verified crawler fleets (search and assistant platforms) are not
// operations, and a platform's user agent alone says nothing; they stay in
// clusters and exports.
func eligible(a classify.Actor) bool {
	if a.Features.MaxStage >= 2 {
		return true
	}
	if a.Class != classify.RogueAgent && a.Class != classify.AIAgent {
		return false
	}
	return a.Score >= 25 && a.Features.DeclaredAs != "crawler" && a.CrawlerCheck != "verified"
}

// Correlate builds campaigns from classified actors (with sessions, links,
// frameworks and cluster IDs already applied). Only campaigns with at least
// two addresses are returned, most severe first.
func Correlate(actors []classify.Actor) []Campaign {
	idx := map[string]int{}
	for i, a := range actors {
		if eligible(a) {
			idx[a.Source] = i
		}
	}
	parent := map[int]int{}
	for _, i := range idx {
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
	why := map[int][]string{} // root-independent: collected per pair, grouped later
	type edge struct {
		a, b   int
		reason string
	}
	var edges []edge
	join := func(a, b int, reason string) {
		if a == b {
			return
		}
		edges = append(edges, edge{a, b, reason})
		if ra, rb := find(a), find(b); ra != rb {
			parent[ra] = rb
		}
	}

	// Sessions and graph links.
	bySession := map[string][]int{}
	for _, i := range idx {
		a := actors[i]
		if a.SessionID != "" {
			bySession[a.SessionID] = append(bySession[a.SessionID], i)
		}
		for _, l := range a.Links {
			if j, ok := idx[l.Agent]; ok {
				join(i, j, "linked through "+strings.Join(l.Via, " → "))
			}
		}
	}
	for id, members := range bySession {
		for _, m := range members[1:] {
			join(members[0], m, "same session "+id)
		}
	}
	// Declared identity: the same agent name, operator URL or contact.
	byIdentity := map[string][]int{}
	for _, i := range idx {
		for _, k := range identityKeys(actors[i]) {
			byIdentity[k] = append(byIdentity[k], i)
		}
	}
	for k, members := range byIdentity {
		slices.Sort(members)
		for _, m := range members[1:] {
			join(members[0], m, "same declared identity ("+k+")")
		}
	}
	// Behavioral cluster plus shared client software.
	byCluster := map[string][]int{}
	for _, i := range idx {
		if c := actors[i].ClusterID; c != "" {
			byCluster[c] = append(byCluster[c], i)
		}
	}
	for c, members := range byCluster {
		slices.Sort(members)
		for x := 0; x < len(members); x++ {
			for y := x + 1; y < len(members); y++ {
				if sw := sharedSoftware(actors[members[x]], actors[members[y]]); sw != "" {
					join(members[x], members[y], "same behavior (cluster "+c+") and client software ("+sw+")")
				}
			}
		}
	}

	groups := map[int][]int{}
	for _, i := range idx {
		groups[find(i)] = append(groups[find(i)], i)
	}
	for _, e := range edges {
		r := find(e.a)
		if !slices.Contains(why[r], e.reason) {
			why[r] = append(why[r], e.reason)
		}
	}
	var out []Campaign
	for root, members := range groups {
		if len(members) < 2 {
			continue
		}
		out = append(out, build(actors, members, why[root]))
	}
	slices.SortFunc(out, func(a, b Campaign) int {
		return cmpInts(b.MaxStage, a.MaxStage, b.Score, a.Score, len(b.Members), len(a.Members), int(b.LastSeen.Unix()), int(a.LastSeen.Unix()))
	})
	return out
}

func build(actors []classify.Actor, members []int, joins []string) Campaign {
	c := Campaign{}
	set := func(dst *[]string, v string) {
		if v != "" && !slices.Contains(*dst, v) {
			*dst = append(*dst, v)
		}
	}
	for _, m := range members {
		a := actors[m]
		c.Members = append(c.Members, a.Source)
		set(&c.Sessions, a.SessionID)
		set(&c.Clusters, a.ClusterID)
		set(&c.Classes, a.Class)
		set(&c.Networks, a.Network)
		if a.Identity != nil {
			set(&c.Identities, a.Identity.Name)
		}
		if a.Features.AgentName != "" {
			set(&c.Identities, a.Features.AgentName)
		}
		for _, n := range likely(a) {
			set(&c.Frameworks, n)
		}
		if c.FirstSeen.IsZero() || a.FirstSeen.Before(c.FirstSeen) {
			c.FirstSeen = a.FirstSeen
		}
		if a.LastSeen.After(c.LastSeen) {
			c.LastSeen = a.LastSeen
		}
		c.MaxStage = max(c.MaxStage, a.Features.MaxStage)
		c.Score = max(c.Score, a.Score)
	}
	for _, l := range [][]string{c.Members, c.Sessions, c.Clusters, c.Classes, c.Networks, c.Identities, c.Frameworks} {
		slices.Sort(l)
	}
	slices.Sort(joins)
	c.Joins = joins
	// Stable while the campaign grows: named after its earliest member.
	earliest := members[0]
	for _, m := range members {
		if actors[m].FirstSeen.Before(actors[earliest].FirstSeen) {
			earliest = m
		}
	}
	sum := sha256.Sum256([]byte(actors[earliest].Source + "|" + actors[earliest].FirstSeen.UTC().Format(time.RFC3339)))
	c.ID = "k-" + hex.EncodeToString(sum[:4])
	switch {
	case c.MaxStage >= 4:
		c.Severity = "critical"
	case c.MaxStage == 3:
		c.Severity = "high"
	case c.MaxStage == 2 || slices.Contains(c.Classes, classify.RogueAgent):
		c.Severity = "medium"
	default:
		c.Severity = "low"
	}
	c.Summary = fmt.Sprintf("%d addresses", len(c.Members))
	if len(c.Networks) > 0 {
		c.Summary += fmt.Sprintf(" on %d network(s)", len(c.Networks))
	}
	if c.MaxStage > 0 {
		c.Summary += fmt.Sprintf(", reached chain stage %d", c.MaxStage)
	}
	if len(c.Identities) > 0 {
		c.Summary += ", declared as " + strings.Join(c.Identities[:min(len(c.Identities), 3)], ", ")
	}
	if span := c.LastSeen.Sub(c.FirstSeen); span >= time.Hour {
		c.Summary += fmt.Sprintf(", active over %s", span.Round(time.Hour))
	}
	return c
}

// Assign sets each member's CampaignID.
func Assign(actors []classify.Actor, campaigns []Campaign) {
	of := map[string]string{}
	for _, c := range campaigns {
		for _, m := range c.Members {
			of[m] = c.ID
		}
	}
	for i := range actors {
		actors[i].CampaignID = of[actors[i].Source]
	}
}

// identityKeys are identities an operator chose: a contact address, the
// name it registered an integration or OAuth client under. The operator URL
// in a user agent is left out: platforms (assistant and search bots) put
// their own URL there for every user they act for.
func identityKeys(a classify.Actor) []string {
	var out []string
	if a.Identity != nil && a.Identity.Email != "" {
		out = append(out, "contact "+strings.ToLower(a.Identity.Email))
	}
	if n := strings.ToLower(strings.TrimSpace(a.Features.AgentName)); len(n) >= 4 {
		out = append(out, "registered as "+n)
	}
	if n := strings.ToLower(strings.TrimSpace(a.Features.OAuthClientName)); len(n) >= 4 {
		out = append(out, "OAuth client "+n)
	}
	return out
}

// sharedSoftware returns client software both actors are likely running,
// or their shared declared identity name.
func sharedSoftware(a, b classify.Actor) string {
	for _, n := range likely(a) {
		if slices.Contains(likely(b), n) && n != "llm" && n != "script" {
			return n
		}
	}
	if a.Identity != nil && b.Identity != nil && a.Identity.Name != "" && strings.EqualFold(a.Identity.Name, b.Identity.Name) {
		return a.Identity.Name
	}
	return ""
}

func likely(a classify.Actor) []string {
	var out []string
	for _, l := range a.Frameworks {
		if l.Level == "likely" {
			out = append(out, l.Name)
		}
	}
	return out
}

func cmpInts(pairs ...int) int {
	for i := 0; i+1 < len(pairs); i += 2 {
		if pairs[i] != pairs[i+1] {
			if pairs[i] < pairs[i+1] {
				return -1
			}
			return 1
		}
	}
	return 0
}
