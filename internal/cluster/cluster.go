// Package cluster groups clients that behave alike, whatever address they
// come from: the same sequence of steps, the same tools and protocol calls,
// the same client software and pacing. A cluster is a behavioral family (one
// agent build, one scanner kit), not proof of one operator; campaign
// correlation combines it with harder links.
//
// Each client becomes a set of behavior tokens. Tokens are weighted by
// rarity (inverse document frequency), so what everyone does ("GET /") counts
// for little and a distinctive step sequence counts for a lot. Clients whose
// weighted Jaccard similarity reaches Threshold are joined (single linkage).
package cluster

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strings"

	"agenttrap/internal/classify"
	"agenttrap/internal/events"
)

// Threshold is the weighted Jaccard similarity at which two clients join.
const Threshold = 0.55

// maxItems bounds one clustering pass.
const maxItems = 6000

// minTokens is the fewest tokens a client needs to be clustered at all:
// one-request visitors are all alike and say nothing.
const minTokens = 6

// Cluster is one behavioral family.
type Cluster struct {
	ID        string   `json:"id"`
	Members   []string `json:"members"`
	Classes   []string `json:"classes"`
	Signature []string `json:"signature"` // tokens most members share, most distinctive first
	Cohesion  float64  `json:"cohesion"`  // mean similarity of joined pairs
}

// Tokens describes one client's behavior.
func Tokens(a classify.Actor, evs []events.Event) []string {
	set := map[string]bool{}
	add := func(t string) { set[t] = true }
	var steps []string
	for _, ev := range evs {
		str := func(k string) string { v, _ := ev.Detail[k].(string); return v }
		step := ""
		switch ev.Kind {
		case events.KindRequest:
			step = ev.Surface + " " + ev.Method + " " + template(ev.Path)
		case events.KindToolCall:
			switch {
			case str("tool") != "":
				step = ev.Protocol + " tool " + str("tool")
			case str("op") != "":
				step = ev.Protocol + " " + str("op")
			case str("rpc_method") != "":
				step = ev.Protocol + " " + str("rpc_method")
			}
			if sk := str("skill"); sk != "" {
				add("skill:" + sk)
			}
		case events.KindCanaryExposed, events.KindCanaryUsed:
			add(ev.Kind + ":" + ev.CanarySlot)
		case events.KindBeacon:
			add("beacon")
		}
		if step != "" && (len(steps) == 0 || steps[len(steps)-1] != step) {
			steps = append(steps, step)
			add("step:" + step)
		}
	}
	for i := 1; i < len(steps); i++ {
		add("seq:" + steps[i-1] + " > " + steps[i])
	}
	f := a.Features
	add("declared:" + f.DeclaredAs)
	if a.Identity != nil && a.Identity.Name != "" {
		add("id:" + strings.ToLower(a.Identity.Name))
	}
	for _, l := range a.Frameworks {
		add("fw:" + l.Name)
	}
	if len(a.JA4) > 0 {
		add("tls:" + tlsStack(a.JA4[0]))
	}
	for _, sc := range f.HoneyScopes {
		add("honey_scope:" + sc)
	}
	if f.MaxStage > 0 {
		add(fmt.Sprintf("stage:%d", f.MaxStage))
	}
	if f.MedianGapMS > 0 {
		add(fmt.Sprintf("gap:%d", int(math.Log2(float64(f.MedianGapMS)))))
	}
	out := make([]string, 0, len(set))
	for t := range set {
		out = append(out, t)
	}
	slices.Sort(out)
	return out
}

var (
	hexRun = regexp.MustCompile(`[0-9a-fA-F]{8,}|[0-9]+`)
	uuidRe = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
)

// template strips the query and replaces IDs and numbers, so /v1/x/123 and
// /v1/x/456 are the same step.
func template(p string) string {
	if i := strings.IndexByte(p, '?'); i >= 0 {
		p = p[:i]
	}
	p = uuidRe.ReplaceAllString(p, ":id")
	return hexRun.ReplaceAllString(p, ":n")
}

func tlsStack(ja4 string) string {
	parts := strings.SplitN(ja4, "_", 3)
	if len(parts) < 2 {
		return ja4
	}
	return parts[0] + "_" + parts[1]
}

// Build clusters actors from their events. Operator traffic is ignored, and
// only clusters of two or more members are returned, largest first.
func Build(actors []classify.Actor, evs map[string][]events.Event) []Cluster {
	type item struct {
		src    string
		class  string
		tokens []string
	}
	var items []item
	for _, a := range actors {
		if a.Class == classify.Operator {
			continue
		}
		toks := Tokens(a, evs[a.Source])
		if len(toks) < minTokens {
			continue
		}
		items = append(items, item{a.Source, a.Class, toks})
	}
	// Bound the work: keep the clients with the most behavior.
	if len(items) > maxItems {
		slices.SortStableFunc(items, func(a, b item) int { return len(b.tokens) - len(a.tokens) })
		items = items[:maxItems]
	}
	n := len(items)
	if n < 2 {
		return nil
	}
	df := map[string]int{}
	for _, it := range items {
		for _, t := range it.tokens {
			df[t]++
		}
	}
	idf := func(t string) float64 { return math.Log(1 + float64(n)/float64(df[t])) }
	weight := make([]map[string]float64, n)
	for i, it := range items {
		weight[i] = make(map[string]float64, len(it.tokens))
		for _, t := range it.tokens {
			weight[i][t] = idf(t)
		}
	}

	// Candidate pairs share at least one token that is not near-universal.
	// The cutoff only bounds the work; with few clients every token counts.
	maxDF := max(200, n/20)
	postings := map[string][]int{}
	for i, it := range items {
		for _, t := range it.tokens {
			if df[t] >= 2 && df[t] <= maxDF {
				postings[t] = append(postings[t], i)
			}
		}
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
	checked := map[[2]int]bool{}
	var simSum = map[int]float64{}
	var simN = map[int]int{}
	type pair struct {
		a, b int
		sim  float64
	}
	var joined []pair
	for _, list := range postings {
		for x := 0; x < len(list); x++ {
			for y := x + 1; y < len(list); y++ {
				k := [2]int{list[x], list[y]}
				if checked[k] {
					continue
				}
				checked[k] = true
				if s := similarity(weight[k[0]], weight[k[1]]); s >= Threshold {
					joined = append(joined, pair{k[0], k[1], s})
					ra, rb := find(k[0]), find(k[1])
					if ra != rb {
						parent[ra] = rb
					}
				}
			}
		}
	}
	for _, p := range joined {
		r := find(p.a)
		simSum[r] += p.sim
		simN[r]++
	}

	groups := map[int][]int{}
	for i := range items {
		groups[find(i)] = append(groups[find(i)], i)
	}
	var out []Cluster
	for root, members := range groups {
		if len(members) < 2 {
			continue
		}
		c := Cluster{}
		classes := map[string]bool{}
		count := map[string]int{}
		for _, m := range members {
			c.Members = append(c.Members, items[m].src)
			classes[items[m].class] = true
			for _, t := range items[m].tokens {
				count[t]++
			}
		}
		slices.Sort(c.Members)
		for cl := range classes {
			c.Classes = append(c.Classes, cl)
		}
		slices.Sort(c.Classes)
		// Signature: tokens at least 80% of members share, rarest first.
		var sig []string
		for t, k := range count {
			if float64(k) >= 0.8*float64(len(members)) {
				sig = append(sig, t)
			}
		}
		sort.Slice(sig, func(i, j int) bool {
			if idf(sig[i]) != idf(sig[j]) {
				return idf(sig[i]) > idf(sig[j])
			}
			return sig[i] < sig[j]
		})
		if len(sig) > 8 {
			sig = sig[:8]
		}
		c.Signature = sig
		if simN[root] > 0 {
			c.Cohesion = math.Round(simSum[root]/float64(simN[root])*100) / 100
		}
		sum := sha256.Sum256([]byte(strings.Join(c.Signature, "\n")))
		c.ID = "c-" + hex.EncodeToString(sum[:4])
		out = append(out, c)
	}
	slices.SortFunc(out, func(a, b Cluster) int {
		if len(a.Members) != len(b.Members) {
			return len(b.Members) - len(a.Members)
		}
		return strings.Compare(a.Members[0], b.Members[0])
	})
	// Two families with the same signature keep distinct IDs.
	seen := map[string]int{}
	for i := range out {
		if k := seen[out[i].ID]; k > 0 {
			seen[out[i].ID]++
			out[i].ID = fmt.Sprintf("%s-%d", out[i].ID, k+1)
		} else {
			seen[out[i].ID] = 1
		}
	}
	return out
}

// similarity is the weighted Jaccard index of two token weight maps.
func similarity(a, b map[string]float64) float64 {
	var inter, union float64
	for t, w := range a {
		if _, ok := b[t]; ok {
			inter += w
		}
		union += w
	}
	for t, w := range b {
		if _, ok := a[t]; !ok {
			union += w
		}
	}
	if union == 0 {
		return 0
	}
	return inter / union
}

// Assign sets each actor's ClusterID.
func Assign(actors []classify.Actor, clusters []Cluster) {
	of := map[string]string{}
	for _, c := range clusters {
		for _, m := range c.Members {
			of[m] = c.ID
		}
	}
	for i := range actors {
		actors[i].ClusterID = of[actors[i].Source]
	}
}
