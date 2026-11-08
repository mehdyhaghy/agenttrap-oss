package digest

import (
	"fmt"
	"slices"
	"strings"
)

// The digest opens with one sentence that tells the reader whether the day
// needs attention, then one line of supporting detail. The subject line, the
// text body and the HTML body all use the same words.

// mood is the day's tone: it picks the headline and the accent color.
type mood int

const (
	moodQuiet  mood = iota // nothing agentic happened
	moodAgents             // AI agents explored, none went rogue
	moodRogue              // at least one agent used bait
)

func (r *Report) mood() mood {
	switch {
	case len(r.Rogue) > 0:
		return moodRogue
	case len(r.Agents) > 0:
		return moodAgents
	}
	return moodQuiet
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// window names the report window in words ("24 hours", "7 days").
func (r *Report) window() string {
	h := int(r.Until.Sub(r.Since).Hours() + 0.5)
	if h >= 48 && h%24 == 0 {
		return plural(h/24, "day", "days")
	}
	return plural(h, "hour", "hours")
}

// Headline is the one-sentence verdict for the window.
func (r *Report) Headline() string {
	switch r.mood() {
	case moodRogue:
		return plural(len(r.Rogue), "rogue agent", "rogue agents") + " took the bait"
	case moodAgents:
		return "No rogue agents — " + plural(len(r.Agents), "AI agent", "AI agents") + " came exploring"
	}
	return "All quiet — no agents took the bait"
}

// deepest is the rogue agent (or, failing that, AI agent) that reached
// furthest into the estate.
func (r *Report) deepest() (actor, bool) {
	pool := r.Rogue
	if len(pool) == 0 {
		pool = r.Agents
	}
	if len(pool) == 0 {
		return actor{}, false
	}
	return slices.MaxFunc(pool, func(a, b actor) int {
		if a.Capability != b.Capability {
			return a.Capability - b.Capability
		}
		return a.Score - b.Score
	}), true
}

// originList names up to three countries the given actors came from, most
// frequent first, with flags: "🇷🇺 Russia, 🇨🇳 China and 🇩🇪 Germany".
func originList(as []actor) string {
	count := map[string]int{}
	name := map[string]string{}
	var order []string
	for _, a := range as {
		if a.CountryCode == "" {
			continue
		}
		if count[a.CountryCode] == 0 {
			order = append(order, a.CountryCode)
		}
		count[a.CountryCode]++
		name[a.CountryCode] = orAny(a.Country, a.CountryCode)
	}
	slices.SortStableFunc(order, func(x, y string) int { return count[y] - count[x] })
	var parts []string
	for _, cc := range first(order, 3) {
		parts = append(parts, strings.TrimSpace(flag(cc)+" "+name[cc]))
	}
	if extra := len(order) - len(parts); extra > 0 {
		return strings.Join(parts, ", ") + " and " + plural(extra, "other country", "other countries")
	}
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

// Subline supports the headline with the most useful single fact.
func (r *Report) Subline() string {
	var out []string
	switch r.mood() {
	case moodRogue, moodAgents:
		if d, ok := r.deepest(); ok && d.Capability > 0 {
			out = append(out, fmt.Sprintf("The deepest, %s, reached depth %d of 7: %s.", r.addr(d.Source), d.Capability, d.Depth))
		}
		pool := r.Rogue
		if len(pool) == 0 {
			pool = r.Agents
		}
		if o := originList(pool); o != "" {
			out = append(out, "They came from "+o+".")
		}
	default:
		out = append(out, fmt.Sprintf("%s in the last %s", plural(r.Overview.Totals.Sources, "visitor", "visitors"), r.window()))
		if c := r.topClass(); c != "" {
			out[0] += ", mostly " + strings.ToLower(pluralLabel(c))
		}
		out[0] += "."
	}
	return strings.Join(out, " ")
}

// topClass is the most common visitor class, or "" with no visitors.
func (r *Report) topClass() string {
	best, n := "", 0
	for _, c := range classOrder {
		if r.Classes[c] > n {
			best, n = c, r.Classes[c]
		}
	}
	return best
}

var classOrder = []string{"rogue_agent", "ai_agent", "scanner", "crawler", "browser", "unknown"}

func pluralLabel(class string) string {
	switch class {
	case "rogue_agent":
		return "Rogue agents"
	case "ai_agent":
		return "AI agents"
	case "scanner":
		return "Scanners"
	case "crawler":
		return "Crawlers"
	case "browser":
		return "Browser-like visitors"
	}
	return "Unclassified"
}

// Subject leads with the verdict so the inbox line alone says whether to open
// it; the persona prefix keeps mail filters working.
func (r *Report) Subject(persona string) string {
	var tail []string
	if n := r.critical(); n > 0 {
		tail = append(tail, fmt.Sprintf("%d critical (went deep, decoys only)", n))
	}
	if r.mood() == moodRogue && len(r.Agents) > 0 {
		tail = append(tail, plural(len(r.Agents), "AI agent", "AI agents"))
	}
	if r.mood() != moodRogue {
		tail = append(tail, plural(r.Overview.Totals.Sources, "visitor", "visitors"))
	}
	s := fmt.Sprintf("[%s] %s", persona, r.Headline())
	if len(r.Ingest.Problems) > 0 {
		s = fmt.Sprintf("[%s] ⚠ Ingestion problem — %s", persona, r.Headline())
	}
	if len(tail) > 0 {
		s += " · " + strings.Join(tail, " · ")
	}
	return s + " — " + r.Until.Format("Jan 2")
}
