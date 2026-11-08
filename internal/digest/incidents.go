package digest

import (
	"fmt"
	"slices"
	"strings"
	"time"
)

// An incident is one address's progress through the planted-credential chain
// (internal/correlate). Its severity says how deep the address got, never that
// anything real was harmed: every credential in the chain is a decoy. The
// digest spells that out next to every severity label so "critical" reads as
// "went deepest", not as "we were breached".

type incident struct {
	Source     string    `json:"source"`
	Spokes     []string  `json:"spokes"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Stages     []int     `json:"stages"`
	Score      int       `json:"score"`
	Severity   string    `json:"severity"`
	CrossSpoke bool      `json:"cross_spoke"`
	OutOfBand  bool      `json:"out_of_band"`
	Relayed    bool      `json:"relayed"`
}

var severityOrder = []string{"critical", "high", "medium", "low"}

// severityMeaning says in plain words what an address did to earn a
// severity. Severity follows the incident score (internal/correlate): each
// planted secret taken or used adds points, so an address can be critical by
// using one deep secret or by collecting several.
func severityMeaning(sev string) string {
	switch sev {
	case "critical":
		return "used a deep secret, collected several (say the database password, cloud keys and a cluster token), or carried a planted key to other infrastructure (score 50+)"
	case "high":
		return "got hold of a deep secret such as a provider key, cloud credential or password (score 25–49)"
	case "medium":
		return "used a planted credential it was shown (score 15–24)"
	}
	return "was shown a planted credential and went no further (score under 15)"
}

// stageLabel names a chain stage the same way for every persona: odd stages
// hand out bait, even stages use it.
func stageLabel(stage int) string {
	switch stage {
	case 1:
		return "shown a planted key"
	case 2:
		return "used a planted key"
	case 3:
		return "found a deep secret"
	case 4:
		return "used a deep secret"
	}
	return fmt.Sprintf("stage %d", stage)
}

// noAction is the answer to "do I need to do anything?", shown with every
// incident list.
const noAction = "Nothing real is at risk: every key, password and token involved is a decoy that works only inside the trap, so there is nothing to rotate or patch."

// suggestedAction is the optional follow-up for the worst severity present.
func suggestedAction(sev string) string {
	switch sev {
	case "critical", "high":
		return "Optional: open the address in the dashboard to read exactly what it did, and report it to its network owner's abuse contact."
	}
	return "No follow-up needed."
}

func (inc incident) flags() []string {
	var out []string
	if inc.Relayed {
		out = append(out, "a key shown to one address was used from another")
	}
	if inc.OutOfBand {
		out = append(out, "used a key it was never shown here")
	}
	if inc.CrossSpoke || len(inc.Spokes) > 1 {
		out = append(out, "active on more than one node")
	}
	return out
}

func (inc incident) path() string {
	var parts []string
	for _, s := range inc.Stages {
		parts = append(parts, stageLabel(s))
	}
	return strings.Join(parts, " → ")
}

// critical is the number of critical incidents in the window.
func (r *Report) critical() int { return r.Overview.Severity["critical"] }

// sortIncidents puts the most severe, then highest-scoring, then latest first.
func sortIncidents(incs []incident) {
	rank := func(s string) int {
		if i := slices.Index(severityOrder, s); i >= 0 {
			return i
		}
		return len(severityOrder)
	}
	slices.SortStableFunc(incs, func(a, b incident) int {
		if d := rank(a.Severity) - rank(b.Severity); d != 0 {
			return d
		}
		if d := b.Score - a.Score; d != 0 {
			return d
		}
		return b.LastSeen.Compare(a.LastSeen)
	})
}

// worst is the most severe label among the incidents, or "".
func (r *Report) worst() string {
	for _, s := range severityOrder {
		if slices.ContainsFunc(r.Incidents, func(i incident) bool { return i.Severity == s }) {
			return s
		}
	}
	return ""
}

const maxIncidents = 15

// writeIncidents renders the plain-text incident list.
func (r *Report) writeIncidents(w func(string, ...any)) {
	w("INCIDENTS (%d)  critical %d · high %d · medium %d", len(r.Incidents), r.critical(), r.Overview.Severity["high"], r.Overview.Severity["medium"])
	w("  An incident is one address working through the planted credentials.")
	if len(r.Incidents) == 0 {
		w("  none")
		return
	}
	w("  %s", noAction)
	w("  %s", suggestedAction(r.worst()))
	for _, inc := range first(r.Incidents, maxIncidents) {
		w("  [%s] %s — %s", strings.ToUpper(inc.Severity), r.addr(inc.Source), severityMeaning(inc.Severity))
		w("    reached: %s (score %d)", inc.path(), inc.Score)
		for _, f := range inc.flags() {
			w("    note: %s", f)
		}
		w("    seen %s – %s UTC", inc.FirstSeen.UTC().Format("Jan 2 15:04"), inc.LastSeen.UTC().Format("Jan 2 15:04"))
	}
	if extra := len(r.Incidents) - maxIncidents; extra > 0 {
		w("  +%d more in the dashboard", extra)
	}
}

// incidents renders the HTML incident section.
func (r *Report) incidents(m *page) {
	if len(r.Incidents) == 0 {
		return
	}
	m.open("Incidents", "Each incident is one address working through the planted credentials. Severity says how deep it got, not how much damage was done.", len(r.Incidents))
	m.p(`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="margin-bottom:14px;background:%s;border-radius:10px"><tr><td style="padding:12px 16px;font:13.5px/1.55 %s;color:%s">`, cQuietBg, fontStack, cBody)
	m.p(`<b style="color:%s">Do I need to act?</b> %s %s</td></tr></table>`, cInk, esc(noAction), esc(suggestedAction(r.worst())))
	shown := first(r.Incidents, maxIncidents)
	for i, inc := range shown {
		top := ifs(i > 0, "border-top:1px solid "+cLine+";", "")
		fg, bg := sevColors(inc.Severity)
		m.p(`<div style="%spadding:12px 0">`, top)
		chip(m, inc.Severity, fg, bg)
		m.p(`<span style="font:600 14px/1.5 %s;color:%s">%s</span>`, monoStack, cInk, esc(r.addr(inc.Source)))
		m.p(`<div style="font:13.5px/1.5 %s;color:%s;margin-top:2px">%s</div>`, fontStack, cBody, esc(capitalize(severityMeaning(inc.Severity))+"."))
		m.p(`<div style="font:12.5px/1.5 %s;color:%s;margin-top:4px">Reached: %s · score %d</div>`, fontStack, cMuted, esc(inc.path()), inc.Score)
		for _, f := range inc.flags() {
			m.p(`<div style="font:12.5px/1.5 %s;color:%s">Note: %s</div>`, fontStack, cMuted, esc(f))
		}
		m.p(`<div style="font:12px/1.5 %s;color:%s;margin-top:2px">%s – %s UTC</div></div>`, fontStack, cFaint,
			inc.FirstSeen.UTC().Format("Jan 2, 15:04"), inc.LastSeen.UTC().Format("Jan 2, 15:04"))
	}
	if extra := len(r.Incidents) - len(shown); extra > 0 {
		m.p(`<div style="font:12.5px/1.5 %s;color:%s">+%d more in the dashboard</div>`, fontStack, cMuted, extra)
	}
	m.close()
}

// severityLegend explains every label once, for the footer of both bodies.
func severityLegend() []string {
	out := make([]string, 0, len(severityOrder))
	for _, s := range severityOrder {
		out = append(out, capitalize(s)+": "+severityMeaning(s)+".")
	}
	return out
}
