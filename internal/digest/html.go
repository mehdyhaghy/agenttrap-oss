package digest

import (
	"fmt"
	"html"
	"strings"

	"agenttrap/internal/geo"
)

// The HTML digest is built for email clients: tables for layout, inline
// styles only, no web fonts, images or scripts, and an explicit light theme so
// clients that invert colors still render it legibly. Every color carries a
// text label too, so meaning survives clients that strip styles.

const (
	cInk      = "#1a1a19"
	cBody     = "#3d3c39"
	cMuted    = "#6b6a66"
	cFaint    = "#9a9892"
	cLine     = "#ebeae6"
	cPage     = "#f3f2ee"
	cSoft     = "#f7f6f3"
	cTrack    = "#e7e5df"
	cRogue    = "#d03b3b"
	cRogueBg  = "#fdf0ef"
	cAgent    = "#2a78d6"
	cAgentBg  = "#eef4fc"
	cQuiet    = "#2f9e6e"
	cQuietBg  = "#eef7f2"
	cScanner  = "#d9912b"
	cCrawler  = "#2f9e6e"
	cBrowser  = "#8b8a85"
	cUnknown  = "#cfcdc6"
	fontStack = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
	monoStack = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace"
)

var classColor = map[string]string{
	"rogue_agent": cRogue, "ai_agent": cAgent, "scanner": cScanner,
	"crawler": cCrawler, "browser": cBrowser, "unknown": cUnknown,
}

type page struct{ b strings.Builder }

func (m *page) p(format string, args ...any) { fmt.Fprintf(&m.b, format, args...) }

var esc = html.EscapeString

// HTML renders the digest as an email-safe HTML document.
func (r *Report) HTML() string {
	m := &page{}
	band, bandBg := cQuiet, cQuietBg
	switch r.mood() {
	case moodRogue:
		band, bandBg = cRogue, cRogueBg
	case moodAgents:
		band, bandBg = cAgent, cAgentBg
	}

	m.p(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">`)
	m.p(`<meta name="color-scheme" content="light"><meta name="supported-color-schemes" content="light"><title>%s</title></head>`, esc(r.Headline()))
	m.p(`<body style="margin:0;padding:0;background:%s;-webkit-text-size-adjust:100%%">`, cPage)
	// Preheader: the inbox preview line under the subject.
	m.p(`<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent">%s</div>`, esc(r.Subline()))
	m.p(`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background:%s"><tr><td align="center" style="padding:28px 12px 40px">`, cPage)
	m.p(`<table role="presentation" width="640" cellpadding="0" cellspacing="0" style="width:100%%;max-width:640px">`)

	// Masthead.
	m.p(`<tr><td style="padding:0 4px 12px"><table role="presentation" width="100%%" cellpadding="0" cellspacing="0"><tr>`)
	m.p(`<td style="font:600 13px/1.4 %s;color:%s;letter-spacing:.2px"><span style="color:%s">&#9673;</span>&nbsp; AgentTrap%s</td>`,
		fontStack, cInk, band, personaSuffix(r.Persona))
	m.p(`<td align="right" style="font:13px/1.4 %s;color:%s">%s – %s UTC</td>`, fontStack, cMuted,
		r.Since.Format("Jan 2, 15:04"), r.Until.Format("Jan 2, 15:04"))
	m.p(`</tr></table></td></tr>`)

	r.ingestWarning(m)
	r.hero(m, band, bandBg)
	r.incidents(m)
	if len(r.Rogue) > 0 {
		m.open("Rogue agents", "They used a planted credential after being shown it. Deepest first: depth runs from 0 (looked around) to 7 (exfiltrated).", len(r.Rogue))
		for i, a := range r.Rogue {
			r.rogueCard(m, a, i == len(r.Rogue)-1)
		}
		m.close()
	}
	if len(r.Agents) > 0 {
		m.open("AI agents", "Read agent-facing content or spoke MCP, but used no bait.", len(r.Agents))
		r.agentRows(m)
		m.close()
	}
	r.coordination(m)
	r.exploits(m)
	r.traps(m)
	r.introductions(m)
	r.disguised(m)
	r.origins(m)
	r.mix(m)
	r.footer(m)

	m.p(`</table></td></tr></table></body></html>`)
	return m.b.String()
}

func personaSuffix(p string) string {
	if p == "" {
		return ""
	}
	return ` <span style="color:#9a9892;font-weight:400">for</span> ` + esc(p)
}

// open starts a white section card with a title, count and one-line intro.
func (m *page) open(title, intro string, count int) {
	m.p(`<tr><td style="padding-top:16px"><table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid %s;border-radius:14px"><tr><td style="padding:22px 24px">`, cLine)
	m.p(`<div style="font:650 17px/1.3 %s;color:%s">%s`, fontStack, cInk, esc(title))
	if count > 0 {
		m.p(` <span style="font-weight:500;color:%s">&nbsp;%d</span>`, cFaint, count)
	}
	m.p(`</div>`)
	if intro != "" {
		m.p(`<div style="font:13.5px/1.5 %s;color:%s;margin:4px 0 16px">%s</div>`, fontStack, cMuted, esc(intro))
	} else {
		m.p(`<div style="height:14px;line-height:14px">&nbsp;</div>`)
	}
}

func (m *page) close() { m.p(`</td></tr></table></td></tr>`) }

func (r *Report) hero(m *page, band, bandBg string) {
	m.p(`<tr><td><table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid %s;border-top:5px solid %s;border-radius:14px"><tr><td style="padding:28px 28px 24px">`, cLine, band)
	m.p(`<div style="font:600 11.5px/1.2 %s;color:%s;letter-spacing:1.2px;text-transform:uppercase">Findings · last %s</div>`, fontStack, band, esc(r.window()))
	m.p(`<div style="font:700 27px/1.25 %s;color:%s;margin:10px 0 8px;letter-spacing:-.3px">%s</div>`, fontStack, cInk, esc(r.Headline()))
	m.p(`<div style="font:15px/1.55 %s;color:%s">%s</div>`, fontStack, cBody, esc(r.Subline()))

	crit := r.critical()
	tiles := []struct {
		label string
		n     int
		color string
	}{
		{"Rogue agents", len(r.Rogue), ifs(len(r.Rogue) > 0, cRogue, cInk)},
		{"AI agents", len(r.Agents), ifs(len(r.Agents) > 0, cAgent, cInk)},
		{"Critical: went deep into the decoy", crit, ifs(crit > 0, cRogue, cInk)},
		{"Visitors", r.Overview.Totals.Sources, cInk},
	}
	m.p(`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="margin-top:22px;background:%s;border-radius:10px"><tr>`, bandBg)
	for i, t := range tiles {
		sep := ""
		if i > 0 {
			sep = "border-left:1px solid rgba(0,0,0,.06);"
		}
		m.p(`<td width="25%%" valign="top" style="padding:14px 14px 12px;%s"><div style="font:700 26px/1.1 %s;color:%s">%d</div><div style="font:12px/1.35 %s;color:%s;margin-top:4px">%s</div></td>`,
			sep, fontStack, t.color, t.n, fontStack, cMuted, esc(t.label))
	}
	m.p(`</tr></table></td></tr></table></td></tr>`)
}

// ingestWarning heads the mail when events are not reaching the hub: an "all
// quiet" verdict means nothing if nothing could be recorded.
func (r *Report) ingestWarning(m *page) {
	if len(r.Ingest.Problems) == 0 {
		return
	}
	m.p(`<tr><td style="padding-bottom:16px"><table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="background:%s;border:1px solid %s;border-radius:14px"><tr><td style="padding:18px 22px">`, cRogueBg, cRogue)
	m.p(`<div style="font:700 16px/1.35 %s;color:%s">&#9888;&nbsp; Ingestion problem — the numbers below are incomplete</div>`, fontStack, cRogue)
	for _, p := range r.Ingest.Problems {
		m.p(`<div style="font:13.5px/1.5 %s;color:%s;margin-top:6px">%s</div>`, fontStack, cBody, esc(p))
	}
	m.p(`</td></tr></table></td></tr>`)
}

func ifs(c bool, a, b string) string {
	if c {
		return a
	}
	return b
}

// ladder draws the 0-7 depth meter: filled segments up to the actor's depth.
func ladder(m *page, depth int, color string, seg int, label string) {
	m.p(`<table role="presentation" cellpadding="0" cellspacing="0" style="display:inline-table;vertical-align:middle"><tr>`)
	for i := range 7 {
		c := cTrack
		if i < depth {
			c = color
		}
		m.p(`<td style="padding:0 2px 0 0"><div style="width:%dpx;height:8px;background:%s;border-radius:2px;font-size:0;line-height:0">&nbsp;</div></td>`, seg, c)
	}
	if label != "" {
		m.p(`<td style="padding-left:8px;font:13px/1.3 %s;color:%s;white-space:nowrap">%s</td>`, fontStack, cBody, label)
	}
	m.p(`</tr></table>`)
}

func chip(m *page, text, fg, bg string) {
	m.p(`<span style="display:inline-block;margin:0 5px 5px 0;padding:2px 9px;border-radius:999px;background:%s;color:%s;font:12px/1.6 %s">%s</span>`, bg, fg, fontStack, esc(text))
}

// who renders a flagged address and its country for a card heading.
func (r *Report) who(m *page, a actor, size int) {
	m.p(`<span style="font:600 %dpx/1.3 %s;color:%s">%s</span>`, size, monoStack, cInk, esc(r.addr(a.Source)))
	if a.Country != "" || a.Network != "" {
		m.p(`<span style="font:13px/1.3 %s;color:%s">&nbsp;&nbsp;%s</span>`, fontStack, cMuted, esc(strings.Join(nonEmpty(a.Country, a.Network), " · ")))
	}
}

func nonEmpty(ss ...string) []string {
	var out []string
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (r *Report) rogueCard(m *page, a actor, last bool) {
	gap := "16px"
	if last {
		gap = "0"
	}
	m.p(`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="margin-bottom:%s;border:1px solid %s;border-left:4px solid %s;border-radius:10px"><tr><td style="padding:16px 18px">`, gap, cLine, cRogue)
	m.p(`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0"><tr><td>`)
	r.who(m, a, 15)
	m.p(`</td><td align="right" style="font:12px/1.3 %s;color:%s;white-space:nowrap">score <b style="color:%s">%d</b></td></tr></table>`, fontStack, cMuted, cInk, a.Score)

	m.p(`<div style="margin:10px 0 12px">`)
	ladder(m, a.Capability, cRogue, 22, fmt.Sprintf(`<b style="color:%s">Depth %d/7</b> · %s`, cInk, a.Capability, esc(a.Depth)))
	m.p(`</div>`)

	var chips []string
	if sw := software(a); sw != "" {
		chips = append(chips, sw)
	} else if ua := first(a.UserAgents, 1); len(ua) > 0 {
		chips = append(chips, clip(ua[0], 44))
	}
	if a.SessionSize > 1 {
		chips = append(chips, fmt.Sprintf("one of %d addresses", a.SessionSize))
	}
	if a.CampaignID != "" {
		chips = append(chips, "campaign "+a.CampaignID)
	}
	if len(chips) > 0 {
		m.p(`<div>`)
		for _, c := range chips {
			chip(m, c, cBody, cSoft)
		}
		m.p(`</div>`)
	}

	m.p(`<ul style="margin:6px 0 0;padding-left:18px;font:14px/1.6 %s;color:%s">`, fontStack, cBody)
	for _, reason := range first(a.Reasons, 4) {
		m.p(`<li style="margin:0 0 2px">%s</li>`, esc(reason))
	}
	m.p(`</ul>`)

	if t := touches(a); len(t) > 0 {
		m.p(`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="margin-top:12px;background:%s;border-radius:8px">`, cSoft)
		for _, x := range t {
			m.p(`<tr><td valign="top" style="padding:7px 12px;font:600 12.5px/1.5 %s;color:%s;white-space:nowrap;width:1%%">%s</td><td style="padding:7px 12px 7px 0;font:13px/1.5 %s;color:%s">%s</td></tr>`,
				fontStack, ifs(x.severe, cRogue, cInk), esc(x.what), fontStack, cBody, esc(x.detail))
			for _, c := range x.lines {
				m.p(`<tr><td></td><td style="padding:0 12px 6px 0;font:12px/1.5 %s;color:%s;word-break:break-all">%s</td></tr>`, monoStack, cMuted, esc(c))
			}
		}
		m.p(`</table>`)
	}

	if len(r.Prompts[a.Source]) > 0 {
		m.p(`<div style="font:600 11.5px/1.2 %s;color:%s;letter-spacing:.8px;text-transform:uppercase;margin:14px 0 -4px">In its own words</div>`, fontStack, cMuted)
	}
	for _, pr := range r.Prompts[a.Source] {
		m.p(`<div style="margin-top:10px;padding:10px 14px;border-left:3px solid %s;background:%s;border-radius:0 8px 8px 0;font:italic 14px/1.5 Georgia,'Times New Roman',serif;color:%s">&ldquo;%s&rdquo;</div>`,
			cRogue, cRogueBg, cInk, esc(strings.TrimPrefix(pr, "(A2A) ")))
	}
	m.p(`</td></tr></table>`)
}

// touch is one surface of the estate an actor reached.
type touch struct {
	what, detail string
	lines        []string
	severe       bool
}

func touches(a actor) []touch {
	f := a.Features
	var out []touch
	if f.SSHLogins > 0 || f.SSHAuthFails > 0 {
		out = append(out, touch{what: "SSH node", severe: f.SSHLogins > 0,
			detail: fmt.Sprintf("%s, %s as %s", plural(f.SSHLogins, "session", "sessions"), plural(f.SSHAuthFails, "failed login", "failed logins"), orAny(strings.Join(first(f.SSHUsernames, 3), ", "), "?")),
			lines:  prefixed("$ ", first(f.SSHCommands, 4))})
	}
	if f.PGConnects > 0 {
		d := fmt.Sprintf("%s as %s, %s", plural(f.PGConnects, "connection", "connections"), clip(orAny(f.PGUser, "?"), 30), plural(len(f.PGQueries), "query", "queries"))
		if f.PGLogin {
			d += " — logged in with a planted password"
		}
		out = append(out, touch{what: "Postgres", detail: d, severe: f.PGLogin, lines: prefixed("sql> ", first(f.PGQueries, 3))})
	}
	if f.RedisConnects > 0 {
		out = append(out, touch{what: "Redis", detail: strings.TrimPrefix(fmt.Sprintf("%s, %s%s", plural(f.RedisConnects, "connection", "connections"), plural(len(f.RedisCommands), "command", "commands"), redisTakeoverNote(a)), " "), severe: f.RedisTakeover > 0})
	}
	if f.CloudCalls > 0 || f.IMDSCreds {
		d := plural(f.CloudCalls, "call", "calls")
		if len(f.CloudServices) > 0 {
			d += " to " + strings.Join(first(f.CloudServices, 5), ", ")
		}
		if f.CloudSecretReads > 0 {
			d += fmt.Sprintf(" — read %s", plural(f.CloudSecretReads, "secret", "secrets"))
		}
		if f.IMDSCreds {
			d += " — took the instance role"
		}
		out = append(out, touch{what: "AWS", detail: d, severe: f.IMDSCreds || f.CloudSecretReads > 0})
	}
	if f.KubeCalls > 0 {
		d := plural(f.KubeCalls, "call", "calls")
		if f.KubeSecretReads > 0 {
			d += " — read " + plural(f.KubeSecretReads, "secret", "secrets")
		}
		out = append(out, touch{what: "Kubernetes", detail: d, severe: f.KubeSecretReads > 0})
	}
	if f.MemorySearches+f.MemoryReads+f.MemoryWrites > 0 {
		d := fmt.Sprintf("%s, %s", plural(f.MemorySearches, "search", "searches"), plural(f.MemoryReads, "read", "reads"))
		if f.MemoryCredSearch {
			d += ", hunting for credentials"
		}
		if f.MemoryWrites > 0 {
			d += ", " + plural(f.MemoryWrites, "write", "writes")
		}
		out = append(out, touch{what: "Team memory", detail: d, severe: f.MemorySecretReads > 0})
	}
	if f.KBSearches+f.KBReads > 0 {
		d := fmt.Sprintf("%s, %s", plural(f.KBSearches, "search", "searches"), plural(f.KBReads, "retrieval", "retrievals"))
		if f.KBCredSearch {
			d += ", hunting for credentials"
		}
		out = append(out, touch{what: "Knowledge base", detail: d, severe: f.KBSecretReads > 0})
	}
	if len(f.Exfil) > 0 {
		out = append(out, touch{what: "Exfiltration", severe: true, detail: strings.Join(f.Exfil, ", ") + " → " + clip(orAny(f.ExfilDest, "?"), 60)})
	} else if f.EgressAttempts > 0 {
		out = append(out, touch{what: "Outbound", detail: plural(f.EgressAttempts, "attempt", "attempts") + ifs(len(f.EgressDests) > 0, ", e.g. "+clip(first(f.EgressDests, 1)[0], 60), "")})
	}
	return out
}

func prefixed(p string, ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = p + clip(s, 110)
	}
	return out
}

// clientOf names the software an address declared, if any.
func (r *Report) clientOf(src string) string {
	for _, c := range r.Clients {
		for _, s := range c.Sources {
			if s == src {
				return c.Name
			}
		}
	}
	return ""
}

func (r *Report) agentRows(m *page) {
	m.p(`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0">`)
	for i, a := range r.Agents {
		top := ""
		if i > 0 {
			top = "border-top:1px solid " + cLine + ";"
		}
		client := r.clientOf(a.Source)
		if client == "" {
			client = software(a)
		}
		if client == "" && len(a.UserAgents) > 0 {
			client = clip(a.UserAgents[0], 40)
		}
		m.p(`<tr><td valign="top" style="%spadding:12px 0">`, top)
		r.who(m, a, 14)
		if len(a.Reasons) > 0 {
			m.p(`<div style="font:13px/1.5 %s;color:%s;margin-top:3px">%s</div>`, fontStack, cMuted, esc(a.Reasons[0]))
		}
		m.p(`</td><td valign="top" align="right" style="%spadding:12px 0 12px 12px;white-space:nowrap">`, top)
		if client != "" {
			m.p(`<div style="margin-bottom:6px">`)
			chip(m, client, cAgent, cAgentBg)
			m.p(`</div>`)
		}
		ladder(m, a.Capability, cAgent, 9, fmt.Sprintf(`<span style="font-size:12px;color:%s">%d/7</span>`, cMuted, a.Capability))
		m.p(`</td></tr>`)
	}
	m.p(`</table>`)
}

// coordination groups multi-address sessions and campaigns: activity that is
// one operator behind several addresses.
func (r *Report) coordination(m *page) {
	if len(r.Sessions)+len(r.Campaigns) == 0 {
		return
	}
	m.open("Coordinated activity", "Addresses tied together as one operator: a shared key, the same client software or the same behavior.", len(r.Sessions)+len(r.Campaigns))
	block := func(title, pillText, pillFg, pillBg string, members []string, why string, last bool) {
		gap := ifs(last, "0", "12px")
		m.p(`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="margin-bottom:%s;background:%s;border-radius:10px"><tr><td style="padding:14px 16px">`, gap, cSoft)
		if pillText != "" {
			chip(m, pillText, pillFg, pillBg)
		}
		m.p(`<span style="font:600 14px/1.5 %s;color:%s">%s</span><div style="margin-top:8px">`, fontStack, cInk, esc(title))
		for _, s := range first(members, 8) {
			m.p(`<span style="display:inline-block;margin:0 6px 6px 0;padding:3px 9px;background:#ffffff;border:1px solid %s;border-radius:6px;font:12.5px/1.5 %s;color:%s">%s</span>`, cLine, monoStack, cInk, esc(r.addr(s)))
		}
		if len(members) > 8 {
			m.p(`<span style="font:12.5px %s;color:%s">+%d more</span>`, fontStack, cMuted, len(members)-8)
		}
		m.p(`</div><div style="font:12.5px/1.5 %s;color:%s">Linked by: %s</div></td></tr></table>`, fontStack, cMuted, esc(why))
	}
	n := len(r.Sessions) + len(r.Campaigns)
	i := 0
	for _, k := range r.Campaigns {
		i++
		fg, bg := sevColors(k.Severity)
		block(k.Summary, k.Severity, fg, bg, k.Members, strings.Join(first(k.Joins, 2), "; "), i == n)
	}
	for _, s := range r.Sessions {
		i++
		block(fmt.Sprintf("One %s behind %d addresses", strings.ToLower(label(s.Class)), len(s.Members)), "", "", "", s.Members, strings.Join(s.Links, "; "), i == n)
	}
	m.close()
}

func sevColors(sev string) (string, string) {
	switch sev {
	case "critical":
		return "#ffffff", cRogue
	case "high":
		return "#8a3a12", "#fbe3d6"
	case "medium":
		return "#7a5410", "#fbefd4"
	}
	return cBody, cTrack
}

// traps shows the canary stages that were reached; untouched ones collapse
// into a single line so the section reads as what happened.
func (r *Report) traps(m *page) {
	maxN, hit := 1, 0
	for _, f := range r.Overview.Funnel {
		maxN = max(maxN, f.Sources)
		if f.Sources > 0 {
			hit++
		}
	}
	if hit == 0 && r.TrialKeys == 0 {
		return
	}
	m.open("Traps sprung", "Planted credentials and how many addresses reached each one.", 0)
	m.p(`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0">`)
	for _, f := range r.Overview.Funnel {
		if f.Sources == 0 {
			continue
		}
		w := max(3, 100*f.Sources/maxN)
		m.p(`<tr><td style="padding:5px 12px 5px 0;font:13.5px/1.4 %s;color:%s;width:45%%">%s</td>`, fontStack, cBody, esc(capitalize(f.Name)))
		m.p(`<td style="padding:5px 0"><table role="presentation" width="%d%%" cellpadding="0" cellspacing="0"><tr><td style="height:10px;background:%s;border-radius:5px;font-size:0;line-height:0">&nbsp;</td></tr></table></td>`, w, cRogue)
		m.p(`<td align="right" style="padding:5px 0 5px 12px;font:600 13.5px/1.4 %s;color:%s;width:32px">%d</td></tr>`, fontStack, cInk, f.Sources)
	}
	m.p(`</table>`)
	var notes []string
	if idle := len(r.Overview.Funnel) - hit; idle > 0 {
		notes = append(notes, plural(idle, "other trap", "other traps")+" not reached")
	}
	notes = append(notes, plural(r.TrialKeys, "trial key", "trial keys")+" issued")
	if len(r.NewFingerprint) > 0 {
		notes = append(notes, plural(len(r.NewFingerprint), "new TLS fingerprint", "new TLS fingerprints"))
	}
	m.p(`<div style="font:12.5px/1.5 %s;color:%s;margin-top:10px">%s</div>`, fontStack, cMuted, esc(strings.Join(notes, " · ")))
	if d := r.deceptionLines(); len(d) > 0 {
		m.p(`<div style="font:600 13px/1.4 %s;color:%s;margin:16px 0 6px">Deception</div><ul style="margin:0;padding-left:18px;font:13.5px/1.6 %s;color:%s">`, fontStack, cInk, fontStack, cBody)
		for _, l := range d {
			m.p(`<li>%s</li>`, esc(l))
		}
		m.p(`</ul>`)
	}
	m.close()
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// introductions lists software that named itself and integration sign-ups.
func (r *Report) introductions(m *page) {
	if len(r.Clients)+len(r.Registrations) == 0 {
		return
	}
	m.open("Who introduced themselves", "Client software that declared its name, and agents that registered an integration.", len(r.Clients)+len(r.Registrations))
	m.p(`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0">`)
	row := func(i int, name, via, who string) {
		top := ifs(i > 0, "border-top:1px solid "+cLine+";", "")
		m.p(`<tr><td valign="top" style="%spadding:10px 12px 10px 0;font:600 14px/1.45 %s;color:%s">%s<div style="font:12.5px/1.45 %s;color:%s;font-weight:400">%s</div></td>`, top, fontStack, cInk, esc(name), fontStack, cMuted, esc(via))
		m.p(`<td valign="top" align="right" style="%spadding:10px 0;font:12.5px/1.6 %s;color:%s">%s</td></tr>`, top, monoStack, cBody, who)
	}
	i := 0
	for _, c := range first(r.Clients, 12) {
		row(i, c.Name, c.Via, strings.ReplaceAll(esc(r.addrs(c.Sources, 4)), ", ", "<br>"))
		i++
	}
	for _, e := range r.Registrations {
		name := fmt.Sprint(e.Detail["agent"])
		via := fmt.Sprintf("registered via %v · purpose: %v", e.Detail["breadcrumb"], e.Detail["purpose"])
		row(i, name, via, esc(r.addr(e.Source)))
		i++
	}
	m.p(`</table>`)
	m.close()
}

// disguised covers automation posing as a browser and fake crawlers.
func (r *Report) disguised(m *page) {
	if len(r.Automation)+len(r.Impersonators) == 0 {
		return
	}
	m.open("In disguise", "Automation that posed as a browser, and bots that claimed to be a search crawler.", len(r.Automation)+len(r.Impersonators))
	m.p(`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0">`)
	i := 0
	row := func(a actor, what string) {
		top := ifs(i > 0, "border-top:1px solid "+cLine+";", "")
		m.p(`<tr><td valign="top" style="%spadding:10px 0">`, top)
		r.who(m, a, 13)
		m.p(`<div style="font:13px/1.5 %s;color:%s;margin-top:3px">%s</div></td></tr>`, fontStack, cMuted, esc(what))
		i++
	}
	for _, a := range first(r.Automation, 8) {
		row(a, strings.Join(first(a.Reasons, 2), "; "))
	}
	for _, a := range first(r.Impersonators, 8) {
		row(a, "claimed to be "+clip(strings.Join(first(a.UserAgents, 1), ""), 80))
	}
	m.p(`</table>`)
	m.close()
}

func (r *Report) origins(m *page) {
	if len(r.Countries) == 0 {
		return
	}
	m.open("Where they came from", "", len(r.Countries))
	top := first(r.Countries, 6)
	maxN := max(1, top[0].Sources)
	m.p(`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0">`)
	for _, c := range top {
		w := max(3, 100*c.Sources/maxN)
		m.p(`<tr><td style="padding:5px 12px 5px 0;font:14px/1.4 %s;color:%s;width:42%%;white-space:nowrap">%s</td>`, fontStack, cInk, esc(countryName(c.Code, c.Name)))
		m.p(`<td style="padding:5px 0"><table role="presentation" width="%d%%" cellpadding="0" cellspacing="0"><tr><td style="height:10px;background:%s;border-radius:5px;font-size:0;line-height:0">&nbsp;</td></tr></table></td>`, w, cAgent)
		m.p(`<td align="right" style="padding:5px 0 5px 12px;font:600 13.5px/1.4 %s;color:%s;width:32px">%d</td></tr>`, fontStack, cInk, c.Sources)
	}
	m.p(`</table>`)
	if len(r.Countries) > len(top) {
		m.p(`<div style="font:12.5px/1.5 %s;color:%s;margin-top:8px">and %s more</div>`, fontStack, cMuted, plural(len(r.Countries)-len(top), "country", "countries"))
	}
	m.close()
}

// mix is a single stacked bar of visitors by class, with a legend.
func (r *Report) mix(m *page) {
	total := 0
	for _, c := range classOrder {
		total += r.Classes[c]
	}
	if total == 0 {
		return
	}
	m.open("Everyone who visited", fmt.Sprintf("%s from %s, classified by behavior.",
		plural(r.Overview.Totals.Requests, "request", "requests"), plural(total, "address", "addresses")), 0)
	m.p(`<table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="border-radius:6px;overflow:hidden"><tr>`)
	for _, c := range classOrder {
		if n := r.Classes[c]; n > 0 {
			m.p(`<td width="%d%%" style="height:14px;background:%s;font-size:0;line-height:0">&nbsp;</td>`, max(2, 100*n/total), classColor[c])
		}
	}
	m.p(`</tr></table><table role="presentation" width="100%%" cellpadding="0" cellspacing="0" style="margin-top:12px"><tr>`)
	for i, c := range classOrder {
		if i == 3 {
			m.p(`</tr><tr>`)
		}
		m.p(`<td width="33%%" style="padding:4px 0;font:13px/1.4 %s;color:%s"><span style="color:%s;font-size:14px">&#9632;</span>&nbsp; %s <b style="color:%s">%d</b></td>`,
			fontStack, cBody, classColor[c], esc(pluralLabel(c)), cInk, r.Classes[c])
	}
	m.p(`</tr></table>`)
	m.close()
}

func (r *Report) footer(m *page) {
	m.p(`<tr><td align="center" style="padding:22px 16px 0;font:12px/1.7 %s;color:%s">`, fontStack, cFaint)
	m.p(`%s · %s · operator traffic excluded<br>`,
		plural(r.Overview.Totals.Requests, "request", "requests"), plural(r.Overview.Totals.Fingerprints, "TLS fingerprint", "TLS fingerprints"))
	if len(r.Countries) > 0 {
		m.p(`%s<br>`, esc(geo.AttributionText))
	}
	m.p(`<div style="max-width:520px;margin:6px auto 10px;text-align:left">Severity is how deep an address got into the decoy, never real damage.<br>`)
	for _, l := range severityLegend() {
		m.p(`%s<br>`, esc(l))
	}
	m.p(`</div>Sent by AgentTrap%s.</td></tr>`, ifs(r.Persona != "", " for "+esc(r.Persona), ""))
}
