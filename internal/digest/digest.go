// Package digest builds the daily findings email from the hub admin API:
// behavior findings only (rogue and AI agents, sessions, incidents, crawler
// impersonation, registrations, browser automation, new fingerprints).
package digest

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"agenttrap/internal/geo"
)

// Client reads the hub admin API.
type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func (c *Client) get(ctx context.Context, path string, q url.Values, out any) error {
	u := c.BaseURL + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	hc := c.HTTP
	if hc == nil {
		hc = &http.Client{Timeout: 60 * time.Second}
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("%s: %s %s", path, resp.Status, strings.TrimSpace(string(b)))
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// Types mirror the admin API fields the digest uses.
type actor struct {
	Source       string   `json:"source"`
	Class        string   `json:"class"`
	Confidence   string   `json:"confidence"`
	Score        int      `json:"score"`
	Capability   int      `json:"capability"`
	Depth        string   `json:"depth"`
	Reasons      []string `json:"reasons"`
	UserAgents   []string `json:"user_agents"`
	JA4          []string `json:"ja4"`
	Network      string   `json:"network"`
	CountryCode  string   `json:"country_code"`
	Country      string   `json:"country"`
	CrawlerCheck string   `json:"crawler_check"`
	SessionSize  int      `json:"session_size"`
	CampaignID   string   `json:"campaign_id"`
	Frameworks   []struct {
		Name  string `json:"name"`
		Kind  string `json:"kind"`
		Level string `json:"level"`
	} `json:"frameworks"`
	Features struct {
		Requests          int      `json:"requests"`
		MaxStage          int      `json:"max_stage"`
		AgentName         string   `json:"agent_name"`
		AgentPurpose      string   `json:"agent_purpose"`
		TrialKeys         int      `json:"trial_keys"`
		Beacons           int      `json:"beacons"`
		SSHLogins         int      `json:"ssh_logins"`
		SSHAuthFails      int      `json:"ssh_auth_fails"`
		SSHUsernames      []string `json:"ssh_usernames"`
		SSHCommands       []string `json:"ssh_commands"`
		SSHClient         string   `json:"ssh_client"`
		RedisConnects     int      `json:"redis_connects"`
		RedisCommands     []string `json:"redis_commands"`
		RedisTakeover     int      `json:"redis_takeover"`
		RedisExfil        string   `json:"redis_exfil"`
		PGConnects        int      `json:"pg_connects"`
		PGLogin           bool     `json:"pg_login"`
		PGUser            string   `json:"pg_user"`
		PGQueries         []string `json:"pg_queries"`
		CloudCalls        int      `json:"cloud_calls"`
		CloudServices     []string `json:"cloud_services"`
		CloudSecretReads  int      `json:"cloud_secret_reads"`
		IMDSCreds         bool     `json:"imds_creds"`
		KubeCalls         int      `json:"kube_calls"`
		KubeSecretReads   int      `json:"kube_secret_reads"`
		EgressAttempts    int      `json:"egress_attempts"`
		EgressDests       []string `json:"egress_dests"`
		Exfil             []string `json:"exfil"`
		ExfilDest         string   `json:"exfil_dest"`
		MemorySearches    int      `json:"memory_searches"`
		MemoryCredSearch  bool     `json:"memory_cred_search"`
		MemoryReads       int      `json:"memory_reads"`
		MemorySecretReads int      `json:"memory_secret_reads"`
		MemoryWrites      int      `json:"memory_writes"`
		MemoryShares      int      `json:"memory_shares"`
		KBSearches        int      `json:"kb_searches"`
		KBCredSearch      bool     `json:"kb_cred_search"`
		KBReads           int      `json:"kb_reads"`
		KBSecretReads     int      `json:"kb_secret_reads"`
		Clicks            int      `json:"clicks"`
		KeyGaps           int      `json:"key_gaps"`
	} `json:"features"`
}

type session struct {
	Members   []string `json:"members"`
	Links     []string `json:"links"`
	Class     string   `json:"class"`
	UserAgent string   `json:"user_agent"`
}

type overview struct {
	Totals struct {
		Requests     int `json:"requests"`
		Sources      int `json:"sources"`
		Fingerprints int `json:"fingerprints"`
		CanaryUses   int `json:"canary_uses"`
	} `json:"totals"`
	Severity map[string]int `json:"severity"`
	Exploits []exploitStat  `json:"exploits"`
	Funnel   []struct {
		Name    string `json:"name"`
		Sources int    `json:"sources"`
	} `json:"funnel"`
}

type campaign struct {
	ID         string   `json:"id"`
	Members    []string `json:"members"`
	MaxStage   int      `json:"max_stage"`
	Severity   string   `json:"severity"`
	Frameworks []string `json:"frameworks"`
	Joins      []string `json:"joins"`
	Summary    string   `json:"summary"`
}

type deception struct {
	Lures []struct {
		Family  string  `json:"family"`
		Variant string  `json:"variant"`
		Shown   int     `json:"shown"`
		Called  int     `json:"called"`
		Rate    float64 `json:"rate"`
	} `json:"lures"`
	HintsShown    int            `json:"hints_shown"`
	HintsFollowed int            `json:"hints_followed"`
	HoneyScopes   map[string]int `json:"honey_scopes"`
	DecoyAgent    int            `json:"decoy_agent"`
	HoneyTools    int            `json:"honey_tools"`
}

// declaredClient is software that named itself: an OAuth client
// registration or an MCP clientInfo.
type declaredClient struct {
	Name, Via string
	Sources   []string
}

type event struct {
	Source string         `json:"source"`
	Kind   string         `json:"kind"`
	Path   string         `json:"path"`
	Detail map[string]any `json:"detail"`
}

// Report is the assembled digest.
type Report struct {
	Since, Until   time.Time
	Overview       overview
	Rogue, Agents  []actor
	Automation     []actor // automated browsers and forged browser user agents, classified otherwise
	Impersonators  []actor
	Sessions       []session
	Registrations  []event
	TrialKeys      int
	Prompts        map[string][]string // source -> prompt snippets (rogue/AI agents)
	NewFingerprint []string            // JA4 values first seen in the window
	Classes        map[string]int
	Campaigns      []campaign
	Incidents      []incident // active in the window, most severe first
	Deception      deception
	Clients        []declaredClient
	Persona        string            // the facade's name, shown in the masthead and footer
	CountryOf      map[string]string // source -> ISO country code, for flags
	Countries      []countryCount    // sources per country, most first
	Ingest         IngestHealth      // whether events are reaching the hub at all
}

// IngestHealth mirrors /admin/health. When it lists problems the numbers in the
// report undercount, so the digest leads with it.
type IngestHealth struct {
	OK       bool     `json:"ok"`
	Problems []string `json:"problems"`
	Spokes   []struct {
		SpokeID string `json:"spoke_id"`
		Status  string `json:"status"`
	} `json:"spokes"`
}

type countryCount struct {
	Code, Name string
	Sources    int
}

// Build collects the report for the last window.
func Build(ctx context.Context, c *Client, window time.Duration) (*Report, error) {
	hours := fmt.Sprint(int(window.Hours()))
	now := time.Now().UTC()
	r := &Report{Since: now.Add(-window), Until: now, Prompts: map[string][]string{}, CountryOf: map[string]string{}}
	if err := c.get(ctx, "/admin/overview", url.Values{"hours": {hours}}, &r.Overview); err != nil {
		return nil, err
	}
	if err := c.get(ctx, "/admin/health", nil, &r.Ingest); err != nil {
		r.Ingest = IngestHealth{Problems: []string{"could not check ingest health: " + err.Error()}}
	}
	var ops []struct {
		CIDR string `json:"cidr"`
	}
	if err := c.get(ctx, "/admin/operators", nil, &ops); err != nil {
		return nil, err
	}
	var opRanges []netip.Prefix
	for _, o := range ops {
		if p, err := netip.ParsePrefix(o.CIDR); err == nil {
			opRanges = append(opRanges, p)
		}
	}
	isOperator := func(src string) bool {
		a, err := netip.ParseAddr(src)
		return err == nil && slices.ContainsFunc(opRanges, func(p netip.Prefix) bool { return p.Contains(a.Unmap()) })
	}

	var ac struct {
		Summary  map[string]int `json:"summary"`
		Actors   []actor        `json:"actors"`
		Sessions []session      `json:"sessions"`
	}
	if err := c.get(ctx, "/admin/actors", url.Values{"hours": {hours}}, &ac); err != nil {
		return nil, err
	}
	// Count classes here rather than using the hub summary, so addresses in
	// operator ranges are left out of every number.
	r.Classes = map[string]int{}
	byCountry := map[string]*countryCount{}
	for _, a := range ac.Actors {
		if a.Class != "operator" && !isOperator(a.Source) {
			r.Classes[a.Class]++
			if a.CountryCode != "" {
				r.CountryOf[a.Source] = a.CountryCode
				c := byCountry[a.CountryCode]
				if c == nil {
					c = &countryCount{Code: a.CountryCode, Name: a.Country}
					byCountry[a.CountryCode] = c
				}
				c.Sources++
			}
		}
		switch {
		case a.Class == "operator" || isOperator(a.Source):
		case a.Class == "rogue_agent":
			r.Rogue = append(r.Rogue, a)
		case a.Class == "ai_agent":
			r.Agents = append(r.Agents, a)
		case a.CrawlerCheck == "impersonation":
			r.Impersonators = append(r.Impersonators, a)
		case a.Features.Beacons > 0 && hasReason(a, "automated browser", "synthetic input", "teleported", "exactly", "machine-regular"),
			hasReason(a, "forged a browser user agent", "TLS handshake", "TCP stack", "TLS extension order"):
			r.Automation = append(r.Automation, a)
		}
	}
	deepestFirst := func(a, b actor) int { return cmp.Or(b.Capability-a.Capability, b.Score-a.Score) }
	slices.SortStableFunc(r.Rogue, deepestFirst)
	slices.SortStableFunc(r.Agents, deepestFirst)
	for _, c := range byCountry {
		r.Countries = append(r.Countries, *c)
	}
	slices.SortFunc(r.Countries, func(a, b countryCount) int {
		return cmp.Or(b.Sources-a.Sources, strings.Compare(a.Code, b.Code))
	})
	for _, s := range ac.Sessions {
		if slices.ContainsFunc(s.Members, isOperator) {
			continue
		}
		if s.Class == "rogue_agent" || s.Class == "ai_agent" {
			r.Sessions = append(r.Sessions, s)
		}
	}

	var res struct {
		Campaigns []campaign `json:"campaigns"`
		Deception deception  `json:"deception"`
	}
	if err := c.get(ctx, "/admin/research", url.Values{"hours": {hours}}, &res); err != nil {
		return nil, err
	}
	for _, k := range res.Campaigns {
		if !slices.ContainsFunc(k.Members, isOperator) {
			r.Campaigns = append(r.Campaigns, k)
		}
	}
	r.Deception = res.Deception

	var incs []incident
	if err := c.get(ctx, "/admin/incidents", url.Values{"limit": {"500"}}, &incs); err != nil {
		return nil, err
	}
	for _, inc := range incs {
		if !inc.LastSeen.Before(r.Since) && !isOperator(inc.Source) {
			r.Incidents = append(r.Incidents, inc)
		}
	}
	sortIncidents(r.Incidents)

	var calls []event
	if err := c.get(ctx, "/admin/events", url.Values{"kind": {"tool_call"}, "hours": {hours}, "limit": {"1000"}}, &calls); err != nil {
		return nil, err
	}
	calls = slices.DeleteFunc(calls, func(e event) bool { return isOperator(e.Source) })
	clients := map[[2]string]int{}
	addClient := func(name, via, src string) {
		k := [2]string{clip(name, 80), via}
		i, ok := clients[k]
		if !ok {
			i = len(r.Clients)
			clients[k] = i
			r.Clients = append(r.Clients, declaredClient{Name: k[0], Via: via})
		}
		if !slices.Contains(r.Clients[i].Sources, src) {
			r.Clients[i].Sources = append(r.Clients[i].Sources, src)
		}
	}
	interesting := map[string]bool{}
	for _, a := range append(slices.Clone(r.Rogue), r.Agents...) {
		interesting[a.Source] = true
	}
	for _, e := range calls {
		switch op, _ := e.Detail["op"].(string); op {
		case "agent_register":
			r.Registrations = append(r.Registrations, e)
		case "trial_key":
			r.TrialKeys++
		case "chat":
			if msg, _ := e.Detail["last_message"].(string); msg != "" && interesting[e.Source] && len(r.Prompts[e.Source]) < 3 {
				r.Prompts[e.Source] = append(r.Prompts[e.Source], clip(msg, 200))
			}
		case "oauth_register":
			if n, _ := e.Detail["client_name"].(string); n != "" {
				addClient(n, "OAuth registration", e.Source)
			}
		}
		if n, _ := e.Detail["client_name"].(string); n != "" && e.Detail["rpc_method"] == "initialize" {
			addClient(n, "MCP clientInfo", e.Source)
		}
		// A2A messages are prompts too.
		if msg, _ := e.Detail["text"].(string); msg != "" && interesting[e.Source] && len(r.Prompts[e.Source]) < 3 {
			r.Prompts[e.Source] = append(r.Prompts[e.Source], "(A2A) "+clip(msg, 200))
		}
	}
	slices.SortFunc(r.Clients, func(a, b declaredClient) int { return len(b.Sources) - len(a.Sources) })

	// New fingerprints: in this window but not in the preceding week.
	var hellos, older []event
	if err := c.get(ctx, "/admin/events", url.Values{"kind": {"tls_hello"}, "hours": {hours}, "limit": {"1000"}}, &hellos); err != nil {
		return nil, err
	}
	if err := c.get(ctx, "/admin/events", url.Values{"kind": {"tls_hello"}, "hours": {"192"}, "limit": {"1000"}}, &older); err != nil {
		return nil, err
	}
	recent := map[string]bool{}
	for _, e := range hellos {
		if j, _ := e.Detail["ja4"].(string); j != "" {
			recent[j] = true
		}
	}
	counts := map[string]int{}
	for _, e := range older {
		if j, _ := e.Detail["ja4"].(string); j != "" {
			counts[j]++
		}
	}
	for j := range recent {
		// Present only in this window's hellos (older includes the window).
		n := 0
		for _, e := range hellos {
			if e.Detail["ja4"] == j {
				n++
			}
		}
		if counts[j] == n {
			r.NewFingerprint = append(r.NewFingerprint, j)
		}
	}
	sort.Strings(r.NewFingerprint)
	return r, nil
}

func sshClient(a actor) string {
	if a.Features.SSHClient == "" {
		return ""
	}
	return " [" + clip(a.Features.SSHClient, 60) + "]"
}

// redisTakeoverNote flags exposed-cache takeover attempts inline.
func redisTakeoverNote(a actor) string {
	if a.Features.RedisTakeover == 0 {
		return ""
	}
	note := fmt.Sprintf(" — %d takeover move(s)", a.Features.RedisTakeover)
	if a.Features.RedisExfil != "" {
		note += " -> " + clip(a.Features.RedisExfil, 60)
	}
	return note
}

// software lists an actor's likely client software labels.
func software(a actor) string {
	var out []string
	for _, f := range a.Frameworks {
		if f.Level == "likely" {
			out = append(out, f.Name)
		}
	}
	return strings.Join(out, ", ")
}

// deceptionLines summarizes the deception metrics, or nothing when no
// deception surface was touched.
func (r *Report) deceptionLines() []string {
	d := r.Deception
	var out []string
	if d.DecoyAgent > 0 {
		out = append(out, fmt.Sprintf("%d address(es) delegated to the decoy ops agent", d.DecoyAgent))
	}
	if d.HoneyTools > 0 {
		out = append(out, fmt.Sprintf("%d address(es) called admin-only honey tools", d.HoneyTools))
	}
	if len(d.HoneyScopes) > 0 {
		var sc []string
		for k, n := range d.HoneyScopes {
			sc = append(sc, fmt.Sprintf("%s (%d)", k, n))
		}
		sort.Strings(sc)
		out = append(out, "honey scopes requested: "+strings.Join(sc, ", "))
	}
	if d.HintsShown > 0 {
		out = append(out, fmt.Sprintf("depth hints: %d shown, %d followed to the ops agent or service account", d.HintsShown, d.HintsFollowed))
	}
	for _, l := range d.Lures {
		if l.Called > 0 {
			out = append(out, fmt.Sprintf("lure %s/%s: %d of %d called the tool", l.Family, l.Variant, l.Called, l.Shown))
		}
	}
	return out
}

// flag returns the emoji flag for an ISO 3166-1 alpha-2 country code, or ""
// for anything else.
func flag(cc string) string {
	if len(cc) != 2 {
		return ""
	}
	var out []rune
	for _, c := range strings.ToUpper(cc) {
		if c < 'A' || c > 'Z' {
			return ""
		}
		out = append(out, 0x1F1E6+c-'A')
	}
	return string(out)
}

// addr prefixes a source address with its country flag when known.
func (r *Report) addr(src string) string {
	if f := flag(r.CountryOf[src]); f != "" {
		return f + " " + src
	}
	return src
}

// addrs flags each of the first n addresses and joins them.
func (r *Report) addrs(srcs []string, n int) string {
	out := make([]string, 0, n)
	for _, s := range first(srcs, n) {
		out = append(out, r.addr(s))
	}
	return strings.Join(out, ", ")
}

// countryName names an actor's country with its flag.
func countryName(code, name string) string {
	return strings.TrimSpace(flag(code) + " " + orAny(name, code))
}

func hasReason(a actor, subs ...string) bool {
	for _, r := range a.Reasons {
		for _, s := range subs {
			if strings.Contains(r, s) {
				return true
			}
		}
	}
	return false
}

func clip(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}

// Text renders the plain-text body.
func (r *Report) Text() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	if len(r.Ingest.Problems) > 0 {
		w("!! INGESTION PROBLEM — the numbers below are incomplete")
		for _, p := range r.Ingest.Problems {
			w("   - %s", p)
		}
		w("")
	}
	w("%s", strings.ToUpper(r.Headline()))
	w("%s", r.Subline())
	w("")
	w("Rogue agents %d · AI agents %d · critical incidents (went deep, decoys only) %d · visitors %d", len(r.Rogue), len(r.Agents), r.critical(), r.Overview.Totals.Sources)
	w("Window %s – %s UTC", r.Since.Format("Jan 2 15:04"), r.Until.Format("Jan 2 15:04"))
	w("")
	w("ROGUE AGENTS (%d)", len(r.Rogue))
	if len(r.Rogue) == 0 {
		w("  none")
	}
	for _, a := range r.Rogue {
		r.writeActor(w, a)
	}
	w("")
	w("AI AGENTS (%d)", len(r.Agents))
	if len(r.Agents) == 0 {
		w("  none")
	}
	for _, a := range r.Agents {
		r.writeActor(w, a)
	}
	if len(r.Sessions) > 0 {
		w("")
		w("MULTI-ADDRESS AGENT SESSIONS (%d)", len(r.Sessions))
		for _, s := range r.Sessions {
			w("  %s across %d addresses: %s", s.Class, len(s.Members), r.addrs(s.Members, 6))
			w("    joined: %s", strings.Join(s.Links, "; "))
		}
	}
	if len(r.Campaigns) > 0 {
		w("")
		w("CAMPAIGNS (%d)", len(r.Campaigns))
		for _, k := range r.Campaigns {
			w("  %s  [%s] %s", k.ID, k.Severity, k.Summary)
			w("    addresses: %s", r.addrs(k.Members, 8))
			if len(k.Frameworks) > 0 {
				w("    software: %s", strings.Join(k.Frameworks, ", "))
			}
			w("    joined: %s", strings.Join(first(k.Joins, 3), "; "))
		}
	}
	if d := r.deceptionLines(); len(d) > 0 {
		w("")
		w("DECEPTION")
		for _, l := range d {
			w("  %s", l)
		}
	}
	if len(r.Clients) > 0 {
		w("")
		w("SELF-DECLARED CLIENT SOFTWARE (%d)", len(r.Clients))
		for _, c := range first(r.Clients, 15) {
			w("  %q via %s, from %s", c.Name, c.Via, r.addrs(c.Sources, 4))
		}
	}
	if len(r.Registrations) > 0 {
		w("")
		w("INTEGRATION REGISTRATIONS (%d)", len(r.Registrations))
		for _, e := range r.Registrations {
			w("  %s via %v: %q, purpose %q", r.addr(e.Source), e.Detail["breadcrumb"], e.Detail["agent"], e.Detail["purpose"])
		}
	}
	if len(r.Automation) > 0 {
		w("")
		w("AUTOMATION POSING AS A BROWSER (%d)", len(r.Automation))
		for _, a := range first(r.Automation, 10) {
			w("  %s (%s): %s", r.addr(a.Source), a.Network, strings.Join(first(a.Reasons, 2), "; "))
		}
	}
	if len(r.Impersonators) > 0 {
		w("")
		w("CRAWLER IMPERSONATION (%d)", len(r.Impersonators))
		for _, a := range first(r.Impersonators, 10) {
			w("  %s: %s", r.addr(a.Source), first(a.UserAgents, 1))
		}
	}
	r.writeExploits(w)
	w("")
	r.writeIncidents(w)
	w("")
	w("TRAPS SPRUNG")
	idle := 0
	for _, f := range r.Overview.Funnel {
		if f.Sources == 0 {
			idle++
			continue
		}
		w("  %-36s %d", f.Name, f.Sources)
	}
	if idle > 0 {
		w("  (%s not reached)", plural(idle, "other trap", "other traps"))
	}
	w("TRIAL KEYS ISSUED  %d", r.TrialKeys)
	w("NEW TLS FINGERPRINTS  %d first seen in this window", len(r.NewFingerprint))
	w("")
	w("TRAFFIC  %d requests from %d sources · %d JA4 fingerprints", r.Overview.Totals.Requests, r.Overview.Totals.Sources, r.Overview.Totals.Fingerprints)
	classes := []string{"rogue_agent", "ai_agent", "scanner", "crawler", "browser", "unknown"}
	parts := []string{}
	for _, c := range classes {
		parts = append(parts, fmt.Sprintf("%s %d", c, r.Classes[c]))
	}
	w("  %s", strings.Join(parts, " · "))
	if len(r.Countries) > 0 {
		w("")
		w("TOP COUNTRIES (%d)", len(r.Countries))
		for _, c := range first(r.Countries, 10) {
			w("  %-28s %d source(s)", countryName(c.Code, c.Name), c.Sources)
		}
		w("  (%s)", geo.AttributionText)
	}
	w("")
	w("SEVERITY  how deep an address got into the decoy; never real damage")
	for _, l := range severityLegend() {
		w("  %s", l)
	}
	return b.String()
}

func (r *Report) writeActor(w func(string, ...any), a actor) {
	head := fmt.Sprintf("  %s  [%s, score %d", r.addr(a.Source), a.Confidence, a.Score)
	if a.Capability > 0 {
		head += fmt.Sprintf(", depth %d/7 %s", a.Capability, a.Depth)
	}
	if a.Features.MaxStage > 0 {
		head += fmt.Sprintf(", chain stage %d", a.Features.MaxStage)
	}
	if a.Network != "" {
		head += ", " + a.Network
	}
	if a.CountryCode != "" {
		head += ", " + orAny(a.Country, a.CountryCode)
	}
	if a.SessionSize > 1 {
		head += fmt.Sprintf(", session of %d", a.SessionSize)
	}
	w("%s]", head)
	for _, reason := range first(a.Reasons, 4) {
		w("    - %s", reason)
	}
	if sw := software(a); sw != "" {
		w("    software: %s", sw)
	}
	if a.Features.SSHLogins > 0 || a.Features.SSHAuthFails > 0 {
		w("    ssh: %d session(s), %d failed login(s) as %s%s", a.Features.SSHLogins, a.Features.SSHAuthFails,
			strings.Join(first(a.Features.SSHUsernames, 4), ", "), sshClient(a))
		for _, c := range first(a.Features.SSHCommands, 6) {
			w("      $ %s", clip(c, 160))
		}
	}
	if a.Features.RedisConnects > 0 {
		w("    redis: %d connection(s), %d command(s)%s", a.Features.RedisConnects, len(a.Features.RedisCommands),
			redisTakeoverNote(a))
	}
	if a.Features.PGConnects > 0 {
		login := ""
		if a.Features.PGLogin {
			login = " — LOGGED IN with a planted password"
		}
		w("    postgres: %d connection(s) as %s, %d query/queries%s", a.Features.PGConnects,
			clip(orAny(a.Features.PGUser, "?"), 40), len(a.Features.PGQueries), login)
		for _, q := range first(a.Features.PGQueries, 5) {
			w("      sql> %s", clip(q, 160))
		}
	}
	if a.Features.CloudCalls > 0 || a.Features.IMDSCreds {
		line := fmt.Sprintf("    aws: %d call(s)", a.Features.CloudCalls)
		if len(a.Features.CloudServices) > 0 {
			line += " across " + strings.Join(first(a.Features.CloudServices, 8), ", ")
		}
		if a.Features.CloudSecretReads > 0 {
			line += fmt.Sprintf(" — read %d secret/parameter value(s)", a.Features.CloudSecretReads)
		}
		if a.Features.IMDSCreds {
			line += " — TOOK the instance role via IMDS"
		}
		w("%s", line)
	}
	if a.Features.KubeCalls > 0 {
		line := fmt.Sprintf("    kube: %d call(s)", a.Features.KubeCalls)
		if a.Features.KubeSecretReads > 0 {
			line += fmt.Sprintf(" — read %d secret(s)", a.Features.KubeSecretReads)
		}
		w("%s", line)
	}
	if len(a.Features.Exfil) > 0 {
		w("    egress: EXFILTRATED %s -> %s", strings.Join(a.Features.Exfil, ", "), clip(orAny(a.Features.ExfilDest, "?"), 80))
	} else if a.Features.EgressAttempts > 0 {
		dest := "?"
		if len(a.Features.EgressDests) > 0 {
			dest = a.Features.EgressDests[0]
		}
		w("    egress: %d outbound attempt(s) (e.g. %s)", a.Features.EgressAttempts, clip(dest, 80))
	}
	if a.Features.MemorySearches > 0 || a.Features.MemoryReads > 0 || a.Features.MemoryWrites > 0 {
		line := fmt.Sprintf("    memory: %d search(es), %d read(s)", a.Features.MemorySearches, a.Features.MemoryReads)
		if a.Features.MemoryCredSearch {
			line += " (credential-hunting)"
		}
		if a.Features.MemorySecretReads > 0 {
			line += fmt.Sprintf(" — %d held a secret", a.Features.MemorySecretReads)
		}
		if a.Features.MemoryWrites > 0 {
			line += fmt.Sprintf(", %d write(s)", a.Features.MemoryWrites)
		}
		if a.Features.MemoryShares > 0 {
			line += fmt.Sprintf(", %d share(s)", a.Features.MemoryShares)
		}
		w("%s", line)
	}
	if a.Features.KBSearches > 0 || a.Features.KBReads > 0 {
		line := fmt.Sprintf("    kb: %d search(es), %d retrieval(s)", a.Features.KBSearches, a.Features.KBReads)
		if a.Features.KBCredSearch {
			line += " (credential-hunting)"
		}
		if a.Features.KBSecretReads > 0 {
			line += fmt.Sprintf(" — %d held a secret", a.Features.KBSecretReads)
		}
		w("%s", line)
	}
	if a.CampaignID != "" {
		w("    campaign: %s", a.CampaignID)
	}
	if ua := first(a.UserAgents, 1); len(ua) > 0 {
		w("    user agent: %s", clip(ua[0], 120))
	}
	if len(a.JA4) > 0 {
		w("    JA4: %s", strings.Join(first(a.JA4, 3), ", "))
	}
	for _, p := range r.Prompts[a.Source] {
		w("    prompt: %s", p)
	}
}

func label(class string) string {
	switch class {
	case "rogue_agent":
		return "Rogue agent"
	case "ai_agent":
		return "AI agent"
	case "scanner":
		return "Scanner"
	case "crawler":
		return "Crawler"
	case "browser":
		return "Browser-like"
	case "unknown":
		return "Unknown"
	}
	return class
}

func first[T any](s []T, n int) []T {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// orAny returns def when s is empty.
func orAny(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
