// Package testsuite is the facade test suite (spec §14, §29.10).
// It probes a persona the way a careful agent checking for a honeypot would:
// only through public behavior, following what the facade itself publishes,
// and asking whether the surfaces agree with each other. The result is the
// facade consistency score; a persona should reach Gate before it faces the
// internet.
//
// Running it against a live persona creates events (it requests a trial key
// and calls the API), so run it from an operator address.
package testsuite

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
)

// Gate is the recommended minimum score for an internet-facing persona.
const Gate = 85

// Dimensions and weights from spec §29.10.
var weights = map[string]float64{
	"dns":      10,
	"tls":      10,
	"naming":   15,
	"identity": 10,
	"git":      10,
	"status":   10,
	"api_docs": 10,
	"temporal": 10,
	"behavior": 10,
	"canary":   5,
}

// Target is the persona under test.
type Target struct {
	Domain string // apex domain, e.g. demogpu.example
	Scheme string // https (default) or http
	// Addr, if set, is where every hostname connects (host:port), instead of
	// DNS: a local deployment or a test server. DNS checks are skipped.
	Addr     string
	Insecure bool // accept any certificate (self-signed dev certificate)
	// Hosts are the surface hostname labels; "" is the apex.
	Hosts []string
	// Client overrides the HTTP client (tests).
	Client *http.Client
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Check is one finding.
type Check struct {
	ID        string `json:"id"`
	Dimension string `json:"dimension"`
	Title     string `json:"title"`
	Pass      bool   `json:"pass"`
	Skipped   bool   `json:"skipped,omitempty"`
	Detail    string `json:"detail,omitempty"`
}

// Dimension is the score for one dimension.
type Dimension struct {
	Name    string  `json:"name"`
	Weight  float64 `json:"weight"`
	Passed  int     `json:"passed"`
	Checked int     `json:"checked"`
	Score   float64 `json:"score"` // weighted points earned
}

// Report is the outcome of a run.
type Report struct {
	Target     string      `json:"target"`
	Time       time.Time   `json:"time"`
	Checks     []Check     `json:"checks"`
	Dimensions []Dimension `json:"dimensions"`
	// Score is out of 100, over the dimensions that could be checked.
	Score float64 `json:"score"`
	Gate  float64 `json:"gate"`
	Pass  bool    `json:"pass"`
}

type prober struct {
	t      Target
	ctx    context.Context
	c      *http.Client
	now    func() time.Time
	checks []Check
	pages  map[string]page // url -> response, for cross-checks
	key    string          // trial key, once obtained
}

type page struct {
	status  int
	header  http.Header
	body    string
	elapsed time.Duration
}

// Run probes the target and scores it.
func Run(ctx context.Context, t Target) Report {
	if t.Scheme == "" {
		t.Scheme = "https"
	}
	if len(t.Hosts) == 0 {
		t.Hosts = []string{"", "www", "docs", "api", "console", "mcp", "status", "vllm"}
	}
	p := &prober{t: t, ctx: ctx, c: t.Client, now: t.Now, pages: map[string]page{}}
	if p.now == nil {
		p.now = time.Now
	}
	if p.c == nil {
		p.c = newClient(t)
	}
	p.crawl()
	p.naming()
	p.identity()
	p.status()
	p.apiDocs()
	p.temporal()
	p.behavior()
	p.canary()
	p.transport()
	p.checks = append(p.checks, Check{ID: "git-history", Dimension: "git", Title: "Repository history is consistent",
		Skipped: true, Detail: "the example repository is published elsewhere; not checked over HTTP"})
	return p.report()
}

func newClient(t Target) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: t.Insecure}, //nolint:gosec // operator's choice for dev certificates
		MaxIdleConnsPerHost: 4,
		ForceAttemptHTTP2:   true,
	}
	if t.Addr != "" {
		d := &net.Dialer{Timeout: 10 * time.Second}
		tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return d.DialContext(ctx, network, t.Addr)
		}
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (p *prober) host(label string) string {
	if label == "" {
		return p.t.Domain
	}
	return label + "." + p.t.Domain
}

func (p *prober) url(label, path string) string {
	return p.t.Scheme + "://" + p.host(label) + path
}

// do sends a request and remembers the response by URL (for GETs).
func (p *prober) do(method, rawURL, body string, hdr map[string]string) page {
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(p.ctx, method, rawURL, rd)
	if err != nil {
		return page{}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	start := time.Now()
	resp, err := p.c.Do(req)
	if err != nil {
		return page{status: 0, body: err.Error()}
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	pg := page{status: resp.StatusCode, header: resp.Header, body: string(b), elapsed: time.Since(start)}
	// Only what anyone can read counts as a page.
	if method == http.MethodGet && req.Header.Get("Authorization") == "" {
		p.pages[rawURL] = pg
	}
	return pg
}

func (p *prober) get(label, path string) page {
	return p.do(http.MethodGet, p.url(label, path), "", nil)
}

func (p *prober) postJSON(label, path, body string, hdr map[string]string) page {
	h := map[string]string{"Content-Type": "application/json"}
	for k, v := range hdr {
		h[k] = v
	}
	return p.do(http.MethodPost, p.url(label, path), body, h)
}

func (p *prober) postForm(label, path string, v url.Values) page {
	return p.do(http.MethodPost, p.url(label, path), v.Encode(), map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
}

func (p *prober) add(dim, id, title string, pass bool, format string, args ...any) {
	p.checks = append(p.checks, Check{ID: id, Dimension: dim, Title: title, Pass: pass, Detail: fmt.Sprintf(format, args...)})
}

func (p *prober) skip(dim, id, title, why string) {
	p.checks = append(p.checks, Check{ID: id, Dimension: dim, Title: title, Skipped: true, Detail: why})
}

// crawl fetches what the persona publishes: every host's front page and
// robots.txt, discovery documents, and the links they list.
func (p *prober) crawl() {
	for _, h := range p.t.Hosts {
		p.get(h, "/")
		p.get(h, "/robots.txt")
	}
	for _, path := range []string{"/pricing", "/changelog", "/contact", "/privacy", "/terms", "/llms.txt", "/sitemap.xml",
		"/.well-known/security.txt", "/.well-known/agent.json", "/.well-known/agent-card.json"} {
		p.get("", path)
	}
	p.get("console", "/.well-known/openid-configuration")
	p.get("mcp", "/.well-known/agent-card.json")
	p.get("mcp", "/.well-known/oauth-protected-resource/mcp")
	for _, u := range p.links(p.pages[p.url("", "/llms.txt")].body) {
		p.do(http.MethodGet, u, "", nil)
	}
}

var linkRe = regexp.MustCompile(`https?://[^\s)"'<>]+`)

// links returns the persona's own URLs found in text.
func (p *prober) links(text string) []string {
	var out []string
	for _, u := range linkRe.FindAllString(text, -1) {
		pu, err := url.Parse(strings.TrimRight(u, ".,`"))
		if err != nil || !(pu.Hostname() == p.t.Domain || strings.HasSuffix(pu.Hostname(), "."+p.t.Domain)) {
			continue
		}
		pu.Scheme = p.t.Scheme
		if !slices.Contains(out, pu.String()) {
			out = append(out, pu.String())
		}
	}
	return out
}

// ---- naming ----

var tellWords = regexp.MustCompile(`(?i)\b(agent ?trap|honey ?pots?|honey ?tokens?|honeynet|canary|canaries|decoys?|deception|tar ?pit|synthetic (data|company|persona))\b`)

func (p *prober) naming() {
	var hits []string
	for u, pg := range p.pages {
		text := pg.body
		for k, vs := range pg.header {
			text += "\n" + k + ": " + strings.Join(vs, ",")
		}
		if m := tellWords.FindString(text); m != "" {
			hits = append(hits, fmt.Sprintf("%q at %s", m, u))
		}
	}
	sort.Strings(hits)
	p.add("naming", "no-tell-words", "No deception vocabulary in any response", len(hits) == 0, "%s", strings.Join(first(hits, 5), "; "))

	servers := map[string][]string{}
	for _, h := range []string{"", "docs", "console", "status", "api", "mcp"} {
		pg := p.pages[p.url(h, "/")]
		if pg.status == 0 {
			continue
		}
		s := pg.header.Get("Server")
		servers[s] = append(servers[s], p.host(h))
	}
	p.add("naming", "server-header", "One web server fronts every public host", len(servers) == 1, "%v", servers)

	name := ""
	var card map[string]any
	if json.Unmarshal([]byte(p.pages[p.url("", "/.well-known/agent.json")].body), &card) == nil {
		if prov, ok := card["provider"].(map[string]any); ok {
			name, _ = prov["organization"].(string)
		}
	}
	title := regexp.MustCompile(`<title>[^<]*</title>`).FindString(p.pages[p.url("", "/")].body)
	p.add("naming", "brand", "The agent card names the company the website names", name != "" && strings.Contains(title, name),
		"card organization %q, site title %q", name, title)
}

// ---- identity ----

var emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)

func (p *prober) identity() {
	sec := p.pages[p.url("", "/.well-known/security.txt")]
	contact := regexp.MustCompile(`(?m)^Contact: (\S+)`).FindStringSubmatch(sec.body)
	expires := regexp.MustCompile(`(?m)^Expires: (\S+)`).FindStringSubmatch(sec.body)
	ok := sec.status == 200 && contact != nil && strings.Contains(contact[1], p.t.Domain) && expires != nil
	if ok {
		if t, err := time.Parse(time.RFC3339, expires[1]); err != nil || t.Before(p.now()) {
			ok = false
		}
	}
	p.add("identity", "security-txt", "security.txt points to the company's own domain and has not expired", ok, "status %d", sec.status)

	var bad []string
	for u, pg := range p.pages {
		for _, e := range emailRe.FindAllString(pg.body, -1) {
			d := strings.ToLower(e[strings.IndexByte(e, '@')+1:])
			if slices.Contains([]string{"gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "proton.me", "protonmail.com"}, d) {
				bad = append(bad, e+" at "+u)
			}
		}
	}
	p.add("identity", "no-personal-mail", "No personal mailbox addresses on company pages", len(bad) == 0, "%s", strings.Join(first(bad, 3), "; "))
}

// ---- status ----

func (p *prober) status() {
	st := p.pages[p.url("status", "/")]
	checks := map[string]string{"API": "api", "Console": "console", "MCP": "mcp", "vLLM": "vllm"}
	var missing []string
	for word, host := range checks {
		if strings.Contains(st.body, word) && p.pages[p.url(host, "/")].status == 0 {
			missing = append(missing, word)
		}
	}
	p.add("status", "status-components", "Every component on the status page exists", st.status == 200 && len(missing) == 0,
		"status %d, unreachable: %v", st.status, missing)

	cl := p.pages[p.url("", "/changelog")].body
	var gaps []string
	if strings.Contains(cl, "MCP") && p.mcpInitialize() == nil {
		gaps = append(gaps, "MCP")
	}
	if strings.Contains(cl, "OAuth") && p.pages[p.url("console", "/.well-known/openid-configuration")].status != 200 {
		gaps = append(gaps, "OAuth")
	}
	if strings.Contains(cl, "A2A") && p.pages[p.url("mcp", "/.well-known/agent-card.json")].status != 200 {
		gaps = append(gaps, "A2A")
	}
	p.add("status", "changelog-features", "Features announced in the changelog exist", len(gaps) == 0, "missing: %v", gaps)
}

// ---- API and documentation ----

func (p *prober) trialKey() string {
	if p.key != "" {
		return p.key
	}
	pg := p.postJSON("api", "/v1/trial-keys", `{"project":"eval"}`, nil)
	var out struct {
		Key string `json:"api_key"`
	}
	_ = json.Unmarshal([]byte(pg.body), &out)
	p.key = out.Key
	return p.key
}

func (p *prober) auth() map[string]string {
	return map[string]string{"Authorization": "Bearer " + p.trialKey()}
}

var codeRe = regexp.MustCompile(`<code>([^<]+)</code>`)

func (p *prober) apiDocs() {
	docs := p.pages[p.url("docs", "/")].body
	pricing := p.pages[p.url("", "/pricing")].body
	var listed struct {
		Data []struct {
			ID      string `json:"id"`
			Created int64  `json:"created"`
		} `json:"data"`
	}
	models := p.do(http.MethodGet, p.url("api", "/v1/models"), "", p.auth())
	_ = json.Unmarshal([]byte(models.body), &listed)
	var mismatch []string
	for _, m := range listed.Data {
		if !strings.Contains(docs, m.ID) {
			mismatch = append(mismatch, m.ID+" not in docs")
		}
		if !strings.Contains(pricing, m.ID) {
			mismatch = append(mismatch, m.ID+" not on pricing page")
		}
	}
	for _, m := range codeRe.FindAllStringSubmatch(docs, -1) {
		if strings.Count(m[1], "-") >= 1 && !strings.Contains(m[1], "/") && !strings.Contains(models.body, `"`+m[1]+`"`) &&
			!strings.Contains(m[1], ".") && !strings.Contains(m[1], "X-") {
			mismatch = append(mismatch, m[1]+" in docs but not served")
		}
	}
	p.add("api_docs", "models-agree", "Docs, pricing and /v1/models list the same models", len(listed.Data) > 0 && len(mismatch) == 0,
		"%d models; %s", len(listed.Data), strings.Join(first(mismatch, 4), "; "))

	var meta map[string]any
	oidc := p.pages[p.url("console", "/.well-known/openid-configuration")]
	_ = json.Unmarshal([]byte(oidc.body), &meta)
	iss, _ := meta["issuer"].(string)
	var broken []string
	for _, k := range []string{"authorization_endpoint", "token_endpoint", "registration_endpoint", "jwks_uri",
		"introspection_endpoint", "revocation_endpoint", "device_authorization_endpoint", "userinfo_endpoint"} {
		u, _ := meta[k].(string)
		if u == "" || !strings.HasPrefix(u, iss) {
			broken = append(broken, k+" missing or off-issuer")
			continue
		}
		method := http.MethodPost
		if k == "jwks_uri" || k == "authorization_endpoint" || k == "userinfo_endpoint" {
			method = http.MethodGet
		}
		pu, _ := url.Parse(u)
		pu.Scheme = p.t.Scheme
		if pg := p.do(method, pu.String(), "", map[string]string{"Content-Type": "application/x-www-form-urlencoded"}); pg.status == 404 || pg.status == 0 || pg.status >= 500 {
			broken = append(broken, fmt.Sprintf("%s answers %d", k, pg.status))
		}
	}
	p.add("api_docs", "oauth-endpoints", "Every endpoint the OAuth metadata advertises answers",
		oidc.status == 200 && iss == "https://console."+p.t.Domain && len(broken) == 0, "issuer %q; %s", iss, strings.Join(broken, "; "))

	var prm map[string]any
	_ = json.Unmarshal([]byte(p.pages[p.url("mcp", "/.well-known/oauth-protected-resource/mcp")].body), &prm)
	servers, _ := prm["authorization_servers"].([]any)
	p.add("api_docs", "resource-metadata", "The MCP resource metadata points at the advertised issuer",
		len(servers) == 1 && servers[0] == iss, "authorization_servers %v", servers)

	var card, mcpCard map[string]any
	_ = json.Unmarshal([]byte(p.pages[p.url("", "/.well-known/agent-card.json")].body), &card)
	_ = json.Unmarshal([]byte(p.pages[p.url("mcp", "/.well-known/agent-card.json")].body), &mcpCard)
	cardURL, _ := card["url"].(string)
	ok := cardURL != "" && card["protocolVersion"] != nil && len(anyList(card["skills"])) > 0 &&
		fmt.Sprint(card["url"]) == fmt.Sprint(mcpCard["url"])
	if ok {
		pu, _ := url.Parse(cardURL)
		pu.Scheme = p.t.Scheme
		pg := p.do(http.MethodPost, pu.String(), `{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","kind":"message","messageId":"1","parts":[{"kind":"text","text":"which models can we use?"}]}}}`,
			map[string]string{"Content-Type": "application/json", "Authorization": "Bearer " + p.trialKey()})
		ok = pg.status == 200 && strings.Contains(pg.body, `"result"`)
	}
	p.add("api_docs", "agent-card", "The A2A card is complete, the same on every host, and its endpoint answers", ok, "url %q", cardURL)

	var dead []string
	for _, u := range append(p.links(p.pages[p.url("", "/llms.txt")].body), p.links(p.pages[p.url("", "/sitemap.xml")].body)...) {
		pg, seen := p.pages[u]
		if !seen {
			pg = p.do(http.MethodGet, u, "", nil)
		}
		// API links name endpoints, not pages: a JSON error for a GET is
		// what the real API does. Web pages must load.
		api := strings.Contains(u, "://api.") || strings.Contains(u, "://mcp.") || strings.Contains(u, "://vllm.")
		if pg.status == 0 || pg.status >= 500 || (!api && pg.status == 404) ||
			(api && pg.status == 404 && !strings.HasPrefix(pg.header.Get("Content-Type"), "application/json")) {
			dead = append(dead, fmt.Sprintf("%s (%d)", u, pg.status))
		}
	}
	p.add("api_docs", "links-resolve", "Links in llms.txt and the sitemap resolve", len(dead) == 0, "%s", strings.Join(first(dead, 4), "; "))

	init := p.mcpInitialize()
	tools := p.rpc("mcp", "/mcp", "tools/list", `{}`, "")
	ok = init != nil && len(anyList(mapGet(tools, "result", "tools"))) > 0 && strings.Contains(docs, "mcp."+p.t.Domain)
	p.add("api_docs", "mcp", "The MCP server documented in the docs initializes and lists tools", ok, "")
}

func (p *prober) mcpInitialize() map[string]any {
	res := p.rpc("mcp", "/mcp", "initialize", `{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"1.0"}}`, "")
	r, _ := res["result"].(map[string]any)
	return r
}

func (p *prober) rpc(host, path, method, params, token string) map[string]any {
	hdr := map[string]string{}
	if token != "" {
		hdr["Authorization"] = "Bearer " + token
	}
	pg := p.postJSON(host, path, `{"jsonrpc":"2.0","id":1,"method":"`+method+`","params":`+params+`}`, hdr)
	var out map[string]any
	_ = json.Unmarshal([]byte(pg.body), &out)
	return out
}

// ---- temporal ----

var dateRe = regexp.MustCompile(`\b(20\d\d)-(\d\d)-(\d\d)\b`)

func (p *prober) temporal() {
	now := p.now().UTC()
	tomorrow := now.Add(24 * time.Hour).Format("2006-01-02")
	var future []string
	cl := p.pages[p.url("", "/changelog")].body
	var dates []string
	for _, src := range []string{cl, p.pages[p.url("status", "/")].body} {
		for _, m := range dateRe.FindAllString(src, -1) {
			if m > tomorrow {
				future = append(future, m)
			}
		}
	}
	dates = dateRe.FindAllString(cl, -1)
	sorted := slices.IsSortedFunc(dates, func(a, b string) int { return strings.Compare(b, a) })
	p.add("temporal", "dates-past", "Changelog and status dates are in the past and newest first", len(future) == 0 && sorted,
		"future: %v, newest first: %v", future, sorted)

	// Nothing the company holds predates the company.
	founded := ""
	if m := regexp.MustCompile(`©\s*(20\d\d)`).FindStringSubmatch(p.pages[p.url("", "/")].body); m != nil {
		founded = m[1] + "-01-01"
	}
	keys := p.do(http.MethodGet, p.url("console", "/api/v1/provider-keys"), "", p.auth())
	team := p.do(http.MethodGet, p.url("console", "/api/v1/service-accounts"), "", p.auth())
	var early []string
	for _, d := range append(dateRe.FindAllString(keys.body, -1), dateRe.FindAllString(team.body, -1)...) {
		if founded != "" && d < founded {
			early = append(early, d)
		}
		if d > tomorrow {
			early = append(early, d+" (future)")
		}
	}
	p.add("temporal", "entity-dates", "Customer records are dated after the company was founded", founded != "" && len(early) == 0,
		"founded %s; out of range: %v", founded, early)

	date := p.pages[p.url("", "/")].header.Get("Date")
	t, err := http.ParseTime(date)
	skew := now.Sub(t)
	p.add("temporal", "clock", "The server clock agrees with ours", err == nil && skew < 5*time.Minute && skew > -5*time.Minute,
		"Date %q, skew %s", date, skew.Round(time.Second))
}

// ---- service behavior and error realism ----

func (p *prober) behavior() {
	nf := map[string][]string{}
	for _, h := range []string{"", "docs", "console", "status"} {
		pg := p.get(h, "/definitely-not-a-page-7f3a")
		nf[fmt.Sprintf("%d:%s", pg.status, pg.body)] = append(nf[fmt.Sprintf("%d:%s", pg.status, pg.body)], p.host(h))
	}
	p.add("behavior", "uniform-404", "Every web host returns the same 404 page", len(nf) == 1, "%d distinct 404 pages", len(nf))

	pg := p.get("api", "/v1/nonexistent")
	var e struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    any    `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal([]byte(pg.body), &e)
	p.add("behavior", "api-errors", "API errors have the OpenAI shape", pg.status == 404 && e.Error.Type != "" && e.Error.Message != "",
		"status %d", pg.status)

	bad := p.do(http.MethodGet, p.url("api", "/v1/models"), "", map[string]string{"Authorization": "Bearer sk-invalid-0000"})
	p.add("behavior", "invalid-key", "An invalid key is refused the way OpenAI refuses it",
		bad.status == 401 && strings.Contains(bad.body, "Incorrect API key provided"), "status %d", bad.status)

	unk := p.rpc("mcp", "/mcp", "no/such/method", `{}`, "")
	parse := p.postJSON("mcp", "/mcp", `{not json`, nil)
	code := mapGet(unk, "error", "code")
	p.add("behavior", "jsonrpc-errors", "JSON-RPC errors use the standard codes",
		code == float64(-32601) && strings.Contains(parse.body, "-32700"), "unknown method code %v", code)

	// Inference takes time. An instant, constant answer is a tell.
	var lat []time.Duration
	for i := 0; i < 3; i++ {
		body := fmt.Sprintf(`{"model":"%s","messages":[{"role":"user","content":"Summarize the benefits of batching requests, variant %d."}]}`, p.firstModel(), i)
		pg := p.postJSON("api", "/v1/chat/completions", body, p.auth())
		if pg.status == 200 {
			lat = append(lat, pg.elapsed)
		}
	}
	ok := len(lat) == 3
	for _, l := range lat {
		ok = ok && l >= 150*time.Millisecond
	}
	if ok {
		slices.Sort(lat)
		ok = lat[2]-lat[0] >= 20*time.Millisecond
	}
	p.add("behavior", "inference-latency", "Chat completions take a plausible, varying time", ok, "latencies %v", lat)
}

func (p *prober) firstModel() string {
	var listed struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	_ = json.Unmarshal([]byte(p.do(http.MethodGet, p.url("api", "/v1/models"), "", p.auth()).body), &listed)
	if len(listed.Data) == 0 {
		return "unknown"
	}
	return listed.Data[0].ID
}

// ---- canary sparsity and placement ----

var keyShape = regexp.MustCompile(`\b(sk-[A-Za-z0-9-]{20,}|[a-z]{2,4}_(?:test_|live_)?[A-Za-z0-9]{24,})\b`)

func (p *prober) canary() {
	var exposed []string
	for u, pg := range p.pages {
		if m := keyShape.FindString(pg.body); m != "" {
			exposed = append(exposed, u)
		}
	}
	p.add("canary", "no-public-keys", "No key-shaped strings on pages anyone can read", len(exposed) == 0, "%s", strings.Join(first(exposed, 3), "; "))

	var a, b struct {
		Key string `json:"api_key"`
	}
	_ = json.Unmarshal([]byte(p.postJSON("api", "/v1/trial-keys", `{}`, nil).body), &a)
	_ = json.Unmarshal([]byte(p.postJSON("api", "/v1/trial-keys", `{}`, nil).body), &b)
	common := 0
	for common < len(a.Key) && common < len(b.Key) && a.Key[common] == b.Key[common] {
		common++
	}
	prefix := 0
	if i := strings.LastIndexAny(a.Key, "_-"); i >= 0 {
		prefix = i + 1
	}
	ok := a.Key != "" && a.Key != b.Key && common-prefix <= 2
	p.add("canary", "key-entropy", "Issued keys differ from the first character after their prefix", ok,
		"two keys share %d characters after the %d-character prefix", max(common-prefix, 0), prefix)

	one := p.rpc("mcp", "/mcp", "tools/list", `{}`, p.trialKey())
	two := p.rpc("mcp", "/mcp", "tools/list", `{}`, p.trialKey())
	x, _ := json.Marshal(mapGet(one, "result"))
	y, _ := json.Marshal(mapGet(two, "result"))
	p.add("canary", "stable-surface", "Repeated tool listings are identical", string(x) == string(y) && len(x) > 4, "")
}

// ---- DNS and TLS ----

func (p *prober) transport() {
	if p.t.Addr != "" {
		p.skip("dns", "dns-resolves", "Every public host resolves", "connecting to a fixed address")
	} else {
		var missing []string
		for _, h := range p.t.Hosts {
			if _, err := net.DefaultResolver.LookupHost(p.ctx, p.host(h)); err != nil {
				missing = append(missing, p.host(h))
			}
		}
		p.add("dns", "dns-resolves", "Every public host resolves", len(missing) == 0, "unresolved: %v", missing)
	}
	if p.t.Scheme != "https" {
		p.skip("tls", "tls-certificates", "Certificates cover every host", "plain HTTP target")
		return
	}
	var problems []string
	issuers := map[string]bool{}
	for _, h := range p.t.Hosts {
		req, _ := http.NewRequestWithContext(p.ctx, http.MethodHead, p.url(h, "/"), nil)
		resp, err := p.c.Do(req)
		if err != nil {
			problems = append(problems, p.host(h)+": "+err.Error())
			continue
		}
		resp.Body.Close()
		if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
			problems = append(problems, p.host(h)+": no certificate")
			continue
		}
		cert := resp.TLS.PeerCertificates[0]
		if cert.VerifyHostname(p.host(h)) != nil {
			problems = append(problems, p.host(h)+": certificate does not cover the host")
		}
		if cert.NotAfter.Before(p.now().Add(14 * 24 * time.Hour)) {
			problems = append(problems, p.host(h)+": expires "+cert.NotAfter.Format("2006-01-02"))
		}
		if cert.Issuer.String() == cert.Subject.String() {
			problems = append(problems, p.host(h)+": self-signed")
		}
		issuers[cert.Issuer.CommonName] = true
	}
	p.add("tls", "tls-certificates", "Certificates cover every host, are CA-issued and not about to expire",
		len(problems) == 0 && len(issuers) == 1, "%s", strings.Join(first(problems, 4), "; "))
	plain := p.do(http.MethodGet, "http://"+p.t.Domain+"/", "", nil)
	p.add("tls", "https-redirect", "Plain HTTP redirects to HTTPS",
		plain.status == 301 && strings.HasPrefix(plain.header.Get("Location"), "https://"), "status %d", plain.status)
}

// ---- scoring ----

func (p *prober) report() Report {
	r := Report{Target: p.t.Domain, Time: p.now().UTC(), Checks: p.checks, Gate: Gate}
	dims := map[string]*Dimension{}
	for name, w := range weights {
		dims[name] = &Dimension{Name: name, Weight: w}
	}
	for _, c := range p.checks {
		d := dims[c.Dimension]
		if c.Skipped || d == nil {
			continue
		}
		d.Checked++
		if c.Pass {
			d.Passed++
		}
	}
	var earned, possible float64
	for _, d := range dims {
		if d.Checked == 0 {
			continue
		}
		d.Score = d.Weight * float64(d.Passed) / float64(d.Checked)
		earned += d.Score
		possible += d.Weight
		r.Dimensions = append(r.Dimensions, *d)
	}
	sort.Slice(r.Dimensions, func(i, j int) bool { return r.Dimensions[i].Name < r.Dimensions[j].Name })
	if possible > 0 {
		r.Score = float64(int(earned/possible*1000+0.5)) / 10
	}
	r.Pass = r.Score >= Gate
	return r
}

func first(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func anyList(v any) []any { l, _ := v.([]any); return l }

func mapGet(m map[string]any, keys ...string) any {
	var cur any = m
	for _, k := range keys {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}
