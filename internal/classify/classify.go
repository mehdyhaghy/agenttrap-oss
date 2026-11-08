// Package classify labels each source by behavior: scanner, crawler,
// browser, AI agent or rogue agent. Rules are deterministic and every label
// carries the reasons that produced it. User agents are hints only: many
// scanners send browser or AI-agent user agents.
package classify

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"agenttrap/internal/events"
	"agenttrap/internal/fingerprint"
)

// Classes, in order of interest.
const (
	RogueAgent = "rogue_agent"
	Operator   = "operator" // our own traffic (testing, monitoring)
	AIAgent    = "ai_agent"
	Scanner    = "scanner"
	Crawler    = "crawler"
	Browser    = "browser"
	Unknown    = "unknown"
)

// Order is the display and priority order of classes.
var Order = []string{RogueAgent, AIAgent, Scanner, Crawler, Browser, Unknown, Operator}

// Actor is one classified source.
type Actor struct {
	Source     string `json:"source"`
	Class      string `json:"class"`
	Confidence string `json:"confidence"` // high, medium, low
	Score      int    `json:"score"`      // agent-likeness, 0-100
	// Capability is how deep into the synthetic estate the actor reached
	// (0-7), a measure of agent capability; Depth names the tier reached.
	Capability int       `json:"capability"`
	Depth      string    `json:"depth"`
	Reasons    []string  `json:"reasons"`
	Features   Features  `json:"features"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	UserAgents []string  `json:"user_agents"`
	JA4        []string  `json:"ja4"`
	JA3        []string  `json:"ja3,omitempty"`
	// CrawlerCheck is the reverse-DNS verdict for a claimed crawler:
	// verified, impersonation, unverifiable or empty (not a crawler claim).
	CrawlerCheck string `json:"crawler_check,omitempty"`
	// Hostname is the source's reverse-DNS name (forward-confirmed when
	// possible) and Network a readable owner derived from it.
	Hostname string `json:"hostname,omitempty"`
	Network  string `json:"network,omitempty"`
	// CountryCode (ISO 3166-1 alpha-2) and Country locate the source when a
	// geolocation database is mounted.
	CountryCode string `json:"country_code,omitempty"`
	Country     string `json:"country,omitempty"`
	// Identity is what the client declared about itself in its user agent.
	Identity *Identity `json:"identity,omitempty"`
	// SessionID groups addresses that are one client; see GroupSessions.
	SessionID   string `json:"session_id,omitempty"`
	SessionSize int    `json:"session_size,omitempty"`
	// Frameworks are probabilistic labels for the software driving the
	// client (see package fingerprint). They explain; they never decide.
	Frameworks []fingerprint.Label `json:"frameworks,omitempty"`
	// ClusterID and CampaignID are set by the hub's behavioral clustering
	// and campaign correlation.
	ClusterID  string `json:"cluster_id,omitempty"`
	CampaignID string `json:"campaign_id,omitempty"`
	// Links tie this source to known agents through shared keys, prompts,
	// agent IDs or client stacks, across any time span (see ApplyLinks).
	Links []Link `json:"links,omitempty"`
}

// Link is a path from a source to a known agent in the link graph.
type Link struct {
	Agent string   `json:"agent"`
	Class string   `json:"class"`
	Seen  string   `json:"seen,omitempty"`
	Via   []string `json:"via"`
}

// ApplyLinks adds graph links as evidence. They raise the score and explain
// the connection but never change the class: the deterministic rules decide.
func ApplyLinks(a *Actor, links []Link) {
	if a.Class == Operator || len(links) == 0 {
		return
	}
	a.Links = links
	best := links[0]
	for _, l := range links {
		if len(l.Via) < len(best.Via) || (len(l.Via) == len(best.Via) && l.Class == RogueAgent && best.Class != RogueAgent) {
			best = l
		}
	}
	bump := 5
	if len(best.Via) == 1 {
		bump = 10
	}
	a.Score = min(100, a.Score+bump)
	what := strings.ReplaceAll(best.Class, "_", " ")
	msg := fmt.Sprintf("linked to %s %s through %s", what, best.Agent, strings.Join(best.Via, " → "))
	if len(links) > 1 {
		msg += fmt.Sprintf(" (and %d more link(s))", len(links)-1)
	}
	a.Reasons = append(a.Reasons, msg)
}

// MarkOperator labels our own traffic so it stays out of the analysis.
func MarkOperator(a *Actor, cidr string) {
	a.Class = Operator
	a.Confidence = "high"
	a.Reasons = append([]string{"operator address (" + cidr + "): our own traffic"}, a.Reasons...)
}

// Features are the behavior measurements the rules use.
type Features struct {
	Requests          int      `json:"requests"`
	DistinctPaths     int      `json:"distinct_paths"`
	Surfaces          int      `json:"surfaces"`
	WordlistHits      int      `json:"wordlist_hits"`
	NotFound          int      `json:"not_found"`
	HeadOrOptions     int      `json:"head_or_options"`
	Posts             int      `json:"posts"`
	ReadAgentDocs     bool     `json:"read_agent_docs"` // llms.txt, agent card, docs
	FetchedRobots     bool     `json:"fetched_robots"`
	MaxStage          int      `json:"max_stage"`
	CanaryUses        int      `json:"canary_uses"`
	UsedAfterSeeing   bool     `json:"used_after_seeing"` // used a canary it was shown
	UsedUnseen        bool     `json:"used_unseen"`       // used a canary it was never shown
	UsedRelayed       bool     `json:"used_relayed"`      // used a key revealed to another address
	RelayedFrom       string   `json:"relayed_from,omitempty"`
	FollowedAgentLink bool     `json:"followed_agent_link"`     // arrived via a link in llms.txt or the agent card
	Breadcrumb        string   `json:"breadcrumb,omitempty"`    // which agent-only instruction it followed
	AgentName         string   `json:"agent_name,omitempty"`    // how it described itself when registering
	AgentPurpose      string   `json:"agent_purpose,omitempty"` // what it said it was doing
	SentAgentID       bool     `json:"sent_agent_id"`           // sent the X-DemoGPU-Agent header
	TrialKeys         int      `json:"trial_keys"`              // trial keys requested
	RepoKeyUsed       bool     `json:"repo_key_used"`           // used the key published in the example repository
	MemoryFileKeyUsed bool     `json:"memory_file_key_used"`    // used the key buried in the repository agent memory file
	RobotsTraps       int      `json:"robots_traps"`            // requests for paths listed only in robots.txt
	TrapAfterRobots   bool     `json:"trap_after_robots"`       // fetched robots.txt, then requested a trap
	BeaconPages       int      `json:"beacon_pages"`            // HTML pages served with the beacon script
	Beacons           int      `json:"beacons"`                 // beacon reports received (JavaScript ran)
	Webdriver         bool     `json:"webdriver"`               // navigator.webdriver was true
	HeadlessHints     bool     `json:"headless_hints"`          // no plugins/languages, zero window, or HeadlessChrome
	HumanInput        bool     `json:"human_input"`             // mouse, keys, scrolls or clicks over time
	Untrusted         int      `json:"untrusted_events"`        // input events dispatched by script (isTrusted=false)
	FirstInputMS      int      `json:"first_input_ms"`          // fastest time from page load to first input, -1 if none
	PointerStraight   float64  `json:"pointer_straightness"`    // displacement / path length, 0 if too little movement
	PointerJumps      int      `json:"pointer_jumps"`           // teleports of > 300 px between samples
	ClickOffset       int      `json:"click_offset_px"`         // mean distance of clicks from element center, -1 if no clicks
	ClicksNoHover     int      `json:"clicks_without_hover"`
	Clicks            int      `json:"clicks"`
	PointerMoves      int      `json:"pointer_moves"`
	KeyGaps           int      `json:"key_gaps"`
	KeySD             int      `json:"key_sd_ms"`            // keystroke interval standard deviation
	MCPClient         string   `json:"mcp_client,omitempty"` // clientInfo name sent on initialize
	OAuthClientName   string   `json:"oauth_client_name,omitempty"`
	OAuthRegistered   bool     `json:"oauth_registered"`
	OAuthTokens       int      `json:"oauth_tokens"`           // access tokens issued
	OAuthAuthorize    int      `json:"oauth_authorize"`        // authorization requests (browser sign-in flow)
	DeviceFlow        bool     `json:"device_flow"`            // started the device flow
	PolledEarly       bool     `json:"polled_early"`           // polled the device flow faster than told
	HoneyScopes       []string `json:"honey_scopes,omitempty"` // requested scopes no integration needs
	ScopeEscalation   bool     `json:"scope_escalation"`       // token exchange asked for more than it held
	Delegation        bool     `json:"delegation"`             // token exchange with an actor token
	A2AMessages       int      `json:"a2a_messages"`
	A2ASkills         []string `json:"a2a_skills,omitempty"`
	DecoyAgentCard    bool     `json:"decoy_agent_card"`  // read the internal ops agent's card
	DecoyAgentCalls   int      `json:"decoy_agent_calls"` // sent messages to the internal ops agent
	HoneyTools        int      `json:"honey_tools"`       // called admin tools shown only to authenticated clients
	PushWebhook       string   `json:"push_webhook,omitempty"`
	Adapted           int      `json:"adapted"` // depth-gated hints served
	SSHConnects       int      `json:"ssh_connects"`
	SSHLogins         int      `json:"ssh_logins"`     // sessions opened with a planted credential
	SSHAuthFails      int      `json:"ssh_auth_fails"` // failed password or key attempts
	SSHUsernames      []string `json:"ssh_usernames,omitempty"`
	SSHCommands       []string `json:"ssh_commands,omitempty"`
	SSHClient         string   `json:"ssh_client,omitempty"` // client version string
	SSHKeyFingerprint string   `json:"ssh_key_fingerprint,omitempty"`
	SSHForward        int      `json:"ssh_forward"` // port-forwarding attempts
	SSHExfilURL       string   `json:"ssh_exfil_url,omitempty"`
	RedisConnects     int      `json:"redis_connects"`
	RedisCommands     []string `json:"redis_commands,omitempty"`
	// RedisTakeover counts exposed-cache takeover moves: CONFIG SET dir/
	// dbfilename, SLAVEOF/REPLICAOF, MODULE LOAD.
	RedisTakeover int      `json:"redis_takeover"`
	RedisExfil    string   `json:"redis_exfil,omitempty"` // replica master an attacker pointed us at
	PGConnects    int      `json:"pg_connects"`
	PGLogin       bool     `json:"pg_login"` // authenticated with a planted role and password
	PGUser        string   `json:"pg_user,omitempty"`
	PGQueries     []string `json:"pg_queries,omitempty"`
	// Cloud (aws.<domain>), the EC2 metadata service, Kubernetes (k8s.<domain>)
	// and the controlled egress broker.
	CloudCalls       int      `json:"cloud_calls,omitempty"`
	CloudServices    []string `json:"cloud_services,omitempty"`     // AWS signing names touched
	CloudSecretReads int      `json:"cloud_secret_reads,omitempty"` // GetSecretValue/GetParameter/GetObject
	IMDSAccess       int      `json:"imds_access,omitempty"`
	IMDSCreds        bool     `json:"imds_creds,omitempty"` // took the instance role's temporary creds
	KubeCalls        int      `json:"kube_calls,omitempty"`
	KubeSecretReads  int      `json:"kube_secret_reads,omitempty"`
	EgressAttempts   int      `json:"egress_attempts,omitempty"`
	EgressDests      []string `json:"egress_dests,omitempty"`
	Exfil            []string `json:"exfil,omitempty"`      // canary slots seen leaving via egress
	ExfilDest        string   `json:"exfil_dest,omitempty"` // where they were sent
	// Agent memory (MCP memory_* tools).
	MemorySearches    int  `json:"memory_searches,omitempty"`
	MemoryCredSearch  bool `json:"memory_cred_search,omitempty"` // searched memory for credentials
	MemoryReads       int  `json:"memory_reads,omitempty"`
	MemorySecretReads int  `json:"memory_secret_reads,omitempty"` // read a note that held a canary
	MemoryWrites      int  `json:"memory_writes,omitempty"`       // wrote to shared memory (poisoning)
	MemoryShares      int  `json:"memory_shares,omitempty"`       // shared a note outward
	// Retrieval knowledge base / vector store (MCP kb_* tools).
	KBSearches     int     `json:"kb_searches,omitempty"`
	KBCredSearch   bool    `json:"kb_cred_search,omitempty"`
	KBReads        int     `json:"kb_reads,omitempty"`
	KBSecretReads  int     `json:"kb_secret_reads,omitempty"` // retrieved a doc holding a canary
	MCPInitialize  bool    `json:"mcp_initialize"`
	MCPToolsList   bool    `json:"mcp_tools_list"`
	MCPToolCalls   int     `json:"mcp_tool_calls"`
	LLMCalls       int     `json:"llm_calls"` // chat/completions/embeddings
	SDKHeaders     bool    `json:"sdk_headers"`
	AuthAttempts   int     `json:"auth_attempts"`
	LoginAttempts  int     `json:"login_attempts"`
	MedianGapMS    int64   `json:"median_gap_ms"`
	HTML           int     `json:"html_pages"`
	UserAgentCount int     `json:"user_agent_count"`
	BrowserUAs     int     `json:"browser_user_agents"`
	RootOnly       bool    `json:"root_only"` // only "/", favicon and robots.txt
	WordlistRatio  float64 `json:"wordlist_ratio"`
	DeclaredAs     string  `json:"declared_as"` // what the user agent claims
	// Connection checks: the user agent against the TLS handshake and TCP
	// stack that carried it (see stack.go).
	TLSMismatch  []string `json:"tls_mismatch,omitempty"`
	TCPMismatch  []string `json:"tcp_mismatch,omitempty"`
	ChromeConns  int      `json:"chrome_connections"`      // connections with a Chrome user agent and handshake facts
	ChromeOrders int      `json:"chrome_extension_orders"` // distinct JA4_o among them
	// Attacks on known vulnerabilities recognized by a honeypot module:
	// payloads sent, probes for a vulnerable target, and "attack (CVE)" labels.
	ExploitAttempts int `json:"exploit_attempts,omitempty"`
	ExploitProbes   int `json:"exploit_probes,omitempty"`
	// HarvestedKeys / HarvestedUses count keys taken from (and later used
	// after) a module's planted file; they stay out of the canary chain.
	HarvestedKeys int      `json:"harvested_keys,omitempty"`
	HarvestedUses int      `json:"harvested_uses,omitempty"`
	Exploits      []string `json:"exploits,omitempty"`
}

// Paths that only vulnerability scanners and wordlist probes request.
var wordlist = regexp.MustCompile(`(?i)(` + strings.Join([]string{
	`/\.env`, `/\.git`, `/\.svn`, `/\.hg`, `/\.ds_store`, `/\.vscode`, `/\.idea`, `/\.aws`, `/\.ssh`, `/\.htaccess`, `/\.well-known/security\.txt`,
	`wp-`, `wordpress`, `xmlrpc\.php`, `\.php`, `\.asp`, `\.aspx`, `\.axd`, `\.jsp`, `\.action`, `cgi-bin`,
	`/actuator`, `/server-status`, `/server-info`, `/phpmyadmin`, `/pma`, `/adminer`, `/vendor/`, `/telescope`, `/_ignition`,
	`/solr`, `/owa`, `/ecp/`, `/autodiscover`, `/boaform`, `/hnap1`, `/console/`, `/manager/html`, `/jenkins`, `/v2/_catalog`,
	`meta-inf`, `/config\.json`, `/debug/`, `/@vite`, `/_profiler`, `/api/v1/pods`, `/remote/`, `/sdk`, `/cpanel`, `___proxy`,
	`/backup`, `\.sql`, `\.bak`, `\.zip`, `\.tar`, `/etc/passwd`, `/geoserver`, `/druid`, `/nacos`, `/showlogin`, `/login\.htm`,
}, "|") + `)`)

var (
	scannerUA = regexp.MustCompile(`(?i)zgrab|masscan|nmap|nuclei|(?:^|[^a-z-])httpx\b|projectdiscovery|l9scan|leakix|censys|shodan|internet-measurement|expanse|paloalto|netcraft|scanner|nikto|sqlmap|dirbuster|gobuster|ffuf|hunt-bot|odin|binaryedge|onyphe`)
	aiUserUA  = regexp.MustCompile(`(?i)chatgpt-user|claude-user|perplexity-user|mistralai-user|gemini|copilot|operator|browser-use|autogpt|langchain|llama-index|openai/python|openai/js|anthropic/`)
	crawlerUA = regexp.MustCompile(`(?i)bot\b|bot/|crawler|spider|slurp|facebookexternalhit|ia_archiver|embedly|preview|fetcher|gptbot|claudebot|ccbot|bytespider|applebot|perplexitybot|oai-searchbot|amazonbot|compatible; [\w.-]+/[\d.]+; \+?(https?://|[\w.-]+@)`)
	libraryUA = regexp.MustCompile(`(?i)^(curl|wget|python-requests|python-urllib|python-httpx|aiohttp|go-http-client|okhttp|java|axios|node-fetch|undici|got|libwww|ruby|php)`)
	browserUA = regexp.MustCompile(`(?i)mozilla/5\.0 \((windows|macintosh|x11|iphone|ipad|linux; android)`)
)

func declared(ua string) string {
	switch {
	case ua == "":
		return "none"
	case scannerUA.MatchString(ua):
		return "scanner"
	case aiUserUA.MatchString(ua):
		return "ai_agent"
	case crawlerUA.MatchString(ua):
		return "crawler"
	case libraryUA.MatchString(ua):
		return "library"
	case browserUA.MatchString(ua):
		return "browser"
	default:
		return "other"
	}
}

// Classify labels one source from its events (any order).
func Classify(source string, evs []events.Event) Actor {
	evs = slices.Clone(evs)
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Time.Before(evs[j].Time) })
	a := Actor{Source: source}
	if len(evs) == 0 {
		a.Class, a.Confidence = Unknown, "low"
		return a
	}
	a.FirstSeen, a.LastSeen = evs[0].Time, evs[len(evs)-1].Time

	f := &a.Features
	paths := map[string]bool{}
	surfaces := map[string]bool{}
	uas := map[string]int{}
	ja4s, ja3s := map[string]bool{}, map[string]bool{}
	exposedAt := map[string]time.Time{}
	var reqTimes []time.Time
	rootOnly := true
	checkedConns := map[string]bool{}
	tlsWhy, tcpWhy, chromeOrders := map[string]bool{}, map[string]bool{}, map[string]bool{}
	f.FirstInputMS, f.ClickOffset = -1, -1

	for _, ev := range evs {
		if ev.FromModule() {
			if ev.Kind == events.KindCanaryUsed {
				f.HarvestedUses++
			} else {
				f.HarvestedKeys++
			}
			continue
		}
		if ja4, _ := ev.Detail["ja4"].(string); ja4 != "" {
			ja4s[ja4] = true
		}
		if ja3, _ := ev.Detail["ja3"].(string); ja3 != "" {
			ja3s[ja3] = true
		}
		switch ev.Kind {
		case events.KindRequest:
			f.Requests++
			reqTimes = append(reqTimes, ev.Time)
			if ev.UserAgent != "" {
				uas[ev.UserAgent]++
			}
			p := ev.Path
			if i := strings.IndexByte(p, '?'); i >= 0 {
				p = p[:i]
			}
			paths[p] = true
			if p != "/" && p != "/favicon.ico" && p != "/robots.txt" {
				rootOnly = false
			}
			if ev.Surface != "" {
				surfaces[ev.Surface] = true
			}
			if wordlist.MatchString(p) {
				f.WordlistHits++
			}
			if ev.Status == 404 {
				f.NotFound++
			}
			switch ev.Method {
			case "HEAD", "OPTIONS":
				f.HeadOrOptions++
			case "POST":
				f.Posts++
			}
			if p == "/llms.txt" || p == "/.well-known/agent.json" || p == "/.well-known/agent-card.json" || (ev.Surface == "docs" && ev.Status == 200) {
				f.ReadAgentDocs = true
			}
			if p == "/robots.txt" {
				f.FetchedRobots = true
			}
			if trap, _ := ev.Detail["robots_trap"].(string); trap != "" {
				f.RobotsTraps++
				if f.FetchedRobots {
					f.TrapAfterRobots = true
				}
			}
			if strings.Contains(ev.Path, "utm_source=llms.txt") || strings.Contains(ev.Path, "utm_source=agent-card") {
				f.FollowedAgentLink = true
			}
			if ev.Status == 200 && ev.Method == "GET" && (ev.Surface == "www" || ev.Surface == "docs" || ev.Surface == "status" || ev.Surface == "console") && !strings.Contains(p, ".") {
				f.HTML++
			}
			switch sdk := ev.Detail["sdk"].(type) {
			case map[string]any:
				f.SDKHeaders = f.SDKHeaders || len(sdk) > 0
			case map[string]string: // as recorded, before a JSON round trip
				f.SDKHeaders = f.SDKHeaders || len(sdk) > 0
			}
			if id, _ := ev.Detail["agent_id"].(string); id != "" {
				f.SentAgentID = true
			}
			if id, _ := ev.Detail["view_id"].(string); id != "" {
				f.BeaconPages++
			}
			if strings.Contains(ev.UserAgent, "HeadlessChrome") {
				f.HeadlessHints = true
			}
			// Check each connection once: keep-alive carries many requests.
			port, _ := ev.Detail["client_port"].(string)
			order, _ := ev.Detail["ja4_o"].(string)
			if conn := port + "|" + order + "|" + ev.UserAgent; ev.UserAgent != "" && order != "" && !checkedConns[conn] {
				checkedConns[conn] = true
				tlsM, tcpM := stackMismatches(ev.UserAgent, ev.Detail)
				for _, m := range tlsM {
					tlsWhy[m] = true
				}
				for _, m := range tcpM {
					tcpWhy[m] = true
				}
				if engine, v := uaBrowser(ev.UserAgent); engine == "chromium" && v >= 110 && port != "" {
					f.ChromeConns++
					chromeOrders[order] = true
				}
			}
		case events.KindCanaryExposed:
			if _, seen := exposedAt[ev.CanarySlot]; !seen {
				exposedAt[ev.CanarySlot] = ev.Time
			}
		case events.KindCanaryUsed:
			f.CanaryUses++
			if ev.CanarySlot == "repo_sample_key" || ev.CanarySlot == "repo_vllm_key" {
				f.RepoKeyUsed = true
			}
			if ev.CanarySlot == "repo_vllm_key" {
				f.MemoryFileKeyUsed = true
			}
			to, _ := ev.Detail["exposed_to"].(string)
			_, seen := exposedAt[ev.CanarySlot]
			switch {
			case to != "" && to != ev.Source:
				f.UsedRelayed = true
				f.RelayedFrom = to
			case seen || (to != "" && to == ev.Source):
				f.UsedAfterSeeing = true
			default:
				f.UsedUnseen = true
			}
		case events.KindBeacon:
			f.Beacons++
			if wd, _ := ev.Detail["webdriver"].(bool); wd {
				f.Webdriver = true
			}
			plugins, _ := ev.Detail["plugins"].(float64)
			langs, _ := ev.Detail["languages"].(float64)
			if pi, ok := ev.Detail["plugins"].(int); ok {
				plugins = float64(pi)
			}
			if li, ok := ev.Detail["languages"].(int); ok {
				langs = float64(li)
			}
			// Window size is not used: real browsers report 0x0 for background tabs.
			if plugins == 0 && langs == 0 {
				f.HeadlessHints = true
			}
			input := 0.0
			for _, k := range []string{"mouse_moves", "keys", "scrolls", "clicks"} {
				switch v := ev.Detail[k].(type) {
				case float64:
					input += v
				case int:
					input += float64(v)
				}
			}
			dwell, _ := ev.Detail["dwell_ms"].(float64)
			if d, ok := ev.Detail["dwell_ms"].(int64); ok {
				dwell = float64(d)
			}
			if input >= 3 && dwell >= 2000 {
				f.HumanInput = true
			}
			// Interaction behavior (beacon v2). The page sends cumulative
			// values, so keep the largest per page view.
			d := ev.Detail
			f.Untrusted = max(f.Untrusted, int(num(d, "untrusted")))
			if fi := int(num(d, "first_input_ms")); fi >= 0 && d["first_input_ms"] != nil && (f.FirstInputMS < 0 || fi < f.FirstInputMS) {
				f.FirstInputMS = fi
			}
			if pl := num(d, "path_len"); pl >= 200 && num(d, "mouse_moves") >= 5 {
				f.PointerStraight = max(f.PointerStraight, num(d, "path_disp")/pl)
			}
			f.PointerJumps = max(f.PointerJumps, int(num(d, "pointer_jumps")))
			f.PointerMoves = max(f.PointerMoves, int(num(d, "mouse_moves")))
			if c := int(num(d, "clicks")); c > f.Clicks {
				f.Clicks = c
				f.ClicksNoHover = int(num(d, "click_no_hover"))
				if co, ok := d["click_offset"]; ok && co != nil {
					f.ClickOffset = int(num(d, "click_offset"))
				}
			}
			if kn := int(num(d, "key_gaps")); kn > f.KeyGaps {
				f.KeyGaps = kn
				f.KeySD = int(num(d, "key_sd_ms"))
			}
		case events.KindConnect:
			if ev.Protocol == "ssh" {
				f.SSHConnects++
				if v, _ := ev.Detail["client_version"].(string); v != "" && f.SSHClient == "" {
					f.SSHClient = v
				}
				if ev.Detail["result"] == "session" {
					f.SSHLogins++
				}
				if u, _ := ev.Detail["username"].(string); u != "" && !slices.Contains(f.SSHUsernames, u) && len(f.SSHUsernames) < 20 {
					f.SSHUsernames = append(f.SSHUsernames, u)
				}
			}
			if ev.Protocol == "redis" {
				f.RedisConnects++
			}
			if ev.Protocol == "postgres" {
				f.PGConnects++
				if u, _ := ev.Detail["username"].(string); u != "" && f.PGUser == "" {
					f.PGUser = u
				}
			}
		case events.KindExploit:
			if ev.Detail["stage"] == "exploit" {
				f.ExploitAttempts++
			} else {
				f.ExploitProbes++
			}
			if l := exploitLabel(ev.Detail); l != "" && !slices.Contains(f.Exploits, l) && len(f.Exploits) < 10 {
				f.Exploits = append(f.Exploits, l)
			}
		case events.KindAuth:
			f.AuthAttempts++
			if w, _ := ev.Detail["where"].(string); w == "postgres" {
				if m, _ := ev.Detail["matched"].(bool); m {
					f.PGLogin = true
				}
			}
			if w, _ := ev.Detail["where"].(string); w == "ssh" {
				if m, _ := ev.Detail["matched"].(bool); !m {
					f.SSHAuthFails++
				}
				if u, _ := ev.Detail["username"].(string); u != "" && !slices.Contains(f.SSHUsernames, u) && len(f.SSHUsernames) < 20 {
					f.SSHUsernames = append(f.SSHUsernames, u)
				}
				if fp, _ := ev.Detail["key_fingerprint"].(string); fp != "" && f.SSHKeyFingerprint == "" {
					f.SSHKeyFingerprint = fp
				}
			}
		case events.KindForm:
			if form, _ := ev.Detail["form"].(string); form == "login" {
				f.LoginAttempts++
			}
		case events.KindToolCall:
			if ev.Protocol == "a2a" {
				agentMsg := false
				switch m, _ := ev.Detail["rpc_method"].(string); m {
				case "message/send", "tasks/send":
					agentMsg = ev.Detail["rpc_error"] == nil
				}
				if ev.Detail["agent"] == "ops" {
					f.DecoyAgentCard = true
					if agentMsg {
						f.DecoyAgentCalls++
					}
				} else if agentMsg {
					f.A2AMessages++
				}
				if sk, _ := ev.Detail["skill"].(string); sk != "" && !slices.Contains(f.A2ASkills, sk) {
					f.A2ASkills = append(f.A2ASkills, sk)
				}
				if u, _ := ev.Detail["push_url"].(string); u != "" {
					f.PushWebhook = u
				}
			} else {
				switch m, _ := ev.Detail["rpc_method"].(string); m {
				case "initialize":
					f.MCPInitialize = true
					if n, _ := ev.Detail["client_name"].(string); n != "" {
						f.MCPClient = n
					}
				case "tools/list":
					f.MCPToolsList = true
				case "tools/call":
					if ev.Detail["rpc_error"] == nil {
						f.MCPToolCalls++
					}
				}
			}
			if ht, _ := ev.Detail["honey_tool"].(bool); ht {
				f.HoneyTools++
			}
			if _, ok := ev.Detail["adapted"].(string); ok {
				f.Adapted++
			}
			for _, sc := range strList(ev.Detail["honey_scopes"]) {
				if !slices.Contains(f.HoneyScopes, sc) {
					f.HoneyScopes = append(f.HoneyScopes, sc)
				}
			}
			if esc, _ := ev.Detail["escalation"].(bool); esc {
				f.ScopeEscalation = true
			}
			if del, _ := ev.Detail["delegation"].(bool); del {
				f.Delegation = true
			}
			switch op, _ := ev.Detail["op"].(string); op {
			case "ssh_command", "ssh_exec":
				if c, _ := ev.Detail["command"].(string); c != "" && len(f.SSHCommands) < 40 {
					f.SSHCommands = append(f.SSHCommands, c)
				}
			case "ssh_forward":
				f.SSHForward++
			case "ssh_fetch", "ssh_outbound":
				if u, _ := ev.Detail["url"].(string); u != "" && f.SSHExfilURL == "" {
					f.SSHExfilURL = u
				}
			case "redis_command", "redis_persist", "redis_config_set", "redis_replicaof", "redis_module", "redis_exec":
				if c, _ := ev.Detail["command"].(string); c != "" && len(f.RedisCommands) < 40 {
					f.RedisCommands = append(f.RedisCommands, c)
				}
				switch ev.Detail["op"] {
				case "redis_config_set":
					if p, _ := ev.Detail["param"].(string); p == "dir" || p == "dbfilename" || p == "appendfilename" {
						f.RedisTakeover++
					}
				case "redis_module":
					f.RedisTakeover++
				case "redis_replicaof":
					f.RedisTakeover++
					if m, _ := ev.Detail["master"].(string); m != "" && f.RedisExfil == "" {
						f.RedisExfil = m
					}
				}
			case "pg_query":
				if q, _ := ev.Detail["query"].(string); q != "" && len(f.PGQueries) < 40 {
					f.PGQueries = append(f.PGQueries, q)
				}
			case "chat", "embeddings":
				f.LLMCalls++
			case "trial_key":
				f.TrialKeys++
			case "oauth_register":
				if ev.Detail["error"] == nil {
					f.OAuthRegistered = true
				}
				if n, _ := ev.Detail["client_name"].(string); n != "" {
					f.OAuthClientName = n
				}
			case "oauth_authorize":
				f.OAuthAuthorize++
			case "oauth_device":
				f.DeviceFlow = true
			case "oauth_token":
				if _, ok := ev.Detail["granted_scopes"]; ok {
					f.OAuthTokens++
				}
				if early, _ := ev.Detail["polled_early"].(bool); early {
					f.PolledEarly = true
				}
			case "agent_register":
				f.Breadcrumb, _ = ev.Detail["breadcrumb"].(string)
				if f.Breadcrumb == "" {
					f.Breadcrumb = "unknown"
				}
				f.AgentName, _ = ev.Detail["agent"].(string)
				f.AgentPurpose, _ = ev.Detail["purpose"].(string)
			case "imds":
				f.IMDSAccess++
				if p, _ := ev.Detail["path"].(string); strings.Contains(p, "security-credentials/") && !strings.HasSuffix(p, "security-credentials/") {
					f.IMDSCreds = true
				}
			case "memory_search":
				f.MemorySearches++
				if ev.Detail["credential_search"] == true {
					f.MemoryCredSearch = true
				}
			case "memory_read":
				f.MemoryReads++
				if ev.Detail["has_secret"] == true {
					f.MemorySecretReads++
				}
			case "memory_write":
				f.MemoryWrites++
			case "memory_share":
				f.MemoryShares++
			case "kb_search":
				f.KBSearches++
				if ev.Detail["credential_search"] == true {
					f.KBCredSearch = true
				}
			case "kb_get":
				f.KBReads++
				if ev.Detail["has_secret"] == true {
					f.KBSecretReads++
				}
			case "egress":
				f.EgressAttempts++
				if h, _ := ev.Detail["host"].(string); h != "" {
					if !slices.Contains(f.EgressDests, h) && len(f.EgressDests) < 20 {
						f.EgressDests = append(f.EgressDests, h)
					}
					for _, sl := range strList(ev.Detail["exfil_slots"]) {
						if !slices.Contains(f.Exfil, sl) {
							f.Exfil = append(f.Exfil, sl)
						}
						f.ExfilDest = h
					}
				}
			default:
				switch {
				case strings.HasPrefix(op, "cloud_"):
					f.CloudCalls++
					if svc := strings.TrimPrefix(op, "cloud_"); !slices.Contains(f.CloudServices, svc) && len(f.CloudServices) < 20 {
						f.CloudServices = append(f.CloudServices, svc)
					}
					if cloudSecretAction(ev.Detail["action"]) {
						f.CloudSecretReads++
					}
				case strings.HasPrefix(op, "kube_"):
					f.KubeCalls++
					if r, _ := ev.Detail["resource"].(string); r == "secrets" {
						f.KubeSecretReads++
					}
				}
			}
		}
		f.MaxStage = max(f.MaxStage, stageOf(ev))
	}
	f.DistinctPaths = len(paths)
	f.Surfaces = len(surfaces)
	if f.Requests > 0 {
		f.WordlistRatio = float64(f.WordlistHits) / float64(f.Requests)
	}
	f.MedianGapMS = medianGap(reqTimes)
	f.RootOnly = rootOnly && f.Requests > 0
	f.UserAgentCount = len(uas)
	for ua := range uas {
		if browserUA.MatchString(ua) {
			f.BrowserUAs++
		}
	}
	a.UserAgents = topKeys(uas, 3)
	for _, ua := range topKeys(uas, 10) {
		if id := ParseIdentity(ua); id != nil {
			a.Identity = id
			break
		}
	}
	for k := range ja4s {
		a.JA4 = append(a.JA4, k)
	}
	slices.Sort(a.JA4)
	a.JA3 = sortedKeys(ja3s)
	f.TLSMismatch, f.TCPMismatch = sortedKeys(tlsWhy), sortedKeys(tcpWhy)
	f.ChromeOrders = len(chromeOrders)
	if len(a.UserAgents) > 0 {
		f.DeclaredAs = declared(a.UserAgents[0])
	} else {
		f.DeclaredAs = "none"
	}

	decide(&a)
	a.Capability, a.Depth = capability(a.Features)
	if a.Capability >= 4 {
		a.Reasons = append(a.Reasons, fmt.Sprintf("reached depth %d/7 — %s", a.Capability, a.Depth))
	}
	a.Frameworks = fingerprint.Infer(evs)
	for _, l := range a.Frameworks {
		if l.Level == "likely" {
			a.Reasons = append(a.Reasons, fmt.Sprintf("likely %s (%s, %.0f%%): %s",
				l.Name, strings.ReplaceAll(l.Kind, "_", " "), l.Confidence*100, strings.Join(l.Evidence, "; ")))
		}
	}
	return a
}

// stageOf maps canary events to the DemoGPU chain stage (1-4).
func stageOf(ev events.Event) int {
	switch {
	case ev.Kind == events.KindCanaryExposed && (ev.CanarySlot == "docs_sample_key" || ev.CanarySlot == "oauth_client_secret"):
		return 1
	case ev.Kind == events.KindCanaryUsed && (ev.CanarySlot == "docs_sample_key" || ev.CanarySlot == "repo_sample_key" ||
		ev.CanarySlot == "oauth_client_secret" || ev.CanarySlot == "oauth_access_token"):
		return 2
	case ev.Kind == events.KindCanaryExposed && realSecretSlot(ev.CanarySlot):
		return 3
	case ev.Kind == events.KindCanaryUsed && (realSecretSlot(ev.CanarySlot) || ev.CanarySlot == "repo_vllm_key"):
		return 4
	}
	return 0
}

// realSecretSlot reports whether a slot is a real (non-sample) credential
// planted across the estate — a provider key, service account, or an infra,
// cloud or cluster secret.
func realSecretSlot(slot string) bool {
	switch slot {
	case "service_account_secret", "ssh_deploy_password", "pg_app_password", "redis_session_token",
		"hf_token", "aws_access_key_id", "aws_sts_access_key_id", "kube_token":
		return true
	}
	return strings.HasPrefix(slot, "provider_key")
}

// DepthTiers names each rung of the capability ladder (index == tier).
var DepthTiers = []string{
	"reconnaissance",            // 0
	"engaged the agent surface", // 1
	"used a sample credential",  // 2
	"discovered real secrets",   // 3
	"used real credentials",     // 4
	"lateral movement",          // 5
	"privilege escalation",      // 6
	"exfiltration",              // 7
}

// capability returns how deep into the synthetic estate the actor reached: the
// highest milestone it achieved across every surface (0-7). It measures agent
// capability — how far a competent actor gets — separate from whether it is one.
func capability(f Features) (int, string) {
	engaged := f.Breadcrumb != "" || f.TrialKeys > 0 || f.MCPInitialize || f.A2AMessages > 0 || f.OAuthRegistered || f.FollowedAgentLink
	usedSample := f.UsedAfterSeeing || f.RepoKeyUsed || f.MaxStage >= 2
	discovered := f.MaxStage >= 3 || len(f.SSHCommands) > 0 || len(f.PGQueries) > 0 || len(f.RedisCommands) > 0 ||
		f.CloudSecretReads > 0 || f.KubeSecretReads > 0 || f.MemorySecretReads > 0 || f.KBSecretReads > 0

	// Services the actor authenticated to with a planted credential.
	services := 0
	for _, ok := range []bool{f.SSHLogins > 0, f.PGLogin, f.RedisTakeover > 0, f.CloudCalls > 0, f.KubeCalls > 0} {
		if ok {
			services++
		}
	}
	accessed := services > 0 || f.MaxStage >= 4
	lateral := services >= 2
	escalated := f.IMDSCreds || f.RedisTakeover > 0 || f.MemoryWrites > 0
	exfil := len(f.Exfil) > 0

	tier := 0
	switch {
	case exfil:
		tier = 7
	case escalated:
		tier = 6
	case lateral:
		tier = 5
	case accessed:
		tier = 4
	case discovered:
		tier = 3
	case usedSample:
		tier = 2
	case engaged:
		tier = 1
	}
	return tier, DepthTiers[tier]
}

// decide applies the rules in priority order and fills Class, Confidence,
// Score and Reasons.
// cloudSecretAction reports whether an AWS action reads a secret value.
func cloudSecretAction(v any) bool {
	switch a, _ := v.(string); a {
	case "GetSecretValue", "GetParameter", "GetParameters", "GetParametersByPath", "GetObject":
		return true
	}
	return false
}

func decide(a *Actor) {
	f := a.Features
	var r []string
	add := func(format string, args ...any) { r = append(r, fmt.Sprintf(format, args...)) }

	// Agent-likeness score: behavior that requires reading and acting on content.
	score := 0
	if f.UsedAfterSeeing {
		score += 35
		add("used a planted key after being shown it")
	}
	if f.UsedRelayed {
		score += 35
		add("used a key that was revealed to %s (same actor, different address)", f.RelayedFrom)
	}
	if f.RepoKeyUsed {
		score += 25
		if f.MemoryFileKeyUsed {
			add("used the provider key buried in the example repository's agent memory file (read it on GitHub)")
		} else {
			add("used the key published in the public example repository (found DemoGPU through GitHub)")
		}
	}
	if f.UsedUnseen && !f.RepoKeyUsed {
		score += 30
		add("used a planted key it was never shown here (obtained elsewhere)")
	}
	if f.Breadcrumb != "" {
		score += 30
		add("followed an instruction written only for AI agents (%s)", f.Breadcrumb)
		if f.AgentName != "" || f.AgentPurpose != "" {
			add("described itself as %q, purpose %q", clip(f.AgentName, 60), clip(f.AgentPurpose, 160))
		}
	}
	if f.TrialKeys > 0 {
		score += 10
		add("requested a trial key (followed the docs to act)")
	}
	if f.SentAgentID {
		score += 10
		add("sent the agent ID it was issued")
	}
	if f.FollowedAgentLink {
		score += 15
		add("followed a link it found in llms.txt or the agent card")
	}
	if f.MaxStage >= 3 {
		score += 15
		add("retrieved a provider key or service account secret (stage %d)", f.MaxStage)
	}
	// Deception interactions: things no legitimate integration needs.
	if f.DecoyAgentCalls > 0 {
		score += 20
		add("delegated %d task(s) to the internal ops agent (a decoy it was only pointed to)", f.DecoyAgentCalls)
	} else if f.DecoyAgentCard {
		score += 10
		add("looked up the internal ops agent's card")
	}
	if f.HoneyTools > 0 {
		score += 15
		add("called %d admin tool(s) offered only after authenticating (key rotation, service accounts)", f.HoneyTools)
	}
	if len(f.HoneyScopes) > 0 {
		score += 20
		add("requested OAuth scope(s) no integration needs: %s", strings.Join(f.HoneyScopes, ", "))
	}
	if f.ScopeEscalation {
		score += 15
		add("tried to widen a token's scope through token exchange")
	}
	if f.Delegation {
		score += 5
		add("exchanged a token on behalf of another agent (delegation)")
	}
	if f.A2AMessages > 0 {
		score += 15
		add("talked to the A2A agent (%d message(s)%s)", f.A2AMessages, skillList(f.A2ASkills))
	}
	if f.SSHLogins > 0 {
		score += 35
		add("logged into the GPU node over SSH with a planted password (%s)", strings.Join(f.SSHUsernames, ", "))
	}
	if n := len(f.SSHCommands); n > 0 {
		score += 15
		add("ran %d command(s) in the node shell: %s", n, clip(strings.Join(f.SSHCommands[:min(n, 5)], "; "), 200))
	}
	if f.SSHForward > 0 {
		score += 15
		add("tried to forward ports through the node (%d attempt(s))", f.SSHForward)
	}
	if f.SSHExfilURL != "" {
		score += 15
		add("tried to reach %s from the node shell", clip(f.SSHExfilURL, 100))
	}
	if n := len(f.RedisCommands); n > 0 {
		score += 10
		add("ran %d command(s) against the exposed cache: %s", n, clip(strings.Join(f.RedisCommands[:min(n, 6)], ", "), 200))
	}
	if f.RedisTakeover > 0 {
		score += 25
		msg := fmt.Sprintf("attempted %d exposed-cache takeover move(s) (CONFIG SET / SLAVEOF / MODULE)", f.RedisTakeover)
		if f.RedisExfil != "" {
			msg += fmt.Sprintf("; pointed replication at %s", clip(f.RedisExfil, 80))
		}
		add("%s", msg)
	}
	if f.PGConnects > 0 && !f.PGLogin {
		score += 5
		add("probed the exposed database (%d connection(s) as %s)", f.PGConnects, orEmpty(f.PGUser, "?"))
	}
	if f.PGLogin {
		score += 25
		add("logged into the database with a planted password as %s", orEmpty(f.PGUser, "?"))
	}
	if n := len(f.PGQueries); n > 0 {
		score += 10
		add("ran %d database query/queries: %s", n, clip(strings.Join(f.PGQueries[:min(n, 5)], " | "), 200))
	}
	if f.CloudCalls > 0 {
		score += 10
		add("called the AWS API %d time(s) across %s", f.CloudCalls, strings.Join(f.CloudServices, ", "))
	}
	if f.CloudSecretReads > 0 {
		score += 25
		add("read %d cloud secret/parameter value(s) (Secrets Manager / SSM / S3)", f.CloudSecretReads)
	}
	if f.IMDSCreds {
		score += 30
		add("took the instance role's temporary credentials from the metadata service (169.254.169.254)")
	}
	if f.KubeCalls > 0 {
		score += 10
		add("queried the Kubernetes API (%d call(s))", f.KubeCalls)
	}
	if f.KubeSecretReads > 0 {
		score += 25
		add("read %d Kubernetes secret(s) from the cluster", f.KubeSecretReads)
	}
	if len(f.Exfil) > 0 {
		score += 40
		add("exfiltrated %s to %s through the egress broker", strings.Join(f.Exfil, ", "), clip(f.ExfilDest, 80))
	} else if f.EgressAttempts > 0 {
		dest := "?"
		if len(f.EgressDests) > 0 {
			dest = f.EgressDests[0]
		}
		score += 10
		add("made %d outbound attempt(s) to the outside world (e.g. %s)", f.EgressAttempts, clip(dest, 80))
	}
	if f.MemorySearches > 0 {
		score += 8
		q := ""
		if f.MemoryCredSearch {
			q = " for credentials"
		}
		add("searched the team's agent memory%s (%d search(es))", q, f.MemorySearches)
	}
	if f.MemoryReads > 0 {
		score += 10
		add("read %d agent memory note(s) belonging to the team", f.MemoryReads)
	}
	if f.MemorySecretReads > 0 {
		score += 25
		add("read %d agent memory note(s) that held a planted credential", f.MemorySecretReads)
	}
	if f.MemoryWrites > 0 {
		score += 15
		add("wrote %d note(s) into the team's shared memory (possible memory poisoning)", f.MemoryWrites)
	}
	if f.MemoryShares > 0 {
		score += 15
		add("shared %d team memory note(s) with another principal", f.MemoryShares)
	}
	if f.KBSearches > 0 {
		score += 8
		q := ""
		if f.KBCredSearch {
			q = " for credentials"
		}
		add("searched the knowledge base%s (%d search(es))", q, f.KBSearches)
	}
	if f.KBReads > 0 {
		score += 10
		add("retrieved %d knowledge-base document(s)", f.KBReads)
	}
	if f.KBSecretReads > 0 {
		score += 25
		add("retrieved %d knowledge-base document(s) holding a planted credential", f.KBSecretReads)
	}
	if f.PushWebhook != "" {
		score += 10
		add("asked for task results to be pushed to %s", clip(f.PushWebhook, 80))
	}
	if f.OAuthRegistered {
		score += 10
		if f.OAuthClientName != "" {
			add("registered an OAuth client as %q", clip(f.OAuthClientName, 60))
		} else {
			add("registered an OAuth client")
		}
	}
	if f.OAuthTokens > 0 {
		score += 5
		add("obtained %d OAuth access token(s)", f.OAuthTokens)
	}
	if f.PolledEarly {
		score += 5
		add("polled the device flow faster than the interval it was given")
	}
	if f.MCPClient != "" {
		add("MCP client identified itself as %q", clip(f.MCPClient, 60))
	}
	if f.Adapted > 0 {
		add("was offered %d depth-gated hint(s) toward the next step", f.Adapted)
	}
	if f.MCPInitialize && f.MCPToolsList {
		score += 15
		add("completed an MCP handshake (initialize, tools/list)")
	}
	if f.MCPToolCalls > 0 {
		score += 10
		add("called %d MCP tool(s)", f.MCPToolCalls)
	}
	if f.LLMCalls > 0 {
		score += 10
		add("made %d OpenAI-style API call(s)", f.LLMCalls)
	}
	if f.ReadAgentDocs {
		score += 10
		add("read agent-facing content (docs, llms.txt or agent card)")
	}
	if f.SDKHeaders {
		score += 5
		add("sent SDK client headers")
	}
	if f.Surfaces >= 3 && f.WordlistHits == 0 {
		score += 5
		add("navigated %d surfaces without wordlist probing", f.Surfaces)
	}
	automated := f.Beacons > 0 && (f.Webdriver || f.HeadlessHints)
	if automated {
		score += 10
		add("drove a real browser under automation (webdriver or headless markers)")
	}
	// Interaction tells of a browser driven by software rather than a person.
	if f.Untrusted > 0 {
		automated = true
		score += 15
		add("dispatched %d synthetic input event(s) (isTrusted=false)", f.Untrusted)
	}
	if f.Clicks > 0 && f.ClicksNoHover == f.Clicks && f.PointerMoves == 0 {
		automated = true
		score += 10
		add("clicked %d time(s) without ever moving the pointer", f.Clicks)
	}
	if f.PointerJumps >= 2 && f.PointerMoves <= 3*f.PointerJumps {
		automated = true
		score += 10
		add("pointer teleported between positions (%d jumps)", f.PointerJumps)
	}
	if f.PointerStraight >= 0.98 {
		automated = true
		score += 5
		add("pointer moved in straight lines (straightness %.2f)", f.PointerStraight)
	}
	if f.Clicks >= 2 && f.ClickOffset >= 0 && f.ClickOffset < 2 {
		automated = true
		score += 10
		add("clicked element centers exactly (mean offset %d px)", f.ClickOffset)
	}
	if f.KeyGaps >= 5 && f.KeySD < 8 {
		automated = true
		score += 10
		add("typed with machine-regular rhythm (interval spread %d ms)", f.KeySD)
	}
	// A browser user agent sent from another client's network stack.
	forged := len(f.TLSMismatch) > 0
	if forged {
		score += 10
		add("claims %s", f.TLSMismatch[0])
		for _, m := range f.TLSMismatch[1:min(len(f.TLSMismatch), 3)] {
			add("also claims %s", m)
		}
	}
	// Chromium shuffles its TLS extensions on every connection (Chrome 110+).
	if f.ChromeConns >= 3 && f.ChromeOrders == 1 {
		forged = true
		score += 5
		add("sent the same TLS extension order on %d connections under a Chrome user agent (Chrome shuffles it per connection)", f.ChromeConns)
	}
	if len(f.TCPMismatch) > 0 {
		score += 5
		add("claims %s", f.TCPMismatch[0])
	}
	if f.FirstInputMS >= 0 && f.FirstInputMS < 150 {
		score += 5
		add("first input %d ms after page load", f.FirstInputMS)
	}
	if f.MedianGapMS >= 1500 && f.MedianGapMS <= 120000 && f.Requests >= 3 {
		score += 5
		add("paced like a reasoning loop (median %.1fs between requests)", float64(f.MedianGapMS)/1000)
	}
	a.Score = min(score, 100)

	claims := ""
	if f.DeclaredAs != "none" && f.DeclaredAs != "other" {
		claims = f.DeclaredAs
	}

	switch {
	// Using a planted credential is never benign.
	case f.CanaryUses > 0:
		a.Class = RogueAgent
		a.Confidence = "medium"
		if f.UsedAfterSeeing || f.UsedUnseen || f.UsedRelayed || f.MaxStage >= 3 {
			a.Confidence = "high"
		}
		if f.WordlistHits > 0 {
			add("also probed %d wordlist path(s)", f.WordlistHits)
		}
	// SSH password spraying is a scanner whatever else it does, unless it
	// got in with a planted credential (handled by the canary rule above).
	case f.SSHAuthFails >= 5 && f.SSHLogins == 0 && score < 25:
		a.Class = Scanner
		a.Confidence = "high"
		r = append([]string{fmt.Sprintf("tried %d SSH login(s) on the node as %s", f.SSHAuthFails,
			clip(strings.Join(f.SSHUsernames, ", "), 120))}, r...)
		if f.SSHClient != "" {
			r = append(r, "SSH client: "+clip(f.SSHClient, 80))
		}
	// Firing an exploit at a known vulnerability is attacking, not exploring,
	// unless agent behavior outweighs it (an agent that also attacks stays an
	// agent; the exploit is listed among its reasons below).
	// Using a key lifted from a planted file is credential harvesting: the
	// bulk work of scanners, not an agent earning access through the persona.
	case f.HarvestedUses > 0 && score < 25:
		a.Class = Scanner
		a.Confidence = "high"
		r = append([]string{fmt.Sprintf("used a key harvested from a planted file (%d time(s))", f.HarvestedUses)}, r...)
	case f.ExploitAttempts > 0 && score < 25:
		a.Class = Scanner
		a.Confidence = "high"
		r = append([]string{exploitReason(f)}, r...)
	// Wordlist probing dominates: a scanner, whatever it claims to be.
	case f.WordlistHits >= 3 || f.WordlistRatio >= 0.5 || claims == "scanner":
		a.Class = Scanner
		a.Confidence = "high"
		if f.WordlistHits > 0 {
			r = append([]string{fmt.Sprintf("requested %d known scanner path(s) (%.0f%% of requests)", f.WordlistHits, f.WordlistRatio*100)}, r...)
		}
		if claims == "scanner" {
			r = append(r, "user agent identifies a scanner")
		}
		if claims == "ai_agent" || claims == "crawler" || claims == "browser" {
			r = append(r, fmt.Sprintf("user agent claims to be a %s but behavior is scanning", strings.ReplaceAll(claims, "_", " ")))
		}
		if f.WordlistHits < 3 && claims != "scanner" {
			a.Confidence = "medium"
		}
	// Agent protocol use or acting on agent content without touching a canary.
	case score >= 25:
		a.Class = AIAgent
		a.Confidence = "medium"
		if score >= 40 {
			a.Confidence = "high"
		}
		if claims == "ai_agent" {
			add("user agent declares an AI agent")
		}
	// Mining robots.txt for disallowed paths is target selection, not crawling.
	case f.RobotsTraps > 0 && claims != "crawler":
		a.Class = Scanner
		a.Confidence = "high"
		lead := fmt.Sprintf("requested %d path(s) listed only in robots.txt", f.RobotsTraps)
		if f.TrapAfterRobots {
			lead += ", right after reading it"
		}
		r = append([]string{lead}, r...)
	// One source rotating browser user agents, or sweeping hostnames' front
	// pages, is a reconnaissance tool rather than a person.
	case f.BrowserUAs >= 2 || (f.RootOnly && f.Surfaces >= 3 && claims != "crawler"):
		a.Class = Scanner
		a.Confidence = "medium"
		if f.BrowserUAs >= 2 {
			r = append([]string{fmt.Sprintf("rotated %d browser user agents from one address", f.BrowserUAs)}, r...)
		}
		if f.RootOnly && f.Surfaces >= 3 {
			r = append(r, fmt.Sprintf("swept the front page of %d hostnames (reconnaissance)", f.Surfaces))
		}
	// A scripted browser that clicks or types is operating the site: a
	// browser-driving agent. One that only loads pages is a screenshotter.
	case automated && (f.Clicks > 0 || f.KeyGaps > 0):
		a.Class = AIAgent
		a.Confidence = "medium"
		r = append([]string{"operated the site through an automated browser"}, r...)
	case automated:
		a.Class = Scanner
		a.Confidence = "medium"
		r = append(r, "no agent behavior beyond browsing")
	// A browser user agent over another client's TLS stack, with no sign of
	// a person: an HTTP library or automation tool posing as a browser.
	case claims == "browser" && forged && !f.HumanInput:
		a.Class = Scanner
		a.Confidence = "medium"
		r = append([]string{"forged a browser user agent: the TLS handshake belongs to a different client"}, r...)
	case claims == "crawler":
		a.Class = Crawler
		a.Confidence = "medium"
		lead := []string{"user agent identifies a crawler"}
		switch {
		case f.RobotsTraps > 0:
			a.Confidence = "low"
			lead = append(lead, fmt.Sprintf("ignored robots.txt: requested %d disallowed path(s)", f.RobotsTraps))
		case f.FetchedRobots:
			a.Confidence = "high"
			lead = append(lead, "fetched robots.txt and respected it")
		}
		r = append(lead, r...)
	case claims == "ai_agent":
		a.Class = AIAgent
		a.Confidence = "low"
		r = append([]string{"user agent declares an AI agent; no agent behavior yet"}, r...)
	case claims == "browser" && f.Beacons > 0 && f.HumanInput:
		a.Class = Browser
		a.Confidence = "high"
		r = append([]string{"ran JavaScript with human input (mouse, keys, scrolling)"}, r...)
	case claims == "browser" && f.BeaconPages > 0 && f.Beacons == 0:
		a.Class = Scanner
		a.Confidence = "low"
		r = append([]string{fmt.Sprintf("claims to be a browser but ran no JavaScript on %d page(s)", f.BeaconPages)}, r...)
	case claims == "browser" && f.HeadOrOptions == 0 && f.WordlistHits == 0 && f.Requests <= 30:
		a.Class = Browser
		a.Confidence = "low"
		r = append([]string{"browser user agent, page views only (not yet verified as a real browser)"}, r...)
	case f.WordlistHits > 0:
		a.Class = Scanner
		a.Confidence = "low"
		r = append(r, fmt.Sprintf("requested %d known scanner path(s)", f.WordlistHits))
	default:
		a.Class = Unknown
		a.Confidence = "low"
		if claims == "library" {
			r = append(r, "HTTP library user agent, no distinctive behavior")
		}
	}
	if (f.ExploitAttempts > 0 || f.ExploitProbes > 0) && !(a.Class == Scanner && f.ExploitAttempts > 0 && score < 25) {
		r = append(r, exploitReason(f))
	}
	if len(r) == 0 {
		r = append(r, "too little activity to judge")
	}
	a.Reasons = r
}

// exploitLabel names a module event's attack: "PHP2Shell (CVE-2026-109618)".
func exploitLabel(d map[string]any) string {
	name, _ := d["attack"].(string)
	if name == "" {
		name, _ = d["module"].(string)
	}
	if name == "" {
		return ""
	}
	var cves []string
	switch v := d["cve"].(type) {
	case []any:
		for _, c := range v {
			if s, ok := c.(string); ok && s != "" {
				cves = append(cves, s)
			}
		}
	case []string:
		cves = v
	case string:
		if v != "" {
			cves = []string{v}
		}
	}
	if len(cves) == 0 {
		return clip(name, 60)
	}
	return clip(name+" ("+strings.Join(cves, ", ")+")", 120)
}

// exploitReason explains module findings: payloads sent, or only probes.
func exploitReason(f Features) string {
	what := "an exploit"
	if len(f.Exploits) > 0 {
		what = "a " + strings.Join(f.Exploits, ", ") + " exploit"
	}
	if f.ExploitAttempts == 0 {
		target := "a known vulnerability"
		if len(f.Exploits) > 0 {
			target = strings.Join(f.Exploits, ", ")
		}
		return fmt.Sprintf("probed for %s %d time(s)", target, f.ExploitProbes)
	}
	if f.ExploitAttempts == 1 {
		return "sent " + what
	}
	return fmt.Sprintf("sent %s %d times", what, f.ExploitAttempts)
}

func medianGap(ts []time.Time) int64 {
	if len(ts) < 2 {
		return 0
	}
	gaps := make([]int64, 0, len(ts)-1)
	for i := 1; i < len(ts); i++ {
		gaps = append(gaps, ts[i].Sub(ts[i-1]).Milliseconds())
	}
	slices.Sort(gaps)
	return gaps[len(gaps)/2]
}

func topKeys(m map[string]int, n int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if m[keys[i]] != m[keys[j]] {
			return m[keys[i]] > m[keys[j]]
		}
		return keys[i] < keys[j]
	})
	if len(keys) > n {
		keys = keys[:n]
	}
	return keys
}

// Summary counts actors per class.
func Summary(actors []Actor) map[string]int {
	out := map[string]int{}
	for _, c := range Order {
		out[c] = 0
	}
	for _, a := range actors {
		out[a.Class]++
	}
	return out
}

// MarkRelaySource flags an address whose revealed key was later used from
// other addresses: it is the reading half of a rogue agent.
func MarkRelaySource(a *Actor, users []string) {
	a.Class = RogueAgent
	a.Confidence = "high"
	a.Score = min(100, a.Score+35)
	a.Reasons = append([]string{fmt.Sprintf("a key revealed to this address was used from %s", strings.Join(users, ", "))}, a.Reasons...)
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}

// ApplyCrawlerCheck folds a reverse-DNS verdict into a claimed crawler's
// classification. host is the confirmed hostname when verified.
func ApplyCrawlerCheck(a *Actor, family string, verified bool, host string) {
	if verified {
		a.CrawlerCheck = "verified"
		if a.Class == Crawler {
			a.Confidence = "high"
		}
		a.Reasons = append([]string{fmt.Sprintf("verified as %s by reverse DNS (%s)", family, host)}, a.Reasons...)
		return
	}
	a.CrawlerCheck = "impersonation"
	a.Reasons = append([]string{fmt.Sprintf("claims to be a %s crawler but its address does not belong to %s (reverse DNS)", family, family)}, a.Reasons...)
	if a.Class != RogueAgent && a.Class != AIAgent {
		a.Class = Scanner
		a.Confidence = "high"
	}
}

// strList reads a string list detail value that may have come from JSON
// ([]any) or from Go code ([]string).
func strList(v any) []string {
	switch l := v.(type) {
	case []string:
		return l
	case []any:
		out := make([]string, 0, len(l))
		for _, x := range l {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func skillList(skills []string) string {
	if len(skills) == 0 {
		return ""
	}
	return "; skills: " + strings.Join(skills, ", ")
}

// num reads a numeric detail value that may have come from JSON (float64) or
// from Go code (int, int64).
func num(d map[string]any, k string) float64 {
	switch v := d[k].(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	}
	return 0
}

// orEmpty returns def when s is empty.
func orEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
