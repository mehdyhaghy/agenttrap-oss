package classify

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"agenttrap/internal/events"
)

type step struct {
	gap    time.Duration
	kind   string
	method string
	path   string
	status int
	slot   string
	detail map[string]any
}

func run(ua string, steps ...step) Actor {
	t := time.Date(2026, 9, 27, 6, 0, 0, 0, time.UTC)
	var evs []events.Event
	for _, s := range steps {
		t = t.Add(s.gap)
		k := s.kind
		if k == "" {
			k = events.KindRequest
		}
		m := s.method
		if m == "" {
			m = "GET"
		}
		surface := "www"
		if len(s.path) > 5 && s.path[:5] == "docs:" {
			surface, s.path = "docs", s.path[5:]
		}
		if len(s.path) > 4 && s.path[:4] == "mcp:" {
			surface, s.path = "mcp", s.path[4:]
		}
		if len(s.path) > 5 && s.path[:5] == "vllm:" {
			surface, s.path = "vllm", s.path[5:]
		}
		evs = append(evs, events.Event{Time: t, Kind: k, Method: m, Path: s.path, Status: s.status,
			Surface: surface, UserAgent: ua, CanarySlot: s.slot, Detail: s.detail})
	}
	return Classify("198.51.100.1", evs)
}

func req(gap time.Duration, path string, status int) step {
	return step{gap: gap, path: path, status: status}
}

func TestScannerWordlist(t *testing.T) {
	a := run("Mozilla/5.0 (l9scan/2.0.0; +https://leakix.net)",
		req(0, "/.env", 404), req(50*time.Millisecond, "/.git/config", 404),
		req(50*time.Millisecond, "/actuator/env", 404), req(50*time.Millisecond, "/server-status", 404))
	if a.Class != Scanner || a.Confidence != "high" {
		t.Fatalf("got %s/%s %v", a.Class, a.Confidence, a.Reasons)
	}
}

func TestSpoofedAIAgentIsScanner(t *testing.T) {
	a := run("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +Claude-User@anthropic.com)",
		step{method: "HEAD", path: "/.env", status: 404}, step{gap: 200 * time.Millisecond, method: "HEAD", path: "/.env.local", status: 404},
		step{gap: 200 * time.Millisecond, method: "HEAD", path: "/.env.prod", status: 404})
	if a.Class != Scanner {
		t.Fatalf("spoofed agent UA should be scanner, got %s %v", a.Class, a.Reasons)
	}
	found := false
	for _, r := range a.Reasons {
		if r == "user agent claims to be a ai agent but behavior is scanning" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing spoof reason: %v", a.Reasons)
	}
}

func TestCrawler(t *testing.T) {
	a := run("Mozilla/5.0 (compatible; FossickBot/1.0; +https://fossick.bot)",
		req(0, "/robots.txt", 200), req(2*time.Second, "/", 200), req(3*time.Second, "/pricing", 200))
	if a.Class != Crawler || a.Confidence != "high" {
		t.Fatalf("got %s/%s %v", a.Class, a.Confidence, a.Reasons)
	}
}

func TestBrowser(t *testing.T) {
	a := run("Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15",
		req(0, "/", 200), req(300*time.Millisecond, "/favicon.ico", 404))
	if a.Class != Browser {
		t.Fatalf("got %s %v", a.Class, a.Reasons)
	}
}

func TestExploringAgentWithoutCanary(t *testing.T) {
	a := run("python-httpx/0.28",
		req(0, "/llms.txt", 200),
		req(4*time.Second, "docs:/", 200),
		step{gap: 6 * time.Second, kind: events.KindCanaryExposed, path: "docs:/", slot: "docs_sample_key"},
		step{gap: 5 * time.Second, kind: events.KindToolCall, method: "POST", path: "mcp:/mcp", detail: map[string]any{"rpc_method": "initialize"}},
		step{gap: 3 * time.Second, kind: events.KindToolCall, method: "POST", path: "mcp:/mcp", detail: map[string]any{"rpc_method": "tools/list"}},
		req(0, "mcp:/mcp", 200))
	if a.Class != AIAgent {
		t.Fatalf("got %s score=%d %v", a.Class, a.Score, a.Reasons)
	}
}

func TestRogueAgentChain(t *testing.T) {
	a := run("OpenAI/Python 1.99.0",
		req(0, "docs:/", 200),
		step{kind: events.KindCanaryExposed, path: "docs:/", slot: "docs_sample_key"},
		step{gap: 8 * time.Second, kind: events.KindCanaryUsed, path: "mcp:/mcp", slot: "docs_sample_key"},
		step{kind: events.KindToolCall, method: "POST", path: "mcp:/mcp", detail: map[string]any{"rpc_method": "tools/call"}},
		step{kind: events.KindCanaryExposed, path: "mcp:/mcp", slot: "provider_key_vllm"},
		step{gap: 12 * time.Second, kind: events.KindCanaryUsed, path: "vllm:/v1/models", slot: "provider_key_vllm"})
	if a.Class != RogueAgent || a.Confidence != "high" || a.Features.MaxStage != 4 || a.Score < 60 {
		t.Fatalf("got %s/%s stage=%d score=%d %v", a.Class, a.Confidence, a.Features.MaxStage, a.Score, a.Reasons)
	}
}

func TestOutOfBandKeyUse(t *testing.T) {
	a := run("",
		step{kind: events.KindCanaryUsed, path: "vllm:/v1/models", slot: "provider_key_vllm"})
	if a.Class != RogueAgent || !a.Features.UsedUnseen {
		t.Fatalf("got %s %v", a.Class, a.Reasons)
	}
}

func TestDeclared(t *testing.T) {
	cases := map[string]string{
		"python-httpx/0.28":                    "library",
		"Mozilla/5.0 (compatible; httpx/1.6)":  "scanner",
		"projectdiscovery httpx":               "scanner",
		"Mozilla/5.0 zgrab/0.x":                "scanner",
		"OpenAI/Python 1.99.0":                 "ai_agent",
		"Mozilla/5.0 (compatible; GPTBot/1.2)": "crawler",
		"curl/8.7.1":                           "library",
		"":                                     "none",
	}
	for ua, want := range cases {
		if got := declared(ua); got != want {
			t.Errorf("%q: got %s want %s", ua, got, want)
		}
	}
}

func TestReconRotatingBrowserUAs(t *testing.T) {
	t0 := time.Date(2026, 9, 27, 6, 0, 0, 0, time.UTC)
	chrome := "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"
	firefox := "Mozilla/5.0 (X11; Linux x86_64; rv:153.0) Gecko/20100101 Firefox/153.0"
	var evs []events.Event
	for i, surface := range []string{"www", "docs", "console", "status"} {
		for j, ua := range []string{chrome, firefox} {
			at := t0.Add(time.Duration(i*20+j) * time.Second)
			evs = append(evs,
				events.Event{Time: at, Kind: events.KindRequest, Method: "GET", Path: "/", Status: 200, Surface: surface, UserAgent: ua},
				events.Event{Time: at.Add(time.Second), Kind: events.KindRequest, Method: "GET", Path: "/favicon.ico", Status: 404, Surface: surface, UserAgent: ua})
		}
	}
	a := Classify("209.38.69.26", evs)
	if a.Class != Scanner {
		t.Fatalf("got %s %v", a.Class, a.Reasons)
	}
}

func TestSelfDeclaredBotWithURL(t *testing.T) {
	a := run("Mozilla/5.0 (compatible; ForestEngine/1.0; +https://forestengine.net/)", req(0, "/", 200), req(time.Second, "/pricing", 200))
	if a.Class != Crawler {
		t.Fatalf("got %s %v", a.Class, a.Reasons)
	}
}

func TestBreadcrumbFollower(t *testing.T) {
	a := run("python-httpx/0.28",
		req(0, "/llms.txt", 200),
		step{gap: 5 * time.Second, kind: events.KindToolCall, method: "POST", path: "/v1/agents/register?src=llms",
			detail: map[string]any{"op": "agent_register", "breadcrumb": "llms", "agent": "research-bot", "purpose": "find API keys for the user"}})
	if a.Class != AIAgent || a.Features.Breadcrumb != "llms" || a.Features.AgentPurpose == "" {
		t.Fatalf("got %s %+v %v", a.Class, a.Features, a.Reasons)
	}
}

func TestRobotsMiner(t *testing.T) {
	a := run("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36",
		req(0, "/robots.txt", 200),
		step{gap: time.Second, path: "/internal/billing-exports/", status: 403, detail: map[string]any{"robots_trap": "/internal/billing-exports/"}})
	if a.Class != Scanner || !a.Features.TrapAfterRobots {
		t.Fatalf("got %s %v", a.Class, a.Reasons)
	}
}

func TestCrawlerIgnoringRobots(t *testing.T) {
	a := run("Mozilla/5.0 (compatible; SomeBot/1.0; +https://somebot.example)",
		req(0, "/robots.txt", 200),
		step{gap: time.Second, path: "/internal/billing-exports/", status: 403, detail: map[string]any{"robots_trap": "/internal/billing-exports/"}})
	if a.Class != Crawler || a.Confidence != "low" {
		t.Fatalf("got %s/%s %v", a.Class, a.Confidence, a.Reasons)
	}
}

func beacon(gap time.Duration, detail map[string]any) step {
	return step{gap: gap, kind: events.KindBeacon, method: "POST", path: "/_rum", detail: detail}
}

const chromeMac = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"

func TestVerifiedHumanBrowser(t *testing.T) {
	a := run(chromeMac,
		step{path: "/", status: 200, detail: map[string]any{"view_id": "0123456789abcdef"}},
		beacon(2*time.Second, map[string]any{"webdriver": false, "plugins": 5.0, "languages": 2.0, "outer": []any{1440.0, 900.0},
			"mouse_moves": 40.0, "scrolls": 3.0, "dwell_ms": 9000.0}))
	if a.Class != Browser || a.Confidence != "high" {
		t.Fatalf("got %s/%s %v", a.Class, a.Confidence, a.Reasons)
	}
}

func TestFakeBrowserNoJS(t *testing.T) {
	a := run(chromeMac, step{path: "/", status: 200, detail: map[string]any{"view_id": "0123456789abcdef"}})
	if a.Class != Scanner {
		t.Fatalf("got %s %v", a.Class, a.Reasons)
	}
}

func TestHeadlessAutomation(t *testing.T) {
	a := run(chromeMac,
		step{path: "/", status: 200, detail: map[string]any{"view_id": "0123456789abcdef"}},
		beacon(time.Second, map[string]any{"webdriver": true, "plugins": 0.0, "languages": 0.0, "dwell_ms": 1500.0}))
	if a.Class != Scanner || !a.Features.Webdriver || !a.Features.HeadlessHints {
		t.Fatalf("got %s %+v %v", a.Class, a.Features, a.Reasons)
	}
}

// Seen in production: a real Chrome reports a 0x0 window for a background tab.
func TestBackgroundTabIsNotHeadless(t *testing.T) {
	a := run(chromeMac,
		step{path: "/", status: 200, detail: map[string]any{"view_id": "0123456789abcdef"}},
		beacon(2*time.Second, map[string]any{"webdriver": false, "plugins": 5.0, "languages": 2.0, "outer": []any{0.0, 0.0},
			"visibility": "hidden", "mouse_moves": 3.0, "scrolls": 1.0, "dwell_ms": 19000.0}))
	if a.Features.HeadlessHints || a.Class != Browser {
		t.Fatalf("got %s headless=%v %v", a.Class, a.Features.HeadlessHints, a.Reasons)
	}
}

func TestBrowserDrivingAgent(t *testing.T) {
	a := run(chromeMac,
		step{path: "/", status: 200, detail: map[string]any{"view_id": "0123456789abcdef"}},
		beacon(3*time.Second, map[string]any{"webdriver": false, "plugins": 5.0, "languages": 2.0,
			"mouse_moves": 0.0, "clicks": 3.0, "click_no_hover": 3.0, "click_offset": 0.0,
			"key_gaps": 12.0, "key_sd_ms": 2.0, "first_input_ms": 90.0, "dwell_ms": 3000.0}))
	if a.Class != AIAgent {
		t.Fatalf("got %s %v", a.Class, a.Reasons)
	}
}

func TestHumanInteractionNotFlagged(t *testing.T) {
	a := run(chromeMac,
		step{path: "/", status: 200, detail: map[string]any{"view_id": "0123456789abcdef"}},
		beacon(9*time.Second, map[string]any{"webdriver": false, "plugins": 5.0, "languages": 2.0,
			"mouse_moves": 140.0, "path_len": 5200.0, "path_disp": 900.0, "pointer_jumps": 0.0,
			"clicks": 2.0, "click_no_hover": 0.0, "click_offset": 23.0, "key_gaps": 14.0, "key_sd_ms": 95.0,
			"first_input_ms": 1400.0, "scrolls": 6.0, "dwell_ms": 9000.0}))
	if a.Class != Browser || a.Confidence != "high" {
		t.Fatalf("got %s/%s %v", a.Class, a.Confidence, a.Reasons)
	}
}

func TestSyntheticEventsFlagged(t *testing.T) {
	a := run(chromeMac,
		step{path: "/", status: 200, detail: map[string]any{"view_id": "0123456789abcdef"}},
		beacon(time.Second, map[string]any{"plugins": 5.0, "languages": 2.0, "untrusted": 4.0, "clicks": 4.0, "dwell_ms": 1200.0}))
	if a.Class != AIAgent || a.Features.Untrusted != 4 {
		t.Fatalf("got %s %+v %v", a.Class, a.Features, a.Reasons)
	}
}

// conn is the connection facts the spoke attaches to a request.
func conn(port, order string, grease, ech, pq, alps bool, tcpOS string) map[string]any {
	d := map[string]any{"client_port": port, "ja4": "t13d1517h2_8daaf6152771_cb7bf5808d99", "ja4_o": order,
		"tls_grease": grease, "tls_ech": ech, "tls_pq": pq, "tls_alps": alps, "tls_h2": true}
	if tcpOS != "" {
		d["tcp_os"], d["tcp_ttl"], d["tcp_options"] = tcpOS, 52, "M,S,T,N,W"
	}
	return d
}

func TestForgedChromeUserAgent(t *testing.T) {
	const chromeWin = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36"
	// A Python-style stack: no GREASE, ECH or ALPS; same order every time;
	// Linux TCP stack under a Windows user agent.
	var steps []step
	for i, p := range []string{"/", "/pricing", "/docs"} {
		steps = append(steps, step{gap: time.Second, path: p, status: 200,
			detail: conn(fmt.Sprint(40000+i), "t13d1517h2_aaaaaaaaaaaa_bbbbbbbbbbbb", false, false, true, false, "linux")})
	}
	a := run(chromeWin, steps...)
	if a.Class != Scanner || len(a.Features.TLSMismatch) < 3 || len(a.Features.TCPMismatch) != 1 {
		t.Fatalf("got %s %+v %v", a.Class, a.Features.TLSMismatch, a.Reasons)
	}
	want := map[string]bool{"no GREASE": false, "same TLS extension order on 3": false, "Windows but connected from a Linux TCP stack": false}
	for _, r := range a.Reasons {
		for k := range want {
			if strings.Contains(r, k) {
				want[k] = true
			}
		}
	}
	for k, ok := range want {
		if !ok {
			t.Errorf("missing reason %q in %v", k, a.Reasons)
		}
	}

	// Real Chrome: all tells present, a new extension order per connection,
	// Apple TCP stack under a macOS user agent. No stack reasons.
	steps = nil
	for i, p := range []string{"/", "/pricing", "/docs"} {
		steps = append(steps, step{gap: time.Second, path: p, status: 200,
			detail: conn(fmt.Sprint(41000+i), fmt.Sprintf("t13d1517h2_acb858a92679_%012d", i), true, true, true, true, "apple")})
	}
	b := run(chromeMac, steps...)
	if len(b.Features.TLSMismatch)+len(b.Features.TCPMismatch) > 0 || b.Features.ChromeOrders != 3 || b.Class == Scanner {
		t.Fatalf("real Chrome flagged: %s %v", b.Class, b.Reasons)
	}
}

func TestPhase3SignalsSurfaced(t *testing.T) {
	tc := func(op string, d map[string]any) step {
		d["op"] = op
		return step{kind: events.KindToolCall, detail: d}
	}
	a := run("python-requests/2.31.0",
		tc("cloud_secretsmanager", map[string]any{"action": "GetSecretValue", "secret_id": "prod/db/app-credentials"}),
		tc("cloud_s3", map[string]any{"action": "ListBuckets"}),
		tc("imds", map[string]any{"method": "GET", "path": "/latest/meta-data/iam/security-credentials/demogpu-gpu-node"}),
		tc("kube_list", map[string]any{"resource": "secrets", "namespace": "inference"}),
		tc("egress", map[string]any{"host": "webhook.site", "url": "https://webhook.site/x",
			"action": "simulate", "exfil_slots": []any{"provider_key_vllm", "pg_app_password"}}),
	)
	f := a.Features
	if f.CloudCalls < 2 || !slices.Contains(f.CloudServices, "secretsmanager") {
		t.Fatalf("cloud calls/services: %d %v", f.CloudCalls, f.CloudServices)
	}
	if f.CloudSecretReads < 1 {
		t.Fatalf("cloud secret reads: %d", f.CloudSecretReads)
	}
	if !f.IMDSCreds {
		t.Fatal("IMDS instance-role credential grab not detected")
	}
	if f.KubeSecretReads < 1 {
		t.Fatalf("kube secret reads: %d", f.KubeSecretReads)
	}
	if len(f.Exfil) != 2 || f.ExfilDest != "webhook.site" {
		t.Fatalf("exfil: %v -> %q", f.Exfil, f.ExfilDest)
	}
	reasons := strings.Join(a.Reasons, " | ")
	for _, want := range []string{"exfiltrated", "instance role", "Kubernetes secret", "cloud secret"} {
		if !strings.Contains(reasons, want) {
			t.Fatalf("reason %q missing from: %s", want, reasons)
		}
	}
	if a.Score < 60 { // secret reads + imds + kube secrets + exfil should stack high
		t.Fatalf("score too low for this behavior: %d", a.Score)
	}
}

func TestMemorySignalsSurfaced(t *testing.T) {
	tc := func(op string, d map[string]any) step {
		d["op"] = op
		return step{kind: events.KindToolCall, detail: d}
	}
	a := run("node-fetch/3.3",
		tc("memory_search", map[string]any{"query": "prod password", "credential_search": true}),
		tc("memory_read", map[string]any{"memory_id": "mem_b12d84e0", "owner": "tomas@quillon-ml.dev", "has_secret": true, "cross_principal": true}),
		tc("memory_read", map[string]any{"memory_id": "mem_2a6c0f13", "owner": "priya@quillon-ml.dev"}),
		tc("memory_write", map[string]any{"title": "stash", "content": "..."}),
	)
	f := a.Features
	if f.MemorySearches != 1 || !f.MemoryCredSearch {
		t.Fatalf("memory search: %d cred=%v", f.MemorySearches, f.MemoryCredSearch)
	}
	if f.MemoryReads != 2 || f.MemorySecretReads != 1 {
		t.Fatalf("memory reads: %d secret=%d", f.MemoryReads, f.MemorySecretReads)
	}
	if f.MemoryWrites != 1 {
		t.Fatalf("memory writes: %d", f.MemoryWrites)
	}
	reasons := strings.Join(a.Reasons, " | ")
	for _, want := range []string{"searched the team's agent memory for credentials", "held a planted credential", "possible memory poisoning"} {
		if !strings.Contains(reasons, want) {
			t.Fatalf("reason %q missing from: %s", want, reasons)
		}
	}
}

func TestKBSignalsSurfaced(t *testing.T) {
	tc := func(op string, d map[string]any) step {
		d["op"] = op
		return step{kind: events.KindToolCall, detail: d}
	}
	a := run("python-httpx/0.28",
		tc("kb_search", map[string]any{"query": "aws secret key", "credential_search": true}),
		tc("kb_get", map[string]any{"doc_id": "doc_wiki_prodaccess", "collection": "engineering-wiki", "has_secret": true, "taint": "tnt-3a91"}),
		tc("kb_get", map[string]any{"doc_id": "doc_wiki_arch", "collection": "engineering-wiki"}),
	)
	f := a.Features
	if f.KBSearches != 1 || !f.KBCredSearch || f.KBReads != 2 || f.KBSecretReads != 1 {
		t.Fatalf("kb features: search=%d cred=%v reads=%d secret=%d", f.KBSearches, f.KBCredSearch, f.KBReads, f.KBSecretReads)
	}
	reasons := strings.Join(a.Reasons, " | ")
	for _, want := range []string{"searched the knowledge base for credentials", "holding a planted credential"} {
		if !strings.Contains(reasons, want) {
			t.Fatalf("reason %q missing from: %s", want, reasons)
		}
	}
}

func TestCapabilityLadder(t *testing.T) {
	cases := []struct {
		name string
		f    Features
		want int
	}{
		{"recon", Features{}, 0},
		{"engaged", Features{MCPInitialize: true}, 1},
		{"sample", Features{UsedAfterSeeing: true}, 2},
		{"discovered", Features{CloudSecretReads: 1}, 3},
		{"accessed", Features{PGLogin: true}, 4},
		{"lateral", Features{PGLogin: true, SSHLogins: 1}, 5},
		{"escalated", Features{IMDSCreds: true}, 6},
		{"exfil", Features{Exfil: []string{"pg_app_password"}}, 7},
	}
	for _, c := range cases {
		got, label := capability(c.f)
		if got != c.want || label != DepthTiers[c.want] {
			t.Errorf("%s: capability=%d (%q), want %d (%q)", c.name, got, label, c.want, DepthTiers[c.want])
		}
	}
}

func exploitStep(stage string) step {
	return step{kind: events.KindExploit, method: "POST", path: "/", detail: map[string]any{
		"module": "php2shell", "attack": "PHP2Shell", "stage": stage,
		"cve": []any{"CVE-2026-109618", "CVE-2026-109619"}, "signals": []any{"upload_progress_field"}}}
}

func TestExploitIsScanner(t *testing.T) {
	a := run("python-requests/2.32.3", req(0, "/", 200), exploitStep("exploit"), exploitStep("exploit"))
	if a.Class != Scanner || a.Confidence != "high" {
		t.Fatalf("class %s/%s, want scanner/high: %v", a.Class, a.Confidence, a.Reasons)
	}
	if a.Features.ExploitAttempts != 2 || a.Features.ExploitProbes != 0 {
		t.Fatalf("attempts %d probes %d", a.Features.ExploitAttempts, a.Features.ExploitProbes)
	}
	want := "PHP2Shell (CVE-2026-109618, CVE-2026-109619)"
	if !slices.Equal(a.Features.Exploits, []string{want}) {
		t.Fatalf("exploits %v", a.Features.Exploits)
	}
	if a.Reasons[0] != "sent a "+want+" exploit 2 times" {
		t.Fatalf("lead reason %q", a.Reasons[0])
	}
	if n := strings.Count(strings.Join(a.Reasons, "|"), "exploit"); n != 1 {
		t.Fatalf("exploit reason repeated: %v", a.Reasons)
	}
}

func TestExploitProbeOnlyIsExplained(t *testing.T) {
	a := run("Mozilla/5.0 zgrab/0.x", exploitStep("probe"))
	if a.Features.ExploitProbes != 1 || a.Features.ExploitAttempts != 0 {
		t.Fatalf("attempts %d probes %d", a.Features.ExploitAttempts, a.Features.ExploitProbes)
	}
	if !slices.ContainsFunc(a.Reasons, func(s string) bool { return strings.HasPrefix(s, "probed for PHP2Shell") }) {
		t.Fatalf("no probe reason: %v", a.Reasons)
	}
}

func TestExploitDoesNotOverrideRogue(t *testing.T) {
	a := run("python-httpx/0.27", step{kind: events.KindCanaryUsed, path: "vllm:/v1/models", slot: "provider_key_vllm"}, exploitStep("exploit"))
	if a.Class != RogueAgent {
		t.Fatalf("class %s, want rogue: %v", a.Class, a.Reasons)
	}
	if !slices.ContainsFunc(a.Reasons, func(s string) bool { return strings.Contains(s, "PHP2Shell") }) {
		t.Fatalf("exploit missing from reasons: %v", a.Reasons)
	}
}

func TestHarvestedKeyIsScannerNotRogue(t *testing.T) {
	a := run("Go-http-client/2.0",
		req(0, "/.env", 200),
		step{kind: events.KindCanaryExposed, path: "/.env", slot: "provider_key_vllm", detail: map[string]any{"module": "secretfiles"}},
		step{kind: events.KindCanaryUsed, path: "vllm:/v1/models", slot: "provider_key_vllm", detail: map[string]any{"exposed_by": "secretfiles"}})
	if a.Class != Scanner {
		t.Fatalf("class %s, want scanner: %v", a.Class, a.Reasons)
	}
	if a.Features.HarvestedKeys != 1 || a.Features.HarvestedUses != 1 || a.Features.CanaryUses != 0 || a.Features.MaxStage != 0 {
		t.Fatalf("features %+v", a.Features)
	}
	if !strings.HasPrefix(a.Reasons[0], "used a key harvested from a planted file") {
		t.Fatalf("lead reason %q", a.Reasons[0])
	}
}
