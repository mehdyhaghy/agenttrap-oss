// Package fingerprint infers which software drives a client: the SDK or HTTP
// library it uses, the MCP or OAuth client it declares, whether a browser is
// automated, and whether a language model or a fixed script is choosing the
// requests.
//
// Labels are probabilistic and never rest on one header or one request
// (spec §13). Evidence comes in independent families (user agent, SDK
// headers, protocol self-description, TLS stack, browser behavior, timing);
// within a family only the strongest signal counts, and families combine as
// a noisy-OR. A label backed by a single family is capped at "possible".
package fingerprint

import (
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"agenttrap/internal/events"
)

// Kinds of label.
const (
	KindSDK        = "llm_sdk"            // OpenAI-style client SDK
	KindLibrary    = "http_library"       // generic HTTP client
	KindMCPClient  = "mcp_client"         // MCP host application
	KindOAuth      = "oauth_client"       // self-registered OAuth client
	KindAgent      = "agent"              // self-declared agent or integration
	KindAutomation = "browser_automation" // a browser driven by software
	KindDriver     = "driver"             // what chooses the requests: llm or script
)

// Evidence families. Signals in one family are not independent of each other.
const (
	famUA       = "user_agent"
	famHeaders  = "sdk_headers"
	famProtocol = "protocol"
	famTLS      = "tls"
	famBrowser  = "browser"
	famTiming   = "timing"
	famContent  = "content"
	famFlow     = "flow"
)

// Label is one inference about the client.
type Label struct {
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Confidence float64  `json:"confidence"` // 0-1
	Level      string   `json:"level"`      // likely, possible
	Families   []string `json:"families"`
	Evidence   []string `json:"evidence"`
}

type signal struct {
	name, kind, family, evidence string
	weight                       float64
}

// uaRules map user agents to software. Weights are how strongly the user
// agent alone suggests the label; user agents are trivially forged.
var uaRules = []struct {
	re         *regexp.Regexp
	name, kind string
	weight     float64
}{
	{regexp.MustCompile(`^OpenAI/Python`), "openai-python", KindSDK, 0.55},
	{regexp.MustCompile(`^OpenAI/JS`), "openai-node", KindSDK, 0.55},
	{regexp.MustCompile(`(?i)langchain`), "langchain", KindAgent, 0.5},
	{regexp.MustCompile(`(?i)llama[-_ ]?index`), "llamaindex", KindAgent, 0.5},
	{regexp.MustCompile(`(?i)crewai`), "crewai", KindAgent, 0.5},
	{regexp.MustCompile(`(?i)autogen`), "autogen", KindAgent, 0.5},
	{regexp.MustCompile(`(?i)browser[-_]use`), "browser-use", KindAutomation, 0.5},
	{regexp.MustCompile(`HeadlessChrome/`), "headless-chrome", KindAutomation, 0.5},
	{regexp.MustCompile(`(?i)^python-httpx/`), "python-httpx", KindLibrary, 0.5},
	{regexp.MustCompile(`(?i)^python-requests/`), "python-requests", KindLibrary, 0.5},
	{regexp.MustCompile(`(?i)^python-urllib`), "python-urllib", KindLibrary, 0.5},
	{regexp.MustCompile(`(?i)^aiohttp/|Python/.*aiohttp/`), "aiohttp", KindLibrary, 0.5},
	{regexp.MustCompile(`(?i)^Go-http-client/`), "go-net-http", KindLibrary, 0.5},
	{regexp.MustCompile(`(?i)^(node-fetch|undici)`), "node-fetch", KindLibrary, 0.5},
	{regexp.MustCompile(`(?i)^node$|^Node\.js`), "node-fetch", KindLibrary, 0.4},
	{regexp.MustCompile(`(?i)^axios/`), "axios", KindLibrary, 0.5},
	{regexp.MustCompile(`(?i)^curl/`), "curl", KindLibrary, 0.5},
	{regexp.MustCompile(`(?i)^Wget/`), "wget", KindLibrary, 0.5},
	{regexp.MustCompile(`(?i)^okhttp/`), "okhttp", KindLibrary, 0.5},
	{regexp.MustCompile(`(?i)^Java-http-client/|^Java/`), "java-http", KindLibrary, 0.5},
}

// Infer labels a client from its events (any order).
func Infer(evs []events.Event) []Label {
	evs = slices.Clone(evs)
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Time.Before(evs[j].Time) })
	var sigs []signal
	add := func(name, kind, family string, weight float64, format string, args ...any) {
		sigs = append(sigs, signal{name: name, kind: kind, family: family, weight: weight, evidence: fmt.Sprintf(format, args...)})
	}

	uas := map[string]int{}
	var reqTimes []time.Time
	requests := 0
	llmCalls, prompts := 0, 0
	stainless := map[string]string{}
	var headerSets [][]string
	for _, ev := range evs {
		str := func(k string) string { v, _ := ev.Detail[k].(string); return v }
		switch ev.Kind {
		case events.KindRequest:
			requests++
			reqTimes = append(reqTimes, ev.Time)
			if ev.UserAgent != "" {
				uas[ev.UserAgent]++
			}
			// map[string]string as recorded; map[string]any after a JSON round trip.
			switch sdk := ev.Detail["sdk"].(type) {
			case map[string]string:
				for k, v := range sdk {
					stainless[k] = v
				}
			case map[string]any:
				for k, v := range sdk {
					if s, ok := v.(string); ok {
						stainless[k] = s
					}
				}
			}
			if hs := strList(ev.Detail["headers"]); len(hs) > 0 && len(headerSets) < 50 {
				headerSets = append(headerSets, hs)
			}
		case events.KindToolCall:
			switch str("op") {
			case "chat", "embeddings":
				llmCalls++
				if len(str("last_message")) >= 20 {
					prompts++
				}
			case "oauth_register":
				if n := strings.TrimSpace(str("client_name")); n != "" {
					add(norm(n), KindOAuth, famFlow, 0.6, "registered an OAuth client named %q", clip(n, 60))
				}
				if n := strings.TrimSpace(str("software_id")); n != "" {
					add(norm(n), KindOAuth, famProtocol, 0.5, "OAuth software_id %q", clip(n, 60))
				}
			case "agent_register":
				if n := strings.TrimSpace(str("agent")); n != "" {
					add(norm(n), KindAgent, famFlow, 0.6, "registered an integration named %q", clip(n, 60))
				}
				if len(str("purpose")) >= 20 {
					add("llm", KindDriver, famContent, 0.5, "described its purpose in free text")
				}
			}
			if ev.Protocol == "mcp" && str("rpc_method") == "initialize" {
				if n := strings.TrimSpace(str("client_name")); n != "" {
					v := str("client_version")
					add(norm(n), KindMCPClient, famProtocol, 0.65, "MCP clientInfo %q %s (protocol %s)", clip(n, 60), clip(v, 20), str("protocol_version"))
				}
			}
			if ev.Protocol == "a2a" && len(str("text")) >= 20 {
				prompts++
			}
		case events.KindBeacon:
			if wd, _ := ev.Detail["webdriver"].(bool); wd {
				add("webdriver", KindAutomation, famBrowser, 0.7, "navigator.webdriver was true")
			}
			if num(ev.Detail, "untrusted") > 0 {
				add("scripted-input", KindAutomation, famBrowser, 0.6, "input events dispatched by script (isTrusted=false)")
			}
		}
	}

	// User agent family: the most used user agent that matches a rule.
	for _, ua := range topKeys(uas) {
		matched := false
		for _, r := range uaRules {
			if r.re.MatchString(ua) {
				add(r.name, r.kind, famUA, r.weight, "user agent %q", clip(ua, 80))
				matched = true
				break
			}
		}
		if matched {
			break
		}
	}

	// SDK headers: OpenAI-style SDKs generated by Stainless send
	// x-stainless-lang, -package-version and -runtime on every request.
	if lang := strings.ToLower(stainless["x-stainless-lang"]); lang != "" {
		name := "stainless-" + lang
		switch lang {
		case "python":
			name = "openai-python"
		case "js":
			name = "openai-node"
		}
		ev := fmt.Sprintf("SDK headers: lang %s", lang)
		if v := stainless["x-stainless-package-version"]; v != "" {
			ev += ", package " + v
		}
		if rt := stainless["x-stainless-runtime"]; rt != "" {
			ev += ", runtime " + rt + " " + stainless["x-stainless-runtime-version"]
		}
		add(name, KindSDK, famHeaders, 0.75, "%s", ev)
	}
	// Header layout: the header names HTTP libraries send by default.
	if lib := headerLibrary(headerSets); lib != "" {
		add(lib, KindLibrary, famHeaders, 0.35, "default header set of %s", lib)
	}

	// TLS: a browser user agent over a non-browser handshake is a library.
	for _, ev := range evs {
		if ev.Kind != events.KindRequest {
			continue
		}
		if _, ok := ev.Detail["tls_grease"]; !ok {
			continue
		}
		grease, _ := ev.Detail["tls_grease"].(bool)
		alps, _ := ev.Detail["tls_alps"].(bool)
		if strings.Contains(ev.UserAgent, "Chrome/") && !grease {
			add("http-library-posing-as-browser", KindLibrary, famTLS, 0.7, "Chrome user agent over a TLS handshake without GREASE")
			break
		}
		if grease && alps && !strings.Contains(ev.UserAgent, "Chrome/") && !strings.Contains(ev.UserAgent, "Edg/") {
			add("chromium", KindAutomation, famTLS, 0.4, "Chromium TLS handshake under a non-Chrome user agent")
			break
		}
	}

	// Driver: a language model choosing requests leaves slow, irregular gaps
	// and writes free text; a script is fast and regular.
	if gaps := intervals(reqTimes); len(gaps) >= 3 {
		med, cv := median(gaps), coeffVar(gaps)
		switch {
		case med >= 1500 && med <= 120000 && cv >= 0.35:
			add("llm", KindDriver, famTiming, 0.55, "irregular pauses (median %.1fs, variation %.2f) between %d requests", med/1000, cv, requests)
		case med < 400 && cv < 0.5:
			add("script", KindDriver, famTiming, 0.6, "fast, regular requests (median %.0f ms, variation %.2f)", med, cv)
		case cv < 0.1 && med >= 400:
			add("script", KindDriver, famTiming, 0.6, "fixed interval between requests (%.1fs, variation %.2f)", med/1000, cv)
		}
	}
	if prompts > 0 {
		add("llm", KindDriver, famContent, 0.45, "sent %d natural-language prompt(s)", prompts)
	}
	if llmCalls > 0 && prompts == 0 {
		add("script", KindDriver, famContent, 0.3, "called the model API only with short or empty prompts")
	}

	return combine(sigs, len(evs))
}

// combine merges signals into labels: strongest signal per family, noisy-OR
// across families, single-family labels capped at "possible".
func combine(sigs []signal, nEvents int) []Label {
	// One label per name: the same software can show up as an MCP client
	// and as an OAuth client; its kind is that of its strongest signal.
	best := map[string]map[string]signal{}
	for _, s := range sigs {
		if best[s.name] == nil {
			best[s.name] = map[string]signal{}
		}
		if cur, ok := best[s.name][s.family]; !ok || s.weight > cur.weight {
			best[s.name][s.family] = s
		}
	}
	var out []Label
	for name, fams := range best {
		miss := 1.0
		l := Label{Name: name}
		top := 0.0
		for fam, s := range fams {
			miss *= 1 - s.weight
			l.Families = append(l.Families, fam)
			l.Evidence = append(l.Evidence, s.evidence)
			if s.weight > top {
				top, l.Kind = s.weight, s.kind
			}
		}
		p := 1 - miss
		if len(fams) == 1 {
			p = math.Min(p, 0.6)
		}
		if nEvents < 2 {
			p = math.Min(p, 0.4)
		}
		l.Confidence = math.Round(p*100) / 100
		l.Level = "possible"
		if len(fams) >= 2 && p >= 0.75 {
			l.Level = "likely"
		}
		slices.Sort(l.Families)
		slices.Sort(l.Evidence)
		out = append(out, l)
	}
	// A client cannot be both LLM-driven and scripted: keep the stronger.
	var llm, script = -1, -1
	for i, l := range out {
		if l.Kind == KindDriver {
			if l.Name == "llm" {
				llm = i
			} else {
				script = i
			}
		}
	}
	if llm >= 0 && script >= 0 {
		drop := script
		if out[script].Confidence > out[llm].Confidence {
			drop = llm
		}
		out = slices.Delete(out, drop, drop+1)
	}
	slices.SortFunc(out, func(a, b Label) int {
		if a.Confidence != b.Confidence {
			if a.Confidence > b.Confidence {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out
}

// Likely returns the names of labels at the "likely" level.
func Likely(ls []Label) []string {
	var out []string
	for _, l := range ls {
		if l.Level == "likely" {
			out = append(out, l.Name)
		}
	}
	return out
}

// headerLibrary recognises the default header sets of common HTTP clients
// when every request sent exactly that set (plus content headers).
func headerLibrary(sets [][]string) string {
	if len(sets) < 2 {
		return ""
	}
	sigs := map[string][]string{
		"python-requests": {"accept", "accept-encoding", "connection", "user-agent"},
		"python-httpx":    {"accept", "accept-encoding", "connection", "host", "user-agent"},
		"curl":            {"accept", "user-agent"},
		"go-net-http":     {"accept-encoding", "user-agent"},
	}
	strip := func(hs []string) []string {
		var out []string
		for _, h := range hs {
			switch h {
			case "content-type", "content-length", "authorization", "x-real-ip", "x-real-port", "x-forwarded-for", "x-forwarded-proto", "host":
				continue
			}
			out = append(out, h)
		}
		return out
	}
	first := strip(sets[0])
	for _, s := range sets[1:] {
		if !slices.Equal(strip(s), first) {
			return ""
		}
	}
	for name, want := range sigs {
		if slices.Equal(first, strip(want)) {
			return name
		}
	}
	return ""
}

func norm(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.Join(strings.Fields(s), "-")
	return clip(s, 60)
}

func intervals(ts []time.Time) []float64 {
	var out []float64
	for i := 1; i < len(ts); i++ {
		if d := ts[i].Sub(ts[i-1]).Milliseconds(); d >= 0 {
			out = append(out, float64(d))
		}
	}
	return out
}

func median(xs []float64) float64 {
	s := slices.Clone(xs)
	slices.Sort(s)
	return s[len(s)/2]
}

func coeffVar(xs []float64) float64 {
	var sum float64
	for _, x := range xs {
		sum += x
	}
	mean := sum / float64(len(xs))
	if mean == 0 {
		return 0
	}
	var ss float64
	for _, x := range xs {
		ss += (x - mean) * (x - mean)
	}
	return math.Sqrt(ss/float64(len(xs))) / mean
}

func topKeys(m map[string]int) []string {
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
	return keys
}

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

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "") + "…"
}
