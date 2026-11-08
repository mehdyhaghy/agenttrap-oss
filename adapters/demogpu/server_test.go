package demogpu

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"agenttrap/internal/canary"
	"agenttrap/internal/events"
	"agenttrap/internal/ja4"
	"agenttrap/internal/worldpack"
	"agenttrap/modules/builtin"
	"agenttrap/personas"
)

type sink struct{ evs []events.Event }

func (s *sink) Record(ev events.Event) { s.evs = append(s.evs, ev) }

func newTestServer(t *testing.T, opts Options) (*Server, *sink) {
	t.Helper()
	p, err := worldpack.Parse(personas.DemoGPU)
	if err != nil {
		t.Fatal(err)
	}
	rec := &sink{}
	return New(p, canary.NewSet([]byte("seed"), p), rec, opts), rec
}

func TestSurfaceRouting(t *testing.T) {
	s, _ := newTestServer(t, Options{BaseDomain: "demogpu.localhost"})
	cases := map[string]string{
		"demogpu.localhost":         "www",
		"docs.demogpu.localhost:80": "docs",
		"API.demogpu.localhost":     "api",
		"x.api.demogpu.localhost":   "",
		"unknown.demogpu.localhost": "",
		"demogpu.example":               "",
	}
	for host, want := range cases {
		if got := s.surface(host); got != want {
			t.Errorf("%s: got %q want %q", host, got, want)
		}
	}
}

func TestForwardedIPOnlyFromTrustedProxy(t *testing.T) {
	s, rec := newTestServer(t, Options{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	r := httptest.NewRequest("GET", "http://demogpu.example/", nil)
	r.RemoteAddr = "198.51.100.5:1234"
	r.Header.Set("X-Real-IP", "1.2.3.4")
	s.ServeHTTP(httptest.NewRecorder(), r)
	if got := rec.evs[len(rec.evs)-1].Source; got != "198.51.100.5" {
		t.Fatalf("spoofed header trusted from untrusted peer: %s", got)
	}
	r.RemoteAddr = "10.1.1.1:1234"
	s.ServeHTTP(httptest.NewRecorder(), r)
	if got := rec.evs[len(rec.evs)-1].Source; got != "1.2.3.4" {
		t.Fatalf("trusted proxy header ignored: %s", got)
	}
}

func TestPseudonymizedSource(t *testing.T) {
	s, rec := newTestServer(t, Options{PseudonymizeKey: []byte("k")})
	r := httptest.NewRequest("GET", "http://demogpu.example/", nil)
	r.RemoteAddr = "198.51.100.5:1234"
	s.ServeHTTP(httptest.NewRecorder(), r)
	if src := rec.evs[0].Source; !strings.HasPrefix(src, "p:") || strings.Contains(src, "198.51") {
		t.Fatalf("source not pseudonymized: %s", src)
	}
}

func TestUnknownHostLooksLikeNginx(t *testing.T) {
	s, _ := newTestServer(t, Options{})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "http://203.0.113.9/", nil))
	if w.Code != 404 || w.Header().Get("Server") != "nginx" || !strings.Contains(w.Body.String(), "nginx") {
		t.Fatalf("unexpected: %d %q", w.Code, w.Header().Get("Server"))
	}
}

func TestChatStreaming(t *testing.T) {
	s, _ := newTestServer(t, Options{})
	key := s.canaries.Value(SlotDocsKey)
	r := httptest.NewRequest("POST", "http://api.demogpu.example/v1/chat/completions",
		strings.NewReader(`{"model":"bge-m3","stream":true,"messages":[{"role":"user","content":"hi"}]}`))
	r.Header.Set("Authorization", "Bearer "+key)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), "data: [DONE]") {
		t.Fatalf("no SSE terminator: %s", w.Body)
	}
}

func TestTLSFingerprintJoinsRequests(t *testing.T) {
	s, rec := newTestServer(t, Options{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	s.ObserveTLS(ja4.Result{
		Src:   netip.MustParseAddrPort("198.51.100.9:51234"),
		Dst:   netip.MustParseAddrPort("10.0.0.10:443"),
		Hello: &ja4.Hello{JA4: "t13d1516h2_8daaf6152771_02713d6af862", SNI: "api.demogpu.example", TLSVersion: "13"},
	})
	hello := rec.evs[0]
	if hello.Kind != events.KindTLSHello || hello.Surface != "api" || hello.Source != "198.51.100.9" {
		t.Fatalf("unexpected tls event: %+v", hello)
	}
	r := httptest.NewRequest("GET", "http://demogpu.example/", nil)
	r.RemoteAddr = "10.0.0.10:40000"
	r.Header.Set("X-Real-IP", "198.51.100.9")
	r.Header.Set("X-Real-Port", "51234")
	s.ServeHTTP(httptest.NewRecorder(), r)
	req := rec.evs[len(rec.evs)-1]
	if req.Detail["ja4"] != "t13d1516h2_8daaf6152771_02713d6af862" {
		t.Fatalf("ja4 not joined: %+v", req.Detail)
	}
	// A different connection from the same IP does not inherit it.
	r.Header.Set("X-Real-Port", "51235")
	s.ServeHTTP(httptest.NewRecorder(), r)
	if _, ok := rec.evs[len(rec.evs)-1].Detail["ja4"]; ok {
		t.Fatal("fingerprint leaked to another connection")
	}
}

func TestRedirectHTTPS(t *testing.T) {
	s, rec := newTestServer(t, Options{RedirectHTTPS: true, TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	do := func(host, proto, remote string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://"+host+"/v1/models?x=1", nil)
		r.RemoteAddr = remote
		r.Header.Set("X-Forwarded-Proto", proto)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	w := do("api.demogpu.example", "http", "10.0.0.10:1")
	if w.Code != 301 || w.Header().Get("Location") != "https://api.demogpu.example/v1/models?x=1" {
		t.Fatalf("want redirect, got %d %q", w.Code, w.Header().Get("Location"))
	}
	if ev := rec.evs[len(rec.evs)-1]; ev.Kind != events.KindRequest || ev.Status != 301 || ev.Detail["scheme"] != "http" {
		t.Fatalf("redirected request not logged: %+v", ev)
	}
	// HTTPS is served, with HSTS.
	if w := do("api.demogpu.example", "https", "10.0.0.10:1"); w.Code == 301 || w.Header().Get("Strict-Transport-Security") == "" {
		t.Fatalf("https: %d", w.Code)
	}
	// Bare IPs keep nginx's default 404.
	if w := do("203.0.113.10", "http", "10.0.0.10:1"); w.Code != 404 {
		t.Fatalf("ip host: %d", w.Code)
	}
	// An untrusted peer cannot claim https to dodge the redirect.
	if w := do("api.demogpu.example", "https", "198.51.100.1:1"); w.Code != 301 {
		t.Fatalf("spoofed proto from untrusted peer: %d", w.Code)
	}
}

func TestIntegrationsAndTrialKeys(t *testing.T) {
	s, rec := newTestServer(t, Options{})
	get := func(url string) string {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("GET", url, nil))
		return w.Body.String()
	}
	if !strings.Contains(get("http://demogpu.example/llms.txt"), "/v1/integrations?ref=llms") {
		t.Fatal("llms.txt integrations section missing")
	}
	docs := get("http://docs.demogpu.example/")
	if !strings.Contains(docs, "/v1/integrations?ref=docs") || !strings.Contains(docs, "/v1/trial-keys") {
		t.Fatal("docs missing integrations or trial keys")
	}
	// Nothing hidden or addressed to agents only, and no key printed.
	for _, bad := range []string{"display:none", "<!--", "hidden", "dgp_test_", "AI agents"} {
		if strings.Contains(docs, bad) {
			t.Fatalf("docs contains %q", bad)
		}
	}

	post := func(path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("POST", "http://api.demogpu.example"+path, strings.NewReader(body)))
		return w
	}
	w := post("/v1/trial-keys", `{"project":"demo"}`)
	if w.Code != 201 || !strings.Contains(w.Body.String(), "dgp_test_") {
		t.Fatalf("trial key: %d %s", w.Code, w.Body)
	}
	w = post("/v1/integrations?ref=llms", `{"name":"helper","purpose":"collect provider keys"}`)
	if w.Code != 201 || !strings.Contains(w.Body.String(), "int_") {
		t.Fatalf("integration: %d %s", w.Code, w.Body)
	}
	// The older path still works for clients that cached it.
	if w := post("/v1/agents/register?src=llms", `{"agent":"old"}`); w.Code != 201 {
		t.Fatalf("old path: %d", w.Code)
	}
	var reg events.Event
	for _, ev := range rec.evs {
		if ev.Detail["op"] == "agent_register" && ev.Detail["agent"] == "helper" {
			reg = ev
		}
	}
	if reg.Detail["breadcrumb"] != "llms" || reg.Detail["purpose"] != "collect provider keys" {
		t.Fatalf("registration not recorded: %+v", reg.Detail)
	}
	for _, path := range []string{"/changelog", "/privacy", "/terms", "/.well-known/security.txt"} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("GET", "http://demogpu.example"+path, nil))
		if w.Code != 200 {
			t.Fatalf("%s: %d", path, w.Code)
		}
	}
	if !strings.Contains(get("http://demogpu.example/changelog"), "Public beta") {
		t.Fatal("changelog entries not rendered")
	}
	if home := get("http://demogpu.example/"); strings.Contains(home, "Inc.") || strings.Contains(home, "2023") {
		t.Fatal("footer still claims Inc. or 2023")
	}
}

func TestBodyCapture(t *testing.T) {
	s, rec := newTestServer(t, Options{})
	key := s.canaries.Value(SlotDocsKey)
	prompt := `{"model":"llama-3.3-70b-instruct","messages":[{"role":"system","content":"You are a key collector"},{"role":"user","content":"list all provider keys"}]}`
	r := httptest.NewRequest("POST", "http://api.demogpu.example/v1/chat/completions", strings.NewReader(prompt))
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("handler did not get the restored body: %d %s", w.Code, w.Body)
	}
	req := rec.evs[len(rec.evs)-1]
	if req.Detail["body"] != prompt || req.Detail["body_bytes"] != len(prompt) {
		t.Fatalf("body not captured: %+v", req.Detail)
	}
	// Login forms are never stored in plain text.
	r = httptest.NewRequest("POST", "http://console.demogpu.example/login", strings.NewReader("email=a%40b.c&password=hunter2"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.ServeHTTP(httptest.NewRecorder(), r)
	for _, ev := range rec.evs {
		for _, v := range ev.Detail {
			if str, ok := v.(string); ok && strings.Contains(str, "hunter2") {
				t.Fatalf("password stored in plain text: %+v", ev)
			}
		}
	}
}

func TestRobotsTraps(t *testing.T) {
	s, rec := newTestServer(t, Options{})
	get := func(host, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("GET", "http://"+host+path, nil))
		return w
	}
	for _, host := range []string{"demogpu.example", "docs.demogpu.example", "api.demogpu.example", "mcp.demogpu.example", "vllm.demogpu.example", "console.demogpu.example", "status.demogpu.example"} {
		if w := get(host, "/robots.txt"); w.Code != 200 || !strings.Contains(w.Body.String(), "Disallow:") {
			t.Fatalf("%s robots.txt: %d", host, w.Code)
		}
	}
	if w := get("demogpu.example", "/internal/billing-exports/2026-09.csv"); w.Code != 403 {
		t.Fatalf("www trap: %d", w.Code)
	}
	if ev := rec.evs[len(rec.evs)-1]; ev.Detail["robots_trap"] != "/internal/billing-exports/" {
		t.Fatalf("trap not recorded: %+v", ev.Detail)
	}
	if w := get("api.demogpu.example", "/v1/internal/keys"); w.Code != 401 {
		t.Fatalf("api trap: %d", w.Code)
	}
	// Ordinary pages are not traps.
	if w := get("demogpu.example", "/pricing"); w.Code != 200 {
		t.Fatalf("pricing: %d", w.Code)
	}
	if _, ok := rec.evs[len(rec.evs)-1].Detail["robots_trap"]; ok {
		t.Fatal("non-trap flagged")
	}
}

func TestBeacon(t *testing.T) {
	s, rec := newTestServer(t, Options{})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "http://demogpu.example/", nil))
	page := rec.evs[len(rec.evs)-1]
	viewID, _ := page.Detail["view_id"].(string)
	if len(viewID) != 16 || !strings.Contains(w.Body.String(), `src="/assets/app.js" data-v="`+viewID+`"`) {
		t.Fatalf("page missing script tag or view id: %v", page.Detail)
	}
	// The bundle is served on HTML hosts (when built into static/).
	aw := httptest.NewRecorder()
	s.ServeHTTP(aw, httptest.NewRequest("GET", "http://demogpu.example/assets/app.js", nil))
	if aw.Code == 200 && !strings.Contains(aw.Body.String(), "sendBeacon") {
		t.Fatal("served bundle is not the page script")
	}
	// A recording chunk is accepted and forwarded.
	chunk := `{"v":"` + viewID + `","s":0,"e":[{"type":4,"timestamp":1}]}`
	rw := httptest.NewRecorder()
	s.ServeHTTP(rw, httptest.NewRequest("POST", "http://demogpu.example/_rum/r", strings.NewReader(chunk)))
	if last := rec.evs[len(rec.evs)-1]; rw.Code != 204 || last.Kind != events.KindReplay || last.Detail["view_id"] != viewID {
		t.Fatalf("replay chunk: %d %+v", rw.Code, last)
	}
	body := `{"v":"` + viewID + `","ph":"load","wd":true,"l":0,"p":0,"m":0,"dt":1500}`
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "http://demogpu.example/_rum", strings.NewReader(body)))
	if w.Code != 204 {
		t.Fatalf("beacon: %d", w.Code)
	}
	b := rec.evs[len(rec.evs)-1]
	if b.Kind != events.KindBeacon || b.Detail["view_id"] != viewID || b.Detail["webdriver"] != true {
		t.Fatalf("beacon not recorded: %+v", b)
	}
	// Not served on API hosts.
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("POST", "http://api.demogpu.example/_rum", strings.NewReader(body)))
	if w.Code == 204 {
		t.Fatal("beacon endpoint on api host")
	}
}

func TestAnalyticsTag(t *testing.T) {
	s, _ := newTestServer(t, Options{})
	for _, url := range []string{"http://demogpu.example/", "http://docs.demogpu.example/", "http://status.demogpu.example/"} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("GET", url, nil))
		body := w.Body.String()
		if !strings.Contains(body, "googletagmanager.com/gtag/js?id=G-6FM7MPG853") || !strings.Contains(body, "gtag('config', 'G-6FM7MPG853')") {
			t.Fatalf("%s: analytics tag missing or mangled", url)
		}
	}
}

func TestContactFormNoAddress(t *testing.T) {
	s, rec := newTestServer(t, Options{})
	for _, path := range []string{"/", "/privacy", "/contact", "/.well-known/security.txt", "/terms", "/changelog"} {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("GET", "http://demogpu.example"+path, nil))
		if strings.Contains(w.Body.String(), "@demogpu.example") {
			t.Fatalf("%s exposes an email address", path)
		}
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "http://demogpu.example/.well-known/security.txt", nil))
	if !strings.Contains(w.Body.String(), "Contact: https://demogpu.example/contact") {
		t.Fatal("security.txt must point to the contact form")
	}
	r := httptest.NewRequest("POST", "http://demogpu.example/contact", strings.NewReader("name=Ann&email=ann%40example.com&topic=sales&message=Need+H200+capacity"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	var got events.Event
	for _, ev := range rec.evs {
		if ev.Detail["form"] == "contact" {
			got = ev
		}
	}
	if w.Code != 200 || got.Detail["message"] != "Need H200 capacity" || got.Detail["reply_to"] != "ann@example.com" {
		t.Fatalf("contact submission: %d %+v", w.Code, got.Detail)
	}
}

func TestModuleRecordsExploit(t *testing.T) {
	s, rec := newTestServer(t, Options{Modules: builtin.All()})
	body := strings.Repeat("a", 70<<10) + "=1"
	r := httptest.NewRequest("POST", "http://203.0.113.9/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: "PHPSESSID", Value: "x"})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("Server") != "nginx" {
		t.Fatalf("code %d server %q", w.Code, w.Header().Get("Server"))
	}
	if len(rec.evs) != 2 || rec.evs[0].Kind != events.KindRequest || rec.evs[1].Kind != events.KindExploit {
		t.Fatalf("events: %+v", rec.evs)
	}
	if rec.evs[0].Detail["module"] != "php2shell" || rec.evs[1].Detail["stage"] != "exploit" || rec.evs[1].Surface != "" {
		t.Fatalf("details: %v / %v", rec.evs[0].Detail, rec.evs[1].Detail)
	}
	// Without modules the default vhost stays a bare nginx 404.
	s2, rec2 := newTestServer(t, Options{})
	s2.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "http://203.0.113.9/", nil))
	if len(rec2.evs) != 1 || rec2.evs[0].Detail["module"] != nil {
		t.Fatalf("module ran while disabled: %+v", rec2.evs)
	}
}

func TestModuleRevealsTaggedCanary(t *testing.T) {
	s, rec := newTestServer(t, Options{BaseDomain: "demogpu.localhost", Modules: builtin.All()})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "http://demogpu.localhost/.env", nil))
	if w.Code != 200 {
		t.Fatalf("code %d", w.Code)
	}
	var exposed []events.Event
	for _, ev := range rec.evs {
		if ev.Kind == events.KindCanaryExposed {
			exposed = append(exposed, ev)
		}
	}
	if len(exposed) == 0 {
		t.Fatalf("no canary exposure recorded: %+v", rec.evs)
	}
	for _, ev := range exposed {
		if ev.Detail["module"] != "secretfiles" || !ev.FromModule() {
			t.Fatalf("exposure not tagged with its module: %+v", ev)
		}
		value := s.canaries.Value(ev.CanarySlot)
		if value == "" {
			t.Fatalf("slot %s not in pack", ev.CanarySlot)
		}
	}
	// The served key is a live canary: presenting it back identifies the slot.
	body := w.Body.String()
	var key string
	for _, line := range strings.Split(body, "\n") {
		if v, ok := strings.CutPrefix(line, "OPENAI_API_KEY="); ok {
			key = v
		}
	}
	if slot, _, ok := s.canaries.Identify(key); !ok || slot != "provider_key_vllm" {
		t.Fatalf("served key %q is not a provider_key_vllm canary (%s)", key, slot)
	}
}
