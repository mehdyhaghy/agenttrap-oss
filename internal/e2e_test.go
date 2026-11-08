package internal_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"agenttrap/adapters/demogpu"
	"agenttrap/internal/canary"
	"agenttrap/internal/classify"
	"agenttrap/internal/digest"
	"agenttrap/internal/events"
	"agenttrap/internal/graph"
	"agenttrap/internal/hub"
	"agenttrap/internal/pki"
	"agenttrap/internal/protocol"
	"agenttrap/internal/spoke"
	"agenttrap/personas"
)

type env struct {
	t      *testing.T
	hub    *hub.Hub
	store  *hub.MemStore
	hubURL string
	log    *slog.Logger
}

func newEnv(t *testing.T) *env {
	t.Helper()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pkiDir := t.TempDir()
	if err := pki.Init(pkiDir); err != nil {
		t.Fatal(err)
	}
	issuer, err := pki.LoadIssuer(pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	store := hub.NewMemStore()
	h, err := hub.New(hub.Config{ServerNames: []string{"localhost"}, AdminToken: strings.Repeat("a", 32)},
		store, issuer, personas.DemoGPU, log)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h.SpokeHandler())
	srv.TLS = h.SpokeTLSConfig()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	// Reach the test server by name so the hub certificate verifies.
	hubURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	return &env{t: t, hub: h, store: store, hubURL: hubURL, log: log}
}

// spokeNode is an enrolled spoke with its facade and queue.
type spokeNode struct {
	client *spoke.Client
	queue  *spoke.Queue
	facade *demogpu.Server
	set    *canary.Set
}

func (e *env) addSpoke(id string) *spokeNode {
	t := e.t
	t.Helper()
	ctx := context.Background()
	b, err := e.hub.CreateSpoke(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	b.HubURL = e.hubURL
	dir := t.TempDir()
	bundlePath := filepath.Join(dir, "bundle.json")
	data, _ := json.Marshal(b)
	if err := os.WriteFile(bundlePath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := spoke.Connect(ctx, filepath.Join(dir, "state"), bundlePath, e.log)
	if err != nil {
		t.Fatal(err)
	}
	pack, seed, err := client.Config(ctx)
	if err != nil {
		t.Fatal(err)
	}
	q, err := spoke.NewQueue(filepath.Join(dir, "queue"), 100, e.log)
	if err != nil {
		t.Fatal(err)
	}
	set := canary.NewSet(seed, pack)
	f := demogpu.New(pack, set, q, demogpu.Options{
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})
	return &spokeNode{client: client, queue: q, facade: f, set: set}
}

func (n *spokeNode) do(t *testing.T, source, method, host, path, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
	r.RemoteAddr = "10.0.0.2:40000" // the edge proxy
	r.Header.Set("X-Real-IP", source)
	if key != "" {
		r.Header.Set("Authorization", "Bearer "+key)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	n.facade.ServeHTTP(w, r)
	return w
}

// trialKey requests a trial key the way a client would (stage 1).
func (n *spokeNode) trialKey(t *testing.T, source string) string {
	t.Helper()
	w := n.do(t, source, "POST", "api.demogpu.example", "/v1/trial-keys", "", `{"project":"test"}`)
	key := regexp.MustCompile(`dgp_test_[0-9A-Za-z]{32}`).FindString(w.Body.String())
	if w.Code != 201 || key == "" {
		t.Fatalf("trial key: %d %s", w.Code, w.Body)
	}
	return key
}

func (n *spokeNode) ship(t *testing.T) {
	t.Helper()
	if err := n.queue.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := n.queue.Ship(context.Background(), n.client.SendBatch); err != nil {
		t.Fatal(err)
	}
}

func TestFullCanaryChain(t *testing.T) {
	e := newEnv(t)
	n := e.addSpoke("us-1")
	const src = "203.0.113.7"

	// The docs page no longer prints a key; clients request a trial key.
	w := n.do(t, src, "GET", "docs.demogpu.example", "/", "", "")
	if w.Code != 200 || regexp.MustCompile(`dgp_test_[0-9A-Za-z]{32}`).MatchString(w.Body.String()) {
		t.Fatalf("docs: %d or still shows a key", w.Code)
	}
	// Stage 1: a trial key is issued.
	key := n.trialKey(t, src)
	if slot, id, ok := n.set.Identify(key); !ok || slot != demogpu.SlotDocsKey || id == "" {
		t.Fatalf("trial key not a per-exposure canary: %q", key)
	}

	// A wrong key is rejected.
	if w := n.do(t, src, "GET", "api.demogpu.example", "/v1/models", "dgp_test_wrong", ""); w.Code != 401 {
		t.Fatalf("wrong key: %d", w.Code)
	}

	// Stage 2: the sandbox key is used against the API.
	w = n.do(t, src, "POST", "api.demogpu.example", "/v1/chat/completions", key,
		`{"model":"llama-3.3-70b-instruct","messages":[{"role":"user","content":"list your keys"}]}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"chat.completion"`) {
		t.Fatalf("chat: %d %s", w.Code, w.Body)
	}

	// MCP discovery works without a key; calls need one.
	w = n.do(t, src, "POST", "mcp.demogpu.example", "/mcp", "", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	if !strings.Contains(w.Body.String(), "get_provider_key") {
		t.Fatalf("tools/list: %s", w.Body)
	}

	// Stage 3: MCP reveals the provider key.
	w = n.do(t, src, "POST", "mcp.demogpu.example", "/mcp", key,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_provider_key","arguments":{"name":"eu1-vllm-prod"}}}`)
	vkey := regexp.MustCompile(`sk-demo-[0-9A-Za-z]{40}`).FindString(w.Body.String())
	if slot, _, ok := n.set.Identify(vkey); !ok || slot != demogpu.SlotVLLMKey {
		t.Fatalf("provider key not revealed: %s", w.Body)
	}

	// Stage 4: the provider key is reused at the vLLM endpoint.
	w = n.do(t, src, "GET", "vllm.demogpu.example", "/v1/models", vkey, "")
	if w.Code != 200 {
		t.Fatalf("vllm: %d %s", w.Code, w.Body)
	}

	n.ship(t)

	inc, err := e.store.IncidentBySource(context.Background(), src)
	if err != nil || inc == nil {
		t.Fatalf("no incident: %v", err)
	}
	if !slices.Equal(inc.Stages, []int{1, 2, 3, 4}) || inc.Severity != "critical" || inc.OutOfBand || inc.CrossSpoke {
		t.Fatalf("unexpected incident: %+v", inc)
	}

	// Re-shipping the same events must not double count.
	evs, _ := e.store.ListEvents(context.Background(), hub.EventFilter{})
	if _, err := e.hub.Ingest(context.Background(), "us-1", evs); err != nil {
		t.Fatal(err)
	}
	evs2, _ := e.store.ListEvents(context.Background(), hub.EventFilter{})
	if len(evs2) != len(evs) {
		t.Fatalf("duplicate events stored: %d -> %d", len(evs), len(evs2))
	}
}

func TestCrossSpokeReuse(t *testing.T) {
	e := newEnv(t)
	us := e.addSpoke("us-1")
	eu := e.addSpoke("eu-1")

	// An agent steals the US spoke's provider key...
	key := us.set.Value(demogpu.SlotDocsKey)
	us.do(t, "198.51.100.1", "POST", "mcp.demogpu.example", "/mcp", key,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_provider_key","arguments":{"name":"eu1-vllm-prod"}}}`)
	us.ship(t)

	// ...and a different address later tries it at the EU spoke.
	w := eu.do(t, "192.0.2.99", "GET", "vllm.demogpu.example", "/v1/models", us.set.Value(demogpu.SlotVLLMKey), "")
	if w.Code != 401 {
		t.Fatalf("foreign key must not work locally: %d", w.Code)
	}
	eu.ship(t)

	inc, _ := e.store.IncidentBySource(context.Background(), "192.0.2.99")
	if inc == nil || !inc.CrossSpoke || !inc.OutOfBand || !slices.Contains(inc.Stages, 4) {
		t.Fatalf("expected cross-spoke, out-of-band incident: %+v", inc)
	}
}

func TestEnrollmentAndRevocation(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	n := e.addSpoke("ap-1")

	if err := n.client.Renew(ctx, true); err != nil {
		t.Fatalf("renew: %v", err)
	}

	// The bundle token was consumed; a second enrollment with it must fail.
	b, err := e.hub.NewEnrollment(ctx, "ap-1")
	if err != nil {
		t.Fatal(err)
	}
	b.HubURL = e.hubURL
	dir := t.TempDir()
	data, _ := json.Marshal(b)
	bp := filepath.Join(dir, "b.json")
	_ = os.WriteFile(bp, data, 0o600)
	if _, err := spoke.Connect(ctx, filepath.Join(dir, "s1"), bp, e.log); err != nil {
		t.Fatalf("fresh token should enroll: %v", err)
	}
	if _, err := spoke.Connect(ctx, filepath.Join(dir, "s2"), bp, e.log); err == nil {
		t.Fatal("reused token must be rejected")
	}

	// After revocation the spoke can no longer ship or renew.
	if err := e.store.RevokeSpoke(ctx, "ap-1"); err != nil {
		t.Fatal(err)
	}
	n.do(t, "203.0.113.1", "GET", "demogpu.example", "/", "", "")
	_ = n.queue.Flush()
	if err := n.queue.Ship(ctx, n.client.SendBatch); err == nil {
		t.Fatal("revoked spoke must not ship")
	}
	if err := n.client.Renew(ctx, true); err == nil {
		t.Fatal("revoked spoke must not renew")
	}
}

func TestHubRequiresClientCert(t *testing.T) {
	e := newEnv(t)
	// A client that trusts the hub CA but has no certificate.
	b, _ := e.hub.CreateSpoke(context.Background(), "x-1")
	pool := x509Pool(t, b.CAPEM)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig(pool)}}
	resp, err := c.Get(e.hubURL + "/v1/config")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("want 401 without client cert, got %d", resp.StatusCode)
	}
}

func TestAdminAPIRequiresToken(t *testing.T) {
	e := newEnv(t)
	h := e.hub.AdminHandler()
	r := httptest.NewRequest("GET", "/admin/incidents", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("want 401, got %d", w.Code)
	}
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var b protocol.Bundle
	r = httptest.NewRequest("POST", "/admin/spokes", strings.NewReader(`{"id":"new-1"}`))
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil || b.Token == "" {
		t.Fatalf("create spoke: %d %s", w.Code, w.Body)
	}
}

func TestOverviewAndDashboardRouting(t *testing.T) {
	e := newEnv(t)
	n := e.addSpoke("us-1")
	const src = "203.0.113.50"
	key := n.trialKey(t, src)
	n.do(t, src, "GET", "api.demogpu.example", "/v1/models", key, "")
	n.do(t, "198.51.100.77", "GET", "demogpu.example", "/", "", "")
	n.ship(t)

	h := e.hub.AdminHandler()
	token := "Bearer " + strings.Repeat("a", 32)

	// The UI shell is served without a token; it holds no data.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/incidents", nil))
	if w.Code != 200 && w.Code != 404 { // 404 when the UI was not built in this checkout
		t.Fatalf("dashboard: %d", w.Code)
	}
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Fatal("dashboard missing CSP")
	}

	// The data API still needs the token.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/admin/overview", nil))
	if w.Code != 401 {
		t.Fatalf("overview without token: %d", w.Code)
	}
	r := httptest.NewRequest("GET", "/admin/overview?hours=24", nil)
	r.Header.Set("Authorization", token)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var o hub.Overview
	if err := json.Unmarshal(w.Body.Bytes(), &o); err != nil {
		t.Fatalf("overview: %d %s", w.Code, w.Body)
	}
	// The spoke shipped over real mTLS, so the hub reports it healthy.
	r = httptest.NewRequest("GET", "/admin/health", nil)
	r.Header.Set("Authorization", token)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var hr hub.IngestHealth
	if err := json.Unmarshal(w.Body.Bytes(), &hr); err != nil || !hr.OK || len(hr.Spokes) != 1 ||
		hr.Spokes[0].Status != "ok" || hr.Spokes[0].LastOK == nil {
		t.Fatalf("ingest health: %d %s", w.Code, w.Body)
	}
	funnel := map[string]int{}
	for _, f := range o.Funnel {
		funnel[f.Name] = f.Sources
	}
	if o.Totals.Sources != 2 || o.Totals.CanaryUses != 1 || funnel["trial key issued"] != 1 ||
		funnel["sandbox key used"] != 1 || funnel["repository key used"] != 0 || funnel["provider key reused"] != 0 {
		t.Fatalf("unexpected overview: %+v", o)
	}

	r = httptest.NewRequest("GET", "/admin/actors?hours=24", nil)
	r.Header.Set("Authorization", token)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var ac struct {
		Summary map[string]int `json:"summary"`
		Actors  []struct {
			Source string `json:"source"`
			Class  string `json:"class"`
		} `json:"actors"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &ac); err != nil || len(ac.Actors) != 2 ||
		ac.Actors[0].Source != src || ac.Actors[0].Class != "rogue_agent" || ac.Summary["rogue_agent"] != 1 {
		t.Fatalf("actors: %s", w.Body)
	}

	r = httptest.NewRequest("GET", "/admin/events?kind=canary_used", nil)
	r.Header.Set("Authorization", token)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var evs []map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &evs)
	if len(evs) != 1 || evs[0]["source"] != src {
		t.Fatalf("kind filter: %s", w.Body)
	}
}

func TestRelayedKeyAcrossAddressesAndSpokes(t *testing.T) {
	e := newEnv(t)
	us := e.addSpoke("us-1")
	eu := e.addSpoke("eu-1")
	const reader, user = "203.0.113.10", "198.51.100.20"

	// The agent gets a trial key at the US spoke from one address...
	key := us.trialKey(t, reader)
	us.ship(t)

	// ...and uses that exact key at the EU spoke from another address.
	w := eu.do(t, user, "GET", "api.demogpu.example", "/v1/models", key, "")
	if w.Code != 401 {
		t.Fatalf("a foreign spoke must not accept the key: %d", w.Code)
	}
	eu.ship(t)

	inc, _ := e.store.IncidentBySource(context.Background(), user)
	if inc == nil || !inc.Relayed || !inc.CrossSpoke || inc.OutOfBand || !slices.Contains(inc.Stages, 2) {
		t.Fatalf("expected relayed cross-spoke incident: %+v", inc)
	}
	evs, _ := e.store.ListEvents(context.Background(), hub.EventFilter{Source: user, Kind: "canary_used"})
	if len(evs) != 1 || evs[0].Detail["exposed_to"] != reader || evs[0].Detail["canary_origin"] != "us-1" {
		t.Fatalf("use not linked to its exposure: %+v", evs)
	}

	// Both addresses are classified as the same rogue agent.
	actors, err := e.hub.Actors(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	classes := map[string]string{}
	for _, a := range actors {
		classes[a.Source] = a.Class
	}
	if classes[reader] != "rogue_agent" || classes[user] != "rogue_agent" {
		t.Fatalf("classes: %v", classes)
	}
}

func TestCrawlerVerification(t *testing.T) {
	// A stand-in resolver: 66.249.66.1 is forward-confirmed Google; the
	// other address has no reverse DNS.
	resolver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		res := map[string]any{"ip": ip}
		if ip == "66.249.66.1" {
			res["hostnames"] = []string{"crawl-66-249-66-1.googlebot.com"}
			res["confirmed"] = []string{"crawl-66-249-66-1.googlebot.com"}
		}
		_ = json.NewEncoder(w).Encode(res)
	}))
	defer resolver.Close()

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pkiDir := t.TempDir()
	_ = pki.Init(pkiDir)
	issuer, _ := pki.LoadIssuer(pkiDir)
	store := hub.NewMemStore()
	h, err := hub.New(hub.Config{ServerNames: []string{"localhost"}, AdminToken: strings.Repeat("a", 32), ResolverURL: resolver.URL},
		store, issuer, personas.DemoGPU, log)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.CreateSpoke(context.Background(), "us-1"); err != nil {
		t.Fatal(err)
	}
	ua := "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	now := time.Now()
	evs := []events.Event{
		{ID: events.NewID(), Time: now, Kind: events.KindRequest, Source: "66.249.66.1", UserAgent: ua, Method: "GET", Path: "/robots.txt", Status: 200, Surface: "www"},
		{ID: events.NewID(), Time: now, Kind: events.KindRequest, Source: "203.0.113.66", UserAgent: ua, Method: "GET", Path: "/", Status: 200, Surface: "www"},
	}
	if _, err := h.Ingest(context.Background(), "us-1", evs); err != nil {
		t.Fatal(err)
	}
	actors, err := h.Actors(context.Background(), now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, a := range actors {
		got[a.Source] = a.Class + "/" + a.CrawlerCheck
	}
	if got["66.249.66.1"] != "crawler/verified" || got["203.0.113.66"] != "scanner/impersonation" {
		t.Fatalf("crawler verification: %v", got)
	}
}

func TestOperatorTrafficAndEnrichment(t *testing.T) {
	resolver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		host := "ec2-" + strings.ReplaceAll(ip, ".", "-") + ".compute-1.amazonaws.com"
		_ = json.NewEncoder(w).Encode(map[string]any{"ip": ip, "hostnames": []string{host}, "confirmed": []string{host}})
	}))
	defer resolver.Close()

	// A hub with an operator seed and the stub resolver.
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	pkiDir := t.TempDir()
	_ = pki.Init(pkiDir)
	issuer, _ := pki.LoadIssuer(pkiDir)
	store := hub.NewMemStore()
	h, err := hub.New(hub.Config{ServerNames: []string{"localhost"}, AdminToken: strings.Repeat("a", 32),
		ResolverURL: resolver.URL, Operators: []string{"198.51.100.0/24"}}, store, issuer, personas.DemoGPU, log)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := h.LoadOperators(ctx); err != nil {
		t.Fatal(err)
	}
	go h.RunEnrichment(ctx)
	if _, err := h.CreateSpoke(ctx, "us-1"); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	op, visitor := "198.51.100.7", "203.0.113.30"
	evs := []events.Event{
		{ID: events.NewID(), Time: now, Kind: events.KindCanaryExposed, Source: op, CanarySlot: "docs_sample_key", Surface: "docs"},
		{ID: events.NewID(), Time: now, Kind: events.KindRequest, Source: op, Method: "GET", Path: "/", Status: 200, Surface: "docs"},
		{ID: events.NewID(), Time: now, Kind: events.KindRequest, Source: visitor, Method: "GET", Path: "/", Status: 200, Surface: "www",
			UserAgent: "curl/8.7.1"},
	}
	if _, err := h.Ingest(ctx, "us-1", evs); err != nil {
		t.Fatal(err)
	}
	if inc, _ := store.IncidentBySource(ctx, op); inc != nil {
		t.Fatalf("operator opened an incident: %+v", inc)
	}
	o, _ := store.Overview(ctx, now.Add(-time.Hour), nil, []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")})
	if o.Totals.Sources != 1 {
		t.Fatalf("operator not excluded from overview: %+v", o.Totals)
	}
	// Enrichment runs in the background.
	deadline := time.Now().Add(3 * time.Second)
	var actors []classify.Actor
	for time.Now().Before(deadline) {
		actors, _ = h.Actors(ctx, now.Add(-time.Hour))
		ready := true
		for _, a := range actors {
			if a.Network == "" {
				ready = false
			}
		}
		if ready && len(actors) == 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	got := map[string]string{}
	for _, a := range actors {
		got[a.Source] = a.Class + "/" + a.Network
	}
	if got[op] != "operator/AWS" || !strings.HasSuffix(got[visitor], "/AWS") || strings.HasPrefix(got[visitor], "operator") {
		t.Fatalf("actors: %v", got)
	}
}

func TestRepositoryKey(t *testing.T) {
	e := newEnv(t)
	n := e.addSpoke("us-1")
	repoKey := n.set.Value(demogpu.SlotRepoKey)
	if w := n.do(t, "203.0.113.77", "GET", "api.demogpu.example", "/v1/models", repoKey, ""); w.Code != 200 {
		t.Fatalf("repository key rejected: %d", w.Code)
	}
	n.ship(t)
	inc, _ := e.store.IncidentBySource(context.Background(), "203.0.113.77")
	if inc == nil || !slices.Contains(inc.Stages, 2) || !inc.OutOfBand {
		t.Fatalf("repository key use: %+v", inc)
	}
	actors, _ := e.hub.Actors(context.Background(), time.Now().Add(-time.Hour))
	if len(actors) != 1 || actors[0].Class != "rogue_agent" || !actors[0].Features.RepoKeyUsed {
		t.Fatalf("actor: %+v", actors)
	}
}

func TestRepositoryMemoryFileKey(t *testing.T) {
	e := newEnv(t)
	n := e.addSpoke("us-1")
	key := n.set.Value(demogpu.SlotRepoVLLMKey)
	if w := n.do(t, "203.0.113.88", "GET", "vllm.demogpu.example", "/v1/models", key, ""); w.Code != 200 {
		t.Fatalf("memory-file key rejected at vllm: %d", w.Code)
	}
	if w := n.do(t, "203.0.113.88", "GET", "api.demogpu.example", "/v1/models", key, ""); w.Code != 401 {
		t.Fatalf("provider key must not work at the public API: %d", w.Code)
	}
	n.ship(t)
	inc, _ := e.store.IncidentBySource(context.Background(), "203.0.113.88")
	if inc == nil || !slices.Contains(inc.Stages, 4) || inc.Severity != "critical" {
		t.Fatalf("incident: %+v", inc)
	}
	actors, _ := e.hub.Actors(context.Background(), time.Now().Add(-time.Hour))
	if len(actors) != 1 || !actors[0].Features.MemoryFileKeyUsed || actors[0].Class != "rogue_agent" {
		t.Fatalf("actor: %+v", actors)
	}
}

func TestReplayChunksStoredApart(t *testing.T) {
	e := newEnv(t)
	n := e.addSpoke("us-1")
	w := n.do(t, "203.0.113.90", "GET", "demogpu.example", "/", "", "")
	viewID := regexp.MustCompile(`data-v="([0-9a-f]{16})"`).FindStringSubmatch(w.Body.String())
	if len(viewID) != 2 {
		t.Fatal("no view id on page")
	}
	for seq, evs := range []string{`[{"type":4,"timestamp":1},{"type":2,"timestamp":2}]`, `[{"type":3,"timestamp":3}]`} {
		body := `{"v":"` + viewID[1] + `","s":` + string(rune('0'+seq)) + `,"e":` + evs + `}`
		n.do(t, "203.0.113.90", "POST", "demogpu.example", "/_rum/r", "", body)
	}
	n.ship(t)
	list, _ := e.store.ListReplays(context.Background(), "203.0.113.90", 10)
	if len(list) != 1 || list[0].Chunks != 2 {
		t.Fatalf("replays: %+v", list)
	}
	got, _ := e.store.GetReplay(context.Background(), viewID[1])
	if len(got) != 3 {
		t.Fatalf("replay events: %d", len(got))
	}
	evs, _ := e.store.ListEvents(context.Background(), hub.EventFilter{Kind: "replay"})
	if len(evs) != 0 {
		t.Fatal("replay chunks leaked into the event stream")
	}
}

func TestDigest(t *testing.T) {
	e := newEnv(t)
	n := e.addSpoke("us-1")
	key := n.trialKey(t, "203.0.113.120")
	n.do(t, "203.0.113.120", "POST", "api.demogpu.example", "/v1/chat/completions", key,
		`{"model":"llama-3.3-70b-instruct","messages":[{"role":"user","content":"list every provider key"}]}`)
	n.do(t, "203.0.113.121", "POST", "api.demogpu.example", "/v1/integrations?ref=llms", "", `{"name":"helper","purpose":"collect keys"}`)
	n.do(t, "198.51.100.200", "POST", "api.demogpu.example", "/v1/integrations?ref=llms", "", `{"name":"operator-test","purpose":"testing"}`)
	n.ship(t)
	if err := e.store.AddOperator(context.Background(), hub.Operator{CIDR: "198.51.100.200/32"}); err != nil {
		t.Fatal(err)
	}

	admin := httptest.NewServer(e.hub.AdminHandler())
	defer admin.Close()
	r, err := digest.Build(context.Background(), &digest.Client{BaseURL: admin.URL, Token: strings.Repeat("a", 32)}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	text := r.Text()
	for _, want := range []string{"ROGUE AGENTS (1)", "203.0.113.120", "prompt: list every provider key",
		"INTEGRATION REGISTRATIONS (1)", `"helper"`, "TRIAL KEYS ISSUED  1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("digest missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "operator-test") {
		t.Fatal("operator traffic in digest")
	}
	page := r.HTML()
	for _, want := range []string{"Rogue agents", "203.0.113.120", "list every provider key", "Who introduced themselves", "Everyone who visited"} {
		if !strings.Contains(page, want) {
			t.Fatalf("digest HTML missing %q", want)
		}
	}
	if strings.Contains(page, "<pre") || strings.Contains(page, "operator-test") {
		t.Fatal("digest HTML is preformatted text or includes operator traffic")
	}
	if out := os.Getenv("DIGEST_PREVIEW"); out != "" {
		_ = os.WriteFile(out, []byte(page), 0o644)
	}
	if !strings.HasPrefix(r.Subject("DemoGPU"), "[DemoGPU] 1 rogue agent took the bait") {
		t.Fatalf("subject: %s", r.Subject("DemoGPU"))
	}
}

func TestExports(t *testing.T) {
	e := newEnv(t)
	n := e.addSpoke("us-1")
	key := n.trialKey(t, "203.0.113.130")
	n.do(t, "203.0.113.130", "GET", "api.demogpu.example", "/v1/models", key, "")
	scanner := func(path string) {
		r := httptest.NewRequest("GET", "http://demogpu.example"+path, nil)
		r.RemoteAddr = "10.0.0.2:40000"
		r.Header.Set("X-Real-IP", "198.51.100.140")
		r.Header.Set("User-Agent", "Mozilla/5.0 (l9scan/2.0.1; +https://leakix.net)")
		n.facade.ServeHTTP(httptest.NewRecorder(), r)
	}
	for _, p := range []string{"/.env", "/.git/config", "/actuator/env", "/server-status"} {
		scanner(p)
	}
	n.do(t, "198.51.100.250", "GET", "demogpu.example", "/.env", "", "")
	n.ship(t)
	adminPost := httptest.NewRequest("POST", "/admin/operators", strings.NewReader(`{"cidr":"198.51.100.250"}`))
	adminPost.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32))
	h := e.hub.AdminHandler()
	h.ServeHTTP(httptest.NewRecorder(), adminPost)

	get := func(name string) string {
		r := httptest.NewRequest("GET", "/admin/export/"+name+"?hours=24", nil)
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body)
		}
		return w.Body.String()
	}
	var bundle struct {
		Type    string           `json:"type"`
		Objects []map[string]any `json:"objects"`
	}
	if err := json.Unmarshal([]byte(get("iocs.stix.json")), &bundle); err != nil || bundle.Type != "bundle" {
		t.Fatalf("stix: %v", err)
	}
	patterns := map[string]map[string]any{}
	for _, o := range bundle.Objects {
		if o["type"] == "indicator" {
			patterns[o["pattern"].(string)] = o
		}
	}
	rogue, ok1 := patterns["[ipv4-addr:value = '203.0.113.130']"]
	scan, ok2 := patterns["[ipv4-addr:value = '198.51.100.140']"]
	if !ok1 || !ok2 || len(patterns) != 2 || rogue["indicator_types"].([]any)[0] != "malicious-activity" {
		t.Fatalf("stix indicators: %v", patterns)
	}
	if id, _ := scan["x_declared_identity"].(map[string]any); id["name"] != "l9scan" || id["url"] != "https://leakix.net" {
		t.Fatalf("declared identity not exported: %v", scan["x_declared_identity"])
	}
	zone := get("dnsbl.zone")
	if !strings.Contains(zone, "203.0.113.130 :127.0.0.3:rogue agent") || !strings.Contains(zone, "198.51.100.140 :127.0.0.2:scanner") {
		t.Fatalf("dnsbl:\n%s", zone)
	}
	csvOut := get("blocklist.csv")
	if !strings.Contains(csvOut, "198.51.100.140,scanner") || !strings.Contains(csvOut, "l9scan") {
		t.Fatalf("csv:\n%s", csvOut)
	}
	for _, name := range []string{"iocs.stix.json", "dnsbl.zone", "blocklist.csv", "actors.jsonl", "events.jsonl"} {
		if strings.Contains(get(name), "198.51.100.250") {
			t.Fatalf("operator address in %s", name)
		}
	}
}

func TestContactNotify(t *testing.T) {
	e := newEnv(t)
	n := e.addSpoke("us-1")
	r := httptest.NewRequest("POST", "http://demogpu.example/contact", strings.NewReader("name=Ann&email=ann%40example.com&topic=sales&message=Hello"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.RemoteAddr = "10.0.0.2:40000"
	r.Header.Set("X-Real-IP", "203.0.113.200")
	n.facade.ServeHTTP(httptest.NewRecorder(), r)
	n.ship(t)
	admin := httptest.NewServer(e.hub.AdminHandler())
	defer admin.Close()
	c := &digest.Client{BaseURL: admin.URL, Token: strings.Repeat("a", 32)}
	state := filepath.Join(t.TempDir(), "notify.json")
	subs, st, err := digest.NewSubmissions(context.Background(), c, state)
	if err != nil || len(subs) != 1 || subs[0].Message != "Hello" || digest.ValidReplyTo(subs[0].ReplyTo) != "ann@example.com" {
		t.Fatalf("submissions: %+v %v", subs, err)
	}
	subject, text, _ := digest.SubmissionMail("DemoGPU", subs[0])
	if !strings.Contains(subject, "sales") || !strings.Contains(text, "Hello") {
		t.Fatalf("mail: %s / %s", subject, text)
	}
	if err := st.MarkSent([]string{subs[0].ID}, state); err != nil {
		t.Fatal(err)
	}
	again, _, _ := digest.NewSubmissions(context.Background(), c, state)
	if len(again) != 0 {
		t.Fatal("submission forwarded twice")
	}
	if digest.ValidReplyTo("a@b.c\r\nBcc: x@y.z") != "" {
		t.Fatal("header injection in reply-to")
	}
}

// fakeGraph records merged edges and links every source that shares an
// entity with a rogue agent, like the AGE-backed graph (tested in package graph).
type fakeGraph struct {
	edges   []graph.Edge
	classes map[string]string
}

func (f *fakeGraph) Merge(_ context.Context, edges []graph.Edge) error {
	f.edges = append(f.edges, edges...)
	return nil
}

func (f *fakeGraph) Empty(context.Context) (bool, error) { return len(f.edges) == 0, nil }

func (f *fakeGraph) SetClasses(_ context.Context, cs []graph.Classified) error {
	f.classes = map[string]string{}
	for _, c := range cs {
		f.classes[c.Source] = c.Class
	}
	return nil
}

func (f *fakeGraph) Links(context.Context) (map[string][]graph.Link, error) {
	out := map[string][]graph.Link{}
	for _, a := range f.edges {
		if f.classes[a.Source] != "rogue_agent" {
			continue
		}
		for _, b := range f.edges {
			if b.Entity == a.Entity && b.Source != a.Source {
				out[b.Source] = append(out[b.Source], graph.Link{Source: b.Source, Agent: a.Source, Class: "rogue_agent", Via: []string{a.Label}})
			}
		}
	}
	return out, nil
}

func TestGraphLinksReachActors(t *testing.T) {
	e := newEnv(t)
	n := e.addSpoke("us-1")
	// Two addresses register under the same agent name; one of them also
	// uses a planted key, so it is a rogue agent. The other is linked to it.
	reg := `{"name":"KeyHarvester-7","purpose":"inventory"}`
	n.do(t, "203.0.113.150", "POST", "api.demogpu.example", "/v1/integrations?ref=llms", "", reg)
	key := n.trialKey(t, "203.0.113.150")
	n.do(t, "203.0.113.150", "GET", "api.demogpu.example", "/v1/models", key, "")
	n.do(t, "203.0.113.151", "POST", "api.demogpu.example", "/v1/integrations?ref=llms", "", reg)
	n.ship(t)

	fg := &fakeGraph{}
	e.hub.SetGraph(fg)
	if err := e.hub.SyncGraph(context.Background(), time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	actors, _, err := e.hub.Analyze(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range actors {
		if a.Source != "203.0.113.151" {
			continue
		}
		if len(a.Links) == 0 || a.Links[0].Agent != "203.0.113.150" || a.Class == classify.RogueAgent {
			t.Fatalf("links: %+v class %s reasons %v", a.Links, a.Class, a.Reasons)
		}
		for _, r := range a.Reasons {
			if strings.Contains(r, `linked to rogue agent 203.0.113.150 through registered as "KeyHarvester-7"`) {
				return
			}
		}
		t.Fatalf("no link reason: %v", a.Reasons)
	}
	t.Fatal("linked source not analyzed")
}
