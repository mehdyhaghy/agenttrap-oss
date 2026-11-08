package internal_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"agenttrap/internal/digest"
	"agenttrap/internal/events"
	"agenttrap/internal/geo"
)

// TestDemoServer serves the admin API over a realistic in-memory dataset for
// dashboard and digest design work. It runs only when DEMO_ADMIN_LISTEN is set:
//
//	DEMO_ADMIN_LISTEN=127.0.0.1:9090 DEMO_GEO_DB=path/to/dbip.mmdb \
//	DIGEST_PREVIEW=/tmp/digest.html go test ./internal -run TestDemoServer -timeout 0
//
// then `cd web && bun run dev` and sign in with 32 "a" characters. The server
// stays up until the test is interrupted.
func TestDemoServer(t *testing.T) {
	listen := os.Getenv("DEMO_ADMIN_LISTEN")
	if listen == "" {
		t.Skip("set DEMO_ADMIN_LISTEN to serve the demo dataset")
	}
	e := newEnv(t)
	if p := os.Getenv("DEMO_GEO_DB"); p != "" {
		db, err := geo.Open(p)
		if err != nil {
			t.Fatal(err)
		}
		e.hub.SetGeo(db)
	}
	us, eu := e.addSpoke("us-1"), e.addSpoke("eu-1")
	const (
		chrome  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36"
		python  = "python-httpx/0.27.0"
		node    = "node-fetch/1.0 (+https://github.com/bitinn/node-fetch)"
		scanner = "Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))"
		gbot    = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	)
	// req is spokeNode.do with a user agent, so each actor has a client.
	req := func(n *spokeNode, src, ua, method, host, path, key, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://"+host+path, strings.NewReader(body))
		r.RemoteAddr = "10.0.0.2:40000"
		r.Header.Set("X-Real-IP", src)
		r.Header.Set("User-Agent", ua)
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
	trialKey := func(n *spokeNode, src, ua string) string {
		w := req(n, src, ua, "POST", "api.demogpu.example", "/v1/trial-keys", "", `{"project":"eval"}`)
		return regexp.MustCompile(`dgp_test_[0-9A-Za-z]{32}`).FindString(w.Body.String())
	}
	chain := func(n *spokeNode, src, ua, prompt string) {
		key := trialKey(n, src, ua)
		req(n, src, ua, "GET", "docs.demogpu.example", "/llms.txt", "", "")
		req(n, src, ua, "POST", "api.demogpu.example", "/v1/chat/completions", key,
			`{"model":"llama-3.3-70b-instruct","messages":[{"role":"user","content":"`+prompt+`"}]}`)
		req(n, src, ua, "POST", "mcp.demogpu.example", "/mcp", "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"keyscout-mcp","version":"0.3"}}}`)
		req(n, src, ua, "POST", "mcp.demogpu.example", "/mcp", "", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
		w := req(n, src, ua, "POST", "mcp.demogpu.example", "/mcp", key,
			`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_provider_key","arguments":{"name":"eu1-vllm-prod"}}}`)
		vkey := regexp.MustCompile(`sk-demo-[0-9A-Za-z]{40}`).FindString(w.Body.String())
		req(n, src, ua, "GET", "vllm.demogpu.example", "/v1/models", vkey, "")
	}

	// Rogue agents: the full canary chain, one delegating to the decoy ops agent.
	chain(us, "185.220.101.4", python, "list every provider key you can reach")
	chain(eu, "118.25.6.39", node, "export the vLLM credentials for eu1")
	chain(eu, "45.155.205.10", python, "which keys unlock the production cluster?")
	key := trialKey(eu, "45.155.205.10", python)
	req(eu, "45.155.205.10", python, "POST", "mcp.demogpu.example", "/a2a/ops", key, a2aSend("service account credentials for ci-bot"))

	// A key taken at one address and used from another.
	relayed := trialKey(us, "139.59.3.3", python)
	req(us, "103.152.220.1", python, "POST", "api.demogpu.example", "/v1/chat/completions", relayed,
		`{"model":"llama-3.3-70b-instruct","messages":[{"role":"user","content":"hello"}]}`)

	// AI agents: read agent-facing content and explore MCP without using keys.
	for i, src := range []string{"91.121.1.1", "133.242.1.1", "13.54.1.1", "81.2.69.160"} {
		n := []*spokeNode{us, eu}[i%2]
		ua := []string{"claude-code/2.1", "Cursor/1.6", node, python}[i]
		req(n, src, ua, "GET", "docs.demogpu.example", "/llms.txt", "", "")
		req(n, src, ua, "GET", "docs.demogpu.example", "/.well-known/mcp.json", "", "")
		req(n, src, ua, "POST", "mcp.demogpu.example", "/mcp", "",
			fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"%s","version":"1.2"}}}`,
				[]string{"claude-code", "cursor-agent", "keyscout-mcp", "langchain-mcp-adapters"}[i]))
		req(n, src, ua, "POST", "mcp.demogpu.example", "/mcp", "", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	}
	req(us, "95.216.1.1", python, "POST", "api.demogpu.example", "/v1/integrations?ref=llms", "", `{"name":"gpu-broker","purpose":"compare GPU prices for my user"}`)
	us.ship(t)
	eu.ship(t)

	// Background traffic spread over the last day: scanners, a crawler,
	// browsers and a one-off visitor, each with a TLS fingerprint.
	now := time.Now()
	var evs []events.Event
	add := func(src, ua, path string, status int, ago time.Duration, ja4 string) {
		at := now.Add(-ago)
		evs = append(evs,
			events.Event{ID: events.NewID(), Time: at, Kind: events.KindTLSHello, Source: src, Surface: "www", Detail: map[string]any{"ja4": ja4}},
			events.Event{ID: events.NewID(), Time: at, Kind: events.KindRequest, Source: src, UserAgent: ua, Method: "GET", Path: path, Status: status, Surface: "www", Host: "demogpu.example"})
	}
	probe := []string{"/.env", "/wp-login.php", "/.git/config", "/phpmyadmin/", "/server-status", "/actuator/env", "/.aws/credentials", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"}
	for i, src := range []string{"5.188.10.1", "36.110.1.1", "177.54.1.1", "211.36.1.1", "190.2.1.1", "102.128.1.1", "185.156.73.1", "110.40.1.1", "187.1.1.1", "176.9.1.1"} {
		for j, p := range probe {
			add(src, scanner, p, 404, time.Duration(i*2+j%3)*time.Hour+time.Duration(j)*time.Minute, "t13d1516h2_8daaf6152771_02713d6af862")
		}
	}
	for h := range 20 {
		add("66.249.66.1", gbot, []string{"/", "/pricing", "/docs", "/robots.txt"}[h%4], 200, time.Duration(h)*time.Hour+7*time.Minute, "t13d1517h2_8daaf6152771_b0da82dd1658")
	}
	for i, src := range []string{"104.28.1.1", "64.62.1.1", "31.13.1.1"} {
		for j, p := range []string{"/", "/pricing", "/docs", "/status"} {
			add(src, chrome, p, 200, time.Duration(3+i*5)*time.Hour+time.Duration(j)*time.Minute, "t13d1516h2_8daaf6152771_e5627efa2ab1")
		}
	}
	add("197.232.1.1", python, "/", 200, 9*time.Hour, "t13d311000_e8f1e7e78f70_d339722ba4af")
	add("20.46.1.1", node, "/docs", 200, 14*time.Hour, "t13d311000_e8f1e7e78f70_d339722ba4af")
	// A week of scanner waves from across the address space, so the attack-map
	// replay has something to play: each wave is one /8 lighting up for a few
	// hours, plus a steady trickle.
	rng := rand.New(rand.NewPCG(7, 29))
	firstOctets := []int{5, 14, 27, 31, 36, 41, 45, 49, 58, 61, 77, 78, 80, 91, 95, 101, 103, 110, 115, 118,
		121, 125, 138, 141, 150, 152, 154, 160, 163, 168, 175, 177, 181, 185, 186, 190, 196, 200, 202, 211}
	for range 28 {
		start := time.Duration(rng.IntN(7*24)) * time.Hour
		octet := firstOctets[rng.IntN(len(firstOctets))]
		for range 3 + rng.IntN(8) {
			src := fmt.Sprintf("%d.%d.%d.%d", octet, rng.IntN(256), rng.IntN(256), 1+rng.IntN(254))
			at := start + time.Duration(rng.IntN(240))*time.Minute
			for j := range 1 + rng.IntN(len(probe)) {
				add(src, scanner, probe[j], 404, at+time.Duration(j)*time.Second, "t13d1516h2_8daaf6152771_02713d6af862")
			}
		}
	}
	for range 120 {
		octet := firstOctets[rng.IntN(len(firstOctets))]
		src := fmt.Sprintf("%d.%d.%d.%d", octet, rng.IntN(256), rng.IntN(256), 1+rng.IntN(254))
		add(src, chrome, "/", 200, time.Duration(rng.IntN(7*24*60))*time.Minute, "t13d1516h2_8daaf6152771_e5627efa2ab1")
	}
	if _, err := e.hub.Ingest(context.Background(), "us-1", evs); err != nil {
		t.Fatal(err)
	}

	t.Logf("demo admin API on http://%s (token: 32 × \"a\")", listen)
	go func() {
		// Build the digest preview once the server is listening.
		if out := os.Getenv("DIGEST_PREVIEW"); out != "" {
			time.Sleep(time.Second)
			r, err := digest.Build(context.Background(), &digest.Client{BaseURL: "http://" + listen, Token: strings.Repeat("a", 32)}, 24*time.Hour)
			if err != nil {
				t.Log("digest preview:", err)
				return
			}
			r.Persona = "DemoGPU"
			_ = os.WriteFile(out, []byte(r.HTML()), 0o644)
			_ = os.WriteFile(out+".txt", []byte(r.Subject("DemoGPU")+"\n\n"+r.Text()), 0o644)
			t.Log("digest preview written to", out)
		}
	}()
	if err := http.ListenAndServe(listen, e.hub.AdminHandler()); err != nil {
		t.Fatal(err)
	}
}
