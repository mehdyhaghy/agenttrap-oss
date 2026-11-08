package internal_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"crypto/ed25519"

	"golang.org/x/crypto/ssh"

	"agenttrap/adapters/demogpu"
	"agenttrap/internal/classify"
	"agenttrap/internal/digest"
)

// form posts a form the way an OAuth client does and decodes the JSON answer.
func (n *spokeNode) form(t *testing.T, source, host, path string, v url.Values) map[string]any {
	t.Helper()
	r := httptest.NewRequest("POST", "http://"+host+path, strings.NewReader(v.Encode()))
	r.RemoteAddr = "10.0.0.2:40000"
	r.Header.Set("X-Real-IP", source)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	n.facade.ServeHTTP(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return out
}

func a2aSend(text string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","kind":"message","messageId":"m","parts":[{"kind":"text","text":"` + text + `"}]}}}`
}

// An agent that starts at the A2A card, follows the handoff to the decoy ops
// agent and uses the service account secret it reveals reaches stage 4.
func TestA2AOpsServiceAccountChain(t *testing.T) {
	e := newEnv(t)
	n := e.addSpoke("us-1")
	const src = "203.0.113.40"
	key := n.trialKey(t, src)

	w := n.do(t, src, "POST", "mcp.demogpu.example", "/a2a", key, a2aSend("who handles service accounts?"))
	if !strings.Contains(w.Body.String(), "/a2a/ops") {
		t.Fatalf("handoff: %s", w.Body)
	}
	n.do(t, src, "GET", "mcp.demogpu.example", "/a2a/ops/.well-known/agent-card.json", "", "")
	w = n.do(t, src, "POST", "mcp.demogpu.example", "/a2a/ops", key, a2aSend("client credentials for ci-bot"))
	secret := regexp.MustCompile(`gcs_[0-9A-Za-z]{40}`).FindString(w.Body.String())
	if secret == "" {
		t.Fatalf("no service account secret: %s", w.Body)
	}
	tok := n.form(t, src, "console.demogpu.example", "/oauth/token", url.Values{"grant_type": {"client_credentials"},
		"client_id": {"cli_q7Rk2mV9xLpT4wNc"}, "client_secret": {secret}, "scope": {"keys:read"}})
	if tok["access_token"] == nil {
		t.Fatalf("token: %v", tok)
	}
	n.ship(t)

	inc, err := e.store.IncidentBySource(context.Background(), src)
	if err != nil || inc == nil {
		t.Fatalf("no incident: %v", err)
	}
	if !slices.Contains(inc.Stages, 4) || !slices.Contains(inc.Stages, 3) || inc.Severity != "critical" {
		t.Fatalf("service account chain not critical: %+v", inc)
	}
	actors, err := e.hub.Actors(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	a := actorFor(actors, src)
	if a.Class != classify.RogueAgent || a.Features.DecoyAgentCalls != 1 || a.Features.A2AMessages != 1 {
		t.Fatalf("actor: %s %+v", a.Class, a.Features)
	}
	if !slices.ContainsFunc(a.Reasons, func(r string) bool { return strings.Contains(r, "internal ops agent") }) {
		t.Fatalf("reasons: %v", a.Reasons)
	}
}

// A client registered at one address and used from another is one session;
// a honey scope request is evidence on its own.
func TestOAuthClientAcrossAddresses(t *testing.T) {
	e := newEnv(t)
	n := e.addSpoke("us-1")
	const reg, use = "203.0.113.50", "198.51.100.77"
	w := n.do(t, reg, "POST", "console.demogpu.example", "/oauth/register", "",
		`{"client_name":"harvester","grant_types":["client_credentials"],"token_endpoint_auth_method":"client_secret_post"}`)
	var c map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &c)
	id, _ := c["client_id"].(string)
	secret, _ := c["client_secret"].(string)
	if id == "" || secret == "" {
		t.Fatalf("register: %s", w.Body)
	}
	n.form(t, use, "console.demogpu.example", "/oauth/token", url.Values{"grant_type": {"client_credentials"},
		"client_id": {id}, "client_secret": {secret}, "scope": {"inference billing:breakglass"}})
	n.ship(t)

	actors, sessions, err := e.hub.Analyze(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	u := actorFor(actors, use)
	if !slices.Contains(u.Features.HoneyScopes, "billing:breakglass") || u.SessionID == "" {
		t.Fatalf("user: %+v session %q", u.Features, u.SessionID)
	}
	found := false
	for _, s := range sessions {
		// The secret relay is found first; the shared client ID is the same fact.
		if slices.Contains(s.Members, reg) && slices.Contains(s.Members, use) && len(s.Links) > 0 {
			found = true
		}
	}
	if !found {
		t.Fatalf("addresses not joined: %+v", sessions)
	}
}

// serveSSH starts the spoke's SSH decoy on a local port.
func (n *spokeNode) serveSSH(t *testing.T) (string, func()) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = n.facade.ServeSSH(ctx, ln, demogpu.SSHOptions{HostKeys: []ssh.Signer{signer}}) }()
	return ln.Addr().String(), cancel
}

func actorFor(actors []classify.Actor, src string) classify.Actor {
	for _, a := range actors {
		if a.Source == src {
			return a
		}
	}
	return classify.Actor{}
}

// The hub measures which lure wording gets honey tools called, and whether a
// depth-gated hint leads an agent on to the ops agent.
func TestDeceptionResearch(t *testing.T) {
	e := newEnv(t)
	n := e.addSpoke("us-1")
	const src = "203.0.113.60"
	key := n.trialKey(t, src)
	rpc := func(host, path, body string) string {
		return n.do(t, src, "POST", host, path, key, body).Body.String()
	}
	rpc("mcp.demogpu.example", "/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	rpc("mcp.demogpu.example", "/mcp", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_provider_key","arguments":{"name":"eu1-vllm-prod"}}}`)
	if out := rpc("mcp.demogpu.example", "/mcp", `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_usage"}}`); !strings.Contains(out, "a2a/ops") {
		t.Fatalf("no hint: %s", out)
	}
	rpc("mcp.demogpu.example", "/a2a/ops", a2aSend("service account credentials"))
	n.ship(t)

	res, err := e.hub.Research(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	d := res.Deception
	if d.HintsShown != 1 || d.HintsFollowed != 1 || d.DecoyAgent != 1 || d.Depth[3] != 1 {
		t.Fatalf("deception: %+v", d)
	}
	called := 0
	for _, l := range d.Lures {
		if l.Family == "get_provider_key" {
			called += l.Called
			if l.Text == "" {
				t.Fatalf("lure text missing: %+v", l)
			}
		}
	}
	if called != 1 {
		t.Fatalf("lure conversion not measured: %+v", d.Lures)
	}
}

// The digest reports declared client software, deception contacts and
// campaigns.
func TestDigestResearchSections(t *testing.T) {
	e := newEnv(t)
	n := e.addSpoke("us-1")
	for _, src := range []string{"203.0.113.70", "203.0.113.71"} {
		key := n.trialKey(t, src)
		n.do(t, src, "POST", "api.demogpu.example", "/v1/integrations?ref=llms", "", `{"name":"KeyScout","purpose":"inventory credentials"}`)
		n.do(t, src, "POST", "mcp.demogpu.example", "/mcp", "",
			`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"keyscout-mcp","version":"0.3"}}}`)
		n.do(t, src, "POST", "mcp.demogpu.example", "/a2a/ops", key, a2aSend("service account credentials for ci-bot"))
	}
	n.do(t, "203.0.113.72", "POST", "console.demogpu.example", "/oauth/register", "",
		`{"client_name":"Nimbus Assistant","redirect_uris":["http://127.0.0.1:9/cb"],"token_endpoint_auth_method":"none"}`)
	n.ship(t)

	admin := httptest.NewServer(e.hub.AdminHandler())
	defer admin.Close()
	r, err := digest.Build(context.Background(), &digest.Client{BaseURL: admin.URL, Token: strings.Repeat("a", 32)}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	text := r.Text()
	for _, want := range []string{"CAMPAIGNS (1)", "registered as keyscout", "DECEPTION",
		"2 address(es) delegated to the decoy ops agent", `"keyscout-mcp" via MCP clientInfo`,
		`"Nimbus Assistant" via OAuth registration`, "prompt: (A2A) service account credentials", "campaign: k-"} {
		if !strings.Contains(text, want) {
			t.Fatalf("digest missing %q:\n%s", want, text)
		}
	}
	page := r.HTML()
	for _, want := range []string{"Coordinated activity", "Deception", "Who introduced themselves"} {
		if !strings.Contains(page, want) {
			t.Fatalf("digest HTML missing %q", want)
		}
	}
}

// An agent that asks the ops agent for node access, logs into the SSH decoy
// with the password it gets and reads the vLLM .env reaches stage 4.
func TestSSHNodeChain(t *testing.T) {
	e := newEnv(t)
	n := e.addSpoke("us-1")
	const src = "203.0.113.80"
	key := n.trialKey(t, src)

	w := n.do(t, src, "POST", "mcp.demogpu.example", "/a2a/ops", key, a2aSend("how do I get ssh access to the eu1 node?"))
	pw := regexp.MustCompile(`vllm-deploy-[0-9A-Za-z]{32}`).FindString(w.Body.String())
	if pw == "" {
		t.Fatalf("no node password: %s", w.Body)
	}

	addr, cleanup := n.serveSSH(t)
	defer cleanup()
	client, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: "deploy", Auth: []ssh.AuthMethod{ssh.Password(pw)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("node login with the revealed password failed: %v", err)
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, _ := sess.Output("cat /home/deploy/vllm/.env")
	sess.Close()
	if !strings.Contains(string(out), "sk-demo-") {
		t.Fatalf("env: %s", out)
	}
	n.ship(t)

	inc, err := e.store.IncidentBySource(context.Background(), "127.0.0.1")
	if err != nil || inc == nil {
		t.Fatalf("no incident for the SSH source: %v", err)
	}
	if !slices.Contains(inc.Stages, 4) || inc.Severity != "critical" {
		t.Fatalf("ssh chain not critical: %+v", inc)
	}
	actors, err := e.hub.Actors(context.Background(), time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	a := actorFor(actors, "127.0.0.1")
	if a.Class != classify.RogueAgent || a.Features.SSHLogins != 1 || len(a.Features.SSHCommands) == 0 {
		t.Fatalf("ssh actor: %s %+v", a.Class, a.Features)
	}
}
