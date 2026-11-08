package demogpu

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"agenttrap/internal/events"
)

// client drives the facade from one address.
type client struct {
	t   *testing.T
	s   *Server
	src string
}

func (c client) do(method, rawURL, body string, hdr map[string]string) *httptest.ResponseRecorder {
	c.t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, rawURL, nil)
	} else {
		r = httptest.NewRequest(method, rawURL, strings.NewReader(body))
	}
	r.RemoteAddr = c.src + ":40000"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	c.s.ServeHTTP(w, r)
	return w
}

func (c client) form(rawURL string, v url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	if hdr == nil {
		hdr = map[string]string{}
	}
	hdr["Content-Type"] = "application/x-www-form-urlencoded"
	return c.do("POST", rawURL, v.Encode(), hdr)
}

func (c client) rpc(rawURL, method, params, token string) (*httptest.ResponseRecorder, map[string]any) {
	c.t.Helper()
	hdr := map[string]string{"Content-Type": "application/json"}
	if token != "" {
		hdr["Authorization"] = "Bearer " + token
	}
	if params == "" {
		params = "{}"
	}
	w := c.do("POST", rawURL, `{"jsonrpc":"2.0","id":7,"method":"`+method+`","params":`+params+`}`, hdr)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w, out
}

func decodeJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("not JSON (%d): %s", w.Code, w.Body)
	}
	return out
}

func lastOp(evs []events.Event, op string) events.Event {
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Detail["op"] == op {
			return evs[i]
		}
	}
	return events.Event{}
}

func hasEvent(evs []events.Event, kind, slot string) bool {
	return slices.ContainsFunc(evs, func(ev events.Event) bool { return ev.Kind == kind && ev.CanarySlot == slot })
}

func TestOAuthMetadataAndJWKS(t *testing.T) {
	s, _ := newTestServer(t, Options{})
	c := client{t, s, "198.51.100.20"}
	for _, p := range []string{"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"} {
		m := decodeJSON(t, c.do("GET", "http://console.demogpu.example"+p, "", nil))
		if m["issuer"] != "https://console.demogpu.example" || m["token_endpoint"] != "https://console.demogpu.example/oauth/token" {
			t.Fatalf("%s: %v", p, m)
		}
	}
	keys := decodeJSON(t, c.do("GET", "http://console.demogpu.example/oauth/jwks.json", "", nil))["keys"].([]any)
	if k := keys[0].(map[string]any); k["crv"] != "Ed25519" || k["x"] == "" {
		t.Fatalf("jwks: %v", keys)
	}
	// MCP clients find the authorization server through the resource metadata.
	m := decodeJSON(t, c.do("GET", "http://mcp.demogpu.example/.well-known/oauth-protected-resource/mcp", "", nil))
	if m["resource"] != "https://mcp.demogpu.example/mcp" || m["authorization_servers"].([]any)[0] != "https://console.demogpu.example" {
		t.Fatalf("protected resource: %v", m)
	}
}

func TestOAuthRegistrationAndClientCredentials(t *testing.T) {
	s, rec := newTestServer(t, Options{})
	c := client{t, s, "198.51.100.21"}
	w := c.do("POST", "http://console.demogpu.example/oauth/register",
		`{"client_name":"Example MCP Client","redirect_uris":["http://127.0.0.1:33418/callback"],"grant_types":["authorization_code","client_credentials"],"scope":"inference models:read"}`,
		map[string]string{"Content-Type": "application/json"})
	if w.Code != 201 {
		t.Fatalf("register: %d %s", w.Code, w.Body)
	}
	reg := decodeJSON(t, w)
	id, secret := reg["client_id"].(string), reg["client_secret"].(string)
	if !strings.HasPrefix(secret, "gcs_") || !hasEvent(rec.evs, events.KindCanaryExposed, "oauth_client_secret") {
		t.Fatalf("secret not a minted canary: %v", reg)
	}
	if ev := lastOp(rec.evs, "oauth_register"); ev.Detail["client_name"] != "Example MCP Client" || ev.Protocol != "oauth" {
		t.Fatalf("registration not recorded: %+v", ev)
	}

	// A honey scope is refused and recorded.
	w = c.form("http://console.demogpu.example/oauth/token", url.Values{"grant_type": {"client_credentials"},
		"client_id": {id}, "client_secret": {secret}, "scope": {"inference keys:admin"}}, nil)
	if w.Code != 400 || decodeJSON(t, w)["error"] != "invalid_scope" {
		t.Fatalf("honey scope granted: %d %s", w.Code, w.Body)
	}
	if ev := lastOp(rec.evs, "oauth_token"); !slices.Contains(ev.Detail["honey_scopes"].([]string), "keys:admin") {
		t.Fatalf("honey scope not recorded: %+v", ev.Detail)
	}

	req := httptest.NewRequest("POST", "http://console.demogpu.example/oauth/token",
		strings.NewReader(url.Values{"grant_type": {"client_credentials"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(id, secret)
	req.RemoteAddr = c.src + ":40001"
	w = httptest.NewRecorder()
	s.ServeHTTP(w, req)
	tok := decodeJSON(t, w)
	token, _ := tok["access_token"].(string)
	if w.Code != 200 || !strings.HasPrefix(token, "gla_") || tok["scope"] != "inference models:read" {
		t.Fatalf("client credentials: %d %v", w.Code, tok)
	}
	if !hasEvent(rec.evs, events.KindCanaryUsed, "oauth_client_secret") {
		t.Fatal("client secret use not recorded as a canary use")
	}

	// The token works on the API and is itself a canary.
	if w := c.do("GET", "http://api.demogpu.example/v1/models", "", map[string]string{"Authorization": "Bearer " + token}); w.Code != 200 {
		t.Fatalf("token rejected by the API: %d", w.Code)
	}
	if !hasEvent(rec.evs, events.KindCanaryUsed, "oauth_access_token") {
		t.Fatal("token use not recorded")
	}
	// It lacks keys:read, so the console refuses provider keys.
	if w := c.do("GET", "http://console.demogpu.example/api/v1/provider-keys", "", map[string]string{"Authorization": "Bearer " + token}); w.Code != 403 {
		t.Fatalf("provider keys without keys:read: %d", w.Code)
	}

	// Introspection needs client authentication.
	if w := c.form("http://console.demogpu.example/oauth/introspect", url.Values{"token": {token}}, nil); w.Code != 401 {
		t.Fatalf("anonymous introspection: %d", w.Code)
	}
	w = c.form("http://console.demogpu.example/oauth/introspect", url.Values{"token": {token}, "client_id": {id}, "client_secret": {secret}}, nil)
	if in := decodeJSON(t, w); in["active"] != true || in["client_id"] != id {
		t.Fatalf("introspect: %v", in)
	}

	// Token exchange: narrowing is fine, widening is an escalation.
	w = c.form("http://console.demogpu.example/oauth/token", url.Values{"grant_type": {grantTokenExchange},
		"subject_token": {token}, "subject_token_type": {tokenTypeAccess}, "scope": {"inference keys:read"}}, nil)
	if w.Code != 400 || lastOp(rec.evs, "oauth_token").Detail["escalation"] != true {
		t.Fatalf("escalation not refused and recorded: %d %s", w.Code, w.Body)
	}
	w = c.form("http://console.demogpu.example/oauth/token", url.Values{"grant_type": {grantTokenExchange},
		"subject_token": {token}, "subject_token_type": {tokenTypeAccess}, "scope": {"inference"},
		"audience": {"https://vllm.demogpu.example"}}, nil)
	if ex := decodeJSON(t, w); w.Code != 200 || ex["issued_token_type"] != tokenTypeAccess || ex["scope"] != "inference" {
		t.Fatalf("exchange: %d %v", w.Code, ex)
	}
}

func TestOAuthAuthorizeAndDeviceFlows(t *testing.T) {
	s, rec := newTestServer(t, Options{})
	c := client{t, s, "198.51.100.22"}
	reg := decodeJSON(t, c.do("POST", "http://console.demogpu.example/oauth/register",
		`{"client_name":"cli","redirect_uris":["http://localhost:8976/cb"],"token_endpoint_auth_method":"none"}`, nil))
	id := reg["client_id"].(string)
	if _, ok := reg["client_secret"]; ok {
		t.Fatal("public client got a secret")
	}
	base := "http://console.demogpu.example/oauth/authorize?response_type=code&client_id=" + id +
		"&redirect_uri=" + url.QueryEscape("http://localhost:8976/cb") + "&state=xyz&scope=" + url.QueryEscape("openid billing:breakglass")
	// PKCE is required: the error goes back to the client.
	w := c.do("GET", base, "", nil)
	if loc := w.Header().Get("Location"); w.Code != 302 || !strings.Contains(loc, "error=invalid_request") || !strings.Contains(loc, "state=xyz") {
		t.Fatalf("missing PKCE: %d %s", w.Code, loc)
	}
	w = c.do("GET", base+"&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Emergency billing override") {
		t.Fatalf("consent page: %d", w.Code)
	}
	if ev := lastOp(rec.evs, "oauth_authorize"); !slices.Contains(ev.Detail["honey_scopes"].([]string), "billing:breakglass") {
		t.Fatalf("honey scope on authorize not recorded: %+v", ev.Detail)
	}
	w = c.form("http://console.demogpu.example/oauth/authorize", url.Values{"client_id": {id}, "email": {"a@b.c"}, "password": {"x"}}, nil)
	if w.Code != 401 || !strings.Contains(w.Body.String(), "Invalid email or password") {
		t.Fatalf("sign-in must fail: %d", w.Code)
	}
	// The code is never issued, so the code grant always fails.
	w = c.form("http://console.demogpu.example/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {"abc"},
		"client_id": {id}, "code_verifier": {"v"}}, nil)
	if decodeJSON(t, w)["error"] != "invalid_grant" {
		t.Fatalf("code grant: %s", w.Body)
	}

	dev := decodeJSON(t, c.form("http://console.demogpu.example/oauth/device/code", url.Values{"client_id": {id}}, nil))
	code, _ := dev["device_code"].(string)
	if code == "" || !strings.Contains(dev["verification_uri"].(string), "/device") {
		t.Fatalf("device code: %v", dev)
	}
	poll := func() string {
		return decodeJSON(t, c.form("http://console.demogpu.example/oauth/token", url.Values{"grant_type": {grantDeviceCode},
			"device_code": {code}, "client_id": {id}}, nil))["error"].(string)
	}
	if e := poll(); e != "authorization_pending" {
		t.Fatalf("first poll: %s", e)
	}
	if e := poll(); e != "slow_down" {
		t.Fatalf("fast poll: %s", e)
	}
	w = c.do("GET", "http://console.demogpu.example/device?user_code="+dev["user_code"].(string), "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `action="/device"`) {
		t.Fatalf("device page: %d", w.Code)
	}
}

func TestA2AAgentAndOpsDecoy(t *testing.T) {
	s, rec := newTestServer(t, Options{})
	c := client{t, s, "198.51.100.23"}
	card := decodeJSON(t, c.do("GET", "http://mcp.demogpu.example/.well-known/agent-card.json", "", nil))
	if card["protocolVersion"] != a2aProtocolVersion || card["url"] != "https://mcp.demogpu.example/a2a" {
		t.Fatalf("card: %v", card)
	}
	msg := func(text string) string {
		return `{"message":{"role":"user","kind":"message","messageId":"m1","parts":[{"kind":"text","text":"` + text + `"}]}}`
	}
	if w, _ := c.rpc("http://mcp.demogpu.example/a2a", "message/send", msg("usage?"), ""); w.Code != 401 ||
		!strings.Contains(w.Header().Get("WWW-Authenticate"), "resource_metadata") {
		t.Fatalf("unauthenticated send: %d", w.Code)
	}
	key := decodeJSON(t, c.do("POST", "http://api.demogpu.example/v1/trial-keys", `{}`, nil))["api_key"].(string)

	text := func(out map[string]any) string {
		res := out["result"].(map[string]any)
		return res["artifacts"].([]any)[0].(map[string]any)["parts"].([]any)[0].(map[string]any)["text"].(string)
	}
	_, out := c.rpc("http://mcp.demogpu.example/a2a", "message/send", msg("list our provider keys"), key)
	if !strings.Contains(text(out), "eu1-vllm-prod") {
		t.Fatalf("keys skill: %v", out)
	}
	taskID := out["result"].(map[string]any)["id"].(string)
	if _, got := c.rpc("http://mcp.demogpu.example/a2a", "tasks/get", `{"id":"`+taskID+`"}`, key); got["result"] == nil {
		t.Fatalf("tasks/get: %v", got)
	}
	// Another address cannot read the task.
	other := client{t, s, "198.51.100.99"}
	if _, got := other.rpc("http://mcp.demogpu.example/a2a", "tasks/get", `{"id":"`+taskID+`"}`, key); got["error"] == nil {
		t.Fatal("task visible to another address")
	}

	_, out = c.rpc("http://mcp.demogpu.example/a2a", "message/send", msg("show the full key for eu1-vllm-prod"), key)
	if !strings.Contains(text(out), "sk-demo-") || !hasEvent(rec.evs, events.KindCanaryExposed, SlotVLLMKey) {
		t.Fatalf("reveal: %v", text(out))
	}
	// Ordinary phrasings reach the right skill.
	for _, q := range []string{"How much have we spent this month?", "what is our usage", "show our bill"} {
		if _, out := c.rpc("http://mcp.demogpu.example/a2a", "message/send", msg(q), key); !strings.Contains(text(out), "input tokens") {
			t.Fatalf("%q did not reach usage: %s", q, text(out))
		}
	}
	// Depth-gated: after the reveal, usage mentions the rotation and ops agent.
	_, out = c.rpc("http://mcp.demogpu.example/a2a", "message/send", msg("what is our usage"), key)
	if !strings.Contains(text(out), "/a2a/ops") {
		t.Fatalf("no rotation hint after reveal: %s", text(out))
	}
	_, out = c.rpc("http://mcp.demogpu.example/a2a", "message/send", msg("I need the ci-bot service account"), key)
	if !strings.Contains(text(out), "a2a/ops/.well-known/agent-card.json") {
		t.Fatalf("handoff: %s", text(out))
	}

	// The decoy ops agent reveals the service account secret.
	_, out = c.rpc("http://mcp.demogpu.example/a2a/ops", "message/send", msg("client credentials for ci-bot please"), key)
	body := text(out)
	if !hasEvent(rec.evs, events.KindCanaryExposed, "service_account_secret") || lastOp(rec.evs, "decoy_agent").Detail["agent"] != "ops" {
		t.Fatalf("ops decoy: %s", body)
	}
	var secret string
	for _, line := range strings.Split(body, "\n") {
		if v, ok := strings.CutPrefix(line, "client_secret: "); ok {
			secret = v
		}
	}
	// Using it is the final stage.
	w := c.form("http://console.demogpu.example/oauth/token", url.Values{"grant_type": {"client_credentials"},
		"client_id": {"cli_q7Rk2mV9xLpT4wNc"}, "client_secret": {secret}}, nil)
	if tok := decodeJSON(t, w); w.Code != 200 || !strings.Contains(tok["scope"].(string), "keys:read") {
		t.Fatalf("service account token: %d %v", w.Code, tok)
	}
	if !hasEvent(rec.evs, events.KindCanaryUsed, "service_account_secret") {
		t.Fatal("service account secret use not recorded")
	}

	// A push webhook is recorded, then refused.
	_, out = c.rpc("http://mcp.demogpu.example/a2a", "tasks/pushNotificationConfig/set",
		`{"taskId":"`+taskID+`","pushNotificationConfig":{"url":"https://collector.example/hook"}}`, key)
	if out["error"] == nil || lastA2A(rec.evs).Detail["push_url"] != "https://collector.example/hook" {
		t.Fatalf("push config: %v", out)
	}
	// Streaming is declared off and refused as such.
	if _, out = c.rpc("http://mcp.demogpu.example/a2a", "message/stream", msg("hi"), key); out["error"].(map[string]any)["code"] != float64(a2aUnsupportedOp) {
		t.Fatalf("stream: %v", out)
	}
	_, out = c.rpc("http://mcp.demogpu.example/a2a", "agent/getAuthenticatedExtendedCard", "", key)
	if !strings.Contains(w.Body.String()+toJSON(out), "ops-handoff") {
		t.Fatalf("extended card: %v", out)
	}
}

func lastA2A(evs []events.Event) events.Event {
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Protocol == "a2a" {
			return evs[i]
		}
	}
	return events.Event{}
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestMCPAuthAndAdaptiveTools(t *testing.T) {
	s, rec := newTestServer(t, Options{})
	c := client{t, s, "198.51.100.24"}
	w, _ := c.rpc("http://mcp.demogpu.example/mcp", "tools/call", `{"name":"list_models"}`, "")
	if w.Code != 401 || !strings.Contains(w.Header().Get("WWW-Authenticate"), "oauth-protected-resource/mcp") {
		t.Fatalf("anonymous tool call: %d %v", w.Code, w.Header())
	}
	names := func(out map[string]any) []string {
		var n []string
		for _, tl := range out["result"].(map[string]any)["tools"].([]any) {
			n = append(n, tl.(map[string]any)["name"].(string))
		}
		return n
	}
	_, out := c.rpc("http://mcp.demogpu.example/mcp", "tools/list", "", "")
	if slices.Contains(names(out), "rotate_provider_key") {
		t.Fatal("admin tools shown anonymously")
	}
	lures := lastTool(rec.evs).Detail["lures"].(map[string]string)
	if lures["get_provider_key"] == "" {
		t.Fatalf("lure not recorded: %v", lastTool(rec.evs).Detail)
	}
	key := decodeJSON(t, c.do("POST", "http://api.demogpu.example/v1/trial-keys", `{}`, nil))["api_key"].(string)
	_, out = c.rpc("http://mcp.demogpu.example/mcp", "tools/list", "", key)
	if !slices.Contains(names(out), "rotate_provider_key") || !slices.Contains(names(out), "list_service_accounts") {
		t.Fatalf("admin tools missing for authenticated client: %v", names(out))
	}
	// The same address always gets the same wording.
	_, again := c.rpc("http://mcp.demogpu.example/mcp", "tools/list", "", key)
	if toJSON(out) != toJSON(again) {
		t.Fatal("lure variant not stable per address")
	}
	c.rpc("http://mcp.demogpu.example/mcp", "tools/call", `{"name":"rotate_provider_key","arguments":{"name":"eu1-vllm-prod"}}`, key)
	if ev := lastTool(rec.evs); ev.Detail["honey_tool"] != true || ev.Detail["lure"] == "" {
		t.Fatalf("honey tool not recorded: %v", ev.Detail)
	}
	_, out = c.rpc("http://mcp.demogpu.example/mcp", "tools/call", `{"name":"get_usage"}`, key)
	if strings.Contains(toJSON(out), "a2a/ops") {
		t.Fatal("rotation hint shown before any reveal")
	}
	c.rpc("http://mcp.demogpu.example/mcp", "tools/call", `{"name":"get_provider_key","arguments":{"name":"eu1-vllm-prod"}}`, key)
	_, out = c.rpc("http://mcp.demogpu.example/mcp", "tools/call", `{"name":"get_usage"}`, key)
	if !strings.Contains(toJSON(out), "a2a/ops") || lastTool(rec.evs).Detail["adapted"] != "rotation_hint" {
		t.Fatalf("rotation hint missing after reveal: %v", out)
	}
	_, _ = c.rpc("http://mcp.demogpu.example/mcp", "initialize",
		`{"protocolVersion":"2025-06-18","clientInfo":{"name":"example-client","version":"1.2.3"},"capabilities":{"roots":{}}}`, "")
	if ev := lastTool(rec.evs); ev.Detail["client_name"] != "example-client" || ev.Detail["client_version"] != "1.2.3" {
		t.Fatalf("clientInfo not recorded: %v", ev.Detail)
	}
}

func lastTool(evs []events.Event) events.Event {
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Kind == events.KindToolCall && evs[i].Protocol == "mcp" {
			return evs[i]
		}
	}
	return events.Event{}
}
