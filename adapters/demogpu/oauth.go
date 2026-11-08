package demogpu

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"agenttrap/internal/events"
	"agenttrap/internal/worldpack"
)

// The console is also DemoGPU's OAuth 2.1 / OpenID Connect authorization
// server. Every flow a client can start is served and recorded; none of them
// reaches a real account. Sign-in always fails, so authorization codes and
// device codes are never granted. Client credentials work for self-registered
// clients (whose secrets are per-registration canaries) and for the team's
// service account, whose secret only the decoy ops agent reveals. Access
// tokens are per-issue canaries too, so a token used anywhere names the grant
// that produced it.

const (
	grantAuthCode      = "authorization_code"
	grantRefresh       = "refresh_token"
	grantClientCreds   = "client_credentials"
	grantDeviceCode    = "urn:ietf:params:oauth:grant-type:device_code"
	grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	tokenTypeAccess    = "urn:ietf:params:oauth:token-type:access_token"

	tokenTTL  = time.Hour
	deviceTTL = 15 * time.Minute
	// maxOAuthState bounds each in-memory table; the oldest entries go first.
	maxOAuthState = 20000
)

// oauthState holds grants for this process. Losing it on restart is fine: a
// token or secret is still recognised as a canary by its MAC, and flows that
// never complete have nothing to lose.
type oauthState struct {
	mu      sync.Mutex
	clients map[string]*oauthClient
	tokens  map[string]*tokenGrant // access token -> grant
	devices map[string]*deviceGrant
}

type oauthClient struct {
	ID           string
	Name         string
	RedirectURIs []string
	Scopes       []string
	Created      time.Time
}

type tokenGrant struct {
	ClientID string
	Scopes   []string
	Audience string
	Subject  string // service account name, or the client ID
	Actor    string // delegated actor, from token exchange
	Expires  time.Time
}

type deviceGrant struct {
	ClientID string
	UserCode string
	Scopes   []string
	Expires  time.Time
	LastPoll time.Time
	Interval time.Duration
}

func newOAuthState() *oauthState {
	return &oauthState{clients: map[string]*oauthClient{}, tokens: map[string]*tokenGrant{}, devices: map[string]*deviceGrant{}}
}

// trim drops arbitrary entries once a table is full. Map iteration order is
// random, which is good enough for a bound that is rarely reached.
func trim[V any](m map[string]V) {
	for k := range m {
		if len(m) < maxOAuthState {
			return
		}
		delete(m, k)
	}
}

func (s *Server) issuer() string { return "https://console." + s.domain }

func (s *Server) oauthRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /.well-known/openid-configuration", s.oauthMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.oauthMetadata)
	mux.HandleFunc("GET /oauth/jwks.json", s.oauthJWKS)
	mux.HandleFunc("POST /oauth/register", s.oauthRegister)
	mux.HandleFunc("GET /oauth/authorize", s.oauthAuthorize)
	mux.HandleFunc("POST /oauth/authorize", s.oauthLogin)
	mux.HandleFunc("POST /oauth/token", s.oauthToken)
	mux.HandleFunc("POST /oauth/device/code", s.oauthDeviceCode)
	mux.HandleFunc("GET /device", s.devicePage)
	mux.HandleFunc("POST /device", s.oauthLogin)
	mux.HandleFunc("POST /oauth/introspect", s.oauthIntrospect)
	mux.HandleFunc("POST /oauth/revoke", s.oauthRevoke)
	mux.HandleFunc("GET /oauth/userinfo", s.oauthUserinfo)
	mux.HandleFunc("POST /oauth/userinfo", s.oauthUserinfo)
}

func (s *Server) oauthMetadata(w http.ResponseWriter, r *http.Request) {
	iss := s.issuer()
	var scopes []string
	for _, sc := range s.pack.OAuth.Scopes {
		scopes = append(scopes, sc.Name)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/oauth/authorize",
		"token_endpoint":                        iss + "/oauth/token",
		"registration_endpoint":                 iss + "/oauth/register",
		"jwks_uri":                              iss + "/oauth/jwks.json",
		"userinfo_endpoint":                     iss + "/oauth/userinfo",
		"introspection_endpoint":                iss + "/oauth/introspect",
		"revocation_endpoint":                   iss + "/oauth/revoke",
		"device_authorization_endpoint":         iss + "/oauth/device/code",
		"scopes_supported":                      scopes,
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{grantAuthCode, grantRefresh, grantClientCreds, grantDeviceCode, grantTokenExchange},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"EdDSA"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "name", "email", "email_verified", "team"},
		"service_documentation":                 "https://docs." + s.domain + "/",
	})
}

// signingKey is the persona's OIDC key. It is stable per spoke and never used
// to sign anything: no ID token is ever issued.
func (s *Server) signingKey() ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(s.canaries.Subkey("oidc-signing")).Public().(ed25519.PublicKey)
}

func (s *Server) oauthJWKS(w http.ResponseWriter, r *http.Request) {
	pub := s.signingKey()
	sum := sha256.Sum256(pub)
	writeJSON(w, http.StatusOK, map[string]any{"keys": []any{map[string]string{
		"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
		"kid": hex.EncodeToString(sum[:8]), "x": base64.RawURLEncoding.EncodeToString(pub),
	}}})
}

func oauthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Cache-Control", "no-store")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="demogpu"`)
	}
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// oauthEvent records one OAuth step as a tool call on the oauth protocol.
func (s *Server) oauthEvent(r *http.Request, op string, detail map[string]any) {
	detail["op"] = op
	s.emit(r, events.Event{Kind: events.KindToolCall, Protocol: "oauth", Detail: detail})
}

// oauthRegister is dynamic client registration (RFC 7591). MCP clients use it
// on first contact, so the metadata they send names the client software.
func (s *Server) oauthRegister(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	var req struct {
		ClientName      string   `json:"client_name"`
		RedirectURIs    []string `json:"redirect_uris"`
		GrantTypes      []string `json:"grant_types"`
		ResponseTypes   []string `json:"response_types"`
		AuthMethod      string   `json:"token_endpoint_auth_method"`
		Scope           string   `json:"scope"`
		SoftwareID      string   `json:"software_id"`
		SoftwareVersion string   `json:"software_version"`
		ClientURI       string   `json:"client_uri"`
		Contacts        []string `json:"contacts"`
	}
	detail := map[string]any{"raw": truncate(string(body), 2000)}
	if err := json.Unmarshal(body, &req); err != nil {
		detail["error"] = "invalid_client_metadata"
		s.oauthEvent(r, "oauth_register", detail)
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", "The request body must be a JSON object.")
		return
	}
	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{grantAuthCode}
	}
	if req.AuthMethod == "" {
		req.AuthMethod = "client_secret_basic"
	}
	detail["client_name"] = truncate(req.ClientName, 200)
	detail["software_id"] = truncate(req.SoftwareID, 200)
	detail["software_version"] = truncate(req.SoftwareVersion, 64)
	detail["client_uri"] = truncate(req.ClientURI, 200)
	detail["redirect_uris"] = clipList(req.RedirectURIs, 5, 300)
	detail["grant_types"] = clipList(req.GrantTypes, 6, 80)
	detail["auth_method"] = truncate(req.AuthMethod, 40)
	scopes := strings.Fields(req.Scope)
	s.noteScopes(detail, scopes)

	fail := func(code, desc string) {
		detail["error"] = code
		s.oauthEvent(r, "oauth_register", detail)
		oauthError(w, http.StatusBadRequest, code, desc)
	}
	for _, g := range req.GrantTypes {
		if !slices.Contains([]string{grantAuthCode, grantRefresh, grantClientCreds, grantDeviceCode, grantTokenExchange}, g) {
			fail("invalid_client_metadata", "Unsupported grant type: "+truncate(g, 80))
			return
		}
	}
	if slices.Contains(req.GrantTypes, grantAuthCode) {
		if len(req.RedirectURIs) == 0 {
			fail("invalid_redirect_uri", "redirect_uris is required for the authorization_code grant.")
			return
		}
		for _, u := range req.RedirectURIs {
			if !validRedirect(u) {
				fail("invalid_redirect_uri", "Redirect URIs must use https, or http on a loopback address.")
				return
			}
		}
	}
	if !slices.Contains([]string{"client_secret_basic", "client_secret_post", "none"}, req.AuthMethod) {
		fail("invalid_client_metadata", "Unsupported token_endpoint_auth_method.")
		return
	}
	for _, sc := range scopes {
		if _, ok := s.scope(sc); !ok {
			fail("invalid_client_metadata", "Unknown scope: "+truncate(sc, 80))
			return
		}
	}

	c := &oauthClient{ID: "cli_" + randomHex(8), Name: truncate(req.ClientName, 200),
		RedirectURIs: req.RedirectURIs, Scopes: scopes, Created: time.Now()}
	s.oauth.mu.Lock()
	trim(s.oauth.clients)
	s.oauth.clients[c.ID] = c
	s.oauth.mu.Unlock()
	detail["client_id"] = c.ID
	s.oauthEvent(r, "oauth_register", detail)

	resp := map[string]any{
		"client_id":                  c.ID,
		"client_id_issued_at":        c.Created.Unix(),
		"client_name":                req.ClientName,
		"redirect_uris":              req.RedirectURIs,
		"grant_types":                req.GrantTypes,
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": req.AuthMethod,
	}
	if req.Scope != "" {
		resp["scope"] = req.Scope
	}
	if req.AuthMethod != "none" {
		resp["client_secret"] = s.revealWith(r, s.pack.OAuth.ClientSlot, map[string]any{"client_id": c.ID})
		resp["client_secret_expires_at"] = 0
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusCreated, resp)
}

func validRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		return h == "localhost" || h == "127.0.0.1" || h == "::1"
	}
	// Private-use schemes for native apps (RFC 8252), e.g. cursor://.
	return strings.Contains(u.Scheme, ".") || len(u.Scheme) > 2
}

// noteScopes records requested scopes, and any honey or unknown ones.
func (s *Server) noteScopes(detail map[string]any, scopes []string) {
	if len(scopes) == 0 {
		return
	}
	detail["scopes"] = clipList(scopes, 20, 60)
	var honey, unknown []string
	for _, sc := range scopes {
		def, ok := s.scope(sc)
		switch {
		case !ok:
			unknown = append(unknown, sc)
		case def.Honey:
			honey = append(honey, sc)
		}
	}
	if len(honey) > 0 {
		detail["honey_scopes"] = honey
	}
	if len(unknown) > 0 {
		detail["unknown_scopes"] = clipList(unknown, 10, 60)
	}
}

func (s *Server) scope(name string) (worldpack.Scope, bool) {
	for _, sc := range s.pack.OAuth.Scopes {
		if sc.Name == name {
			return sc, true
		}
	}
	return worldpack.Scope{}, false
}

// authRequest is an authorization request carried through the sign-in form.
type authRequest struct {
	ResponseType, ClientID, RedirectURI, Scope, State, Challenge, Method, Resource, UserCode string
}

func (a authRequest) values() url.Values {
	v := url.Values{}
	for k, val := range map[string]string{"response_type": a.ResponseType, "client_id": a.ClientID,
		"redirect_uri": a.RedirectURI, "scope": a.Scope, "state": a.State, "code_challenge": a.Challenge,
		"code_challenge_method": a.Method, "resource": a.Resource, "user_code": a.UserCode} {
		if val != "" {
			v.Set(k, val)
		}
	}
	return v
}

func authRequestFrom(v url.Values) authRequest {
	return authRequest{ResponseType: v.Get("response_type"), ClientID: v.Get("client_id"), RedirectURI: v.Get("redirect_uri"),
		Scope: v.Get("scope"), State: v.Get("state"), Challenge: v.Get("code_challenge"),
		Method: v.Get("code_challenge_method"), Resource: v.Get("resource"), UserCode: v.Get("user_code")}
}

// client returns a registered client. Registrations are kept in memory, so
// a well-formed ID from before a restart is accepted without its metadata.
func (s *Server) client(id string) (*oauthClient, bool) {
	s.oauth.mu.Lock()
	c, ok := s.oauth.clients[id]
	s.oauth.mu.Unlock()
	if ok {
		return c, true
	}
	if rest, found := strings.CutPrefix(id, "cli_"); found && len(rest) == 16 {
		if _, err := hex.DecodeString(rest); err == nil {
			return &oauthClient{ID: id}, true
		}
	}
	for _, sa := range s.pack.ServiceAccounts {
		if sa.ClientID == id {
			return &oauthClient{ID: id, Name: sa.Name, Scopes: sa.Scopes}, true
		}
	}
	return nil, false
}

// oauthAuthorize starts the authorization code flow and shows the sign-in page.
func (s *Server) oauthAuthorize(w http.ResponseWriter, r *http.Request) {
	a := authRequestFrom(r.URL.Query())
	detail := map[string]any{"client_id": truncate(a.ClientID, 80), "redirect_uri": truncate(a.RedirectURI, 300),
		"pkce": a.Method, "resource": truncate(a.Resource, 200), "response_type": truncate(a.ResponseType, 40)}
	scopes := strings.Fields(a.Scope)
	s.noteScopes(detail, scopes)
	c, ok := s.client(a.ClientID)
	if ok {
		detail["client_name"] = c.Name
	}
	// Errors that cannot be sent back to the client are shown on the page.
	if !ok {
		detail["error"] = "invalid_client"
		s.oauthEvent(r, "oauth_authorize", detail)
		s.render(w, r, http.StatusBadRequest, "oauth_error.html", "Sign in", func(d *pageData) {
			d.Message = "This application is not registered with " + s.pack.Company.Name + "."
		})
		return
	}
	if (len(c.RedirectURIs) > 0 && !slices.Contains(c.RedirectURIs, a.RedirectURI)) || !validRedirect(a.RedirectURI) {
		detail["error"] = "invalid_redirect_uri"
		s.oauthEvent(r, "oauth_authorize", detail)
		s.render(w, r, http.StatusBadRequest, "oauth_error.html", "Sign in", func(d *pageData) {
			d.Message = "The redirect URI does not match the one registered for this application."
		})
		return
	}
	redirectErr := func(code, desc string) {
		detail["error"] = code
		s.oauthEvent(r, "oauth_authorize", detail)
		v := url.Values{"error": {code}, "error_description": {desc}, "iss": {s.issuer()}}
		if a.State != "" {
			v.Set("state", a.State)
		}
		sep := "?"
		if strings.Contains(a.RedirectURI, "?") {
			sep = "&"
		}
		http.Redirect(w, r, a.RedirectURI+sep+v.Encode(), http.StatusFound)
	}
	switch {
	case a.ResponseType != "code":
		redirectErr("unsupported_response_type", "Only response_type=code is supported.")
		return
	case a.Challenge == "" || a.Method != "S256":
		redirectErr("invalid_request", "PKCE with code_challenge_method=S256 is required.")
		return
	}
	for _, sc := range scopes {
		if _, ok := s.scope(sc); !ok {
			redirectErr("invalid_scope", "Unknown scope: "+truncate(sc, 80))
			return
		}
	}
	s.oauthEvent(r, "oauth_authorize", detail)
	s.renderConsent(w, r, http.StatusOK, a, c.Name, "")
}

func (s *Server) renderConsent(w http.ResponseWriter, r *http.Request, status int, a authRequest, client, msg string) {
	var scopes []worldpack.Scope
	for _, sc := range strings.Fields(a.Scope) {
		if def, ok := s.scope(sc); ok {
			scopes = append(scopes, def)
		}
	}
	if client == "" {
		client = "an application"
	}
	action := "/oauth/authorize"
	if a.UserCode != "" {
		action = "/device"
	}
	s.render(w, r, status, "oauth_login.html", "Sign in", func(d *pageData) {
		d.Message = msg
		d.OAuth = &oauthPage{Client: client, Scopes: scopes, Action: action, Hidden: a.values()}
	})
}

// oauthPage is what the sign-in and consent page shows.
type oauthPage struct {
	Client string
	Scopes []worldpack.Scope
	Action string
	Hidden url.Values
}

// oauthLogin handles the sign-in form of the authorization code and device
// flows. It never succeeds; the attempt, the username and the password (as a
// possible canary) are recorded as on the console login.
func (s *Server) oauthLogin(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	a := authRequestFrom(r.PostForm)
	user := truncate(r.PostForm.Get("email"), 128)
	pass := r.PostForm.Get("password")
	flow := "authorization_code"
	if a.UserCode != "" || r.URL.Path == "/device" {
		flow = "device"
	}
	s.emit(r, events.Event{Kind: events.KindForm, Protocol: "oauth", Detail: map[string]any{
		"form": "login", "username": user, "flow": flow, "client_id": truncate(a.ClientID, 80)}})
	if pass != "" {
		s.credential(r, pass, "oauth-login")
	}
	name := ""
	if c, ok := s.client(a.ClientID); ok {
		name = c.Name
	}
	if flow == "device" && user == "" {
		// The code entry step of the device page.
		code := strings.ToUpper(strings.TrimSpace(r.PostForm.Get("user_code")))
		if dg, ok := s.deviceByUserCode(code); ok {
			a.UserCode, a.ClientID, a.Scope = code, dg.ClientID, strings.Join(dg.Scopes, " ")
			s.renderConsent(w, r, http.StatusOK, a, name, "")
			return
		}
		s.render(w, r, http.StatusOK, "device.html", "Connect a device", func(d *pageData) {
			d.Message = "That code is invalid or has expired."
		})
		return
	}
	s.renderConsent(w, r, http.StatusUnauthorized, a, name, "Invalid email or password.")
}

func (s *Server) oauthDeviceCode(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	clientID := r.PostForm.Get("client_id")
	if id, _, ok := r.BasicAuth(); ok {
		clientID = id
	}
	scopes := strings.Fields(r.PostForm.Get("scope"))
	detail := map[string]any{"client_id": truncate(clientID, 80)}
	s.noteScopes(detail, scopes)
	if _, ok := s.client(clientID); !ok {
		detail["error"] = "invalid_client"
		s.oauthEvent(r, "oauth_device", detail)
		oauthError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed.")
		return
	}
	dg := &deviceGrant{ClientID: clientID, UserCode: userCode(), Scopes: scopes,
		Expires: time.Now().Add(deviceTTL), Interval: 5 * time.Second}
	code := randomHex(20)
	s.oauth.mu.Lock()
	trim(s.oauth.devices)
	s.oauth.devices[code] = dg
	s.oauth.mu.Unlock()
	s.oauthEvent(r, "oauth_device", detail)
	verify := s.issuer() + "/device"
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code": code, "user_code": dg.UserCode, "verification_uri": verify,
		"verification_uri_complete": verify + "?user_code=" + dg.UserCode,
		"expires_in":                int(deviceTTL.Seconds()), "interval": int(dg.Interval.Seconds()),
	})
}

// userCode returns an eight-letter code without easily confused letters.
func userCode() string {
	const letters = "BCDFGHJKLMNPQRSTVWXZ"
	b := []byte(randomHex(8))
	out := make([]byte, 0, 9)
	for i, c := range b {
		if i == 4 {
			out = append(out, '-')
		}
		out = append(out, letters[int(c)%len(letters)])
	}
	return string(out)
}

func (s *Server) deviceByUserCode(code string) (*deviceGrant, bool) {
	s.oauth.mu.Lock()
	defer s.oauth.mu.Unlock()
	for _, dg := range s.oauth.devices {
		if dg.UserCode == code && time.Now().Before(dg.Expires) {
			return dg, true
		}
	}
	return nil, false
}

func (s *Server) devicePage(w http.ResponseWriter, r *http.Request) {
	code := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("user_code")))
	if dg, ok := s.deviceByUserCode(code); ok {
		name := ""
		if c, ok := s.client(dg.ClientID); ok {
			name = c.Name
		}
		s.renderConsent(w, r, http.StatusOK, authRequest{ClientID: dg.ClientID, UserCode: code, Scope: strings.Join(dg.Scopes, " ")}, name, "")
		return
	}
	s.render(w, r, http.StatusOK, "device.html", "Connect a device", nil)
}

// clientAuth reads client credentials (HTTP Basic or form) and checks them.
// It returns the client ID, the service account if the credentials are one,
// and whether a secret was presented and accepted.
func (s *Server) clientAuth(r *http.Request) (id string, sa *worldpack.ServiceAccount, presented, ok bool) {
	id, secret, basic := r.BasicAuth()
	if basic {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if secret == "" {
		return id, nil, false, false
	}
	slot := s.credential(r, secret, "oauth-client")
	for i := range s.pack.ServiceAccounts {
		if a := &s.pack.ServiceAccounts[i]; a.ClientID == id {
			return id, a, true, slot == a.Slot
		}
	}
	_, known := s.client(id)
	return id, nil, true, known && slot == s.pack.OAuth.ClientSlot
}

func (s *Server) oauthToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f := r.PostForm
	grant := f.Get("grant_type")
	detail := map[string]any{"grant_type": truncate(grant, 80)}
	scopes := strings.Fields(f.Get("scope"))
	s.noteScopes(detail, scopes)
	for _, k := range []string{"audience", "resource", "requested_token_type", "subject_token_type"} {
		if v := f.Get(k); v != "" {
			detail[k] = truncate(v, 200)
		}
	}
	fail := func(status int, code, desc string) {
		detail["error"] = code
		s.oauthEvent(r, "oauth_token", detail)
		oauthError(w, status, code, desc)
	}
	id, sa, presented, authed := s.clientAuth(r)
	detail["client_id"] = truncate(id, 80)
	if sa != nil {
		detail["service_account"] = sa.Name
	}
	if presented && !authed {
		fail(http.StatusUnauthorized, "invalid_client", "Client authentication failed.")
		return
	}

	switch grant {
	case grantClientCreds:
		if !authed {
			fail(http.StatusUnauthorized, "invalid_client", "Client authentication failed.")
			return
		}
		allowed := s.grantableScopes()
		subject := id
		if sa != nil {
			allowed, subject = sa.Scopes, sa.Name
		} else if c, ok := s.client(id); ok && len(c.Scopes) > 0 {
			allowed = intersect(c.Scopes, allowed)
		}
		granted, denied := grantScopes(scopes, allowed)
		if len(denied) > 0 {
			detail["denied_scopes"] = denied
			fail(http.StatusBadRequest, "invalid_scope", "The requested scope is not permitted for this client.")
			return
		}
		s.issueToken(w, r, detail, &tokenGrant{ClientID: id, Scopes: granted, Subject: subject,
			Audience: s.audience(f)}, "")
	case grantTokenExchange:
		s.tokenExchange(w, r, detail, fail)
	case grantDeviceCode:
		s.oauth.mu.Lock()
		dg, ok := s.oauth.devices[f.Get("device_code")]
		var early bool
		if ok {
			early = !dg.LastPoll.IsZero() && time.Since(dg.LastPoll) < dg.Interval
			dg.LastPoll = time.Now()
		}
		s.oauth.mu.Unlock()
		switch {
		case !ok:
			fail(http.StatusBadRequest, "invalid_grant", "The device code is invalid.")
		case time.Now().After(dg.Expires):
			fail(http.StatusBadRequest, "expired_token", "The device code has expired.")
		case early:
			detail["polled_early"] = true
			fail(http.StatusBadRequest, "slow_down", "Polling too frequently.")
		default:
			fail(http.StatusBadRequest, "authorization_pending", "The user has not yet completed authorization.")
		}
	case grantAuthCode:
		// No sign-in ever succeeds, so no code was ever issued.
		detail["pkce_verifier"] = f.Get("code_verifier") != ""
		fail(http.StatusBadRequest, "invalid_grant", "The authorization code is invalid or has expired.")
	case grantRefresh:
		if rt := f.Get("refresh_token"); rt != "" {
			s.credential(r, rt, "oauth-refresh")
		}
		fail(http.StatusBadRequest, "invalid_grant", "The refresh token is invalid or has expired.")
	case "":
		fail(http.StatusBadRequest, "invalid_request", "Missing grant_type.")
	default:
		fail(http.StatusBadRequest, "unsupported_grant_type", "The grant type is not supported.")
	}
}

// tokenExchange is RFC 8693: a client trades a token it holds for one with
// another audience or narrower scope, optionally acting for another party.
// Asking for more than the subject token carries is the escalation the spec
// calls out; it is recorded and refused.
func (s *Server) tokenExchange(w http.ResponseWriter, r *http.Request, detail map[string]any, fail func(int, string, string)) {
	f := r.PostForm
	subject := f.Get("subject_token")
	if subject == "" {
		fail(http.StatusBadRequest, "invalid_request", "Missing subject_token.")
		return
	}
	g, ok := s.lookupToken(r, subject, "oauth-token-exchange")
	if !ok {
		fail(http.StatusBadRequest, "invalid_grant", "The subject token is invalid or has expired.")
		return
	}
	detail["subject"] = g.Subject
	detail["subject_scopes"] = g.Scopes
	actor := ""
	if at := f.Get("actor_token"); at != "" {
		detail["delegation"] = true
		if ag, ok := s.lookupToken(r, at, "oauth-actor"); ok {
			actor = ag.Subject
		} else {
			fail(http.StatusBadRequest, "invalid_grant", "The actor token is invalid or has expired.")
			return
		}
		detail["actor"] = actor
	}
	scopes := strings.Fields(f.Get("scope"))
	granted, denied := grantScopes(scopes, g.Scopes)
	if len(denied) > 0 {
		detail["denied_scopes"] = denied
		detail["escalation"] = true
		fail(http.StatusBadRequest, "invalid_scope", "The requested scope exceeds the scope of the subject token.")
		return
	}
	s.issueToken(w, r, detail, &tokenGrant{ClientID: g.ClientID, Scopes: granted, Subject: g.Subject,
		Actor: actor, Audience: s.audience(f)}, tokenTypeAccess)
}

func (s *Server) audience(f url.Values) string {
	if v := f.Get("resource"); v != "" {
		return truncate(v, 200)
	}
	return truncate(f.Get("audience"), 200)
}

// issueToken mints an access token (a per-issue canary) and answers.
func (s *Server) issueToken(w http.ResponseWriter, r *http.Request, detail map[string]any, g *tokenGrant, issuedType string) {
	g.Expires = time.Now().Add(tokenTTL)
	detail["granted_scopes"] = g.Scopes
	if g.Audience != "" {
		detail["audience"] = g.Audience
	}
	s.oauthEvent(r, "oauth_token", detail)
	token := s.revealWith(r, s.pack.OAuth.TokenSlot, map[string]any{"client_id": g.ClientID, "subject": g.Subject,
		"scopes": g.Scopes})
	s.oauth.mu.Lock()
	trim(s.oauth.tokens)
	s.oauth.tokens[token] = g
	s.oauth.mu.Unlock()
	resp := map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": int(tokenTTL.Seconds()),
		"scope": strings.Join(g.Scopes, " ")}
	if issuedType != "" {
		resp["issued_token_type"] = issuedType
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

// lookupToken records a presented access token and returns its grant. A
// token minted before a restart is still ours (its MAC verifies) but its
// grant is gone; it gets the default grantable scopes.
func (s *Server) lookupToken(r *http.Request, token, where string) (*tokenGrant, bool) {
	if s.credential(r, token, where) != s.pack.OAuth.TokenSlot {
		return nil, false
	}
	return s.grantFor(token)
}

func (s *Server) grantFor(token string) (*tokenGrant, bool) {
	s.oauth.mu.Lock()
	g, ok := s.oauth.tokens[token]
	s.oauth.mu.Unlock()
	if !ok {
		return &tokenGrant{Subject: "unknown", Scopes: s.grantableScopes(), Expires: time.Now().Add(tokenTTL)}, true
	}
	if time.Now().After(g.Expires) {
		return nil, false
	}
	return g, true
}

func (s *Server) grantableScopes() []string {
	var out []string
	for _, sc := range s.pack.OAuth.Scopes {
		if sc.Grantable && sc.Name != "openid" && sc.Name != "profile" && sc.Name != "email" {
			out = append(out, sc.Name)
		}
	}
	return out
}

// grantScopes returns the requested scopes that are allowed, or all allowed
// ones when none were requested, and the requested ones that are not.
func grantScopes(requested, allowed []string) (granted, denied []string) {
	if len(requested) == 0 {
		return slices.Clone(allowed), nil
	}
	for _, sc := range requested {
		if slices.Contains(allowed, sc) {
			granted = append(granted, sc)
		} else {
			denied = append(denied, sc)
		}
	}
	return granted, denied
}

func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		if slices.Contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}

func (s *Server) oauthIntrospect(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	detail := map[string]any{}
	id, _, _, authed := s.clientAuth(r)
	detail["client_id"] = truncate(id, 80)
	if !authed {
		detail["error"] = "invalid_client"
		s.oauthEvent(r, "oauth_introspect", detail)
		oauthError(w, http.StatusUnauthorized, "invalid_client", "Client authentication failed.")
		return
	}
	token := r.PostForm.Get("token")
	g, ok := s.lookupToken(r, token, "oauth-introspect")
	detail["active"] = ok
	s.oauthEvent(r, "oauth_introspect", detail)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]bool{"active": false})
		return
	}
	resp := map[string]any{"active": true, "scope": strings.Join(g.Scopes, " "), "client_id": g.ClientID,
		"token_type": "Bearer", "exp": g.Expires.Unix(), "iat": g.Expires.Add(-tokenTTL).Unix(),
		"iss": s.issuer(), "sub": g.Subject}
	if g.Audience != "" {
		resp["aud"] = g.Audience
	}
	if g.Actor != "" {
		resp["act"] = map[string]string{"sub": g.Actor}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) oauthRevoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if t := r.PostForm.Get("token"); t != "" {
		s.credential(r, t, "oauth-revoke")
	}
	s.oauthEvent(r, "oauth_revoke", map[string]any{})
	w.WriteHeader(http.StatusOK)
}

func (s *Server) oauthUserinfo(w http.ResponseWriter, r *http.Request) {
	token := bearer(r)
	detail := map[string]any{}
	g, ok := s.lookupToken(r, token, "oauth-userinfo")
	switch {
	case token == "" || !ok:
		detail["error"] = "invalid_token"
		s.oauthEvent(r, "oauth_userinfo", detail)
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
	default:
		// Client credentials tokens have no end user.
		detail["error"] = "insufficient_scope"
		detail["subject"] = g.Subject
		s.oauthEvent(r, "oauth_userinfo", detail)
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="openid"`)
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "insufficient_scope"})
	}
}

// protectedResource is the RFC 9728 metadata for an API host, which MCP
// clients read to find the authorization server.
func (s *Server) protectedResource(resource string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"resource":                 resource,
			"authorization_servers":    []string{s.issuer()},
			"scopes_supported":         []string{"models:read", "inference", "usage:read", "keys:read"},
			"bearer_methods_supported": []string{"header"},
			"resource_documentation":   "https://docs." + s.domain + "/",
		})
	}
}

// revealWith is reveal with extra detail on the exposure event.
func (s *Server) revealWith(r *http.Request, slot string, extra map[string]any) string {
	value, id := s.canaries.Reveal(slot)
	d := map[string]any{"exposure_id": id}
	for k, v := range extra {
		d[k] = v
	}
	s.emit(r, events.Event{Kind: events.KindCanaryExposed, CanarySlot: slot, Detail: d})
	s.noteDepth(infoFrom(r.Context()).source, "exposed", slot)
	return value
}

func clipList(in []string, n, width int) []string {
	out := make([]string, 0, min(len(in), n))
	for _, v := range in[:min(len(in), n)] {
		out = append(out, truncate(v, width))
	}
	return out
}
