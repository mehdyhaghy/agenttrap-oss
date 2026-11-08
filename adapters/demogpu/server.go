// Package demogpu serves the DemoGPU persona: marketing site, docs, an
// OpenAI-compatible API, the customer console, an MCP server, a status page and
// the "self-hosted vLLM" upstream that planted provider keys point at.
//
// Every response is derived from the frozen world pack; canary values come
// from the per-spoke canary set.
package demogpu

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"agenttrap/internal/canary"
	"agenttrap/internal/events"
	"agenttrap/internal/ja4"
	"agenttrap/internal/worldpack"
	"agenttrap/modules"
)

// Recorder receives events. The spoke's disk queue implements it.
type Recorder interface {
	Record(events.Event)
}

// Canary slots used by this persona. They must exist in the pack.
const (
	SlotDocsKey = "docs_sample_key"
	// SlotRepoKey is the key published in the public example repository; a
	// use of it proves the client found DemoGPU through that repository.
	SlotRepoKey = "repo_sample_key"
	// SlotRepoVLLMKey is the upstream vLLM key buried in the example
	// repository's agent memory file; a use proves that file was read.
	SlotRepoVLLMKey = "repo_vllm_key"
	SlotVLLMKey     = "provider_key_vllm"
)

// Options configures the facade.
type Options struct {
	// BaseDomain overrides the pack domain, e.g. "demogpu.localhost" for local tests.
	BaseDomain string
	// TrustedProxies are the only peers whose X-Real-IP / X-Forwarded-For are believed.
	TrustedProxies []netip.Prefix
	// PseudonymizeKey, if set, replaces client IPs with a keyed hash before
	// they leave the spoke.
	PseudonymizeKey []byte
	// RedirectHTTPS answers plain-HTTP requests for persona hostnames with a
	// 301 to HTTPS (after logging them), so clients that follow it reach the
	// TLS listener and get a JA4 fingerprint.
	RedirectHTTPS bool
	// Modules are the honeypot modules offered every request ahead of the
	// persona (see package modules).
	Modules []modules.Module
}

// Server is the facade HTTP handler.
type Server struct {
	pack     *worldpack.Pack
	canaries *canary.Set
	rec      Recorder
	opts     Options
	domain   string
	surfaces map[string]http.Handler
	tls      *tlsCache
	oauth    *oauthState
	tasks    *taskStore
	depth    *depthTracker
}

// New builds the facade.
func New(pack *worldpack.Pack, canaries *canary.Set, rec Recorder, opts Options) *Server {
	s := &Server{pack: pack, canaries: canaries, rec: rec, opts: opts, domain: pack.Company.Domain, tls: newTLSCache(),
		oauth: newOAuthState(), tasks: newTaskStore(), depth: newDepthTracker()}
	if opts.BaseDomain != "" {
		s.domain = opts.BaseDomain
	}
	s.surfaces = map[string]http.Handler{
		"www":     s.wwwHandler(),
		"docs":    s.docsHandler(),
		"api":     s.apiHandler(),
		"console": s.consoleHandler(),
		"mcp":     s.mcpHandler(),
		"status":  s.statusHandler(),
		"vllm":    s.vllmHandler(),
	}
	if pack.Cloud != nil {
		s.surfaces["aws"] = s.awsHandler()
	}
	if pack.Kube != nil {
		s.surfaces["k8s"] = s.kubeHandler()
	}
	return s
}

// surface maps a Host header to a surface name.
func (s *Server) surface(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == s.domain {
		return "www"
	}
	if label, ok := strings.CutSuffix(host, "."+s.domain); ok && !strings.Contains(label, ".") {
		if _, known := s.surfaces[label]; known {
			return label
		}
	}
	return ""
}

type ctxKey struct{}

// reqInfo carries per-request data to handlers.
type reqInfo struct {
	surface string
	source  string
	viewID  string // set when an HTML page with the beacon was served
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	surface := s.surface(r.Host)
	ip, port := s.clientAddr(r)
	info := &reqInfo{surface: surface, source: s.pseudonymize(ip)}
	rw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
	if s.pack.Company.ServerHeader != "" {
		rw.Header().Set("Server", s.pack.Company.ServerHeader)
	}
	if surface == "vllm" {
		rw.Header().Set("Server", "uvicorn")
	}
	r = r.WithContext(withInfo(r.Context(), info))
	if mod := modules.Pick(s.opts.Modules, modules.Request{Request: r, Surface: surface}); mod != nil {
		s.serveModule(rw, r, mod, port)
		return
	}
	// Bound every facade body (modules keep their own limits): ParseForm
	// would otherwise buffer up to 10 MB per request.
	r.Body = http.MaxBytesReader(rw, r.Body, maxRequestBody)
	body := captureBody(r, surface)
	scheme := s.scheme(r)
	h, known := s.surfaces[surface]
	trap := ""
	if known {
		trap = robotsTrap(surface, r.URL.Path)
	}
	switch {
	case !known:
		notFound(rw)
	case s.opts.RedirectHTTPS && scheme == "http":
		redirectHTTPS(rw, r)
	case r.URL.Path == "/robots.txt" && hasRobots(surface):
		s.serveRobots(rw, surface)
	case r.URL.Path == beaconPath && htmlSurface(surface):
		s.serveBeacon(rw, r)
		return // the beacon event is the record; no separate request event
	case r.URL.Path == replayPath && htmlSurface(surface):
		s.serveReplay(rw, r)
		return
	case r.URL.Path == "/assets/app.js" && htmlSurface(surface):
		serveAppJS(rw, r)
	case trap != "":
		serveTrap(rw, surface)
	default:
		if s.opts.RedirectHTTPS {
			rw.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.ServeHTTP(rw, r)
	}
	detail := fingerprint(r)
	detail["client_port"] = port
	if id := integrationHeader(r); id != "" {
		detail["agent_id"] = truncate(id, 64)
	}
	if trap != "" {
		detail["robots_trap"] = trap
	}
	if info.viewID != "" {
		detail["view_id"] = info.viewID
	}
	if body != nil {
		for k, v := range body {
			detail[k] = v
		}
	}
	detail["scheme"] = scheme
	if facts, ok := s.tls.get(connKey(ip, port), time.Now()); ok {
		for k, v := range facts {
			detail[k] = v
		}
	}
	s.emit(r, events.Event{Kind: events.KindRequest, Status: rw.status, Detail: detail})
}

// moduleRequest wraps r for a module, letting it hand out the persona's
// canaries. Each reveal is recorded like any other exposure, tagged with the
// module so a scanner that harvests a planted file can be told apart from an
// agent that earned the key through the persona.
func (s *Server) moduleRequest(r *http.Request, surface, module string) modules.Request {
	return modules.Request{Request: r, Surface: surface, Reveal: func(slot string) string {
		if s.canaries.Value(slot) == "" {
			return ""
		}
		return s.revealWith(r, slot, map[string]any{"module": module})
	}}
}

// serveModule lets a honeypot module answer the request, then records the
// request tagged with the module and, for a probe or exploit, an exploit event
// carrying what the module saw.
func (s *Server) serveModule(rw *statusWriter, r *http.Request, mod modules.Module, port string) {
	info := infoFrom(r.Context())
	hit := mod.Serve(rw, s.moduleRequest(r, info.surface, mod.Name()))
	detail := fingerprint(r)
	detail["client_port"] = port
	detail["scheme"] = s.scheme(r)
	detail["module"] = mod.Name()
	if hit.Attack != "" {
		detail["attack"] = hit.Attack
	}
	ip, _ := s.clientAddr(r)
	if facts, ok := s.tls.get(connKey(ip, port), time.Now()); ok {
		for k, v := range facts {
			detail[k] = v
		}
	}
	s.emit(r, events.Event{Kind: events.KindRequest, Status: rw.status, Detail: detail})
	if hit.Stage == "" {
		return
	}
	ex := map[string]any{"module": mod.Name(), "attack": hit.Attack, "stage": hit.Stage,
		"cve": hit.CVE, "signals": hit.Signals, "content_type": truncate(r.Header.Get("Content-Type"), 100)}
	for k, v := range hit.Detail {
		ex[k] = v
	}
	s.emit(r, events.Event{Kind: events.KindExploit, Status: rw.status, Detail: ex})
}

// ObserveTLS records a TLS ClientHello seen by the packet sensor next to the
// edge proxy. Src is the client address exactly as the proxy sees it.
func (s *Server) ObserveTLS(res ja4.Result) {
	if res.Hello == nil {
		return
	}
	ip, port := res.Src.Addr().Unmap().String(), strconv.Itoa(int(res.Src.Port()))
	facts := connFacts(res)
	s.tls.put(connKey(ip, port), facts, time.Now())
	t := res.Time
	if t.IsZero() {
		t = time.Now()
	}
	s.rec.Record(events.Event{
		ID:       events.NewID(),
		Time:     t.UTC(),
		Protocol: "tls",
		Surface:  s.surface(res.Hello.SNI),
		Kind:     events.KindTLSHello,
		Source:   s.pseudonymize(ip),
		Host:     truncate(res.Hello.SNI, 255),
		Detail: withFacts(facts, map[string]any{"tls_version": res.Hello.TLSVersion,
			"alpn": res.Hello.ALPN, "client_port": port}),
	})
}

func withFacts(facts, detail map[string]any) map[string]any {
	for k, v := range facts {
		detail[k] = v
	}
	return detail
}

// emit records an event, filling in request context.
func (s *Server) emit(r *http.Request, ev events.Event) {
	info := infoFrom(r.Context())
	ev.ID = events.NewID()
	ev.Time = time.Now().UTC()
	if ev.Protocol == "" {
		ev.Protocol = "http"
		switch info.surface {
		case "api", "vllm":
			ev.Protocol = "openai"
		case "mcp":
			ev.Protocol = "mcp"
		case "aws":
			ev.Protocol = "aws"
		case "k8s":
			ev.Protocol = "k8s"
		}
	}
	ev.Surface = info.surface
	ev.Source = info.source
	ev.UserAgent = r.UserAgent()
	ev.Method = r.Method
	ev.Host = r.Host
	ev.Path = r.URL.RequestURI()
	s.rec.Record(ev)
}

// htmlSurface reports whether surface serves HTML pages (and their script).
func htmlSurface(surface string) bool {
	return surface == "www" || surface == "docs" || surface == "console" || surface == "status"
}

// isAPIKey reports whether slot is a DemoGPU API key (trial or repository).
func isAPIKey(slot string) bool { return slot == SlotDocsKey || slot == SlotRepoKey }

// reveal mints a canary value unique to this exposure, records that it was
// shown to the client, and returns it. A later use of the value names this
// exact exposure, even from another address.
func (s *Server) reveal(r *http.Request, slot string) string {
	return s.revealWith(r, slot, nil)
}

// credential records a presented credential and returns the local canary
// slot it matches, if any. Unknown credentials are still hashed so the hub
// can match them against other spokes' fixed canaries; values shaped like a
// canary are forwarded so the hub can verify other spokes' minted ones.
func (s *Server) credential(r *http.Request, presented, where string) string {
	if presented == "" {
		return ""
	}
	ev := events.Event{Kind: events.KindAuth, CredentialSHA256: canary.Hash(presented),
		Detail: map[string]any{"where": where, "prefix": credPrefix(presented)}}
	slot, exposureID, ok := s.canaries.Identify(presented)
	switch {
	case ok:
		ev.Kind = events.KindCanaryUsed
		ev.CanarySlot = slot
		if exposureID != "" {
			ev.Detail["exposure_id"] = exposureID
		}
	case s.canaries.LooksLike(presented):
		ev.Detail["presented_canary"] = presented
	}
	s.emit(r, ev)
	s.noteDepth(infoFrom(r.Context()).source, "used", slot)
	return slot
}

// clientAddr returns the client IP and port, believing the edge proxy's
// X-Real-IP / X-Real-Port headers only when the peer is a trusted proxy.
func (s *Server) clientAddr(r *http.Request) (ip, port string) {
	host, port, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host, port = r.RemoteAddr, ""
	}
	ip = host
	if addr, err := netip.ParseAddr(host); err == nil && s.trusted(addr) {
		if real := strings.TrimSpace(r.Header.Get("X-Real-IP")); real != "" {
			ip = real
			port = strings.TrimSpace(r.Header.Get("X-Real-Port"))
		} else if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			ip, port = strings.TrimSpace(parts[len(parts)-1]), ""
		}
	}
	if a, err := netip.ParseAddr(ip); err == nil {
		ip = a.Unmap().String()
	}
	return ip, port
}

// maxBodyCapture bounds how much of a request body is stored.
const maxBodyCapture = 16 << 10

// maxRequestBody caps any facade request body.
const maxRequestBody = 1 << 20

// captureBody reads and restores the body of JSON API requests (api, vllm,
// mcp) so the full prompt or tool arguments are recorded. Form surfaces
// (console login, waitlist) are never captured: they may carry real people's
// passwords or email addresses, which are only ever hashed.
func captureBody(r *http.Request, surface string) map[string]any {
	if r.Body == nil || r.Method == http.MethodGet || r.Method == http.MethodHead {
		return nil
	}
	if surface != "api" && surface != "vllm" && surface != "mcp" && surface != "aws" && surface != "k8s" {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBodyCapture+1))
	rest := r.Body
	r.Body = struct {
		io.Reader
		io.Closer
	}{io.MultiReader(bytes.NewReader(data), rest), rest}
	if err != nil || len(data) == 0 {
		return nil
	}
	sum := sha256.Sum256(data)
	out := map[string]any{
		"body_sha256":  hex.EncodeToString(sum[:]),
		"body_bytes":   len(data),
		"content_type": truncate(r.Header.Get("Content-Type"), 100),
	}
	if len(data) > maxBodyCapture {
		data = data[:maxBodyCapture]
		out["body_truncated"] = true
	}
	out["body"] = strings.ToValidUTF8(string(data), "\uFFFD")
	return out
}

// scheme reports how the client reached the edge proxy ("http" or "https").
// X-Forwarded-Proto is believed only from a trusted proxy.
func (s *Server) scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if addr, err := netip.ParseAddr(host); err == nil && s.trusted(addr) {
		if p := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto"))); p == "https" || p == "http" {
			return p
		}
	}
	return "http"
}

// redirectHTTPS sends the same 301 page nginx does.
func redirectHTTPS(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	w.Header().Set("Location", "https://"+host+r.URL.RequestURI())
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusMovedPermanently)
	_, _ = w.Write([]byte("<html>\r\n<head><title>301 Moved Permanently</title></head>\r\n<body>\r\n<center><h1>301 Moved Permanently</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"))
}

// pseudonymize replaces an IP with a keyed hash when configured.
func (s *Server) pseudonymize(ip string) string {
	if len(s.opts.PseudonymizeKey) > 0 {
		mac := hmac.New(sha256.New, s.opts.PseudonymizeKey)
		mac.Write([]byte(ip))
		return "p:" + hex.EncodeToString(mac.Sum(nil))[:24]
	}
	return ip
}

func (s *Server) trusted(addr netip.Addr) bool {
	addr = addr.Unmap()
	return slices.ContainsFunc(s.opts.TrustedProxies, func(p netip.Prefix) bool { return p.Contains(addr) })
}

// fingerprint captures request traits useful for identifying agent frameworks.
func fingerprint(r *http.Request) map[string]any {
	names := make([]string, 0, len(r.Header))
	sdk := map[string]string{}
	for k, v := range r.Header {
		lk := strings.ToLower(k)
		names = append(names, lk)
		if strings.HasPrefix(lk, "x-stainless-") ||
			strings.HasPrefix(lk, "mcp-") || lk == "openai-organization" || lk == "openai-project" {
			sdk[lk] = truncate(strings.Join(v, ","), 128)
		}
	}
	slices.Sort(names)
	d := map[string]any{"headers": names, "proto": r.Proto}
	for _, h := range []string{"Accept", "Accept-Language", "Accept-Encoding"} {
		if v := r.Header.Get(h); v != "" {
			d[strings.ToLower(h)] = truncate(v, 256)
		}
	}
	if len(sdk) > 0 {
		d["sdk"] = sdk
	}
	return d
}

func bearer(r *http.Request) string {
	v, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return strings.TrimSpace(r.Header.Get("X-Api-Key"))
	}
	return strings.TrimSpace(v)
}

// credPrefix keeps only a short, non-secret prefix for display.
func credPrefix(s string) string {
	if i := strings.IndexAny(s, "_-"); i > 0 && i < 12 {
		return s[:i+1]
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status, w.wrote = code, true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	w.wrote = true
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"))
}
