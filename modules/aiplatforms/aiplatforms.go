// Package aiplatforms poses as exposed AI and agent platforms that scanners
// exploit in the wild: Langflow and Flowise code-execution endpoints, the
// Feast feature server's file read, an open Ollama server (LLMjacking), and
// leaked LiteLLM proxy configs. Nothing submitted is ever executed; code,
// prompts and the URLs they reach for are recorded, and leaked configs carry
// the persona's canary provider keys so a later use traces back here.
package aiplatforms

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"agenttrap/modules"
)

// bodyLimit bounds how much of a request body is inspected.
const bodyLimit = 64 << 10

// CVEs, verified against NVD:
//   - CVE-2025-3248   Langflow POST /api/v1/validate/code, unauthenticated exec
//   - CVE-2026-33017  Langflow POST /api/v1/build_public_tmp/{id}/flow, unauthenticated exec
//   - CVE-2025-59528  Flowise POST /api/v1/node-load-method/customMCP, Function() injection
//   - CVE-2026-46442  Flowise POST /api/v1/node-custom-function, NodeVM escape
//   - CVE-2026-23536  Feast feature server POST /read-document, file read
const (
	cveLangflowValidate = "CVE-2025-3248"
	cveLangflowBuild    = "CVE-2026-33017"
	cveFlowiseMCP       = "CVE-2025-59528"
	cveFlowiseFunction  = "CVE-2026-46442"
	cveFeastRead        = "CVE-2026-23536"
)

// target is one recognized endpoint.
type target int

const (
	none target = iota
	langflowValidate
	langflowBuild
	flowiseMCP
	flowiseFunction
	feastRead
	ollamaTags
	ollamaVersion
	ollamaPS
	ollamaShow
	ollamaGenerate
	ollamaChat
	ollamaPull
	ollamaCreate
	litellmConfig
)

var (
	langflowBuildPath = regexp.MustCompile(`^/api/v1/build_public_tmp/[^/]+/flow$`)
	litellmPaths      = map[string]bool{
		"/litellm_config.yaml": true, "/litellm_config.yml": true,
		"/litellm/config.yaml": true, "/litellm/config.yml": true,
		"/litellm.yml": true, "/litellm.yaml": true,
		"/config/litellm.yaml": true, "/config/litellm.yml": true,
	}
	ollamaPaths = map[string]target{
		"/api/tags": ollamaTags, "/api/version": ollamaVersion, "/api/ps": ollamaPS,
		"/api/show": ollamaShow, "/api/generate": ollamaGenerate, "/api/chat": ollamaChat,
		"/api/pull": ollamaPull, "/api/create": ollamaCreate,
	}
)

// classify maps a request to the endpoint it targets.
func classify(path string) target {
	p := strings.ToLower(path)
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	if litellmPaths[p] {
		return litellmConfig
	}
	if t, ok := ollamaPaths[p]; ok {
		return t
	}
	if p == "/feast/read-document" || p == "/read-document" {
		return feastRead
	}
	for _, prefix := range []string{"/langflow", "/flowise", ""} {
		rest, ok := strings.CutPrefix(p, prefix)
		if !ok {
			continue
		}
		switch {
		case prefix != "/flowise" && rest == "/api/v1/validate/code":
			return langflowValidate
		case prefix != "/flowise" && langflowBuildPath.MatchString(rest):
			return langflowBuild
		case prefix != "/langflow" && rest == "/api/v1/node-load-method/custommcp":
			return flowiseMCP
		case prefix != "/langflow" && rest == "/api/v1/node-custom-function":
			return flowiseFunction
		}
	}
	return none
}

// Module is the AI-platform trap.
type Module struct{}

// New returns the module.
func New() *Module { return &Module{} }

// Name implements modules.Module.
func (*Module) Name() string { return "aiplatforms" }

// Claim takes the recognized endpoints on web surfaces. The persona's own
// OpenAI-compatible surfaces (api, vllm) are never touched, and neither are
// /v1/models or /v1/chat/completions anywhere.
func (*Module) Claim(r modules.Request) modules.Claim {
	if !modules.WebSurface(r.Surface) {
		return modules.Pass
	}
	if classify(r.URL.Path) == none {
		return modules.Pass
	}
	return modules.Attack
}

// Serve implements modules.Module.
func (m *Module) Serve(w http.ResponseWriter, r modules.Request) modules.Hit {
	t := classify(r.URL.Path)
	var body []byte
	var total int64
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		body, total = modules.ReadBody(r.Request, bodyLimit)
	}
	hit := modules.Hit{Detail: map[string]any{}}
	if total > 0 {
		hit.Detail["body_bytes"] = total
	}
	switch t {
	case langflowValidate, langflowBuild:
		serveLangflow(w, r, t, body, &hit)
	case flowiseMCP, flowiseFunction:
		serveFlowise(w, r, t, body, &hit)
	case feastRead:
		serveFeast(w, r, body, &hit)
	case litellmConfig:
		serveLiteLLM(w, r, &hit)
	default:
		serveOllama(w, r, t, body, &hit)
	}
	return hit
}

// methodNotAllowed answers a request with the wrong method to a POST
// endpoint the way the platform's framework does: FastAPI (Langflow, Feast)
// with a JSON 405, Express (Flowise) with its "Cannot GET" page.
func methodNotAllowed(w http.ResponseWriter, fastapi bool, method, path string) {
	if fastapi {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"detail": "Method Not Allowed"})
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Error</title>\n</head>\n<body>\n<pre>Cannot " +
		htmlEscape(method) + " " + htmlEscape(modules.Clip(path, 200)) + "</pre>\n</body>\n</html>\n"))
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// Indicators pulled out of submitted code and prompts.
var (
	urlRe   = regexp.MustCompile(`(?i)\b(?:https?|ftp|tcp|udp)://[^\s"'\\<>()]{3,200}`)
	ipRe    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b`)
	shellRe = regexp.MustCompile(`(?i)\b(?:curl|wget|bash|sh -c|/bin/sh|nc|ncat|python3? -c|base64 -d|chmod \+x|busybox|tftp|powershell)\b`)
)

// indicators records code, URLs, IPs and shell use found in s on hit.
func indicators(s string, hit *modules.Hit) {
	if s == "" {
		return
	}
	hit.Detail["payload"] = modules.Clip(s, 4096)
	if urls := uniq(urlRe.FindAllString(s, 20), 10); len(urls) > 0 {
		hit.Detail["urls"] = urls
		hit.Signals = appendNew(hit.Signals, "remote_url")
	}
	if ips := uniq(ipRe.FindAllString(s, 20), 10); len(ips) > 0 {
		hit.Detail["ips"] = ips
	}
	if sh := uniq(lower(shellRe.FindAllString(s, 20)), 10); len(sh) > 0 {
		hit.Detail["shell"] = sh
		hit.Signals = appendNew(hit.Signals, "shell_command")
	}
	low := strings.ToLower(s)
	for sig, needles := range map[string][]string{
		"python_exec": {"exec(", "eval(", "subprocess", "os.system", "os.popen", "__import__"},
		"node_exec":   {"child_process", "execsync", "require(", "process.mainmodule", "function("},
	} {
		for _, n := range needles {
			if strings.Contains(low, n) {
				hit.Signals = appendNew(hit.Signals, sig)
				break
			}
		}
	}
}

func lower(in []string) []string {
	for i := range in {
		in[i] = strings.ToLower(in[i])
	}
	return in
}

func uniq(in []string, n int) []string {
	var out []string
	for _, s := range in {
		s = modules.Clip(s, 200)
		if len(out) >= n {
			break
		}
		if !contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func appendNew(list []string, s string) []string {
	if contains(list, s) {
		return list
	}
	return append(list, s)
}
