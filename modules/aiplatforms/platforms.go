package aiplatforms

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"agenttrap/modules"
)

// Langflow: both endpoints run attacker Python (validate/code through a
// function default argument or decorator, build_public_tmp through a custom
// component in the flow data). A vulnerable instance answers validate/code
// with empty error lists and build_public_tmp with a job id.
func serveLangflow(w http.ResponseWriter, r modules.Request, t target, body []byte, hit *modules.Hit) {
	w.Header().Set("Server", "uvicorn")
	hit.Attack = "Langflow RCE"
	if r.Method != http.MethodPost {
		hit.Stage = modules.StageProbe
		methodNotAllowed(w, true, r.Method, r.URL.Path)
		return
	}
	hit.Stage = modules.StageExploit
	if t == langflowValidate {
		hit.CVE = []string{cveLangflowValidate}
		var req struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(body, &req)
		indicators(firstNonEmpty(req.Code, string(body)), hit)
		writeJSON(w, http.StatusOK, map[string]any{"imports": map[string]any{"errors": []any{}}, "function": map[string]any{"errors": []any{}}})
		return
	}
	hit.CVE = []string{cveLangflowBuild}
	indicators(string(body), hit)
	writeJSON(w, http.StatusOK, map[string]any{"job_id": uuid()})
}

// Flowise: customMCP evaluates mcpServerConfig through Function(); the
// custom-function endpoint runs javascriptFunction in an escapable NodeVM.
func serveFlowise(w http.ResponseWriter, r modules.Request, t target, body []byte, hit *modules.Hit) {
	w.Header().Set("X-Powered-By", "Express")
	hit.Attack = "Flowise RCE"
	if r.Method != http.MethodPost {
		hit.Stage = modules.StageProbe
		methodNotAllowed(w, false, r.Method, r.URL.Path)
		return
	}
	hit.Stage = modules.StageExploit
	var req struct {
		Inputs struct {
			MCPServerConfig string `json:"mcpServerConfig"`
		} `json:"inputs"`
		JavascriptFunction string `json:"javascriptFunction"`
	}
	_ = json.Unmarshal(body, &req)
	if t == flowiseMCP {
		hit.CVE = []string{cveFlowiseMCP}
		indicators(firstNonEmpty(req.Inputs.MCPServerConfig, string(body)), hit)
		// The vulnerable loader lists the MCP server's tools; with none
		// reachable it returns an empty list.
		writeJSON(w, http.StatusOK, []any{})
		return
	}
	hit.CVE = []string{cveFlowiseFunction}
	indicators(firstNonEmpty(req.JavascriptFunction, string(body)), hit)
	writeJSON(w, http.StatusOK, "")
}

// Feast: /read-document returns the contents of any path the server can read.
func serveFeast(w http.ResponseWriter, r modules.Request, body []byte, hit *modules.Hit) {
	w.Header().Set("Server", "uvicorn")
	hit.Attack = "Feast file read"
	hit.CVE = []string{cveFeastRead}
	if r.Method != http.MethodPost {
		hit.Stage = modules.StageProbe
		methodNotAllowed(w, true, r.Method, r.URL.Path)
		return
	}
	hit.Stage = modules.StageExploit
	var req map[string]any
	_ = json.Unmarshal(body, &req)
	path := ""
	for _, k := range []string{"file_path", "path", "document_path", "file"} {
		if v, ok := req[k].(string); ok && v != "" {
			path = v
			break
		}
	}
	if path == "" {
		indicators(string(body), hit)
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"detail": []any{map[string]any{
			"type": "missing", "loc": []any{"body", "file_path"}, "msg": "Field required", "input": req}}})
		return
	}
	hit.Detail["file"] = modules.Clip(path, 300)
	content, ok := fakeFile(path)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"detail": "File not found: " + modules.Clip(path, 300)})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"file_path": path, "content": content})
}

// fakeFile returns believable contents for the files file-read exploits
// fetch first.
func fakeFile(path string) (string, bool) {
	switch {
	case strings.HasSuffix(path, "/etc/passwd"):
		return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\nfeast:x:1000:1000::/home/feast:/bin/sh\n", true
	case strings.HasSuffix(path, "/etc/hostname"):
		return "feast-feature-server-7c9d5b6f4-x2kqp\n", true
	case strings.HasSuffix(path, "/proc/self/environ"):
		return "PATH=/usr/local/bin:/usr/bin:/bin\x00HOSTNAME=feast-feature-server-7c9d5b6f4-x2kqp\x00FEAST_USAGE=False\x00HOME=/home/feast\x00", true
	}
	return "", false
}

// LiteLLM: a proxy config left in the web root. The provider keys are the
// persona's canaries, minted per exposure.
func serveLiteLLM(w http.ResponseWriter, r modules.Request, hit *modules.Hit) {
	hit.Attack = "LiteLLM config leak"
	hit.Stage = modules.StageProbe
	hit.Signals = []string{"config_read"}
	vllm := r.Canary("provider_key_vllm", "sk-demo-"+randHex(24))
	master := r.Canary("docs_sample_key", "sk-"+randHex(24))
	hit.Detail["exposed"] = []string{"provider_key_vllm", "docs_sample_key"}
	cfg := fmt.Sprintf(`model_list:
  - model_name: llama-3.1-70b
    litellm_params:
      model: hosted_vllm/meta-llama/Llama-3.1-70B-Instruct
      api_base: https://vllm.demogpu.example/v1
      api_key: %[1]s
  - model_name: qwen2.5-coder-32b
    litellm_params:
      model: hosted_vllm/Qwen/Qwen2.5-Coder-32B-Instruct
      api_base: https://vllm.demogpu.example/v1
      api_key: %[1]s
  - model_name: gpt-4o
    litellm_params:
      model: openai/gpt-4o
      api_base: https://api.demogpu.example/v1
      api_key: %[2]s

litellm_settings:
  drop_params: true
  request_timeout: 600

general_settings:
  master_key: %[2]s
  database_url: os.environ/DATABASE_URL
`, vllm, master)
	w.Header().Set("Content-Type", "application/x-yaml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(cfg))
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func randHex(n int) string {
	b := make([]byte, (n+1)/2)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)[:n]
}

func uuid() string {
	h := randHex(32)
	return h[:8] + "-" + h[8:12] + "-4" + h[13:16] + "-a" + h[17:20] + "-" + h[20:]
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }
