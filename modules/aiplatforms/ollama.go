package aiplatforms

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"agenttrap/modules"
)

// An Ollama server left on the internet: free GPU inference for whoever
// finds it (LLMjacking). Listing models and the version is a probe; running a
// prompt, pulling or creating a model is abuse and recorded as an exploit.

const ollamaVersionString = "0.12.6"

type ollamaModel struct {
	Name, Family, Params, Quant string
	Size                        int64
	Digest                      string
	Modified                    string
}

var ollamaModels = []ollamaModel{
	{"llama3.1:70b", "llama", "70.6B", "Q4_K_M", 42520413916, "711a9e8463af2b2ee4a1a8b0e0f6d7b81ea5f8c5ad0f6b0d3b0fbd2d63b9a5a1", "2026-09-30T14:12:09.418027291Z"},
	{"qwen2.5-coder:32b", "qwen2", "32.8B", "Q4_K_M", 19851349856, "4bd6cbf2d094264457a17aab6bd6acd1ed7a72fb8f8be3cfb193f63c78dd56df", "2026-10-03T09:41:55.120941367Z"},
	{"deepseek-r1:32b", "qwen2", "32.8B", "Q4_K_M", 19851337640, "38056bbcbb2d068501ecb2d5ea9cea9dd4847465f1ab88c4d4a412a9f7792717", "2026-10-07T18:02:31.553210004Z"},
	{"nomic-embed-text:latest", "nomic-bert", "137M", "F16", 274302450, "0a109f422b47e3a30ba2b10eca18548e944e8a23073ee3f3e947efcf3c45e59f", "2026-08-21T11:20:47.006571139Z"},
}

func (m ollamaModel) tag() map[string]any {
	return map[string]any{
		"name": m.Name, "model": m.Name, "modified_at": m.Modified, "size": m.Size, "digest": m.Digest,
		"details": map[string]any{"parent_model": "", "format": "gguf", "family": m.Family,
			"families": []string{m.Family}, "parameter_size": m.Params, "quantization_level": m.Quant},
	}
}

func serveOllama(w http.ResponseWriter, r modules.Request, t target, body []byte, hit *modules.Hit) {
	hit.Attack = "Ollama exposure"
	hit.Stage = modules.StageProbe
	switch t {
	case ollamaTags:
		models := make([]any, 0, len(ollamaModels))
		for _, m := range ollamaModels {
			models = append(models, m.tag())
		}
		ollamaJSON(w, http.StatusOK, map[string]any{"models": models})
		return
	case ollamaVersion:
		ollamaJSON(w, http.StatusOK, map[string]any{"version": ollamaVersionString})
		return
	case ollamaPS:
		ollamaJSON(w, http.StatusOK, map[string]any{"models": []any{}})
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = w.Write([]byte("405 method not allowed"))
		return
	}
	var req struct {
		Model     string `json:"model"`
		Name      string `json:"name"`
		Prompt    string `json:"prompt"`
		System    string `json:"system"`
		From      string `json:"from"`
		Modelfile string `json:"modelfile"`
		Stream    *bool  `json:"stream"`
		Messages  []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		} `json:"messages"`
	}
	_ = json.Unmarshal(body, &req)
	model := firstNonEmpty(req.Model, req.Name)
	if model != "" {
		hit.Detail["model"] = modules.Clip(model, 120)
	}
	stream := req.Stream == nil || *req.Stream
	switch t {
	case ollamaShow:
		m, ok := findModel(model)
		if !ok {
			ollamaJSON(w, http.StatusNotFound, map[string]any{"error": fmt.Sprintf("model '%s' not found", modules.Clip(model, 120))})
			return
		}
		ollamaJSON(w, http.StatusOK, map[string]any{"modelfile": "FROM " + m.Name + "\n", "parameters": "stop \"<|eot_id|>\"",
			"template": "{{ .Prompt }}", "details": m.tag()["details"], "modified_at": m.Modified})
		return
	case ollamaPull, ollamaCreate:
		hit.Stage = modules.StageExploit
		hit.Signals = appendNew(hit.Signals, map[target]string{ollamaPull: "model_pull", ollamaCreate: "model_create"}[t])
		if req.From != "" {
			hit.Detail["from"] = modules.Clip(req.From, 200)
		}
		indicators(req.Modelfile, hit)
		ollamaStatus(w, stream, []string{"pulling manifest", "success"})
		return
	}
	// generate / chat: someone is spending our GPUs.
	hit.Stage = modules.StageExploit
	hit.Signals = appendNew(hit.Signals, "inference")
	var prompt strings.Builder
	if req.System != "" {
		prompt.WriteString("[system] " + req.System + "\n")
	}
	prompt.WriteString(req.Prompt)
	for _, m := range req.Messages {
		fmt.Fprintf(&prompt, "[%s] %s\n", m.Role, m.Content)
	}
	if p := strings.TrimSpace(prompt.String()); p != "" {
		hit.Detail["prompt"] = modules.Clip(p, 4096)
		if urls := uniq(urlRe.FindAllString(p, 20), 10); len(urls) > 0 {
			hit.Detail["urls"] = urls
		}
	}
	if _, ok := findModel(model); !ok {
		ollamaJSON(w, http.StatusNotFound, map[string]any{"error": fmt.Sprintf("model \"%s\" not found, try pulling it first", modules.Clip(model, 120))})
		return
	}
	reply := "I'm sorry, I can't help with that right now. Please try again later."
	if t == ollamaChat {
		ollamaReply(w, stream, model, reply, func(part string, done bool) map[string]any {
			return map[string]any{"message": map[string]any{"role": "assistant", "content": part}}
		})
		return
	}
	ollamaReply(w, stream, model, reply, func(part string, done bool) map[string]any {
		return map[string]any{"response": part}
	})
}

func findModel(name string) (ollamaModel, bool) {
	if name != "" && !strings.Contains(name, ":") {
		name += ":latest"
	}
	for _, m := range ollamaModels {
		if m.Name == name {
			return m, true
		}
	}
	return ollamaModel{}, false
}

func ollamaJSON(w http.ResponseWriter, status int, v any) {
	b, _ := json.Marshal(v)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// ollamaReply writes the answer as one JSON object, or as NDJSON chunks
// ending in a done record, the way /api/generate and /api/chat stream.
func ollamaReply(w http.ResponseWriter, stream bool, model, text string, shape func(part string, done bool) map[string]any) {
	final := func(part string) map[string]any {
		obj := shape(part, true)
		obj["model"], obj["created_at"], obj["done"], obj["done_reason"] = model, now(), true, "stop"
		obj["total_duration"], obj["load_duration"], obj["eval_count"] = int64(2310442750), int64(21894125), len(strings.Fields(text))+4
		return obj
	}
	if !stream {
		ollamaJSON(w, http.StatusOK, final(text))
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	for _, word := range strings.SplitAfter(text, " ") {
		obj := shape(word, false)
		obj["model"], obj["created_at"], obj["done"] = model, now(), false
		_ = enc.Encode(obj)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		time.Sleep(15 * time.Millisecond)
	}
	_ = enc.Encode(final(""))
}

func ollamaStatus(w http.ResponseWriter, stream bool, steps []string) {
	if !stream {
		ollamaJSON(w, http.StatusOK, map[string]any{"status": steps[len(steps)-1]})
		return
	}
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	for _, s := range steps {
		_ = enc.Encode(map[string]any{"status": s})
	}
}
