package demogpu

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"agenttrap/internal/events"
)

// apiHandler is api.<domain>: the public OpenAI-compatible endpoint. The docs
// sample key is the only key that works.
func (s *Server) apiHandler() http.Handler {
	return s.openAIMux("api", func(r *http.Request, key string) bool { return s.accessFor(r, key, "api").ok })
}

// vllmHandler is vllm.<domain>: the "self-hosted vLLM cluster" that planted
// provider keys point at. Any use of its key is the final chain stage.
func (s *Server) vllmHandler() http.Handler {
	return s.openAIMux("vllm", func(r *http.Request, key string) bool {
		slot := s.credential(r, key, "vllm")
		return slot == SlotVLLMKey || slot == SlotRepoVLLMKey
	})
}

// openAIMux serves the OpenAI-compatible routes; valid records the presented
// key and reports whether it is accepted on this surface.
func (s *Server) openAIMux(surface string, valid func(r *http.Request, key string) bool) http.Handler {
	mux := http.NewServeMux()
	auth := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			key := bearer(r)
			if key == "" {
				openAIError(w, http.StatusUnauthorized, "missing_api_key",
					"You didn't provide an API key. Provide it in the Authorization header as 'Bearer YOUR_KEY'.")
				return
			}
			if !valid(r, key) {
				openAIError(w, http.StatusUnauthorized, "invalid_api_key", "Incorrect API key provided.")
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("GET /v1/models", auth(func(w http.ResponseWriter, r *http.Request) {
		type model struct {
			ID      string `json:"id"`
			Object  string `json:"object"`
			Created int64  `json:"created"`
			OwnedBy string `json:"owned_by"`
		}
		var data []model
		for _, m := range s.pack.Models {
			owner := m.OwnedBy
			if surface == "vllm" {
				owner = "vllm"
			}
			data = append(data, model{ID: m.ID, Object: "model", Created: m.Created, OwnedBy: owner})
		}
		writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
	}))
	mux.HandleFunc("POST /v1/chat/completions", auth(s.chatCompletions))
	mux.HandleFunc("POST /v1/completions", auth(s.chatCompletions))
	mux.HandleFunc("POST /v1/embeddings", auth(s.embeddings))
	if surface == "api" {
		mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.protectedResource("https://api."+s.domain+"/v1"))
		mux.HandleFunc("POST /v1/integrations", s.integrationRegister)
		mux.HandleFunc("POST /v1/agents/register", s.integrationRegister) // older path, may be cached
		mux.HandleFunc("POST /v1/trial-keys", s.trialKey)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if surface == "vllm" {
			writeJSON(w, http.StatusNotFound, map[string]string{"detail": "Not Found"})
			return
		}
		openAIError(w, http.StatusNotFound, "unknown_url", fmt.Sprintf("Unknown request URL: %s %s.", r.Method, r.URL.Path))
	})
	return mux
}

type chatRequest struct {
	Model    string `json:"model"`
	Stream   bool   `json:"stream"`
	Prompt   any    `json:"prompt"`
	Messages []struct {
		Role    string `json:"role"`
		Content any    `json:"content"`
	} `json:"messages"`
}

func (s *Server) chatCompletions(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req chatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		openAIError(w, http.StatusBadRequest, "invalid_request_error", "We could not parse the JSON body of your request.")
		return
	}
	if !s.knownModel(req.Model) {
		openAIError(w, http.StatusNotFound, "model_not_found", fmt.Sprintf("The model `%s` does not exist or you do not have access to it.", req.Model))
		return
	}
	// Record what the client asked for; prompts reveal intent.
	var last string
	for _, m := range req.Messages {
		if c, ok := m.Content.(string); ok {
			last = c
		}
	}
	s.emit(r, events.Event{Kind: events.KindToolCall, Detail: map[string]any{
		"op": "chat", "model": req.Model, "messages": len(req.Messages), "stream": req.Stream,
		"last_message": truncate(last, 2000)}})

	reply := s.reply(body)
	id := "chatcmpl-" + shortID(body)
	created := time.Now().Unix()
	// Inference takes time: queueing and prefill before the first token,
	// then decoding. An instant answer would give the facade away.
	if !pause(r, ttft(len(body))) {
		return
	}
	if req.Stream {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		words := strings.SplitAfter(reply, " ")
		for i, word := range words {
			delta := map[string]any{"content": word}
			if i == 0 {
				delta["role"] = "assistant"
			}
			chunk := map[string]any{"id": id, "object": "chat.completion.chunk", "created": created, "model": req.Model,
				"choices": []any{map[string]any{"index": 0, "delta": delta, "finish_reason": nil}}}
			writeSSE(w, chunk)
			if !pause(r, decodeTime()) {
				return
			}
		}
		writeSSE(w, map[string]any{"id": id, "object": "chat.completion.chunk", "created": created, "model": req.Model,
			"choices": []any{map[string]any{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"}}})
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
		return
	}
	promptTokens := len(body) / 4
	completionTokens := len(reply) / 4
	if !pause(r, time.Duration(completionTokens)*decodeTime()) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": id, "object": "chat.completion", "created": created, "model": req.Model,
		"choices": []any{map[string]any{"index": 0, "finish_reason": "stop",
			"message": map[string]any{"role": "assistant", "content": reply}}},
		"usage": map[string]int{"prompt_tokens": promptTokens, "completion_tokens": completionTokens,
			"total_tokens": promptTokens + completionTokens},
	})
}

func (s *Server) embeddings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Model string `json:"model"`
		Input any    `json:"input"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		openAIError(w, http.StatusBadRequest, "invalid_request_error", "We could not parse the JSON body of your request.")
		return
	}
	var inputs []string
	switch v := req.Input.(type) {
	case string:
		inputs = []string{v}
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok {
				inputs = append(inputs, s)
			}
		}
	}
	s.emit(r, events.Event{Kind: events.KindToolCall, Detail: map[string]any{"op": "embeddings", "model": req.Model, "inputs": len(inputs)}})
	if !pause(r, 30*time.Millisecond+time.Duration(rand.IntN(80))*time.Millisecond) {
		return
	}
	data := make([]any, len(inputs))
	tokens := 0
	for i, in := range inputs {
		data[i] = map[string]any{"object": "embedding", "index": i, "embedding": pseudoEmbedding(in, 1024)}
		tokens += len(in) / 4
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data, "model": req.Model,
		"usage": map[string]int{"prompt_tokens": tokens, "total_tokens": tokens}})
}

func (s *Server) knownModel(id string) bool {
	for _, m := range s.pack.Models {
		if m.ID == id {
			return true
		}
	}
	return false
}

// reply picks a frozen reply deterministically from the request.
func (s *Server) reply(body []byte) string {
	if len(s.pack.Replies) == 0 {
		return "OK."
	}
	sum := sha256.Sum256(body)
	return s.pack.Replies[binary.BigEndian.Uint32(sum[:4])%uint32(len(s.pack.Replies))]
}

// pseudoEmbedding returns a deterministic unit vector for text.
func pseudoEmbedding(text string, dim int) []float32 {
	out := make([]float32, dim)
	var norm float64
	for i := 0; i < dim; i += 8 {
		sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%s", i, text)))
		for j := 0; j < 8 && i+j < dim; j++ {
			v := float64(int32(binary.BigEndian.Uint32(sum[j*4:]))) / math.MaxInt32
			out[i+j] = float32(v)
			norm += v * v
		}
	}
	norm = math.Sqrt(norm)
	for i := range out {
		out[i] = float32(float64(out[i]) / norm)
	}
	return out
}

// ttft is a plausible time to first token for a prompt of n bytes: queueing
// and prefill on a shared GPU.
func ttft(n int) time.Duration {
	return 220*time.Millisecond + time.Duration(rand.IntN(380))*time.Millisecond + time.Duration(n/400)*time.Millisecond
}

// decodeTime is the time per generated token, 12 to 22 ms (45-80 tokens/s).
func decodeTime() time.Duration {
	return time.Duration(12+rand.IntN(10)) * time.Millisecond
}

// pause waits for d unless the client goes away first.
func pause(r *http.Request, d time.Duration) bool {
	t := time.NewTimer(min(d, 4*time.Second))
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-r.Context().Done():
		return false
	}
}

func shortID(b []byte) string {
	sum := sha256.Sum256(append(b, []byte(time.Now().String())...))
	return fmt.Sprintf("%x", sum[:12])
}

func openAIError(w http.ResponseWriter, status int, code, msg string) {
	typ := "invalid_request_error"
	writeJSON(w, status, map[string]any{"error": map[string]any{"message": msg, "type": typ, "param": nil, "code": code}})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeSSE(w http.ResponseWriter, v any) {
	data, _ := json.Marshal(v)
	_, _ = w.Write([]byte("data: "))
	_, _ = w.Write(data)
	_, _ = w.Write([]byte("\n\n"))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}
