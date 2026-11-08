package secretfiles

import (
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"agenttrap/modules"
)

func req(method, target, surface string, reveal func(string) string) modules.Request {
	return modules.Request{Request: httptest.NewRequest(method, target, nil), Surface: surface, Reveal: reveal}
}

func TestClaim(t *testing.T) {
	m := New()
	cases := []struct {
		path, surface string
		want          modules.Claim
	}{
		{"/.env", "", modules.Attack},
		{"/.env.production", "www", modules.Attack},
		{"/api/.env", "docs", modules.Attack},
		{"/laravel/.ENV.bak", "", modules.Attack},
		{"/%00cgi-bin/%00.env", "", modules.Attack},
		{"/.git/config", "", modules.Attack},
		{"/www/.git/config", "", modules.Attack},
		{"/.git/HEAD", "", modules.Attack},
		{"/.git/logs/HEAD", "", modules.Attack},
		{"/.git-credentials", "", modules.Attack},
		{"/.aws/credentials", "", modules.Attack},
		{"/.aws/config", "", modules.Attack},
		{"/docker-compose.yml", "", modules.Attack},
		{"/Dockerfile", "", modules.Attack},
		{"/credentials.json", "", modules.Attack},
		{"/secrets.json", "", modules.Attack},
		{"/config.json", "", modules.Attack},
		{"/config.js", "", modules.Attack},
		{"/.npmrc", "", modules.Attack},
		{"/.gitlab-ci.yml", "", modules.Attack},
		{"/.github/workflows/deploy.yml", "", modules.Attack},
		{"/%00wp-config.php.bak", "", modules.Attack},
		{"/wp-config.php~", "", modules.Attack},
		{"/wp-config.php", "", modules.Pass},
		{"/.env", "api", modules.Pass},
		{"/.env", "aws", modules.Pass},
		{"/@fs/.env", "", modules.Pass},
		{"/@fs/%252e%252e/etc/passwd", "", modules.Pass},
		{"/litellm_config.yaml", "", modules.Pass},
		{"/litellm/.env", "", modules.Pass},
		{"/.envrc", "", modules.Pass},
		{"/env", "", modules.Pass},
		{"/", "", modules.Pass},
		{"/index.php", "", modules.Pass},
	}
	for _, c := range cases {
		if got := m.Claim(req("GET", "http://203.0.113.9"+c.path, c.surface, nil)); got != c.want {
			t.Errorf("%s on %q: claim %v, want %v", c.path, c.surface, got, c.want)
		}
	}
}

// fakeReveal returns recognizable canaries and records the slots asked for.
func fakeReveal(asked *[]string) func(string) string {
	return func(slot string) string {
		*asked = append(*asked, slot)
		if slot == "kube_token" {
			return "" // a slot the persona lacks
		}
		return "CANARY-" + slot
	}
}

func TestEnvCarriesCanaries(t *testing.T) {
	var asked []string
	w := httptest.NewRecorder()
	hit := New().Serve(w, req("GET", "https://www.demogpu.example/.env", "www", fakeReveal(&asked)))
	body := w.Body.String()
	want := []string{"provider_key_vllm", "docs_sample_key", "aws_access_key_id", "pg_app_password", "redis_session_token", "hf_token"}
	for _, slot := range want {
		if !strings.Contains(body, "CANARY-"+slot) {
			t.Errorf(".env lacks %s", slot)
		}
		if n := strings.Count(strings.Join(asked, " "), slot); n != 1 {
			t.Errorf("%s revealed %d times, want once", slot, n)
		}
	}
	slots, _ := hit.Detail["slots"].([]string)
	if len(slots) != len(want) || hit.Stage != modules.StageProbe || hit.Signals[0] != famEnv {
		t.Fatalf("hit = %+v", hit)
	}
	if !strings.Contains(body, "api.demogpu.example") && !strings.Contains(body, "vllm.demogpu.example") {
		t.Error("persona .env does not mention persona hosts")
	}
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/octet-stream" || w.Header().Get("ETag") == "" {
		t.Fatalf("headers: %d %v", w.Code, w.Header())
	}
}

func TestOnlyContainedSlotsRevealed(t *testing.T) {
	var asked []string
	New().Serve(httptest.NewRecorder(), req("GET", "http://203.0.113.9/.aws/credentials", "", fakeReveal(&asked)))
	if !slices.Equal(asked, []string{"aws_access_key_id"}) {
		t.Fatalf("revealed %v", asked)
	}
	asked = nil
	w := httptest.NewRecorder()
	hit := New().Serve(w, req("GET", "http://203.0.113.9/.git/HEAD", "", fakeReveal(&asked)))
	if len(asked) != 0 || w.Body.String() != "ref: refs/heads/main\n" || hit.Detail["slots"] != nil {
		t.Fatalf("HEAD file revealed %v: %q", asked, w.Body.String())
	}
}

func TestFallbacksWithoutPersona(t *testing.T) {
	w := httptest.NewRecorder()
	New().Serve(w, req("GET", "http://203.0.113.9/.env", "", nil))
	body := w.Body.String()
	for _, prefix := range []string{"OPENAI_API_KEY=sk-demo-", "AWS_ACCESS_KEY_ID=AKIA", "HF_TOKEN=hf_", "postgres://app:pg_", "ops-portal"} {
		if !strings.Contains(body, prefix) {
			t.Errorf("fallback .env lacks %q:\n%s", prefix, body)
		}
	}
	// Stable for the same path.
	w2 := httptest.NewRecorder()
	New().Serve(w2, req("GET", "http://203.0.113.9/.env", "", nil))
	if w2.Body.String() != body {
		t.Error("fallback content changes between requests")
	}
}

func TestGitFiles(t *testing.T) {
	var asked []string
	w := httptest.NewRecorder()
	New().Serve(w, req("GET", "https://www.demogpu.example/.git/config", "www", fakeReveal(&asked)))
	if !strings.Contains(w.Body.String(), "url = https://deploy:CANARY-ssh_deploy_password@github.com/demogpu/platform.git") {
		t.Fatalf("git config: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	New().Serve(w, req("GET", "http://203.0.113.9/.git/logs/HEAD", "", nil))
	if lines := strings.Split(strings.TrimSpace(w.Body.String()), "\n"); len(lines) != 4 || !strings.HasPrefix(lines[0], "0000000000000000000000000000000000000000 ") {
		t.Fatalf("git log: %q", w.Body.String())
	}
}

func TestHeadAndPost(t *testing.T) {
	var asked []string
	w := httptest.NewRecorder()
	New().Serve(w, req("HEAD", "https://www.demogpu.example/.env", "www", fakeReveal(&asked)))
	if len(asked) != 0 || w.Code != 200 || w.Body.Len() != 0 || w.Header().Get("Content-Length") == "" {
		t.Fatalf("HEAD revealed %v, code %d body %d", asked, w.Code, w.Body.Len())
	}
	w = httptest.NewRecorder()
	hit := New().Serve(w, req("POST", "http://203.0.113.9/.env", "", fakeReveal(&asked)))
	if w.Code != 405 || len(asked) != 0 || hit.Stage != modules.StageProbe {
		t.Fatalf("POST: %d %v", w.Code, asked)
	}
}

func TestEveryFamilyRenders(t *testing.T) {
	for _, p := range []string{"/.env", "/.git/config", "/.git/HEAD", "/.git/logs/HEAD", "/.git-credentials", "/.aws/credentials",
		"/.aws/config", "/docker-compose.yml", "/Dockerfile", "/credentials.json", "/secrets.json", "/config.json", "/config.js",
		"/.npmrc", "/.gitlab-ci.yml", "/.github/workflows/deploy.yml", "/wp-config.php.bak"} {
		w := httptest.NewRecorder()
		New().Serve(w, req("GET", "http://203.0.113.9"+p, "", nil))
		if w.Code != 200 || w.Body.Len() < 15 {
			t.Errorf("%s: %d %q", p, w.Code, w.Body.String())
		}
	}
}
