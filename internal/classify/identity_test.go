package classify

import "testing"

func TestParseIdentity(t *testing.T) {
	cases := []struct {
		ua                           string
		name, version, url, email, d string
	}{
		{"Mozilla/5.0 (l9scan/2.0.331313e2436313e21373e2736313; +https://leakix.net)", "l9scan", "2.0.331313e2436313e21373e2736313", "https://leakix.net", "", "scanner"},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)", "ClaudeBot", "1.0", "", "claudebot@anthropic.com", "crawler"},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)", "GPTBot", "1.2", "https://openai.com/gptbot", "", "crawler"},
		{"Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot", "ChatGPT-User", "1.0", "https://openai.com/bot", "", "ai_agent"},
		{"Mozilla/5.0 (compatible; Databot)", "Databot", "", "", "", "crawler"},
		{"curl/8.7.1", "curl", "8.7.1", "", "", "library"},
		{"OpenAI/Python 1.99.0", "OpenAI/Python", "1.99.0", "", "", "ai_agent"},
	}
	for _, c := range cases {
		id := ParseIdentity(c.ua)
		if id == nil {
			t.Errorf("%q: no identity", c.ua)
			continue
		}
		if id.Name != c.name || id.Version != c.version || id.URL != c.url || id.Email != c.email || id.Declared != c.d {
			t.Errorf("%q: got %+v", c.ua, *id)
		}
	}
	if id := ParseIdentity("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"); id != nil {
		t.Errorf("browser declared an identity: %+v", *id)
	}
}
