package digest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMailjetSend(t *testing.T) {
	var got map[string]any
	var user, pass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ = r.BasicAuth()
		if !strings.HasSuffix(r.URL.Path, "/v3.1/send") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"Messages":[{"Status":"success","To":[{"Email":"admin@demogpu.example"}]}]}`))
	}))
	defer srv.Close()

	m := Mail{APIKey: "pub", SecretKey: "sec", From: "admin@demogpu.example", FromName: "DemoGPU", To: "admin@demogpu.example", BaseURL: srv.URL + "/v3"}
	if err := m.Send("subject", "text body", "<p>html</p>"); err != nil {
		t.Fatal(err)
	}
	if user != "pub" || pass != "sec" {
		t.Fatalf("auth: %q %q", user, pass)
	}
	msg := got["Messages"].([]any)[0].(map[string]any)
	if msg["Subject"] != "subject" || msg["TextPart"] != "text body" || msg["HTMLPart"] != "<p>html</p>" {
		t.Fatalf("payload: %+v", msg)
	}
	if err := (Mail{}).Send("s", "t", "h"); err == nil {
		t.Fatal("missing keys must fail")
	}
}
