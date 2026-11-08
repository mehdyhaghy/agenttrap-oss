package builtin

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"agenttrap/modules"
)

func TestSelect(t *testing.T) {
	if all, _ := Select("all"); len(all) != len(All()) {
		t.Fatal("all")
	}
	if none, _ := Select("none"); len(none) != 0 {
		t.Fatal("none")
	}
	if m, err := Select(" php2shell "); err != nil || len(m) != 1 || m[0].Name() != "php2shell" {
		t.Fatalf("by name: %v %v", m, err)
	}
	if _, err := Select("nope"); err == nil {
		t.Fatal("unknown module accepted")
	}
}

func TestNamesUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, m := range All() {
		if seen[m.Name()] {
			t.Fatalf("duplicate module %s", m.Name())
		}
		seen[m.Name()] = true
	}
}

func TestPriority(t *testing.T) {
	cases := map[string]string{
		"/cgi-bin/.%2e/.%2e/.%2e/.env": "traversal",
		"/@fs/app/.env?raw??":          "traversal",
		"/alfa.php":                    "webshell",
		"/api/tags":                    "aiplatforms",
		"/.env":                        "secretfiles",
		"/phpinfo.php":                 "php2shell",
		"/":                            "php2shell",
	}
	for target, want := range cases {
		r := httptest.NewRequest("GET", "http://203.0.113.9/", nil)
		r.RequestURI = target
		r.URL, _ = url.ParseRequestURI(target)
		m := modules.Pick(All(), modules.Request{Request: r})
		if m == nil || m.Name() != want {
			t.Errorf("%s: picked %v, want %s", target, m, want)
		}
	}
	// A persona's own page is left to the persona.
	r := httptest.NewRequest("GET", "https://www.demogpu.example/pricing", nil)
	if m := modules.Pick(All(), modules.Request{Request: r, Surface: "www"}); m != nil {
		t.Errorf("persona page claimed by %s", m.Name())
	}
}
