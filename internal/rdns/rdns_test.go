package rdns

import "testing"

func TestClaimedAndVerified(t *testing.T) {
	g, ok := Claimed("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
	if !ok || g.Name != "Google" {
		t.Fatal("googlebot not recognised")
	}
	if _, ok := Claimed("Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"); ok {
		t.Fatal("GPTBot has no rDNS convention and must be unverifiable")
	}
	good := Result{IP: "66.249.66.1", Confirmed: []string{"crawl-66-249-66-1.googlebot.com"}}
	if h, ok := Verified(good, g); !ok || h == "" {
		t.Fatal("real googlebot not verified")
	}
	// A hostname that only contains the domain as a substring must not pass.
	fake := Result{IP: "203.0.113.9", Confirmed: []string{"googlebot.com.evil.example"}}
	if _, ok := Verified(fake, g); ok {
		t.Fatal("suffix check bypassed")
	}
	// Reverse DNS alone (not forward-confirmed) is not proof.
	unconfirmed := Result{IP: "203.0.113.9", Hostnames: []string{"crawl.googlebot.com"}}
	if _, ok := Verified(unconfirmed, g); ok {
		t.Fatal("unconfirmed PTR accepted")
	}
}

func TestNetwork(t *testing.T) {
	cases := map[string]string{
		"ec2-3-80-1-2.compute-1.amazonaws.com":      "AWS",
		"crawl-66-249-66-1.googlebot.com":           "Google (crawler)",
		"static.12.34.56.78.clients.your-server.de": "Hetzner",
		"c-73-1-2-3.hsd1.ca.comcast.net":            "Comcast (residential)",
		"host.example.org":                          "example.org",
		"":                                          "",
	}
	for host, want := range cases {
		if got := Network(host); got != want {
			t.Errorf("%q: got %q want %q", host, got, want)
		}
	}
}
