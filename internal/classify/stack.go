package classify

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Checks of a request's user agent against the TLS handshake and TCP stack
// of the connection that carried it. A client that sends a browser user
// agent from an HTTP library (Python, Go, Node) gives itself away here.
//
// TLS-inspecting corporate proxies and relays that re-originate connections
// can also fail these checks, so they add supporting reasons and score but
// never decide a class on their own for a client with human input.

var (
	chromeVersion  = regexp.MustCompile(`\bChrome/(\d+)`)
	firefoxVersion = regexp.MustCompile(`\bFirefox/(\d+)`)
)

// uaBrowser returns the browser engine a user agent claims ("chromium" or
// "firefox") and its major version, or "" for anything else. Chrome on iOS
// uses Apple's network stack and is not checked.
func uaBrowser(ua string) (string, int) {
	if strings.Contains(ua, "CriOS") || strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad") {
		return "", 0
	}
	if m := chromeVersion.FindStringSubmatch(ua); m != nil {
		v, _ := strconv.Atoi(m[1])
		return "chromium", v
	}
	if m := firefoxVersion.FindStringSubmatch(ua); m != nil {
		v, _ := strconv.Atoi(m[1])
		return "firefox", v
	}
	return "", 0
}

// uaOS returns the network stack family a user agent's platform implies.
// Safari on Apple platforms is skipped: iCloud Private Relay re-originates
// its connections from Apple's relays.
func uaOS(ua string) string {
	switch {
	case strings.Contains(ua, "Windows NT"):
		return "windows"
	case strings.Contains(ua, "Android") || strings.Contains(ua, "X11; Linux") || strings.Contains(ua, "CrOS"):
		return "linux"
	case strings.Contains(ua, "Macintosh") && chromeVersion.MatchString(ua):
		return "apple"
	}
	return ""
}

var osNames = map[string]string{"windows": "Windows", "linux": "Linux", "apple": "macOS/iOS"}

// stackMismatches returns why a request's connection does not match the
// client its user agent claims. d is the request detail; without handshake
// facts (no packet sensor, plain HTTP) it returns nothing.
func stackMismatches(ua string, d map[string]any) (tls, tcp []string) {
	if _, ok := d["tls_grease"]; ok {
		flag := func(k string) bool { v, _ := d[k].(bool); return v }
		switch engine, v := uaBrowser(ua); engine {
		case "chromium":
			name := fmt.Sprintf("Chrome %d", v)
			if v >= 60 && !flag("tls_grease") {
				tls = append(tls, name+" but its TLS handshake has no GREASE values")
			}
			if v >= 60 && !flag("tls_h2") {
				tls = append(tls, name+" but its TLS handshake does not offer HTTP/2")
			}
			if v >= 117 && !flag("tls_ech") {
				tls = append(tls, name+" but its TLS handshake has no Encrypted Client Hello extension")
			}
			if v >= 131 && !flag("tls_pq") {
				tls = append(tls, name+" but its TLS handshake offers no post-quantum key exchange")
			}
			if v >= 91 && !flag("tls_alps") {
				tls = append(tls, name+" but its TLS handshake lacks Chromium's application_settings extension")
			}
		case "firefox":
			if flag("tls_grease") {
				tls = append(tls, fmt.Sprintf("Firefox %d but its TLS handshake has GREASE values (Firefox never sends them)", v))
			}
		}
	}
	if stack, _ := d["tcp_os"].(string); stack != "" {
		if claim := uaOS(ua); claim != "" && claim != stack {
			tcp = append(tcp, fmt.Sprintf("%s but connected from a %s TCP stack (TTL %v, options %v)",
				osNames[claim], osNames[stack], d["tcp_ttl"], d["tcp_options"]))
		}
	}
	return tls, tcp
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
