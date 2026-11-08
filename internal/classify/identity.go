package classify

import (
	"regexp"
	"strings"
)

// Identity is what a client says it is in its user agent: the product name
// and version, and the contact its operator publishes.
type Identity struct {
	Name     string `json:"name"`
	Version  string `json:"version,omitempty"`
	URL      string `json:"url,omitempty"`
	Email    string `json:"email,omitempty"`
	Declared string `json:"declared"` // ai_agent, crawler, scanner, library, other
}

var (
	idURL   = regexp.MustCompile(`\+?(https?://[^\s;)"]+)`)
	idEmail = regexp.MustCompile(`[\w.+-]+@[\w-]+(?:\.[\w-]+)+`)
	// Product tokens: Name/1.2.3 or Name-Sub/1.0.
	idToken = regexp.MustCompile(`([A-Za-z][\w.\-]*)/(\d[\w.\-]*)`)
	idSDK   = regexp.MustCompile(`^([A-Za-z][\w.\-]*/[A-Za-z]+) (\d[\w.\-]*)`)
	// Browser engine and platform tokens that are never the client's own name.
	idGeneric = map[string]bool{
		"mozilla": true, "applewebkit": true, "chrome": true, "safari": true, "gecko": true, "firefox": true,
		"version": true, "mobile": true, "edg": true, "opr": true, "khtml": true, "trident": true, "like": true,
		"crios": true, "fxios": true, "headlesschrome": false,
	}
)

// ParseIdentity extracts a declared identity from a user agent. It returns
// nil for plain browser user agents, which declare nothing about the client.
func ParseIdentity(ua string) *Identity {
	if ua == "" {
		return nil
	}
	decl := declared(ua)
	if decl == "browser" || decl == "none" {
		return nil
	}
	id := &Identity{Declared: decl}
	if m := idURL.FindStringSubmatch(ua); m != nil {
		id.URL = strings.TrimRight(m[1], ".,")
	}
	if m := strings.TrimLeft(idEmail.FindString(ua), "+"); m != "" && !strings.Contains(id.URL, m) {
		id.Email = m
	}
	// SDK style: "OpenAI/Python 1.99.0" (name/language version).
	if m := idSDK.FindStringSubmatch(ua); m != nil {
		id.Name, id.Version = m[1], m[2]
		return id
	}
	// Prefer the first non-generic product token; for "compatible; X/1.0"
	// style strings that is the bot's own name.
	for _, m := range idToken.FindAllStringSubmatch(ua, -1) {
		if idGeneric[strings.ToLower(m[1])] {
			continue
		}
		id.Name, id.Version = m[1], m[2]
		break
	}
	if id.Name == "" {
		// Names without a version, e.g. "Mozilla/5.0 (compatible; Databot)".
		if m := regexp.MustCompile(`compatible;\s*([A-Za-z][\w.\-]*)`).FindStringSubmatch(ua); m != nil {
			id.Name = m[1]
		}
	}
	if id.Name == "" && id.URL == "" && id.Email == "" {
		return nil
	}
	return id
}
