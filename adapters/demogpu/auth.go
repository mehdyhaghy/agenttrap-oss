package demogpu

import (
	"net/http"
	"slices"
)

// access is what a presented bearer credential allows: a DemoGPU API key
// grants the whole team, an OAuth access token its scopes.
type access struct {
	ok      bool
	apiKey  bool
	scopes  []string
	subject string
}

func (a access) can(scope string) bool {
	return a.ok && (a.apiKey || scope == "" || slices.Contains(a.scopes, scope))
}

// access records the request's bearer credential and reports what it allows.
func (s *Server) access(r *http.Request, where string) access {
	return s.accessFor(r, bearer(r), where)
}

func (s *Server) accessFor(r *http.Request, token, where string) access {
	if token == "" {
		return access{}
	}
	slot := s.credential(r, token, where)
	switch {
	case isAPIKey(slot):
		return access{ok: true, apiKey: true, subject: "api_key"}
	case slot != "" && slot == s.pack.OAuth.TokenSlot:
		if g, ok := s.grantFor(token); ok {
			return access{ok: true, scopes: g.Scopes, subject: g.Subject}
		}
	}
	return access{}
}
