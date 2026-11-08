package demogpu

import (
	"io"
	"net/http"
	"strings"
)

// Each host serves its own robots.txt. Trap paths appear only there: a
// request for one means the client read robots.txt and went exactly where it
// was asked not to. Legitimate crawlers respect these rules.
type robotsPolicy struct {
	disallow []string // listed in robots.txt
	traps    []string // subset linked from nowhere else
}

var robotsBySurface = map[string]robotsPolicy{
	"www":     {disallow: []string{"/internal/", "/internal/billing-exports/", "/admin/"}, traps: []string{"/internal/billing-exports/"}},
	"docs":    {disallow: []string{"/drafts/"}, traps: []string{"/drafts/"}},
	"console": {disallow: []string{"/api/", "/admin/key-escrow/"}, traps: []string{"/admin/key-escrow/"}},
	"status":  {disallow: []string{"/incidents/private/"}, traps: []string{"/incidents/private/"}},
	"api":     {disallow: []string{"/v1/internal/", "/v1/admin/"}, traps: []string{"/v1/internal/", "/v1/admin/"}},
	"mcp":     {disallow: []string{"/ops/"}, traps: []string{"/ops/"}},
	"vllm":    {disallow: []string{"/metrics-private/"}, traps: []string{"/metrics-private/"}},
}

// hasRobots reports whether surface serves a robots.txt (the web surfaces do;
// the AWS endpoint does not, so its /robots.txt reaches the S3 handler).
func hasRobots(surface string) bool {
	_, ok := robotsBySurface[surface]
	return ok
}

func (s *Server) serveRobots(w http.ResponseWriter, surface string) {
	p := robotsBySurface[surface]
	var b strings.Builder
	b.WriteString("User-agent: *\n")
	for _, d := range p.disallow {
		b.WriteString("Disallow: " + d + "\n")
	}
	if surface == "www" {
		b.WriteString("\nSitemap: https://" + s.domain + "/sitemap.xml\n")
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = io.WriteString(w, b.String())
}

// robotsTrap returns the trap a path falls under on surface, if any.
func robotsTrap(surface, path string) string {
	for _, t := range robotsBySurface[surface].traps {
		if strings.HasPrefix(path, t) {
			return t
		}
	}
	return ""
}

// serveTrap answers a trap path the way the real surface would refuse it.
func serveTrap(w http.ResponseWriter, surface string) {
	switch surface {
	case "api", "vllm", "mcp":
		openAIError(w, http.StatusUnauthorized, "insufficient_permissions", "This endpoint requires an admin API key.")
	default:
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<html>\r\n<head><title>403 Forbidden</title></head>\r\n<body>\r\n<center><h1>403 Forbidden</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n"))
	}
}
