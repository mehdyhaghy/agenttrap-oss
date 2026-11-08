// Package dashboard serves the admin web UI compiled from web/ into dist/.
package dashboard

import (
	"embed"
	"io/fs"
	"net/http"
	"path"
	"strings"
)

//go:embed all:dist
var distFS embed.FS

// Handler serves the single-page app. Unknown paths fall back to index.html
// so client-side routes work on reload. The UI holds no data itself; every
// API call it makes needs the admin token.
func Handler() http.Handler {
	root, _ := fs.Sub(distFS, "dist")
	files := http.FileServer(http.FS(root))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")

		name := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
		if name == "" {
			name = "index.html"
		}
		if _, err := fs.Stat(root, name); err != nil {
			name = "index.html"
		}
		if _, err := fs.Stat(root, "index.html"); err != nil {
			http.Error(w, "dashboard not built: run `bun run build` in web/", http.StatusNotFound)
			return
		}
		if name == "index.html" {
			h.Set("Cache-Control", "no-store")
			http.ServeFileFS(w, r, root, "index.html")
			return
		}
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
		files.ServeHTTP(w, r)
	})
}
