package demogpu

import (
	"embed"
	"net/http"
)

// static/assets/app.js is built from site/rum (bun run build in site/).
//
//go:embed all:static
var staticFS embed.FS

func serveAppJS(w http.ResponseWriter, r *http.Request) {
	data, err := staticFS.ReadFile("static/assets/app.js")
	if err != nil {
		notFound(w)
		return
	}
	w.Header().Set("Content-Type", "application/javascript")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(data)
}
