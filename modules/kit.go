package modules

import (
	"bytes"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
)

// Helpers shared by modules. Each module keeps its own signatures and fake
// content; only plumbing every trap needs lives here.

// WebSurface reports whether a module may answer on surface: the default
// virtual host ("") and the persona's HTML sites. API-shaped surfaces (api,
// vllm, mcp, aws, k8s) keep their own protocol answers.
func WebSurface(surface string) bool {
	switch surface {
	case "", "www", "docs", "console", "status":
		return true
	}
	return false
}

// NotFound writes nginx's 404 page, the same one the persona serves.
func NotFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n")
}

// DrainLimit bounds how much of any body a module reads in total.
const DrainLimit = 64 << 20

// ReadBody returns up to limit bytes of the body and the total size read,
// draining (and discarding) the rest up to DrainLimit.
func ReadBody(r *http.Request, limit int64) (sample []byte, total int64) {
	if r.Body == nil {
		return nil, 0
	}
	sample, _ = io.ReadAll(io.LimitReader(r.Body, limit))
	rest, _ := io.Copy(io.Discard, io.LimitReader(r.Body, DrainLimit-int64(len(sample))))
	return sample, int64(len(sample)) + rest
}

// Field is one submitted form or query parameter.
type Field struct{ Name, Value string }

// Fields parses a urlencoded or multipart body (and the query string) into
// fields; file parts appear with Value set to "file:" + filename.
func Fields(r *http.Request, body []byte) []Field {
	var out []Field
	for k, vs := range r.URL.Query() {
		for _, v := range vs {
			out = append(out, Field{k, v})
		}
	}
	ct, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch ct {
	case "application/x-www-form-urlencoded":
		if q, err := url.ParseQuery(string(body)); err == nil {
			for k, vs := range q {
				for _, v := range vs {
					out = append(out, Field{k, v})
				}
			}
		}
	case "multipart/form-data":
		mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
		for {
			p, err := mr.NextPart()
			if err != nil {
				break
			}
			if fn := p.FileName(); fn != "" {
				out = append(out, Field{p.FormName(), "file:" + fn})
			} else {
				v, _ := io.ReadAll(io.LimitReader(p, 4096))
				out = append(out, Field{p.FormName(), string(v)})
			}
			_ = p.Close()
		}
	}
	return out
}

// Clip shortens s to n bytes of valid UTF-8 for recording.
func Clip(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return strings.ToValidUTF8(s, "�")
}
