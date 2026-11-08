// Package php2shell traps scanners and exploits for PHP2Shell
// (CVE-2026-109618, CVE-2026-109619), the pre-auth PHP request-startup RCE
// pair fixed in PHP 8.2.35, 8.3.36, 8.4.27 and 8.5.12 on 2026-10-21.
//
// The module plays the server's default virtual host as a legacy nginx +
// PHP-FPM application one patch behind the fix (8.4.26), so version scanners
// see a target. Exploit-shaped requests are recognized on any hostname from
// their headers, then the body is inspected for the published indicators:
// upload-progress fields, PHPSESSID form fields, deeply nested field names,
// hundreds of parts, PHP or serialized objects in upload filenames, a single
// huge urlencoded field name, and oversized bodies. An exploit is answered the
// way a vulnerable worker with display_errors on answers it: 200 with a
// memory-exhaustion fatal error raised before any script ran.
package php2shell

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"agenttrap/modules"
)

const (
	// phpVersion is the last 8.4 release before the fix.
	phpVersion = "8.4.26"
	// memoryLimit is php.ini's default 128M, as phpinfo and the fatal error show it.
	memoryLimit = 128 << 20

	// inspectLimit bounds how much of a body is parsed; the rest is drained.
	inspectLimit = 4 << 20
	// drainLimit bounds how much is read in total before the connection is
	// dropped (exploits send 100 MB+ fill).
	drainLimit = 64 << 20
	// bigBody is the declared size that alone marks a POST as memory pressure.
	bigBody = 8 << 20
)

// Signal names recorded on hits.
const (
	sigUploadProgress = "upload_progress_field"
	sigSessionField   = "phpsessid_field"
	sigSessionCookie  = "phpsessid_cookie"
	sigNested         = "nested_field_names"
	sigManyParts      = "many_parts"
	sigPHPFilename    = "php_in_filename"
	sigLongName       = "long_field_name"
	sigOversized      = "oversized_body"
	sigChunked        = "chunked_body"
)

// exploitSignals are the indicators that make a request an exploit attempt
// rather than an ordinary form post.
var exploitSignals = []string{sigUploadProgress, sigSessionField, sigNested, sigManyParts, sigPHPFilename, sigLongName, sigOversized}

var cves = []string{"CVE-2026-109618", "CVE-2026-109619"}

// Module is the PHP2Shell trap.
type Module struct{}

// New returns the module.
func New() *Module { return &Module{} }

// Name implements modules.Module.
func (*Module) Name() string { return "php2shell" }

// Claim takes form POSTs that carry exploit traits in their headers on any
// host, and everything on the default virtual host.
func (*Module) Claim(r modules.Request) modules.Claim {
	if r.Method == http.MethodPost && isForm(r.Request) && (r.ContentLength > bigBody || hasSessionCookie(r.Request) ||
		(r.ContentLength < 0 && r.Header.Get("Content-Type") != "" && slices.Contains(r.TransferEncoding, "chunked"))) {
		return modules.Attack
	}
	if r.Surface == "" {
		return modules.Vhost
	}
	return modules.Pass
}

// Serve implements modules.Module.
func (m *Module) Serve(w http.ResponseWriter, r modules.Request) modules.Hit {
	hit := modules.Hit{Attack: "PHP2Shell", Detail: map[string]any{}}
	if r.Method == http.MethodPost {
		ins := inspect(r.Request)
		ins.record(hit.Detail)
		hit.Signals = ins.signals
		if slices.ContainsFunc(ins.signals, func(s string) bool { return slices.Contains(exploitSignals, s) }) {
			hit.Stage = modules.StageExploit
			hit.CVE = cves
			fatal(w, ins)
			return hit
		}
	}
	path := r.URL.Path
	switch {
	case path == "/" || path == "/index.php":
		page(w, http.StatusOK, loginPage)
	case isInfoPath(path):
		hit.Stage, hit.CVE = modules.StageProbe, cves
		hit.Signals = append(hit.Signals, "phpinfo")
		page(w, http.StatusOK, phpinfo())
	case strings.HasSuffix(path, ".php"):
		// php-fpm's answer for a script that does not exist.
		w.Header().Set("X-Powered-By", "PHP/"+phpVersion)
		w.Header().Set("Content-Type", "text/html; charset=UTF-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, "File not found.\n")
	default:
		notFound(w)
	}
	if r.Method == http.MethodPost {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, drainLimit))
	}
	return hit
}

func isForm(r *http.Request) bool {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return ct == "multipart/form-data" || ct == "application/x-www-form-urlencoded"
}

func hasSessionCookie(r *http.Request) bool {
	_, err := r.Cookie("PHPSESSID")
	return err == nil
}

func isInfoPath(p string) bool {
	switch strings.ToLower(p) {
	case "/phpinfo.php", "/info.php", "/php_info.php", "/i.php", "/test.php", "/php.php", "/pi.php":
		return true
	}
	return false
}

// inspection is what was learned from a request body.
type inspection struct {
	signals   []string
	bytes     int64 // body bytes read in total
	sha256    string
	parts     int
	maxDepth  int // deepest bracket nesting in a field name
	nested    int // field names nested three or more levels deep
	longest   int // longest field name
	names     []string
	filenames []string
	values    []string // short field values: where commands and URLs ride
}

func (in *inspection) add(sig string) {
	if !slices.Contains(in.signals, sig) {
		in.signals = append(in.signals, sig)
	}
}

func (in *inspection) record(d map[string]any) {
	d["body_bytes"] = in.bytes
	if in.sha256 != "" {
		d["body_sha256"] = in.sha256
	}
	if in.parts > 0 {
		d["parts"] = in.parts
	}
	if in.maxDepth > 0 {
		d["max_name_depth"] = in.maxDepth
	}
	if in.longest > 0 {
		d["longest_name"] = in.longest
	}
	for k, v := range map[string][]string{"field_names": in.names, "filenames": in.filenames, "field_values": in.values} {
		if len(v) > 0 {
			d[k] = v
		}
	}
}

// keep appends s (clipped) to list while it has room and s is new.
func keep(list []string, s string, max, clip int) []string {
	s = clipStr(s, clip)
	if len(list) >= max || slices.Contains(list, s) {
		return list
	}
	return append(list, s)
}

func clipStr(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return strings.ToValidUTF8(s, "�")
}

// inspect reads the body (up to inspectLimit parsed, drainLimit in total)
// and looks for the PHP2Shell indicators.
func inspect(r *http.Request) *inspection {
	in := &inspection{}
	if hasSessionCookie(r) {
		in.add(sigSessionCookie)
	}
	if slices.Contains(r.TransferEncoding, "chunked") {
		in.add(sigChunked)
	}
	if r.ContentLength > bigBody {
		in.add(sigOversized)
	}
	h := sha256.New()
	counted := &countingReader{r: io.TeeReader(io.LimitReader(r.Body, inspectLimit), h)}
	ct, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch ct {
	case "multipart/form-data":
		in.multipart(counted, params["boundary"])
	case "application/x-www-form-urlencoded":
		in.urlencoded(counted)
	}
	_, _ = io.Copy(io.Discard, counted) // finish hashing what was inspected
	rest, _ := io.Copy(io.Discard, io.LimitReader(r.Body, drainLimit-inspectLimit))
	in.bytes = counted.n + rest
	in.sha256 = hex.EncodeToString(h.Sum(nil))
	if in.bytes > bigBody {
		in.add(sigOversized)
	}
	return in
}

func (in *inspection) multipart(body io.Reader, boundary string) {
	if boundary == "" {
		return
	}
	mr := multipart.NewReader(body, boundary)
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		in.parts++
		name, file := p.FormName(), p.FileName()
		in.field(name)
		if file != "" {
			in.filenames = keep(in.filenames, file, 5, 300)
			if strings.Contains(file, "<?php") || strings.Contains(file, "<?=") || strings.Contains(file, "|O:") {
				in.add(sigPHPFilename)
			}
		}
		if strings.EqualFold(name, "PHP_SESSION_UPLOAD_PROGRESS") {
			in.add(sigUploadProgress)
		}
		if strings.EqualFold(name, "PHPSESSID") {
			in.add(sigSessionField)
		}
		if file == "" {
			v, _ := io.ReadAll(io.LimitReader(p, 513))
			if len(v) > 0 && len(v) <= 512 {
				in.values = keep(in.values, string(v), 10, 512)
			}
		}
		_ = p.Close()
	}
	if in.parts >= 500 {
		in.add(sigManyParts)
	}
	if in.nested >= 50 {
		in.add(sigNested)
	}
}

// urlencoded scans name=value pairs without holding the body in memory.
func (in *inspection) urlencoded(body io.Reader) {
	br := bufio.NewReaderSize(body, 64<<10)
	for {
		pair, err := br.ReadString('&')
		pair = strings.TrimSuffix(pair, "&")
		if pair != "" {
			in.parts++
			name, value, _ := strings.Cut(pair, "=")
			in.field(name)
			if strings.EqualFold(name, "PHP_SESSION_UPLOAD_PROGRESS") {
				in.add(sigUploadProgress)
			}
			if strings.EqualFold(name, "PHPSESSID") {
				in.add(sigSessionField)
			}
			if value != "" && len(value) <= 512 {
				in.values = keep(in.values, value, 10, 512)
			}
		}
		if err != nil {
			break
		}
	}
	if in.longest >= 64<<10 {
		in.add(sigLongName)
	}
	if in.nested >= 50 {
		in.add(sigNested)
	}
}

func (in *inspection) field(name string) {
	in.longest = max(in.longest, len(name))
	depth := strings.Count(name, "[")
	in.maxDepth = max(in.maxDepth, depth)
	if depth >= 3 {
		in.nested++
	}
	in.names = keep(in.names, name, 10, 120)
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// fatal answers like a worker that ran out of memory while parsing the
// request, with display_errors on.
func fatal(w http.ResponseWriter, in *inspection) {
	alloc := 3500032
	if in.bytes > 0 {
		alloc = int(min(in.bytes, memoryLimit/2)) &^ 0xfff
		alloc = max(alloc, 4096)
	}
	page(w, http.StatusOK, fmt.Sprintf("<br />\n<b>Fatal error</b>:  Allowed memory size of %d bytes exhausted (tried to allocate %d bytes) in <b>Unknown</b> on line <b>0</b><br />\n", memoryLimit, alloc))
}

func page(w http.ResponseWriter, status int, body string) {
	w.Header().Set("X-Powered-By", "PHP/"+phpVersion)
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("Set-Cookie", "PHPSESSID="+sessionID()+"; path=/")
	w.Header().Set("Expires", "Thu, 19 Nov 1981 08:52:00 GMT")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func notFound(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusNotFound)
	_, _ = io.WriteString(w, "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n")
}
