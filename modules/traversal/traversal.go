// Package traversal traps path-traversal attacks: the Apache 2.4.49/2.4.50
// cgi-bin traversal and its command-execution variant (CVE-2021-41773,
// CVE-2021-42013), Vite dev-server file-serving bypasses under /@fs/
// (CVE-2025-30208, CVE-2025-31125, CVE-2025-31486), Tomcat-style "..;/"
// path-parameter tricks, and generic ../ reads of system files.
//
// Nothing is ever read from disk or executed. File reads get fixed decoy
// content; command requests get canned output for the handful of commands
// scanners use to confirm a hit, and the submitted commands (with any URLs
// they would download from) are recorded.
package traversal

import (
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"agenttrap/modules"
)

// Module is the path-traversal trap.
type Module struct{}

// New returns the module.
func New() *Module { return &Module{} }

// Name implements modules.Module.
func (*Module) Name() string { return "traversal" }

const (
	attackApache  = "Apache path traversal"
	attackVite    = "Vite fs bypass"
	attackTomcat  = "Path parameter traversal"
	attackGeneric = "Path traversal"
)

var (
	apacheCVEs = []string{"CVE-2021-41773", "CVE-2021-42013"}
	viteCVEs   = []string{"CVE-2025-30208", "CVE-2025-31125", "CVE-2025-31486"}
)

// rawPath is the request target as sent, before Go decodes it.
func rawPath(r *http.Request) string {
	p := r.RequestURI
	if p == "" || p == "*" {
		p = r.URL.EscapedPath()
	}
	if i := strings.Index(p, "://"); i >= 0 { // absolute-form target
		if j := strings.IndexByte(p[i+3:], '/'); j >= 0 {
			p = p[i+3+j:]
		}
	}
	return p
}

// dotdot matches a parent-directory segment in any of the encodings scanners
// use: "..", ".%2e", "%2e.", "%2e%2e", double-encoded "%252e", and the
// overlong "%%32%65" form.
var dotdot = regexp.MustCompile(`(?i)(?:\.|%2e|%252e|%%32%65)(?:\.|%2e|%252e|%%32%65)(?:/|%2f|%252f|\\|%5c|;)`)

// kind classifies a request target, or returns "".
func kind(raw string) string {
	lower := strings.ToLower(raw)
	path, _, _ := strings.Cut(lower, "?")
	switch {
	case strings.HasPrefix(path, "/@fs/"):
		return attackVite
	case dotdot.MatchString(lower) && (strings.HasPrefix(path, "/cgi-bin/") || strings.HasPrefix(path, "/icons/")):
		return attackApache
	case strings.Contains(path, "..;/"):
		return attackTomcat
	case dotdot.MatchString(lower):
		return attackGeneric
	}
	return ""
}

// Claim implements modules.Module.
func (*Module) Claim(r modules.Request) modules.Claim {
	if modules.WebSurface(r.Surface) && kind(rawPath(r.Request)) != "" {
		return modules.Attack
	}
	return modules.Pass
}

// Serve implements modules.Module.
func (*Module) Serve(w http.ResponseWriter, r modules.Request) modules.Hit {
	raw := rawPath(r.Request)
	k := kind(raw)
	hit := modules.Hit{Attack: k, Stage: modules.StageExploit, Detail: map[string]any{"target": modules.Clip(raw, 300)}}
	switch k {
	case attackApache:
		hit.CVE = apacheCVEs
	case attackVite:
		hit.CVE = viteCVEs
	}
	target := targetFile(r.URL.Path)
	if target != "" {
		hit.Detail["file"] = target
	}

	// Apache cgi-bin traversal to a shell: the POST body is a script.
	if k == attackApache && isShell(target) {
		body, _ := modules.ReadBody(r.Request, 16<<10)
		cmds := commands(string(body))
		hit.Signals = []string{"cgi_shell"}
		hit.Detail["body"] = modules.Clip(string(body), 4096)
		hit.Detail["commands"] = cmds
		if urls := extractURLs(string(body)); len(urls) > 0 {
			hit.Detail["urls"] = urls
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		var out strings.Builder
		for _, c := range cmds {
			out.WriteString(fakeOutput(c))
		}
		_, _ = io.WriteString(w, out.String())
		return hit
	}
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		_, _ = modules.ReadBody(r.Request, 0)
	}

	content, ok := fileContent(target, r)
	switch {
	case k == attackTomcat:
		// A Tomcat manager behind the trick asks for credentials.
		hit.Signals = []string{"path_parameter"}
		if user, pass, has := r.BasicAuth(); has {
			hit.Detail["username"] = modules.Clip(user, 64)
			hit.Detail["password"] = modules.Clip(pass, 128)
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="Tomcat Manager Application"`)
		w.Header().Set("Content-Type", "text/html;charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, tomcat401)
	case !ok:
		hit.Signals = []string{"file_read"}
		modules.NotFound(w)
	case k == attackVite && strings.Contains(strings.ToLower(r.URL.RawQuery), "import"):
		// Vite answers ?import&raw / ?raw?? reads with the file as a JS module.
		hit.Signals = []string{"file_read"}
		w.Header().Set("Content-Type", "text/javascript")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "export default "+jsString(content)+"\n")
	default:
		hit.Signals = []string{"file_read"}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, content)
	}
	return hit
}

// targetFile reduces a decoded path to the file it reaches: everything after
// the last parent-directory hop, as an absolute path ("/etc/passwd").
func targetFile(decoded string) string {
	for range 2 { // double-encoded targets ("%252e") arrive still encoded once
		if u, err := url.PathUnescape(decoded); err == nil {
			decoded = u
		}
	}
	p := strings.ReplaceAll(decoded, `\`, "/")
	if i := strings.LastIndex(p, "../"); i >= 0 {
		p = p[i+2:]
	} else if strings.HasPrefix(p, "/@fs/") {
		p = strings.TrimPrefix(p, "/@fs")
	}
	if i := strings.Index(p, "..;/"); i >= 0 {
		p = p[i+3:]
	}
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	return p
}

func isShell(target string) bool {
	switch target {
	case "/bin/sh", "/bin/bash", "/usr/bin/sh", "/usr/bin/bash", "/bin/dash":
		return true
	}
	return false
}

// commands splits a CGI shell script into the commands it runs, dropping the
// "echo Content-Type ...; echo" header scanners prepend to get output back.
func commands(body string) []string {
	var out []string
	for _, line := range strings.FieldsFunc(body, func(r rune) bool { return r == ';' || r == '\n' || r == '&' }) {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if line == "" || lower == "echo" || strings.HasPrefix(lower, "echo content-type") || strings.HasPrefix(lower, "echo 'content-type") ||
			strings.HasPrefix(lower, `echo "content-type`) {
			continue
		}
		if len(out) < 20 {
			out = append(out, modules.Clip(line, 300))
		}
	}
	return out
}

var urlRE = regexp.MustCompile(`(?i)\b(?:https?|ftp|tftp)://[^\s'"|;<>` + "`" + `)]+|\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b`)

func extractURLs(s string) []string {
	var out []string
	for _, m := range urlRE.FindAllString(s, 20) {
		out = append(out, modules.Clip(m, 300))
	}
	return out
}

// fakeOutput is what a confirmation command prints on the decoy host (Apache
// CGI runs as daemon). Anything else prints nothing, like a fetch-and-run
// line whose download fails quietly.
func fakeOutput(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return ""
	}
	switch f[0] {
	case "id":
		return "uid=1(daemon) gid=1(daemon) groups=1(daemon)\n"
	case "whoami":
		return "daemon\n"
	case "uname":
		if len(f) > 1 && strings.Contains(f[1], "a") {
			return "Linux web01 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 (2024-01-31) x86_64 GNU/Linux\n"
		}
		return "Linux\n"
	case "pwd":
		return "/usr/local/apache2/cgi-bin\n"
	case "hostname":
		return "web01\n"
	case "echo":
		return strings.Trim(strings.Join(f[1:], " "), `'"`) + "\n"
	case "cat":
		if len(f) > 1 && f[1] == "/etc/passwd" {
			return passwd
		}
	}
	return ""
}

// fileContent returns decoy content for the system files traversal scanners
// read, and false for anything else.
func fileContent(target string, r modules.Request) (string, bool) {
	switch strings.ToLower(target) {
	case "/etc/passwd":
		return passwd, true
	case "/etc/hosts":
		return "127.0.0.1\tlocalhost\n10.0.4.17\tweb01\n", true
	case "/etc/hostname":
		return "web01\n", true
	case "/etc/issue":
		return "Debian GNU/Linux 11 \\n \\l\n\n", true
	case "/proc/version":
		return "Linux version 5.10.0-28-amd64 (debian-kernel@lists.debian.org) (gcc-10 (Debian 10.2.1-6) 10.2.1 20210110, GNU ld (GNU Binutils for Debian) 2.35.2) #1 SMP Debian 5.10.209-2 (2024-01-31)\n", true
	case "/proc/self/environ":
		key := r.Canary("aws_access_key_id", "AKIA287VJ6V9233M2C5T")
		env := []string{"APACHE_RUN_USER=daemon", "HOSTNAME=web01", "HOME=/usr/sbin", "AWS_DEFAULT_REGION=us-east-1",
			"AWS_ACCESS_KEY_ID=" + key, "AWS_SECRET_ACCESS_KEY=" + secretFor(key),
			"PATH=/usr/local/apache2/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
		return strings.Join(env, "\x00") + "\x00", true
	case "/windows/win.ini", "/c:/windows/win.ini", "/winnt/win.ini":
		return "; for 16-bit app support\r\n[fonts]\r\n[extensions]\r\n[mci extensions]\r\n[files]\r\n[Mail]\r\nMAPI=1\r\n", true
	}
	return "", false
}

// secretFor derives a stable-looking secret access key from the key id; the
// cloud decoy accepts any secret paired with a canary key id.
func secretFor(keyID string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	b := make([]byte, 40)
	h := uint32(2166136261)
	for i := range b {
		for _, c := range []byte(keyID) {
			h = (h ^ uint32(c) ^ uint32(i)) * 16777619
		}
		b[i] = alphabet[h%uint32(len(alphabet))]
	}
	return string(b)
}

func jsString(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\x00", `\u0000`)
	return `"` + r.Replace(s) + `"`
}

const passwd = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
deploy:x:1000:1000:deploy,,,:/home/deploy:/bin/bash
postgres:x:105:111:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
`

const tomcat401 = `<!doctype html><html lang="en"><head><title>HTTP Status 401 – Unauthorized</title></head><body><h1>HTTP Status 401 – Unauthorized</h1><hr class="line" /><p><b>Type</b> Status Report</p><p><b>Description</b> The request has not been applied to the target resource because it lacks valid authentication credentials for that resource.</p><hr class="line" /><h3>Apache Tomcat/9.0.83</h3></body></html>`
