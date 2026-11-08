// Package webshell answers bots that hunt for webshells someone else already
// planted (alfa.php, wso.php, random-name .php drops, file managers). It
// plays a password-protected shell: discovery gets a login form, the password
// tried is recorded, and commands, uploads and the URLs they fetch are
// captured with plausible output for the usual reconnaissance commands.
package webshell

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"path"
	"regexp"
	"strings"

	"agenttrap/modules"
)

const (
	phpVersion = "8.4.26"
	bodyLimit  = 1 << 20
)

// shellNames are basenames seen probed in the wild or belonging to well-known
// shells. Kept to names that only a shell (or a shell hunter) would use.
var shellNames = map[string]bool{
	"alfa.php": true, "chosen.php": true, "radio.php": true, "adminfuns.php": true,
	"wp_filemanager.php": true, "k.php": true, "ccc.php": true, "dex.php": true,
	"txets.php": true, "opsh.php": true, "this_is_a_new_hello_world.php": true,
	"wp_blog_footer.php": true, "terminal-xhr.php": true, "shell.php": true,
	"cmd.php": true, "c99.php": true, "r57.php": true, "wso.php": true,
	"b374k.php": true, "mini.php": true, "up.php": true, "x.php": true,
	"1.php": true, "alfa-rex.php": true, "wso2.php": true, "shell20.php": true,
	"sh.php": true, "bypass.php": true, "marijuana.php": true, "leaf.php": true,
	"gecko.php": true, "lock360.php": true, "simple.php": true, "uploader.php": true,
}

var (
	// digitsName matches /123.php-style drops and fN.php-style ones.
	digitsName = regexp.MustCompile(`^[a-z]?[0-9]{1,6}\.php$`)
	// randomName matches random mixed-case drops like NPJcpMFsDNB.php.
	randomName = regexp.MustCompile(`^[A-Za-z]{6,12}\.php$`)
	upper      = regexp.MustCompile(`[A-Z]`)
	urlRe      = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s'"<>|;)]+|\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b`)
)

// commandParams carry a command in common shells; WSO instead sends
// a=Console&p1=<command>.
var commandParams = []string{"cmd", "c", "exec", "command", "execute"}

var passwordParams = []string{"pass", "password", "pwd", "p", "pw", "passwd", "auth"}

// Module is the webshell trap.
type Module struct{}

// New returns the module.
func New() *Module { return &Module{} }

// Name implements modules.Module.
func (*Module) Name() string { return "webshell" }

// Claim takes known and shell-shaped .php names, and any .php carrying a
// command parameter, on web surfaces.
func (*Module) Claim(r modules.Request) modules.Claim {
	if !modules.WebSurface(r.Surface) {
		return modules.Pass
	}
	if isShellPath(r.URL.Path) {
		return modules.Attack
	}
	if strings.HasSuffix(strings.ToLower(r.URL.Path), ".php") {
		q := r.URL.Query()
		for _, p := range []string{"cmd", "c", "exec", "command"} {
			if q.Get(p) != "" {
				return modules.Attack
			}
		}
	}
	return modules.Pass
}

func isShellPath(p string) bool {
	base := path.Base(p)
	if shellNames[strings.ToLower(base)] {
		return true
	}
	if digitsName.MatchString(base) {
		return true
	}
	return randomName.MatchString(base) && len(upper.FindAllString(base, -1)) >= 3
}

// Serve implements modules.Module.
func (m *Module) Serve(w http.ResponseWriter, r modules.Request) modules.Hit {
	hit := modules.Hit{Attack: "Webshell", Stage: modules.StageProbe, Detail: map[string]any{"shell": path.Base(r.URL.Path)}}
	var body []byte
	if r.Body != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
		var total int64
		body, total = modules.ReadBody(r.Request, bodyLimit)
		hit.Detail["body_bytes"] = total
	}
	fields := modules.Fields(r.Request, body)
	get := func(names []string) string {
		for _, f := range fields {
			for _, n := range names {
				if strings.EqualFold(f.Name, n) && f.Value != "" && !strings.HasPrefix(f.Value, "file:") {
					return f.Value
				}
			}
		}
		return ""
	}

	// Uploads.
	if ups := uploads(r.Request, body); len(ups) > 0 {
		hit.Stage = modules.StageExploit
		hit.Signals = append(hit.Signals, "upload")
		hit.Detail["uploads"] = ups
		page(w, http.StatusOK, "<b>File uploaded</b>")
		return hit
	}

	cmd := get(commandParams)
	if cmd == "" && strings.EqualFold(get([]string{"a"}), "Console") {
		cmd = get([]string{"p1"})
	}
	if cmd != "" {
		hit.Stage = modules.StageExploit
		hit.Signals = append(hit.Signals, "command")
		hit.Detail["command"] = modules.Clip(cmd, 1000)
		if urls := urlRe.FindAllString(cmd, 10); len(urls) > 0 {
			hit.Detail["urls"] = urls
		}
		out := fakeOutput(cmd)
		if strings.Contains(r.URL.Path, "terminal-xhr") {
			w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, out)
			return hit
		}
		page(w, http.StatusOK, "<pre>"+htmlEscape(out)+"</pre>")
		return hit
	}

	if pw := get(passwordParams); pw != "" {
		hit.Stage = modules.StageExploit
		hit.Signals = append(hit.Signals, "login")
		hit.Detail["password"] = modules.Clip(pw, 128)
		http.SetCookie(w, &http.Cookie{Name: "PHPSESSID", Value: "f3a9c1e7b2d84a6c9e0f5b1d27", Path: "/"})
		page(w, http.StatusOK, fileManager)
		return hit
	}

	hit.Signals = append(hit.Signals, "discovery")
	page(w, http.StatusOK, loginPage)
	return hit
}

type upload struct {
	Field    string `json:"field"`
	Filename string `json:"filename"`
	Bytes    int    `json:"bytes"`
	SHA256   string `json:"sha256"`
}

func uploads(r *http.Request, body []byte) []upload {
	ct, params, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct != "multipart/form-data" || len(body) == 0 {
		return nil
	}
	var out []upload
	mr := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	for len(out) < 5 {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		if fn := p.FileName(); fn != "" {
			data, _ := io.ReadAll(p)
			sum := sha256.Sum256(data)
			out = append(out, upload{Field: modules.Clip(p.FormName(), 64), Filename: modules.Clip(fn, 200),
				Bytes: len(data), SHA256: hex.EncodeToString(sum[:])})
		}
		_ = p.Close()
	}
	return out
}

// fakeOutput answers the reconnaissance commands bots run first.
func fakeOutput(cmd string) string {
	var out strings.Builder
	for _, part := range strings.FieldsFunc(cmd, func(r rune) bool { return r == ';' || r == '\n' || r == '&' }) {
		c := strings.TrimSpace(part)
		switch {
		case c == "id":
			out.WriteString("uid=33(www-data) gid=33(www-data) groups=33(www-data)\n")
		case c == "whoami":
			out.WriteString("www-data\n")
		case strings.HasPrefix(c, "uname"):
			if strings.Contains(c, "-a") {
				out.WriteString("Linux web01 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 (2024-01-31) x86_64 GNU/Linux\n")
			} else {
				out.WriteString("Linux\n")
			}
		case c == "pwd":
			out.WriteString("/var/www/html\n")
		case c == "hostname":
			out.WriteString("web01\n")
		case c == "ls" || strings.HasPrefix(c, "ls "):
			out.WriteString("index.php\nwp-config.php\nwp-content\nwp-includes\nwp-admin\n.htaccess\n")
		case strings.HasPrefix(c, "echo "):
			out.WriteString(strings.Trim(strings.TrimPrefix(c, "echo "), `"'`) + "\n")
		}
	}
	return out.String()
}

func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

func page(w http.ResponseWriter, status int, body string) {
	w.Header().Set("X-Powered-By", "PHP/"+phpVersion)
	w.Header().Set("Content-Type", "text/html; charset=UTF-8")
	w.Header().Set("Content-Length", fmt.Sprint(len(body)))
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

const loginPage = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>403 Forbidden</title>
<style>body{background:#000;color:#0f0;font-family:monospace}input{background:#111;color:#0f0;border:1px solid #0f0}</style>
</head><body>
<center><br><br><br>
<form method="post"><input type="password" name="pass" autofocus> <input type="submit" value="&gt;&gt;"></form>
</center>
</body></html>
`

const fileManager = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>web01 - /var/www/html</title>
<style>body{background:#222;color:#ddd;font:12px monospace}a{color:#9cf}td{padding:2px 8px}</style>
</head><body>
<div>Uname: Linux web01 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 x86_64<br>User: 33 (www-data) Group: 33 (www-data)<br>Php: 8.4.26 Safe mode: OFF<br>Hdd: 58 GB Free: 49 GB<br>Cwd: /var/www/html</div>
<table>
<tr><th>Name</th><th>Size</th><th>Perms</th></tr>
<tr><td><a href="?d=wp-admin">[ wp-admin ]</a></td><td>dir</td><td>drwxr-xr-x</td></tr>
<tr><td><a href="?d=wp-content">[ wp-content ]</a></td><td>dir</td><td>drwxr-xr-x</td></tr>
<tr><td>index.php</td><td>405 B</td><td>-rw-r--r--</td></tr>
<tr><td>wp-config.php</td><td>3.2 KB</td><td>-rw-r-----</td></tr>
</table>
<form method="post"><input name="cmd" size="80"> <input type="submit" value="Execute"></form>
<form method="post" enctype="multipart/form-data"><input type="file" name="f"> <input type="submit" value="Upload"></form>
</body></html>
`
