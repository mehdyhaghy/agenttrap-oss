package php2shell

import (
	"crypto/rand"
	"fmt"
	"strings"
)

// sessionID returns a fresh 26-character PHP session id (the default
// session.sid_length and sid_bits_per_character=5 alphabet).
func sessionID() string {
	const alphabet = "0123456789abcdefghijklmnopqrstuv"
	b := make([]byte, 26)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = alphabet[b[i]&31]
	}
	return string(b)
}

// loginPage is the default virtual host's front page: an old internal
// operations portal of the kind left on a server's IP for years.
const loginPage = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Ops Portal - Sign in</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;background:#eef1f4;margin:0}
.box{width:320px;margin:120px auto;background:#fff;border:1px solid #ccd3da;padding:28px 32px}
h1{font-size:18px;margin:0 0 18px;color:#2c3e50}
label{display:block;font-size:12px;color:#555;margin:10px 0 4px}
input[type=text],input[type=password]{width:100%;box-sizing:border-box;padding:7px;border:1px solid #bbb}
button{margin-top:16px;padding:7px 18px;background:#2c6fad;color:#fff;border:0}
.f{font-size:11px;color:#999;margin-top:22px}
</style>
</head>
<body>
<div class="box">
<h1>Ops Portal</h1>
<form method="post" action="/index.php" enctype="multipart/form-data">
<input type="hidden" name="action" value="login">
<label for="u">Username</label><input type="text" id="u" name="username">
<label for="p">Password</label><input type="password" id="p" name="password">
<button type="submit">Sign in</button>
</form>
<div class="f">v2.3.1 &middot; build 2019-04</div>
</div>
</body>
</html>
`

// phpinfo renders a trimmed phpinfo() page: enough for version and
// configuration fingerprinting (SAPI, upload progress, memory limit), which
// is what PHP2Shell scanners read.
func phpinfo() string {
	rows := [][2]string{
		{"System", "Linux web01 5.10.0-28-amd64 #1 SMP Debian 5.10.209-2 (2024-01-31) x86_64"},
		{"Build Date", "Sep 26 2026 18:41:07"},
		{"Server API", "FPM/FastCGI"},
		{"Virtual Directory Support", "disabled"},
		{"Configuration File (php.ini) Path", "/usr/local/etc/php"},
		{"Loaded Configuration File", "/usr/local/etc/php/php.ini"},
		{"PHP API", "20240924"},
		{"PHP Extension", "20240924"},
		{"Zend Extension", "420240924"},
		{"Debug Build", "no"},
		{"Thread Safety", "disabled"},
		{"Zend Memory Manager", "enabled"},
	}
	directives := [][2]string{
		{"display_errors", "On"},
		{"file_uploads", "On"},
		{"max_input_vars", "1000"},
		{"memory_limit", "128M"},
		{"post_max_size", "64M"},
		{"session.upload_progress.enabled", "On"},
		{"session.upload_progress.name", "PHP_SESSION_UPLOAD_PROGRESS"},
		{"upload_max_filesize", "64M"},
	}
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml"><head>
<style type="text/css">
body {background-color: #fff; color: #222; font-family: sans-serif;}
table {border-collapse: collapse; border: 0; width: 934px; box-shadow: 1px 2px 3px rgba(0, 0, 0, 0.2);}
.center {text-align: center;}
.center table {margin: 1em auto; text-align: left;}
td, th {border: 1px solid #666; font-size: 75%; vertical-align: baseline; padding: 4px 5px;}
h1 {font-size: 150%;}
.p {text-align: left;}
.e {background-color: #ccf; width: 300px; font-weight: bold;}
.h {background-color: #99c; font-weight: bold;}
.v {background-color: #ddd; max-width: 300px; overflow-x: auto; word-wrap: break-word;}
</style>
<title>PHP `)
	b.WriteString(phpVersion)
	b.WriteString(` - phpinfo()</title><meta name="ROBOTS" content="NOINDEX,NOFOLLOW,NOARCHIVE" /></head>
<body><div class="center">
<table>
<tr class="h"><td>
<h1 class="p">PHP Version `)
	b.WriteString(phpVersion)
	b.WriteString("</h1>\n</td></tr>\n</table>\n<table>\n")
	for _, r := range rows {
		fmt.Fprintf(&b, "<tr><td class=\"e\">%s </td><td class=\"v\">%s </td></tr>\n", r[0], r[1])
	}
	b.WriteString("</table>\n<h2>Core</h2>\n<table>\n<tr class=\"h\"><th>Directive</th><th>Local Value</th><th>Master Value</th></tr>\n")
	for _, d := range directives {
		fmt.Fprintf(&b, "<tr><td class=\"e\">%s</td><td class=\"v\">%s</td><td class=\"v\">%s</td></tr>\n", d[0], d[1], d[1])
	}
	b.WriteString("</table>\n</div></body></html>\n")
	return b.String()
}
