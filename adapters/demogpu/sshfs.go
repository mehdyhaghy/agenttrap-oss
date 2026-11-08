package demogpu

import (
	"fmt"
	"math/rand/v2"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"agenttrap/internal/events"
	"agenttrap/internal/worldpack"
)

// The synthetic filesystem and the commands the shell answers. File contents
// come from the world pack; {{canary:<slot>}} in a file is replaced by a
// fresh per-exposure canary each time the file is read, so a key taken from
// this node names the exact read.

var canaryRef = regexp.MustCompile(`\{\{canary:([a-z0-9_]+)\}\}`)

// resolve turns a possibly relative path into an absolute, cleaned one.
func (s *shell) resolve(p string) string {
	switch {
	case p == "" || p == "~":
		return s.c.home()
	case strings.HasPrefix(p, "~/"):
		p = path.Join(s.c.home(), p[2:])
	case !strings.HasPrefix(p, "/"):
		p = path.Join(s.cwd, p)
	}
	return path.Clean(p)
}

// file returns a file's contents with canaries minted, and whether it exists.
func (s *shell) file(p string) (string, bool) {
	raw, ok := s.c.s.pack.SSH.Files[p]
	if !ok {
		return "", false
	}
	r := s.c.request()
	return canaryRef.ReplaceAllStringFunc(raw, func(m string) string {
		slot := canaryRef.FindStringSubmatch(m)[1]
		return s.c.s.revealWith(r, slot, map[string]any{"via": "ssh", "path": p})
	}), true
}

// dirs returns the set of directories implied by the pack's files.
func (s *shell) dirs() map[string]bool {
	out := map[string]bool{"/": true}
	for p := range s.c.s.pack.SSH.Files {
		for d := path.Dir(p); d != "/" && d != "."; d = path.Dir(d) {
			out[d] = true
		}
	}
	for _, u := range s.c.s.pack.SSH.Users {
		out[u.Home] = true
	}
	return out
}

func (s *shell) isDir(p string) bool { return s.dirs()[p] }

// list returns the names directly under a directory, with a flag per name
// saying whether it is itself a directory.
func (s *shell) list(dir string) []struct {
	Name  string
	IsDir bool
	Size  int
} {
	seen := map[string]bool{}
	var out []struct {
		Name  string
		IsDir bool
		Size  int
	}
	add := func(name string, isDir bool, size int) {
		if name == "" || seen[name] {
			return
		}
		seen[name] = true
		out = append(out, struct {
			Name  string
			IsDir bool
			Size  int
		}{name, isDir, size})
	}
	prefix := strings.TrimSuffix(dir, "/") + "/"
	for p, content := range s.c.s.pack.SSH.Files {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		rest := strings.TrimPrefix(p, prefix)
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			add(rest[:i], true, 4096)
		} else {
			add(rest, false, len(content))
		}
	}
	for d := range s.dirs() {
		if strings.HasPrefix(d, prefix) {
			rest := strings.TrimPrefix(d, prefix)
			if !strings.Contains(rest, "/") {
				add(rest, true, 4096)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

var bootTime = time.Now().Add(-13*24*time.Hour - 7*time.Hour)

// command runs one command and returns its output and exit status.
func (s *shell) command(ch ssh.Channel, args []string) (string, int) {
	cmd := path.Base(args[0])
	rest := args[1:]
	flags, operands := split(rest)
	pack := s.c.s.pack
	notFound := func(name string) (string, int) {
		return name + ": command not found\n", 127
	}

	switch cmd {
	case "pwd":
		return s.cwd + "\n", 0
	case "cd":
		target := s.c.home()
		if len(operands) > 0 {
			target = s.resolve(operands[0])
		}
		switch {
		case s.isDir(target):
			s.cwd = target
			return "", 0
		case s.exists(target):
			return "bash: cd: " + operands[0] + ": Not a directory\n", 1
		default:
			return "bash: cd: " + operands[0] + ": No such file or directory\n", 1
		}
	case "ls", "dir":
		return s.ls(flags, operands)
	case "cat", "less", "more", "bat":
		if len(operands) == 0 {
			return "", 0
		}
		var b strings.Builder
		status := 0
		for _, o := range operands {
			p := s.resolve(o)
			switch {
			case s.isDir(p):
				b.WriteString("cat: " + o + ": Is a directory\n")
				status = 1
			default:
				if content, ok := s.file(p); ok {
					b.WriteString(content)
				} else {
					b.WriteString("cat: " + o + ": No such file or directory\n")
					status = 1
				}
			}
		}
		return b.String(), status
	case "head", "tail":
		if len(operands) == 0 {
			return "", 0
		}
		content, ok := s.file(s.resolve(operands[0]))
		if !ok {
			return cmd + ": cannot open '" + operands[0] + "' for reading: No such file or directory\n", 1
		}
		return applyFilter(content, append([]string{cmd}, flags...)), 0
	case "whoami":
		return s.c.user + "\n", 0
	case "id":
		u := s.user()
		return fmt.Sprintf("uid=%d(%s) gid=%d(%s) groups=%d(%s),27(sudo),999(docker)\n", u.UID, u.Name, u.UID, u.Group, u.UID, u.Group), 0
	case "hostname":
		return pack.SSH.Hostname + "\n", 0
	case "uname":
		switch {
		case slices.Contains(flags, "-a"):
			return fmt.Sprintf("Linux %s %s #85-Ubuntu SMP PREEMPT_DYNAMIC Thu Aug 14 10:22:31 UTC 2026 x86_64 x86_64 x86_64 GNU/Linux\n",
				pack.SSH.Hostname, pack.SSH.Kernel), 0
		case slices.Contains(flags, "-r"):
			return pack.SSH.Kernel + "\n", 0
		default:
			return "Linux\n", 0
		}
	case "uptime":
		return fmt.Sprintf(" %s up %s,  1 user,  load average: 1.94, 2.06, 2.11\n",
			time.Now().Format("15:04:05"), fmtDuration(time.Since(bootTime))), 0
	case "ps":
		var b strings.Builder
		b.WriteString("USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n")
		for _, p := range pack.SSH.Procs {
			b.WriteString(p + "\n")
		}
		return b.String(), 0
	case "top", "htop":
		return "top: failed tty get\n", 1
	case "nvidia-smi":
		return s.nvidiaSMI(), 0
	case "env", "printenv":
		return s.environ(), 0
	case "echo":
		return s.expand(strings.Join(rest, " ")) + "\n", 0
	case "export", "set", "unset", "alias", "umask", "shopt":
		return "", 0
	case "history":
		if content, ok := s.file(path.Join(s.c.home(), ".bash_history")); ok {
			var b strings.Builder
			for i, l := range strings.Split(strings.TrimSuffix(content, "\n"), "\n") {
				fmt.Fprintf(&b, "%5d  %s\n", i+1, l)
			}
			return b.String(), 0
		}
		return "", 0
	case "which", "command", "type":
		if len(operands) == 0 {
			return "", 1
		}
		if bin := s.which(operands[len(operands)-1]); bin != "" {
			return bin + "\n", 0
		}
		return "", 1
	case "df":
		return "Filesystem      Size  Used Avail Use% Mounted on\n" +
			"/dev/nvme0n1p2  1.8T  1.1T  654G  63% /\n" +
			"tmpfs           252G     0  252G   0% /dev/shm\n" +
			"/dev/nvme1n1    3.5T  1.3T  2.1T  39% /data\n", 0
	case "free":
		return "               total        used        free      shared  buff/cache   available\n" +
			"Mem:       515842116   197326048    18420336      262144   300095732   315204908\n" +
			"Swap:              0           0           0\n", 0
	case "nproc":
		return "64\n", 0
	case "w", "who":
		return "USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n" +
			s.c.user + "   pts/0    10.20.3.1        " + time.Now().Format("15:04") + "    0.00s  0.01s  0.00s w\n", 0
	case "last":
		return s.c.user + "  pts/0        10.20.3.1        " + time.Now().Format("Mon Jan _2 15:04") + "   still logged in\n", 0
	case "docker":
		return s.docker(operands), 0
	case "systemctl", "service":
		return s.systemctl(operands)
	case "curl", "wget":
		return s.fetch(cmd, rest)
	case "ssh", "scp", "sftp", "rsync", "nc", "ncat", "telnet":
		s.c.emit(events.KindToolCall, map[string]any{"op": "ssh_outbound", "command": truncate(strings.Join(args, " "), 500)})
		return fmt.Sprintf("ssh: connect to host %s port 22: Connection timed out\n", firstOperand(operands)), 255
	case "sudo":
		if len(rest) == 0 {
			return "usage: sudo -h | -K | -k | -V\n", 1
		}
		s.c.emit(events.KindToolCall, map[string]any{"op": "ssh_sudo", "command": truncate(strings.Join(rest, " "), 500)})
		return fmt.Sprintf("[sudo] password for %s: \nsudo: a password is required\n", s.c.user), 1
	case "su":
		return "su: Authentication failure\n", 1
	case "find":
		return s.find(operands, flags), 0
	case "grep", "egrep", "rg":
		if len(operands) >= 2 {
			content, ok := s.file(s.resolve(operands[1]))
			if !ok {
				return "grep: " + operands[1] + ": No such file or directory\n", 2
			}
			out := applyFilter(content, append([]string{"grep"}, operands[0]))
			if out == "" {
				return "", 1
			}
			return out, 0
		}
		return "", 1
	case "python3", "python", "pip", "pip3", "node", "npm", "git", "make", "vi", "vim", "nano", "tar", "unzip":
		if bin := s.which(cmd); bin == "" {
			return notFound(cmd)
		}
		return s.refuse(cmd, args)
	case "mkdir", "touch", "rm", "mv", "cp", "chmod", "chown", "ln", "dd", "truncate":
		s.c.emit(events.KindToolCall, map[string]any{"op": "ssh_write", "command": truncate(strings.Join(args, " "), 500)})
		return cmd + ": cannot create '" + firstOperand(operands) + "': Read-only file system\n", 1
	case "exit", "logout":
		return "", 0
	case "clear":
		if s.pty {
			return "\x1b[H\x1b[2J", 0
		}
		return "", 0
	case "sleep", "true", ":":
		return "", 0
	case "false":
		return "", 1
	case "date":
		return time.Now().Format("Mon Jan _2 15:04:05 MST 2006") + "\n", 0
	case "lscpu":
		return "Architecture:            x86_64\n  CPU op-mode(s):        32-bit, 64-bit\nCPU(s):                  64\nModel name:              AMD EPYC 9354 32-Core Processor\n", 0
	case "bash", "sh", "zsh":
		return "", 0
	default:
		return notFound(cmd)
	}
}

func (s *shell) exists(p string) bool {
	_, ok := s.c.s.pack.SSH.Files[p]
	return ok || s.isDir(p)
}

func (s *shell) user() worldpack.SSHUser {
	for _, u := range s.c.s.pack.SSH.Users {
		if u.Name == s.c.user {
			return u
		}
	}
	return worldpack.SSHUser{Name: s.c.user, UID: 1000, Home: s.c.home(), Group: s.c.user}
}

// which reports the path of a binary the node has, or "" for one it does not.
func (s *shell) which(name string) string {
	switch path.Base(name) {
	case "python3", "pip3", "nvidia-smi", "docker", "curl", "wget", "git", "vi", "vim", "tar", "systemctl", "ssh", "scp", "grep", "find", "ps", "ls", "cat":
		if name == "nvidia-smi" {
			return "/usr/bin/nvidia-smi"
		}
		return "/usr/bin/" + path.Base(name)
	case "python", "pip", "node", "npm", "nano", "unzip", "make":
		return "" // not installed on the node
	}
	return ""
}

// refuse answers for installed tools we do not simulate.
func (s *shell) refuse(cmd string, args []string) (string, int) {
	s.c.emit(events.KindToolCall, map[string]any{"op": "ssh_tool", "command": truncate(strings.Join(args, " "), 500)})
	switch cmd {
	case "git":
		return "fatal: not a git repository (or any of the parent directories): .git\n", 128
	case "python3":
		if len(args) > 1 && !strings.HasPrefix(args[1], "-") {
			return fmt.Sprintf("python3: can't open file '%s': [Errno 2] No such file or directory\n", s.resolve(args[1])), 2
		}
		return "Python 3.12.3 (main, Aug 14 2026, 10:22:31) [GCC 13.2.0] on linux\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n", 0
	case "pip3":
		return "ERROR: Could not find an activated virtualenv (required).\n", 3
	case "vi", "vim", "nano":
		return "", 0
	case "tar", "unzip":
		return cmd + ": Cannot write: Read-only file system\n", 2
	case "make":
		return "make: *** No targets specified and no makefile found.  Stop.\n", 2
	}
	return "", 1
}

func (s *shell) ls(flags, operands []string) (string, int) {
	long := slices.ContainsFunc(flags, func(f string) bool { return strings.Contains(f, "l") })
	all := slices.ContainsFunc(flags, func(f string) bool { return strings.Contains(f, "a") })
	target := s.cwd
	if len(operands) > 0 {
		target = s.resolve(operands[0])
	}
	if !s.isDir(target) {
		if s.exists(target) {
			if long {
				return fmt.Sprintf("-rw-r--r-- 1 %s %s %6d Sep 20 11:42 %s\n", s.c.user, s.user().Group,
					len(s.c.s.pack.SSH.Files[target]), operands[0]), 0
			}
			return operands[0] + "\n", 0
		}
		return "ls: cannot access '" + firstOperand(operands) + "': No such file or directory\n", 2
	}
	entries := s.list(target)
	var b strings.Builder
	if long {
		fmt.Fprintf(&b, "total %d\n", 4*len(entries)+8)
		if all {
			fmt.Fprintf(&b, "drwxr-xr-x  %d %s %s   4096 Sep 20 11:42 .\n", len(entries)+2, s.c.user, s.user().Group)
			fmt.Fprintf(&b, "drwxr-xr-x  8 root root    4096 Sep 14 08:11 ..\n")
		}
	}
	var names []string
	for _, e := range entries {
		if !all && strings.HasPrefix(e.Name, ".") {
			continue
		}
		if long {
			mode := "-rw-r--r--"
			if e.IsDir {
				mode = "drwxr-xr-x"
			} else if strings.HasSuffix(e.Name, ".sh") {
				mode = "-rwxr-xr-x"
			}
			owner := s.c.user + " " + s.user().Group
			if !strings.HasPrefix(target, "/home/") {
				owner = "root root"
			}
			fmt.Fprintf(&b, "%s  %d %s %6d Sep 20 11:42 %s\n", mode, 1+btoi(e.IsDir), owner, e.Size, e.Name)
		} else {
			names = append(names, e.Name)
		}
	}
	if !long {
		return strings.Join(names, "  ") + "\n", 0
	}
	return b.String(), 0
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *shell) find(operands, flags []string) string {
	root := s.cwd
	if len(operands) > 0 {
		root = s.resolve(operands[0])
	}
	var name string
	for i, f := range flags {
		if f == "-name" && i+1 < len(flags) {
			name = flags[i+1]
		}
	}
	if name == "" && len(operands) > 1 {
		name = operands[len(operands)-1] // find . -name '*.env' puts the glob here
	}
	var out []string
	for p := range s.c.s.pack.SSH.Files {
		if !strings.HasPrefix(p, strings.TrimSuffix(root, "/")+"/") && p != root {
			continue
		}
		if name != "" && !matchGlob(name, path.Base(p)) {
			continue
		}
		out = append(out, p)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "\n") + "\n"
}

func matchGlob(pattern, name string) bool {
	ok, err := path.Match(pattern, name)
	return err == nil && ok
}

func (s *shell) environ() string {
	env := map[string]string{
		"SHELL": "/bin/bash", "PWD": s.cwd, "LOGNAME": s.c.user, "HOME": s.c.home(), "USER": s.c.user,
		"PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LANG": "C.UTF-8", "SSH_CONNECTION": "10.20.3.1 51234 10.20.3.13 22", "HF_HOME": "/data/hf",
	}
	if s.term != "" {
		env["TERM"] = s.term
	}
	for k, v := range s.env {
		env[k] = v
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s=%s\n", k, env[k])
	}
	return b.String()
}

// expand substitutes $VAR and ${VAR} from the session environment.
func (s *shell) expand(text string) string {
	envText := s.environ()
	lookup := func(name string) string {
		for _, line := range strings.Split(envText, "\n") {
			if k, v, ok := strings.Cut(line, "="); ok && k == name {
				return v
			}
		}
		return ""
	}
	return regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?`).ReplaceAllStringFunc(text, func(m string) string {
		return lookup(strings.Trim(m, "${}"))
	})
}

func (s *shell) docker(operands []string) string {
	sub := ""
	if len(operands) > 0 {
		sub = operands[0]
	}
	switch sub {
	case "ps":
		return "CONTAINER ID   IMAGE                       COMMAND                  CREATED      STATUS      PORTS                      NAMES\n" +
			"4f1c9a2b7e83   vllm/vllm-openai:v0.10.1    \"python3 -m vllm.ent…\"   7 days ago   Up 7 days   127.0.0.1:8000->8000/tcp   vllm-vllm-1\n"
	case "images":
		return "REPOSITORY          TAG        IMAGE ID       CREATED        SIZE\nvllm/vllm-openai    v0.10.1    9c3b8d1e4a77   3 weeks ago    16.4GB\n"
	case "compose":
		if len(operands) > 1 && operands[1] == "ps" {
			return "NAME          IMAGE                      COMMAND                  SERVICE   CREATED      STATUS      PORTS\n" +
				"vllm-vllm-1   vllm/vllm-openai:v0.10.1   \"python3 -m vllm.ent…\"   vllm      7 days ago   Up 7 days   127.0.0.1:8000->8000/tcp\n"
		}
		return "no configuration file provided: not found\n"
	case "logs":
		return "INFO:     Started server process [1]\nINFO:     Waiting for application startup.\nINFO 09-20 11:42:07 api_server.py:517] Loaded model meta-llama/Llama-3.3-70B-Instruct\nINFO:     Uvicorn running on http://0.0.0.0:8000 (Press CTRL+C to quit)\n"
	case "inspect", "exec", "run", "pull", "build":
		return "permission denied while trying to connect to the Docker daemon socket\n"
	}
	return "docker: 'docker " + sub + "' is not a docker command.\nSee 'docker --help'\n"
}

func (s *shell) systemctl(operands []string) (string, int) {
	if len(operands) >= 2 && (operands[0] == "restart" || operands[0] == "stop" || operands[0] == "start") {
		s.c.emit(events.KindToolCall, map[string]any{"op": "ssh_service", "command": truncate(strings.Join(operands, " "), 200)})
		return "Failed to " + operands[0] + " " + operands[1] + ": Interactive authentication required.\n", 1
	}
	if len(operands) >= 2 && operands[0] == "status" {
		return "● " + operands[1] + " - " + operands[1] + "\n     Loaded: loaded\n     Active: active (running)\n", 0
	}
	return "UNIT                       LOAD   ACTIVE SUB     DESCRIPTION\ndocker.service             loaded active running Docker Application Container Engine\nssh.service                loaded active running OpenBSD Secure Shell server\n", 0
}

// fetch handles an outbound HTTP attempt from the node. The metadata service
// and the node's own vLLM are answered; a request to the outside world goes
// through the controlled egress broker (recorded, canaries flagged as
// exfiltration, then simulated for a collector or refused); an internal host is
// a lateral probe that fails closed. The URL is where the actor wanted to send
// data, and -d @file / -T uploads are read so the exfiltrated bytes are seen.
func (s *shell) fetch(cmd string, args []string) (string, int) {
	var target string
	for _, a := range args {
		if strings.HasPrefix(a, "http://") || strings.HasPrefix(a, "https://") || (!strings.HasPrefix(a, "-") && strings.Contains(a, ".")) {
			target = a
			break
		}
	}
	host, urlPath := splitURL(target)
	// The metadata service is on the box, not an egress target: it hands out
	// the instance role's temporary credentials on a tokenless GET.
	if isIMDSHost(host) {
		return s.c.s.imds(s.c.request(), fetchMethod(args), urlPath), 0
	}
	// The outside world goes through the controlled egress broker.
	if target != "" && !s.c.s.isInternalHost(host) {
		res := s.c.s.egress(s.c.request(), egressReq{Via: "ssh", Tool: cmd, Method: fetchMethod(args),
			URL: target, Host: host, Body: s.outboundBody(args)})
		if res.Action == egressSimulate {
			return res.Body, 0
		}
		return egressDenied(cmd, host)
	}
	// Internal destinations: the node's own vLLM is answered, anything else is a
	// lateral probe. Both are recorded as an outbound attempt.
	expanded := s.expand(strings.Join(args, " "))
	s.c.emit(events.KindToolCall, map[string]any{"op": "ssh_fetch", "tool": cmd,
		"url": truncate(target, 500), "command": truncate(expanded, 1000)})
	if strings.HasPrefix(host, "localhost:8000") || strings.HasPrefix(host, "127.0.0.1:8000") {
		if strings.Contains(target, "/v1/models") {
			return `{"object":"list","data":[{"id":"meta-llama/Llama-3.3-70B-Instruct","object":"model","owned_by":"vllm"}]}` + "\n", 0
		}
		return `{"detail":"Not Found"}` + "\n", 0
	}
	if target == "" {
		return "curl: try 'curl --help' for more information\n", 2
	}
	return egressDenied(cmd, host)
}

// egressDenied is the connection failure an egress-firewalled host returns.
func egressDenied(cmd, host string) (string, int) {
	h := host
	if hh, _, ok := strings.Cut(host, ":"); ok {
		h = hh
	}
	if cmd == "wget" {
		return fmt.Sprintf("--%s--  connect to %s\nConnecting to %s... failed: Connection timed out.\nwget: unable to connect to remote host.\n",
			time.Now().Format("2006-01-02 15:04:05"), host, host), 4
	}
	return fmt.Sprintf("curl: (28) Failed to connect to %s port 443 after 130004 ms: Couldn't connect to server\n", h), 28
}

// outboundBody assembles the request payload from curl/wget data arguments,
// reading @file references (which mints canaries) so exfiltrated file contents
// are captured and scanned.
func (s *shell) outboundBody(args []string) string {
	var parts []string
	inline := func(v string) string {
		if body, ok := strings.CutPrefix(v, "@"); ok {
			if content, ok := s.file(s.resolve(body)); ok {
				return content
			}
			return ""
		}
		return v
	}
	form := func(v string) string {
		if _, val, ok := strings.Cut(v, "="); ok {
			return inline(val)
		}
		return inline(v)
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch {
		case a == "-d" || a == "--data" || a == "--data-raw" || a == "--data-binary" || a == "--data-urlencode" || a == "--json":
			parts = append(parts, inline(next()))
		case strings.HasPrefix(a, "--data="):
			parts = append(parts, inline(strings.TrimPrefix(a, "--data=")))
		case strings.HasPrefix(a, "-d") && len(a) > 2:
			parts = append(parts, inline(a[2:]))
		case a == "-F" || a == "--form":
			parts = append(parts, form(next()))
		case a == "-T" || a == "--upload-file":
			if content, ok := s.file(s.resolve(next())); ok {
				parts = append(parts, content)
			}
		}
	}
	return strings.Join(parts, "&")
}

// splitURL returns the host[:port] and path of a possibly scheme-less URL.
func splitURL(target string) (host, urlPath string) {
	rest := strings.TrimPrefix(strings.TrimPrefix(target, "https://"), "http://")
	host, after, found := strings.Cut(rest, "/")
	if found {
		urlPath = "/" + after
	}
	if i := strings.IndexByte(urlPath, '?'); i >= 0 {
		urlPath = urlPath[:i]
	}
	return host, urlPath
}

// fetchMethod extracts the HTTP method from curl/wget arguments (-X/--request).
func fetchMethod(args []string) string {
	for i, a := range args {
		switch {
		case a == "-X" || a == "--request":
			if i+1 < len(args) {
				return strings.ToUpper(args[i+1])
			}
		case strings.HasPrefix(a, "-X"):
			return strings.ToUpper(strings.TrimPrefix(a, "-X"))
		}
	}
	return "GET"
}

func (s *shell) nvidiaSMI() string {
	now := time.Now().Format("Mon Jan _2 15:04:05 2006")
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", now)
	b.WriteString("+-----------------------------------------------------------------------------------------+\n")
	b.WriteString("| NVIDIA-SMI 560.35.03              Driver Version: 560.35.03      CUDA Version: 12.6     |\n")
	b.WriteString("|-----------------------------------------+------------------------+----------------------+\n")
	b.WriteString("| GPU  Name                 Persistence-M | Bus-Id          Disp.A | Volatile Uncorr. ECC |\n")
	b.WriteString("| Fan  Temp   Perf          Pwr:Usage/Cap |           Memory-Usage | GPU-Util  Compute M. |\n")
	b.WriteString("|=========================================+========================+======================|\n")
	for i := 0; i < 4; i++ {
		temp := 61 + rand.IntN(8)
		pwr := 290 + rand.IntN(90)
		used := 68000 + rand.IntN(4000)
		util := 82 + rand.IntN(18)
		fmt.Fprintf(&b, "|   %d  NVIDIA H100 80GB HBM3          On  | 00000000:%02X:00.0 Off |                    0 |\n", i, 0x18+i*8)
		fmt.Fprintf(&b, "| N/A   %dC    P0            %3dW / 700W |  %5dMiB / 81559MiB |     %2d%%      Default |\n", temp, pwr, used, util)
		b.WriteString("|                                         |                        |             Disabled |\n")
		b.WriteString("+-----------------------------------------+------------------------+----------------------+\n")
	}
	b.WriteString("\n+-----------------------------------------------------------------------------------------+\n")
	b.WriteString("| Processes:                                                                              |\n")
	b.WriteString("|  GPU   GI   CI        PID   Type   Process name                              GPU Memory |\n")
	b.WriteString("|        ID   ID                                                               Usage      |\n")
	b.WriteString("|=========================================================================================|\n")
	for i := 0; i < 4; i++ {
		fmt.Fprintf(&b, "|    %d   N/A  N/A     20411      C   python3                                   %5dMiB |\n", i, 68000+rand.IntN(4000))
	}
	b.WriteString("+-----------------------------------------------------------------------------------------+\n")
	return b.String()
}

// split separates flags from operands, keeping flag arguments with the flags.
func split(args []string) (flags, operands []string) {
	for _, a := range args {
		if strings.HasPrefix(a, "-") && a != "-" {
			flags = append(flags, a)
		} else {
			operands = append(operands, a)
		}
	}
	return flags, operands
}

func firstOperand(operands []string) string {
	if len(operands) == 0 {
		return ""
	}
	return operands[0]
}
