package demogpu

import (
	"fmt"
	"io"
	"math/rand/v2"
	"path"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"agenttrap/internal/events"
)

// The simulated shell. Every command is recorded and answered from the world
// pack; nothing runs on the host. Unknown commands get the shell's own
// "command not found", so the session ends when the client gives up rather
// than when we refuse.

const shellPromptFmt = "%s@%s:%s$ "

// session serves one SSH session channel.
func (c *sshConn) session(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	sh := &shell{c: c, cwd: c.home(), pty: false}
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			sh.pty = true
			var p struct {
				Term          string
				Cols, Rows    uint32
				Width, Height uint32
				Modes         string
			}
			_ = ssh.Unmarshal(req.Payload, &p)
			sh.term, sh.cols = p.Term, int(p.Cols)
			c.emit(events.KindToolCall, map[string]any{"op": "ssh_pty", "term": truncate(p.Term, 40),
				"cols": int(p.Cols), "rows": int(p.Rows)})
			reply(req, true)
		case "env":
			var p struct{ Name, Value string }
			_ = ssh.Unmarshal(req.Payload, &p)
			if sh.env == nil {
				sh.env = map[string]string{}
			}
			if len(sh.env) < 40 {
				sh.env[truncate(p.Name, 64)] = truncate(p.Value, 200)
			}
			reply(req, true)
		case "window-change":
			reply(req, true)
		case "shell":
			reply(req, true)
			sh.interactive(ch)
			return
		case "exec":
			var p struct{ Command string }
			_ = ssh.Unmarshal(req.Payload, &p)
			reply(req, true)
			c.emit(events.KindToolCall, map[string]any{"op": "ssh_exec", "command": truncate(p.Command, 2000)})
			status := sh.runLine(ch, p.Command)
			exit(ch, status)
			return
		case "subsystem":
			var p struct{ Name string }
			_ = ssh.Unmarshal(req.Payload, &p)
			// sftp is the usual next step after a shell: record the attempt.
			c.emit(events.KindToolCall, map[string]any{"op": "ssh_subsystem", "subsystem": truncate(p.Name, 40)})
			reply(req, false)
		default:
			reply(req, false)
		}
	}
}

func reply(req *ssh.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

func exit(ch ssh.Channel, status int) {
	_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(status)}))
}

type shell struct {
	c    *sshConn
	cwd  string
	pty  bool
	term string
	cols int
	env  map[string]string
	n    int // commands run
}

func (c *sshConn) home() string {
	for _, u := range c.s.pack.SSH.Users {
		if u.Name == c.user {
			return u.Home
		}
	}
	return "/home/" + c.user
}

// interactive runs the login shell: banner, prompt, line editing, commands.
func (s *shell) interactive(ch ssh.Channel) {
	write(ch, strings.ReplaceAll(s.c.s.pack.SSH.MOTD, "\n", "\r\n"))
	write(ch, "\r\n"+s.lastLogin()+"\r\n")
	for {
		write(ch, s.prompt())
		line, ok := s.readLine(ch)
		if !ok {
			return
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		s.c.emit(events.KindToolCall, map[string]any{"op": "ssh_command", "command": truncate(line, 2000), "cwd": s.cwd})
		if isExit(line) {
			write(ch, "logout\r\n")
			exit(ch, 0)
			return
		}
		s.runLine(ch, line)
		if s.n > 500 {
			return
		}
	}
}

func isExit(line string) bool {
	switch strings.TrimSpace(line) {
	case "exit", "logout", "quit":
		return true
	}
	return false
}

func (s *shell) prompt() string {
	cwd := s.cwd
	if cwd == s.c.home() {
		cwd = "~"
	} else if h := s.c.home(); strings.HasPrefix(cwd, h+"/") {
		cwd = "~" + strings.TrimPrefix(cwd, h)
	}
	return fmt.Sprintf(shellPromptFmt, s.c.user, s.c.s.pack.SSH.Hostname, cwd)
}

func (s *shell) lastLogin() string {
	t := time.Now().Add(-time.Duration(3+rand.IntN(20)) * time.Hour)
	return "Last login: " + t.Format("Mon Jan _2 15:04:05 2006") + " from 10.20.3.1\r\n"
}

// readLine reads one command line, echoing as a PTY shell does.
func (s *shell) readLine(ch ssh.Channel) (string, bool) {
	if !s.pty {
		// No PTY: the client pipes commands, so read plain lines.
		var line []byte
		buf := make([]byte, 1)
		for {
			n, err := ch.Read(buf)
			if n == 0 || err != nil {
				return string(line), len(line) > 0
			}
			if buf[0] == '\n' || buf[0] == '\r' {
				return string(line), true
			}
			if len(line) < 4096 {
				line = append(line, buf[0])
			}
		}
	}
	var line []rune
	buf := make([]byte, 1)
	for {
		n, err := ch.Read(buf)
		if n == 0 || err != nil {
			return "", false
		}
		switch b := buf[0]; b {
		case '\r', '\n':
			write(ch, "\r\n")
			return string(line), true
		case 0x7f, 0x08: // backspace
			if len(line) > 0 {
				line = line[:len(line)-1]
				write(ch, "\b \b")
			}
		case 0x03: // ctrl-c
			write(ch, "^C\r\n")
			return "", true
		case 0x04: // ctrl-d
			if len(line) == 0 {
				write(ch, "logout\r\n")
				return "", false
			}
		case 0x15: // ctrl-u
			for range line {
				write(ch, "\b \b")
			}
			line = nil
		case 0x1b: // escape sequences (arrows): swallow the next two bytes
			_, _ = ch.Read(buf)
			_, _ = ch.Read(buf)
		default:
			if b >= 0x20 && len(line) < 4096 {
				line = append(line, rune(b))
				write(ch, string(b))
			}
		}
	}
}

func write(ch ssh.Channel, s string) { _, _ = io.WriteString(ch, s) }

// out writes command output with the line endings the client expects.
func (s *shell) out(ch ssh.Channel, text string) {
	if s.pty {
		text = strings.ReplaceAll(text, "\n", "\r\n")
	}
	write(ch, text)
}

// runLine runs one command line (splitting on ; && ||) and returns the exit
// status of the last command.
func (s *shell) runLine(ch ssh.Channel, line string) int {
	status := 0
	for _, part := range splitCommands(line) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		s.n++
		if s.n > 500 {
			return status
		}
		status = s.run(ch, part)
	}
	return status
}

// splitCommands splits on ;, && and || outside quotes. Pipes stay in the
// command: the last stage decides the output (grep/head are handled there).
func splitCommands(line string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	for i := 0; i < len(line); i++ {
		c := rune(line[i])
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
			cur.WriteRune(c)
		case c == '\'' || c == '"':
			quote = c
			cur.WriteRune(c)
		case c == ';':
			out = append(out, cur.String())
			cur.Reset()
		case (c == '&' || c == '|') && i+1 < len(line) && rune(line[i+1]) == c:
			out = append(out, cur.String())
			cur.Reset()
			i++
		default:
			cur.WriteRune(c)
		}
	}
	out = append(out, cur.String())
	return out
}

// run executes one command and returns its exit status.
func (s *shell) run(ch ssh.Channel, cmdline string) int {
	// A pipeline's output is the last stage's; keep the first stage's data
	// and apply simple filters (grep, head, tail) after it.
	stages := splitPipeline(cmdline)
	args := fields(stages[0])
	if len(args) == 0 {
		return 0
	}
	// VAR=value prefixes.
	for len(args) > 1 && strings.Contains(args[0], "=") && !strings.HasPrefix(args[0], "-") {
		if s.env == nil {
			s.env = map[string]string{}
		}
		k, v, _ := strings.Cut(args[0], "=")
		s.env[k] = v
		args = args[1:]
	}
	text, status := s.command(ch, args)
	for _, st := range stages[1:] {
		text = applyFilter(text, fields(st))
	}
	if text != "" {
		s.out(ch, text)
	}
	return status
}

func splitPipeline(line string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	for _, c := range line {
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
			cur.WriteRune(c)
		case c == '\'' || c == '"':
			quote = c
			cur.WriteRune(c)
		case c == '|':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(c)
		}
	}
	return append(out, cur.String())
}

// fields splits a command into arguments, honouring quotes.
func fields(s string) []string {
	var out []string
	var cur strings.Builder
	var quote rune
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, c := range s {
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else {
				cur.WriteRune(c)
			}
		case c == '\'' || c == '"':
			quote = c
		case c == ' ' || c == '\t':
			flush()
		default:
			cur.WriteRune(c)
		}
	}
	flush()
	return out
}

// applyFilter applies grep/head/tail/wc to piped text.
func applyFilter(text string, args []string) string {
	if len(args) == 0 {
		return text
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	switch path.Base(args[0]) {
	case "grep", "egrep", "fgrep":
		var pat string
		invert := false
		for _, a := range args[1:] {
			switch {
			case a == "-v":
				invert = true
			case strings.HasPrefix(a, "-"):
			case pat == "":
				pat = a
			}
		}
		var keep []string
		for _, l := range lines {
			if strings.Contains(strings.ToLower(l), strings.ToLower(pat)) != invert {
				keep = append(keep, l)
			}
		}
		if len(keep) == 0 {
			return ""
		}
		return strings.Join(keep, "\n") + "\n"
	case "head", "tail":
		n := 10
		for i, a := range args {
			if a == "-n" && i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &n)
			} else if strings.HasPrefix(a, "-") && len(a) > 1 {
				fmt.Sscanf(a[1:], "%d", &n)
			}
		}
		n = min(max(n, 0), len(lines))
		if path.Base(args[0]) == "head" {
			lines = lines[:n]
		} else {
			lines = lines[len(lines)-n:]
		}
		return strings.Join(lines, "\n") + "\n"
	case "wc":
		return fmt.Sprintf("%8d%8d%8d\n", len(lines), len(strings.Fields(text)), len(text))
	case "jq", "cat", "less", "more", "sort", "uniq", "tr", "awk", "sed", "column":
		return text
	}
	return text
}
