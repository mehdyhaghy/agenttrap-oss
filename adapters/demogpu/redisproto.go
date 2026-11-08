package demogpu

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Minimal RESP (REdis Serialization Protocol) reader and writers for the Redis
// decoy. It parses the RESP array form real clients send and the inline form a
// human at netcat types, and writes RESP2/RESP3 replies.

var errRedisProtocol = errors.New("redis: protocol error")

// readCommand reads one command as a slice of arguments. It accepts both the
// RESP array form (*N\r\n$len\r\n...) and inline commands.
func readCommand(br *bufio.Reader) ([]string, error) {
	prefix, err := br.ReadByte()
	if err != nil {
		return nil, err
	}
	if prefix != '*' {
		// Inline command: the rest of the line, whitespace-split.
		_ = br.UnreadByte()
		line, err := readLine(br)
		if err != nil {
			return nil, err
		}
		return strings.Fields(line), nil
	}
	n, err := readCount(br)
	if err != nil {
		return nil, err
	}
	if n <= 0 || n > redisMaxArgs {
		if n <= 0 {
			return nil, nil
		}
		return nil, errRedisProtocol
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if b, err := br.ReadByte(); err != nil {
			return nil, err
		} else if b != '$' {
			return nil, errRedisProtocol
		}
		length, err := readCount(br)
		if err != nil {
			return nil, err
		}
		if length < 0 || length > redisMaxBulk {
			return nil, errRedisProtocol
		}
		buf := make([]byte, length+2) // include trailing CRLF
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:length]))
	}
	return args, nil
}

// readLine reads one line of at most redisMaxLine bytes. It never buffers
// more than that, so a client streaming bytes without a newline cannot grow
// memory.
func readLine(br *bufio.Reader) (string, error) {
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(line)+len(chunk) > redisMaxLine {
			return "", errRedisProtocol
		}
		line = append(line, chunk...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(line), "\r\n"), nil
	}
}

func readCount(br *bufio.Reader) (int, error) {
	line, err := readLine(br)
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		return 0, errRedisProtocol
	}
	return n, nil
}

func writeSimple(w *bufio.Writer, s string) { fmt.Fprintf(w, "+%s\r\n", s) }
func writeErr(w *bufio.Writer, s string)    { fmt.Fprintf(w, "-%s\r\n", s) }
func writeInt(w *bufio.Writer, n int64)     { fmt.Fprintf(w, ":%d\r\n", n) }

func writeBulk(w *bufio.Writer, s string) {
	fmt.Fprintf(w, "$%d\r\n", len(s))
	_, _ = w.WriteString(s)
	_, _ = w.WriteString("\r\n")
}

// writeNil writes the null reply in the client's protocol: $-1 in RESP2, _ in RESP3.
func writeNil(w *bufio.Writer, resp3 bool) {
	if resp3 {
		_, _ = w.WriteString("_\r\n")
		return
	}
	_, _ = w.WriteString("$-1\r\n")
}

func writeArray(w *bufio.Writer, n int)       { fmt.Fprintf(w, "*%d\r\n", n) }
func writeArrayHeader(w *bufio.Writer, n int) { fmt.Fprintf(w, "*%d\r\n", n) }
func writeMapHeader(w *bufio.Writer, n int)   { fmt.Fprintf(w, "%%%d\r\n", n) }

// writeConfigGet answers CONFIG GET with the parameters matching pat as a flat
// array of key, value pairs.
func writeConfigGet(w *bufio.Writer, cfg map[string]string, pat string) {
	type kv struct{ k, v string }
	var out []kv
	for k, v := range cfg {
		if globMatch(pat, k) {
			out = append(out, kv{k, v})
		}
	}
	writeArrayHeader(w, len(out)*2)
	for _, e := range out {
		writeBulk(w, e.k)
		writeBulk(w, e.v)
	}
}

// globMatch is a small case-insensitive glob for CONFIG GET patterns: it
// supports a leading/trailing/whole "*", enough for the recon clients use.
func globMatch(pat, s string) bool {
	pat, s = strings.ToLower(pat), strings.ToLower(s)
	switch {
	case pat == "*" || pat == "":
		return true
	case strings.HasPrefix(pat, "*") && strings.HasSuffix(pat, "*"):
		return strings.Contains(s, strings.Trim(pat, "*"))
	case strings.HasSuffix(pat, "*"):
		return strings.HasPrefix(s, strings.TrimSuffix(pat, "*"))
	case strings.HasPrefix(pat, "*"):
		return strings.HasSuffix(s, strings.TrimPrefix(pat, "*"))
	default:
		return pat == s
	}
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func mustInt(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}

// clipArgs bounds recorded argument lists so a flood of huge arguments cannot
// bloat an event.
func clipArgs(args []string) []string {
	const maxArgs, maxLen = 12, 200
	out := make([]string, 0, min(len(args), maxArgs))
	for i, a := range args {
		if i >= maxArgs {
			out = append(out, fmt.Sprintf("...(+%d)", len(args)-maxArgs))
			break
		}
		out = append(out, truncate(a, maxLen))
	}
	return out
}

// redisRunID is the stable 40-hex run_id shown in INFO/HELLO, derived from the
// spoke's canary seed so it does not change across restarts.
func (s *Server) redisRunID() string {
	return hex.EncodeToString(s.canaries.Subkey("redis-run-id"))[:40]
}
