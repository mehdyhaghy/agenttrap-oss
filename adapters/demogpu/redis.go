package demogpu

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"agenttrap/internal/events"
)

// The Redis surface is the persona's cache on port 6379: an exposed,
// unauthenticated-looking Redis. It speaks enough of RESP to look real,
// answers from the world pack, and records every command. Nothing is stored
// and nothing is executed: the classic exposed-Redis takeover moves (CONFIG
// SET dir/dbfilename then SAVE, SLAVEOF, MODULE LOAD) are answered with the
// realistic success reply an attacker expects, but only the attempt — and the
// address or path it names — is recorded. Reading a planted key mints a
// per-exposure canary, so a later use of that value names this exact read.

// RedisOptions configures the Redis surface.
type RedisOptions struct {
	Relays   []netip.Prefix // peers allowed to send a PROXY header (the relay)
	MaxConns int
}

const (
	redisAuthTimeout = 30 * time.Second
	redisIdleTimeout = 5 * time.Minute
	redisMaxCommands = 500
	redisMaxArgs     = 1024
	redisMaxBulk     = 64 << 10 // 64 KiB per argument
	redisMaxLine     = 64 << 10
)

// ServeRedis accepts connections on ln until ctx ends.
func (s *Server) ServeRedis(ctx context.Context, ln net.Listener, opts RedisOptions) error {
	if s.pack.Redis == nil {
		return errors.New("demogpu: world pack has no redis section")
	}
	if opts.MaxConns == 0 {
		opts.MaxConns = 256
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	var active atomic.Int64
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		if active.Add(1) > int64(opts.MaxConns) {
			active.Add(-1)
			_ = c.Close()
			continue
		}
		go func() {
			defer active.Add(-1)
			s.handleRedis(ctx, c, opts)
		}()
	}
}

// redisConn is one client connection's context.
type redisConn struct {
	s      *Server
	ctx    context.Context
	source string
	port   string
	id     string
	resp3  bool // client switched to RESP3 with HELLO 3
	n      int  // commands seen
}

// request builds the synthetic HTTP request the facade's recording helpers
// take, so Redis events carry the same source handling as HTTP ones.
func (c *redisConn) request() *http.Request {
	r := (&http.Request{Method: "REDIS", Header: http.Header{}, URL: &url.URL{Path: ""}, Host: c.s.domain}).
		WithContext(withInfo(c.ctx, &reqInfo{surface: "redis", source: c.source}))
	return r
}

func (c *redisConn) emit(kind string, detail map[string]any) {
	detail["redis_session"] = c.id
	detail["client_port"] = c.port
	c.s.emit(c.request(), events.Event{Kind: kind, Protocol: "redis", Detail: detail})
}

func (s *Server) handleRedis(ctx context.Context, raw net.Conn, opts RedisOptions) {
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(redisAuthTimeout))
	conn, ip, port := proxied(raw, opts.Relays)
	c := &redisConn{s: s, ctx: ctx, source: s.pseudonymize(ip), port: port, id: randomHex(8)}
	c.emit(events.KindConnect, map[string]any{"where": "redis", "result": "open"})

	br := bufio.NewReaderSize(conn, 4096)
	bw := bufio.NewWriter(conn)
	for {
		args, err := readCommand(br)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		c.n++
		if c.n > redisMaxCommands {
			return
		}
		_ = raw.SetDeadline(time.Now().Add(redisIdleTimeout))
		if quit := c.dispatch(bw, args); quit {
			_ = bw.Flush()
			return
		}
		if err := bw.Flush(); err != nil {
			return
		}
	}
}

// dispatch handles one command and returns true when the connection should
// close (QUIT). Every command is recorded; the classic takeover moves are
// tagged so they stand out.
func (c *redisConn) dispatch(w *bufio.Writer, args []string) bool {
	cmd := strings.ToUpper(args[0])
	detail := map[string]any{"op": "redis_command", "command": truncate(cmd, 32), "args": clipArgs(args[1:])}
	switch cmd {
	case "PING":
		if len(args) > 1 {
			writeBulk(w, args[1])
		} else {
			writeSimple(w, "PONG")
		}
	case "ECHO":
		if len(args) > 1 {
			writeBulk(w, args[1])
		} else {
			writeErr(w, "ERR wrong number of arguments for 'echo' command")
		}
	case "QUIT":
		writeSimple(w, "OK")
		c.emit(events.KindToolCall, detail)
		return true
	case "AUTH":
		// Record the credential, then answer like a server with no password
		// set — the state that makes an exposed Redis worth attacking.
		pw := args[len(args)-1]
		user := ""
		if len(args) == 3 {
			user = args[1]
		}
		slot := c.credential(pw, "redis")
		detail["op"] = "redis_command"
		detail["auth_user"] = truncate(user, 64)
		detail["matched"] = slot != ""
		c.emit(events.KindToolCall, detail)
		writeErr(w, "ERR Client sent AUTH, but no password is set. Did you mean AUTH <username> <password>?")
		return false
	case "HELLO":
		c.hello(w, args)
	case "INFO":
		writeBulk(w, c.info(args))
	case "CONFIG":
		c.config(w, args, detail)
		return false
	case "COMMAND":
		// COMMAND DOCS / COUNT / empty: a small, plausible reply.
		if len(args) > 1 && strings.EqualFold(args[1], "COUNT") {
			writeInt(w, 240)
		} else {
			writeArray(w, 0)
		}
	case "CLIENT":
		c.client(w, args)
	case "SELECT":
		writeSimple(w, "OK")
	case "DBSIZE":
		writeInt(w, int64(len(c.s.pack.Redis.Keys)))
	case "KEYS", "SCAN":
		c.keys(w, cmd, args)
	case "TYPE":
		writeSimple(w, "string")
	case "TTL", "PTTL":
		writeInt(w, -1)
	case "GET", "GETRANGE", "MGET", "HGETALL", "LRANGE", "SMEMBERS", "DUMP":
		c.read(w, cmd, args, detail)
		return false
	case "SET", "SETEX", "MSET", "HSET", "APPEND", "DEL", "EXPIRE", "RENAME", "FLUSHALL", "FLUSHDB":
		writeSimple(w, "OK")
	case "SAVE", "BGSAVE", "BGREWRITEAOF":
		// The write step of the CONFIG SET file technique. Nothing is written.
		detail["op"] = "redis_persist"
		c.emit(events.KindToolCall, detail)
		if cmd == "SAVE" {
			writeSimple(w, "OK")
		} else {
			writeSimple(w, "Background saving started")
		}
		return false
	case "SLAVEOF", "REPLICAOF":
		// Replication-based takeover: the arguments name the attacker's own
		// host. Record it; start no replication.
		detail["op"] = "redis_replicaof"
		if len(args) >= 3 {
			detail["master"] = truncate(net.JoinHostPort(args[1], args[2]), 120)
		}
		c.emit(events.KindToolCall, detail)
		writeSimple(w, "OK")
		return false
	case "MODULE":
		// MODULE LOAD <path>: loading a malicious module for RCE.
		detail["op"] = "redis_module"
		c.emit(events.KindToolCall, detail)
		if len(args) > 1 && strings.EqualFold(args[1], "LIST") {
			writeArray(w, 0)
		} else {
			writeErr(w, "ERR Error loading the extension. Please check the server logs.")
		}
		return false
	case "EVAL", "EVALSHA", "FUNCTION", "SCRIPT", "DEBUG":
		detail["op"] = "redis_exec"
		c.emit(events.KindToolCall, detail)
		writeErr(w, "ERR unknown command or arguments")
		return false
	case "SUBSCRIBE", "PSUBSCRIBE", "MONITOR", "WAIT":
		writeErr(w, "ERR unsupported in this context")
	default:
		c.emit(events.KindToolCall, detail)
		writeErr(w, fmt.Sprintf("ERR unknown command '%s'", truncate(strings.ToLower(args[0]), 32)))
		return false
	}
	c.emit(events.KindToolCall, detail)
	return false
}

// read serves a key read, minting a per-exposure canary when the value holds a
// {{canary:slot}} placeholder.
func (c *redisConn) read(w *bufio.Writer, cmd string, args []string, detail map[string]any) {
	if len(args) < 2 {
		c.emit(events.KindToolCall, detail)
		writeNil(w, c.resp3)
		return
	}
	if cmd == "MGET" {
		writeArrayHeader(w, len(args)-1)
		for _, k := range args[1:] {
			if v, ok := c.value(k); ok {
				writeBulk(w, v)
			} else {
				writeNil(w, c.resp3)
			}
		}
		c.emit(events.KindToolCall, detail)
		return
	}
	v, ok := c.value(args[1])
	c.emit(events.KindToolCall, detail)
	if !ok {
		writeNil(w, c.resp3)
		return
	}
	if cmd == "HGETALL" || cmd == "SMEMBERS" || cmd == "LRANGE" {
		writeArrayHeader(w, 1)
	}
	writeBulk(w, v)
}

// value returns a key's content with canary placeholders minted for this read.
func (c *redisConn) value(key string) (string, bool) {
	raw, ok := c.s.pack.Redis.Keys[key]
	if !ok {
		return "", false
	}
	r := c.request()
	return canaryRef.ReplaceAllStringFunc(raw, func(m string) string {
		slot := canaryRef.FindStringSubmatch(m)[1]
		return c.s.revealWith(r, slot, map[string]any{"via": "redis", "key": truncate(key, 120)})
	}), true
}

func (c *redisConn) keys(w *bufio.Writer, cmd string, args []string) {
	names := make([]string, 0, len(c.s.pack.Redis.Keys))
	for k := range c.s.pack.Redis.Keys {
		names = append(names, k)
	}
	sort.Strings(names)
	c.emit(events.KindToolCall, map[string]any{"op": "redis_command", "command": cmd, "args": clipArgs(args[1:])})
	if cmd == "SCAN" {
		// SCAN cursor ...: one page, cursor 0 (done).
		writeArrayHeader(w, 2)
		writeBulk(w, "0")
	}
	writeArrayHeader(w, len(names))
	for _, k := range names {
		writeBulk(w, k)
	}
}

func (c *redisConn) config(w *bufio.Writer, args []string, detail map[string]any) {
	if len(args) < 2 {
		writeErr(w, "ERR wrong number of arguments for 'config' command")
		return
	}
	switch strings.ToUpper(args[1]) {
	case "GET":
		pat := "*"
		if len(args) > 2 {
			pat = args[2]
		}
		c.emit(events.KindToolCall, detail)
		writeConfigGet(w, c.s.pack.Redis.Config, pat)
	case "SET":
		// CONFIG SET dir / dbfilename is the setup for writing a file
		// (authorized_keys, a cron job). Record it precisely; change nothing.
		detail["op"] = "redis_config_set"
		if len(args) >= 4 {
			detail["param"] = truncate(strings.ToLower(args[2]), 64)
			detail["value"] = truncate(args[3], 200)
		}
		c.emit(events.KindToolCall, detail)
		writeSimple(w, "OK")
	default:
		c.emit(events.KindToolCall, detail)
		writeSimple(w, "OK")
	}
}

func (c *redisConn) client(w *bufio.Writer, args []string) {
	if len(args) > 1 {
		switch strings.ToUpper(args[1]) {
		case "SETNAME", "SETINFO", "NO-EVICT", "NO-TOUCH", "REPLY":
			writeSimple(w, "OK")
			return
		case "GETNAME":
			writeBulk(w, "")
			return
		case "ID":
			writeInt(w, 42)
			return
		case "INFO":
			writeBulk(w, fmt.Sprintf("id=42 addr=%s:%s name= db=0 flags=N", c.source, c.port))
			return
		}
	}
	writeSimple(w, "OK")
}

func (c *redisConn) hello(w *bufio.Writer, args []string) {
	if len(args) > 1 {
		switch args[1] {
		case "3":
			c.resp3 = true
		case "2":
			c.resp3 = false
		default:
			writeErr(w, "NOPROTO unsupported protocol version")
			return
		}
	}
	proto := 2
	if c.resp3 {
		proto = 3
	}
	rd := c.s.pack.Redis
	fields := []struct{ k, v string }{
		{"server", "redis"}, {"version", rd.Version}, {"proto", strconv.Itoa(proto)},
		{"id", "42"}, {"mode", orDefault(rd.Mode, "standalone")}, {"role", orDefault(rd.Role, "master")},
	}
	if c.resp3 {
		writeMapHeader(w, len(fields))
	} else {
		writeArrayHeader(w, len(fields)*2)
	}
	for _, f := range fields {
		writeBulk(w, f.k)
		if f.k == "proto" || f.k == "id" {
			writeInt(w, mustInt(f.v))
		} else {
			writeBulk(w, f.v)
		}
	}
}

func (c *redisConn) info(args []string) string {
	rd := c.s.pack.Redis
	var b strings.Builder
	fmt.Fprintf(&b, "# Server\r\nredis_version:%s\r\nredis_mode:%s\r\nos:%s\r\narch_bits:64\r\nprocess_id:1\r\nrun_id:%s\r\ntcp_port:6379\r\nuptime_in_seconds:%d\r\n",
		rd.Version, orDefault(rd.Mode, "standalone"), orDefault(rd.OS, "Linux 6.8.0 x86_64"), c.s.redisRunID(), 3600*24*11)
	fmt.Fprintf(&b, "\r\n# Clients\r\nconnected_clients:2\r\n")
	fmt.Fprintf(&b, "\r\n# Memory\r\nused_memory:8123456\r\nused_memory_human:7.75M\r\nmaxmemory:0\r\nmaxmemory_policy:noeviction\r\n")
	fmt.Fprintf(&b, "\r\n# Persistence\r\nrdb_bgsave_in_progress:0\r\nrdb_last_save_time:%d\r\naof_enabled:0\r\n", time.Now().Add(-2*time.Hour).Unix())
	fmt.Fprintf(&b, "\r\n# Replication\r\nrole:%s\r\nconnected_slaves:0\r\n", orDefault(rd.Role, "master"))
	fmt.Fprintf(&b, "\r\n# Keyspace\r\ndb0:keys=%d,expires=0,avg_ttl=0\r\n", len(rd.Keys))
	return b.String()
}

// credential records a presented Redis credential and returns the canary slot
// it matches, if any.
func (c *redisConn) credential(pw, where string) string {
	return c.s.credential(c.request(), pw, where)
}
