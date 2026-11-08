package demogpu

import (
	"bufio"
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"agenttrap/internal/events"
	"agenttrap/internal/worldpack"
)

// The Postgres surface is the persona's database on port 5432. It speaks the
// v3 wire protocol, asks for a cleartext password (so every attempt is
// captured), and records the user, database and application_name a client
// declares. A planted role and password open a read-only session that answers
// canned recon queries from the world pack; reading a planted row mints a
// per-exposure canary. Nothing runs, and no real database is reachable — the
// spoke has no route to it.

// PostgresOptions configures the Postgres surface.
type PostgresOptions struct {
	Relays   []netip.Prefix
	MaxConns int
}

const (
	pgAuthTimeout    = 30 * time.Second
	pgSessionTimeout = 15 * time.Minute
	pgMaxQueries     = 200
)

// ServePostgres accepts connections on ln until ctx ends.
func (s *Server) ServePostgres(ctx context.Context, ln net.Listener, opts PostgresOptions) error {
	if s.pack.Postgres == nil {
		return errors.New("demogpu: world pack has no postgres section")
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
			s.handlePostgres(ctx, c, opts)
		}()
	}
}

type pgConn struct {
	s       *Server
	ctx     context.Context
	source  string
	port    string
	id      string
	user    string
	db      string
	appName string
}

func (c *pgConn) request() *http.Request {
	return (&http.Request{Method: "PGSQL", Header: http.Header{}, URL: &url.URL{Path: ""}, Host: c.s.domain}).
		WithContext(withInfo(c.ctx, &reqInfo{surface: "postgres", source: c.source}))
}

func (c *pgConn) emit(kind string, detail map[string]any) {
	detail["pg_session"] = c.id
	detail["client_port"] = c.port
	c.s.emit(c.request(), events.Event{Kind: kind, Protocol: "postgres", Detail: detail})
}

func (s *Server) handlePostgres(ctx context.Context, raw net.Conn, opts PostgresOptions) {
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(pgAuthTimeout))
	conn, ip, port := proxied(raw, opts.Relays)
	c := &pgConn{s: s, ctx: ctx, source: s.pseudonymize(ip), port: port, id: randomHex(8)}
	br := bufio.NewReaderSize(conn, 8192)
	bw := bufio.NewWriter(conn)
	pw := pgWriter{w: bw}

	// Negotiate SSL/GSSAPI: decline (plaintext), as an exposed instance would.
	params, ok := c.startup(br, bw, pw)
	if !ok {
		return
	}
	c.user = truncate(params["user"], 64)
	c.db = truncate(orDefault(params["database"], params["user"]), 64)
	c.appName = truncate(params["application_name"], 80)
	c.emit(events.KindConnect, map[string]any{"where": "postgres", "result": "startup",
		"username": c.user, "database": c.db, "application_name": c.appName})

	// Ask for a cleartext password so the attempt is captured verbatim.
	pw.authCleartext()
	if bw.Flush() != nil {
		return
	}
	msg, err := readMessage(br)
	if err != nil || msg.Type != 'p' {
		return
	}
	password := cString(msg.Body)
	slot := c.s.credential(c.request(), password, "postgres")
	authed := slot != "" && c.roleMatches(c.user, slot)
	c.emit(events.KindAuth, map[string]any{"where": "postgres", "username": c.user, "database": c.db,
		"password_len": len(password), "matched": authed})

	if !authed {
		pw.errorResponse("FATAL", "28P01", "password authentication failed for user \""+c.user+"\"")
		_ = bw.Flush()
		return
	}
	c.session(br, bw, pw, raw)
}

// startup handles SSL/GSSAPI negotiation and returns the startup parameters.
func (c *pgConn) startup(br *bufio.Reader, bw *bufio.Writer, pw pgWriter) (map[string]string, bool) {
	for i := 0; i < 3; i++ {
		code, body, err := readStartup(br)
		if err != nil {
			return nil, false
		}
		switch code {
		case pgSSLRequest, pgGSSENCReq:
			// 'N' = negotiation declined; the client continues in plaintext.
			_ = bw.WriteByte('N')
			if bw.Flush() != nil {
				return nil, false
			}
		case pgProtocolV3:
			return parseStartupParams(body), true
		case pgCancelReq:
			return nil, false
		default:
			pw.errorResponse("FATAL", "0A000", "unsupported frontend protocol")
			_ = bw.Flush()
			return nil, false
		}
	}
	return nil, false
}

func (c *pgConn) roleMatches(user, slot string) bool {
	for _, u := range c.s.pack.Postgres.Users {
		if u.Name == user && u.Slot == slot {
			return true
		}
	}
	return false
}

// session runs the authenticated read-only query loop.
func (c *pgConn) session(br *bufio.Reader, bw *bufio.Writer, pw pgWriter, raw net.Conn) {
	_ = raw.SetDeadline(time.Now().Add(pgSessionTimeout))
	pg := c.s.pack.Postgres
	pw.authOK()
	for _, ps := range []struct{ k, v string }{
		{"server_version", orDefault(pg.Version, "16.4")},
		{"server_encoding", "UTF8"}, {"client_encoding", "UTF8"},
		{"DateStyle", "ISO, MDY"}, {"TimeZone", "UTC"},
		{"standard_conforming_strings", "on"}, {"application_name", c.appName},
	} {
		pw.parameterStatus(ps.k, ps.v)
	}
	pw.backendKeyData(int32(1000+rand.IntN(60000)), rand.Int32())
	pw.readyForQuery('I')
	if bw.Flush() != nil {
		return
	}

	n := 0
	for {
		_ = raw.SetDeadline(time.Now().Add(pgSessionTimeout))
		msg, err := readMessage(br)
		if err != nil {
			return
		}
		switch msg.Type {
		case 'Q':
			n++
			if n > pgMaxQueries {
				return
			}
			c.query(pw, cString(msg.Body))
			if bw.Flush() != nil {
				return
			}
		case 'X': // Terminate
			return
		case 'S': // Sync (extended protocol)
			pw.readyForQuery('I')
			_ = bw.Flush()
		case 'P', 'B', 'D', 'E', 'C', 'H':
			// Extended query protocol: not supported by the decoy.
			pw.errorResponse("ERROR", "0A000", "extended query protocol not supported")
			pw.readyForQuery('I')
			_ = bw.Flush()
		default:
			return
		}
	}
}

var pgSpaces = regexp.MustCompile(`\s+`)

// query answers one simple query from the world pack's canned results.
func (c *pgConn) query(pw pgWriter, sql string) {
	norm := strings.TrimSuffix(strings.TrimSpace(pgSpaces.ReplaceAllString(strings.ToLower(sql), " ")), ";")
	c.emit(events.KindToolCall, map[string]any{"op": "pg_query", "query": truncate(sql, 2000)})

	q := c.match(norm)
	if q == nil {
		// Unknown SELECT: empty result; anything else: a bland completion.
		if strings.HasPrefix(norm, "select") || strings.HasPrefix(norm, "table ") || strings.HasPrefix(norm, "with ") {
			pw.commandComplete("SELECT 0")
		} else if norm == "" {
			pw.emptyQuery()
		} else {
			pw.commandComplete("SELECT 0")
		}
		pw.readyForQuery('I')
		return
	}
	pw.rowDescription(q.Columns)
	r := c.request()
	for _, row := range q.Rows {
		cells := make([]string, len(row))
		for i, cell := range row {
			cells[i] = canaryRef.ReplaceAllStringFunc(cell, func(m string) string {
				return c.s.revealWith(r, canaryRef.FindStringSubmatch(m)[1], map[string]any{"via": "postgres", "query": truncate(sql, 200)})
			})
		}
		pw.dataRow(cells)
	}
	tag := q.Tag
	if tag == "" {
		tag = "SELECT " + itoa(len(q.Rows))
	}
	pw.commandComplete(tag)
	pw.readyForQuery('I')
}

// match finds a canned query by exact match, then by prefix.
func (c *pgConn) match(norm string) *worldpack.PostgresQuery {
	qs := c.s.pack.Postgres.Queries
	for i := range qs {
		if strings.ToLower(qs[i].Match) == norm {
			return &qs[i]
		}
	}
	for i := range qs {
		if m := strings.ToLower(qs[i].Match); m != "" && strings.HasPrefix(norm, m) {
			return &qs[i]
		}
	}
	return nil
}

func (p pgWriter) emptyQuery() { p.msg('I', nil) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
