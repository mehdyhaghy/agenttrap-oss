package demogpu

import (
	"bufio"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"agenttrap/internal/events"
)

func pgTestServer(t *testing.T) (string, *Server, *sink) {
	t.Helper()
	s, rec := newTestServer(t, Options{})
	if s.pack.Postgres == nil {
		t.Fatal("built-in pack has no postgres section")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = s.ServePostgres(ctx, ln, PostgresOptions{}) }()
	return ln.Addr().String(), s, rec
}

type pgClient struct {
	c  net.Conn
	br *bufio.Reader
}

func dialPG(t *testing.T, addr, user, db, password string) (*pgClient, []pgMessage) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	t.Cleanup(func() { c.Close() })
	cl := &pgClient{c: c, br: bufio.NewReader(c)}

	// SSLRequest -> expect 'N'.
	cl.writeStartupRaw(t, pgSSLRequest, nil)
	b := make([]byte, 1)
	if _, err := io.ReadFull(cl.br, b); err != nil || b[0] != 'N' {
		t.Fatalf("ssl negotiation: %q err=%v", b, err)
	}
	// StartupMessage.
	body := be32(pgProtocolV3)
	for _, kv := range [][2]string{{"user", user}, {"database", db}, {"application_name", "psql"}} {
		body = append(body, cstr(kv[0])...)
		body = append(body, cstr(kv[1])...)
	}
	body = append(body, 0)
	cl.writeStartupBody(t, body)

	// Expect AuthenticationCleartextPassword.
	m := cl.read(t)
	if m.Type != 'R' || binary.BigEndian.Uint32(m.Body[:4]) != 3 {
		t.Fatalf("expected cleartext auth request, got %q %v", m.Type, m.Body)
	}
	// PasswordMessage.
	cl.writeMsg('p', cstr(password))

	// Read until ReadyForQuery or ErrorResponse.
	var msgs []pgMessage
	for {
		m := cl.read(t)
		msgs = append(msgs, m)
		if m.Type == 'Z' || m.Type == 'E' {
			break
		}
	}
	return cl, msgs
}

func (cl *pgClient) writeStartupRaw(t *testing.T, code int32, extra []byte) {
	body := append(be32(code), extra...)
	cl.writeStartupBody(t, body)
}

func (cl *pgClient) writeStartupBody(t *testing.T, body []byte) {
	t.Helper()
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(body)+4))
	if _, err := cl.c.Write(append(l[:], body...)); err != nil {
		t.Fatal(err)
	}
}

func (cl *pgClient) writeMsg(typ byte, body []byte) {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(body)+4))
	_, _ = cl.c.Write(append([]byte{typ}, append(l[:], body...)...))
}

func (cl *pgClient) read(t *testing.T) pgMessage {
	t.Helper()
	m, err := readMessage(cl.br)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return m
}

func (cl *pgClient) query(t *testing.T, sql string) []pgMessage {
	cl.writeMsg('Q', cstr(sql))
	var msgs []pgMessage
	for {
		m := cl.read(t)
		msgs = append(msgs, m)
		if m.Type == 'Z' {
			return msgs
		}
	}
}

func dataRows(msgs []pgMessage) [][]string {
	var out [][]string
	for _, m := range msgs {
		if m.Type != 'D' {
			continue
		}
		n := int(binary.BigEndian.Uint16(m.Body[:2]))
		cells := make([]string, 0, n)
		off := 2
		for i := 0; i < n; i++ {
			l := int32(binary.BigEndian.Uint32(m.Body[off:]))
			off += 4
			if l < 0 {
				cells = append(cells, "")
				continue
			}
			cells = append(cells, string(m.Body[off:off+int(l)]))
			off += int(l)
		}
		out = append(out, cells)
	}
	return out
}

func pgPassword(s *Server) string {
	u := s.pack.Postgres.Users[0]
	return s.canaries.Value(u.Slot)
}

func TestPostgresRejectsWrongPassword(t *testing.T) {
	addr, s, rec := pgTestServer(t)
	_, msgs := dialPG(t, addr, s.pack.Postgres.Users[0].Name, "demogpu", "hunter2")
	if len(msgs) != 1 || msgs[0].Type != 'E' {
		t.Fatalf("expected an ErrorResponse, got %+v", msgs)
	}
	var auth, connect bool
	for _, ev := range rec.evs {
		if ev.Kind == events.KindAuth && ev.Protocol == "postgres" {
			auth = true
			if ev.Detail["matched"] != false {
				t.Fatal("wrong password recorded as matched")
			}
		}
		if ev.Kind == events.KindConnect && ev.Protocol == "postgres" {
			connect = true
			if ev.Detail["username"] != s.pack.Postgres.Users[0].Name {
				t.Fatalf("startup username not recorded: %+v", ev.Detail)
			}
		}
	}
	if !auth || !connect {
		t.Fatalf("auth=%v connect=%v not recorded", auth, connect)
	}
}

func TestPostgresPlantedLoginAndKeyDump(t *testing.T) {
	addr, s, rec := pgTestServer(t)
	cl, msgs := dialPG(t, addr, s.pack.Postgres.Users[0].Name, "demogpu", pgPassword(s))
	// The handshake must end with ReadyForQuery, not an error.
	last := msgs[len(msgs)-1]
	if last.Type != 'Z' {
		t.Fatalf("planted login did not reach ReadyForQuery: %q", last.Type)
	}

	// version() answers with the persona's version.
	vm := cl.query(t, "SELECT version();")
	rows := dataRows(vm)
	if len(rows) != 1 || rows[0][0] == "" {
		t.Fatalf("version(): %+v", rows)
	}

	// Dumping the keys table mints a per-exposure provider key.
	km := cl.query(t, "select * from api_keys")
	rows = dataRows(km)
	if len(rows) != 2 {
		t.Fatalf("api_keys rows: %d", len(rows))
	}
	secret := rows[0][3]
	if slot, id, ok := s.canaries.Identify(secret); !ok || slot != SlotVLLMKey || id == "" {
		t.Fatalf("api_keys did not mint a provider key: %q slot=%q", secret, slot)
	}
	if !hasEvent(rec.evs, events.KindCanaryExposed, SlotVLLMKey) {
		t.Fatal("provider key exposure not recorded")
	}
	var queries int
	for _, ev := range rec.evs {
		if ev.Detail["op"] == "pg_query" {
			queries++
		}
	}
	if queries < 2 {
		t.Fatalf("queries not recorded: %d", queries)
	}
}
