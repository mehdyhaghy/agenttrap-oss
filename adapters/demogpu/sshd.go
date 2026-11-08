package demogpu

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ssh"

	"agenttrap/internal/events"
	"agenttrap/internal/worldpack"
)

// The SSH surface is the persona's GPU node on port 22. It records every
// connection and login attempt; only a planted credential opens a session,
// and the session is a simulated shell answering from the world pack
// (sshshell.go). Nothing is ever executed, and every channel type except an
// interactive session (port forwarding, agent forwarding, X11) is refused.

// SSHOptions configures the SSH surface.
type SSHOptions struct {
	HostKeys []ssh.Signer
	// Relays are the only peers allowed to send a PROXY protocol header
	// naming the real client (the relay container in front of port 22).
	Relays []netip.Prefix
	// MaxConns bounds concurrent connections.
	MaxConns int
}

const (
	sshAuthTimeout    = 30 * time.Second
	sshIdleTimeout    = 10 * time.Minute
	sshSessionTimeout = 30 * time.Minute
	sshMaxAuthTries   = 6
)

// ServeSSH accepts SSH connections on ln until ctx ends.
func (s *Server) ServeSSH(ctx context.Context, ln net.Listener, opts SSHOptions) error {
	if s.pack.SSH == nil {
		return errors.New("demogpu: world pack has no ssh section")
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
			s.handleSSH(ctx, c, opts)
		}()
	}
}

// sshConn is one client connection's context.
type sshConn struct {
	s       *Server
	ctx     context.Context
	source  string
	port    string
	version string
	id      string
	user    string
	shown   map[string]bool // public key fingerprints already recorded
}

// request builds the synthetic HTTP request the facade's recording helpers
// take, so SSH events carry the same source handling as HTTP ones.
func (c *sshConn) request() *http.Request {
	r := (&http.Request{Method: "SSH", Header: http.Header{}, URL: &url.URL{Path: ""}, Host: c.s.domain}).
		WithContext(withInfo(c.ctx, &reqInfo{surface: "ssh", source: c.source}))
	r.Header.Set("User-Agent", c.version)
	return r
}

func (c *sshConn) emit(kind string, detail map[string]any) {
	detail["ssh_session"] = c.id
	detail["client_port"] = c.port
	c.s.emit(c.request(), events.Event{Kind: kind, Protocol: "ssh", Detail: detail})
}

func (s *Server) handleSSH(ctx context.Context, raw net.Conn, opts SSHOptions) {
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(sshAuthTimeout))
	conn, ip, port := proxied(raw, opts.Relays)
	c := &sshConn{s: s, ctx: ctx, source: s.pseudonymize(ip), port: port, id: randomHex(8), shown: map[string]bool{}}

	cfg := &ssh.ServerConfig{
		ServerVersion: s.pack.SSH.Banner,
		MaxAuthTries:  sshMaxAuthTries,
		PasswordCallback: func(meta ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			return c.password(meta, string(pw), "password")
		},
		KeyboardInteractiveCallback: func(meta ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			ans, err := challenge("", "", []string{"Password: "}, []bool{false})
			if err != nil || len(ans) != 1 {
				return nil, errors.New("no answer")
			}
			return c.password(meta, ans[0], "keyboard-interactive")
		},
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			c.version = string(meta.ClientVersion())
			fp := ssh.FingerprintSHA256(key)
			if !c.shown[fp] && len(c.shown) < 20 {
				c.shown[fp] = true
				c.emit(events.KindAuth, map[string]any{"where": "ssh", "method": "publickey", "username": clipUser(meta.User()),
					"key_type": key.Type(), "key_fingerprint": fp})
			}
			return nil, errors.New("denied")
		},
	}
	for _, k := range opts.HostKeys {
		cfg.AddHostKey(k)
	}
	sc, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if c.version == "" && sc != nil {
		c.version = string(sc.ClientVersion())
	}
	if err != nil {
		// Scanners that only read the banner, and failed logins, end here.
		detail := map[string]any{"result": "closed"}
		var ve interface{ ClientVersion() []byte }
		if errors.As(err, &ve) {
			c.version = string(ve.ClientVersion())
		}
		if c.version != "" {
			detail["client_version"] = truncate(c.version, 255)
		}
		detail["error"] = truncate(err.Error(), 120)
		c.emit(events.KindConnect, detail)
		return
	}
	defer sc.Close()
	c.version = string(sc.ClientVersion())
	c.user = sc.User()
	c.emit(events.KindConnect, map[string]any{"result": "session", "client_version": truncate(c.version, 255), "username": clipUser(c.user)})
	_ = raw.SetDeadline(time.Now().Add(sshSessionTimeout))

	go func() {
		for req := range reqs {
			// Global requests (remote port forwarding, keepalives) are refused.
			if req.Type == "tcpip-forward" {
				c.emit(events.KindToolCall, map[string]any{"op": "ssh_forward", "direction": "remote", "payload": truncate(string(req.Payload), 200)})
			}
			if req.WantReply {
				_ = req.Reply(false, nil)
			}
		}
	}()
	// Concurrent sessions per connection, as OpenSSH's MaxSessions counts them.
	var sessions atomic.Int32
	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			if sessions.Add(1) > 10 {
				sessions.Add(-1)
				_ = nc.Reject(ssh.ResourceShortage, "too many sessions")
				continue
			}
			ch, creqs, err := nc.Accept()
			if err != nil {
				sessions.Add(-1)
				continue
			}
			go func() {
				defer sessions.Add(-1)
				c.session(ch, creqs)
			}()
		case "direct-tcpip":
			// Local port forwarding: where the client wanted to reach through us.
			var p struct {
				Host     string
				Port     uint32
				OrigHost string
				OrigPort uint32
			}
			_ = ssh.Unmarshal(nc.ExtraData(), &p)
			c.emit(events.KindToolCall, map[string]any{"op": "ssh_forward", "direction": "local",
				"target": truncate(net.JoinHostPort(p.Host, strconv.Itoa(int(p.Port))), 200)})
			_ = nc.Reject(ssh.Prohibited, "administratively prohibited: open failed")
		default:
			c.emit(events.KindToolCall, map[string]any{"op": "ssh_channel", "channel": truncate(nc.ChannelType(), 40)})
			_ = nc.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

// password records a password attempt and accepts only planted credentials:
// the SSH user's own password, or any other planted key reused as a
// password (credential reuse across protocols).
func (c *sshConn) password(meta ssh.ConnMetadata, pw, method string) (*ssh.Permissions, error) {
	c.version = string(meta.ClientVersion())
	r := c.request()
	user := meta.User()
	slot := c.s.credential(r, pw, "ssh")
	c.emit(events.KindAuth, map[string]any{"where": "ssh", "method": method, "username": clipUser(user),
		"password_len": len(pw), "password_sha256": sha256hex(pw), "matched": slot != ""})
	if slot != "" && slices.ContainsFunc(c.s.pack.SSH.Users, func(u worldpack.SSHUser) bool { return u.Name == user }) {
		return &ssh.Permissions{Extensions: map[string]string{"slot": slot}}, nil
	}
	// OpenSSH delays failed attempts; an instant refusal is a tell.
	d := time.Duration(1500+rand.IntN(1500)) * time.Millisecond
	select {
	case <-time.After(d):
	case <-c.ctx.Done():
	}
	return nil, errors.New("denied")
}

// proxied reads a PROXY protocol v1 header when the peer is a trusted relay
// and returns the connection (with any buffered bytes) and the client address.
func proxied(c net.Conn, relays []netip.Prefix) (net.Conn, string, string) {
	host, port, _ := net.SplitHostPort(c.RemoteAddr().String())
	addr, err := netip.ParseAddr(host)
	if err != nil || !slices.ContainsFunc(relays, func(p netip.Prefix) bool { return p.Contains(addr.Unmap()) }) {
		return c, unmapped(host), port
	}
	br := bufio.NewReaderSize(c, 256)
	line, err := br.ReadString('\n')
	if err != nil || len(line) > 108 {
		return &bufConn{Conn: c, r: br}, unmapped(host), port
	}
	f := strings.Fields(strings.TrimSpace(line))
	if len(f) == 6 && f[0] == "PROXY" && (f[1] == "TCP4" || f[1] == "TCP6") {
		if a, err := netip.ParseAddr(f[2]); err == nil {
			return &bufConn{Conn: c, r: br}, a.Unmap().String(), f[4]
		}
	}
	return &bufConn{Conn: c, r: br}, unmapped(host), port
}

func unmapped(h string) string {
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap().String()
	}
	return h
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func clipUser(u string) string { return truncate(u, 64) }

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// fmtDuration is used by the shell for uptime.
func fmtDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	return fmt.Sprintf("%d days, %2d:%02d", days, int(d.Hours())%24, int(d.Minutes())%60)
}
