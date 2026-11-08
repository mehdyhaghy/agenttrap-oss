// Package relay publishes a TCP port on the edge and forwards connections to
// a backend on an internal network, prefixing each one with a PROXY protocol
// v1 header so the backend sees the real client address. It is the only way
// a non-HTTP decoy (SSH) is reachable without putting the spoke itself on a
// public network.
//
// The relay never reads or changes the stream: it copies bytes. It holds no
// keys and has no access to the hub or the database.
package relay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"
	"time"
)

// Config configures one relay.
type Config struct {
	Listen   string        // public address, e.g. ":22"
	Backend  string        // internal address, e.g. "spoke:2022"
	MaxConns int           // concurrent connections (default 512)
	Idle     time.Duration // connection lifetime cap (default 30m)
	Dial     time.Duration // backend dial timeout (default 5s)

	// Per-source rate limiting sheds brute-force floods before they reach the
	// decoy. A source may open Burst connections at once, then one more every
	// Refill interval. Burst <= 0 disables it.
	Burst      int
	Refill     time.Duration
	MaxSources int            // most sources tracked at once (default 4096)
	Exempt     []netip.Prefix // sources never limited (operators, health checks)
}

// Run accepts connections until ctx ends.
func Run(ctx context.Context, cfg Config, log *slog.Logger) error {
	if cfg.MaxConns == 0 {
		cfg.MaxConns = 512
	}
	if cfg.Idle == 0 {
		cfg.Idle = 30 * time.Minute
	}
	if cfg.Dial == 0 {
		cfg.Dial = 5 * time.Second
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	lim := newLimiter(cfg.Burst, cfg.Refill, cfg.MaxSources, cfg.Exempt)
	if lim != nil {
		go sweepLoop(ctx, lim, cfg.Refill)
	}
	log.Info("relay listening", "addr", cfg.Listen, "backend", cfg.Backend, "rate_limited", lim != nil)

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
		if !lim.allow(sourceAddr(c.RemoteAddr()), time.Now()) {
			log.Debug("relay throttled source", "remote", c.RemoteAddr().String())
			_ = c.Close()
			continue
		}
		if active.Add(1) > int64(cfg.MaxConns) {
			active.Add(-1)
			_ = c.Close()
			continue
		}
		go func() {
			defer active.Add(-1)
			if err := forward(ctx, c, cfg); err != nil {
				log.Debug("relay connection ended", "err", err)
			}
		}()
	}
}

func forward(ctx context.Context, client net.Conn, cfg Config) error {
	defer client.Close()
	deadline := time.Now().Add(cfg.Idle)
	_ = client.SetDeadline(deadline)

	d := net.Dialer{Timeout: cfg.Dial}
	backend, err := d.DialContext(ctx, "tcp", cfg.Backend)
	if err != nil {
		return err
	}
	defer backend.Close()
	_ = backend.SetDeadline(deadline)

	if _, err := io.WriteString(backend, proxyHeader(client.LocalAddr(), client.RemoteAddr())); err != nil {
		return err
	}
	done := make(chan error, 2)
	go func() { _, err := io.Copy(backend, client); done <- err }()
	go func() { _, err := io.Copy(client, backend); done <- err }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// proxyHeader builds a PROXY protocol v1 line. An address the header cannot
// describe (not TCP over IP) yields UNKNOWN, which the backend accepts while
// falling back to the peer address.
func proxyHeader(local, remote net.Addr) string {
	src, sok := remote.(*net.TCPAddr)
	dst, dok := local.(*net.TCPAddr)
	if !sok || !dok {
		return "PROXY UNKNOWN\r\n"
	}
	family := "TCP4"
	if src.IP.To4() == nil || dst.IP.To4() == nil {
		family = "TCP6"
	}
	return fmt.Sprintf("PROXY %s %s %s %d %d\r\n", family, ipString(src.IP), ipString(dst.IP), src.Port, dst.Port)
}

func ipString(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// sourceAddr extracts the client IP for rate limiting; an unparseable address
// yields the zero Addr, which the limiter treats as its own bucket.
func sourceAddr(a net.Addr) netip.Addr {
	if ta, ok := a.(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(ta.IP); ok {
			return ip.Unmap()
		}
	}
	if host, _, err := net.SplitHostPort(a.String()); err == nil {
		if ip, err := netip.ParseAddr(host); err == nil {
			return ip.Unmap()
		}
	}
	return netip.Addr{}
}

// sweepLoop drops idle buckets on an interval so memory tracks active sources.
func sweepLoop(ctx context.Context, lim *limiter, refill time.Duration) {
	every := refill * 4
	if every < time.Minute {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			lim.sweep(now)
		}
	}
}
