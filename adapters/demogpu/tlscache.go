package demogpu

import (
	"net"
	"slices"
	"sync"
	"time"

	"agenttrap/internal/ja4"
)

// connFacts are the per-connection fields recorded on the TLS event and on
// every request sent over that connection, so each user agent can be checked
// against the handshake and network stack that carried it.
func connFacts(res ja4.Result) map[string]any {
	h := res.Hello
	f := map[string]any{
		"ja4": h.JA4, "ja4_o": h.JA4O, "ja3": h.JA3, "tls_sni": h.SNI,
		"tls_grease": h.Grease, "tls_ech": h.ECH, "tls_pq": h.PostQuantum,
		"tls_alps": h.ALPS, "tls_cert_compress": h.CertCompress,
		"tls_h2": slices.Contains(h.ALPN, "h2"),
	}
	if t := res.TCP; t != nil {
		f["tcp_ttl"], f["tcp_window"], f["tcp_options"] = t.TTL, t.Window, t.Options
		if t.MSS > 0 {
			f["tcp_mss"] = t.MSS
		}
		if t.OS != "" {
			f["tcp_os"] = t.OS
		}
	}
	return f
}

// tlsCache maps a client connection (ip:port as seen by the edge proxy) to
// its TLS and TCP facts, so HTTP requests on that connection can carry them.
type tlsCache struct {
	mu      sync.Mutex
	entries map[string]tlsEntry
	ttl     time.Duration
	max     int
}

type tlsEntry struct {
	facts   map[string]any
	expires time.Time
}

func newTLSCache() *tlsCache {
	return &tlsCache{entries: map[string]tlsEntry{}, ttl: 10 * time.Minute, max: 100000}
}

func connKey(ip, port string) string { return net.JoinHostPort(ip, port) }

func (c *tlsCache) put(key string, facts map[string]any, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		for k, e := range c.entries {
			if now.After(e.expires) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= c.max {
			return
		}
	}
	c.entries[key] = tlsEntry{facts: facts, expires: now.Add(c.ttl)}
}

// get returns the connection facts and extends its lifetime (keep-alive
// connections carry many requests).
func (c *tlsCache) get(key string, now time.Time) (map[string]any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || now.After(e.expires) {
		return nil, false
	}
	e.expires = now.Add(c.ttl)
	c.entries[key] = e
	return e.facts, true
}
