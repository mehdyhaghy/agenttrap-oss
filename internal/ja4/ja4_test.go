package ja4

import (
	"crypto/tls"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// ALPN encoding rules from the JA4 specification (BSD-3-Clause).
func TestALPNCode(t *testing.T) {
	cases := map[string]string{
		"h2": "h2", "http/1.1": "h1", "h": "hh", "": "00",
		"\xab": "ab", "\x20": "20", "\xab\xcd": "ad", "\x20\x61": "21",
		"\x30\xab": "3b", "\x61\x20": "60", "\x30\x31\xab\xcd": "3d",
	}
	for in, want := range cases {
		if got := alpnCode(in); got != want {
			t.Errorf("alpnCode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestGrease(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0xfafa} {
		if !grease(v) {
			t.Errorf("%04x should be GREASE", v)
		}
	}
	for _, v := range []uint16{0x0a1a, 0x1301, 0x0000} {
		if grease(v) {
			t.Errorf("%04x should not be GREASE", v)
		}
	}
}

// captureHello records the bytes a Go TLS client sends first.
func captureHello(t *testing.T, cfg *tls.Config) []byte {
	t.Helper()
	client, server := net.Pipe()
	done := make(chan []byte)
	go func() {
		buf := make([]byte, 16<<10)
		n, _ := server.Read(buf)
		done <- buf[:n]
		server.Close()
	}()
	go func() { _ = tls.Client(client, cfg).Handshake() }()
	select {
	case b := <-done:
		client.Close()
		return b
	case <-time.After(5 * time.Second):
		t.Fatal("no ClientHello")
		return nil
	}
}

func TestParseGoClientHello(t *testing.T) {
	raw := captureHello(t, &tls.Config{ServerName: "api.demogpu.example", NextProtos: []string{"h2", "http/1.1"}})
	h, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.SNI != "api.demogpu.example" || len(h.ALPN) != 2 || h.TLSVersion != "13" {
		t.Fatalf("unexpected hello: %+v", h)
	}
	if !strings.HasPrefix(h.JA4, "t13d") || !strings.Contains(h.JA4[:10], "h2") || len(h.JA4) != 36 {
		t.Fatalf("unexpected ja4: %s", h.JA4)
	}
	// Truncated input asks for more bytes.
	if _, err := Parse(raw[:len(raw)/2]); err != ErrIncomplete {
		t.Fatalf("want ErrIncomplete, got %v", err)
	}
	// No SNI means "i".
	h2, err := Parse(captureHello(t, &tls.Config{InsecureSkipVerify: true}))
	if err != nil || h2.JA4[3] != 'i' || h2.SNI != "" {
		t.Fatalf("no-SNI hello: %+v %v", h2, err)
	}
}

func TestAssemblerSplitHello(t *testing.T) {
	raw := captureHello(t, &tls.Config{ServerName: "demogpu.example"})
	want, _ := Parse(raw)
	a := NewAssembler()
	src := netip.MustParseAddrPort("198.51.100.1:50000")
	dst := netip.MustParseAddrPort("10.89.0.10:443")
	now := time.Now()
	half := len(raw) / 2
	if _, ok := a.Add(Segment{Src: src, Dst: dst, Seq: 1000, Payload: raw[:half]}, now); ok {
		t.Fatal("completed too early")
	}
	// A retransmission of the first half is ignored.
	if _, ok := a.Add(Segment{Src: src, Dst: dst, Seq: 1000, Payload: raw[:half]}, now); ok {
		t.Fatal("retransmit completed")
	}
	r, ok := a.Add(Segment{Src: src, Dst: dst, Seq: 1000 + uint32(half), Payload: raw[half:]}, now)
	if !ok || r.Hello.JA4 != want.JA4 || r.Src != src {
		t.Fatalf("reassembly failed: %+v", r)
	}
	if r.TCP != nil {
		t.Fatal("SYN facts without a SYN")
	}
	// The connection is fingerprinted only once.
	if _, ok := a.Add(Segment{Src: src, Dst: dst, Seq: 5000, Payload: raw}, now); ok {
		t.Fatal("second hello on same connection fingerprinted")
	}
}

func TestAssemblerAttachesSYN(t *testing.T) {
	raw := captureHello(t, &tls.Config{ServerName: "demogpu.example"})
	a := NewAssembler()
	src := netip.MustParseAddrPort("198.51.100.2:50001")
	dst := netip.MustParseAddrPort("10.89.0.10:443")
	now := time.Now()
	linux := []byte{2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7}
	a.Add(Segment{Src: src, Dst: dst, Seq: 999, Flags: 0x02, TTL: 50, Window: 64240, Options: linux}, now)
	r, ok := a.Add(Segment{Src: src, Dst: dst, Seq: 1000, Payload: raw}, now)
	if !ok || r.TCP == nil || r.TCP.OS != "linux" || r.TCP.WScale != 7 || r.TCP.Options != "M,S,T,N,W" {
		t.Fatalf("syn not attached: %+v", r)
	}
	if len(a.syns) != 0 {
		t.Fatal("syn entry kept after use")
	}
	// Go's client: no GREASE, no ECH, post-quantum group by default.
	if r.Hello.Grease || r.Hello.ECH || r.Hello.ALPS || !r.Hello.PostQuantum {
		t.Fatalf("go stack tells: %+v", r.Hello)
	}
}

// Some TLS stacks write the record header in its own TCP segment.
func TestAssemblerHeaderOnlyFirstSegment(t *testing.T) {
	raw := captureHello(t, &tls.Config{ServerName: "demogpu.example"})
	want, _ := Parse(raw)
	a := NewAssembler()
	src := netip.MustParseAddrPort("198.51.100.2:50001")
	dst := netip.MustParseAddrPort("10.89.0.10:443")
	now := time.Now()
	if _, ok := a.Add(Segment{Src: src, Dst: dst, Seq: 1, Payload: raw[:5]}, now); ok {
		t.Fatal("completed on the header alone")
	}
	r, ok := a.Add(Segment{Src: src, Dst: dst, Seq: 6, Payload: raw[5:]}, now)
	if !ok || r.Hello.JA4 != want.JA4 {
		t.Fatalf("header-split hello not fingerprinted: %+v", r)
	}
	if a.Stats.Started != 1 || a.Stats.Completed != 1 {
		t.Fatalf("stats: %+v", a.Stats)
	}
	// A non-handshake record is not started.
	if IsStart([]byte{0x17, 0x03, 0x03}) {
		t.Fatal("application data treated as a hello")
	}
}
