package ja4

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// buildHello assembles a TLS 1.3 ClientHello record from parts, so the test
// vector is fully defined here rather than taken from third-party captures.
func buildHello(ciphers []uint16, exts [][2]any) []byte {
	u16 := func(b []byte, v int) []byte { return binary.BigEndian.AppendUint16(b, uint16(v)) }
	var body []byte
	body = u16(body, 0x0303)                 // legacy_version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session id
	body = u16(body, 2*len(ciphers))
	for _, c := range ciphers {
		body = u16(body, int(c))
	}
	body = append(body, 1, 0) // compression: null
	var ext []byte
	for _, e := range exts {
		data := e[1].([]byte)
		ext = u16(ext, int(e[0].(uint16)))
		ext = u16(ext, len(data))
		ext = append(ext, data...)
	}
	body = u16(body, len(ext))
	body = append(body, ext...)
	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	rec := []byte{0x16, 0x03, 0x01}
	rec = u16(rec, len(hs))
	return append(rec, hs...)
}

func TestHandBuiltVector(t *testing.T) {
	sni := []byte("api.demogpu.example")
	sniExt := append([]byte{0, byte(len(sni) + 3), 0, 0, byte(len(sni))}, sni...)
	alpn := []byte{0, 12, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1'}
	versions := []byte{6, 0x2a, 0x2a, 0x03, 0x04, 0x03, 0x03}
	sigalgs := []byte{0, 6, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01}
	raw := buildHello(
		[]uint16{0x0a0a, 0x1302, 0xc02b, 0x1301}, // GREASE + 3 suites, unsorted
		[][2]any{
			{uint16(0x1a1a), []byte{}}, // GREASE extension
			{uint16(0x0000), sniExt},
			{uint16(0x0033), []byte{0, 0}}, // key_share (contents irrelevant)
			{uint16(0x0010), alpn},
			{uint16(0x002b), versions},
			{uint16(0x000d), sigalgs},
		},
	)
	// JA4_a: TLS 1.3 from supported_versions, SNI present, 3 ciphers,
	// 5 extensions (GREASE excluded), ALPN "h2".
	// JA4_b: sha256("1301,1302,c02b")[:12]
	// JA4_c: sha256("000d,002b,0033_0403,0804,0401")[:12]
	const want = "t13d0305h2_5559582ccdc4_703bc65e5b6f"
	h, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if h.JA4 != want || h.SNI != "api.demogpu.example" || len(h.ALPN) != 2 {
		t.Fatalf("got %+v, want %s", h, want)
	}
	// Split across records at an arbitrary point: same fingerprint.
	first := raw[5:40]
	rest := raw[40:]
	split := append([]byte{0x16, 0x03, 0x01, 0, byte(len(first))}, first...)
	split = append(split, 0x16, 0x03, 0x01, byte(len(rest)>>8), byte(len(rest)))
	split = append(split, rest...)
	if h2, err := Parse(split); err != nil || h2.JA4 != want {
		t.Fatalf("multi-record: %+v %v", h2, err)
	}
}

func TestStackTells(t *testing.T) {
	groups := []byte{0, 6, 0x6a, 0x6a, 0x11, 0xec, 0x00, 0x1d}
	raw := buildHello(
		[]uint16{0x0a0a, 0x1302, 0xc02b, 0x1301},
		[][2]any{
			{uint16(0x0000), append([]byte{0, 14, 0, 0, 11}, "demogpu.example"...)},
			{uint16(0x000a), groups},
			{uint16(0xfe0d), []byte{0}},
			{uint16(0x44cd), []byte{0, 3, 2, 'h', '2'}},
			{uint16(0x001b), []byte{2, 0, 2}},
			{uint16(0x002b), []byte{2, 0x03, 0x04}},
		},
	)
	h, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !h.Grease || !h.ECH || !h.PostQuantum || !h.ALPS || !h.CertCompress {
		t.Fatalf("tells: %+v", h)
	}
	// JA4_o keeps the order sent, so it differs from the sorted JA4 but
	// shares its first part.
	if h.JA4O == h.JA4 || h.JA4O[:10] != h.JA4[:10] {
		t.Fatalf("ja4_o %s vs ja4 %s", h.JA4O, h.JA4)
	}
	sum := md5.Sum([]byte("771,4866-49195-4865,0-10-65037-17613-27-43,4588-29,"))
	if h.JA3 != hex.EncodeToString(sum[:]) {
		t.Fatalf("ja3 %s", h.JA3)
	}
}

func TestParseSYN(t *testing.T) {
	for _, tc := range []struct {
		opts []byte
		ttl  uint8
		want string
	}{
		// Linux: MSS, SACK permitted, timestamps, NOP, window scale.
		{[]byte{2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7}, 52, "linux"},
		// Windows: MSS, NOP, window scale, NOP, NOP, SACK permitted.
		{[]byte{2, 4, 0x05, 0xb4, 1, 3, 3, 8, 1, 1, 4, 2}, 117, "windows"},
		// Apple: MSS, NOP, WS, NOP, NOP, timestamps, SACK permitted, EOL.
		{[]byte{2, 4, 0x05, 0xb4, 1, 3, 3, 6, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 4, 2, 0, 0}, 55, "apple"},
		// Linux layout with a Windows-range TTL: unclear.
		{[]byte{2, 4, 0x05, 0xb4, 4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0, 1, 3, 3, 7}, 120, ""},
	} {
		s := ParseSYN(Segment{Options: tc.opts, TTL: tc.ttl, Window: 64240})
		if s.OS != tc.want || s.MSS != 1460 {
			t.Errorf("%v ttl %d: got %+v, want %q", tc.opts, tc.ttl, s, tc.want)
		}
	}
}
