// Package ja4 computes the JA4 TLS client fingerprint from a raw ClientHello.
//
// This is an independent implementation of the JA4 (TLS client) method by
// FoxIO, which is licensed separately under BSD-3-Clause. Only JA4 (and its
// original-order JA4_o variant) is implemented here, not the rest of the
// JA4+ suite. JA3 (Salesforce, BSD-3-Clause) is computed for compatibility.
// Specification: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
package ja4

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Hello is a parsed ClientHello with its fingerprint.
type Hello struct {
	JA4        string   `json:"ja4"`
	SNI        string   `json:"sni,omitempty"`
	ALPN       []string `json:"alpn,omitempty"`
	TLSVersion string   `json:"tls_version"`
	// JA4O is JA4 with ciphers and extensions in the order sent (JA4_o).
	// Chromium shuffles its extensions on every connection, so a JA4O that
	// never changes under a Chrome user agent points to another TLS stack.
	JA4O string `json:"ja4_o,omitempty"`
	// JA3 is the legacy JA3 hash, kept for threat-intel consumers.
	JA3 string `json:"ja3,omitempty"`
	// Stack tells: facts of the handshake that identify the TLS library
	// regardless of the user agent it is paired with.
	Grease       bool `json:"grease"`        // GREASE values present (Chromium, Safari)
	ECH          bool `json:"ech"`           // encrypted_client_hello extension
	PostQuantum  bool `json:"post_quantum"`  // hybrid ML-KEM (or draft Kyber) group offered
	ALPS         bool `json:"alps"`          // application_settings (Chromium only)
	CertCompress bool `json:"cert_compress"` // compress_certificate extension
}

var (
	// ErrIncomplete means more bytes are needed to parse the ClientHello.
	ErrIncomplete = errors.New("ja4: incomplete ClientHello")
	// ErrNotClientHello means the data is not a TLS ClientHello.
	ErrNotClientHello = errors.New("ja4: not a ClientHello")
)

const (
	extSNI           = 0x0000
	extALPN          = 0x0010
	extSigAlgs       = 0x000d
	extSupportedVers = 0x002b
	extGroups        = 0x000a
	extPointFormats  = 0x000b
	extCertCompress  = 0x001b
	extECH           = 0xfe0d
	extALPSOld       = 0x4469
	extALPS          = 0x44cd

	groupMLKEM768   = 0x11ec // X25519MLKEM768
	groupKyberDraft = 0x6399 // X25519Kyber768Draft00
	groupSecpMLKEM  = 0x11eb // SecP256r1MLKEM768
)

// IsStart reports whether data looks like the first bytes of a TLS
// handshake record carrying a ClientHello. Some TLS stacks send the 5-byte
// record header in its own TCP segment, so a bare header also qualifies;
// Parse rejects anything that turns out not to be a ClientHello.
func IsStart(data []byte) bool {
	if len(data) < 3 || data[0] != 0x16 || data[1] != 0x03 {
		return false
	}
	return len(data) < 6 || data[5] == 0x01
}

// handshake joins the handshake-record fragments at the start of data and
// returns the ClientHello message body.
func handshake(data []byte) ([]byte, error) {
	if !IsStart(data) {
		return nil, ErrNotClientHello
	}
	if len(data) < 6 {
		return nil, ErrIncomplete
	}
	var hs []byte
	for len(data) > 0 {
		if len(data) < 5 {
			return nil, ErrIncomplete
		}
		if data[0] != 0x16 {
			return nil, ErrNotClientHello
		}
		n := int(binary.BigEndian.Uint16(data[3:5]))
		if len(data) < 5+n {
			hs = append(hs, data[5:]...)
			data = nil
		} else {
			hs = append(hs, data[5:5+n]...)
			data = data[5+n:]
		}
		if len(hs) >= 4 {
			if hs[0] != 0x01 {
				return nil, ErrNotClientHello
			}
			need := 4 + (int(hs[1])<<16 | int(hs[2])<<8 | int(hs[3]))
			if len(hs) >= need {
				return hs[4:need], nil
			}
		}
	}
	return nil, ErrIncomplete
}

// Parse fingerprints the ClientHello at the start of data (one or more TLS
// records, as seen on the wire). It returns ErrIncomplete if data is cut short.
func Parse(data []byte) (*Hello, error) {
	body, err := handshake(data)
	if err != nil {
		return nil, err
	}
	r := reader{b: body}
	legacyVersion := r.u16()
	r.skip(32) // random
	r.skip(int(r.u8()))
	cipherBytes := r.bytes(int(r.u16()))
	r.skip(int(r.u8())) // compression methods
	if r.err {
		return nil, ErrNotClientHello
	}

	h := &Hello{}
	var ciphers []uint16
	for i := 0; i+1 < len(cipherBytes); i += 2 {
		if c := binary.BigEndian.Uint16(cipherBytes[i:]); !grease(c) {
			ciphers = append(ciphers, c)
		} else {
			h.Grease = true
		}
	}

	var exts, sigAlgs, groups, pointFormats []uint16
	version := legacyVersion
	hasSNI := false
	if r.remaining() >= 2 {
		er := reader{b: r.bytes(int(r.u16()))}
		for er.remaining() >= 4 && !er.err {
			typ := er.u16()
			data := er.bytes(int(er.u16()))
			if er.err {
				break
			}
			if grease(typ) {
				h.Grease = true
				continue
			}
			exts = append(exts, typ)
			switch typ {
			case extECH:
				h.ECH = true
			case extALPS, extALPSOld:
				h.ALPS = true
			case extCertCompress:
				h.CertCompress = true
			case extGroups:
				gr := reader{b: data}
				list := reader{b: gr.bytes(int(gr.u16()))}
				for list.remaining() >= 2 {
					switch v := list.u16(); {
					case grease(v):
						h.Grease = true
					default:
						groups = append(groups, v)
						if v == groupMLKEM768 || v == groupKyberDraft || v == groupSecpMLKEM {
							h.PostQuantum = true
						}
					}
				}
			case extPointFormats:
				pr := reader{b: data}
				for _, v := range pr.bytes(int(pr.u8())) {
					pointFormats = append(pointFormats, uint16(v))
				}
			case extSNI:
				hasSNI = true
				h.SNI = parseSNI(data)
			case extALPN:
				h.ALPN = parseALPN(data)
			case extSigAlgs:
				sr := reader{b: data}
				list := reader{b: sr.bytes(int(sr.u16()))}
				for list.remaining() >= 2 {
					if v := list.u16(); !grease(v) {
						sigAlgs = append(sigAlgs, v)
					}
				}
			case extSupportedVers:
				vr := reader{b: data}
				list := reader{b: vr.bytes(int(vr.u8()))}
				best := uint16(0)
				for list.remaining() >= 2 {
					if v := list.u16(); !grease(v) && v > best {
						best = v
					}
				}
				if best != 0 {
					version = best
				}
			}
		}
	}

	h.TLSVersion = versionCode(version)
	sni := "i"
	if hasSNI {
		sni = "d"
	}
	alpn := "00"
	if len(h.ALPN) > 0 {
		alpn = alpnCode(h.ALPN[0])
	}
	a := fmt.Sprintf("t%s%s%02d%02d%s", h.TLSVersion, sni, min(len(ciphers), 99), min(len(exts), 99), alpn)

	b := "000000000000"
	if len(ciphers) > 0 {
		sorted := slices.Clone(ciphers)
		slices.Sort(sorted)
		b = hash12(hexList(sorted))
	}

	c := "000000000000"
	var cExts []uint16
	for _, e := range exts {
		if e != extSNI && e != extALPN {
			cExts = append(cExts, e)
		}
	}
	if len(cExts) > 0 {
		slices.Sort(cExts)
		s := hexList(cExts)
		if len(sigAlgs) > 0 {
			s += "_" + hexList(sigAlgs)
		}
		c = hash12(s)
	}
	h.JA4 = a + "_" + b + "_" + c

	// JA4_o: the same fields in the order sent, SNI and ALPN included.
	bo, co := "000000000000", "000000000000"
	if len(ciphers) > 0 {
		bo = hash12(hexList(ciphers))
	}
	if len(exts) > 0 {
		s := hexList(exts)
		if len(sigAlgs) > 0 {
			s += "_" + hexList(sigAlgs)
		}
		co = hash12(s)
	}
	h.JA4O = a + "_" + bo + "_" + co

	// JA3: version,ciphers,extensions,groups,point formats (decimal, GREASE removed).
	ja3 := fmt.Sprintf("%d,%s,%s,%s,%s", legacyVersion, decList(ciphers), decList(exts), decList(groups), decList(pointFormats))
	sum := md5.Sum([]byte(ja3))
	h.JA3 = hex.EncodeToString(sum[:])
	return h, nil
}

func decList(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

// grease reports whether v is a GREASE value (RFC 8701).
func grease(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

func versionCode(v uint16) string {
	switch v {
	case 0x0304:
		return "13"
	case 0x0303:
		return "12"
	case 0x0302:
		return "11"
	case 0x0301:
		return "10"
	case 0x0300:
		return "s3"
	case 0x0002:
		return "s2"
	case 0xfeff:
		return "d1"
	case 0xfefd:
		return "d2"
	case 0xfefc:
		return "d3"
	default:
		return "00"
	}
}

func alphanumeric(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}

func alpnCode(v string) string {
	if v == "" {
		return "00"
	}
	first, last := v[0], v[len(v)-1]
	if alphanumeric(first) && alphanumeric(last) {
		return string([]byte{first, last})
	}
	x := hex.EncodeToString([]byte(v))
	return string([]byte{x[0], x[len(x)-1]})
}

func parseSNI(data []byte) string {
	r := reader{b: data}
	list := reader{b: r.bytes(int(r.u16()))}
	for list.remaining() >= 3 && !list.err {
		typ := list.u8()
		name := list.bytes(int(list.u16()))
		if typ == 0 && !list.err {
			return string(name)
		}
	}
	return ""
}

func parseALPN(data []byte) []string {
	r := reader{b: data}
	list := reader{b: r.bytes(int(r.u16()))}
	var out []string
	for list.remaining() >= 1 && !list.err {
		v := list.bytes(int(list.u8()))
		if !list.err {
			out = append(out, string(v))
		}
	}
	return out
}

func hexList(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func hash12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// reader is a bounds-checked big-endian reader; after an overrun it sets err
// and returns zero values.
type reader struct {
	b   []byte
	err bool
}

func (r *reader) remaining() int { return len(r.b) }

func (r *reader) bytes(n int) []byte {
	if n < 0 || n > len(r.b) {
		r.err = true
		r.b = nil
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) skip(n int) { r.bytes(n) }

func (r *reader) u8() uint8 {
	b := r.bytes(1)
	if b == nil {
		return 0
	}
	return b[0]
}

func (r *reader) u16() uint16 {
	b := r.bytes(2)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint16(b)
}
