package demogpu

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
)

// Minimal PostgreSQL v3 frontend/backend protocol framing for the decoy.
// Reference: the message formats in the PostgreSQL protocol documentation.

const (
	pgProtocolV3   = 196608   // 3.0
	pgSSLRequest   = 80877103 // startup code for an SSL negotiation
	pgGSSENCReq    = 80877104 // startup code for a GSSAPI encryption negotiation
	pgCancelReq    = 80800257 // startup code for a cancel request
	pgMaxStartup   = 10 << 10 // startup packet size cap
	pgMaxMessage   = 64 << 10 // regular message size cap
	pgMaxQueryText = 8 << 10
)

var errPGProtocol = errors.New("postgres: protocol error")

// readStartup reads the length-prefixed startup packet (no type byte) and
// returns the protocol code and the raw body after the code.
func readStartup(br *bufio.Reader) (code int32, body []byte, err error) {
	var length int32
	if err = binary.Read(br, binary.BigEndian, &length); err != nil {
		return 0, nil, err
	}
	if length < 8 || length > pgMaxStartup {
		return 0, nil, errPGProtocol
	}
	buf := make([]byte, length-4)
	if _, err = io.ReadFull(br, buf); err != nil {
		return 0, nil, err
	}
	code = int32(binary.BigEndian.Uint32(buf[:4]))
	return code, buf[4:], nil
}

// pgMessage is one typed frontend message.
type pgMessage struct {
	Type byte
	Body []byte
}

// readMessage reads a typed message (1 byte type + int32 length + body).
func readMessage(br *bufio.Reader) (pgMessage, error) {
	t, err := br.ReadByte()
	if err != nil {
		return pgMessage{}, err
	}
	var length int32
	if err := binary.Read(br, binary.BigEndian, &length); err != nil {
		return pgMessage{}, err
	}
	if length < 4 || length > pgMaxMessage {
		return pgMessage{}, errPGProtocol
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(br, body); err != nil {
		return pgMessage{}, err
	}
	return pgMessage{Type: t, Body: body}, nil
}

// parseStartupParams parses the "key\0value\0...\0" body of a startup packet.
func parseStartupParams(body []byte) map[string]string {
	out := map[string]string{}
	parts := splitCStrings(body)
	for i := 0; i+1 < len(parts); i += 2 {
		if parts[i] == "" {
			break
		}
		out[parts[i]] = parts[i+1]
	}
	return out
}

// splitCStrings splits a buffer of null-terminated strings.
func splitCStrings(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == 0 {
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	return out
}

// cString reads a null-terminated string from the front of body.
func cString(body []byte) string {
	for i, c := range body {
		if c == 0 {
			return string(body[:i])
		}
	}
	return string(body)
}

// pgWriter builds backend messages into a buffered writer.
type pgWriter struct{ w *bufio.Writer }

func (p pgWriter) msg(t byte, body []byte) {
	_ = p.w.WriteByte(t)
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(body)+4))
	_, _ = p.w.Write(l[:])
	_, _ = p.w.Write(body)
}

func (p pgWriter) authOK()              { p.msg('R', be32(0)) }
func (p pgWriter) authCleartext()       { p.msg('R', be32(3)) }
func (p pgWriter) readyForQuery(s byte) { p.msg('Z', []byte{s}) }
func (p pgWriter) backendKeyData(a, b int32) {
	body := append(be32(a), be32(b)...)
	p.msg('K', body)
}

func (p pgWriter) parameterStatus(name, val string) {
	body := append(cstr(name), cstr(val)...)
	p.msg('S', body)
}

func (p pgWriter) commandComplete(tag string) { p.msg('C', cstr(tag)) }

// errorResponse sends a FATAL/ERROR with a SQLSTATE code and message.
func (p pgWriter) errorResponse(severity, code, message string) {
	var b []byte
	b = append(b, 'S')
	b = append(b, cstr(severity)...)
	b = append(b, 'V')
	b = append(b, cstr(severity)...)
	b = append(b, 'C')
	b = append(b, cstr(code)...)
	b = append(b, 'M')
	b = append(b, cstr(message)...)
	b = append(b, 0)
	p.msg('E', b)
}

// rowDescription describes result columns (all reported as text type).
func (p pgWriter) rowDescription(cols []string) {
	var b []byte
	b = append(b, be16(int16(len(cols)))...)
	for _, name := range cols {
		b = append(b, cstr(name)...)
		b = append(b, be32(0)...)  // table OID
		b = append(b, be16(0)...)  // column attr number
		b = append(b, be32(25)...) // type OID 25 = text
		b = append(b, be16(-1)...) // type length (variable)
		b = append(b, be32(-1)...) // type modifier
		b = append(b, be16(0)...)  // format code: text
	}
	p.msg('T', b)
}

// dataRow sends one result row; a nil cell is NULL.
func (p pgWriter) dataRow(cells []string) {
	var b []byte
	b = append(b, be16(int16(len(cells)))...)
	for _, c := range cells {
		b = append(b, be32(int32(len(c)))...)
		b = append(b, []byte(c)...)
	}
	p.msg('D', b)
}

func be16(v int16) []byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(v))
	return b[:]
}

func be32(v int32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(v))
	return b[:]
}

func cstr(s string) []byte { return append([]byte(s), 0) }
