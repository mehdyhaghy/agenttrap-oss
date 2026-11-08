package demogpu

import (
	"bufio"
	"io"
	"strings"
	"testing"
)

// endless never sends a newline.
type endless struct{ n int }

func (e *endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	e.n += len(p)
	return len(p), nil
}

func TestReadLineBounded(t *testing.T) {
	src := &endless{}
	if _, err := readLine(bufio.NewReaderSize(src, 4096)); err != errRedisProtocol {
		t.Fatalf("err = %v, want protocol error", err)
	}
	if src.n > redisMaxLine+8192 {
		t.Fatalf("read %d bytes before giving up", src.n)
	}
	long := strings.Repeat("b", 10000) + "\r\n"
	got, err := readLine(bufio.NewReaderSize(strings.NewReader(long), 4096))
	if err != nil || got != strings.Repeat("b", 10000) {
		t.Fatalf("line longer than the buffer: %v, len %d", err, len(got))
	}
	if _, err := readLine(bufio.NewReader(strings.NewReader("no newline"))); err != io.EOF {
		t.Fatalf("err = %v, want EOF", err)
	}
}
