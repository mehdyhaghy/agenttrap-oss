//go:build linux

package ja4

import (
	"context"
	"errors"
	"slices"
	"time"

	"golang.org/x/sys/unix"
)

// Sniff reads packets on every interface in the current network namespace
// and calls out for each new TLS ClientHello sent to one of ports. It needs
// CAP_NET_RAW only; it never modifies traffic. report, if set, receives the
// assembler statistics every interval.
func Sniff(ctx context.Context, ports []uint16, out func(Result), report func(Stats), interval time.Duration) error {
	const ethPAll = 0x0003
	proto := int(ethPAll<<8&0xff00 | ethPAll>>8) // htons
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, proto)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 4<<20)
	tv := unix.NsecToTimeval(int64(time.Second))
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return err
	}

	a := NewAssembler()
	buf := make([]byte, 1<<16)
	lastReport := time.Now()
	for ctx.Err() == nil {
		if report != nil && time.Since(lastReport) >= interval {
			report(a.Stats)
			lastReport = time.Now()
		}
		n, from, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		// Skip our own outgoing packets (e.g. ACME requests from the proxy).
		if ll, ok := from.(*unix.SockaddrLinklayer); ok && ll.Pkttype == unix.PACKET_OUTGOING {
			continue
		}
		seg, ok := DecodeIP(buf[:n])
		if !ok || !slices.Contains(ports, seg.Dst.Port()) {
			continue
		}
		if r, ok := a.Add(seg, time.Now()); ok {
			out(*r)
		}
	}
	return nil
}
