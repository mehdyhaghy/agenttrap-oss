package ja4

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Segment is one TCP segment with its payload.
type Segment struct {
	Src, Dst netip.AddrPort
	Seq      uint32
	Payload  []byte
	Flags    uint8  // TCP flags
	TTL      uint8  // IPv4 TTL or IPv6 hop limit
	Window   uint16 // TCP window (unscaled)
	Options  []byte // raw TCP options
}

// Result is a completed fingerprint for one connection.
type Result struct {
	Src, Dst netip.AddrPort
	Time     time.Time
	Hello    *Hello
	TCP      *SYN `json:"tcp,omitempty"`
}

// SYN holds the facts of a connection's opening packet that identify the
// client's operating system network stack. These are raw observations (no
// third-party signature database is used).
type SYN struct {
	TTL     int    `json:"ttl"`
	Window  int    `json:"window"`
	MSS     int    `json:"mss,omitempty"`
	WScale  int    `json:"wscale"`  // -1 when absent
	Options string `json:"options"` // option kinds in order, e.g. "M,S,T,N,W"
	// OS is the stack family implied by the option layout and initial TTL:
	// linux, windows, apple, or empty when unclear.
	OS string `json:"os,omitempty"`
}

const (
	tcpSYN = 0x02
	tcpACK = 0x10
)

// ParseSYN reads the facts of a SYN segment.
func ParseSYN(seg Segment) *SYN {
	s := &SYN{TTL: int(seg.TTL), Window: int(seg.Window), WScale: -1}
	var kinds []string
	o := seg.Options
	for len(o) > 0 {
		kind := o[0]
		if kind == 0 { // end of options
			kinds = append(kinds, "E")
			break
		}
		if kind == 1 {
			kinds = append(kinds, "N")
			o = o[1:]
			continue
		}
		if len(o) < 2 || int(o[1]) < 2 || int(o[1]) > len(o) {
			break
		}
		data := o[2:o[1]]
		switch kind {
		case 2:
			kinds = append(kinds, "M")
			if len(data) == 2 {
				s.MSS = int(binary.BigEndian.Uint16(data))
			}
		case 3:
			kinds = append(kinds, "W")
			if len(data) == 1 {
				s.WScale = int(data[0])
			}
		case 4:
			kinds = append(kinds, "S")
		case 8:
			kinds = append(kinds, "T")
		default:
			kinds = append(kinds, strconv.Itoa(int(kind)))
		}
		o = o[o[1]:]
	}
	s.Options = strings.Join(kinds, ",")
	s.OS = stackFamily(s.Options, s.TTL)
	return s
}

// stackFamily maps a SYN option layout and observed TTL to the default
// layouts of the common network stacks. Observed TTLs are the initial value
// (64 for Linux and Apple, 128 for Windows) minus the hops travelled.
func stackFamily(opts string, ttl int) string {
	unix, windows := ttl > 32 && ttl <= 64, ttl > 64 && ttl <= 128
	switch {
	case unix && opts == "M,S,T,N,W":
		return "linux"
	case unix && strings.HasPrefix(opts, "M,N,W,N,N,T,S"):
		return "apple"
	case windows && opts == "M,N,W,N,N,S":
		return "windows"
	}
	return ""
}

// Assembler reassembles ClientHellos that span several TCP segments (common
// with post-quantum key shares) and emits one Result per connection.
type Assembler struct {
	MaxFlows int
	Timeout  time.Duration
	Stats    Stats

	flows map[flowKey]*flow
	done  map[flowKey]time.Time
	syns  map[flowKey]synEntry
	calls int
}

type synEntry struct {
	syn *SYN
	at  time.Time
}

// Stats counts what the assembler saw, to explain missed fingerprints.
type Stats struct {
	Segments    uint64 // TCP segments with payload offered
	Started     uint64 // ClientHello starts seen
	Completed   uint64 // fingerprints produced
	ParseErrors uint64 // started but not a parseable ClientHello
	Oversize    uint64 // gave up after maxHelloBytes
	Expired     uint64 // never completed before Timeout
	OutOfOrder  uint64 // segments not matching the expected sequence
	FlowsFull   uint64 // starts dropped because MaxFlows was reached
	// LastFailure holds the first bytes of the last unparseable ClientHello.
	LastFailure []byte
}

type flowKey struct{ src, dst netip.AddrPort }

type flow struct {
	next  uint32
	buf   []byte
	start time.Time
}

const maxHelloBytes = 16 << 10

func NewAssembler() *Assembler {
	return &Assembler{MaxFlows: 10000, Timeout: 10 * time.Second,
		flows: map[flowKey]*flow{}, done: map[flowKey]time.Time{}, syns: map[flowKey]synEntry{}}
}

// Add feeds a segment and returns a Result once a ClientHello is complete.
// Only the first ClientHello of a connection is fingerprinted (a second one
// after HelloRetryRequest is ignored), matching the reference implementation.
func (a *Assembler) Add(seg Segment, now time.Time) (*Result, bool) {
	if a.calls++; a.calls%1024 == 0 {
		a.expire(now)
	}
	key := flowKey{seg.Src, seg.Dst}
	if seg.Flags&(tcpSYN|tcpACK) == tcpSYN {
		if len(a.syns) < a.MaxFlows {
			a.syns[key] = synEntry{ParseSYN(seg), now}
		}
		return nil, false
	}
	if len(seg.Payload) == 0 {
		return nil, false
	}
	a.Stats.Segments++
	f, ok := a.flows[key]
	if !ok {
		if _, seen := a.done[key]; seen || !IsStart(seg.Payload) {
			return nil, false
		}
		if len(a.flows) >= a.MaxFlows {
			a.Stats.FlowsFull++
			return nil, false
		}
		a.Stats.Started++
		f = &flow{next: seg.Seq, start: now}
		a.flows[key] = f
	}
	if seg.Seq != f.next {
		a.Stats.OutOfOrder++
		return nil, false // retransmission or out of order
	}
	f.buf = append(f.buf, seg.Payload...)
	f.next += uint32(len(seg.Payload))

	h, err := Parse(f.buf)
	switch {
	case errors.Is(err, ErrIncomplete) && len(f.buf) < maxHelloBytes:
		return nil, false
	case errors.Is(err, ErrIncomplete):
		a.Stats.Oversize++
		delete(a.flows, key)
		a.done[key] = now
		return nil, false
	case err != nil:
		a.Stats.ParseErrors++
		a.Stats.LastFailure = append([]byte(nil), f.buf[:min(len(f.buf), 48)]...)
		delete(a.flows, key)
		a.done[key] = now
		return nil, false
	}
	a.Stats.Completed++
	delete(a.flows, key)
	a.done[key] = now
	res := &Result{Src: seg.Src, Dst: seg.Dst, Time: f.start, Hello: h}
	if e, ok := a.syns[key]; ok {
		res.TCP = e.syn
		delete(a.syns, key)
	}
	return res, true
}

func (a *Assembler) expire(now time.Time) {
	for k, f := range a.flows {
		if now.Sub(f.start) > a.Timeout {
			a.Stats.Expired++
			delete(a.flows, k)
		}
	}
	for k, t := range a.done {
		if now.Sub(t) > 2*time.Minute {
			delete(a.done, k)
		}
	}
	for k, e := range a.syns {
		if now.Sub(e.at) > a.Timeout {
			delete(a.syns, k)
		}
	}
}

// DecodeIP extracts a TCP segment from an IPv4 or IPv6 packet (no link-layer
// header). It returns false for anything else, including IP fragments.
func DecodeIP(pkt []byte) (Segment, bool) {
	if len(pkt) < 1 {
		return Segment{}, false
	}
	var src, dst netip.Addr
	var tcp []byte
	var ttl uint8
	switch pkt[0] >> 4 {
	case 4:
		if len(pkt) < 20 {
			return Segment{}, false
		}
		ihl := int(pkt[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(pkt[2:4]))
		frag := binary.BigEndian.Uint16(pkt[6:8])
		if pkt[9] != 6 || ihl < 20 || total < ihl || total > len(pkt) || frag&0x3fff != 0 {
			return Segment{}, false
		}
		ttl = pkt[8]
		src = netip.AddrFrom4([4]byte(pkt[12:16]))
		dst = netip.AddrFrom4([4]byte(pkt[16:20]))
		tcp = pkt[ihl:total]
	case 6:
		if len(pkt) < 40 {
			return Segment{}, false
		}
		plen := int(binary.BigEndian.Uint16(pkt[4:6]))
		if pkt[6] != 6 || 40+plen > len(pkt) { // extension headers are not followed
			return Segment{}, false
		}
		ttl = pkt[7]
		src = netip.AddrFrom16([16]byte(pkt[8:24]))
		dst = netip.AddrFrom16([16]byte(pkt[24:40]))
		tcp = pkt[40 : 40+plen]
	default:
		return Segment{}, false
	}
	if len(tcp) < 20 {
		return Segment{}, false
	}
	off := int(tcp[12]>>4) * 4
	if off < 20 || off > len(tcp) {
		return Segment{}, false
	}
	return Segment{
		Src:     netip.AddrPortFrom(src, binary.BigEndian.Uint16(tcp[0:2])),
		Dst:     netip.AddrPortFrom(dst, binary.BigEndian.Uint16(tcp[2:4])),
		Seq:     binary.BigEndian.Uint32(tcp[4:8]),
		Payload: tcp[off:],
		Flags:   tcp[13],
		TTL:     ttl,
		Window:  binary.BigEndian.Uint16(tcp[14:16]),
		Options: tcp[20:off],
	}, true
}
