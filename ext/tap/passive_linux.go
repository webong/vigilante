//go:build linux

package tap

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/webong/vigilante/ext/agent"
)

// PassiveOptions configures a passive AF_PACKET mirror: it observes traffic on
// an interface without being in the forwarding path (a true sensor).
type PassiveOptions struct {
	// Iface is the network interface to sniff (e.g. "eth0"). Required.
	Iface string
	// Ports, when non-empty, restricts capture to these TCP/UDP source or
	// destination ports via a BPF filter. Empty captures all IPv4 traffic.
	Ports []int
	// SnapLen bounds each captured frame's payload preview (default 1514).
	SnapLen int
	// Promiscuous enables promiscuous mode on the interface.
	Promiscuous bool
}

// PassiveSensor sniffs packets off an interface into a MirrorQueue. It never
// forwards or modifies traffic — it is observe-only (the sensor posture).
type PassiveSensor struct {
	opts      PassiveOptions
	q         *MirrorQueue
	fd        int
	ifIndex   int
	captured  atomic.Uint64
	malformed atomic.Uint64
}

// NewPassiveSensor opens the AF_PACKET socket (requires CAP_NET_RAW / root).
func NewPassiveSensor(opts PassiveOptions, q *MirrorQueue) (*PassiveSensor, error) {
	if opts.Iface == "" {
		return nil, fmt.Errorf("passive sensor: interface is required")
	}
	iface, err := net.InterfaceByName(opts.Iface)
	if err != nil {
		return nil, fmt.Errorf("passive sensor: interface %q: %w", opts.Iface, err)
	}
	if opts.SnapLen <= 0 {
		opts.SnapLen = 1514
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("passive sensor: AF_PACKET socket (need root/CAP_NET_RAW): %w", err)
	}
	s := &PassiveSensor{opts: opts, q: q, fd: fd, ifIndex: iface.Index}
	if opts.Promiscuous {
		_ = s.setPromisc(true)
	}
	if len(opts.Ports) > 0 {
		if err := s.attachPortFilter(opts.Ports); err != nil {
			_ = syscall.Close(fd)
			return nil, fmt.Errorf("passive sensor: BPF filter: %w", err)
		}
	}
	sa := &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: iface.Index}
	if err := syscall.Bind(fd, sa); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("passive sensor: bind %s: %w", opts.Iface, err)
	}
	return s, nil
}

// Run reads frames until ctx is done, enqueueing decoded events.
func (s *PassiveSensor) Run(ctx context.Context) error {
	defer s.Close()
	buf := make([]byte, 65536)
	for {
		if ctx.Err() != nil {
			return nil
		}
		tv := syscall.NsecToTimeval((250 * time.Millisecond).Nanoseconds())
		_ = syscall.SetsockoptTimeval(s.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
		n, _, err := syscall.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
				continue
			}
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if n <= 0 {
			continue
		}
		ev, ok := s.decode(buf[:n])
		if !ok {
			s.malformed.Add(1)
			continue
		}
		if s.q.Enqueue(ev) {
			s.captured.Add(1)
		}
	}
}

// Close releases the socket.
func (s *PassiveSensor) Close() error {
	if s.fd >= 0 {
		err := syscall.Close(s.fd)
		s.fd = -1
		return err
	}
	return nil
}

// decode parses an Ethernet frame into a PacketEvent. Returns ok=false for
// non-IPv4, truncated, or malformed frames.
func (s *PassiveSensor) decode(frame []byte) (agent.PacketEvent, bool) {
	if len(frame) < 14+20 {
		return agent.PacketEvent{}, false
	}
	ethType := binary.BigEndian.Uint16(frame[12:14])
	if ethType != 0x0800 { // IPv4 only
		return agent.PacketEvent{}, false
	}
	ip := frame[14:]
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl {
		return agent.PacketEvent{}, false
	}
	proto := ip[9]
	srcIP := net.IP(ip[12:16]).String()
	dstIP := net.IP(ip[16:20]).String()

	transport := ip[ihl:]
	var sport, dport uint16
	var payload []byte
	protocol := "tcp"
	switch proto {
	case 6: // TCP
		if len(transport) < 20 {
			return agent.PacketEvent{}, false
		}
		sport = binary.BigEndian.Uint16(transport[0:2])
		dport = binary.BigEndian.Uint16(transport[2:4])
		dataOff := int(transport[12]>>4) * 4
		if dataOff < 20 || len(transport) < dataOff {
			return agent.PacketEvent{}, false
		}
		payload = bounded(transport[dataOff:], s.opts.SnapLen)
	case 17: // UDP
		if len(transport) < 8 {
			return agent.PacketEvent{}, false
		}
		sport = binary.BigEndian.Uint16(transport[0:2])
		dport = binary.BigEndian.Uint16(transport[2:4])
		payload = bounded(transport[8:], s.opts.SnapLen)
		protocol = "udp"
	default:
		return agent.PacketEvent{}, false
	}

	ev := agent.PacketEvent{
		Timestamp:      time.Now().UTC(),
		Protocol:       protocol,
		SrcAddr:        net.JoinHostPort(srcIP, fmt.Sprintf("%d", sport)),
		DstAddr:        net.JoinHostPort(dstIP, fmt.Sprintf("%d", dport)),
		TargetAddr:     net.JoinHostPort(dstIP, fmt.Sprintf("%d", dport)),
		PayloadPreview: string(payload),
		PayloadBytes:   len(payload),
	}
	ev.Redact()
	return ev, true
}

// bounded returns at most n bytes of b.
func bounded(b []byte, n int) []byte {
	if n <= 0 || len(b) <= n {
		return b
	}
	return b[:n]
}

// htons converts a 16-bit value to network byte order.
func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}

// attachPortFilter installs a classic BPF program keeping only frames whose TCP
// or UDP source/destination port matches one of the given ports.
func (s *PassiveSensor) attachPortFilter(ports []int) error {
	type sockFilter struct {
		Code uint16
		Jt   uint8
		Jf   uint8
		K    uint32
	}
	type sockFprog struct {
		Len    uint16
		Filter *sockFilter
	}
	const (
		ldhAbs = 0x28 // LDH [k]
		ldbAbs = 0x30 // LDB [k]
		jeqK   = 0x15 // JEQ k
		retK   = 0x06 // RET k
	)
	// reject index is computed after building; we lay out:
	//   [0] LDH ethertype, [1] JEQ 0x0800 else -> reject
	//   [2] LDB ip proto,   [3] JEQ TCP(6) jt=1, [4] JEQ UDP(17) else -> reject
	//   [5] LDH src port,   [6..] per-port JEQ -> accept
	//   [N] LDH dst port,   [M..] per-port JEQ -> accept
	//   [reject] RET 0, [accept] RET -1
	var f []sockFilter
	f = append(f, sockFilter{Code: ldhAbs, K: 12})                 // 0 ethertype
	f = append(f, sockFilter{Code: jeqK, K: 0x0800, Jt: 0, Jf: 1}) // 1 -> skip to reject if not IPv4
	f = append(f, sockFilter{Code: ldbAbs, K: 23})                 // 2 ip proto
	f = append(f, sockFilter{Code: jeqK, K: 6, Jt: 1, Jf: 0})      // 3 tcp -> jt=1 (skip next)
	f = append(f, sockFilter{Code: jeqK, K: 17, Jt: 0, Jf: 1})     // 4 udp else -> reject
	// reject offset will be len after src+dst JEQs; compute placeholder later.
	// We build JEQs then patch jumps. For simplicity use fixed jump targets:
	// every failing JEQ falls through; last falls to reject; accept is final.
	f = append(f, sockFilter{Code: ldhAbs, K: 34}) // 5 src port
	srcJEQ := len(f)
	for range ports {
		f = append(f, sockFilter{}) // placeholder (filled below)
	}
	f = append(f, sockFilter{Code: ldhAbs, K: 36}) // dst port load
	dstJEQ := len(f)
	for range ports {
		f = append(f, sockFilter{}) // placeholder (filled below)
	}
	rejectIdx := len(f)
	f = append(f, sockFilter{Code: retK, K: 0})
	acceptIdx := len(f)
	f = append(f, sockFilter{Code: retK, K: 0xFFFFFFFF})

	// Fill source-port JEQs: match -> jump to accept; else fall through.
	for i := range ports {
		jt := uint8(acceptIdx - (srcJEQ + i) - 1)
		f[srcJEQ+i] = sockFilter{Code: jeqK, K: uint32(ports[i]), Jt: jt, Jf: 0}
	}
	// Fill dest-port JEQs similarly.
	for i := range ports {
		jt := uint8(acceptIdx - (dstJEQ + i) - 1)
		f[dstJEQ+i] = sockFilter{Code: jeqK, K: uint32(ports[i]), Jt: jt, Jf: 0}
	}
	// Patch the IPv4/UDP fallthroughs to jump to reject.
	f[1].Jf = uint8(rejectIdx - 2) // not IPv4 -> reject
	f[4].Jf = uint8(rejectIdx - 4) // not udp -> reject (tcp path fell through)

	prog := sockFprog{Len: uint16(len(f)), Filter: &f[0]}
	const (
		solSocket      = 1
		soAttachFilter = 26
	)
	_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(s.fd), uintptr(solSocket),
		uintptr(soAttachFilter), uintptr(unsafe.Pointer(&prog)), unsafe.Sizeof(prog), 0)
	if e != 0 {
		return e
	}
	return nil
}

// Stats returns captured and malformed frame counters.
func (s *PassiveSensor) Stats() (captured, malformed uint64) {
	return s.captured.Load(), s.malformed.Load()
}

// setPromisc toggles promiscuous mode via SOL_PACKET/PACKET_ADD_MEMBERSHIP.
func (s *PassiveSensor) setPromisc(enable bool) error {
	type packetMreq struct {
		Ifindex int32
		Type    uint16
		Alen    uint16
		Address [8]byte
	}
	const (
		solPacket       = 263
		packetAddMember = 1
		packetMrPromisc = 1
	)
	mr := packetMreq{Ifindex: int32(s.ifIndex), Type: packetMrPromisc}
	_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(s.fd), uintptr(solPacket),
		uintptr(packetAddMember), uintptr(unsafe.Pointer(&mr)), unsafe.Sizeof(mr), 0)
	_ = enable
	if e != 0 {
		return e
	}
	return nil
}
