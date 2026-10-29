package tap

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/webong/vigilante/ext/agent"
)

// PassiveOptions configures a passive packet-capture mirror: it observes traffic
// on an interface without being in the forwarding path (a true sensor).
type PassiveOptions struct {
	// Iface is the network interface to sniff (e.g. "eth0", "en0"). Empty uses
	// the platform default.
	Iface string
	// Ports, when non-empty, restricts capture to these TCP/UDP source or
	// destination ports. Empty captures all IPv4 and IPv6 traffic.
	Ports []int
	// SnapLen bounds each captured frame's payload preview (default 1514).
	SnapLen int
	// Promiscuous enables promiscuous mode where supported (Linux).
	Promiscuous bool
}

// passiveCapture is the per-OS packet-capture backend. Implementations live in
// capture_<os>.go and must honor ctx cancellation.
type passiveCapture interface {
	// ReadEvent returns the next captured event, or ok=false if none is ready
	// yet (backend timed out / tick). Returning err aborts the sensor.
	ReadEvent(ctx context.Context) (ev agent.PacketEvent, ok bool, err error)
	Close() error
}

// PassiveSensor sniffs packets off an interface into a MirrorQueue. It never
// forwards or modifies traffic — it is observe-only (the sensor posture).
// The OS-specific capture lives behind passiveCapture.
type PassiveSensor struct {
	opts      PassiveOptions
	q         *MirrorQueue
	backend   passiveCapture
	streams   *streamPreview
	captured  atomic.Uint64
	malformed atomic.Uint64
}

// NewPassiveSensor opens the platform capture backend (Linux: AF_PACKET,
// macOS: tcpdump, Windows: npcap-style — see capture_<os>.go).
func NewPassiveSensor(opts PassiveOptions, q *MirrorQueue) (*PassiveSensor, error) {
	if opts.SnapLen <= 0 {
		opts.SnapLen = 1514
	}
	backend, err := newPassiveCapture(opts)
	if err != nil {
		return nil, err
	}
	return &PassiveSensor{opts: opts, q: q, backend: backend, streams: newStreamPreview()}, nil
}

// Run reads frames until ctx is done, enqueueing decoded events.
func (s *PassiveSensor) Run(ctx context.Context) error {
	defer s.Close()
	for {
		if ctx.Err() != nil {
			return nil
		}
		ev, ok, err := s.backend.ReadEvent(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if !ok {
			continue
		}
		if len(s.opts.Ports) > 0 && !matchesPort(ev, s.opts.Ports) {
			continue
		}
		if s.streams != nil {
			ev = s.streams.Add(ev)
		}
		if s.q.Enqueue(ev) {
			s.captured.Add(1)
		}
	}
}

func matchesPort(ev agent.PacketEvent, ports []int) bool {
	for _, addr := range []string{ev.SrcAddr, ev.DstAddr} {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		p, err := strconv.Atoi(port)
		if err != nil {
			continue
		}
		for _, wanted := range ports {
			if p == wanted {
				return true
			}
		}
	}
	return false
}

// Close releases the underlying capture.
func (s *PassiveSensor) Close() error {
	if s.backend != nil {
		return s.backend.Close()
	}
	return nil
}

// Stats returns captured and malformed frame counters.
func (s *PassiveSensor) Stats() (captured, malformed uint64) {
	return s.captured.Load(), s.malformed.Load()
}

// DecodeFrame parses an Ethernet frame into a PacketEvent. Fragmented packets
// are skipped because a single fragment cannot provide a trustworthy preview.
func DecodeFrame(frame []byte, snapLen int) (agent.PacketEvent, bool) {
	if len(frame) < 14 {
		return agent.PacketEvent{}, false
	}
	ethType := binary.BigEndian.Uint16(frame[12:14])
	frame = frame[14:]
	for tags := 0; ethType == 0x8100 || ethType == 0x88a8; tags++ {
		if tags >= 2 || len(frame) < 4 {
			return agent.PacketEvent{}, false
		}
		ethType = binary.BigEndian.Uint16(frame[2:4])
		frame = frame[4:]
	}
	var srcIP, dstIP string
	var proto byte
	var transport []byte
	switch ethType {
	case 0x0800:
		if len(frame) < 20 || frame[0]>>4 != 4 {
			return agent.PacketEvent{}, false
		}
		ihl := int(frame[0]&0x0f) * 4
		if ihl < 20 || len(frame) < ihl || binary.BigEndian.Uint16(frame[6:8])&0x3fff != 0 {
			return agent.PacketEvent{}, false
		}
		length := int(binary.BigEndian.Uint16(frame[2:4]))
		if length < ihl || length > len(frame) {
			return agent.PacketEvent{}, false
		}
		proto = frame[9]
		srcIP, dstIP = net.IP(frame[12:16]).String(), net.IP(frame[16:20]).String()
		transport = frame[ihl:length]
	case 0x86dd:
		if len(frame) < 40 || frame[0]>>4 != 6 {
			return agent.PacketEvent{}, false
		}
		length := 40 + int(binary.BigEndian.Uint16(frame[4:6]))
		if length > len(frame) {
			return agent.PacketEvent{}, false
		}
		proto = frame[6]
		srcIP, dstIP = net.IP(frame[8:24]).String(), net.IP(frame[24:40]).String()
		transport = frame[40:length]
		for hops := 0; hops < 8; hops++ {
			if proto != 0 && proto != 43 && proto != 60 {
				break
			}
			if len(transport) < 2 {
				return agent.PacketEvent{}, false
			}
			next, extLen := transport[0], (int(transport[1])+1)*8
			if extLen > len(transport) {
				return agent.PacketEvent{}, false
			}
			proto, transport = next, transport[extLen:]
		}
	default:
		return agent.PacketEvent{}, false
	}
	var sport, dport uint16
	var payload []byte
	var payloadBytes int
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
		payloadBytes = len(transport[dataOff:])
		payload = bounded(transport[dataOff:], snapLen)
	case 17: // UDP
		if len(transport) < 8 {
			return agent.PacketEvent{}, false
		}
		sport = binary.BigEndian.Uint16(transport[0:2])
		dport = binary.BigEndian.Uint16(transport[2:4])
		payloadBytes = len(transport[8:])
		payload = bounded(transport[8:], snapLen)
		protocol = "udp"
	default:
		protocol = fmt.Sprintf("ip-%d", proto)
		switch proto {
		case 1:
			protocol = "icmp"
		case 58:
			protocol = "icmpv6"
		case 132:
			protocol = "sctp"
		case 47:
			protocol = "gre"
		case 50:
			protocol = "esp"
		case 51:
			protocol = "ah"
		}
		payloadBytes = len(transport)
		payload = bounded(transport, snapLen)
	}

	ev := agent.PacketEvent{
		Timestamp:       time.Now().UTC(),
		Protocol:        protocol,
		SrcAddr:         net.JoinHostPort(srcIP, fmt.Sprintf("%d", sport)),
		DstAddr:         net.JoinHostPort(dstIP, fmt.Sprintf("%d", dport)),
		TargetAddr:      net.JoinHostPort(dstIP, fmt.Sprintf("%d", dport)),
		PayloadPreview:  string(payload),
		PayloadBytes:    payloadBytes,
		PreviewComplete: payloadBytes == len(payload),
	}
	if proto == 6 {
		ev.TCPSequence = binary.BigEndian.Uint32(transport[4:8])
	}
	if proto != 6 && proto != 17 {
		ev.SrcAddr, ev.DstAddr, ev.TargetAddr = srcIP, dstIP, dstIP
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
