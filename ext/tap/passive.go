package tap

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
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
	// destination ports. Empty captures all IPv4 traffic.
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
	return &PassiveSensor{opts: opts, q: q, backend: backend}, nil
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
		if s.q.Enqueue(ev) {
			s.captured.Add(1)
		}
	}
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

// DecodeFrame parses an Ethernet frame (snapLen bounds payload) into a
// PacketEvent. It is shared across all OS backends. Returns ok=false for
// non-IPv4, truncated, or malformed frames.
func DecodeFrame(frame []byte, snapLen int) (agent.PacketEvent, bool) {
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
		payload = bounded(transport[dataOff:], snapLen)
	case 17: // UDP
		if len(transport) < 8 {
			return agent.PacketEvent{}, false
		}
		sport = binary.BigEndian.Uint16(transport[0:2])
		dport = binary.BigEndian.Uint16(transport[2:4])
		payload = bounded(transport[8:], snapLen)
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
