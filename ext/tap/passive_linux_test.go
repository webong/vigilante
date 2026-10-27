//go:build linux

package tap

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

// buildIPv4TCPFrame constructs a minimal Ethernet+IPv4+TCP frame with a payload.
func buildIPv4TCPFrame(srcIP, dstIP net.IP, sport, dport uint16, payload []byte) []byte {
	frame := make([]byte, 14)
	binary.BigEndian.PutUint16(frame[12:14], 0x0800) // IPv4

	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(20+20+len(payload)))
	ip[9] = 6 // TCP
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], dstIP.To4())

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	tcp[12] = 0x50 // data offset 5 (20 bytes)

	return append(append(frame, ip...), append(tcp, payload...)...)
}

func TestDecodeIPv4TCP(t *testing.T) {
	s := &PassiveSensor{opts: PassiveOptions{SnapLen: 1514}}
	frame := buildIPv4TCPFrame(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 5555, 8080, []byte("GET /admin"))
	ev, ok := s.decode(frame)
	if !ok {
		t.Fatal("decode failed")
	}
	if ev.Protocol != "tcp" {
		t.Fatalf("protocol = %q", ev.Protocol)
	}
	if ev.SrcAddr != "10.0.0.1:5555" || ev.DstAddr != "10.0.0.2:8080" {
		t.Fatalf("addrs = %q -> %q", ev.SrcAddr, ev.DstAddr)
	}
	if !strings.Contains(ev.PayloadPreview, "GET /admin") {
		t.Fatalf("payload = %q", ev.PayloadPreview)
	}
}

func TestDecodeRejectsNonIPv4(t *testing.T) {
	s := &PassiveSensor{opts: PassiveOptions{SnapLen: 1514}}
	frame := make([]byte, 40)
	binary.BigEndian.PutUint16(frame[12:14], 0x86DD) // IPv6
	if _, ok := s.decode(frame); ok {
		t.Fatal("non-IPv4 should be rejected")
	}
}

func TestDecodeRejectsTruncated(t *testing.T) {
	s := &PassiveSensor{opts: PassiveOptions{SnapLen: 1514}}
	if _, ok := s.decode([]byte{1, 2, 3}); ok {
		t.Fatal("truncated frame should be rejected")
	}
}

func TestDecodeRedactsPayload(t *testing.T) {
	s := &PassiveSensor{opts: PassiveOptions{SnapLen: 1514}}
	frame := buildIPv4TCPFrame(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1, 2,
		[]byte(`token=sk-abcdefghijklmnop`))
	ev, ok := s.decode(frame)
	if !ok {
		t.Fatal("decode failed")
	}
	if strings.Contains(ev.PayloadPreview, "sk-abcdefghijklmnop") {
		t.Fatalf("payload leaked secret: %q", ev.PayloadPreview)
	}
}
