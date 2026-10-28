package tap

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"

	"github.com/webong/vigilante/ext/agent"
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
	frame := buildIPv4TCPFrame(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 5555, 8080, []byte("GET /admin"))
	ev, ok := DecodeFrame(frame, 1514)
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

func TestDecodeRejectsMalformedIPv6(t *testing.T) {
	frame := make([]byte, 40)
	binary.BigEndian.PutUint16(frame[12:14], 0x86DD) // IPv6
	if _, ok := DecodeFrame(frame, 1514); ok {
		t.Fatal("malformed IPv6 should be rejected")
	}
}

func TestDecodeIPv6TCPAndVLAN(t *testing.T) {
	frame := make([]byte, 14+4+40+20+5)
	binary.BigEndian.PutUint16(frame[12:14], 0x8100)
	binary.BigEndian.PutUint16(frame[16:18], 0x86dd)
	ip := frame[18:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], 25)
	ip[6] = 6
	copy(ip[8:24], net.ParseIP("2001:db8::1").To16())
	copy(ip[24:40], net.ParseIP("2001:db8::2").To16())
	tcp := ip[40:]
	binary.BigEndian.PutUint16(tcp[0:2], 1234)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 0x50
	copy(tcp[20:], "hello")
	ev, ok := DecodeFrame(frame, 1514)
	if !ok || ev.SrcAddr != "[2001:db8::1]:1234" || ev.DstAddr != "[2001:db8::2]:443" || ev.PayloadPreview != "hello" {
		t.Fatalf("unexpected decode: %+v, ok=%v", ev, ok)
	}
}

func TestDecodeSkipsIPv4Fragments(t *testing.T) {
	frame := buildIPv4TCPFrame(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1, 2, nil)
	binary.BigEndian.PutUint16(frame[14+6:14+8], 0x2000)
	if _, ok := DecodeFrame(frame, 1514); ok {
		t.Fatal("fragment should be skipped without reassembly")
	}
}

func TestMatchesPortWithIPv6(t *testing.T) {
	if !matchesPort(agent.PacketEvent{SrcAddr: "[2001:db8::1]:1234", DstAddr: "[2001:db8::2]:443"}, []int{443}) {
		t.Fatal("destination port should match")
	}
}

func TestDecodeRejectsTruncated(t *testing.T) {
	if _, ok := DecodeFrame([]byte{1, 2, 3}, 1514); ok {
		t.Fatal("truncated frame should be rejected")
	}
}

func TestDecodeRedactsPayload(t *testing.T) {
	frame := buildIPv4TCPFrame(net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2"), 1, 2,
		[]byte(`token=sk-abcdefghijklmnop`))
	ev, ok := DecodeFrame(frame, 1514)
	if !ok {
		t.Fatal("decode failed")
	}
	if strings.Contains(ev.PayloadPreview, "sk-abcdefghijklmnop") {
		t.Fatalf("payload leaked secret: %q", ev.PayloadPreview)
	}
}
