package tap

import (
	"encoding/binary"
	"testing"
)

func fragment(offset int, more bool, data string) []byte {
	p := make([]byte, 20+len(data))
	p[0] = 0x45
	p[9] = 1
	p[12] = 10
	p[16] = 20
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	bits := uint16(offset / 8)
	if more {
		bits |= 8192
	}
	binary.BigEndian.PutUint16(p[6:8], bits)
	copy(p[20:], data)
	return p
}

func TestFragmentsOutOfOrder(t *testing.T) {
	a := &IPAssembler{}
	if _, ok := a.Add(fragment(8, false, "tail")); ok {
		t.Fatal("premature completion")
	}
	p, ok := a.Add(fragment(0, true, "12345678"))
	if !ok || string(p[20:]) != "12345678tail" {
		t.Fatalf("assembly: %x %v", p, ok)
	}
	src, _, proto, ok := IPIdentity(fragment(8, false, "tail"))
	if !ok || src != "10.0.0.0" || proto != 1 {
		t.Fatal("fragment identity unavailable")
	}
}

func TestFragmentOverlapRejected(t *testing.T) {
	a := &IPAssembler{}
	a.Add(fragment(0, true, "1234567812345678"))
	if _, ok := a.Add(fragment(8, false, "tail")); ok {
		t.Fatal("overlap accepted")
	}
	if len(a.sets) != 0 {
		t.Fatal("overlapping datagram retained")
	}
}

func TestProtocolSelection(t *testing.T) {
	p, err := ParseProtocols("tcp,icmp,icmpv6,99")
	if err != nil || !p.Includes(1) || !p.Includes(58) || !p.Includes(99) || p.Includes(17) {
		t.Fatal(p, err)
	}
	if _, err := ParseProtocols("256"); err == nil {
		t.Fatal("invalid ID accepted")
	}
}

func TestIPv6FragmentAssembly(t *testing.T) {
	makePart := func(offset uint16, data string) []byte {
		p := make([]byte, 48+len(data))
		p[0] = 0x60
		p[6] = 44
		p[8] = 0x20
		p[24] = 0x30
		p[40] = 58
		binary.BigEndian.PutUint16(p[4:6], uint16(len(p)-40))
		binary.BigEndian.PutUint16(p[42:44], offset)
		copy(p[48:], data)
		return p
	}
	a := &IPAssembler{}
	if _, ok := a.Add(makePart(1, "12345678")); ok {
		t.Fatal("premature assembly")
	}
	p, ok := a.Add(makePart(8, "tail"))
	if !ok || p[6] != 58 || string(p[40:]) != "12345678tail" {
		t.Fatalf("IPv6 assembly: %x %v", p, ok)
	}
}

func TestDecodeICMPAndUnknown(t *testing.T) {
	for _, proto := range []byte{1, 58, 99} {
		p := fragment(0, false, "12345678")
		p[9] = proto
		frame := make([]byte, 14+len(p))
		frame[12] = 8
		copy(frame[14:], p)
		ev, ok := DecodeFrame(frame, 1514)
		if !ok || ev.SrcAddr != "10.0.0.0" || ev.PayloadBytes != 8 {
			t.Fatalf("%d: %+v %v", proto, ev, ok)
		}
	}
}
