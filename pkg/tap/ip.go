package tap

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// Protocols selects IP protocol numbers. An empty set selects all protocols.
type Protocols map[byte]bool

func ParseProtocols(value string) (Protocols, error) {
	p := Protocols{}
	if value == "" || value == "all" {
		return p, nil
	}
	for _, name := range strings.Split(value, ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		names := map[string]int{"icmp": 1, "tcp": 6, "udp": 17, "icmpv6": 58, "sctp": 132, "gre": 47, "esp": 50, "ah": 51}
		n, ok := names[name]
		if !ok {
			var err error
			n, err = strconv.Atoi(name)
			if err != nil || n < 0 || n > 255 {
				return nil, fmt.Errorf("invalid IP protocol %q", name)
			}
		}
		p[byte(n)] = true
	}
	return p, nil
}

func (p Protocols) Includes(n byte) bool { return len(p) == 0 || p[n] }

// IPIdentity extracts network identity even when transport data is fragmented.
func IPIdentity(p []byte) (src, dst string, proto byte, ok bool) {
	if len(p) >= 20 && p[0]>>4 == 4 {
		return net.IP(p[12:16]).String(), net.IP(p[16:20]).String(), p[9], true
	}
	if len(p) >= 40 && p[0]>>4 == 6 {
		proto = p[6]
		offset := 40
		for i := 0; i < 8; i++ {
			if proto == 44 {
				if len(p) < offset+8 {
					return "", "", 0, false
				}
				proto = p[offset]
				break
			}
			if proto != 0 && proto != 43 && proto != 60 {
				break
			}
			if len(p) < offset+2 {
				return "", "", 0, false
			}
			next := p[offset]
			offset += (int(p[offset+1]) + 1) * 8
			if offset > len(p) {
				return "", "", 0, false
			}
			proto = next
		}
		return net.IP(p[8:24]).String(), net.IP(p[24:40]).String(), proto, true
	}
	return "", "", 0, false
}

type fragmentSet struct {
	header    []byte
	data      map[int][]byte
	end       int
	seen      time.Time
	nextField int
	proto     byte
}

// IPAssembler bounds fragment state to 128 datagrams, 64KiB each, for 30s.
// Overlaps discard the whole datagram. Only complete datagrams are emitted.
type IPAssembler struct{ sets map[string]*fragmentSet }

func (a *IPAssembler) Add(p []byte) ([]byte, bool) {
	src, dst, proto, ok := IPIdentity(p)
	if !ok {
		return nil, false
	}
	start, offset, end, more, nextField := 0, 0, len(p), false, 6
	id := uint32(0)
	switch p[0] >> 4 {
	case 4:
		start = int(p[0]&15) * 4
		end = int(binary.BigEndian.Uint16(p[2:4]))
		if start < 20 || end < start || end > len(p) {
			return nil, false
		}
		bits := binary.BigEndian.Uint16(p[6:8])
		offset = int(bits&8191) * 8
		more = bits&8192 != 0
		if offset == 0 && !more {
			return p[:end], true
		}
		id = uint32(binary.BigEndian.Uint16(p[4:6]))
	case 6:
		end = 40 + int(binary.BigEndian.Uint16(p[4:6]))
		if end > len(p) {
			return nil, false
		}
		start = 40
		n := p[6]
		for i := 0; n != 44; i++ {
			if n != 0 && n != 43 && n != 60 {
				return p[:end], true
			}
			if i >= 8 || start+2 > end {
				return nil, false
			}
			nextField = start
			n = p[start]
			start += (int(p[start+1]) + 1) * 8
		}
		if start+8 > end {
			return nil, false
		}
		proto = p[start]
		bits := binary.BigEndian.Uint16(p[start+2 : start+4])
		offset = int(bits & 0xfff8)
		more = bits&1 != 0
		id = binary.BigEndian.Uint32(p[start+4 : start+8])
		start += 8
	}
	key := fmt.Sprintf("%s/%s/%d/%d", src, dst, proto, id)
	if a.sets == nil {
		a.sets = map[string]*fragmentSet{}
	}
	now := time.Now()
	for k, s := range a.sets {
		if now.Sub(s.seen) > 30*time.Second {
			delete(a.sets, k)
		}
	}
	s := a.sets[key]
	if s == nil {
		if len(a.sets) >= 128 {
			return nil, false
		}
		s = &fragmentSet{data: map[int][]byte{}, end: -1, seen: now, proto: proto, nextField: nextField}
		a.sets[key] = s
	}
	payload := p[start:end]
	if len(payload) == 0 || offset+len(payload) > 65535 || (more && len(payload)%8 != 0) {
		delete(a.sets, key)
		return nil, false
	}
	for pos, b := range s.data {
		if offset < pos+len(b) && pos < offset+len(payload) {
			delete(a.sets, key)
			return nil, false
		}
	}
	s.data[offset] = append([]byte(nil), payload...)
	if offset == 0 {
		h := start
		if p[0]>>4 == 6 {
			h -= 8
		}
		s.header = append([]byte(nil), p[:h]...)
	}
	if !more {
		s.end = offset + len(payload)
	}
	if s.end < 0 || s.header == nil {
		return nil, false
	}
	out := append([]byte(nil), s.header...)
	for pos := 0; pos < s.end; {
		b, ok := s.data[pos]
		if !ok {
			return nil, false
		}
		out = append(out, b...)
		pos += len(b)
		if pos > s.end {
			delete(a.sets, key)
			return nil, false
		}
	}
	delete(a.sets, key)
	if len(out) > 65535 {
		return nil, false
	}
	if out[0]>>4 == 4 {
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		out[6] = 0
		out[7] = 0
		out[10] = 0
		out[11] = 0
	} else {
		out[s.nextField] = s.proto
		binary.BigEndian.PutUint16(out[4:6], uint16(len(out)-40))
	}
	return out, true
}
