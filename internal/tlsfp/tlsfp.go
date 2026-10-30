// Package tlsfp computes TLS ClientHello fingerprints (JA3 and JA4) so the core
// can tell look-alike clients apart even when they share an address — the input
// the actor index needs to key actors by more than IP.
//
// It has two entry points:
//
//   - JA3/JA4, from a *tls.ClientHelloInfo — for the terminating proxy, where
//     the TLS library has already parsed the ClientHello and preserves field
//     order.
//   - ParseClientHello, from raw bytes — for paths that see the wire directly
//     (the TCP tee, and a future passive sensor).
//
// Both produce fingerprints keyed by the same connection: JA3 is the MD5 of the
// canonical JA3 string, JA4 is the FoxIO JA4 fingerprint of the ClientHello.
package tlsfp

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Hello is a parsed ClientHello reduced to the fields JA3 and JA4 use.
type Hello struct {
	Version          uint16   // legacy_version
	CipherSuites     []uint16 // in wire order
	Extensions       []uint16 // in wire order, including GREASE
	Curves           []uint16 // supported_groups, in order
	PointFormats     []uint8  // ec_point_formats, in order
	SignatureSchemes []uint16 // signature_algorithms, in wire order (JA4)
	ALPN             []string // application_layer_protocol_negotiation (JA4)
}

// JA3 returns the canonical JA3 fingerprint for a ClientHelloInfo.
func JA3(info *tls.ClientHelloInfo) string {
	if info == nil {
		return ""
	}
	// The ClientHello legacy_version: TLS 1.3 sets 0x0303; TLS 1.2 and below
	// advertise a single version, which Go surfaces as the only entry.
	version := uint16(tls.VersionTLS12)
	if len(info.SupportedVersions) == 1 {
		version = info.SupportedVersions[0]
	}
	curves := make([]uint16, len(info.SupportedCurves))
	for i, c := range info.SupportedCurves {
		curves[i] = uint16(c)
	}
	return ja3Hash(ja3String(version, info.CipherSuites, info.Extensions, curves, info.SupportedPoints))
}

// JA3 returns the canonical JA3 fingerprint for a parsed ClientHello.
func (h Hello) JA3() string {
	return ja3Hash(h.JA3String())
}

// JA3String returns the pre-hash JA3 string, for debugging and databases.
func (h Hello) JA3String() string {
	return ja3String(h.Version, h.CipherSuites, h.Extensions, h.Curves, h.PointFormats)
}

// JA4 returns the FoxIO JA4 fingerprint for this parsed ClientHello.
//
//	t<tls version><sni d/i><cipher count><ext count><alpn chars>_<cipher hash>_<ext+sigalg hash>
//
// The "t" prefix denotes TCP (JA4 is TCP-only). When SignatureSchemes or ALPN
// were not captured by the parser, their contributions are empty.
func (h Hello) JA4() string {
	return JA4FromParts(h.CipherSuites, h.Extensions, h.SignatureSchemes, []uint16{h.Version}, h.ALPN)
}

// JA4 returns the FoxIO JA4 fingerprint for a ClientHelloInfo.
func JA4(info *tls.ClientHelloInfo) string {
	if info == nil {
		return ""
	}
	sigs := make([]uint16, len(info.SignatureSchemes))
	for i, s := range info.SignatureSchemes {
		sigs[i] = uint16(s)
	}
	return JA4FromParts(info.CipherSuites, info.Extensions, sigs, info.SupportedVersions, info.SupportedProtos)
}

// JA4FromParts computes JA4 from raw ClientHello values, per the FoxIO spec.
func JA4FromParts(ciphers, extensions, sigAlgs, versions []uint16, alpn []string) string {
	ciphers = withoutGREASE(ciphers)
	extensions = withoutGREASE(extensions)
	sigAlgs = withoutGREASE(sigAlgs)

	sni := "i"
	if slices.Contains(extensions, 0x0000) {
		sni = "d"
	}

	a := fmt.Sprintf("t%s%s%02d%02d%s",
		tlsVersion(withoutGREASE(versions)), sni,
		min(len(ciphers), 99), min(len(extensions), 99), alpnChars(alpn))

	slices.Sort(ciphers)
	b := hash12(hexList(ciphers))

	var exts []uint16
	for _, e := range extensions {
		if e != 0x0000 && e != 0x0010 { // SNI and ALPN are already in part a
			exts = append(exts, e)
		}
	}
	slices.Sort(exts)
	c := "000000000000"
	if len(exts) > 0 {
		in := hexList(exts)
		if len(sigAlgs) > 0 {
			in += "_" + hexList(sigAlgs) // original order, not sorted
		}
		c = hash12(in)
	}
	return a + "_" + b + "_" + c
}

func isGREASE(v uint16) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

func withoutGREASE(in []uint16) []uint16 {
	out := make([]uint16, 0, len(in))
	for _, v := range in {
		if !isGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func tlsVersion(versions []uint16) string {
	if len(versions) == 0 {
		return "00"
	}
	switch slices.Max(versions) {
	case tls.VersionTLS13:
		return "13"
	case tls.VersionTLS12:
		return "12"
	case tls.VersionTLS11:
		return "11"
	case tls.VersionTLS10:
		return "10"
	case 0x0300:
		return "s3"
	default:
		return "00"
	}
}

func alpnChars(alpn []string) string {
	if len(alpn) == 0 || alpn[0] == "" {
		return "00"
	}
	v := alpn[0]
	first, last := v[0], v[len(v)-1]
	if isAlnum(first) && isAlnum(last) {
		return string([]byte{first, last})
	}
	h := hex.EncodeToString([]byte(v))
	return string([]byte{h[0], h[len(h)-1]})
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func hexList(vs []uint16) string {
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func hash12(s string) string {
	if s == "" {
		return "000000000000"
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}

// ParseClientHello extracts a Hello from the leading bytes of a TLS stream. It
// tolerates truncated input by reading what is present. The bool is false when
// the bytes are not a TLS ClientHello record.
func ParseClientHello(data []byte) (Hello, bool) {
	// Record layer: 5-byte header (type 0x16, version, length).
	if len(data) < 5 || data[0] != 0x16 {
		return Hello{}, false
	}
	recordLen := int(data[3])<<8 | int(data[4])
	payload := data[5:]
	if len(payload) > recordLen {
		payload = payload[:recordLen]
	}
	// Handshake: type 0x01, 3-byte length, then the ClientHello body.
	if len(payload) < 4 || payload[0] != 0x01 {
		return Hello{}, false
	}
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	body := payload[4:]
	if len(body) > hsLen {
		body = body[:hsLen]
	}
	return parseBody(body)
}

func parseBody(b []byte) (Hello, bool) {
	if len(b) < 2+32 {
		return Hello{}, false
	}
	h := Hello{Version: uint16(b[0])<<8 | uint16(b[1])}
	p := b[2+32:]

	// Session ID.
	if len(p) < 1 {
		return Hello{}, false
	}
	n := int(p[0])
	p = p[1:]
	if len(p) < n {
		return Hello{}, false
	}
	p = p[n:]

	// Cipher suites.
	if len(p) < 2 {
		return Hello{}, false
	}
	csLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < csLen || csLen%2 != 0 {
		return Hello{}, false
	}
	for i := 0; i+1 < csLen; i += 2 {
		h.CipherSuites = append(h.CipherSuites, uint16(p[i])<<8|uint16(p[i+1]))
	}
	p = p[csLen:]

	// Compression methods.
	if len(p) < 1 {
		return Hello{}, false
	}
	n = int(p[0])
	p = p[1:]
	if len(p) < n {
		return Hello{}, false
	}
	p = p[n:]

	// Extensions (optional).
	if len(p) == 0 {
		return h, true
	}
	if len(p) < 2 {
		return Hello{}, false
	}
	extLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) > extLen {
		p = p[:extLen]
	}
	for len(p) >= 4 {
		typ := uint16(p[0])<<8 | uint16(p[1])
		l := int(p[2])<<8 | int(p[3])
		if len(p) < 4+l {
			break
		}
		data := p[4 : 4+l]
		h.Extensions = append(h.Extensions, typ)
		switch typ {
		case 10: // supported_groups
			if len(data) >= 2 {
				gl := int(data[0])<<8 | int(data[1])
				for i := 2; i+1 < len(data) && i < 2+gl; i += 2 {
					h.Curves = append(h.Curves, uint16(data[i])<<8|uint16(data[i+1]))
				}
			}
		case 11: // ec_point_formats
			if len(data) >= 1 {
				pl := int(data[0])
				for i := 1; i < len(data) && i < 1+pl; i++ {
					h.PointFormats = append(h.PointFormats, data[i])
				}
			}
		case 13: // signature_algorithms (JA4)
			if len(data) >= 2 {
				gl := int(data[0])<<8 | int(data[1])
				for i := 2; i+1 < len(data) && i < 2+gl; i += 2 {
					h.SignatureSchemes = append(h.SignatureSchemes, uint16(data[i])<<8|uint16(data[i+1]))
				}
			}
		case 16: // ALPN (JA4)
			if len(data) >= 2 {
				al := int(data[0])<<8 | int(data[1])
				p2 := data[2 : 2+min(al, len(data)-2)]
				for len(p2) >= 2 {
					l := int(p2[0])
					if len(p2) < 1+l {
						break
					}
					h.ALPN = append(h.ALPN, string(p2[1:1+l]))
					p2 = p2[1+l:]
				}
			}
		}
		p = p[4+l:]
	}
	return h, true
}

func ja3String(version uint16, ciphers, extensions, curves []uint16, points []uint8) string {
	return strings.Join([]string{
		strconv.Itoa(int(version)),
		joinUint16(ciphers),
		joinUint16(extensions),
		joinUint16(curves),
		joinUint8(points),
	}, ",")
}

func joinUint16(vals []uint16) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

func joinUint8(vals []uint8) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = strconv.Itoa(int(v))
	}
	return strings.Join(parts, "-")
}

func ja3Hash(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}
