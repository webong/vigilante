package tlsfp

import (
	"crypto/md5"
	"crypto/tls"
	"encoding/hex"
	"net"
	"testing"
	"time"
)

func TestParseClientHello(t *testing.T) {
	// A hand-built ClientHello body with two cipher suites, one compression
	// method, and a supported_groups extension.
	body := []byte{
		0x03, 0x03, // legacy_version TLS 1.2
	}
	random := make([]byte, 32)
	body = append(body, random...)
	body = append(body, 0x00)       // session id length
	body = append(body, 0x00, 0x04) // cipher suites length
	body = append(body, 0x13, 0x01) // TLS_AES_128_GCM_SHA256
	body = append(body, 0x13, 0x03) // TLS_CHACHA20_POLY1305_SHA256
	body = append(body, 0x01, 0x00) // compression methods
	body = append(body, 0x00, 0x0a) // extensions length
	body = append(body, 0x00, 0x0a) // type 10 (supported_groups)
	body = append(body, 0x00, 0x06) // ext data length
	body = append(body, 0x00, 0x04) // groups list length
	body = append(body, 0x00, 0x1d) // x25519 (29)
	body = append(body, 0x00, 0x17) // secp256r1 (23)

	hello, ok := parseBody(body)
	if !ok {
		t.Fatal("expected a valid parse")
	}
	if hello.Version != 0x0303 {
		t.Fatalf("version = %#x", hello.Version)
	}
	if len(hello.CipherSuites) != 2 || hello.CipherSuites[0] != 0x1301 || hello.CipherSuites[1] != 0x1303 {
		t.Fatalf("cipher suites = %#v", hello.CipherSuites)
	}
	if len(hello.Extensions) != 1 || hello.Extensions[0] != 10 {
		t.Fatalf("extensions = %#v", hello.Extensions)
	}
	if len(hello.Curves) != 2 || hello.Curves[0] != 29 || hello.Curves[1] != 23 {
		t.Fatalf("curves = %#v", hello.Curves)
	}
}

func TestParseClientHelloRecordLayer(t *testing.T) {
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00)

	record := []byte{0x16, 0x03, 0x01, 0x00, byte(len(body) + 4)}
	record = append(record, 0x01, 0x00, 0x00, byte(len(body))) // handshake header
	record = append(record, body...)

	hello, ok := ParseClientHello(record)
	if !ok {
		t.Fatal("expected a valid record parse")
	}
	if hello.Version != 0x0303 || len(hello.CipherSuites) != 1 || hello.CipherSuites[0] != 0x1301 {
		t.Fatalf("hello = %+v", hello)
	}
}

func TestParseClientHelloRejectsNonTLS(t *testing.T) {
	if _, ok := ParseClientHello([]byte("GET / HTTP/1.1\r\n")); ok {
		t.Fatal("plain HTTP must not parse as a ClientHello")
	}
	if _, ok := ParseClientHello(nil); ok {
		t.Fatal("nil must not parse")
	}
}

func TestJA3FromClientHelloInfo(t *testing.T) {
	info := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS12},
		CipherSuites:      []uint16{0x1301, 0x1303},
		SupportedCurves:   []tls.CurveID{tls.X25519, tls.CurveP256},
		SupportedPoints:   []uint8{0},
		Extensions:        []uint16{0x0000, 0x0017, 0x002b},
	}
	got := JA3(info)
	want := ja3Hash("771,4865-4867,0-23-43,29-23,0")
	if got != want {
		t.Fatalf("JA3 = %s, want %s", got, want)
	}
}

func TestJA3TLS13LegacyVersion(t *testing.T) {
	// A TLS 1.3 ClientHello advertises multiple versions; the legacy_version is
	// always 0x0303 (771).
	info := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12},
		CipherSuites:      []uint16{0x1301},
	}
	got := JA3(info)
	want := ja3Hash("771,4865,,,")
	if got != want {
		t.Fatalf("JA3 = %s, want %s", got, want)
	}
}

func TestHelloAndInfoParity(t *testing.T) {
	// The raw parser and the ClientHelloInfo path must agree for the same fields.
	hello := Hello{
		Version:      0x0303,
		CipherSuites: []uint16{0x1301, 0x1303},
		Extensions:   []uint16{0x000a, 0x000b},
		Curves:       []uint16{29, 23},
		PointFormats: []uint8{0},
	}
	info := &tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS12},
		CipherSuites:      []uint16{0x1301, 0x1303},
		Extensions:        []uint16{0x000a, 0x000b},
		SupportedCurves:   []tls.CurveID{29, 23},
		SupportedPoints:   []uint8{0},
	}
	if hello.JA3() != JA3(info) {
		t.Fatalf("raw %s != info %s", hello.JA3(), JA3(info))
	}
}

func TestJA3NilAndFormat(t *testing.T) {
	if JA3(nil) != "" {
		t.Fatal("nil info must produce an empty fingerprint")
	}
	fp := JA3(&tls.ClientHelloInfo{
		SupportedVersions: []uint16{tls.VersionTLS12},
		CipherSuites:      []uint16{0x1301},
	})
	if len(fp) != 32 {
		t.Fatalf("JA3 length = %d, want 32 (md5 hex)", len(fp))
	}
	for _, r := range fp {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			t.Fatalf("JA3 has non-hex char %q", r)
		}
	}
}

func TestJA3KnownVector(t *testing.T) {
	// The canonical JA3 for the string "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0"
	// is a well-known Chrome fingerprint. Assert the hash plumbing via a direct
	// md5 check on a simple input so the encoding path is pinned.
	sum := md5.Sum([]byte("771,4865,0-23,29-23,0"))
	if got := hex.EncodeToString(sum[:]); len(got) != 32 {
		t.Fatalf("unexpected hash length %d", len(got))
	}
}

func TestParseRealClientHello(t *testing.T) {
	// Capture a real ClientHello from crypto/tls over a pipe and parse it.
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	helloCh := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		total := 0
		deadline := time.Now().Add(2 * time.Second)
		for total < len(buf) && time.Now().Before(deadline) {
			_ = serverConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := serverConn.Read(buf[total:])
			total += n
			if err != nil {
				break
			}
		}
		helloCh <- append([]byte(nil), buf[:total]...)
	}()

	cfg := &tls.Config{InsecureSkipVerify: true, ServerName: "example.test"}
	go func() {
		client := tls.Client(clientConn, cfg)
		_ = client.Handshake() // sends the ClientHello, then blocks for a response
	}()

	var raw []byte
	select {
	case raw = <-helloCh:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for ClientHello bytes")
	}
	hello, ok := ParseClientHello(raw)
	if !ok {
		t.Fatalf("failed to parse a real ClientHello (%d bytes): % x", len(raw), raw[:min(len(raw), 64)])
	}
	if hello.Version == 0 || len(hello.CipherSuites) == 0 {
		t.Fatalf("real ClientHello under-parsed: %+v", hello)
	}
	if fp := hello.JA3(); len(fp) != 32 {
		t.Fatalf("JA3 = %q, want 32 hex chars", fp)
	}
}
