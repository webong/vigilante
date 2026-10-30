package tap

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

type fakeConn struct{ addr net.Addr }

func (c fakeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c fakeConn) Write(b []byte) (int, error)      { return len(b), nil }
func (c fakeConn) Close() error                     { return nil }
func (c fakeConn) LocalAddr() net.Addr              { return c.addr }
func (c fakeConn) RemoteAddr() net.Addr             { return c.addr }
func (c fakeConn) SetDeadline(time.Time) error      { return nil }
func (c fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (c fakeConn) SetWriteDeadline(time.Time) error { return nil }

func TestFingerprintStoreRoundTrip(t *testing.T) {
	s := NewFingerprintStore()
	s.record(fakeConn{addr: fakeAddr("203.0.113.9:443")}, fingerprints{JA3: "abc123", JA4: "t13d0202h2_xxxxxxxxxxxx_yyyyyyyyyyyy"})
	if got := s.LookupJA3("203.0.113.9:443"); got != "abc123" {
		t.Fatalf("LookupJA3 = %q", got)
	}
	if got := s.LookupJA4("203.0.113.9:443"); got != "t13d0202h2_xxxxxxxxxxxx_yyyyyyyyyyyy" {
		t.Fatalf("LookupJA4 = %q", got)
	}
	// Lookup remains a JA3 alias.
	if got := s.Lookup("203.0.113.9:443"); got != "abc123" {
		t.Fatalf("Lookup = %q", got)
	}
	if got := s.LookupJA3("203.0.113.9:444"); got != "" {
		t.Fatalf("Lookup unknown = %q", got)
	}
	if got := s.LookupJA4("203.0.113.9:444"); got != "" {
		t.Fatalf("LookupJA4 unknown = %q", got)
	}
}

func TestFingerprintStoreTLSConfigRecordsJA3(t *testing.T) {
	s := NewFingerprintStore()
	cfg := s.TLSConfig(&tls.Config{MinVersion: tls.VersionTLS12})
	if cfg.GetConfigForClient == nil {
		t.Fatal("TLSConfig must set GetConfigForClient")
	}
	conn := fakeConn{addr: fakeAddr("203.0.113.9:443")}
	if _, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{
		Conn:              conn,
		SupportedVersions: []uint16{tls.VersionTLS12},
		CipherSuites:      []uint16{0x1301, 0x1303},
		SupportedCurves:   []tls.CurveID{tls.X25519},
		SupportedPoints:   []uint8{0},
		Extensions:        []uint16{0x000a, 0x000b},
	}); err != nil {
		t.Fatalf("GetConfigForClient: %v", err)
	}
	fp := s.Lookup("203.0.113.9:443")
	if len(fp) != 32 {
		t.Fatalf("recorded JA3 = %q, want 32 hex chars", fp)
	}
	j4 := s.LookupJA4("203.0.113.9:443")
	if len(j4) != 36 {
		t.Fatalf("recorded JA4 = %q, want 36 chars", j4)
	}
}

func TestPreviewRequestCarriesFingerprint(t *testing.T) {
	q := NewMirrorQueue(4)
	s := NewFingerprintStore()
	q.SetFingerprints(s)
	s.record(fakeConn{addr: fakeAddr("203.0.113.9:443")}, fingerprints{JA3: "fp-fixed", JA4: "t13d0202h2_xxxxxxxxxxxx_yyyyyyyyyyyy"})

	r, _ := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	r.RemoteAddr = "203.0.113.9:443"
	PreviewRequest(q, r, ":8080", "app:3000")

	select {
	case ev := <-q.Events():
		if ev.TLSFingerprint != "fp-fixed" {
			t.Fatalf("TLSFingerprint = %q, want fp-fixed", ev.TLSFingerprint)
		}
		if ev.JA4 != "t13d0202h2_xxxxxxxxxxxx_yyyyyyyyyyyy" {
			t.Fatalf("JA4 = %q", ev.JA4)
		}
	case <-time.After(time.Second):
		t.Fatal("no event enqueued")
	}
}

func TestEnqueueTCPFingerprint(t *testing.T) {
	// A minimal ClientHello record.
	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...)
	body = append(body, 0x00, 0x00, 0x02, 0x13, 0x01, 0x01, 0x00)
	record := []byte{0x16, 0x03, 0x01, 0x00, byte(len(body) + 4)}
	record = append(record, 0x01, 0x00, 0x00, byte(len(body)))
	record = append(record, body...)

	q := NewMirrorQueue(4)
	enqueueTCP(q, ":443", "app:5432", "203.0.113.9:443", record, len(record))

	select {
	case ev := <-q.Events():
		if ev.TLSFingerprint == "" {
			t.Fatal("expected a TLS fingerprint for a ClientHello stream")
		}
		if len(ev.TLSFingerprint) != 32 {
			t.Fatalf("fingerprint = %q, want 32 hex", ev.TLSFingerprint)
		}
		if len(ev.JA4) != 36 {
			t.Fatalf("JA4 = %q, want 36 chars", ev.JA4)
		}
	case <-time.After(time.Second):
		t.Fatal("no event enqueued")
	}
}

func TestEnqueueTCPPlaintextHasNoFingerprint(t *testing.T) {
	q := NewMirrorQueue(4)
	enqueueTCP(q, ":5432", "app:5432", "203.0.113.9:443", []byte("SELECT 1;"), 8)
	select {
	case ev := <-q.Events():
		if ev.TLSFingerprint != "" {
			t.Fatalf("plaintext must not carry a fingerprint, got %q", ev.TLSFingerprint)
		}
		if ev.JA4 != "" {
			t.Fatalf("plaintext must not carry JA4, got %q", ev.JA4)
		}
	case <-time.After(time.Second):
		t.Fatal("no event enqueued")
	}
}
