package tap

import (
	"crypto/tls"
	"net"
	"sync"

	"github.com/webong/vigilante/ext/tlsfp"
)

// FingerprintStore records each connection's TLS ClientHello JA3 fingerprint as
// the handshake happens, keyed by the client's address, so a mirror event can
// carry the fingerprint of the actor that opened the connection.
//
// Keying by address is safe here: a request is always preceded by its
// connection's handshake, so the entry is (re)written before the first request
// on that connection is served, and HTTP/2 multiplexes requests over one
// handshake and one address.
type FingerprintStore struct {
	m sync.Map // remote addr -> fingerprint
}

// NewFingerprintStore returns an empty store.
func NewFingerprintStore() *FingerprintStore { return &FingerprintStore{} }

// TLSConfig returns a *tls.Config whose GetConfigForClient records the JA3
// fingerprint for each handshake. When base is non-nil its fields are cloned and
// its existing GetConfigForClient is chained.
func (s *FingerprintStore) TLSConfig(base *tls.Config) *tls.Config {
	cfg := &tls.Config{}
	if base != nil {
		cfg = base.Clone()
	}
	prev := cfg.GetConfigForClient
	cfg.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
		if fp := tlsfp.JA3(info); fp != "" {
			s.record(info.Conn, fp)
		}
		if prev != nil {
			return prev(info)
		}
		return nil, nil
	}
	return cfg
}

func (s *FingerprintStore) record(conn net.Conn, fp string) {
	if conn == nil {
		return
	}
	s.m.Store(conn.RemoteAddr().String(), fp)
}

// Lookup returns the recorded fingerprint for a remote address, or "".
func (s *FingerprintStore) Lookup(remoteAddr string) string {
	if s == nil {
		return ""
	}
	if v, ok := s.m.Load(remoteAddr); ok {
		return v.(string)
	}
	return ""
}
