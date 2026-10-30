package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"syscall"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/webong/vigilante/internal/flow"
)

var ErrNoSignature = errors.New("no web bot auth signature")
var ErrDirectoryUnavailable = errors.New("key directory unavailable")

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}
type WebBotAuth struct {
	client HTTPClient
	mu     sync.Mutex
	dirs   map[string]directory
}
type directory struct {
	keys    map[string]ed25519.PublicKey
	fetched time.Time
	err     error
}

func NewWebBotAuth(client HTTPClient) *WebBotAuth {
	if client == nil {
		dialer := &net.Dialer{Timeout: 5 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
			ap, err := netip.ParseAddrPort(address)
			if err != nil {
				return err
			}
			if a := ap.Addr().Unmap(); !a.IsGlobalUnicast() || a.IsPrivate() {
				return fmt.Errorf("refusing to fetch key directory from %s", a)
			}
			return nil
		}}
		client = &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: 5 * time.Second}, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	return &WebBotAuth{client: client, dirs: map[string]directory{}}
}
func (w *WebBotAuth) Verify(ctx context.Context, ev flow.Event) (string, error) {
	sigInput, sigs, agentHeader := header(ev.Headers, "signature-input"), header(ev.Headers, "signature"), header(ev.Headers, "signature-agent")
	if sigInput == "" || sigs == "" {
		return "", ErrNoSignature
	}
	inputs, err := httpsfv.UnmarshalDictionary([]string{sigInput})
	if err != nil {
		return "", fmt.Errorf("Signature-Input: %w", err)
	}
	values, err := httpsfv.UnmarshalDictionary([]string{sigs})
	if err != nil {
		return "", fmt.Errorf("Signature: %w", err)
	}
	var lastErr = ErrNoSignature
	for _, label := range inputs.Names() {
		raw, _ := inputs.Get(label)
		il, ok := raw.(httpsfv.InnerList)
		if !ok || paramString(il.Params, "tag") != "web-bot-auth" {
			continue
		}
		origin, err := signatureOrigin(agentHeader, label)
		if err != nil {
			lastErr = err
			continue
		}
		keyid := paramString(il.Params, "keyid")
		if keyid == "" {
			lastErr = errors.New("missing keyid")
			continue
		}
		created, _ := paramInt(il.Params, "created")
		expires, _ := paramInt(il.Params, "expires")
		now := ev.Timestamp.Unix()
		if now == 0 {
			now = time.Now().Unix()
		}
		if created > now+60 || (expires > 0 && expires < now-60) {
			lastErr = errors.New("signature not valid at request time")
			continue
		}
		base, err := signatureBase(ev, il, label, origin)
		if err != nil {
			lastErr = err
			continue
		}
		member, ok := values.Get(label)
		if !ok {
			lastErr = errors.New("signature label not found")
			continue
		}
		sig, ok := member.(httpsfv.Item)
		if !ok {
			lastErr = errors.New("invalid signature item")
			continue
		}
		bytes, ok := sig.Value.([]byte)
		if !ok {
			lastErr = errors.New("signature is not a byte sequence")
			continue
		}
		key, err := w.key(ctx, origin, keyid)
		if err != nil {
			lastErr = err
			continue
		}
		if !ed25519.Verify(key, []byte(base), bytes) {
			lastErr = errors.New("signature does not verify")
			continue
		}
		return origin, nil
	}
	return "", lastErr
}
func signatureOrigin(header, label string) (string, error) {
	dict, err := httpsfv.UnmarshalDictionary([]string{header})
	if err != nil {
		return "", err
	}
	raw, ok := dict.Get(label)
	if !ok {
		return "", errors.New("Signature-Agent label not found")
	}
	item, ok := raw.(httpsfv.Item)
	if !ok {
		return "", errors.New("invalid Signature-Agent")
	}
	origin, ok := item.Value.(string)
	if !ok {
		return "", errors.New("Signature-Agent is not a URI")
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Path != "" {
		return "", errors.New("Signature-Agent must be an https origin")
	}
	return origin, nil
}
func (w *WebBotAuth) key(ctx context.Context, origin, keyid string) (ed25519.PublicKey, error) {
	w.mu.Lock()
	dir, ok := w.dirs[origin]
	w.mu.Unlock()
	if !ok || time.Since(dir.fetched) > time.Hour || (dir.err != nil && time.Since(dir.fetched) > 5*time.Minute) {
		dir = w.fetch(ctx, origin)
		w.mu.Lock()
		w.dirs[origin] = dir
		w.mu.Unlock()
	}
	if dir.err != nil {
		return nil, dir.err
	}
	key, ok := dir.keys[keyid]
	if !ok {
		return nil, fmt.Errorf("%s publishes no key %s", origin, keyid)
	}
	return key, nil
}
func Thumbprint(pub []byte) string {
	canonical := `{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}`
	sum := sha256.Sum256([]byte(canonical))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
func paramString(p *httpsfv.Params, k string) string {
	if p == nil {
		return ""
	}
	v, _ := p.Get(k)
	s, _ := v.(string)
	return s
}
func paramInt(p *httpsfv.Params, k string) (int64, bool) {
	if p == nil {
		return 0, false
	}
	v, _ := p.Get(k)
	n, ok := v.(int64)
	return n, ok
}
