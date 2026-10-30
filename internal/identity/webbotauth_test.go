package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/dunglas/httpsfv"
	"time"

	"github.com/webong/vigilante/internal/flow"
)

type testAgent struct {
	priv  ed25519.PrivateKey
	keyid string
	srv   *httptest.Server
}

func newTestAgent(t *testing.T) *testAgent {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	a := &testAgent{priv: priv, keyid: Thumbprint(pub)}
	x := base64.RawURLEncoding.EncodeToString(pub)
	a.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"keys":[{"kty":"OKP","crv":"Ed25519","x":%q}]}`, x)
	}))
	t.Cleanup(a.srv.Close)
	return a
}
func (a *testAgent) sign(host string, now time.Time) flow.Event {
	params := fmt.Sprintf(`("@authority" "signature-agent";key="sig1");created=%d;keyid="%s";alg="ed25519";expires=%d;tag="web-bot-auth"`, now.Add(-time.Minute).Unix(), a.keyid, now.Add(time.Hour).Unix())
	// The signature base uses the raw (unquoted) header value for the
	// signature-agent component; the header itself carries it quoted (valid SFV).
	origin := a.srv.URL
	base := `"@authority": ` + host + "\n" + `"signature-agent";key="sig1": ` + origin + "\n" + `"@signature-params": ` + params
	sig := ed25519.Sign(a.priv, []byte(base))
	return flow.Event{Timestamp: now, Host: host, Path: "/", Headers: map[string]string{"Signature-Agent": "sig1=" + fmt.Sprintf("%q", origin), "Signature-Input": "sig1=" + params, "Signature": "sig1=:" + base64.StdEncoding.EncodeToString(sig) + ":"}}
}
func TestValidAndTamperedSignatures(t *testing.T) {
	a := newTestAgent(t)
	v := NewWebBotAuth(a.srv.Client())
	now := time.Now()
	ev := a.sign("example.com", now)
	params, parseErr := httpsfv.UnmarshalDictionary([]string{ev.Headers["Signature-Input"]})
	if parseErr != nil {
		t.Fatalf("test structured field: %v input=%q", parseErr, ev.Headers["Signature-Input"])
	}
	member, _ := params.Get("sig1")
	il := member.(httpsfv.InnerList)
	base, baseErr := signatureBase(ev, il, "sig1", a.srv.URL)
	t.Logf("base=%q err=%v", base, baseErr)
	expectedPrefix := `"@authority": example.com` + "\n" + `"signature-agent";key="sig1": https://`
	if baseErr != nil || len(base) < len(expectedPrefix) || base[:len(expectedPrefix)] != expectedPrefix {
		t.Fatalf("canonical base=%q err=%v", base, baseErr)
	}
	origin, err := v.Verify(context.Background(), ev)
	if err != nil || origin != a.srv.URL {
		t.Fatalf("origin=%q err=%v", origin, err)
	}
	ev.Host = "victim.example"
	if _, err := v.Verify(context.Background(), ev); err == nil {
		t.Fatal("tampered authority verified")
	}
}
func TestDefaultClientRefusesPrivateDirectory(t *testing.T) {
	a := newTestAgent(t)
	_, err := NewWebBotAuth(nil).Verify(context.Background(), a.sign("example.com", time.Now()))
	if !errors.Is(err, ErrDirectoryUnavailable) {
		t.Fatalf("err=%v", err)
	}
}
