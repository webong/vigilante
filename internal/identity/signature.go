package identity

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/dunglas/httpsfv"
	"github.com/webong/vigilante/internal/flow"
)

func signatureBase(ev flow.Event, il httpsfv.InnerList, label, origin string) (string, error) {
	var b strings.Builder
	hasTarget := false
	host := ev.Host
	if host == "" {
		host = ev.TargetAddr
	}
	uri := ev.Path
	if !strings.HasPrefix(uri, "/") {
		uri = "/" + uri
	}
	scheme := "http"
	if ev.TLSFingerprint != "" {
		scheme = "https"
	}
	for _, item := range il.Items {
		name, ok := item.Value.(string)
		if !ok {
			return "", fmt.Errorf("invalid covered component")
		}
		id := "\"" + name + "\""
		if key := paramString(item.Params, "key"); key != "" {
			id += ";key=\"" + key + "\""
		}
		var v string
		switch name {
		case "@authority":
			v = host
			hasTarget = true
		case "@target-uri":
			v = scheme + "://" + host + uri
			hasTarget = true
		case "@path":
			v = strings.SplitN(uri, "?", 2)[0]
		case "@query":
			if i := strings.IndexByte(uri, '?'); i >= 0 {
				v = uri[i:]
			}
		case "@method":
			v = ev.Method
		case "signature-agent":
			v = origin
		default:
			v = header(ev.Headers, name)
			if v == "" || strings.HasPrefix(name, "@") {
				return "", fmt.Errorf("signature covers %q, which is not recorded", name)
			}
		}
		fmt.Fprintf(&b, "%s: %s\n", id, v)
	}
	if !hasTarget {
		return "", fmt.Errorf("signature covers no request target")
	}
	params, err := httpsfv.Marshal(httpsfv.List{il})
	if err != nil {
		return "", err
	}
	fmt.Fprintf(&b, "\"@signature-params\": %s", params)
	return b.String(), nil
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Nbf int64  `json:"nbf"`
	Exp int64  `json:"exp"`
}

func (w *WebBotAuth) fetch(ctx context.Context, origin string) directory {
	dir := directory{keys: map[string]ed25519.PublicKey{}, fetched: time.Now()}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/.well-known/http-message-signatures-directory", nil)
	if err != nil {
		dir.err = err
		return dir
	}
	resp, err := w.client.Do(req)
	if err != nil {
		dir.err = fmt.Errorf("%w: %v", ErrDirectoryUnavailable, err)
		return dir
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		dir.err = fmt.Errorf("%w: directory answered %s", ErrDirectoryUnavailable, resp.Status)
		return dir
	}
	var body struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&body); err != nil {
		dir.err = fmt.Errorf("%w: %v", ErrDirectoryUnavailable, err)
		return dir
	}
	now := time.Now().Unix()
	for i, k := range body.Keys {
		if i >= 32 {
			break
		}
		if k.Kty != "OKP" || k.Crv != "Ed25519" || (k.Nbf != 0 && now < k.Nbf) || (k.Exp != 0 && now > k.Exp) {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			continue
		}
		dir.keys[Thumbprint(x)] = ed25519.PublicKey(x)
	}
	return dir
}
