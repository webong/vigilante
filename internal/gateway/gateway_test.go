package gateway

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/webong/vigilante/ext/agent"
)

func TestServerForwardsAndObserves(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "upstream:%s:%s", r.URL.Path, body)
	}))
	defer upstream.Close()

	var mu sync.Mutex
	var seen []agent.PacketEvent
	srv, err := NewServer(Options{
		ListenAddr: "127.0.0.1:0",
		TargetURL:  upstream.URL,
	}, func(_ context.Context, ev agent.PacketEvent) {
		mu.Lock()
		seen = append(seen, ev)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ln, err := newLocalListener()
	if err != nil {
		t.Fatal(err)
	}
	srv.httpSrv.Addr = ln.Addr().String()
	go func() { _ = srv.httpSrv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	base := "http://" + ln.Addr().String()
	resp, err := http.Post(base+"/api/v1/things", "text/plain", io.NopCloser(
		//nolint:errcheck // test
		stringReader("hello")))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if string(out) != "upstream:/api/v1/things:hello" {
		t.Fatalf("forwarded response = %q", out)
	}

	// Health/metrics endpoints must not be forwarded.
	health, err := http.Get(base + "/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = health.Body.Close()
	if health.StatusCode != http.StatusOK {
		t.Fatalf("/health status = %d", health.StatusCode)
	}

	// Wait for the async mirror drain to observe the request.
	deadline := time.Now().Add(2 * time.Second)
	for {
		mu.Lock()
		n := len(seen)
		mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("request was not observed by the mirror queue")
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	ev := seen[0]
	mu.Unlock()
	if ev.Path != "/api/v1/things" || ev.Method != http.MethodPost {
		t.Fatalf("observed event = %+v", ev)
	}
	if ev.PayloadPreview != "hello" {
		t.Fatalf("payload preview = %q", ev.PayloadPreview)
	}
}

func TestParseMode(t *testing.T) {
	for in, want := range map[string]Mode{
		"":          ModeLocal,
		"local":     ModeLocal,
		"embedded":  ModeLocal, // legacy alias
		"Local ":    ModeLocal,
		"external":  ModeExternal,
		"companion": ModeExternal, // legacy alias
	} {
		got, err := ParseMode(in)
		if err != nil || got != want {
			t.Errorf("ParseMode(%q) = %v/%v, want %v", in, got, err, want)
		}
	}
	if _, err := ParseMode("bogus"); err == nil {
		t.Error("expected error for unknown mode")
	}
}

func TestExternalModeForwardsToExistingIngress(t *testing.T) {
	// Stand-in for an already-running ingress/gateway process.
	existing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "existing-gateway:%s", r.URL.Path)
	}))
	defer existing.Close()

	srv, err := NewServer(Options{
		Mode:        ModeExternal,
		ExternalURL: existing.URL,
		// ListenAddr/TargetURL intentionally empty: external owns no listener.
	}, nil)
	if err != nil {
		t.Fatalf("NewServer external: %v", err)
	}
	if srv.Mode() != ModeExternal {
		t.Fatalf("Mode() = %v", srv.Mode())
	}

	ln, err := newLocalListener()
	if err != nil {
		t.Fatal(err)
	}
	srv.httpSrv.Addr = ln.Addr().String()
	go func() { _ = srv.httpSrv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	resp, err := http.Get("http://" + ln.Addr().String() + "/hook")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if string(out) != "existing-gateway:/hook" {
		t.Fatalf("external forwarded to = %q, want the existing ingress", out)
	}
}

func TestExternalModeRequiresEndpoint(t *testing.T) {
	if _, err := NewServer(Options{Mode: ModeExternal}, nil); err == nil {
		t.Fatal("expected error with no external endpoint or target")
	}
}

func TestServerRequiresTarget(t *testing.T) {
	if _, err := NewServer(Options{ListenAddr: ":0"}, nil); err == nil {
		t.Fatal("expected error without target URL")
	}
}

func TestServerPlannerFailOpen(t *testing.T) {
	// Planner is unreachable (closed server): traffic must still be forwarded.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	srv, err := NewServer(Options{
		ListenAddr: "127.0.0.1:0",
		TargetURL:  upstream.URL,
		PlannerURL: "http://127.0.0.1:1", // closed port -> instant refusal
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := newLocalListener()
	if err != nil {
		t.Fatal(err)
	}
	srv.httpSrv.Addr = ln.Addr().String()
	go func() { _ = srv.httpSrv.Serve(ln) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + ln.Addr().String() + "/ping")
	if err != nil {
		t.Fatalf("request with dead planner failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status with dead planner = %d, want 200 (fail-open)", resp.StatusCode)
	}
}

func TestServerTLSTermination(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("secure-ok"))
	}))
	defer upstream.Close()

	srv, err := NewServer(Options{
		ListenAddr:  "127.0.0.1:0",
		TargetURL:   upstream.URL,
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	ln, err := newLocalListener()
	if err != nil {
		t.Fatal(err)
	}
	srv.httpSrv.Addr = ln.Addr().String()
	go func() { _ = srv.httpSrv.ServeTLS(ln, certFile, keyFile) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	pool := x509.NewCertPool()
	pemBytes, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("failed to parse test cert")
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
	}}
	resp, err := client.Get("https://" + ln.Addr().String() + "/ping")
	if err != nil {
		t.Fatalf("https request: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if string(out) != "secure-ok" {
		t.Fatalf("https response = %q", out)
	}
}

func newLocalListener() (net.Listener, error) {
	return net.Listen("tcp", "127.0.0.1:0")
}

type stringReader string

func (s stringReader) Read(p []byte) (int, error) {
	if len(s) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s)
	return n, io.EOF
}

// writeSelfSignedCert generates a short-lived self-signed cert for TLS tests.
func writeSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "vigilante-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:         true,
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	certOut, err := os.Create(certFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		t.Fatal(err)
	}
	_ = certOut.Close()

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}); err != nil {
		t.Fatal(err)
	}
	_ = keyOut.Close()
	return certFile, keyFile
}
