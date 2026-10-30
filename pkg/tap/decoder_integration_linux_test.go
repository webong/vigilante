//go:build linux

package tap

import (
	"bufio"
	"context"
	"crypto/tls"
	"github.com/quic-go/quic-go/http3"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/webong/vigilante/ext/agent"
)

func TestLinuxTLSDecode(t *testing.T) {
	if os.Getenv("VIGILANTE_LINUX_INTEGRATION") != "1" {
		t.Skip("requires isolated Linux capture tools")
	}
	for _, mode := range []string{"tls12", "tls13", "http2", "http3"} {
		t.Run(mode, func(t *testing.T) {
			version := uint16(tls.VersionTLS13)
			if mode == "tls12" {
				version = tls.VersionTLS12
			}
			dir := t.TempDir()
			pcap := filepath.Join(dir, "traffic.pcap")
			keys := filepath.Join(dir, "keys.log")
			keyFile, err := os.OpenFile(keys, os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer keyFile.Close()
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
			srv.TLS = &tls.Config{MinVersion: version, MaxVersion: version, KeyLogWriter: keyFile}
			srv.EnableHTTP2 = mode == "http2"
			srv.StartTLS()
			defer srv.Close()
			client, url := srv.Client(), srv.URL
			if mode == "http3" {
				conn, err := net.ListenPacket("udp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				h3 := &http3.Server{TLSConfig: srv.TLS.Clone(), Handler: srv.Config.Handler}
				go h3.Serve(conn)
				defer h3.Close()
				transport := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
				defer transport.Close()
				client = &http.Client{Transport: transport, Timeout: 5 * time.Second}
				url = "https://" + conn.LocalAddr().String()
			}

			capture := exec.Command("tcpdump", "-i", "lo", "-U", "-w", pcap, "tcp or udp")
			stderr, err := capture.StderrPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err = capture.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if capture.ProcessState == nil {
					capture.Process.Kill()
					capture.Wait()
				}
			}()
			ready := make(chan struct{})
			go func() {
				s := bufio.NewScanner(stderr)
				for s.Scan() {
					if strings.Contains(s.Text(), "listening on") {
						close(ready)
						return
					}
				}
			}()
			select {
			case <-ready:
			case <-time.After(5 * time.Second):
				t.Fatal("capture did not start")
			}
			resp, err := client.Post(url+"/inspection?password=supersecretvalue", "text/plain", strings.NewReader("inspection-body"))
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if mode == "http2" || mode == "http3" {
				resp, err = client.Post(url+"/second", "text/plain", strings.NewReader("second-body"))
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			// libpcap delivers buffered packets on a timed capture tick.
			time.Sleep(1500 * time.Millisecond)
			capture.Process.Signal(os.Interrupt)
			if err := capture.Wait(); err != nil {
				t.Fatal(err)
			}
			var withKeys, withoutKeys []agent.PacketEvent
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			err = RunDecoder(ctx, DecoderOptions{CaptureFile: pcap, KeyLogFile: keys}, func(ev agent.PacketEvent) { withKeys = append(withKeys, ev) })
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, ev := range withKeys {
				if ev.Method == "POST" && strings.HasPrefix(ev.Path, "/inspection") {
					found = true
					if (mode == "http2" || mode == "http3") && (ev.Protocol != mode || ev.StreamID == "") {
						t.Fatalf("missing protocol/stream: %+v", ev)
					}
					if mode != "http2" && mode != "http3" && ev.PayloadPreview != "inspection-body" {
						t.Fatalf("decoded body = %q", ev.PayloadPreview)
					}
					if strings.Contains(ev.Path, "supersecretvalue") {
						t.Fatal("plaintext secret leaked")
					}
				}
			}
			if mode == "http2" || mode == "http3" {
				requests, bodies := map[string]string{}, map[string]string{}
				flow := ""
				for _, ev := range withKeys {
					if ev.Protocol == mode && ev.Method == "POST" {
						requests[ev.StreamID] = ev.Path
						if flow != "" && flow != ev.FlowID {
							t.Fatal("requests did not reuse connection")
						}
						flow = ev.FlowID
					}
				}
				for _, ev := range withKeys {
					if ev.FlowID == flow {
						bodies[ev.StreamID] += ev.PayloadPreview
					}
				}
				if len(requests) != 2 {
					t.Fatalf("missing distinct streams: %+v", withKeys)
				}
				for stream, path := range requests {
					want := "inspection-body"
					if path == "/second" {
						want = "second-body"
					}
					if stream == "" || bodies[stream] != want {
						t.Fatalf("incorrect stream body: %q %q", stream, bodies[stream])
					}
				}
			}
			if !found {
				t.Fatalf("no decrypted request: %+v", withKeys)
			}
			err = RunDecoder(ctx, DecoderOptions{CaptureFile: pcap}, func(ev agent.PacketEvent) { withoutKeys = append(withoutKeys, ev) })
			if err != nil {
				t.Fatal(err)
			}
			for _, ev := range withoutKeys {
				if ev.Method != "" {
					t.Fatal("plaintext appeared without keys")
				}
			}
		})
	}
}
