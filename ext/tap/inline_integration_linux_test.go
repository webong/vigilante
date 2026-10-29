//go:build linux

package tap

import (
	"context"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestLinuxNFQUEUE(t *testing.T) {
	if os.Getenv("VIGILANTE_LINUX_INTEGRATION") != "1" {
		t.Skip("requires isolated Linux network namespace and CAP_NET_ADMIN")
	}
	nft := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("nft", args...).CombinedOutput(); err != nil {
			t.Fatalf("nft: %v %s", err, out)
		}
	}
	nft("add", "table", "inet", "vigilante_test")
	defer exec.Command("nft", "delete", "table", "inet", "vigilante_test").Run()
	nft("add", "chain", "inet", "vigilante_test", "output", "{ type filter hook output priority 0; policy accept; }")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- RunInline(ctx, 321, NewMirrorQueue(32), func(r *http.Request) string {
			if r.RemoteAddr == "127.0.0.2" {
				return "deny"
			}
			return "allow"
		})
	}()
	// Poll queue registration before installing interception, with a fixed deadline.
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-done:
			t.Fatalf("queue startup: %v", err)
		default:
		}
		b, _ := os.ReadFile("/proc/net/netfilter/nfnetlink_queue")
		if len(b) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("queue did not register")
		}
		time.Sleep(20 * time.Millisecond)
	}
	nft("add", "rule", "inet", "vigilante_test", "output", "ip", "saddr", "127.0.0.0/8", "ip", "protocol", "icmp", "queue", "num", "321")
	if out, err := exec.Command("ping", "-c", "1", "-W", "1", "127.0.0.1").CombinedOutput(); err != nil {
		t.Fatalf("allowed ping: %v %s", err, out)
	}
	if err := exec.Command("ping", "-I", "127.0.0.2", "-c", "1", "-W", "1", "127.0.0.1").Run(); err == nil {
		t.Fatal("denied ICMP passed")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("queue shutdown hung")
	}
}
