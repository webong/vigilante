//go:build darwin

package tap

import (
	"testing"
)

func TestParseTcpdumpLine(t *testing.T) {
	line := `12:34:56.789012 IP 10.0.0.1.5555 > 10.0.0.2.8080: Flags [S], seq 1, win 65535, length 0`
	ev, ok := parseTcpdumpLine(line, 1514)
	if !ok {
		t.Fatal("parse failed")
	}
	if ev.SrcAddr != "10.0.0.1:5555" || ev.DstAddr != "10.0.0.2:8080" {
		t.Fatalf("addrs = %q -> %q", ev.SrcAddr, ev.DstAddr)
	}
	if ev.Protocol != "tcp" {
		t.Fatalf("protocol = %q", ev.Protocol)
	}
}

func TestParseTcpdumpLineRejectsNonIP(t *testing.T) {
	if _, ok := parseTcpdumpLine("some unrelated output", 1514); ok {
		t.Fatal("non-IP line should be rejected")
	}
}
