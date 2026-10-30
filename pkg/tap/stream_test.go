package tap

import (
	"strings"
	"testing"

	"github.com/webong/vigilante/ext/agent"
)

func TestStreamPreviewJoinsConsecutivePayloads(t *testing.T) {
	s := newStreamPreview()
	base := agent.PacketEvent{Protocol: "tcp", SrcAddr: "10.0.0.1:1", DstAddr: "10.0.0.2:2", PreviewComplete: true}
	first := base
	first.TCPSequence, first.PayloadPreview, first.PayloadBytes = 100, "../", 3
	s.Add(first)
	second := base
	second.TCPSequence, second.PayloadPreview, second.PayloadBytes = 103, "etc/passwd", 10
	got := s.Add(second)
	if got.PayloadPreview != "../etc/passwd" {
		t.Fatalf("joined preview = %q", got.PayloadPreview)
	}
	third := base
	third.TCPSequence, third.PayloadPreview, third.PayloadBytes = 999, "new", 3
	if got := s.Add(third); got.PayloadPreview != "new" {
		t.Fatalf("gap must reset preview, got %q", got.PayloadPreview)
	}
}

func TestStreamPreviewRedactsAcrossBoundary(t *testing.T) {
	s := newStreamPreview()
	first := agent.PacketEvent{Protocol: "tcp", SrcAddr: "a:1", DstAddr: "b:2", TCPSequence: 1, PayloadPreview: "token=sk-", PayloadBytes: 9, PreviewComplete: true}
	second := first
	second.TCPSequence, second.PayloadPreview, second.PayloadBytes = 10, "abcdefghijklmnop", 16
	s.Add(first)
	got := s.Add(second)
	if strings.Contains(got.PayloadPreview, "sk-abcdefghijklmnop") {
		t.Fatalf("split secret leaked: %q", got.PayloadPreview)
	}
}
