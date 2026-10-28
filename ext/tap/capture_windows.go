//go:build windows

package tap

import (
	"context"
	"fmt"

	"github.com/webong/vigilante/ext/agent"
)

// windowsCapture is the Windows passive-capture backend.
//
// Windows packet capture requires a kernel driver: npcap (or the legacy
// WinPcap). Go bindings for it are cgo-based and require installing the npcap
// runtime + SDK, which is a heavyweight, non-portable dependency. Until a
// driver-backed backend is wired in, Windows reports a clear error so the
// sensor posture degrades honestly rather than silently capturing nothing.
//
// To implement: link against npcap's Packet.dll (via cgo or a syscall shim to
// Packet.dll's PacketReceivePacket), open an adapter with
// PacketOpenAdapter, apply a BPF filter, and parse frames with DecodeFrame —
// the same shared decode path used by Linux. The passiveCapture seam is
// already the right place for it.
type windowsCapture struct{}

func newPassiveCapture(opts PassiveOptions) (passiveCapture, error) {
	return nil, fmt.Errorf("passive sensor: Windows capture requires the npcap driver (Packet.dll); not yet wired in — build on Linux (AF_PACKET) or macOS (tcpdump) for passive mode")
}

func (c *windowsCapture) ReadEvent(ctx context.Context) (agent.PacketEvent, bool, error) {
	return agent.PacketEvent{}, false, fmt.Errorf("windows passive capture unavailable")
}

func (c *windowsCapture) Close() error { return nil }
