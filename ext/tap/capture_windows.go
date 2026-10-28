//go:build windows

package tap

import (
	"context"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/webong/vigilante/ext/agent"
)

// windowsCapture uses npcap's Packet.dll (the standard Windows packet driver,
// from https://npcap.com) loaded via pure-Go syscall — no cgo. It opens an
// adapter and reads raw frames with
// PacketReceivePacket, feeding the shared DecodeFrame path.
//
// Requires the npcap driver + Packet.dll installed (npcap.com), and the process
// usually needs to run as Administrator for capture.
var (
	packetDLL           = windows.NewLazyDLL("Packet.dll")
	procOpenAdapter     = packetDLL.NewProc("PacketOpenAdapter")
	procCloseAdapter    = packetDLL.NewProc("PacketCloseAdapter")
	procSetSnapLen      = packetDLL.NewProc("PacketSetHwSnapLen")
	procReceivePacket   = packetDLL.NewProc("PacketReceivePacket")
	procGetAdapterNames = packetDLL.NewProc("PacketGetAdapterNames")
)

// packetHeader mirrors npcap's PACKET_HEADER (minimal layout for receive).
type packetHeader struct {
	Alert        uint8
	Presentation uint8
	DataLength   uint32
	Snaplen      uint32
	// Followed by a data buffer in the npcap API; we use PacketReceivePacket
	// with an overlapped buffer allocated after the header.
}

type windowsCapture struct {
	adapter uintptr
	snapLen int
	buf     []byte
	closed  bool
}

func newPassiveCapture(opts PassiveOptions) (passiveCapture, error) {
	if err := packetDLL.Load(); err != nil {
		return nil, fmt.Errorf("passive sensor: npcap Packet.dll not found (install from npcap.com): %w", err)
	}
	iface := opts.Iface
	if iface == "" {
		// Pick the first adapter when none specified.
		name, err := firstAdapterName()
		if err != nil {
			return nil, err
		}
		iface = name
	}
	// npcap adapter names are UTF-16, often prefixed with \Device\NPF_.
	adapterName, err := utf16Ptr(iface)
	if err != nil {
		return nil, err
	}
	adapter, _, _ := procOpenAdapter.Call(uintptr(unsafe.Pointer(adapterName)))
	if adapter == 0 {
		return nil, fmt.Errorf("passive sensor: PacketOpenAdapter(%q) failed (npcap installed? run as Admin?)", iface)
	}
	c := &windowsCapture{adapter: adapter, snapLen: opts.SnapLen, buf: make([]byte, 65536)}
	if opts.SnapLen > 0 {
		procSetSnapLen.Call(adapter, uintptr(uint32(opts.SnapLen)))
	}
	return c, nil
}

// ReadEvent receives one packet and decodes it via the shared DecodeFrame.
func (c *windowsCapture) ReadEvent(ctx context.Context) (agent.PacketEvent, bool, error) {
	if c.closed {
		return agent.PacketEvent{}, false, fmt.Errorf("capture closed")
	}
	// PacketReceivePacket blocks; honor ctx with a short timeout via a
	// non-blocking design: we issue the call and rely on the caller's ctx
	// cancellation to close the adapter (Close is called on ctx done by Run).
	// To avoid a hard block, use PacketReceivePacket with a small buffer; npcap
	// returns quickly when no packets. We add a select-style guard by checking
	// ctx before each call.
	if ctx.Err() != nil {
		return agent.PacketEvent{}, false, ctx.Err()
	}

	// Build a PACKET_HEADER + data buffer as npcap expects: header then data.
	type pktHdr struct {
		Alert        uint8
		Presentation uint8
		DataLength   uint32
		Snaplen      uint32
	}
	// Allocate header + buffer contiguously.
	const hdrSize = int(unsafe.Sizeof(pktHdr{}))
	total := hdrSize + len(c.buf)
	raw := make([]byte, total)
	hdr := (*pktHdr)(unsafe.Pointer(&raw[0]))
	hdr.Snaplen = uint32(c.snapLen)

	// overlapped = 0 (synchronous receive).
	recv, _, _ := procReceivePacket.Call(c.adapter, uintptr(unsafe.Pointer(hdr)), 0)
	if recv == 0 {
		// No packet (or error); brief sleep to avoid a busy spin.
		select {
		case <-ctx.Done():
			return agent.PacketEvent{}, false, ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
		return agent.PacketEvent{}, false, nil
	}
	dataLen := int(hdr.DataLength)
	if dataLen <= 0 || dataLen > len(c.buf) {
		return agent.PacketEvent{}, false, nil
	}
	frame := raw[hdrSize : hdrSize+dataLen]
	ev, ok := DecodeFrame(frame, c.snapLen)
	return ev, ok, nil
}

func (c *windowsCapture) Close() error {
	if !c.closed && c.adapter != 0 {
		procCloseAdapter.Call(c.adapter)
		c.closed = true
	}
	return nil
}

// firstAdapterName returns the first adapter name reported by npcap.
func firstAdapterName() (string, error) {
	buf := make([]uint16, 4096)
	ret, _, _ := procGetAdapterNames.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)*2))
	if ret == 0 {
		return "", fmt.Errorf("passive sensor: PacketGetAdapterNames returned no adapters (npcap installed?)")
	}
	// Names are a double-null-separated UTF-16 list.
	s := windows.UTF16ToString(buf)
	if s == "" {
		return "", fmt.Errorf("passive sensor: no adapters reported")
	}
	return s, nil
}

// utf16Ptr converts a Go string to a *uint16 for npcap calls.
func utf16Ptr(s string) (*uint16, error) {
	u, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return nil, fmt.Errorf("passive sensor: adapter name encoding: %w", err)
	}
	return u, nil
}
