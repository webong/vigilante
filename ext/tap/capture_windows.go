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
// adapter, applies an optional port filter, and reads raw frames with
// PacketReceivePacket, feeding the shared DecodeFrame path.
//
// Requires the npcap driver + Packet.dll installed (npcap.com), and the process
// usually needs to run as Administrator for capture.
var (
	packetDLL           = windows.NewLazyDLL("Packet.dll")
	procOpenAdapter     = packetDLL.NewProc("PacketOpenAdapter")
	procCloseAdapter    = packetDLL.NewProc("PacketCloseAdapter")
	procSetSnapLen      = packetDLL.NewProc("PacketSetHwSnapLen")
	procSetBpf          = packetDLL.NewProc("PacketSetBpf")
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

// bpfProgram mirrors the classic-BPF program passed to PacketSetBpf
// (the same bytecode our Linux backend builds).
type bpfProgram struct {
	Len    uint16
	Filter *bpfInsn
}

type bpfInsn struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
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
	if len(opts.Ports) > 0 {
		prog, err := buildWindowsBPF(opts.Ports)
		if err != nil {
			procCloseAdapter.Call(adapter)
			return nil, err
		}
		procSetBpf.Call(adapter, uintptr(unsafe.Pointer(prog)))
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

// buildWindowsBPF builds the same classic-BPF bytecode as the Linux backend
// (port filter) for npcap's PacketSetBpf.
func buildWindowsBPF(ports []int) (*bpfProgram, error) {
	const (
		ldhAbs = 0x28
		ldbAbs = 0x30
		jeqK   = 0x15
		retK   = 0x06
	)
	var f []bpfInsn
	f = append(f, bpfInsn{Code: ldhAbs, K: 12})
	f = append(f, bpfInsn{Code: jeqK, K: 0x0800, Jt: 0, Jf: 1})
	f = append(f, bpfInsn{Code: ldbAbs, K: 23})
	f = append(f, bpfInsn{Code: jeqK, K: 6, Jt: 1, Jf: 0})
	f = append(f, bpfInsn{Code: jeqK, K: 17, Jt: 0, Jf: 1})
	f = append(f, bpfInsn{Code: ldhAbs, K: 34})
	srcJEQ := len(f)
	for range ports {
		f = append(f, bpfInsn{})
	}
	f = append(f, bpfInsn{Code: ldhAbs, K: 36})
	dstJEQ := len(f)
	for range ports {
		f = append(f, bpfInsn{})
	}
	rejectIdx := len(f)
	f = append(f, bpfInsn{Code: retK, K: 0})
	acceptIdx := len(f)
	f = append(f, bpfInsn{Code: retK, K: 0xFFFFFFFF})
	for i := range ports {
		jt := uint8(acceptIdx - (srcJEQ + i) - 1)
		f[srcJEQ+i] = bpfInsn{Code: jeqK, K: uint32(ports[i]), Jt: jt}
	}
	for i := range ports {
		jt := uint8(acceptIdx - (dstJEQ + i) - 1)
		f[dstJEQ+i] = bpfInsn{Code: jeqK, K: uint32(ports[i]), Jt: jt}
	}
	f[1].Jf = uint8(rejectIdx - 2)
	f[4].Jf = uint8(rejectIdx - 4)
	return &bpfProgram{Len: uint16(len(f)), Filter: &f[0]}, nil
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
