//go:build linux

package tap

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"

	"github.com/webong/vigilante/ext/agent"
)

// linuxCapture implements passiveCapture with an AF_PACKET raw socket
// (requires CAP_NET_RAW / root).
type linuxCapture struct {
	fd      int
	ifIndex int
	opts    PassiveOptions
}

func newPassiveCapture(opts PassiveOptions) (passiveCapture, error) {
	if opts.Iface == "" {
		return nil, fmt.Errorf("passive sensor: interface is required on Linux (e.g. eth0)")
	}
	iface, err := net.InterfaceByName(opts.Iface)
	if err != nil {
		return nil, fmt.Errorf("passive sensor: interface %q: %w", opts.Iface, err)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return nil, fmt.Errorf("passive sensor: AF_PACKET socket (need root/CAP_NET_RAW): %w", err)
	}
	c := &linuxCapture{fd: fd, ifIndex: iface.Index, opts: opts}
	if opts.Promiscuous {
		_ = c.setPromisc()
	}
	sa := &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: iface.Index}
	if err := syscall.Bind(fd, sa); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("passive sensor: bind %s: %w", opts.Iface, err)
	}
	return c, nil
}

func (c *linuxCapture) ReadEvent(ctx context.Context) (agent.PacketEvent, bool, error) {
	buf := make([]byte, 65536)
	tv := syscall.NsecToTimeval((250 * time.Millisecond).Nanoseconds())
	_ = syscall.SetsockoptTimeval(c.fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv)
	n, _, err := syscall.Recvfrom(c.fd, buf, 0)
	if err != nil {
		if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
			return agent.PacketEvent{}, false, nil
		}
		return agent.PacketEvent{}, false, err
	}
	if n <= 0 {
		return agent.PacketEvent{}, false, nil
	}
	ev, ok := DecodeFrame(buf[:n], c.opts.SnapLen)
	return ev, ok, nil
}

func (c *linuxCapture) Close() error {
	if c.fd >= 0 {
		err := syscall.Close(c.fd)
		c.fd = -1
		return err
	}
	return nil
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}

func (c *linuxCapture) setPromisc() error {
	type packetMreq struct {
		Ifindex int32
		Type    uint16
		Alen    uint16
		Address [8]byte
	}
	const (
		solPacket       = 263
		packetAddMember = 1
		packetMrPromisc = 1
	)
	mr := packetMreq{Ifindex: int32(c.ifIndex), Type: packetMrPromisc}
	_, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(c.fd), uintptr(solPacket),
		uintptr(packetAddMember), uintptr(unsafe.Pointer(&mr)), unsafe.Sizeof(mr), 0)
	if e != 0 {
		return e
	}
	return nil
}
