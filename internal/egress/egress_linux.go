//go:build linux

// Package egress records outbound TCP connections without a C toolchain.
package egress

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/webong/vigilante/internal/history"
)

const (
	recordSize  = 56
	flushWindow = 10 * time.Second
)

type Options struct{ Loopback bool }
type flowKey struct {
	comm string
	uid  uint32
	dst  netip.Addr
	port uint16
}
type flow struct {
	pid   uint32
	count int
}

func Run(ctx context.Context, opts Options, emit func(history.Egress)) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("egress memlock: %w", err)
	}
	events, err := ebpf.NewMap(&ebpf.MapSpec{Name: "vigilante_egress", Type: ebpf.RingBuf, MaxEntries: 1 << 20})
	if err != nil {
		return err
	}
	defer events.Close()
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "vigilante_connect", Type: ebpf.TracePoint, License: "Dual MIT/GPL", Instructions: program(events)})
	if err != nil {
		return fmt.Errorf("egress load: %w", err)
	}
	defer prog.Close()
	tp, err := link.Tracepoint("sock", "inet_sock_set_state", prog, nil)
	if err != nil {
		return fmt.Errorf("egress attach: %w", err)
	}
	defer tp.Close()
	rd, err := ringbuf.NewReader(events)
	if err != nil {
		return err
	}
	go func() { <-ctx.Done(); rd.Close() }()
	flows := map[flowKey]*flow{}
	start := time.Now()
	rd.SetDeadline(start.Add(flushWindow))
	for {
		rec, err := rd.Read()
		switch {
		case errors.Is(err, ringbuf.ErrClosed):
			flush(flows, start, emit)
			return nil
		case errors.Is(err, os.ErrDeadlineExceeded):
		case err != nil:
			return err
		default:
			if k, pid, ok := parse(rec.RawSample, opts); ok {
				f := flows[k]
				if f == nil {
					f = &flow{}
					flows[k] = f
				}
				f.pid = pid
				f.count++
			}
		}
		if now := time.Now(); now.Sub(start) >= flushWindow {
			flush(flows, start, emit)
			clear(flows)
			start = now
			rd.SetDeadline(start.Add(flushWindow))
		}
	}
}
func program(events *ebpf.Map) asm.Instructions {
	i := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1), asm.LoadMem(asm.R2, asm.R6, 20, asm.Word), asm.JNE.Imm(asm.R2, 2, "exit"), asm.LoadMem(asm.R2, asm.R6, 30, asm.Half), asm.JNE.Imm(asm.R2, 6, "exit"), asm.LoadMapPtr(asm.R1, events.FD()), asm.Mov.Imm(asm.R2, recordSize), asm.Mov.Imm(asm.R3, 0), asm.FnRingbufReserve.Call(), asm.JEq.Imm(asm.R0, 0, "exit"), asm.Mov.Reg(asm.R7, asm.R0), asm.FnGetCurrentPidTgid.Call(), asm.StoreMem(asm.R7, 0, asm.R0, asm.DWord), asm.FnGetCurrentUidGid.Call(), asm.StoreMem(asm.R7, 8, asm.R0, asm.DWord), asm.LoadMem(asm.R2, asm.R6, 28, asm.Half), asm.StoreMem(asm.R7, 16, asm.R2, asm.Half), asm.LoadMem(asm.R2, asm.R6, 26, asm.Half), asm.StoreMem(asm.R7, 18, asm.R2, asm.Half), asm.LoadMem(asm.R2, asm.R6, 36, asm.Word), asm.StoreMem(asm.R7, 20, asm.R2, asm.Word)}
	for off := int16(0); off < 16; off += 4 {
		i = append(i, asm.LoadMem(asm.R2, asm.R6, 56+off, asm.Word), asm.StoreMem(asm.R7, 24+off, asm.R2, asm.Word))
	}
	return append(i, asm.Mov.Reg(asm.R1, asm.R7), asm.Add.Imm(asm.R1, 40), asm.Mov.Imm(asm.R2, 16), asm.FnGetCurrentComm.Call(), asm.Mov.Reg(asm.R1, asm.R7), asm.Mov.Imm(asm.R2, 0), asm.FnRingbufSubmit.Call(), asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"), asm.Return())
}
func parse(b []byte, opts Options) (flowKey, uint32, bool) {
	if len(b) < recordSize {
		return flowKey{}, 0, false
	}
	ne := binary.NativeEndian
	pid := uint32(ne.Uint64(b[:8]) >> 32)
	uid := uint32(ne.Uint64(b[8:16]))
	var dst netip.Addr
	switch ne.Uint16(b[16:18]) {
	case 2:
		dst = netip.AddrFrom4([4]byte(b[20:24]))
	case 10:
		dst = netip.AddrFrom16([16]byte(b[24:40])).Unmap()
	default:
		return flowKey{}, 0, false
	}
	if dst.IsLoopback() && !opts.Loopback {
		return flowKey{}, 0, false
	}
	comm := b[40:56]
	n := 0
	for n < len(comm) && comm[n] != 0 {
		n++
	}
	return flowKey{comm: string(comm[:n]), uid: uid, dst: dst, port: ne.Uint16(b[18:20])}, pid, true
}
func flush(flows map[flowKey]*flow, ts time.Time, emit func(history.Egress)) {
	for k, f := range flows {
		emit(history.Egress{TS: ts.UTC(), Comm: k.comm, PID: f.pid, UID: k.uid, DstIP: k.dst.String(), DstPort: k.port, Count: f.count})
	}
}
