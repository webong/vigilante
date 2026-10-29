//go:build linux

package tap

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"time"

	nfqueue "github.com/florianl/go-nfqueue/v2"
)

// RunInline returns immediate packet verdicts for an operator-configured
// netfilter queue. Agent analysis happens asynchronously after observation.
// Only IP-level rules are meaningful here; HTTP is not reconstructed.
func RunInline(ctx context.Context, number uint16, q *MirrorQueue, gate PolicyGate, selections ...Protocols) error {
	var selected Protocols
	if len(selections) > 0 {
		selected = selections[0]
	}
	assembler := &IPAssembler{}
	streams := newStreamPreview()
	nf, err := nfqueue.Open(&nfqueue.Config{NfQueue: number, MaxPacketLen: 65535, MaxQueueLen: 1024, Copymode: nfqueue.NfQnlCopyPacket, WriteTimeout: 100 * time.Millisecond})
	if err != nil {
		return fmt.Errorf("open NFQUEUE (requires CAP_NET_ADMIN): %w", err)
	}
	defer nf.Close()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	failures := make(chan error, 1)
	fail := func(err error) int {
		select {
		case failures <- err:
		default:
		}
		cancel()
		return 1
	}
	err = nf.RegisterWithErrorFunc(ctx, func(a nfqueue.Attribute) int {
		if a.PacketID == nil {
			return fail(fmt.Errorf("NFQUEUE packet missing ID"))
		}
		verdict := nfqueue.NfAccept
		if a.Payload != nil {
			packet := *a.Payload
			src, _, proto, valid := IPIdentity(packet)
			if valid && selected.Includes(proto) && gate != nil {
				action := gate(&http.Request{Method: "CONNECT", URL: &url.URL{Path: "/"}, RemoteAddr: src, Header: make(http.Header)})
				if action == "deny" || action == "block" {
					verdict = nfqueue.NfDrop
				}
			}
			if !valid || !selected.Includes(proto) {
				return verdictResult(nf, *a.PacketID, verdict, fail)
			}
			packet, valid = assembler.Add(packet)
			if !valid {
				return verdictResult(nf, *a.PacketID, verdict, fail)
			}
			if len(packet) > 0 {
				frame := make([]byte, 14+len(packet))
				switch packet[0] >> 4 {
				case 4:
					frame[12] = 8
				case 6:
					frame[12] = 0x86
					frame[13] = 0xdd
				}
				copy(frame[14:], packet)
				if ev, ok := DecodeFrame(frame, 1514); ok {
					q.Enqueue(streams.Add(ev))
				}
			}
		}
		if err := nf.SetVerdict(*a.PacketID, verdict); err != nil {
			return fail(err)
		}
		return 0
	}, fail)
	if err != nil {
		return err
	}
	select {
	case err := <-failures:
		return err
	case <-ctx.Done():
		select {
		case err := <-failures:
			return err
		default:
			return nil
		}
	}
}

func verdictResult(nf *nfqueue.Nfqueue, id uint32, verdict int, fail func(error) int) int {
	if err := nf.SetVerdict(id, verdict); err != nil {
		return fail(err)
	}
	return 0
}
