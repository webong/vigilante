package tap

import (
	"time"

	"github.com/webong/vigilante/ext/agent"
)

// streamPreview joins consecutive TCP payloads in one direction so an agent can
// inspect markers split across packet boundaries. It is deliberately bounded;
// gaps, truncation, and out-of-order segments start a new preview.
type streamPreview struct {
	flows map[string]streamState
}

type streamState struct {
	next     uint32
	text     string
	seen     time.Time
	complete bool
}

func newStreamPreview() *streamPreview {
	return &streamPreview{flows: make(map[string]streamState)}
}

func (s *streamPreview) Add(ev agent.PacketEvent) agent.PacketEvent {
	if ev.Protocol != "tcp" || ev.PayloadBytes == 0 {
		return ev
	}
	key := ev.SrcAddr + "|" + ev.DstAddr
	now := time.Now()
	if len(s.flows) >= 1024 {
		for key, state := range s.flows {
			if now.Sub(state.seen) > time.Minute {
				delete(s.flows, key)
			}
		}
		if len(s.flows) >= 1024 {
			s.flows = make(map[string]streamState)
		}
	}
	state, ok := s.flows[key]
	if !ok || now.Sub(state.seen) > time.Minute || ev.TCPSequence != state.next || !state.complete || !ev.PreviewComplete {
		state.text = ev.PayloadPreview
	} else {
		state.text += ev.PayloadPreview
		if len(state.text) > 4096 {
			state.text = state.text[len(state.text)-4096:]
		}
	}
	state.next = ev.TCPSequence + uint32(ev.PayloadBytes)
	state.seen = now
	state.complete = ev.PreviewComplete
	ev.PayloadPreview = state.text
	ev.Redact() // catch secrets whose bytes crossed a packet boundary
	state.text = ev.PayloadPreview
	s.flows[key] = state
	return ev
}
