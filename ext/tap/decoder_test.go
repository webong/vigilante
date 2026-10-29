package tap

import (
	"bufio"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/webong/vigilante/ext/agent"
)

func TestTSharkMultiplexedStreams(t *testing.T) {
	for _, protocol := range []string{"http2", "http3"} {
		t.Run(protocol, func(t *testing.T) {
			group, id := "http2.stream", "http2.streamid"
			if protocol == "http3" {
				group, id = "http3.frame", "http3.frame_streamid"
			}
			packet := `<packet><proto name="ip"><field name="ip.src" show="192.0.2.1"/><field name="ip.dst" show="192.0.2.2"/></proto><proto name="` + protocol + `">`
			for _, stream := range []string{"0", "4"} {
				packet += `<field name="` + group + `"><field name="` + id + `" show="` + stream + `"/><field name="` + protocol + `.headers.method" show="GET"/><field name="` + protocol + `.headers.path" show="/request-` + stream + `"/></field>`
			}
			packet += `</proto></packet>`
			events, err := parseTShark([]byte(packet))
			if err != nil || len(events) != 2 {
				t.Fatalf("events=%+v err=%v", events, err)
			}
			for i, stream := range []string{"0", "4"} {
				if events[i].StreamID != stream || events[i].Path != "/request-"+stream {
					t.Fatalf("mixed streams: %+v", events)
				}
			}
		})
	}
}

func TestPDMLRecordBounds(t *testing.T) {
	for _, input := range []string{"<pdml><packet>truncated", "<packet>" + strings.Repeat("x", 2048) + "</packet>"} {
		s := bufio.NewScanner(strings.NewReader(input))
		s.Buffer(make([]byte, 64), 1024)
		s.Split(splitPDML)
		for s.Scan() {
		}
		if s.Err() == nil {
			t.Fatal("accepted truncated or oversized packet")
		}
	}
}

func TestDecoderHelper(t *testing.T) {
	if os.Getenv("VIGILANTE_DECODER_HELPER") != "1" {
		return
	}
	if os.Getenv("VIGILANTE_DECODER_HANG") == "1" {
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	os.Stdout.WriteString("{\"src_addr\":\"1.2.3.4:1234\",\"dst_addr\":\"5.6.7.8:443\",\"method\":\"GET\",\"path\":\"/?password=supersecretvalue\",\"headers\":{\"Authorization\":\"Bearer abcdefghijklmnopqrstuvwxyz\"}}\n")
	os.Exit(0)
}

func TestDecoderCancellation(t *testing.T) {
	t.Setenv("VIGILANTE_DECODER_HELPER", "1")
	t.Setenv("VIGILANTE_DECODER_HANG", "1")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- RunDecoder(ctx, DecoderOptions{Command: os.Args[0], Args: []string{"-test.run=^TestDecoderHelper$"}}, func(agent.PacketEvent) {})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("decoder failed to stop")
	}
}

func TestExternalDecoderRedacts(t *testing.T) {
	t.Setenv("VIGILANTE_DECODER_HELPER", "1")
	var events []agent.PacketEvent
	err := RunDecoder(context.Background(), DecoderOptions{Command: os.Args[0], Args: []string{"-test.run=^TestDecoderHelper$"}}, func(ev agent.PacketEvent) { events = append(events, ev) })
	if err != nil || len(events) != 1 {
		t.Fatalf("%v %+v", err, events)
	}
	if events[0].Visibility != "application-plaintext" || events[0].ObservationSource != "external-decoder" {
		t.Fatal(events[0])
	}
	if events[0].Path == "/?password=supersecretvalue" {
		t.Fatal("secret not redacted")
	}
}
