package tap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	credential "github.com/webong/ext/res/system/credential/client"
	"github.com/webong/vigilante/ext/agent"
	"github.com/webong/vigilante/internal/redact"
)

// DecoderOptions configures a local observation producer, never a packet verdict provider.
// Custom commands own capture/decryption and emit PacketEvent JSONL on stdout.
type DecoderOptions struct {
	Command          string
	Args             []string
	Interface        string
	CaptureFile      string
	KeyLogFile       string
	KeyLogCredential string
}

func (o DecoderOptions) command() (string, []string, error) {
	if o.Command != "" {
		if o.KeyLogFile != "" || o.CaptureFile != "" {
			return "", nil, fmt.Errorf("custom decoder owns capture and key configuration; use decoder arguments")
		}
		return o.Command, o.Args, nil
	}
	if (o.Interface == "") == (o.CaptureFile == "") {
		return "", nil, fmt.Errorf("TShark requires exactly one interface or capture file")
	}
	args := []string{"-n", "-l", "-T", "pdml", "-o", "tcp.desegment_tcp_streams:TRUE", "-o", "tls.desegment_ssl_records:TRUE", "-o", "tls.desegment_ssl_application_data:TRUE"}
	if o.CaptureFile != "" {
		args = append(args, "-r", o.CaptureFile)
	} else {
		args = append(args, "-i", o.Interface)
	}
	if o.KeyLogFile != "" {
		f, err := os.Open(o.KeyLogFile)
		if err != nil {
			return "", nil, fmt.Errorf("open TLS key log: %w", err)
		}
		_ = f.Close()
		args = append(args, "-o", "tls.keylog_file:"+o.KeyLogFile)
	}
	args = append(args, "-Y", "http.request or http2 or http3 or tls.handshake.type == 1")
	return "tshark", args, nil
}

// RunDecoder runs the local decoder until EOF or cancellation. Raw output and
// stderr never reach the agent or logs. Each record is bounded and redacted.
func RunDecoder(ctx context.Context, o DecoderOptions, emit func(agent.PacketEvent)) error {
	if o.KeyLogCredential != "" {
		if o.KeyLogFile != "" || o.Command != "" {
			return fmt.Errorf("key-log credential cannot be combined with a key-log file or custom decoder")
		}
		space, item, ok := strings.Cut(o.KeyLogCredential, ":")
		if !ok || item == "" {
			return fmt.Errorf("key-log credential must be space:item")
		}
		lookup, cancel := context.WithTimeout(ctx, 10*time.Second)
		secret, err := credential.GetDeclared(lookup, space, item)
		cancel()
		if err != nil {
			return fmt.Errorf("TLS key-log credential lookup failed")
		}
		defer clear(secret)
		f, err := os.CreateTemp("", "vigilante-tls-keys-*")
		if err != nil {
			return err
		}
		defer os.Remove(f.Name())
		_, err = f.Write(secret)
		clear(secret)
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		o.KeyLogFile = f.Name()
	}
	name, args, err := o.command()
	if err != nil {
		return err
	}
	if o.Command == "" {
		if err := checkTShark(ctx); err != nil {
			return err
		}
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(child, name, args...)
	cmd.WaitDelay = time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start decoder: %w", err)
	}
	stopRead := context.AfterFunc(child, func() { _ = stdout.Close() })
	defer stopRead()
	scan := bufio.NewScanner(stdout)
	scan.Buffer(make([]byte, 4096), 1<<20)
	if o.Command == "" {
		scan.Buffer(make([]byte, 4096), 4<<20)
		scan.Split(splitPDML)
	}
	var parseErr error
	for scan.Scan() {
		var ev agent.PacketEvent
		var events []agent.PacketEvent
		if o.Command != "" {
			err = json.Unmarshal(scan.Bytes(), &ev)
			events = []agent.PacketEvent{ev}
		} else {
			events, err = parseTShark(scan.Bytes())
		}
		if err != nil {
			parseErr = fmt.Errorf("decoder emitted invalid record")
			cancel()
			break
		}
		for _, ev := range events {
			if ev.SrcAddr == "" || ev.DstAddr == "" {
				continue
			}
			if ev.Timestamp.IsZero() {
				ev.Timestamp = time.Now().UTC()
			}
			ev.ObservationSource = "external-decoder"
			if o.Command == "" {
				ev.ObservationSource = "tshark"
			}
			ev.Visibility = "metadata"
			if ev.Method != "" || ev.PayloadPreview != "" {
				ev.Visibility = "application-plaintext"
			}
			ev.Headers = redact.Headers(ev.Headers)
			ev.Redact()
			if len(ev.PayloadPreview) > 4096 {
				ev.PayloadPreview = ev.PayloadPreview[:4096]
				ev.PreviewComplete = false
			}
			emit(ev)
		}
	}
	if scan.Err() != nil {
		parseErr = fmt.Errorf("decoder record exceeds limit or output read failed")
		cancel()
	}
	waitErr := cmd.Wait()
	if ctx.Err() != nil {
		return nil
	}
	if parseErr != nil {
		return parseErr
	}
	if waitErr != nil {
		return fmt.Errorf("decoder exited unsuccessfully")
	}
	return nil
}

// Require a dissector that identifies HTTP/3 streams explicitly. Older versions
// flatten QUIC and HTTP/3 into sibling trees, which cannot be paired reliably.
func checkTShark(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "tshark", "-G", "fields")
	cmd.WaitDelay = time.Second
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = io.Discard
	if err = cmd.Start(); err != nil {
		return fmt.Errorf("start TShark: %w", err)
	}
	scan := bufio.NewScanner(stdout)
	scan.Buffer(make([]byte, 4096), 1<<20)
	method, stream := false, false
	for scan.Scan() {
		fields := strings.Split(scan.Text(), "\t")
		if len(fields) < 3 {
			continue
		}
		switch fields[2] {
		case "http3.headers.method":
			method = true
		case "http3.frame_streamid", "http3.stream.id":
			stream = true
		}
	}
	if scan.Err() != nil {
		cancel()
	}
	if err := cmd.Wait(); err != nil || scan.Err() != nil {
		return fmt.Errorf("TShark capability discovery failed")
	}
	if !method || !stream {
		return fmt.Errorf("TShark requires HTTP/3 header and stream-ID fields; install TShark 4.6 or newer with HTTP/3 support")
	}
	return nil
}

// splitPDML bounds each XML packet, including packets with many multiplexed streams.
func splitPDML(data []byte, atEOF bool) (int, []byte, error) {
	start := bytes.Index(data, []byte("<packet>"))
	if start < 0 {
		if atEOF {
			return len(data), nil, nil
		}
		return 0, nil, nil
	}
	end := bytes.Index(data[start:], []byte("</packet>"))
	if end < 0 {
		if atEOF {
			return 0, nil, fmt.Errorf("truncated PDML packet")
		}
		return 0, nil, nil
	}
	end += start + len("</packet>")
	return end, data[start:end], nil
}

type pdmlNode struct {
	Name     string     `xml:"name,attr"`
	Show     string     `xml:"show,attr"`
	Value    string     `xml:"value,attr"`
	Children []pdmlNode `xml:",any"`
}

func (n pdmlNode) field(name string) string {
	if n.Name == name {
		return n.Show
	}
	for _, c := range n.Children {
		if v := c.field(name); v != "" {
			return v
		}
	}
	return ""
}
func (n pdmlNode) nodes(name string) []pdmlNode {
	if n.Name == name {
		return []pdmlNode{n}
	}
	var out []pdmlNode
	for _, c := range n.Children {
		out = append(out, c.nodes(name)...)
	}
	return out
}
func parseTShark(data []byte) ([]agent.PacketEvent, error) {
	var packet pdmlNode
	if err := xml.Unmarshal(data, &packet); err != nil {
		return nil, err
	}
	first := func(names ...string) string {
		for _, n := range names {
			if v := packet.field(n); v != "" {
				return v
			}
		}
		return ""
	}
	addr := func(host, port string) string {
		if host == "" {
			return ""
		}
		return net.JoinHostPort(host, port)
	}
	base := agent.PacketEvent{SrcAddr: addr(first("ip.src", "ipv6.src"), first("tcp.srcport", "udp.srcport")), DstAddr: addr(first("ip.dst", "ipv6.dst"), first("tcp.dstport", "udp.dstport"))}
	base.TargetAddr = base.DstAddr
	if seconds, err := strconv.ParseFloat(first("frame.time_epoch"), 64); err == nil {
		base.Timestamp = time.Unix(0, int64(seconds*1e9)).UTC()
	}
	var events []agent.PacketEvent
	for _, spec := range []struct{ protocol, group, method, path, host, body, stream string }{
		{"http", "http", "http.request.method", "http.request.uri", "http.host", "http.file_data", ""},
		{"http2", "http2.stream", "http2.headers.method", "http2.headers.path", "http2.headers.authority", "http2.data.data", "http2.streamid"},
		{"http3", "http3", "http3.headers.method", "http3.headers.path", "http3.headers.authority", "http3.data", "http3.frame_streamid"},
	} {
		for _, group := range packet.nodes(spec.group) {
			// Modern HTTP/3 exposes individual frames, each carrying its own stream ID.
			groups := []pdmlNode{group}
			if spec.protocol == "http3" {
				if frames := group.nodes("http3.frame"); len(frames) > 0 {
					groups = frames
				}
			}
			for _, g := range groups {
				ev := base
				ev.Protocol = spec.protocol
				ev.Method = g.field(spec.method)
				ev.Path = g.field(spec.path)
				ev.Headers = map[string]string{}
				if host := g.field(spec.host); host != "" {
					ev.Headers["Host"] = host
				}
				if ua := g.field(spec.protocol + ".headers.user_agent"); ua != "" {
					ev.Headers["User-Agent"] = ua
				}
				if spec.protocol == "http" {
					ev.Headers["User-Agent"] = g.field("http.user_agent")
				}
				if spec.stream != "" {
					ev.StreamID = g.field(spec.stream)
				}
				if spec.protocol == "http3" && ev.StreamID == "" {
					ev.StreamID = group.field("http3.stream.id")
				}
				connection := first("tcp.stream")
				if spec.protocol == "http3" {
					connection = first("quic.connection.number")
				}
				ev.FlowID = spec.protocol + ":" + connection + ":" + ev.SrcAddr + ">" + ev.DstAddr
				for _, body := range g.nodes(spec.body) {
					decoded, err := hex.DecodeString(strings.ReplaceAll(body.Value, ":", ""))
					if err != nil {
						return nil, fmt.Errorf("invalid body bytes")
					}
					ev.PayloadPreview += string(decoded)
				}
				ev.PayloadBytes = len(ev.PayloadPreview)
				// DATA observations retain stream identity; they are not complete messages.
				if ev.Method != "" || ev.PayloadBytes > 0 {
					events = append(events, ev)
				}
			}
		}
	}
	if sni := first("tls.handshake.extensions_server_name"); sni != "" {
		ev := base
		ev.Protocol = "tls"
		ev.Headers = map[string]string{"TLS-SNI": sni}
		events = append(events, ev)
	}
	return events, nil
}
