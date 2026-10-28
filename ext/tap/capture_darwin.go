//go:build darwin

package tap

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/webong/vigilante/ext/agent"
)

// darwinCapture uses the system tcpdump (ships with macOS, no cgo) to observe
// traffic and parses its line output into PacketEvents. macOS has no
// AF_PACKET; opening /dev/bpf directly would require the BPF ioctl interface.
// Requires root (tcpdump needs elevated capture).
type darwinCapture struct {
	cmd   *exec.Cmd
	lines chan string
	done  chan struct{}
	opts  PassiveOptions
}

// Matches e.g. "IP 10.0.0.1.5555 > 10.0.0.2.8080: Flags [S], ...".
var tcpdumpLineRe = regexp.MustCompile(`\bIP\s+([0-9a-fA-F:.]+)\.(\d+)\s+>\s+([0-9a-fA-F:.]+)\.(\d+):`)

func newPassiveCapture(opts PassiveOptions) (passiveCapture, error) {
	iface := opts.Iface
	if iface == "" {
		iface = "any"
	}
	args := []string{"-i", iface, "-n", "-l", "-q"}
	if len(opts.Ports) > 0 {
		for i, p := range opts.Ports {
			if i > 0 {
				args = append(args, "or")
			}
			args = append(args, "port", strconv.Itoa(p))
		}
	}
	cmd := exec.Command("tcpdump", args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("passive sensor: tcpdump stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("passive sensor: start tcpdump (need root): %w", err)
	}
	c := &darwinCapture{cmd: cmd, lines: make(chan string, 1024), done: make(chan struct{}), opts: opts}
	go func() {
		defer close(c.lines)
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 65536), 65536)
		for sc.Scan() {
			select {
			case c.lines <- sc.Text():
			case <-c.done:
				return
			}
		}
	}()
	return c, nil
}

// ReadEvent returns the next event parsed from a tcpdump line.
func (c *darwinCapture) ReadEvent(ctx context.Context) (agent.PacketEvent, bool, error) {
	select {
	case <-ctx.Done():
		return agent.PacketEvent{}, false, ctx.Err()
	case line, ok := <-c.lines:
		if !ok {
			return agent.PacketEvent{}, false, fmt.Errorf("tcpdump exited")
		}
		ev, ok := parseTcpdumpLine(line, c.opts.SnapLen)
		return ev, ok, nil
	}
}

func (c *darwinCapture) Close() error {
	close(c.done)
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
		_ = c.cmd.Wait()
	}
	return nil
}

// parseTcpdumpLine extracts a PacketEvent from a tcpdump text line.
func parseTcpdumpLine(line string, snapLen int) (agent.PacketEvent, bool) {
	m := tcpdumpLineRe.FindStringSubmatch(line)
	if m == nil {
		return agent.PacketEvent{}, false
	}
	srcHost, srcPort, dstHost, dstPort := m[1], m[2], m[3], m[4]

	protocol := "tcp"
	if strings.Contains(line, "UDP") {
		protocol = "udp"
	}
	var payload string
	if snapLen > 0 && len(payload) > snapLen {
		payload = payload[:snapLen]
	}

	// Normalize host (strip any trailing .port artifact from IPv6 split).
	srcHost = strings.TrimSuffix(srcHost, "."+srcPort)
	dstHost = strings.TrimSuffix(dstHost, "."+dstPort)

	ev := agent.PacketEvent{
		Timestamp:      time.Now().UTC(),
		Protocol:       protocol,
		SrcAddr:        net.JoinHostPort(srcHost, srcPort),
		DstAddr:        net.JoinHostPort(dstHost, dstPort),
		TargetAddr:     net.JoinHostPort(dstHost, dstPort),
		PayloadPreview: payload,
		PayloadBytes:   len(payload),
	}
	ev.Redact()
	return ev, true
}
