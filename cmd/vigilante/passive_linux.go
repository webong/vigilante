//go:build linux

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/webong/vigilante/ext/agent"
	"github.com/webong/vigilante/ext/obs"
	"github.com/webong/vigilante/ext/tap"
	"github.com/webong/vigilante/internal/alert"
	"github.com/webong/vigilante/internal/correlator"
)

// runPassiveMode starts the AF_PACKET passive sensor: it observes traffic on an
// interface (no forwarding, no listener) and dispatches captured flows to the
// agent pipeline. Requires root/CAP_NET_RAW. Status/obs are served on a sidecar.
func runPassiveMode(ctx context.Context, out io.Writer, corr *correlator.Correlator, iface, portsCSV string, queueSize int, sampleRate float64, alertStore *alert.Store, obsB *obs.Bridge, obsM func(http.ResponseWriter)) error {
	if iface == "" {
		return fmt.Errorf("-mode passive requires -passive-iface (e.g. eth0)")
	}
	var ports []int
	for _, p := range strings.Split(portsCSV, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return fmt.Errorf("invalid port %q: %w", p, err)
		}
		ports = append(ports, n)
	}

	queue := tap.NewMirrorQueue(queueSize)
	queue.SetSampleRate(sampleRate)
	registerQueue(queue)
	queue.Drain(ctx, 2, func(ctx context.Context, ev agent.PacketEvent) {
		_, _ = corr.ProcessPacket(ctx, ev)
	})

	sensor, err := tap.NewPassiveSensor(tap.PassiveOptions{Iface: iface, Ports: ports}, queue)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "[vigilante] passive sensor active on %s (observe-only, ports=%v) — no forwarding, CAP_NET_RAW required\n", iface, ports)

	// Status/obs sidecar so /healthz, /metrics, /obs are reachable.
	adminAddr := adminAddrFor("127.0.0.1:0")
	go serveTCPAdmin(ctx, out, adminAddr, queue, alertStatsOf(alertStore), obsB, obsM)

	return sensor.Run(ctx)
}
