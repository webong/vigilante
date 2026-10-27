//go:build !linux

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/webong/vigilante/ext/obs"
	"github.com/webong/vigilante/internal/alert"
	"github.com/webong/vigilante/internal/correlator"
)

// runPassiveMode is unavailable on non-linux hosts (AF_PACKET is Linux-only).
func runPassiveMode(ctx context.Context, out io.Writer, corr *correlator.Correlator, iface, portsCSV string, queueSize int, sampleRate float64, alertStore *alert.Store, obsB *obs.Bridge, obsM func(http.ResponseWriter)) error {
	return fmt.Errorf("-mode passive is only supported on Linux (AF_PACKET); build on linux to capture passively")
}
