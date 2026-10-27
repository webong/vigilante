// Package tap provides non-blocking network middleware that copies incoming
// packets and HTTP/TCP streams into a bounded ring-buffer channel for the
// vigilante correlator and agent pipeline without stalling primary traffic.
package tap

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/webong/vigilante/internal/agent"
	"github.com/webong/vigilante/internal/redact"
)

// Mirror is the minimal seam a host application needs to embed Vigilante in
// its own HTTP stack: it observes (clones) each request into the mirror queue
// while letting next handle the real traffic untouched.
type Mirror interface {
	Observe(*http.Request)
}

// mirrorQueue adapts *MirrorQueue to the Mirror interface.
type mirrorQueue struct{ q *MirrorQueue }

func (m mirrorQueue) Observe(r *http.Request) {
	PreviewRequest(m.q, r, "", "")
}

// NewMirror wraps an existing http.Handler so every request is non-blockingly
// cloned into queue before being served by next. Use this to embed Vigilante
// in-process in any Go service:
//
//	http.Handle("/", tap.NewMirror(myHandler, queue, "app:8080", "app:8080"))
func NewMirror(next http.Handler, queue *MirrorQueue, listenAddr, targetAddr string) http.Handler {
	return HTTPMiddleware(next, queue, listenAddr, targetAddr)
}

// NewMirrorGate is NewMirror with policy enforcement (deny -> 403, block ->
// mirror + 403).
func NewMirrorGate(next http.Handler, queue *MirrorQueue, listenAddr, targetAddr string, gate PolicyGate) http.Handler {
	return HTTPMiddlewareGate(next, queue, listenAddr, targetAddr, gate)
}

// NewMirrorQueueAdapter returns a Mirror that feeds the given queue.
func NewMirrorQueueAdapter(queue *MirrorQueue) Mirror {
	return mirrorQueue{q: queue}
}

const DefaultMaxPreviewBytes = 1024

// PolicyGate evaluates a request and returns "allow", "deny", or "block".
// It is satisfied by a closure over *policy.Engine (see cmd/vigilante).
type PolicyGate func(*http.Request) string

var sensitiveHeaders = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"set-cookie":          true,
	"x-api-key":           true,
	"proxy-authorization": true,
}

// MirrorQueue is a non-blocking bounded ring-buffer dispatcher. If the agent
// pipeline experiences backpressure, MirrorQueue drops mirrored copies and
// increments a counter so production traffic never blocks.
type MirrorQueue struct {
	ch      chan agent.PacketEvent
	dropped atomic.Uint64
	queued  atomic.Uint64
	// sampleRate in [0,1]; 1 mirrors everything. A negative value means
	// "mirror everything" (unset). Uses atomic float bits for lock-free reads.
	sampleRate atomic.Uint64 // math.Float64bits, 0 = unset (treat as 1.0)
	sampledOut atomic.Uint64
}

// NewMirrorQueue allocates a bounded asynchronous packet mirror queue.
func NewMirrorQueue(capacity int) *MirrorQueue {
	if capacity <= 0 {
		capacity = 256
	}
	return &MirrorQueue{
		ch: make(chan agent.PacketEvent, capacity),
	}
}

// SetSampleRate configures what fraction [0,1] of mirrored events are enqueued.
// Values <= 0 disable sampling (mirror everything); values >= 1 mirror all.
// Sampling is best-effort and lock-free; it never affects primary traffic.
func (q *MirrorQueue) SetSampleRate(rate float64) {
	if rate <= 0 {
		q.sampleRate.Store(math.Float64bits(0)) // 0 => no sampling
		return
	}
	if rate > 1 {
		rate = 1
	}
	q.sampleRate.Store(math.Float64bits(rate))
}

// shouldSample reports whether the current event passes the sample filter.
func (q *MirrorQueue) shouldSample() bool {
	rate := math.Float64frombits(q.sampleRate.Load())
	if rate <= 0 || rate >= 1 {
		return true
	}
	return rand.Float64() < rate
}

// Enqueue attempts to copy an event into the mirror pipeline without blocking.
// Returns true if queued, or false if dropped due to backpressure or sampling.
func (q *MirrorQueue) Enqueue(ev agent.PacketEvent) bool {
	if !q.shouldSample() {
		q.sampledOut.Add(1)
		return false
	}
	select {
	case q.ch <- ev:
		q.queued.Add(1)
		return true
	default:
		q.dropped.Add(1)
		return false
	}
}

// Events returns the read-only channel of mirrored PacketEvents.
func (q *MirrorQueue) Events() <-chan agent.PacketEvent {
	return q.ch
}

// Stats returns the total queued and dropped packet counts.
func (q *MirrorQueue) Stats() (queued, dropped uint64) {
	return q.queued.Load(), q.dropped.Load()
}

// SampledOut returns how many events were skipped by the sample filter.
func (q *MirrorQueue) SampledOut() uint64 { return q.sampledOut.Load() }

// Drain runs worker goroutines that consume mirrored events and pass them to fn.
func (q *MirrorQueue) Drain(ctx context.Context, workers int, fn func(context.Context, agent.PacketEvent)) {
	if workers <= 0 {
		workers = 2
	}
	for i := 0; i < workers; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case ev, ok := <-q.ch:
					if !ok {
						return
					}
					fn(ctx, ev)
				}
			}
		}()
	}
}

// HTTPMiddleware wraps an http.Handler, cloning request metadata and a bounded
// body preview into the MirrorQueue while forwarding the untouched request to
// next. When a PolicyGate is provided, deny verdicts return 403 before
// forwarding and block verdicts still mirror (so the correlator sees them).
func HTTPMiddleware(next http.Handler, queue *MirrorQueue, listenAddr, targetAddr string) http.Handler {
	return HTTPMiddlewareGate(next, queue, listenAddr, targetAddr, nil)
}

// HTTPMiddlewareGate is HTTPMiddleware with policy enforcement.
func HTTPMiddlewareGate(next http.Handler, queue *MirrorQueue, listenAddr, targetAddr string, gate PolicyGate) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gate != nil {
			switch gate(r) {
			case "deny":
				http.Error(w, "forbidden by policy", http.StatusForbidden)
				return
			case "block":
				// Mirror first (agent triage sees the offending request), then
				// reject; the block itself is enforced by the caller via the
				// correlator's verdict path.
				PreviewRequest(queue, r, listenAddr, targetAddr)
				http.Error(w, "blocked by policy", http.StatusForbidden)
				return
			}
		}
		PreviewRequest(queue, r, listenAddr, targetAddr)
		next.ServeHTTP(w, r)
	})
}

// PreviewRequest clones request metadata and a bounded body preview into queue
// and restores the body so the real handler is unaffected. It is the shared
// observation primitive used by HTTPMiddleware and by external ingress
// adapters (e.g. an external gateway) that forward traffic themselves.
func PreviewRequest(queue *MirrorQueue, r *http.Request, listenAddr, targetAddr string) {
	var preview string
	var totalBytes int

	if r.Body != nil {
		buf, err := io.ReadAll(io.LimitReader(r.Body, DefaultMaxPreviewBytes))
		if err == nil && len(buf) > 0 {
			preview = string(buf)
			totalBytes = len(buf)
			r.Body = &teeReadCloser{
				Reader: io.MultiReader(bytes.NewReader(buf), r.Body),
				Closer: r.Body,
			}
		}
	}

	headers := make(map[string]string, len(r.Header))
	for k, vals := range r.Header {
		lower := strings.ToLower(k)
		if sensitiveHeaders[lower] {
			headers[k] = "[REDACTED]"
			continue
		}
		headers[k] = strings.Join(vals, ", ")
	}

	ev := agent.PacketEvent{
		Timestamp:      time.Now().UTC(),
		Protocol:       "http",
		SrcAddr:        r.RemoteAddr,
		DstAddr:        listenAddr,
		TargetAddr:     targetAddr,
		Method:         r.Method,
		Path:           r.URL.Path,             // path only (no query)
		Headers:        headers,                // sensitive headers already [REDACTED]
		PayloadPreview: redact.String(preview), // scrub secrets from body preview
		PayloadBytes:   totalBytes,
	}
	// Scrub secrets from the query string while preserving its structure.
	if q := r.URL.RawQuery; q != "" {
		ev.Path += "?" + redact.Query(q)
	}
	queue.Enqueue(ev)
}

// NewHTTPReverseProxyTap creates a reverse-proxy HTTP handler that forwards
// traffic to targetURL while cloning every request into queue.
func NewHTTPReverseProxyTap(targetURL *url.URL, queue *MirrorQueue, listenAddr string) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	return HTTPMiddleware(proxy, queue, listenAddr, targetURL.Host)
}

// ProxyTCPConn copies a bidirectional TCP connection to targetAddr while teeing
// ingress samples into queue. It applies a PolicyGate to the connection's
// source address (deny/block before forwarding), redacts the payload preview,
// and — when continuous sampling is on — keeps teeing periodic chunks rather
// than only the first packet.
func ProxyTCPConn(ctx context.Context, clientConn net.Conn, listenAddr, targetAddr string, queue *MirrorQueue, gate TCPGate) error {
	defer clientConn.Close()

	// Policy gate on the source address before touching the upstream.
	if gate != nil {
		srcIP := hostOnly(clientConn.RemoteAddr().String())
		switch gate(srcIP) {
		case "deny":
			return fmt.Errorf("policy denied tcp connection from %s", srcIP)
		case "block":
			// Mirror the attempt for triage, then refuse to forward.
			enqueueTCP(queue, listenAddr, targetAddr, clientConn.RemoteAddr().String(), nil, 0)
			return fmt.Errorf("policy blocked tcp connection from %s", srcIP)
		}
	}

	dialer := net.Dialer{Timeout: 5 * time.Second}
	upstreamConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return err
	}
	defer upstreamConn.Close()

	// Tee the first ingress chunk for the agent without delaying stream bytes.
	sampleBuf := make([]byte, DefaultMaxPreviewBytes)
	_ = clientConn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	n, readErr := clientConn.Read(sampleBuf)
	_ = clientConn.SetReadDeadline(time.Time{})

	if n > 0 {
		enqueueTCP(queue, listenAddr, targetAddr, clientConn.RemoteAddr().String(), sampleBuf[:n], n)
		if _, err := upstreamConn.Write(sampleBuf[:n]); err != nil {
			return err
		}
	} else if readErr != nil && !isTimeout(readErr) && readErr != io.EOF {
		return readErr
	}

	// client->upstream: keep a low-rate rolling tee so long-lived connections
	// (databases, streams) are observed beyond the first packet.
	done := make(chan struct{}, 2)
	go func() {
		buf := make([]byte, 32<<10)
		var sinceSample time.Duration
		for {
			nr, rerr := clientConn.Read(buf)
			if nr > 0 {
				if _, werr := upstreamConn.Write(buf[:nr]); werr != nil {
					break
				}
				sinceSample += time.Duration(nr)
				// Roughly every 64 KiB, emit another redacted sample.
				if sinceSample >= 64<<10 {
					enqueueTCP(queue, listenAddr, targetAddr, clientConn.RemoteAddr().String(), buf[:nr], nr)
					sinceSample = 0
				}
			}
			if rerr != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(clientConn, upstreamConn)
		done <- struct{}{}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return nil
	}
}

// TCPGate evaluates a source IP and returns "allow", "deny", or "block".
type TCPGate func(srcIP string) string

// enqueueTCP builds and enqueues a TCP PacketEvent with payload redaction.
func enqueueTCP(queue *MirrorQueue, listenAddr, targetAddr, remoteAddr string, payload []byte, n int) {
	if queue == nil {
		return
	}
	var preview string
	if n > 0 {
		preview = redact.String(string(payload))
	}
	queue.Enqueue(agent.PacketEvent{
		Timestamp:      time.Now().UTC(),
		Protocol:       "tcp",
		SrcAddr:        remoteAddr,
		DstAddr:        listenAddr,
		TargetAddr:     targetAddr,
		PayloadPreview: preview,
		PayloadBytes:   n,
	})
}

// hostOnly strips the port from an addr, leaving the IP.
func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

type teeReadCloser struct {
	io.Reader
	io.Closer
}

func isTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return false
}
