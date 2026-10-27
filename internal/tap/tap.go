// Package tap provides non-blocking network middleware that copies incoming
// packets and HTTP/TCP streams into a bounded ring-buffer channel for the
// vigilante correlator and agent pipeline without stalling primary traffic.
package tap

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/webong/vigilante/internal/agent"
)

const DefaultMaxPreviewBytes = 1024

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

// Enqueue attempts to copy an event into the mirror pipeline without blocking.
// Returns true if queued, or false if dropped due to backpressure.
func (q *MirrorQueue) Enqueue(ev agent.PacketEvent) bool {
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
// body preview into the MirrorQueue while forwarding the untouched request to next.
func HTTPMiddleware(next http.Handler, queue *MirrorQueue, listenAddr, targetAddr string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			Path:           r.URL.RequestURI(),
			Headers:        headers,
			PayloadPreview: preview,
			PayloadBytes:   totalBytes,
		}
		queue.Enqueue(ev)

		next.ServeHTTP(w, r)
	})
}

// NewHTTPReverseProxyTap creates a reverse-proxy HTTP handler that forwards
// traffic to targetURL while cloning every request into queue.
func NewHTTPReverseProxyTap(targetURL *url.URL, queue *MirrorQueue, listenAddr string) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(targetURL)
	return HTTPMiddleware(proxy, queue, listenAddr, targetURL.Host)
}

// ProxyTCPConn copies a bidirectional TCP connection to targetAddr while teeing
// the initial ingress packet sample into queue.
func ProxyTCPConn(ctx context.Context, clientConn net.Conn, listenAddr, targetAddr string, queue *MirrorQueue) error {
	defer clientConn.Close()

	dialer := net.Dialer{Timeout: 5 * time.Second}
	upstreamConn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return err
	}
	defer upstreamConn.Close()

	// Tee the first ingress chunk for the agent without delaying subsequent stream bytes.
	sampleBuf := make([]byte, DefaultMaxPreviewBytes)
	_ = clientConn.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
	n, readErr := clientConn.Read(sampleBuf)
	_ = clientConn.SetReadDeadline(time.Time{})

	if n > 0 {
		queue.Enqueue(agent.PacketEvent{
			Timestamp:      time.Now().UTC(),
			Protocol:       "tcp",
			SrcAddr:        clientConn.RemoteAddr().String(),
			DstAddr:        listenAddr,
			TargetAddr:     targetAddr,
			PayloadPreview: string(sampleBuf[:n]),
			PayloadBytes:   n,
		})
		if _, err := upstreamConn.Write(sampleBuf[:n]); err != nil {
			return err
		}
	} else if readErr != nil && !isTimeout(readErr) && readErr != io.EOF {
		return readErr
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(upstreamConn, clientConn)
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
