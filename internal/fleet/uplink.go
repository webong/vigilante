package fleet

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/webong/vigilante/internal/block"
	"github.com/webong/vigilante/internal/decision"
	"github.com/webong/vigilante/internal/flow"
	"github.com/webong/vigilante/internal/history"
)

// UplinkOptions configures a sensor's non-blocking batch uplink and decision
// snapshot poller (ADR 0004 §3, §4).
type UplinkOptions struct {
	// ServerURL is the central Vigilante server base URL (https://... or loopback http://...).
	ServerURL string
	// SensorKey is the vg_-prefixed sensor authentication key.
	SensorKey string
	// Insecure allows a plain-HTTP ServerURL on a non-loopback host.
	Insecure bool
	// Remote is the sensor's secondary decision.Set populated from GET /v1/decisions.
	Remote *decision.Set
	// Local is the sensor's local decision.Set. When Enforcer is set, an IP
	// removed from Remote is only unblocked in the host firewall if Local does
	// not also block it.
	Local *decision.Set
	// Enforcer optionally reconciles IP-scoped fleet block decisions into the
	// sensor's local host firewall (iptables/nft/log).
	Enforcer *block.Enforcer
	// BufferSize is the bounded queue capacity before incoming items are dropped (default 1024).
	BufferSize int
	// BatchSize is the maximum number of items per POST /v1/ingest batch (default 100).
	BatchSize int
	// MaxBacklog caps how many events are retained across failed uploads (default 500).
	MaxBacklog int
	// FlushInterval is the maximum time between batch uploads (default 2s).
	FlushInterval time.Duration
	// PollInterval is how often GET /v1/decisions is polled (default 5s).
	PollInterval time.Duration
	// Client is an optional HTTP client (default 10s timeout).
	Client *http.Client
	// OnError is an optional callback invoked when an upload or poll fails.
	OnError func(error)
}

// Uplink is a flow.Sink that batches triaged flows and outbound egress records
// to a central Vigilante server while polling its decision snapshot into a
// remote decision.Set.
type Uplink struct {
	baseURL       string
	sensorKey     string
	remote        *decision.Set
	local         *decision.Set
	enforcer      *block.Enforcer
	batchSize     int
	maxBacklog    int
	flushInterval time.Duration
	pollInterval  time.Duration
	client        *http.Client
	onError       func(error)

	eventsCh chan flow.Event
	egressCh chan history.Egress

	dropped      atomic.Uint64
	pendingDrops atomic.Uint64

	mu            sync.Mutex
	backlogEvents []flow.Event
	backlogEgress []history.Egress
	failures      int
	nextRetry     time.Time
	etag          string
	enforcedIPs   map[string]struct{}

	stopOnce sync.Once
	stopCh   chan struct{}
	wg       sync.WaitGroup
}

// NewUplink validates options and returns a ready Uplink. Call Start to run
// the background flush and poll loops.
func NewUplink(opts UplinkOptions) (*Uplink, error) {
	u, err := ValidateServerURL(opts.ServerURL, opts.Insecure)
	if err != nil {
		return nil, err
	}
	if _, err := HashKey(opts.SensorKey); err != nil {
		return nil, err
	}
	bufSize := opts.BufferSize
	if bufSize <= 0 {
		bufSize = 1024
	}
	batchSize := opts.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}
	if batchSize > MaxBatchItems {
		batchSize = MaxBatchItems
	}
	maxBacklog := opts.MaxBacklog
	if maxBacklog <= 0 {
		maxBacklog = 500
	}
	flushInt := opts.FlushInterval
	if flushInt <= 0 {
		flushInt = 2 * time.Second
	}
	pollInt := opts.PollInterval
	if pollInt <= 0 {
		pollInt = 5 * time.Second
	}
	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Uplink{
		baseURL:       strings.TrimRight(u.String(), "/"),
		sensorKey:     strings.TrimSpace(opts.SensorKey),
		remote:        opts.Remote,
		local:         opts.Local,
		enforcer:      opts.Enforcer,
		batchSize:     batchSize,
		maxBacklog:    maxBacklog,
		flushInterval: flushInt,
		pollInterval:  pollInt,
		client:        client,
		onError:       opts.OnError,
		eventsCh:      make(chan flow.Event, bufSize),
		egressCh:      make(chan history.Egress, bufSize),
		enforcedIPs:   map[string]struct{}{},
		stopCh:        make(chan struct{}),
	}, nil
}

// Ingest implements flow.Sink. It never blocks; when the buffer is full the
// event is dropped and counted so the server can display loss per sensor.
func (u *Uplink) Ingest(_ context.Context, ev flow.Event) error {
	if u == nil {
		return nil
	}
	select {
	case u.eventsCh <- ev:
	default:
		u.dropped.Add(1)
		u.pendingDrops.Add(1)
	}
	return nil
}

// RecordEgress enqueues an outbound TCP observation without blocking.
func (u *Uplink) RecordEgress(eg history.Egress) {
	if u == nil {
		return
	}
	select {
	case u.egressCh <- eg:
	default:
		u.dropped.Add(1)
		u.pendingDrops.Add(1)
	}
}

// Dropped returns the total number of events/egress records dropped by this
// sensor due to buffer or backlog overflow.
func (u *Uplink) Dropped() uint64 {
	if u == nil {
		return 0
	}
	return u.dropped.Load()
}

// Start launches the background batch uploader and decision poller tied to ctx.
func (u *Uplink) Start(ctx context.Context) {
	if u == nil {
		return
	}
	// Perform an initial decision poll immediately so enforcement starts fresh.
	if err := u.PollOnce(ctx); err != nil && u.onError != nil {
		u.onError(err)
	}
	u.wg.Add(2)
	go u.runFlusher(ctx)
	go u.runPoller(ctx)
}

// Close stops background loops and performs a final best-effort flush using ctx.
func (u *Uplink) Close(ctx context.Context) error {
	if u == nil {
		return nil
	}
	u.stopOnce.Do(func() { close(u.stopCh) })
	u.wg.Wait()
	return u.Flush(ctx)
}

func (u *Uplink) runFlusher(ctx context.Context) {
	defer u.wg.Done()
	ticker := time.NewTicker(u.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-u.stopCh:
			return
		case ev := <-u.eventsCh:
			u.appendEvent(ev)
			if u.pendingLen() >= u.batchSize {
				if err := u.Flush(ctx); err != nil && u.onError != nil {
					u.onError(err)
				}
			}
		case eg := <-u.egressCh:
			u.appendEgress(eg)
			if u.pendingLen() >= u.batchSize {
				if err := u.Flush(ctx); err != nil && u.onError != nil {
					u.onError(err)
				}
			}
		case <-ticker.C:
			if err := u.Flush(ctx); err != nil && u.onError != nil {
				u.onError(err)
			}
		}
	}
}

func (u *Uplink) runPoller(ctx context.Context) {
	defer u.wg.Done()
	ticker := time.NewTicker(u.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-u.stopCh:
			return
		case <-ticker.C:
			if err := u.PollOnce(ctx); err != nil && u.onError != nil {
				u.onError(err)
			}
		}
	}
}

func (u *Uplink) drainChannels() {
	for {
		select {
		case ev := <-u.eventsCh:
			u.appendEvent(ev)
		default:
			goto drainEgress
		}
	}
drainEgress:
	for {
		select {
		case eg := <-u.egressCh:
			u.appendEgress(eg)
		default:
			return
		}
	}
}

func (u *Uplink) appendEvent(ev flow.Event) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.backlogEvents = append(u.backlogEvents, ev)
	if over := len(u.backlogEvents) - u.maxBacklog; over > 0 {
		// Keep the newest events up to maxBacklog.
		u.backlogEvents = append([]flow.Event(nil), u.backlogEvents[over:]...)
		u.dropped.Add(uint64(over))
		u.pendingDrops.Add(uint64(over))
	}
}

func (u *Uplink) appendEgress(eg history.Egress) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.backlogEgress = append(u.backlogEgress, eg)
	if over := len(u.backlogEgress) - u.maxBacklog; over > 0 {
		u.backlogEgress = append([]history.Egress(nil), u.backlogEgress[over:]...)
		u.dropped.Add(uint64(over))
		u.pendingDrops.Add(uint64(over))
	}
}

func (u *Uplink) pendingLen() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.backlogEvents) + len(u.backlogEgress)
}

// Flush drains buffered events and uploads them in gzip-compressed batches to
// POST /v1/ingest. On upload failure, the newest events up to MaxBacklog are
// retained and retried with exponential backoff.
func (u *Uplink) Flush(ctx context.Context) error {
	if u == nil {
		return nil
	}
	u.drainChannels()

	u.mu.Lock()
	if !u.nextRetry.IsZero() && time.Now().Before(u.nextRetry) {
		u.mu.Unlock()
		return nil
	}
	u.mu.Unlock()

	for {
		u.mu.Lock()
		if len(u.backlogEvents) == 0 && len(u.backlogEgress) == 0 && u.pendingDrops.Load() == 0 {
			u.mu.Unlock()
			return nil
		}
		evCount := min(len(u.backlogEvents), u.batchSize)
		egCount := min(len(u.backlogEgress), u.batchSize-evCount)
		events := append([]flow.Event(nil), u.backlogEvents[:evCount]...)
		egress := append([]history.Egress(nil), u.backlogEgress[:egCount]...)
		u.backlogEvents = u.backlogEvents[evCount:]
		u.backlogEgress = u.backlogEgress[egCount:]
		drops := u.pendingDrops.Swap(0)
		u.mu.Unlock()

		batch := Batch{
			Events:  events,
			Egress:  egress,
			Dropped: drops,
		}
		if err := u.sendBatch(ctx, batch); err != nil {
			// Restore unsent items to the front of the backlog, capping at maxBacklog.
			u.mu.Lock()
			u.backlogEvents = append(events, u.backlogEvents...)
			if over := len(u.backlogEvents) - u.maxBacklog; over > 0 {
				u.backlogEvents = append([]flow.Event(nil), u.backlogEvents[over:]...)
				u.dropped.Add(uint64(over))
				drops += uint64(over)
			}
			u.backlogEgress = append(egress, u.backlogEgress...)
			if over := len(u.backlogEgress) - u.maxBacklog; over > 0 {
				u.backlogEgress = append([]history.Egress(nil), u.backlogEgress[over:]...)
				u.dropped.Add(uint64(over))
				drops += uint64(over)
			}
			u.pendingDrops.Add(drops)
			u.failures++
			backoff := min(time.Duration(1<<min(u.failures-1, 5))*500*time.Millisecond, 30*time.Second)
			u.nextRetry = time.Now().Add(backoff)
			u.mu.Unlock()
			return err
		}

		u.mu.Lock()
		u.failures = 0
		u.nextRetry = time.Time{}
		more := len(u.backlogEvents) > 0 || len(u.backlogEgress) > 0
		u.mu.Unlock()
		if !more {
			return nil
		}
	}
}

func (u *Uplink) sendBatch(ctx context.Context, batch Batch) error {
	raw, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(raw); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.baseURL+"/v1/ingest", &buf)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+u.sensorKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")

	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fleet: ingest HTTP %d", resp.StatusCode)
	}
	return nil
}

// PollOnce polls GET /v1/decisions once using If-None-Match and updates the
// remote decision.Set on 200 OK.
func (u *Uplink) PollOnce(ctx context.Context) error {
	if u == nil || u.remote == nil {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.baseURL+"/v1/decisions", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+u.sensorKey)
	req.Header.Set("Accept-Encoding", "gzip")
	u.mu.Lock()
	etag := u.etag
	u.mu.Unlock()
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := u.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		u.reconcileFirewall(ctx)
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return fmt.Errorf("fleet: decisions HTTP %d", resp.StatusCode)
	}

	var reader io.Reader = resp.Body
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return err
		}
		defer gz.Close()
		reader = gz
	}
	body, err := io.ReadAll(io.LimitReader(reader, MaxDecompressedBytes))
	if err != nil {
		return err
	}
	var dec Decisions
	if err := json.Unmarshal(body, &dec); err != nil {
		return err
	}
	u.remote.Replace(dec.Entries)
	newETag := resp.Header.Get("ETag")
	if newETag == "" {
		newETag = dec.ETag
	}
	u.mu.Lock()
	u.etag = newETag
	u.mu.Unlock()
	u.reconcileFirewall(ctx)
	return nil
}

// reconcileFirewall programs IP-scoped fleet block/deny decisions into the
// sensor's local block.Enforcer and removes expired or revoked fleet blocks
// unless the IP is still blocked in the local decision set.
func (u *Uplink) reconcileFirewall(ctx context.Context) {
	if u == nil || u.enforcer == nil || u.remote == nil {
		return
	}
	_ = u.remote.Sweep()
	active := u.remote.Active()
	desired := make(map[string]string, len(active))
	for _, e := range active {
		if e.Scope == decision.ScopeIP && (e.Action == "block" || e.Action == "deny") {
			if ip := decision.NormalizeIP(e.Target); ip != "" {
				reason := e.Reason
				if reason == "" {
					reason = e.ID
				}
				desired[ip] = reason
			}
		}
	}

	u.mu.Lock()
	var toAdd []struct {
		ip     string
		reason string
	}
	for ip, reason := range desired {
		if _, ok := u.enforcedIPs[ip]; !ok {
			toAdd = append(toAdd, struct {
				ip     string
				reason string
			}{ip: ip, reason: reason})
		}
	}
	var toRemove []string
	for ip := range u.enforcedIPs {
		if _, ok := desired[ip]; !ok {
			toRemove = append(toRemove, ip)
		}
	}
	u.mu.Unlock()

	for _, item := range toAdd {
		parsed := net.ParseIP(item.ip)
		if parsed == nil || parsed.IsLoopback() || parsed.IsUnspecified() {
			continue
		}
		if err := u.enforcer.Block(ctx, parsed, "fleet:"+item.reason); err == nil {
			u.mu.Lock()
			u.enforcedIPs[item.ip] = struct{}{}
			u.mu.Unlock()
		}
	}

	for _, ip := range toRemove {
		if u.locallyBlocked(ip) {
			u.mu.Lock()
			delete(u.enforcedIPs, ip)
			u.mu.Unlock()
			continue
		}
		parsed := net.ParseIP(ip)
		if parsed != nil {
			_ = u.enforcer.Unblock(ctx, parsed)
		}
		u.mu.Lock()
		delete(u.enforcedIPs, ip)
		u.mu.Unlock()
	}
}

func (u *Uplink) locallyBlocked(ip string) bool {
	if u.local == nil {
		return false
	}
	e, ok := u.local.Lookup(ip, "", "")
	return ok && (e.Action == "block" || e.Action == "deny")
}

// Ensure URL import is used for callers inspecting parsed URLs.
var _ = (*url.URL)(nil)
