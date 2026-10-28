package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RemoteOptions configures a model-independent HTTP agent. The remote service
// receives a self-contained EnrichedEnvelope. It may acknowledge delivery
// without a verdict or return a Verdict for host-side handling.
type RemoteOptions struct {
	URL        string
	Token      string
	Timeout    time.Duration
	HTTPClient *http.Client
	OnError    func(error)
}

func NewRemoteHandler(opts RemoteOptions) (Handler, error) {
	u, err := url.Parse(opts.URL)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return nil, fmt.Errorf("remote agent: invalid URL")
	}
	if u.Scheme != "https" {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if u.Scheme != "http" || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
			return nil, fmt.Errorf("remote agent: HTTPS is required outside loopback")
		}
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: opts.Timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}
	}
	return func(ctx context.Context, env EnrichedEnvelope) (Verdict, error) {
		payload, err := json.Marshal(env)
		if err != nil {
			return remoteError(opts, err)
		}
		if len(payload) > 4<<20 {
			return remoteError(opts, fmt.Errorf("remote agent: context exceeds 4 MiB"))
		}
		reqCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, opts.URL, bytes.NewReader(payload))
		if err != nil {
			return remoteError(opts, err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-Vigilante-Contract", "vigilante.agent/v1")
		if opts.Token != "" {
			req.Header.Set("Authorization", "Bearer "+opts.Token)
		}
		resp, err := client.Do(req)
		if err != nil {
			return remoteError(opts, fmt.Errorf("remote agent request: %w", err))
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return remoteError(opts, fmt.Errorf("remote agent returned HTTP %d", resp.StatusCode))
		}
		if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusNoContent {
			return Verdict{}, nil
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
		if err != nil || len(body) > 1<<20 {
			return remoteError(opts, fmt.Errorf("remote agent response exceeds 1 MiB or could not be read"))
		}
		if len(bytes.TrimSpace(body)) == 0 {
			return Verdict{}, nil
		}
		var ack map[string]json.RawMessage
		if err := json.Unmarshal(body, &ack); err == nil && ack != nil {
			_, severity := ack["severity"]
			_, action := ack["action"]
			_, summary := ack["summary"]
			if !severity && !action && !summary {
				return Verdict{}, nil
			}
		}
		verdict, err := ParseVerdictOutput(body)
		if err != nil {
			return remoteError(opts, err)
		}
		if verdict.FlowID != "" && verdict.FlowID != env.Event.FlowID {
			return remoteError(opts, fmt.Errorf("remote agent returned a different flow_id"))
		}
		if verdict.FlowID == "" {
			verdict.FlowID = env.Event.FlowID
		}
		if !validSeverity(verdict.Severity) || strings.TrimSpace(verdict.Action) == "" || strings.TrimSpace(verdict.Summary) == "" {
			return remoteError(opts, fmt.Errorf("remote agent returned an incomplete verdict"))
		}
		return verdict, nil
	}, nil
}

func remoteError(opts RemoteOptions, err error) (Verdict, error) {
	if opts.OnError != nil {
		opts.OnError(err)
	}
	return Verdict{}, err
}

func validSeverity(s string) bool {
	switch s {
	case "info", "low", "medium", "high", "critical":
		return true
	default:
		return false
	}
}
