// Package remote is the open-ended action executor: it speaks HTTP to any
// consumer that exposes an API, so a detection can disable a Cloudflare WAF
// rule, add an address to a load balancer's deny list, open a ticket, page an
// on-call engineer, or quarantine a workload without changing the core.
//
// URLs and the request body are templates. Substitutions:
//
//	{target}  the decision target (URL-escaped in URLs, raw in bodies)
//	{scope}   ip | cidr | actor | fingerprint | global
//	{action}  the action id
//	{reason}  the decision reason
//	{ttl}     the requested duration in seconds
//	{ref}     the revert reference (revert URLs only)
//
// A create response may return {"id": ...} or {"revert_ref": ...}; the host
// stores that handle and passes it back as {ref} when the decision expires or
// is reverted by an operator.
package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/webong/vigilante/internal/action"
	"github.com/webong/vigilante/internal/decision"
)

// Options configures a remote executor. ID, Label and URL are required.
type Options struct {
	ID          string
	Label       string
	Description string
	Scopes      []decision.Scope

	// URL and Method describe the create call (method defaults to POST).
	URL    string
	Method string
	// BodyTemplate is the JSON body to send. Defaults to a generic envelope
	// describing the decision.
	BodyTemplate string

	// RevertURL and RevertMethod describe the undo call. RevertMethod defaults
	// to DELETE. When RevertURL is empty the capability is not reversible.
	RevertURL    string
	RevertMethod string

	Headers map[string]string
	Timeout time.Duration
	Client  *http.Client

	DefaultTTL           time.Duration
	MaxTTL               time.Duration
	RequiresConfirmation bool
	Destructive          bool
}

// Executor implements action.Executor over HTTP.
type Executor struct {
	opts   Options
	client *http.Client
}

// New validates opts and returns an executor.
func New(opts Options) (*Executor, error) {
	if strings.TrimSpace(opts.ID) == "" {
		return nil, fmt.Errorf("remote action: id is required")
	}
	if strings.TrimSpace(opts.URL) == "" {
		return nil, fmt.Errorf("remote action %q: url is required", opts.ID)
	}
	if opts.Method == "" {
		opts.Method = http.MethodPost
	}
	if opts.RevertMethod == "" {
		opts.RevertMethod = http.MethodDelete
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: opts.Timeout}
	}
	if opts.Label == "" {
		opts.Label = opts.ID
	}
	if len(opts.Scopes) == 0 {
		opts.Scopes = []decision.Scope{decision.ScopeIP}
	}
	return &Executor{opts: opts, client: opts.Client}, nil
}

// Capability implements action.Executor.
func (e *Executor) Capability() action.Capability {
	return action.Capability{
		ID:          e.opts.ID,
		Label:       e.opts.Label,
		Description: e.opts.Description,
		Scopes:      e.opts.Scopes,
		DefaultTTL:  e.opts.DefaultTTL,
		MaxTTL:      e.opts.MaxTTL,
		Reversible:  e.opts.RevertURL != "",
		Destructive: e.opts.Destructive,
	}
}

// Execute implements action.Executor.
func (e *Executor) Execute(ctx context.Context, req action.Request) (action.Result, error) {
	payload := e.payload(req)
	if req.DryRun {
		return action.Result{Detail: fmt.Sprintf("dry-run: would %s %s", e.opts.Method, e.substitute(e.opts.URL, req, ""))}, nil
	}

	body := []byte(payload)
	httpReq, err := http.NewRequestWithContext(ctx, e.opts.Method, e.substitute(e.opts.URL, req, ""), bytes.NewReader(body))
	if err != nil {
		return action.Result{}, fmt.Errorf("remote action %q: build request: %w", e.opts.ID, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range e.opts.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := e.client.Do(httpReq)
	if err != nil {
		return action.Result{}, fmt.Errorf("remote action %q: %w", e.opts.ID, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return action.Result{}, fmt.Errorf("remote action %q: status %d: %s", e.opts.ID, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	ref := req.Target
	var decoded struct {
		ID        string `json:"id"`
		RevertRef string `json:"revert_ref"`
	}
	if len(bytes.TrimSpace(respBody)) > 0 && json.Unmarshal(respBody, &decoded) == nil {
		switch {
		case decoded.RevertRef != "":
			ref = decoded.RevertRef
		case decoded.ID != "":
			ref = decoded.ID
		}
	}
	return action.Result{RevertRef: ref, Detail: fmt.Sprintf("%s %s -> %d", e.opts.Method, e.substitute(e.opts.URL, req, ""), resp.StatusCode)}, nil
}

// Revert implements action.Executor.
func (e *Executor) Revert(ctx context.Context, d action.Decision) error {
	if e.opts.RevertURL == "" {
		return fmt.Errorf("remote action %q: not reversible", e.opts.ID)
	}
	ref := d.RevertRef
	if ref == "" {
		ref = d.Target
	}
	req := action.Request{
		ID:     d.ID,
		Action: d.Action,
		Scope:  d.Scope,
		Target: d.Target,
		Reason: d.Reason,
		TTL:    time.Until(d.ExpiresAt),
	}
	httpReq, err := http.NewRequestWithContext(ctx, e.opts.RevertMethod, e.substitute(e.opts.RevertURL, req, ref), nil)
	if err != nil {
		return fmt.Errorf("remote action %q: build revert: %w", e.opts.ID, err)
	}
	for k, v := range e.opts.Headers {
		httpReq.Header.Set(k, v)
	}
	resp, err := e.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("remote action %q: revert: %w", e.opts.ID, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("remote action %q: revert status %d: %s", e.opts.ID, resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return nil
}

func (e *Executor) payload(req action.Request) string {
	tmpl := e.opts.BodyTemplate
	if tmpl == "" {
		body := map[string]any{
			"action":   req.Action,
			"scope":    string(req.Scope),
			"target":   req.Target,
			"reason":   req.Reason,
			"operator": req.Operator,
			"ttl":      int(req.TTL.Seconds()),
			"evidence": req.Evidence,
		}
		encoded, err := json.Marshal(body)
		if err != nil {
			return "{}"
		}
		return string(encoded)
	}
	return e.substitute(tmpl, req, "")
}

// substitute expands the documented placeholders. In URLs every value is
// escaped; in bodies the values are inserted raw so they can be JSON literals.
func (e *Executor) substitute(tmpl string, req action.Request, ref string) string {
	isURL := strings.HasPrefix(tmpl, "http://") || strings.HasPrefix(tmpl, "https://")
	esc := func(v string) string {
		if !isURL {
			return v
		}
		return url.PathEscape(v)
	}
	replacer := strings.NewReplacer(
		"{action}", esc(req.Action),
		"{scope}", esc(string(req.Scope)),
		"{target}", esc(req.Target),
		"{reason}", esc(req.Reason),
		"{ttl}", strconv.Itoa(int(req.TTL.Seconds())),
		"{ref}", esc(ref),
	)
	return replacer.Replace(tmpl)
}
