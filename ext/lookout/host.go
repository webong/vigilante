package lookout

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/webong/ext/pkg/ext-go/engine"
	"github.com/webong/ext/pkg/ext-go/engine/guest/author"
	"github.com/webong/ext/pkg/ext-go/engine/transport/inprocess"
	"github.com/webong/vigilante/ext/triage"
	"github.com/webong/vigilante/internal/action"
	"github.com/webong/vigilante/internal/fleet"
	"github.com/webong/vigilante/internal/history"
)

// CoreHost implements Host over Vigilante's core. Actions is optional; without
// it the console can review but not enforce. Triager is optional.
type CoreHost struct {
	History *history.Store
	Actions *action.Registry
	Triager triage.Service
}

var errNoActions = errors.New("no action registry is configured")

func (h CoreHost) Actors(ctx context.Context, limit int) ([]history.Actor, error) {
	return h.History.Actors(ctx, limit)
}
func (h CoreHost) Flows(ctx context.Context, key string, since time.Time, limit int) ([]history.Flow, error) {
	return h.History.Flows(ctx, key, since, limit)
}
func (h CoreHost) Egress(ctx context.Context, since time.Time, limit int) ([]history.Egress, error) {
	return h.History.Egress(ctx, since, limit)
}
func (h CoreHost) Suggestions(ctx context.Context, status string) ([]history.Suggestion, error) {
	return h.History.Suggestions(ctx, status)
}
func (h CoreHost) Suggest(ctx context.Context, s history.Suggestion) error {
	return h.History.Suggest(ctx, s)
}
func (h CoreHost) ResolveSuggestion(ctx context.Context, id, status, decisionID string) (history.Suggestion, error) {
	return h.History.ResolveSuggestion(ctx, id, status, decisionID)
}
func (h CoreHost) Execute(ctx context.Context, req action.Request) (action.Decision, error) {
	if h.Actions == nil {
		return action.Decision{}, errNoActions
	}
	return h.Actions.Execute(ctx, req)
}
func (h CoreHost) Revert(ctx context.Context, id string) (action.Decision, error) {
	if h.Actions == nil {
		return action.Decision{}, errNoActions
	}
	return h.Actions.Revert(ctx, id)
}
func (h CoreHost) TriageModel(context.Context) (string, error) {
	if h.Triager == nil {
		return "", nil
	}
	return h.Triager.Model(), nil
}
func (h CoreHost) Triage(ctx context.Context, in triage.Input) (triage.Verdict, error) {
	if h.Triager == nil {
		return triage.Verdict{}, errors.New("LLM actor triage is not configured")
	}
	return h.Triager.Triage(ctx, in)
}
func (h CoreHost) Sensors(ctx context.Context) ([]history.Sensor, error) {
	return h.History.Sensors(ctx)
}
func (h CoreHost) CreateSensor(ctx context.Context, name string) (CreatedSensor, error) {
	plain, hash, err := fleet.GenerateKey()
	if err != nil {
		return CreatedSensor{}, err
	}
	sensor, err := h.History.CreateSensor(ctx, name, hash)
	if err != nil {
		return CreatedSensor{}, err
	}
	return CreatedSensor{Sensor: sensor, Key: plain}, nil
}
func (h CoreHost) DeleteSensor(ctx context.Context, id int64) error {
	return h.History.DeleteSensor(ctx, id)
}

// Bridge forwards HTTP requests under the console's mount to the guest.
type Bridge struct {
	session *engine.Session
}

// Open serves the lookout guest in process, offering it vigilante.console@v1
// backed by host, and returns the HTTP bridge to mount (with the mount prefix
// stripped) plus a close function.
func Open(ctx context.Context, opts Options, host Host) (*Bridge, func(context.Context) error, error) {
	if host == nil {
		return nil, nil, errors.New("lookout: host is required")
	}
	desc, guest, err := BuildGuest(opts)
	if err != nil {
		return nil, nil, err
	}
	backend, err := inprocess.New(guest)
	if err != nil {
		return nil, nil, err
	}
	session, err := engine.Open(ctx, desc, engine.Options{
		Verify: func(_ context.Context, actual engine.Descriptor) error {
			return engine.MatchHandshake(desc, actual)
		},
		Authorize: func(_ context.Context, req engine.Request) error {
			_, err := desc.Lookup(req.Contract, req.Operation)
			return err
		},
		Connect: func(context.Context, engine.Descriptor) (engine.Backend, error) {
			return backend, nil
		},
		Reverse: hostReverseOptions(host),
	})
	if err != nil {
		_ = backend.Close()
		return nil, nil, err
	}
	return &Bridge{session: session}, session.Close, nil
}

func (b *Bridge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBody))
	if err != nil {
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
		return
	}
	path := r.URL.Path
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	req := HTTPRequest{Method: r.Method, Path: path, Query: r.URL.RawQuery, Body: body, TLS: r.TLS != nil}
	for _, h := range forwardedHeaders {
		if v := r.Header.Get(h); v != "" {
			if req.Headers == nil {
				req.Headers = map[string]string{}
			}
			req.Headers[h] = v
		}
	}
	resp, err := author.Call(r.Context(), b.session, ServeHTTPMethod(), req)
	if err != nil {
		http.Error(w, "console unavailable", http.StatusBadGateway)
		return
	}
	for k, v := range resp.Headers {
		w.Header().Set(k, v)
	}
	if resp.Status == 0 {
		resp.Status = http.StatusOK
	}
	w.WriteHeader(resp.Status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(resp.Body)
	}
}
