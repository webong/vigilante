package triage

import (
	"context"
	"io"
	"time"

	"github.com/webong/ext/pkg/ext-go/engine"
	"github.com/webong/ext/pkg/ext-go/engine/guest/author"
	"github.com/webong/ext/pkg/ext-go/engine/transport/inprocess"
	"github.com/webong/ext/pkg/ext-go/engine/transport/jsonline"
)

const (
	ContractName         = "vigilante.triage"
	ContractVersion      = "v1"
	OperationTriageActor = "triage-actor"
)

// Service is what core consumers (the behavior sink, the dashboard) hold. A
// Client satisfies it; so does a Triager when no plugin boundary is wanted, as
// in tests.
type Service interface {
	Triage(ctx context.Context, in Input) (Verdict, error)
	Model() string
}

// Handler judges one actor inside a guest.
type Handler func(ctx context.Context, in Input) (Verdict, error)

// TriageActorMethod is the typed vigilante.triage@v1/triage-actor operation.
func TriageActorMethod() author.Method[Input, Verdict] {
	return author.Method[Input, Verdict]{
		Contract:  engine.ContractRef{Name: ContractName, Version: ContractVersion},
		Operation: engine.Operation{Name: OperationTriageActor, Surface: "observation"},
	}
}

// Identity identifies the triage guest.
func Identity() engine.Identity {
	return engine.Identity{ID: "vigilante/actor-triage", Revision: "v1.0.0", Version: "1.0.0"}
}

// BuildGuest constructs the ext.plugin/v1 guest serving triage-actor.
func BuildGuest(handler Handler) (engine.Descriptor, *engine.Guest, error) {
	reg, err := author.New(Identity())
	if err != nil {
		return engine.Descriptor{}, nil, err
	}
	if err := author.Register(reg, TriageActorMethod(), func(ctx context.Context, _ engine.Request, in Input) (Verdict, error) {
		return handler(ctx, in)
	}); err != nil {
		return engine.Descriptor{}, nil, err
	}
	desc, guestOpts, err := reg.Snapshot(author.Options{
		Authorize:       func(context.Context, engine.Request) error { return nil },
		MaxCallDuration: 2 * time.Minute, // model calls are slow; the sink runs off the request path
	})
	if err != nil {
		return engine.Descriptor{}, nil, err
	}
	guest, err := engine.NewGuest(desc, guestOpts)
	if err != nil {
		return engine.Descriptor{}, nil, err
	}
	return desc, guest, nil
}

// ServeStdio runs a triage guest out of process over conn.
func ServeStdio(ctx context.Context, conn io.ReadWriteCloser, handler Handler) error {
	_, guest, err := BuildGuest(handler)
	if err != nil {
		_ = conn.Close()
		return err
	}
	return jsonline.ServeGuest(ctx, conn, guest)
}

// Client calls a triage guest through an engine.Session.
type Client struct {
	session *engine.Session
	method  author.Method[Input, Verdict]
	model   string
}

// Open serves t as an in-process guest and returns a Client bound to it.
func Open(ctx context.Context, t Service) (*Client, error) {
	desc, guest, err := BuildGuest(t.Triage)
	if err != nil {
		return nil, err
	}
	backend, err := inprocess.New(guest)
	if err != nil {
		return nil, err
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
	})
	if err != nil {
		_ = backend.Close()
		return nil, err
	}
	return NewSessionClient(session, t.Model()), nil
}

// NewSessionClient wraps an existing session, such as a supervised jsonline
// guest. model is reported to operators as the triage model.
func NewSessionClient(session *engine.Session, model string) *Client {
	return &Client{session: session, method: TriageActorMethod(), model: model}
}

func (c *Client) Triage(ctx context.Context, in Input) (Verdict, error) {
	return author.Call(ctx, c.session, c.method, in)
}

func (c *Client) Model() string { return c.model }

func (c *Client) Close(ctx context.Context) error {
	if c == nil || c.session == nil {
		return nil
	}
	return c.session.Close(ctx)
}
