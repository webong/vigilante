package executor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/webong/ext/pkg/ext-go/engine"
	"github.com/webong/ext/pkg/ext-go/engine/guest/author"
	"github.com/webong/ext/pkg/ext-go/engine/transport/inprocess"
	"github.com/webong/ext/pkg/ext-go/engine/transport/jsonline"
	"github.com/webong/vigilante/internal/action"
)

// IPCEnv is the environment variable a supervised guest reads to find the
// host's socket.
const IPCEnv = "VIGILANTE_ACTION_IPC"

func DescribeMethod() author.Method[Describe, Capability] {
	return method[Describe, Capability](OperationDescribe)
}
func ExecuteMethod() author.Method[Request, Result] { return method[Request, Result](OperationExecute) }
func RevertMethod() author.Method[Decision, Reverted] {
	return method[Decision, Reverted](OperationRevert)
}

func method[In, Out any](op string) author.Method[In, Out] {
	return author.Method[In, Out]{
		Contract:  engine.ContractRef{Name: ContractName, Version: ContractVersion},
		Operation: engine.Operation{Name: op, Surface: "action"},
	}
}

// Identity identifies an executor guest. Every guest shares the contract
// descriptor; the capability ID tells executors apart.
func Identity() engine.Identity {
	return engine.Identity{ID: "vigilante/action-executor", Revision: "v1.0.0", Version: "1.0.0"}
}

// BuildGuest constructs the ext.plugin/v1 guest serving e.
func BuildGuest(e Executor) (engine.Descriptor, *engine.Guest, error) {
	if e == nil {
		return engine.Descriptor{}, nil, errors.New("executor: nil executor")
	}
	reg, err := author.New(Identity())
	if err != nil {
		return engine.Descriptor{}, nil, err
	}
	if err := author.Register(reg, DescribeMethod(), func(context.Context, engine.Request, Describe) (Capability, error) {
		return e.Capability(), nil
	}); err != nil {
		return engine.Descriptor{}, nil, err
	}
	if err := author.Register(reg, ExecuteMethod(), func(ctx context.Context, _ engine.Request, req Request) (Result, error) {
		return e.Execute(ctx, req)
	}); err != nil {
		return engine.Descriptor{}, nil, err
	}
	if err := author.Register(reg, RevertMethod(), func(ctx context.Context, _ engine.Request, d Decision) (Reverted, error) {
		return Reverted{}, e.Revert(ctx, d)
	}); err != nil {
		return engine.Descriptor{}, nil, err
	}
	desc, guestOpts, err := reg.Snapshot(author.Options{
		Authorize:       func(context.Context, engine.Request) error { return nil },
		MaxCallDuration: 30 * time.Second,
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

// ServeConn serves e as a JSON-line guest over conn.
func ServeConn(ctx context.Context, conn io.ReadWriteCloser, e Executor) error {
	_, guest, err := BuildGuest(e)
	if err != nil {
		_ = conn.Close()
		return err
	}
	return jsonline.ServeGuest(ctx, conn, guest)
}

// RunWorkerIPC dials the host socket at addr (normally os.Getenv(IPCEnv)) and
// serves e. This is the entry point for a supervised executor binary.
func RunWorkerIPC(ctx context.Context, addr string, e Executor) error {
	if addr == "" {
		return fmt.Errorf("executor: %s is not set", IPCEnv)
	}
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return ServeConn(ctx, conn, e)
}

// Client is the host side of one executor guest. It implements
// action.Executor, so it is registered with action.Registry and inherits every
// host rail.
type Client struct {
	session *engine.Session
	cap     action.Capability
	closeFn func(context.Context) error
}

var _ action.Executor = (*Client)(nil)

// Open serves e in process and returns a Client bound to it.
func Open(ctx context.Context, e Executor) (*Client, error) {
	desc, guest, err := BuildGuest(e)
	if err != nil {
		return nil, err
	}
	backend, err := inprocess.New(guest)
	if err != nil {
		return nil, err
	}
	session, err := openSession(ctx, desc, backend)
	if err != nil {
		_ = backend.Close()
		return nil, err
	}
	return NewSessionClient(ctx, session, nil)
}

// NewSessionClient wraps an open session and reads the guest's capability.
// closeFn, when set, runs after the session closes (e.g. stopping a process).
func NewSessionClient(ctx context.Context, session *engine.Session, closeFn func(context.Context) error) (*Client, error) {
	c := &Client{session: session, closeFn: closeFn}
	wc, err := author.Call(ctx, session, DescribeMethod(), Describe{})
	if err != nil {
		_ = c.Close(ctx)
		return nil, fmt.Errorf("describe executor: %w", err)
	}
	if wc.ID == "" {
		_ = c.Close(ctx)
		return nil, errors.New("executor: guest declared a capability without an id")
	}
	c.cap = coreCapability(wc)
	return c, nil
}

func (c *Client) Capability() action.Capability { return c.cap }

func (c *Client) Execute(ctx context.Context, req action.Request) (action.Result, error) {
	res, err := author.Call(ctx, c.session, ExecuteMethod(), wireRequest(req))
	return action.Result{RevertRef: res.RevertRef, Detail: res.Detail}, err
}

func (c *Client) Revert(ctx context.Context, d action.Decision) error {
	_, err := author.Call(ctx, c.session, RevertMethod(), wireDecision(d))
	return err
}

func (c *Client) Close(ctx context.Context) error {
	if c == nil {
		return nil
	}
	var err error
	if c.session != nil {
		err = c.session.Close(ctx)
	}
	if c.closeFn != nil {
		err = errors.Join(err, c.closeFn(ctx))
	}
	return err
}

func openSession(ctx context.Context, desc engine.Descriptor, backend engine.Backend) (*engine.Session, error) {
	return engine.Open(ctx, desc, engine.Options{
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
}
