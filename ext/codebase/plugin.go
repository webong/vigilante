package codebase

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
	"github.com/webong/vigilante/ext/agent"
)

const (
	ContractName       = "vigilante.codebase"
	ContractVersion    = "v1"
	OperationSnapshot  = "snapshot"
	OperationMatch     = "match-route"
	OperationRead      = "read-source"
)

// IPCEnv is the environment variable a supervised codebase guest reads to find
// the host's IPC socket.
const IPCEnv = "VIGILANTE_CODEBASE_IPC"

// Describe is the empty input for the snapshot operation.
type Describe struct{}

// MatchInput is the wire input for matching an HTTP method and path to a
// discovered route handler.
type MatchInput struct {
	Method string `json:"method,omitempty"`
	Path   string `json:"path"`
}

// MatchOutput is the wire output for route matching.
type MatchOutput struct {
	Matched bool          `json:"matched"`
	Route   *RouteHandler `json:"route,omitempty"`
}

// SnippetInput requests a root-jailed source snippet from the indexed repository.
type SnippetInput struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

// SnippetOutput returns the requested source snippet.
type SnippetOutput struct {
	File    string `json:"file"`
	Snippet string `json:"snippet"`
}

// Service is what Vigilante's correlator and agent reverse-call host hold.
// Both *Index (direct) and *Client (over an engine.Session) satisfy it.
type Service = agent.CodebaseService

var (
	_ Service = (*Index)(nil)
	_ Service = (*Client)(nil)
)

func SnapshotMethod() author.Method[Describe, Snapshot] {
	return method[Describe, Snapshot](OperationSnapshot)
}

func MatchRouteMethod() author.Method[MatchInput, MatchOutput] {
	return method[MatchInput, MatchOutput](OperationMatch)
}

func ReadSourceMethod() author.Method[SnippetInput, SnippetOutput] {
	return method[SnippetInput, SnippetOutput](OperationRead)
}

func method[In, Out any](op string) author.Method[In, Out] {
	return author.Method[In, Out]{
		Contract:  engine.ContractRef{Name: ContractName, Version: ContractVersion},
		Operation: engine.Operation{Name: op, Surface: "observation"},
	}
}

// GuestIdentity identifies the codebase guest.
func GuestIdentity() engine.Identity {
	return engine.Identity{ID: "vigilante/codebase", Revision: "v1.0.0", Version: "1.0.0"}
}

// BuildGuest constructs the ext.plugin/v1 guest serving s.
func BuildGuest(s Service) (engine.Descriptor, *engine.Guest, error) {
	if s == nil {
		return engine.Descriptor{}, nil, errors.New("codebase: nil service")
	}
	reg, err := author.New(GuestIdentity())
	if err != nil {
		return engine.Descriptor{}, nil, err
	}
	if err := author.Register(reg, SnapshotMethod(), func(context.Context, engine.Request, Describe) (Snapshot, error) {
		return s.Snapshot(), nil
	}); err != nil {
		return engine.Descriptor{}, nil, err
	}
	if err := author.Register(reg, MatchRouteMethod(), func(_ context.Context, _ engine.Request, in MatchInput) (MatchOutput, error) {
		r, ok := s.MatchRoute(in.Method, in.Path)
		if !ok {
			return MatchOutput{Matched: false}, nil
		}
		return MatchOutput{Matched: true, Route: &r}, nil
	}); err != nil {
		return engine.Descriptor{}, nil, err
	}
	if err := author.Register(reg, ReadSourceMethod(), func(_ context.Context, _ engine.Request, in SnippetInput) (SnippetOutput, error) {
		snippet, err := s.ReadSnippet(in.File, in.StartLine, in.EndLine)
		if err != nil {
			return SnippetOutput{}, err
		}
		return SnippetOutput{File: in.File, Snippet: snippet}, nil
	}); err != nil {
		return engine.Descriptor{}, nil, err
	}
	desc, guestOpts, err := reg.Snapshot(author.Options{
		Authorize:       func(context.Context, engine.Request) error { return nil },
		MaxCallDuration: 15 * time.Second,
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

// ServeConn serves s as a JSON-line guest over conn.
func ServeConn(ctx context.Context, conn io.ReadWriteCloser, s Service) error {
	_, guest, err := BuildGuest(s)
	if err != nil {
		_ = conn.Close()
		return err
	}
	return jsonline.ServeGuest(ctx, conn, guest)
}

// RunWorkerIPC dials the host socket at addr (normally os.Getenv(IPCEnv)) and
// serves s. This is the entry point for a supervised codebase binary.
func RunWorkerIPC(ctx context.Context, addr string, s Service) error {
	if addr == "" {
		return fmt.Errorf("codebase: %s is not set", IPCEnv)
	}
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return ServeConn(ctx, conn, s)
}

// Client is the host side of one codebase plugin session. It satisfies Service
// so the correlator and agent gateway consume it identically to *Index.
type Client struct {
	session *engine.Session
	snap    Snapshot
	closeFn func(context.Context) error
}

// OpenPlugin serves s as an in-process ext.plugin/v1 guest and returns a Client
// bound to the verified session.
func OpenPlugin(ctx context.Context, s Service) (*Client, error) {
	desc, guest, err := BuildGuest(s)
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
	return NewSessionClient(ctx, session, func(context.Context) error {
		return backend.Close()
	})
}

// NewSessionClient wraps an open session and caches the initial codebase
// snapshot from the guest.
func NewSessionClient(ctx context.Context, session *engine.Session, closeFn func(context.Context) error) (*Client, error) {
	c := &Client{session: session, closeFn: closeFn}
	snap, err := author.Call(ctx, session, SnapshotMethod(), Describe{})
	if err != nil {
		_ = c.Close(ctx)
		return nil, fmt.Errorf("snapshot codebase plugin: %w", err)
	}
	c.snap = snap
	return c, nil
}

func (c *Client) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{}
	}
	return cloneSnapshot(c.snap)
}

func (c *Client) MatchRoute(method, reqPath string) (RouteHandler, bool) {
	if c == nil || c.session == nil || reqPath == "" {
		return RouteHandler{}, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := author.Call(ctx, c.session, MatchRouteMethod(), MatchInput{Method: method, Path: reqPath})
	if err != nil || !out.Matched || out.Route == nil {
		return RouteHandler{}, false
	}
	return *out.Route, true
}

func (c *Client) ReadSnippet(relPath string, startLine, endLine int) (string, error) {
	if c == nil || c.session == nil {
		return "", errors.New("codebase: no plugin session")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := author.Call(ctx, c.session, ReadSourceMethod(), SnippetInput{
		File:      relPath,
		StartLine: startLine,
		EndLine:   endLine,
	})
	if err != nil {
		return "", err
	}
	return out.Snippet, nil
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
