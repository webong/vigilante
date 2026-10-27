package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/webong/ext/pkg/ext-go/engine"
	"github.com/webong/ext/pkg/ext-go/engine/transport/jsonline"
	"github.com/webong/ext/res/system/graph"
	"github.com/webong/ext/res/system/supervisor"
	"github.com/webong/vigilante/internal/repo"
)

// SupervisedOptions configures an out-of-process agent managed by
// github.com/webong/ext/res/system/supervisor and connected over jsonline IPC.
type SupervisedOptions struct {
	Store           graph.Store
	Repo            *repo.Index
	Command         string
	Args            []string
	Environment     map[string]string
	SecretRefs      map[string]supervisor.SecretReference
	SecretResolver  func(context.Context, supervisor.SecretReference) (string, error)
	RequireChecksum bool
}

// NewSupervisedGateway launches an out-of-process agent via res/system/supervisor
// (verifying SHA-256 artifact checksums, managing process leases in ext.runtime,
// and resolving opaque SecretReferences) and connects to it over a local socket
// speaking ext.plugin/v1 JSON-line with bidirectional reverse host callbacks.
func NewSupervisedGateway(ctx context.Context, opts SupervisedOptions) (*Gateway, *supervisor.Supervisor, error) {
	if opts.Store == nil {
		return nil, nil, fmt.Errorf("graph store is required for supervisor")
	}
	cmdPath := opts.Command
	if cmdPath == "" {
		var err error
		cmdPath, err = os.Executable()
		if err != nil {
			return nil, nil, err
		}
	}

	checksum, err := fileSHA256(cmdPath)
	if err != nil {
		return nil, nil, fmt.Errorf("checksum agent binary: %w", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	ipcAddr := ln.Addr().String()

	sup, err := supervisor.New(supervisor.Options{
		Graph:           opts.Store,
		SecretResolver:  opts.SecretResolver,
		RequireChecksum: opts.RequireChecksum,
		OrphanPolicy:    supervisor.OrphanTerminate,
		LeaseDuration:   15 * time.Second,
	})
	if err != nil {
		_ = ln.Close()
		return nil, nil, err
	}

	env := map[string]string{
		"VIGILANTE_AGENT_IPC": ipcAddr,
	}
	for k, v := range opts.Environment {
		env[k] = v
	}

	args := opts.Args
	if len(args) == 0 {
		args = []string{"-mode", "agent-worker", "-agent-ipc", ipcAddr}
	}

	connCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			errCh <- acceptErr
			return
		}
		connCh <- conn
	}()

	desc, _, err := BuildGuest(nil)
	if err != nil {
		_ = ln.Close()
		_ = sup.Close(ctx)
		return nil, nil, err
	}

	var openedSession *engine.Session

	spec := supervisor.Spec{
		Artifact: supervisor.Artifact{
			ID:       "vigilante-agent",
			Revision: "v1.1.0",
			Checksum: "sha256:" + checksum,
		},
		Command:          cmdPath,
		Args:             args,
		Environment:      env,
		SecretReferences: opts.SecretRefs,
		Endpoints: []supervisor.Endpoint{
			{
				ID:        "agent-ipc",
				Address:   ipcAddr,
				Transport: "tcp-jsonline",
				Direction: "bidirectional",
			},
		},
		ReadinessTimeout: 10 * time.Second,
		ProtocolHandshake: func(hCtx context.Context, _ supervisor.Instance) error {
			select {
			case <-hCtx.Done():
				return hCtx.Err()
			case acceptErr := <-errCh:
				return acceptErr
			case conn := <-connCh:
				client := jsonline.NewClient(conn)
				sess, openErr := engine.Open(hCtx, desc, engine.Options{
					Verify: func(_ context.Context, actual engine.Descriptor) error {
						return engine.MatchHandshake(desc, actual)
					},
					Authorize: func(_ context.Context, req engine.Request) error {
						_, lErr := desc.Lookup(req.Contract, req.Operation)
						return lErr
					},
					Connect: func(context.Context, engine.Descriptor) (engine.Backend, error) {
						return client, nil
					},
					Reverse: BuildHostReverseOptions(opts.Store, opts.Repo),
				})
				if openErr != nil {
					_ = conn.Close()
					return openErr
				}
				openedSession = sess
				return nil
			}
		},
	}

	inst, err := sup.Start(ctx, spec)
	if err != nil {
		_ = ln.Close()
		_ = sup.Close(ctx)
		return nil, nil, err
	}

	// Wait for the supervised agent to reach StateReady (handshake complete).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		cur, err := sup.Instance(inst.ID)
		if err != nil {
			break
		}
		if cur.State == supervisor.StateReady && openedSession != nil {
			_ = ln.Close()
			gw := NewSessionGateway(openedSession, func(cCtx context.Context) error {
				return sup.Close(cCtx)
			})
			return gw, sup, nil
		}
		if cur.State == supervisor.StateCrashed || cur.State == supervisor.StateStopped {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	_ = ln.Close()
	_ = sup.Close(ctx)
	return nil, nil, fmt.Errorf("supervised agent failed to reach ready state")
}

// RunWorkerIPC dials the host's IPC socket and serves the ext.plugin/v1 JSON-line
// agent guest.
func RunWorkerIPC(ctx context.Context, ipcAddr string, handler Handler) error {
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", ipcAddr)
	if err != nil {
		return err
	}
	return ServeStdio(ctx, conn, handler)
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
