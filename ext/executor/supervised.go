package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/webong/ext/pkg/ext-go/engine"
	"github.com/webong/ext/pkg/ext-go/engine/transport/jsonline"
	"github.com/webong/ext/res/system/graph"
	"github.com/webong/ext/res/system/supervisor"
)

// LaunchOptions configures an out-of-process executor guest.
type LaunchOptions struct {
	Store       graph.Store
	Command     string
	Args        []string
	Environment map[string]string
}

// Launch starts Command under res/system/supervisor (checksum-pinned, leased,
// terminated with the host), hands it the IPC address in IPCEnv, and returns a
// Client once the guest completes the ext.plugin/v1 handshake and describes
// its capability. Closing the Client stops the process.
func Launch(ctx context.Context, opts LaunchOptions) (*Client, error) {
	if opts.Store == nil {
		return nil, fmt.Errorf("executor: graph store is required for supervisor")
	}
	if opts.Command == "" {
		return nil, fmt.Errorf("executor: command is required")
	}
	checksum, err := fileSHA256(opts.Command)
	if err != nil {
		return nil, fmt.Errorf("checksum executor binary: %w", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	addr := ln.Addr().String()

	sup, err := supervisor.New(supervisor.Options{
		Graph:           opts.Store,
		RequireChecksum: true,
		OrphanPolicy:    supervisor.OrphanTerminate,
		LeaseDuration:   15 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	env := map[string]string{IPCEnv: addr}
	for k, v := range opts.Environment {
		env[k] = v
	}

	desc, _, err := BuildGuest(nopExecutor{})
	if err != nil {
		_ = sup.Close(ctx)
		return nil, err
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

	var session atomic.Pointer[engine.Session]
	inst, err := sup.Start(ctx, supervisor.Spec{
		Artifact: supervisor.Artifact{
			ID:       "vigilante-action-" + filepath.Base(opts.Command),
			Revision: "v1",
			Checksum: "sha256:" + checksum,
		},
		Command:     opts.Command,
		Args:        opts.Args,
		Environment: env,
		Endpoints: []supervisor.Endpoint{{
			ID: "action-ipc", Address: addr, Transport: "tcp-jsonline", Direction: "bidirectional",
		}},
		ReadinessTimeout: 10 * time.Second,
		ProtocolHandshake: func(hCtx context.Context, _ supervisor.Instance) error {
			select {
			case <-hCtx.Done():
				return hCtx.Err()
			case acceptErr := <-errCh:
				return acceptErr
			case conn := <-connCh:
				sess, openErr := openSession(hCtx, desc, jsonline.NewClient(conn))
				if openErr != nil {
					_ = conn.Close()
					return openErr
				}
				session.Store(sess)
				return nil
			}
		},
	})
	if err != nil {
		_ = sup.Close(ctx)
		return nil, err
	}

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		cur, ierr := sup.Instance(inst.ID)
		if ierr != nil || cur.State == supervisor.StateCrashed || cur.State == supervisor.StateStopped {
			break
		}
		if sess := session.Load(); cur.State == supervisor.StateReady && sess != nil {
			return NewSessionClient(ctx, sess, sup.Close)
		}
		time.Sleep(25 * time.Millisecond)
	}
	_ = sup.Close(ctx)
	return nil, fmt.Errorf("executor %s failed to reach ready state", opts.Command)
}

// nopExecutor only exists to derive the host-side descriptor.
type nopExecutor struct{}

func (nopExecutor) Capability() Capability                           { return Capability{} }
func (nopExecutor) Execute(context.Context, Request) (Result, error) { return Result{}, nil }
func (nopExecutor) Revert(context.Context, Decision) error           { return nil }

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
