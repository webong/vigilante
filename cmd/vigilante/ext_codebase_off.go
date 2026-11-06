//go:build nocodebase

package main

import (
	"context"
	"io"

	"github.com/webong/ext/res/system/graph"
	"github.com/webong/vigilante/ext/agent"
)

func openCodebase(context.Context, io.Writer, *Config, string, string, graph.Store) (agent.CodebaseService, func(context.Context) error, error) {
	return nil, nil, nil
}
