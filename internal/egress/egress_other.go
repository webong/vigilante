//go:build !linux

package egress

import (
	"context"
	"errors"

	"github.com/webong/vigilante/internal/history"
)

type Options struct{ Loopback bool }

func Run(context.Context, Options, func(history.Egress)) error {
	return errors.New("egress eBPF observation is supported only on Linux")
}
