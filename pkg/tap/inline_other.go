//go:build !linux

package tap

import (
	"context"
	"fmt"
)

func RunInline(context.Context, uint16, *MirrorQueue, PolicyGate, ...Protocols) error {
	return fmt.Errorf("inline NFQUEUE interception requires Linux")
}
