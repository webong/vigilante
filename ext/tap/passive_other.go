//go:build !linux

package tap

// PassiveOptions mirrors the linux build tag so cross-compiling docs and tests
// referencing the type still resolve on non-linux hosts.
type PassiveOptions struct {
	Iface       string
	Ports       []int
	SnapLen     int
	Promiscuous bool
}
