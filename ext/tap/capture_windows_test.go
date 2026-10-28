//go:build windows

package tap

import "testing"

func TestBuildWindowsBPFProducesFilter(t *testing.T) {
	prog, err := buildWindowsBPF([]int{80, 443})
	if err != nil {
		t.Fatal(err)
	}
	// 5 fixed + 2 src JEQ + 1 dst load + 2 dst JEQ + reject + accept = 12.
	if prog.Len != 12 {
		t.Fatalf("BPF len = %d, want 12", prog.Len)
	}
	if prog.Filter == nil {
		t.Fatal("filter nil")
	}
	// Filter points at the first instruction (a pointer to element, not an array).
	first := *prog.Filter
	// First insn: LDH [12] (ethertype).
	if first.Code != 0x28 || first.K != 12 {
		t.Fatalf("first insn = %+v, want LDH 12", first)
	}
}
