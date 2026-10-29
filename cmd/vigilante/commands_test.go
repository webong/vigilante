package main

import (
	"reflect"
	"testing"
)

func TestNormalizeCommand(t *testing.T) {
	for _, tc := range []struct{ in, want []string }{
		{[]string{"run", "reverse", "--protocol", "tcp"}, []string{"-mode", "reverse", "--protocol", "tcp"}},
		{[]string{"eval"}, []string{"-mode", "eval"}},
		{[]string{"-mode", "http"}, []string{"-mode", "http"}},
		{[]string{"run"}, []string{"-help"}},
	} {
		if got := normalizeCommand(tc.in); !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%v: got %v want %v", tc.in, got, tc.want)
		}
	}
}
