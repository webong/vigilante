package main

import "testing"

func TestSplitGatewayArg(t *testing.T) {
	cases := []struct{ in, wantPosture, wantEndpoint string }{
		{"local", "local", ""},
		{"", "local", ""},
		{"external:http://gw.example:5001", "external", "http://gw.example:5001"},
	}
	for _, c := range cases {
		posture, ep := splitGatewayArg(c.in)
		if posture != c.wantPosture || ep != c.wantEndpoint {
			t.Errorf("splitGatewayArg(%q) = %q/%q, want %q/%q", c.in, posture, ep, c.wantPosture, c.wantEndpoint)
		}
	}
}

func TestSplitAgentArg(t *testing.T) {
	cases := []struct{ in, kind, cmd string }{
		{"", "", ""},
		{"builtin", "builtin", ""},
		{"supervised", "supervised", ""},
		{"cli:claude -p", "cli", "claude -p"},
	}
	for _, c := range cases {
		kind, cmd := splitAgentArg(c.in)
		if kind != c.kind || cmd != c.cmd {
			t.Errorf("splitAgentArg(%q) = %q/%q, want %q/%q", c.in, kind, cmd, c.kind, c.cmd)
		}
	}
}
