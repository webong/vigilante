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
