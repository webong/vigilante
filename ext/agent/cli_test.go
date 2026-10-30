package agent

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"
)

func sampleEnv() EnrichedEnvelope {
	return EnrichedEnvelope{
		Event:         PacketEvent{FlowID: "f1", Method: "GET", Path: "/admin", SrcAddr: "1.2.3.4:5", DstAddr: "9.9.9.9:80", PayloadPreview: "../etc/passwd"},
		TriggerReason: "test",
		OS:            OSContext{OS: "linux", Arch: "amd64", Hostname: "web1"},
		ServerProcess: ServerProcessContext{PID: 42, Name: "server", Executable: "/usr/bin/server"},
	}
}

func TestParseVerdictBareJSON(t *testing.T) {
	out := []byte(`{"flow_id":"f1","severity":"high","action":"alert","summary":"sqli"}`)
	v, err := ParseVerdictOutput(out)
	if err != nil {
		t.Fatal(err)
	}
	if v.Severity != "high" || v.Action != "alert" || v.Summary != "sqli" {
		t.Fatalf("verdict = %+v", v)
	}
}

func TestParseVerdictFenced(t *testing.T) {
	out := []byte("Here is my analysis:\n```json\n{\"severity\":\"critical\",\"action\":\"recommend-block\",\"summary\":\"inj\"}\n```\nDone.")
	v, err := ParseVerdictOutput(out)
	if err != nil {
		t.Fatal(err)
	}
	if v.Severity != "critical" || v.Action != "recommend-block" {
		t.Fatalf("verdict = %+v", v)
	}
}

func TestParseVerdictEmbeddedWithProseAndNestedBraces(t *testing.T) {
	out := []byte(`Analysis found {"severity":"low","action":"observe","summary":"ok {nested} braces","recommendations":["a","b"]} trailing`)
	v, err := ParseVerdictOutput(out)
	if err != nil {
		t.Fatal(err)
	}
	if v.Severity != "low" {
		t.Fatalf("verdict = %+v", v)
	}
	if !strings.Contains(v.Summary, "{nested}") {
		t.Fatalf("summary lost braces: %q", v.Summary)
	}
}

func TestParseVerdictAfterUnrelatedJSON(t *testing.T) {
	v, err := ParseVerdictOutput([]byte(`{"event":"progress"}\n{"severity":"high","action":"alert","summary":"found"}`))
	if err != nil || v.Summary != "found" {
		t.Fatalf("verdict = %+v, %v", v, err)
	}
}

func TestParseVerdictRejectsEmptyAndNonVerdict(t *testing.T) {
	if _, err := ParseVerdictOutput([]byte("   ")); err == nil {
		t.Fatal("empty should error")
	}
	if _, err := ParseVerdictOutput([]byte(`{"foo":"bar"}`)); err == nil {
		t.Fatal("non-verdict object should error")
	}
}

func TestBuildPromptContainsContext(t *testing.T) {
	env := sampleEnv()
	p := BuildPrompt(env)
	for _, want := range []string{"security triage", "ENRICHED_ENVELOPE", "severity", "findings", "does not prove exposure"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
	if strings.Contains(p, env.Event.PayloadPreview) || strings.Contains(p, env.Event.SrcAddr) {
		t.Error("event data must stay on stdin")
	}
}

func TestCLIHandlerSuccess(t *testing.T) {
	h := NewCLIHandler(CLIOptions{
		Command: "fake",
		Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return []byte(`{"severity":"high","action":"alert","summary":"from cli"}`), nil
		},
	})
	v, err := h(context.Background(), sampleEnv())
	if err != nil {
		t.Fatal(err)
	}
	if v.Summary != "from cli" || v.Severity != "high" {
		t.Fatalf("verdict = %+v", v)
	}
	if v.FlowID != "f1" {
		t.Fatalf("FlowID not defaulted: %q", v.FlowID)
	}
}

func TestCLIHandlerMayCompleteWithoutVerdict(t *testing.T) {
	h := NewCLIHandler(CLIOptions{Command: "fake", Run: func(context.Context, string, ...string) ([]byte, error) {
		return nil, nil
	}})
	v, err := h(context.Background(), sampleEnv())
	if err != nil || v.Severity != "" || v.Action != "" || v.Summary != "" {
		t.Fatalf("expected delivery acknowledgement, got %+v, %v", v, err)
	}
}

func TestCLIHandlerFallsBackOnFailure(t *testing.T) {
	var sawErr error
	h := NewCLIHandler(CLIOptions{
		Command: "broken",
		Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return nil, errors.New("boom")
		},
		OnError: func(err error) { sawErr = err },
	})
	// sampleEnv path traversal -> builtin fallback should yield high/alert.
	v, err := h(context.Background(), sampleEnv())
	if err != nil {
		t.Fatal(err)
	}
	if sawErr == nil {
		t.Fatal("OnError not invoked")
	}
	if v.Action != "alert" || v.Severity != "high" {
		t.Fatalf("fallback verdict = %+v, want builtin path-traversal alert", v)
	}
}

func TestCLIProbeRejectsInvalidVerdicts(t *testing.T) {
	for _, tc := range []struct{ name, output, want string }{
		{"flow mismatch", `{"flow_id":"other","severity":"high","action":"alert","summary":"stale"}`, "different flow_id"},
		{"invalid severity", `{"severity":"urgent","action":"alert","summary":"bad"}`, "incomplete verdict"},
		{"missing action", `{"severity":"high","summary":"bad"}`, "incomplete verdict"},
		{"missing summary", `{"severity":"high","action":"alert"}`, "incomplete verdict"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewCLIProbeHandler(CLIOptions{Command: "fake", Run: func(context.Context, string, ...string) ([]byte, error) {
				return []byte(tc.output), nil
			}})
			_, err := h(context.Background(), sampleEnv())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCLIOutputLimit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires sh")
	}
	_, err := runWithStdin(context.Background(), CLIOptions{Command: "sh", Args: []string{"-c", "head -c 1048577 /dev/zero"}}, nil)
	if err == nil || !strings.Contains(err.Error(), "exceeds 1 MiB") {
		t.Fatalf("oversized output error = %v", err)
	}
}

func TestCLIHandlerUnparseableOutputFallsBack(t *testing.T) {
	h := NewCLIHandler(CLIOptions{
		Command: "bad",
		Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return []byte("i am not json"), nil
		},
	})
	v, err := h(context.Background(), sampleEnv())
	if err != nil {
		t.Fatal(err)
	}
	// Builtin fallback for the traversal sample.
	if v.Action != "alert" {
		t.Fatalf("verdict = %+v", v)
	}
}

func TestCLITimeoutFallsBack(t *testing.T) {
	h := NewCLIHandler(CLIOptions{
		Command: "slow",
		Timeout: 10 * time.Millisecond,
		Run: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	})
	if _, err := h(context.Background(), sampleEnv()); err != nil {
		t.Fatalf("timeout must fall back, not error: %v", err)
	}
}

func TestCLIExpandsPromptArgument(t *testing.T) {
	var got []string
	h := NewCLIHandler(CLIOptions{
		Command: "fake", Args: []string{"run", "{prompt}"},
		Run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			got = args
			return []byte(`{"severity":"low","action":"observe","summary":"checked"}`), nil
		},
	})
	if _, err := h(context.Background(), sampleEnv()); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != "run" || !strings.Contains(got[1], "ENRICHED_ENVELOPE") {
		t.Fatalf("argv = %q", got)
	}
}

func TestCLIStdoutSeparateFromDiagnostics(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires sh")
	}
	out, err := runWithStdin(context.Background(), CLIOptions{Command: "sh", Args: []string{"-c", "cat; echo diagnostic >&2"}}, []byte(`{"severity":"low"}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"severity":"low"}` {
		t.Fatalf("stdout = %q", out)
	}
}

func TestCLIPromptStdinMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires sh")
	}
	v, err := cliTriage(context.Background(), CLIOptions{
		Command: "sh", Args: []string{"-c", "grep -q 'ENRICHED_ENVELOPE JSON:' && printf '{\"severity\":\"low\",\"action\":\"observe\",\"summary\":\"checked\"}'"},
		Input: "prompt", Timeout: time.Second,
	}, sampleEnv())
	if err != nil {
		t.Fatal(err)
	}
	if v.Summary != "checked" || v.FlowID != "f1" {
		t.Fatalf("verdict = %+v", v)
	}
}
