package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/webong/vigilante/internal/repo"
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
	env.Codebase = &CodebaseContext{
		Source: "https://x/repo", Commit: "abc", FileCount: 10,
		MatchedRoute: &repo.RouteHandler{Method: "GET", Pattern: "/admin", File: "main.go", Line: 42},
	}
	p := BuildPrompt(env)
	for _, want := range []string{"security triage", "/admin", "PID 42", "linux/amd64", "Dependencies:", "https://x/repo"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt missing %q", want)
		}
	}
	if !strings.Contains(p, "severity") || !strings.Contains(p, "findings") || !strings.Contains(p, "does not prove exposure") {
		t.Error("prompt must state the output contract")
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
