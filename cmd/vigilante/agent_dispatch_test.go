package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/webong/vigilante/ext/agent"
)

func TestResolveAgentPresets(t *testing.T) {
	for _, tc := range []struct {
		kind string
		args []string
	}{
		{"opencode", []string{"run", "-"}},
		{"claude", []string{"-p"}},
		{"codex", []string{"exec", "-"}},
	} {
		args, input := []string(nil), ""
		kind, command := resolveAgentPreset(tc.kind, "", &args, &input)
		if kind != "cli" || command != tc.kind || input != "prompt" || !reflect.DeepEqual(args, tc.args) {
			t.Errorf("%s: kind=%q command=%q input=%q args=%q", tc.kind, kind, command, input, args)
		}
	}
}

func TestResolveAgentPresetHonorsOverrides(t *testing.T) {
	args, input := []string{"custom"}, "json"
	kind, command := resolveAgentPreset("claude", "my-claude", &args, &input)
	if kind != "cli" || command != "my-claude" || input != "json" || !reflect.DeepEqual(args, []string{"custom"}) {
		t.Fatalf("override lost: %q %q %q %q", kind, command, input, args)
	}
	args = nil
	kind, command = resolveAgentPreset("cli:other", "override", &args, &input)
	if kind != "cli" || command != "override" {
		t.Fatalf("generic command override lost: %q %q", kind, command)
	}
}

func TestRunAgentTestLocalCLI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test helper requires sh")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "agent")
	if err := os.WriteFile(script, []byte("#!/bin/sh\ngrep -q 'agent-connectivity-test'\nprintf '%s' '{\"severity\":\"low\",\"action\":\"observe\",\"summary\":\"local agent connected\"}'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	err := run([]string{"-mode", "agent-test", "-agent", "cli:" + script, "-agent-timeout", "2s"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"status: verdict received", "severity: low", "local agent connected"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q: %s", want, out.String())
		}
	}
}

func TestRunAgentTestLocalFailureDoesNotFallBack(t *testing.T) {
	var out bytes.Buffer
	err := runAgentTest(context.Background(), &out, agentDispatchOptions{Kind: "cli:definitely-not-a-vigilante-agent", Timeout: time.Second})
	if err == nil || !strings.Contains(err.Error(), "agent test failed") {
		t.Fatalf("expected strict probe error, got %v", err)
	}
	if strings.Contains(out.String(), "verdict received") {
		t.Fatalf("fallback reported as successful probe: %s", out.String())
	}
}

func TestRunAgentTestRemote(t *testing.T) {
	t.Setenv("VIGILANTE_AGENT_TOKEN", "probe-token")
	for _, tc := range []struct {
		name, body, want string
		status           int
	}{
		{"verdict", `{"flow_id":"agent-connectivity-test","severity":"low","action":"observe","summary":"cloud agent connected"}`, "cloud agent connected", http.StatusOK},
		{"accepted", `{"job_id":"test"}`, "status: accepted", http.StatusAccepted},
		{"empty", "", "status: accepted", http.StatusNoContent},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-Vigilante-Contract") != "vigilante.agent/v1" || r.Header.Get("Authorization") != "Bearer probe-token" {
					t.Error("missing agent contract or authorization header")
				}
				var env agent.EnrichedEnvelope
				if err := json.NewDecoder(r.Body).Decode(&env); err != nil || env.Event.FlowID != "agent-connectivity-test" {
					t.Errorf("invalid probe envelope: %+v, %v", env, err)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			var out bytes.Buffer
			err := runAgentTest(context.Background(), &out, agentDispatchOptions{Kind: "remote:" + server.URL, Timeout: time.Second})
			if err != nil || !strings.Contains(out.String(), tc.want) {
				t.Fatalf("output=%q err=%v", out.String(), err)
			}
		})
	}
}
