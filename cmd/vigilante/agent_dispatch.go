package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/webong/vigilante/ext/agent"
)

type agentDispatchOptions struct {
	Kind    string
	Command string
	Args    []string
	Input   string
	Dir     string
	Timeout time.Duration
}

// resolveAgentPreset applies convenient local CLI defaults while leaving the
// generic cli backend and explicit arguments available for other agents.
func resolveAgentPreset(kind, command string, args *[]string, input *string) (string, string) {
	if *input == "" {
		switch kind {
		case "opencode", "claude", "codex":
			*input = "prompt"
		default:
			if splitKind, _ := splitAgentArg(kind); splitKind == "remote" {
				*input = ""
			} else {
				*input = "json"
			}
		}
	}
	switch kind {
	case "opencode", "claude", "codex":
		if command == "" {
			command = kind
		}
		if len(*args) == 0 {
			switch kind {
			case "opencode":
				*args = []string{"run", "-"}
			case "claude":
				*args = []string{"-p"}
			case "codex":
				*args = []string{"exec", "-"}
			}
		}
		return "cli", command
	}
	kind, target := splitAgentArg(kind)
	if kind == "cli" && command != "" {
		target = command
	}
	return kind, target
}

// runAgentTest performs one strict dispatch. Unlike the live pipeline, CLI
// failures do not fall back to the built-in detector: the purpose is to expose
// configuration and connectivity problems to the operator.
func runAgentTest(ctx context.Context, out io.Writer, opts agentDispatchOptions) error {
	args := append([]string(nil), opts.Args...)
	kind, target := resolveAgentPreset(opts.Kind, opts.Command, &args, &opts.Input)
	if opts.Input != "" && opts.Input != "json" && opts.Input != "prompt" {
		return fmt.Errorf("agent input must be json or prompt")
	}
	var handler agent.Handler
	switch kind {
	case "cli":
		if target == "" {
			return fmt.Errorf("local agent requires -agent opencode, claude, codex, or cli:<command>")
		}
		handler = agent.NewCLIProbeHandler(agent.CLIOptions{
			Command: target, Args: args, Input: opts.Input, Dir: opts.Dir, Timeout: opts.Timeout,
		})
	case "remote":
		var err error
		handler, err = agent.NewRemoteHandler(agent.RemoteOptions{URL: target, Token: os.Getenv("VIGILANTE_AGENT_TOKEN"), Timeout: opts.Timeout})
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("agent-test supports local CLI or remote agents, not %q", kind)
	}

	env := agent.EnrichedEnvelope{
		Event: agent.PacketEvent{
			FlowID: "agent-connectivity-test", Timestamp: time.Now().UTC(),
			Protocol: "http", SrcAddr: "192.0.2.10:12345", DstAddr: "192.0.2.20:8080",
			Method: "GET", Path: "/health",
		},
		TriggerReason: "agent-connectivity-test",
	}
	started := time.Now()
	verdict, err := handler(ctx, env)
	if err != nil {
		return fmt.Errorf("agent test failed: %w", err)
	}
	fmt.Fprintf(out, "agent: %s\n", opts.Kind)
	fmt.Fprintf(out, "duration: %s\n", time.Since(started).Round(time.Millisecond))
	if verdict.Severity == "" && verdict.Action == "" && verdict.Summary == "" {
		fmt.Fprintln(out, "status: accepted (agent handles delivery; no verdict returned)")
		return nil
	}
	fmt.Fprintln(out, "status: verdict received")
	fmt.Fprintf(out, "severity: %s\naction: %s\nsummary: %s\n", verdict.Severity, verdict.Action, verdict.Summary)
	return nil
}
