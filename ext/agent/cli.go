package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// CLIOptions configures the CLI-backed agent: a Handler that shells out to an
// external command (an LLM CLI, a python triage script, `curl` to a model API,
// etc.) and parses a Verdict from its stdout.
//
// The external command receives the full EnrichedEnvelope as JSON on stdin and
// may print a JSON Verdict (a bare object, or one embedded in a larger
// response), or exit successfully without output. Reverse host capabilities (read-source, query-graph) are performed
// by the command itself using its environment; the triage contract still
// executes behind the same ext.plugin/v1 session as any other agent.
type CLIOptions struct {
	// Command is the executable to run (e.g. "claude", "python3", "sh").
	Command string
	// Args are appended after Command (the envelope JSON goes on stdin).
	Args []string
	// Env entries (KEY=VALUE) are appended to the inherited environment.
	Env []string
	// Timeout bounds one triage invocation (default 30s).
	Timeout time.Duration
	// Run, when non-nil, replaces command execution (tests). Its combined
	// output is parsed as the Verdict when present.
	Run Runner
	// OnError, when set, is invoked with the underlying command error.
	OnError func(error)
}

// NewCLIHandler returns a Handler that triages by invoking an external command.
// It falls back to DefaultBuiltInHandler if the command fails, so a broken CLI
// never silences triage.
func NewCLIHandler(opts CLIOptions) Handler {
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	return func(ctx context.Context, env EnrichedEnvelope) (Verdict, error) {
		verdict, err := cliTriage(ctx, opts, env)
		if err != nil {
			if opts.OnError != nil {
				opts.OnError(err)
			}
			// Never lose triage: degrade to the built-in rule engine.
			return DefaultBuiltInHandler(ctx, env)
		}
		return verdict, nil
	}
}

// cliTriage runs the external command with the envelope on stdin and parses the
// Verdict from stdout.
func cliTriage(ctx context.Context, opts CLIOptions, env EnrichedEnvelope) (Verdict, error) {
	payload, err := json.Marshal(env)
	if err != nil {
		return Verdict{}, fmt.Errorf("cli agent: marshal envelope: %w", err)
	}

	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	var out []byte
	if opts.Run != nil {
		out, err = opts.Run(runCtx, opts.Command, opts.Args...)
	} else {
		out, err = runWithStdin(runCtx, opts, payload)
	}
	if err != nil {
		return Verdict{}, fmt.Errorf("cli agent: %s: %w", opts.Command, err)
	}
	if len(bytes.TrimSpace(out)) == 0 {
		return Verdict{}, nil
	}

	verdict, perr := ParseVerdictOutput(out)
	if perr != nil {
		return Verdict{}, fmt.Errorf("cli agent: parse output: %w", perr)
	}
	if verdict.FlowID == "" {
		verdict.FlowID = env.Event.FlowID
	}
	return verdict, nil
}

// runWithStdin invokes the command with the envelope JSON on stdin and returns
// its combined output.
func runWithStdin(ctx context.Context, opts CLIOptions, stdin []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, opts.Command, opts.Args...)
	cmd.Stdin = bytes.NewReader(stdin)
	if len(opts.Env) > 0 {
		cmd.Env = append(os.Environ(), opts.Env...)
	}
	return cmd.CombinedOutput()
}

// ParseVerdictOutput extracts a Verdict JSON object from command output. It
// tolerates surrounding prose/fences: it scans for the first balanced JSON
// object that unmarshals into a Verdict with a non-empty severity/action/summary.
func ParseVerdictOutput(raw []byte) (Verdict, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return Verdict{}, fmt.Errorf("empty output")
	}
	// Fast path: the whole output is the JSON object.
	if v, ok := tryVerdict(trimmed); ok {
		return v, nil
	}
	s := string(trimmed)
	// Fenced block: ```json ... ``` or ``` ... ```.
	if i := strings.Index(s, "```"); i >= 0 {
		rest := s[i+3:]
		if j := strings.Index(rest, "```"); j > 0 {
			inner := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(rest[:j], "json"), "\n"))
			if v, ok := tryVerdict([]byte(inner)); ok {
				return v, nil
			}
		}
	}
	// Scan for the first balanced object that looks like a verdict.
	if i := strings.IndexByte(s, '{'); i >= 0 {
		if v, ok := extractVerdict(s[i:]); ok {
			return v, nil
		}
	}
	return Verdict{}, fmt.Errorf("no verdict JSON object found in output")
}

// tryVerdict unmarshals b into a Verdict and reports whether it looks valid.
func tryVerdict(b []byte) (Verdict, bool) {
	var v Verdict
	if err := json.Unmarshal(b, &v); err != nil {
		return Verdict{}, false
	}
	if v.Severity == "" && v.Action == "" && v.Summary == "" {
		return Verdict{}, false
	}
	return v, true
}

// extractVerdict finds the first balanced JSON object in s that unmarshals to a
// valid Verdict, correctly skipping braces inside strings.
func extractVerdict(s string) (Verdict, bool) {
	depth := 0
	inStr := false
	esc := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				if v, ok := tryVerdict([]byte(s[:i+1])); ok {
					return v, true
				}
				depth = 0
			}
		}
	}
	return Verdict{}, false
}

// BuildPrompt renders a human-readable triage brief for an external CLI/LLM
// agent. It is pure and deterministic so it can be unit-tested. The envelope
// JSON itself is delivered on stdin; this prompt provides the instructions.
func BuildPrompt(env EnrichedEnvelope) string {
	var b strings.Builder
	b.WriteString("You are a security triage agent for a live network gateway.\n")
	b.WriteString("Analyze the ENRICHED_ENVELOPE JSON provided on stdin. If Vigilante should handle your verdict, respond with ONLY a JSON object:\n")
	b.WriteString("{\"flow_id\":\"...\",\"severity\":\"info|low|medium|high|critical\",\n")
	b.WriteString("\"action\":\"your recommended action\",\"summary\":\"...\",\n")
	b.WriteString("\"findings\":[{\"subject\":\"...\",\"claim\":\"...\",\"evidence\":[\"...\"],\"sources\":[\"...\"],\"confidence\":\"...\"}],\"recommendations\":[\"...\"]}\n")
	b.WriteString("Investigate independently. An installed dependency does not prove exposure or reachability. State uncertainty and cite evidence for vulnerability claims.\n\n")
	b.WriteString("If your agent stores or delivers its own result, it may exit successfully without output.\n\n")
	fmt.Fprintf(&b, "Event: %s %s from %s -> %s\n", env.Event.Method, env.Event.Path, env.Event.SrcAddr, env.Event.DstAddr)
	fmt.Fprintf(&b, "Trigger: %s\n", env.TriggerReason)
	fmt.Fprintf(&b, "Process: %s (PID %d, %s)\n", env.ServerProcess.Name, env.ServerProcess.PID, env.ServerProcess.Executable)
	fmt.Fprintf(&b, "OS: %s/%s host=%s\n", env.OS.OS, env.OS.Arch, env.OS.Hostname)
	fmt.Fprintf(&b, "Dependencies: %d inventoried modules (advisory status not pre-judged)\n",
		len(env.DependencyGraph.Dependencies))
	if env.Codebase != nil {
		fmt.Fprintf(&b, "Codebase: %s (commit %s, %d files)\n", env.Codebase.Source, env.Codebase.Commit, env.Codebase.FileCount)
		if env.Codebase.MatchedRoute != nil {
			fmt.Fprintf(&b, "Matched route: %s %s -> %s:%d\n",
				env.Codebase.MatchedRoute.Method, env.Codebase.MatchedRoute.Pattern,
				env.Codebase.MatchedRoute.File, env.Codebase.MatchedRoute.Line)
		}
	}
	if env.Event.PayloadPreview != "" {
		fmt.Fprintf(&b, "Payload preview: %s\n", env.Event.PayloadPreview)
	}
	return b.String()
}
