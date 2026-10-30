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
	// Dir is the agent's working directory, where it can discover project skills
	// and configuration. Empty uses Vigilante's working directory.
	Dir string
	// Input is "json" (default) or "prompt". Prompt mode writes the triage
	// instructions and envelope to stdin for CLIs that use stdin as a prompt.
	Input string
	// Env entries (KEY=VALUE) are appended to the inherited environment.
	Env []string
	// Timeout bounds one triage invocation (default 30s).
	Timeout time.Duration
	// Run, when non-nil, replaces command execution (tests).
	Run Runner
	// OnError, when set, is invoked with the underlying command error.
	OnError func(error)
}

// NewCLIProbeHandler invokes an external command without the production
// built-in fallback. It is intended for connectivity checks, where a fallback
// verdict would hide a broken agent configuration.
func NewCLIProbeHandler(opts CLIOptions) Handler {
	return func(ctx context.Context, env EnrichedEnvelope) (Verdict, error) {
		return cliTriage(ctx, opts, env)
	}
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
	prompt := BuildPrompt(env)
	input := payload
	switch opts.Input {
	case "", "json":
	case "prompt":
		input = []byte(prompt + "\nENRICHED_ENVELOPE JSON:\n" + string(payload) + "\n")
	default:
		return Verdict{}, fmt.Errorf("cli agent: unknown input mode %q", opts.Input)
	}
	args := make([]string, len(opts.Args))
	for i, arg := range opts.Args {
		args[i] = strings.ReplaceAll(arg, "{prompt}", prompt)
	}
	opts.Args = args

	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	var out []byte
	if opts.Run != nil {
		out, err = opts.Run(runCtx, opts.Command, opts.Args...)
	} else {
		out, err = runWithStdin(runCtx, opts, input)
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
	if verdict.FlowID != "" && verdict.FlowID != env.Event.FlowID {
		return Verdict{}, fmt.Errorf("cli agent returned a different flow_id")
	}
	if verdict.FlowID == "" {
		verdict.FlowID = env.Event.FlowID
	}
	if !validSeverity(verdict.Severity) || strings.TrimSpace(verdict.Action) == "" || strings.TrimSpace(verdict.Summary) == "" {
		return Verdict{}, fmt.Errorf("cli agent returned an incomplete verdict")
	}
	return verdict, nil
}

// runWithStdin invokes the command with input on stdin. Diagnostics on stderr
// are kept separate from the agent's final answer on stdout.
func runWithStdin(ctx context.Context, opts CLIOptions, stdin []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, opts.Command, opts.Args...)
	cmd.Dir = opts.Dir
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	// One extra byte distinguishes an exactly 1 MiB answer from an oversized one.
	cmd.Stdout = &limitedBuffer{buf: &stdout, limit: 1 << 20}
	cmd.Stderr = &stderr
	if len(opts.Env) > 0 {
		cmd.Env = append(os.Environ(), opts.Env...)
	}
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if stdout.Len() > 1<<20 {
		return nil, fmt.Errorf("cli agent: response exceeds 1 MiB")
	}
	return stdout.Bytes(), nil
}

// limitedBuffer discards output beyond limit while retaining one overflow byte.
// The command can finish normally, but the oversized answer is never buffered
// without bound or accepted as a verdict.
type limitedBuffer struct {
	buf   *bytes.Buffer
	limit int
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := w.limit + 1 - w.buf.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = w.buf.Write(p)
	}
	return n, nil
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

// extractVerdict finds a balanced JSON verdict object, skipping unrelated JSON
// objects and braces inside strings.
func extractVerdict(s string) (Verdict, bool) {
	depth := 0
	start := -1
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
			if depth == 0 {
				start = i
			}
			depth++
		case '}':
			if depth == 0 {
				continue
			}
			depth--
			if depth == 0 {
				if v, ok := tryVerdict([]byte(s[start : i+1])); ok {
					return v, true
				}
				depth = 0
			}
		}
	}
	return Verdict{}, false
}

// BuildPrompt returns agent instructions for a CLI prompt argument. Event data
// stays on stdin so it is not exposed in the process argument list.
func BuildPrompt(_ EnrichedEnvelope) string {
	var b strings.Builder
	b.WriteString("You are a security triage agent for a live network gateway.\n")
	b.WriteString("Analyze the ENRICHED_ENVELOPE JSON provided on stdin. If Vigilante should handle your verdict, respond with ONLY a JSON object:\n")
	b.WriteString("{\"flow_id\":\"...\",\"severity\":\"info|low|medium|high|critical\",\n")
	b.WriteString("\"action\":\"your recommended action\",\"summary\":\"...\",\n")
	b.WriteString("\"findings\":[{\"subject\":\"...\",\"claim\":\"...\",\"evidence\":[\"...\"],\"sources\":[\"...\"],\"confidence\":\"...\"}],\"recommendations\":[\"...\"]}\n")
	b.WriteString("Investigate independently. An installed dependency does not prove exposure or reachability. State uncertainty and cite evidence for vulnerability claims.\n\n")
	b.WriteString("If your agent stores or delivers its own result, it may exit successfully without output.\n")
	return b.String()
}
