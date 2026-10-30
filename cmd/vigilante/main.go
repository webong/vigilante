// Command vigilante brings an agent into the network stack by mirroring incoming
// HTTP/TCP traffic into a non-blocking pipeline, enriching each flow with OS,
// server process, network topology, application dependency graphs, and indexed
// GitHub/local codebase context via github.com/webong/ext, and dispatching it
// to an ext.plugin/v1 agent.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/webong/ext/res/system"
	"github.com/webong/ext/res/system/graph"
	"github.com/webong/ext/res/system/supervisor"
	"github.com/webong/vigilante/ext/agent"
	"github.com/webong/vigilante/ext/executor"
	"github.com/webong/vigilante/ext/obs"
	"github.com/webong/vigilante/ext/triage"
	"github.com/webong/vigilante/internal/action"
	blockaction "github.com/webong/vigilante/internal/action/block"
	"github.com/webong/vigilante/internal/action/remote"
	responseaction "github.com/webong/vigilante/internal/action/response"
	"github.com/webong/vigilante/internal/actor"
	"github.com/webong/vigilante/internal/alert"
	"github.com/webong/vigilante/internal/behavior"
	"github.com/webong/vigilante/internal/block"
	"github.com/webong/vigilante/internal/correlator"
	"github.com/webong/vigilante/internal/decision"
	"github.com/webong/vigilante/internal/deps"
	"github.com/webong/vigilante/internal/egress"
	"github.com/webong/vigilante/internal/flow"
	policygate "github.com/webong/vigilante/internal/gate"
	"github.com/webong/vigilante/internal/gateway"
	"github.com/webong/vigilante/internal/history"
	"github.com/webong/vigilante/internal/policy"
	"github.com/webong/vigilante/internal/repo"
	httpResponse "github.com/webong/vigilante/internal/response"
	"github.com/webong/vigilante/internal/schema"
	"github.com/webong/vigilante/internal/status"
	"github.com/webong/vigilante/pkg/ingress"
	"github.com/webong/vigilante/pkg/tap"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "vigilante:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	args = normalizeCommand(args)
	fs := flag.NewFlagSet("vigilante", flag.ContinueOnError)
	fs.SetOutput(out)

	mode := fs.String("mode", "demo", "Placement: passive, reverse, middle, inline; utilities: demo, eval, agent-test; legacy modes remain supported")
	protocol := fs.String("protocol", "http", "Protocol for reverse mode: http or tcp")
	decoderCommand := fs.String("decoder-command", "", "Local decoder executable emitting PacketEvent JSONL")
	var decoderArgs stringListFlag
	fs.Var(&decoderArgs, "decoder-arg", "Decoder argv element (repeatable)")
	tlsKeyLog := fs.String("tls-keylog", "", "Local application-exported TLS session key log for TShark")
	tlsKeyCredential := fs.String("tls-keylog-credential", "", "CTX credential space:item containing a TLS key-log snapshot")
	captureFile := fs.String("capture-file", "", "PCAP/PCAPNG to decode with TShark in passive mode")
	decodeTLS := fs.Bool("decode-tls", false, "Enable local TShark observation alongside inline or instead of passive capture")
	inlineQueue := fs.Int("inline-queue", 100, "Linux NFQUEUE number for inline interception")
	transports := fs.String("transports", "all", "Inline IP protocols to inspect and enforce: all or tcp,udp,icmp,icmpv6,sctp,gre,esp,ah or numeric IDs")
	passiveIface := fs.String("passive-iface", "", "Interface to passively sniff in -mode passive (e.g. eth0; requires root/CAP_NET_RAW)")
	passivePorts := fs.String("passive-ports", "", "Comma-separated ports to capture in -mode passive (empty = all)")
	listenAddr := fs.String("listen", "127.0.0.1:8080", "Address for vigilante middleware to listen on")
	sidecarListen := fs.String("sidecar-listen", "127.0.0.1:9090", "Listen address for -mode sidecar (ingress decision API: /v1/decide, /v1/check, /v1/observe)")
	sidecarToken := fs.String("sidecar-token", "", "Bearer token required by -mode sidecar (prefer VIGILANTE_SIDECAR_TOKEN; required for a non-loopback bind)")
	sidecarAllowRemote := fs.Bool("sidecar-allow-remote", false, "Allow -sidecar-listen to bind a non-loopback address (requires -sidecar-token)")
	sidecarCacheTTL := fs.Duration("sidecar-cache-ttl", time.Second, "Memoize cacheable decisions for repeat requests sharing method/host/path/query/client address (0 disables)")
	targetAddr := fs.String("target", "http://127.0.0.1:9000", "Upstream server URL (for http/gateway/sidecar) or host:port (for tcp)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file for HTTPS on -listen (http/gateway modes)")
	tlsKey := fs.String("tls-key", "", "TLS private key file for HTTPS on -listen (http/gateway modes)")
	plannerURL := fs.String("planner-url", "", "Optional upstream gateway/route-planner URL for route decisions (gateway mode)")
	plannerToken := fs.String("planner-token", "", "Internal token for the upstream route planner (gateway mode)")
	gatewayPosture := fs.String("gateway", "local", "Gateway posture: local (Vigilante's own ingress, default) or external:<url> (attach to an ingress running elsewhere — recommended if you already run one)")
	policyFile := fs.String("policy", "", "Path to a policy file (YAML/JSON) with allow/deny/block rules")
	policyWatch := fs.Bool("policy-watch", true, "Reload a file-based policy when it changes on disk, and on SIGHUP (no restart, no dropped connections)")
	evalCorpus := fs.String("eval-corpus", "", "Labelled JSONL corpus for -mode eval (one case per line)")
	evalJSON := fs.Bool("eval-json", false, "Emit the -mode eval report as a single JSON object")
	evalMinRecall := fs.Float64("eval-min-recall", 0, "Fail -mode eval when recall is below this value (0 = no gate)")
	evalMaxFPR := fs.Float64("eval-max-fpr", 1, "Fail -mode eval when the false-positive rate exceeds this value (1 = no gate)")
	obsEnabled := fs.Bool("obs", true, "Enable the obs ext plugin (dashboard at /obs/dashboard + JSON API), when an alert store is present")
	blockMode := fs.String("block-mode", "log", "Block enforcement mode: log (dry-run), iptables, or nft")
	blockChain := fs.String("block-chain", "VIGILANTE", "iptables/nft chain name for block enforcement")
	blockThreshold := fs.Int("block-threshold", 0, "Auto-block a source after N qualifying verdicts within -block-window (0 = disabled)")
	blockWindow := fs.Duration("block-window", time.Minute, "Sliding window for -block-threshold")
	blockMinSev := fs.String("block-min-severity", "high", "Lowest verdict severity counted toward -block-threshold")
	actorWindow := fs.Duration("actor-window", 24*time.Hour, "Sliding window over which an actor's risk score is computed")
	actorRiskThreshold := fs.Int("actor-risk-threshold", 50, "Risk score at or above which an actor is flagged suspicious")
	actorMax := fs.Int("actor-max", 10000, "Maximum number of actors to retain before evicting the least recently seen")
	actionAllow := fs.String("action-allow", "block", "Comma-separated action ids the host may execute; empty denies every action")
	actionDryRun := fs.Bool("action-dry-run", false, "Force every action into dry-run: report what would happen, enforce nothing")
	actionTTL := fs.Duration("action-ttl", time.Hour, "Default lifetime of an applied action before it is reverted")
	actionMaxTTL := fs.Duration("action-max-ttl", 24*time.Hour, "Host ceiling on any action's lifetime")
	actionWebhook := fs.String("action-webhook", "", "Optional remote action endpoint (e.g. a WAF API); enables the notify action")
	actionWebhookBody := fs.String("action-webhook-body", "", "JSON body template for -action-webhook ({target},{scope},{reason},{ttl})")
	actionWebhookRevert := fs.String("action-webhook-revert", "", "Revert URL template for -action-webhook ({ref}) so expiring decisions undo themselves")
	var actionPlugins stringListFlag
	fs.Var(&actionPlugins, "action-plugin", "vigilante.action@v1 executor binary to launch under the supervisor; repeat for each (still subject to -action-allow)")
	actionWebhookToken := fs.String("action-webhook-token", "", "Bearer token sent to -action-webhook (prefer the config file over argv)")
	alertFile := fs.String("alert-file", "", "Path to the JSONL alert store (enables persistence; rotated by size)")
	alertMinSev := fs.String("alert-min-severity", "", "Minimum verdict severity to record/deliver: info, low, medium, high, critical")
	alertDeliver := fs.String("alert-deliver-url", "", "Webhook URL to POST alerts to (direct when no planner is configured)")
	alertMaxBytes := fs.Int64("alert-max-bytes", 10<<20, "Rotate the alert file after this many bytes")
	alertKeep := fs.Int("alert-keep", 3, "Number of rotated alert files to retain")
	sampleRate := fs.Float64("sample-rate", 1.0, "Fraction [0,1] of mirrored flows dispatched to the agent (<=0 or 1 = all); sampling never affects primary traffic")
	repoTarget := fs.String("repo", ".", "Git repo target to index for codebase awareness: any host URL (https/ssh/git/file://, scp-like git@host:path), owner/repo or host/owner/repo shorthand, a local path, or \"auto\" to discover the target service's source root from -target")
	repoRef := fs.String("repo-ref", "", "Branch or tag to shallow-clone for -repo (empty = remote default branch)")
	repoUser := fs.String("repo-user", "", "HTTPS username for private -repo clones (default: x-access-token, or VIGILANTE_GIT_USER)")
	repoToken := fs.String("repo-token", "", "HTTPS auth token for private -repo clones (prefer the VIGILANTE_GIT_TOKEN env var to keep it out of argv)")
	repoSSHKey := fs.String("repo-ssh-key", "", "Path to an SSH private key for private ssh:// or git@ clones of -repo (default: VIGILANTE_GIT_SSH_KEY env var / ssh-agent)")
	graphFile := fs.String("graph-file", "", "Optional path to persist the ext + vigilante graph JSON store")
	queueSize := fs.Int("queue-size", 256, "Bounded packet mirror ring-buffer capacity")
	supervisedAgent := fs.Bool("supervised-agent", false, "Launch agent out-of-process via ext/res/system/supervisor + jsonline IPC (equivalent to -agent supervised)")
	agentKind := fs.String("agent", "", "Agent kind: opencode, claude, codex, builtin, cli:<command>, remote:<https-url>, or supervised")
	agentCommand := fs.String("agent-command", "", "Executable for -agent cli or to override a named preset")
	agentDir := fs.String("agent-dir", "", "Working directory for CLI agent skills and configuration")
	agentInput := fs.String("agent-input", "", "CLI stdin format: json or prompt (presets default to prompt)")
	var agentArgs stringListFlag
	fs.Var(&agentArgs, "agent-arg", "CLI argument; repeat for each argv element; {prompt} inserts triage instructions")
	agentTimeout := fs.Duration("agent-timeout", 30*time.Second, "Per-triage timeout for CLI or remote agent")
	agentIPC := fs.String("agent-ipc", "", "Internal IPC address when running in -mode agent-worker")
	var configPaths stringListFlag
	historyFile := fs.String("history-file", "", "SQLite evidence store for flows, actors, review and egress")
	historyRetention := fs.Duration("history-retention", 7*24*time.Hour, "How long retained evidence is kept")
	behaviorEnabled := fs.Bool("behavior", false, "Enable asynchronous behavioral actor analysis")
	identityVerify := fs.Bool("identity-verify", false, "Verify crawler DNS and Web Bot Auth identities")
	behaviorMinScore := fs.Int("behavior-min-score", 80, "Minimum behavior score for a review suggestion")
	triageEnabled := fs.Bool("triage", false, "Send interesting actors to an LLM for classification before suggesting enforcement")
	triageProvider := fs.String("triage-provider", "openrouter", "LLM provider: openrouter or anthropic")
	triageAPIKey := fs.String("triage-api-key", "", "LLM API key (env VIGILANTE_TRIAGE_API_KEY)")
	triageModel := fs.String("triage-model", "", "LLM model (provider default if unset)")
	triageMinScore := fs.Int("triage-min-score", 25, "Minimum behavior score that sends an actor to LLM triage")
	triageEffort := fs.String("triage-effort", "", "Reasoning effort: low, medium or high")
	egressEnabled := fs.Bool("egress", false, "Observe outbound TCP connections with Linux eBPF")
	obsToken := fs.String("obs-token", "", "Bearer token for authenticated history and review APIs")
	httpChallenge := fs.Bool("http-challenge", false, "Enable proof-of-work challenge responses")
	httpRateLimit := fs.Bool("http-rate-limit", false, "Enable in-process rate-limit responses")
	httpRateRPM := fs.Int("http-rate-rpm", 60, "Requests per minute for in-process rate limiting")
	trustProxy := fs.String("trust-proxy", "", "Comma-separated proxy CIDRs trusted to supply X-Forwarded-For")
	fs.Var(&configPaths, "config", "Config file (YAML or JSON); repeat in order, later files override earlier files; CLI flags win")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Apply config-file values for any flag the user did not set explicitly
	// (CLI flags always win). Each key maps to its flag.
	cfg, err := loadConfigs(configPaths)
	if err != nil {
		return err
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	applyStr := func(flagSet bool, dst *string, val string) {
		if !flagSet && val != "" {
			*dst = val
		}
	}
	applyInt := func(flagSet bool, dst *int, val int) {
		if !flagSet && val != 0 {
			*dst = val
		}
	}
	applyInt64 := func(flagSet bool, dst *int64, val int64) {
		if !flagSet && val != 0 {
			*dst = val
		}
	}
	applyDur := func(flagSet bool, dst *time.Duration, val time.Duration) {
		if !flagSet && val != 0 {
			*dst = val
		}
	}
	applyBool := func(flagSet bool, dst *bool, val *bool) {
		if !flagSet && val != nil {
			*dst = *val
		}
	}
	applyStr(set["mode"], mode, cfg.Mode)
	applyStr(set["protocol"], protocol, cfg.Protocol)
	applyStr(set["decoder-command"], decoderCommand, cfg.DecoderCommand)
	applyStr(set["tls-keylog"], tlsKeyLog, cfg.TLSKeyLog)
	applyStr(set["tls-keylog-credential"], tlsKeyCredential, cfg.TLSKeyLogCredential)
	applyStr(set["capture-file"], captureFile, cfg.CaptureFile)
	applyBool(set["decode-tls"], decodeTLS, cfg.DecodeTLS)
	if !set["decoder-arg"] {
		decoderArgs = append(decoderArgs, cfg.DecoderArgs...)
	}
	applyStr(set["transports"], transports, cfg.Transports)
	applyStr(set["agent"], agentKind, cfg.Agent)
	applyStr(set["agent-command"], agentCommand, cfg.AgentCommand)
	applyStr(set["agent-dir"], agentDir, cfg.AgentDir)
	applyStr(set["agent-input"], agentInput, cfg.AgentInput)
	if !set["agent-arg"] {
		agentArgs = append(agentArgs, cfg.AgentArgs...)
	}
	if !set["action-plugin"] {
		actionPlugins = append(actionPlugins, cfg.ActionPlugins...)
	}
	applyStr(set["gateway"], gatewayPosture, cfg.Gateway)
	applyStr(set["listen"], listenAddr, cfg.Listen)
	applyStr(set["sidecar-listen"], sidecarListen, cfg.SidecarListen)
	applyStr(set["sidecar-token"], sidecarToken, cfg.SidecarToken)
	applyBool(set["sidecar-allow-remote"], sidecarAllowRemote, cfg.SidecarAllowRemote)
	if !set["sidecar-cache-ttl"] && cfg.SidecarCacheTTLSet {
		*sidecarCacheTTL = cfg.SidecarCacheTTL
	}
	applyStr(set["target"], targetAddr, cfg.Target)
	applyStr(set["repo"], repoTarget, cfg.Repo)
	applyStr(set["repo-ref"], repoRef, cfg.RepoRef)
	applyStr(set["repo-user"], repoUser, cfg.RepoUser)
	applyStr(set["repo-token"], repoToken, cfg.RepoToken)
	applyStr(set["repo-ssh-key"], repoSSHKey, cfg.RepoSSHKey)
	applyStr(set["tls-cert"], tlsCert, cfg.TLSCert)
	applyStr(set["tls-key"], tlsKey, cfg.TLSKey)
	applyStr(set["planner-url"], plannerURL, cfg.PlannerURL)
	applyStr(set["planner-token"], plannerToken, cfg.PlannerToken)
	applyStr(set["policy"], policyFile, cfg.Policy)
	applyBool(set["policy-watch"], policyWatch, cfg.PolicyWatch)
	applyStr(set["eval-corpus"], evalCorpus, cfg.EvalCorpus)
	applyBool(set["eval-json"], evalJSON, cfg.EvalJSON)
	if !set["eval-min-recall"] && cfg.EvalMinRecallSet {
		*evalMinRecall = cfg.EvalMinRecall
	}
	if !set["eval-max-fpr"] && cfg.EvalMaxFPRSet {
		*evalMaxFPR = cfg.EvalMaxFPR
	}
	applyStr(set["block-mode"], blockMode, cfg.BlockMode)
	applyStr(set["block-chain"], blockChain, cfg.BlockChain)
	applyStr(set["block-min-severity"], blockMinSev, cfg.BlockMinSeverity)
	applyStr(set["action-allow"], actionAllow, cfg.ActionAllow)
	applyStr(set["action-webhook"], actionWebhook, cfg.ActionWebhook)
	applyStr(set["action-webhook-body"], actionWebhookBody, cfg.ActionWebhookBody)
	applyStr(set["action-webhook-revert"], actionWebhookRevert, cfg.ActionWebhookRevert)
	applyStr(set["action-webhook-token"], actionWebhookToken, cfg.ActionWebhookToken)
	applyStr(set["alert-file"], alertFile, cfg.AlertFile)
	applyStr(set["alert-deliver-url"], alertDeliver, cfg.AlertDeliver)
	applyStr(set["alert-min-severity"], alertMinSev, cfg.AlertMinSeverity)
	applyStr(set["graph-file"], graphFile, cfg.GraphFile)
	applyStr(set["passive-iface"], passiveIface, cfg.PassiveIface)
	applyStr(set["passive-ports"], passivePorts, cfg.PassivePorts)

	applyInt(set["block-threshold"], blockThreshold, cfg.BlockThreshold)
	applyInt(set["alert-keep"], alertKeep, cfg.AlertKeep)
	applyInt(set["queue-size"], queueSize, cfg.QueueSize)
	applyInt(set["actor-risk-threshold"], actorRiskThreshold, cfg.ActorRiskThreshold)
	applyInt(set["actor-max"], actorMax, cfg.ActorMax)
	applyInt64(set["alert-max-bytes"], alertMaxBytes, cfg.AlertMaxBytes)
	applyDur(set["block-window"], blockWindow, cfg.BlockWindow)
	applyDur(set["agent-timeout"], agentTimeout, cfg.AgentTimeout)
	applyDur(set["action-ttl"], actionTTL, cfg.ActionTTL)
	applyDur(set["action-max-ttl"], actionMaxTTL, cfg.ActionMaxTTL)
	applyDur(set["actor-window"], actorWindow, cfg.ActorWindow)
	applyStr(set["history-file"], historyFile, cfg.HistoryFile)
	applyDur(set["history-retention"], historyRetention, cfg.HistoryRetention)
	applyBool(set["behavior"], behaviorEnabled, cfg.Behavior)
	applyBool(set["identity-verify"], identityVerify, cfg.IdentityVerify)
	applyInt(set["behavior-min-score"], behaviorMinScore, cfg.BehaviorMinScore)
	applyBool(set["triage"], triageEnabled, cfg.Triage)
	applyStr(set["triage-provider"], triageProvider, cfg.TriageProvider)
	applyStr(set["triage-api-key"], triageAPIKey, cfg.TriageAPIKey)
	applyStr(set["triage-model"], triageModel, cfg.TriageModel)
	applyInt(set["triage-min-score"], triageMinScore, cfg.TriageMinScore)
	applyStr(set["triage-effort"], triageEffort, cfg.TriageEffort)
	applyBool(set["egress"], egressEnabled, cfg.Egress)
	applyStr(set["obs-token"], obsToken, cfg.ObsToken)
	applyBool(set["http-challenge"], httpChallenge, cfg.HTTPChallenge)
	applyBool(set["http-rate-limit"], httpRateLimit, cfg.HTTPRateLimit)
	applyInt(set["http-rate-rpm"], httpRateRPM, cfg.HTTPRateRPM)
	applyStr(set["trust-proxy"], trustProxy, cfg.TrustProxy)
	if *obsToken == "" {
		*obsToken = os.Getenv("VIGILANTE_OBS_TOKEN")
	}
	if *triageAPIKey == "" {
		*triageAPIKey = os.Getenv("VIGILANTE_TRIAGE_API_KEY")
	}
	trustedProxies, err := parseTrustedProxies(*trustProxy)
	if err != nil {
		return err
	}
	var responseHandler httpResponse.Handler
	if *httpChallenge {
		responseHandler.Challenge = httpResponse.NewChallenger()
	}
	if *httpRateLimit {
		responseHandler.Limits = httpResponse.NewLimiter(*httpRateRPM)
	}
	if !set["sample-rate"] && cfg.SampleRate > 0 {
		*sampleRate = cfg.SampleRate
	}
	if !set["obs"] && cfg.Obs != nil {
		*obsEnabled = *cfg.Obs
	}
	if !set["action-dry-run"] && cfg.ActionDryRun != nil {
		*actionDryRun = *cfg.ActionDryRun
	}
	if !set["supervised-agent"] && cfg.Supervised {
		*supervisedAgent = true
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx = withResponseRuntime(ctx, responseHandler)
	decoderEnabled := *decodeTLS || *tlsKeyLog != "" || *captureFile != "" || *decoderCommand != "" || *tlsKeyCredential != ""
	if decoderEnabled && *mode != "passive" && *mode != "inline" {
		return fmt.Errorf("decoder options require passive or inline mode")
	}
	if *mode == "inline" && *captureFile != "" {
		return fmt.Errorf("capture-file requires passive mode")
	}
	switch *mode {
	case "reverse":
		if *protocol != "http" && *protocol != "tcp" {
			return fmt.Errorf("reverse protocol must be http or tcp")
		}
		*mode = *protocol
	case "middle":
		*mode = "sidecar"
	case "inline":
		if *inlineQueue < 0 || *inlineQueue > 65535 {
			return fmt.Errorf("inline queue must be between 0 and 65535")
		}
	}

	if *mode == "eval" {
		return runEval(ctx, out, *evalCorpus, *evalJSON, *evalMinRecall, *evalMaxFPR)
	}
	if *mode == "agent-test" {
		return runAgentTest(ctx, out, agentDispatchOptions{
			Kind: *agentKind, Command: *agentCommand, Args: []string(agentArgs),
			Input: *agentInput, Dir: *agentDir, Timeout: *agentTimeout,
		})
	}

	if *mode == "agent-worker" {
		if *agentIPC == "" {
			return fmt.Errorf("-agent-ipc is required for -mode agent-worker")
		}
		return agent.RunWorkerIPC(ctx, *agentIPC, nil)
	}

	var store graph.Store
	if *graphFile != "" {
		store, err = graph.OpenFile(*graphFile)
		if err != nil {
			return fmt.Errorf("open graph file: %w", err)
		}
	} else {
		store = graph.NewMemory()
	}
	defer store.Close()

	sysGraph, err := system.New(store)
	if err != nil {
		return fmt.Errorf("init ext.system graph: %w", err)
	}

	// Auto-discovery: when -repo is "auto" (or empty), infer the target's
	// source root from -target (port -> listening PID -> open cwd / checkout).
	target := strings.TrimSpace(*targetAddr)
	if t := strings.ToLower(strings.TrimSpace(*repoTarget)); t == "auto" || t == "" {
		if root := repo.DiscoverRoot(ctx, target); root != "" {
			fmt.Fprintf(out, "[vigilante] discovered codebase root %s for target %s\n", root, target)
			*repoTarget = root
		} else {
			fmt.Fprintf(out, "[vigilante] auto repo discovery found no source root for %s; codebase context disabled\n", orDash(target))
			*repoTarget = ""
		}
	}

	var repoIdx *repo.Index
	if *repoTarget != "" {
		repoOpts := repo.Options{
			Ref:    *repoRef,
			User:   firstNonEmpty(*repoUser, os.Getenv("VIGILANTE_GIT_USER")),
			Token:  firstNonEmpty(*repoToken, os.Getenv("VIGILANTE_GIT_TOKEN")),
			SSHKey: firstNonEmpty(*repoSSHKey, os.Getenv("VIGILANTE_GIT_SSH_KEY")),
		}
		fmt.Fprintf(out, "[vigilante] indexing codebase repository %q...", *repoTarget)
		sshTarget := strings.HasPrefix(*repoTarget, "git@") || strings.HasPrefix(*repoTarget, "ssh://")
		switch {
		case repoOpts.Token != "" && !sshTarget:
			fmt.Fprintln(out, " (auth: HTTPS token via GIT_ASKPASS helper)")
		case repoOpts.SSHKey != "" && sshTarget:
			fmt.Fprintf(out, " (auth: ssh key %s)\n", repoOpts.SSHKey)
		default:
			fmt.Fprintln(out, " (auth: configured git credential helpers / ssh-agent)")
		}
		repoIdx, err = repo.OpenWithOptions(ctx, *repoTarget, repoOpts)
		if err != nil {
			return fmt.Errorf("index repo %q: %w", *repoTarget, err)
		}
		defer repoIdx.Close()
		snap := repoIdx.Snapshot()
		fmt.Fprintf(out, "[vigilante] codebase indexed: %d files, %d routes, %d sinks (commit %s, tree %s...)\n",
			snap.FileCount, len(snap.Routes), len(snap.Sinks), snap.Commit, shortHash(snap.TreeDigest))
	}

	// The enforcement snapshot the request path reads. Stateful consumers
	// (operators, a console plugin, remote actions) write into it; entries are
	// always time-bounded, so a dead writer cannot pin a rule forever.
	decisions := decision.NewSet()

	var polGate tap.PolicyGate
	var polEngine *policy.Engine
	var enforcer *block.Enforcer
	var threshold *block.Threshold
	switch {
	case *policyFile != "":
		engine, err := policy.Load(*policyFile)
		if err != nil {
			return err
		}
		polEngine = engine
		fmt.Fprintf(out, "[vigilante] policy loaded from %s (%d rules)\n", *policyFile, engine.RuleCount())
	case cfg.PolicyEngine != nil:
		polEngine = cfg.PolicyEngine
		fmt.Fprintf(out, "[vigilante] policy loaded inline from config (%d rules)\n", polEngine.RuleCount())
	}
	if polEngine != nil {
		polGate = func(r *http.Request) string {
			return string(polEngine.Evaluate(r).Action)
		}
	}
	// File-based policies reload without a restart: a 2s stat loop catches an
	// edited file, and SIGHUP forces an immediate reload. A failed reload keeps
	// the previous rules in force, so a typo can never widen access.
	if polEngine != nil && *policyFile != "" {
		polEngine.SetReloadHook(func(err error) {
			if err != nil {
				fmt.Fprintf(out, "[vigilante] policy reload FAILED, keeping previous rules: %v\n", err)
				return
			}
			fmt.Fprintf(out, "[vigilante] policy reloaded from %s (%d rules, cache invalidated)\n", *policyFile, polEngine.RuleCount())
		})
		if *policyWatch {
			polEngine.Watch(ctx, 2*time.Second)
			fmt.Fprintln(out, "[vigilante] policy watch active (2s; SIGHUP reloads immediately)")
		}
		sighup := make(chan os.Signal, 1)
		signal.Notify(sighup, syscall.SIGHUP)
		go func() {
			for {
				select {
				case <-ctx.Done():
					signal.Stop(sighup)
					return
				case <-sighup:
					_ = polEngine.Reload()
				}
			}
		}()
	}
	// Static policy first, then the live snapshot. The snapshot can only make
	// the outcome stricter, never loosen a configured rule.
	polGate = policygate.New(policygate.Options{Policy: polGate, Set: decisions, Responses: map[string]bool{"challenge": *httpChallenge, "rate_limit": *httpRateLimit}})
	baseGate := polGate
	polGate = func(r *http.Request) string {
		if r.URL.Path == httpResponse.ChallengePath {
			return "allow"
		}
		r = trustedRequest(r, trustedProxies)
		return baseGate(r)
	}
	{
		var err error
		enforcer, err = block.New(block.Options{
			Mode:  block.Mode(*blockMode),
			Chain: *blockChain,
			OnBlock: func(ip net.IP, rule string) {
				fmt.Fprintf(out, "[vigilante] BLOCK enforced (%s) ip=%s rule=%s\n", *blockMode, ip, rule)
			},
			OnUnblock: func(ip net.IP) {
				fmt.Fprintf(out, "[vigilante] BLOCK reverted (%s) ip=%s\n", *blockMode, ip)
			},
		})
		if err != nil {
			return err
		}
		threshold = block.NewThreshold(block.ThresholdConfig{
			Count:       *blockThreshold,
			Window:      *blockWindow,
			MinSeverity: *blockMinSev,
		}, enforcer)
		if threshold != nil {
			fmt.Fprintf(out, "[vigilante] dynamic block threshold: %d %s+ verdicts/%s per source\n",
				*blockThreshold, *blockMinSev, *blockWindow)
		}
	}

	// The action registry is the host's response authority. Only the ids in
	// -action-allow may run, every decision is audited, and every applied
	// decision is pushed into the snapshot the gate reads.
	registry := action.New(action.Options{
		Set:        decisions,
		Allow:      splitCSV(*actionAllow),
		DryRun:     *actionDryRun,
		DefaultTTL: *actionTTL,
		MaxTTL:     *actionMaxTTL,
		OnDecision: func(d action.Decision) {
			fmt.Fprintf(out, "[vigilante] ACTION %s %s scope=%s target=%s decision=%s expires=%s %s\n",
				d.Action, d.Status, d.Scope, d.Target, d.ID,
				orNever(d.ExpiresAt), orDash(d.Detail))
		},
		OnRevert: func(d action.Decision, err error) {
			if err != nil {
				fmt.Fprintf(out, "[vigilante] ACTION revert failed %s: %v\n", d.ID, err)
				return
			}
			fmt.Fprintf(out, "[vigilante] ACTION reverted %s (%s %s)\n", d.ID, d.Action, d.Target)
		},
	})
	if ba := blockaction.New(enforcer); ba != nil {
		if err := registry.Register(ba); err != nil {
			return err
		}
	}
	for _, kind := range []string{"challenge", "rate_limit"} {
		if (kind == "challenge" && *httpChallenge) || (kind == "rate_limit" && *httpRateLimit) {
			if err := registry.Register(responseaction.New(kind)); err != nil {
				return err
			}
		}
	}
	if *actionWebhook != "" {
		headers := map[string]string{}
		if *actionWebhookToken != "" {
			headers["Authorization"] = "Bearer " + *actionWebhookToken
		}
		re, err := remote.New(remote.Options{
			ID:           "notify",
			Label:        "Notify / remote action",
			Description:  "Call an external API (WAF, load balancer, ticketing, on-call) to respond to this flow.",
			Scopes:       []decision.Scope{decision.ScopeIP, decision.ScopeCIDR, decision.ScopeActor, decision.ScopeFingerprint},
			URL:          *actionWebhook,
			BodyTemplate: *actionWebhookBody,
			RevertURL:    *actionWebhookRevert,
			Headers:      headers,
			DefaultTTL:   *actionTTL,
			MaxTTL:       *actionMaxTTL,
			Destructive:  true,
		})
		if err != nil {
			return err
		}
		if err := registry.Register(re); err != nil {
			return err
		}
	}
	for _, cmd := range actionPlugins {
		client, err := executor.Launch(ctx, executor.LaunchOptions{Store: store, Command: cmd})
		if err != nil {
			return fmt.Errorf("launch action plugin %s: %w", cmd, err)
		}
		defer func() { _ = client.Close(context.Background()) }()
		if err := registry.Register(client); err != nil {
			return fmt.Errorf("register action plugin %s: %w", cmd, err)
		}
		fmt.Fprintf(out, "[vigilante] action plugin %s: %s (ext.plugin/v1 vigilante.action@v1)\n", client.Capability().ID, cmd)
	}
	stopReaper := registry.StartReaper(ctx, 30*time.Second)
	defer stopReaper()
	caps := make([]string, 0, len(registry.Capabilities()))
	for _, c := range registry.Capabilities() {
		state := "available"
		if !registry.Allowed(c.ID) {
			state = "registered, not allowed"
		}
		caps = append(caps, c.ID+" ("+state+")")
	}
	fmt.Fprintf(out, "[vigilante] actions: allow=%v dry-run=%v ttl=%s max=%s capabilities=[%s]\n",
		splitCSV(*actionAllow), *actionDryRun, *actionTTL, *actionMaxTTL, strings.Join(caps, ", "))

	var historyStore *history.Store
	if *historyFile != "" {
		var err error
		historyStore, err = history.Open(*historyFile)
		if err != nil {
			return err
		}
		defer historyStore.Close()
		if *egressEnabled {
			go func() {
				if err := egress.Run(ctx, egress.Options{}, func(ev history.Egress) { _ = historyStore.RecordEgress(context.Background(), ev) }); err != nil && ctx.Err() == nil {
					fmt.Fprintln(out, "[vigilante] egress extension:", err)
				}
			}()
		}
		go runHistoryMaintenance(ctx, historyStore, *historyRetention)
		fmt.Fprintf(out, "[vigilante] history store active: %s\n", *historyFile)
	} else if *behaviorEnabled || *egressEnabled {
		return fmt.Errorf("history-file is required for behavior and egress extensions")
	}
	var alertStore *alert.Store
	if *alertFile != "" || *alertDeliver != "" {
		path := *alertFile
		if path == "" {
			path = filepath.Join(os.TempDir(), "vigilante-alerts.jsonl")
		}
		store, err := alert.Open(alert.Options{
			Path:          path,
			MaxBytes:      *alertMaxBytes,
			KeepFiles:     *alertKeep,
			MinSeverity:   alert.Severity(*alertMinSev),
			DeliverURL:    *alertDeliver,
			PlannerURL:    *plannerURL,
			InternalToken: *plannerToken,
			OnError: func(err error) {
				fmt.Fprintln(out, "[vigilante] alert error:", err)
			},
		})
		if err != nil {
			return err
		}
		alertStore = store
		defer store.Close()
		fmt.Fprintf(out, "[vigilante] alert store active: %s (deliver: %s)\n", path, orDash(*alertDeliver))
	}

	// The actor index aggregates flows into per-actor risk. It is the stateful
	// counterpart to the stateless core, consumed as data (see /obs/actors).
	var actorIdx *actor.Index
	if alertStore != nil {
		actorIdx = actor.NewIndex(*actorWindow, *actorMax)
		actorIdx.SetRiskThreshold(*actorRiskThreshold)
	}

	// Open the obs ext plugin (dashboard + query API) whenever an alert store
	// exists. It reads alerts via the store's Reader; metrics flow into /metrics.
	var obsBridge *obs.Bridge
	var obsClose func(context.Context) error
	var obsMetrics func(http.ResponseWriter)

	// Actor triage is the vigilante.triage@v1 plugin, shared between the
	// behavior sink and the dashboard API. Left as a nil interface when off.
	var triager triage.Service
	if historyStore != nil && *triageEnabled && *triageAPIKey != "" {
		var p triage.Provider
		model := *triageModel
		switch *triageProvider {
		case "anthropic":
			if model == "" {
				model = "claude-opus-5-5"
			}
			p = triage.NewAnthropic(*triageAPIKey, model, *triageEffort)
		default:
			if model == "" {
				model = "deepseek/deepseek-v4.1-flash"
			}
			p = triage.NewOpenRouter("https://openrouter.ai/api/v1", *triageAPIKey, model, *triageEffort)
		}
		client, terr := triage.Open(ctx, triage.New(p, model))
		if terr != nil {
			return fmt.Errorf("open triage plugin: %w", terr)
		}
		defer func() { _ = client.Close(context.Background()) }()
		triager = client
		fmt.Fprintf(out, "[vigilante] triage plugin active: %s (ext.plugin/v1 vigilante.triage@v1)\n", model)
	} else if historyStore != nil && *triageEnabled {
		fmt.Fprintln(out, "[vigilante] triage enabled but no API key set (VIGILANTE_TRIAGE_API_KEY); running rules only")
	}

	if alertStore != nil && *obsEnabled {
		obsSvc := obs.NewService(
			alertStore,
			obsQueueStats(obsQueueProbe),
			alertStore.Stats,
		)
		// Expose the action surface as data (capabilities + active decisions +
		// audit) for any consumer to render. Vigilante ships no UI.
		obsSvc.SetActions(func() obs.ActionsOutput { return actionView(registry) })
		// Expose the actor surface as data for any consumer to render.
		obsSvc.SetActors(func(in obs.ActorsInput) obs.ActorsOutput { return actorView(actorIdx, in) })
		_, bridge, closeFn, oerr := obs.Open(ctx, obsSvc)
		if oerr != nil {
			return fmt.Errorf("open obs plugin: %w", oerr)
		}
		obsBridge, obsClose = bridge, closeFn
		defer func() {
			if obsClose != nil {
				_ = obsClose(context.Background())
			}
		}()
		obsMetrics = func(w http.ResponseWriter) {
			for sev, n := range alertStore.CountBySeverity() {
				fmt.Fprintf(w, "vigilante_alerts_by_severity{severity=%q} %d\n", string(sev), n)
			}
		}
		fmt.Fprintln(out, "[vigilante] obs plugin active: /obs/dashboard, /obs/alerts, /obs/summary, /obs/actions, /obs/actors (ext.plugin/v1 vigilante.obs@v1)")
	}
	// History, review and the web dashboard wrap the obs bridge rather than
	// replace it, so both route sets stay mounted.
	if historyStore != nil && *obsEnabled {
		obsBridge = obs.NewExtensionBridge(obs.Extension{History: historyStore, Actions: registry, Token: *obsToken, Triager: triager}, obsBridge)
	}

	// Flow publication: the stateless core hands each triaged flow to a bounded
	// fan-out. Sinks never backpressure live traffic; a full queue drops and
	// counts. The alert store is the baseline sink; the actor index is the
	// stateful aggregation sink; a custom console is another Sink.
	var publisher *flow.Publisher
	var sinks []flow.Sink
	if alertStore != nil {
		sinks = append(sinks, flow.AlertSink{Store: alertStore}, actorIdx)
	}
	if historyStore != nil {
		if *behaviorEnabled {
			bs := behavior.Sink{Store: historyStore, Verifier: optionalVerifier(*identityVerify), MinScore: *behaviorMinScore, Triager: triager, TriageMinScore: *triageMinScore}
			bs.EnsureTriaged()
			sinks = append(sinks, bs)
		} else {
			sinks = append(sinks, historyStore)
		}
	}
	if len(sinks) > 0 {
		publisher = flow.NewPublisher(sinks, *queueSize, 2)
		defer func() {
			cctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := publisher.Close(cctx); err != nil {
				fmt.Fprintln(out, "[vigilante] flow publisher:", err)
			}
		}()
		fmt.Fprintf(out, "[vigilante] flow publisher active (%d extension sinks)\n", len(sinks))
	}

	var gw *agent.Gateway
	// Resolve the agent kind: explicit -agent wins; -supervised-agent maps to
	// "supervised"; empty means builtin.
	kind, cliCmd := resolveAgentPreset(*agentKind, *agentCommand, (*[]string)(&agentArgs), agentInput)
	if kind == "" && *supervisedAgent {
		kind = "supervised"
	}
	switch kind {
	case "supervised":
		fmt.Fprintln(out, "[vigilante] starting out-of-process supervised agent via github.com/webong/ext/res/system/supervisor...")
		gw, _, err = agent.NewSupervisedGateway(ctx, agent.SupervisedOptions{
			Store:           store,
			Repo:            repoIdx,
			RequireChecksum: true,
		})
	case "cli":
		if *agentCommand != "" {
			cliCmd = *agentCommand
		}
		fmt.Fprintf(out, "[vigilante] CLI agent: %s (timeout %s)\n", orDash(cliCmd), *agentTimeout)
		if cliCmd == "" {
			return fmt.Errorf("-agent cli requires -agent-command or cli:<command>")
		}
		if *agentInput != "json" && *agentInput != "prompt" {
			return fmt.Errorf("-agent-input must be json or prompt")
		}
		cliHandler := agent.NewCLIHandler(agent.CLIOptions{
			Command: cliCmd,
			Args:    []string(agentArgs),
			Input:   *agentInput,
			Dir:     *agentDir,
			Timeout: *agentTimeout,
			OnError: func(err error) {
				fmt.Fprintln(out, "[vigilante] cli agent error (falling back to builtin):", err)
			},
		})
		gw, err = agent.NewInProcessGateway(ctx, store, repoIdx, cliHandler)
	case "remote":
		remoteHandler, remoteErr := agent.NewRemoteHandler(agent.RemoteOptions{
			URL:     cliCmd,
			Token:   os.Getenv("VIGILANTE_AGENT_TOKEN"),
			Timeout: *agentTimeout,
			OnError: func(err error) {
				fmt.Fprintln(out, "[vigilante] remote agent error:", err)
			},
		})
		if remoteErr != nil {
			return remoteErr
		}
		fmt.Fprintf(out, "[vigilante] remote agent: %s (timeout %s)\n", cliCmd, *agentTimeout)
		gw, err = agent.NewInProcessGateway(ctx, store, repoIdx, remoteHandler)
	case "", "builtin":
		if *agentInput != "json" && *agentInput != "prompt" {
			return fmt.Errorf("-agent-input must be json or prompt")
		}
		gw, err = agent.NewInProcessGateway(ctx, store, repoIdx, nil)
	default:
		return fmt.Errorf("unknown agent kind %q", kind)
	}
	if err != nil {
		return fmt.Errorf("init ext.plugin/v1 agent gateway: %w", err)
	}
	defer gw.Close(context.Background())

	corr, err := correlator.New(correlator.Options{
		SystemGraph:    sysGraph,
		Gateway:        gw,
		RemoteBundle:   kind == "remote",
		AdvisoryClient: &deps.OSVClient{},
		Repo:           repoIdx,
		FallbackPID:    os.Getpid(),
		OnVerdict: func(env agent.EnrichedEnvelope, v agent.Verdict) {
			printVerdict(out, env, v)
			// Publish the triaged flow to every sink (alert store, consoles,
			// exporters). Publication is non-blocking: a slow sink can never
			// stall traffic or triage.
			if publisher != nil {
				findings := make([]alert.Finding, 0, len(v.Findings))
				for _, finding := range v.Findings {
					findings = append(findings, alert.Finding{Subject: finding.Subject, Claim: finding.Claim, Evidence: finding.Evidence, Sources: finding.Sources, Confidence: finding.Confidence})
				}
				publisher.Publish(flow.Event{
					Timestamp:       time.Now().UTC(),
					FlowID:          v.FlowID,
					Severity:        v.Severity,
					Verdict:         v.Action,
					Summary:         v.Summary,
					Method:          env.Event.Method,
					Path:            env.Event.Path,
					SrcAddr:         env.Event.SrcAddr,
					TargetAddr:      env.Event.TargetAddr,
					UserAgent:       headerValue(env.Event.Headers, "User-Agent"),
					TLSFingerprint:  env.Event.TLSFingerprint,
					JA4:             env.Event.JA4,
					Protocol:        env.Event.Protocol,
					Host:            env.Event.Host,
					Headers:         env.Event.Headers,
					Status:          env.Event.Status,
					Duration:        env.Event.Duration,
					BytesIn:         env.Event.BytesIn,
					BytesOut:        env.Event.BytesOut,
					Handler:         v.MatchedHandler,
					Advisories:      v.MatchedAdvisories,
					Findings:        findings,
					Recommendations: v.Recommendations,
				})
			}
			// Enforce the agent's recommendation through the action registry:
			// allowlisted, audited, TTL-bounded, and revertible.
			if v.Action == "recommend-block" && registry != nil {
				if _, err := registry.Execute(ctx, action.Request{
					Action:    "block",
					Scope:     decision.ScopeIP,
					Target:    env.Event.SrcAddr,
					Actor:     decision.NormalizeIP(env.Event.SrcAddr),
					Reason:    "agent-verdict:" + v.Severity,
					Operator:  "vigilante/agent",
					Confirmed: true,
					Evidence: map[string]string{
						"flow_id":  v.FlowID,
						"severity": v.Severity,
						"summary":  v.Summary,
					},
				}); err != nil {
					fmt.Fprintln(out, "[vigilante] action failed:", err)
				}
			}
			// Feed the verdict into the dynamic threshold (auto-block after N).
			if threshold != nil && v.Severity != "" && env.Event.SrcAddr != "" {
				if threshold.Observe(ctx, env.Event.SrcAddr, v.Severity) {
					fmt.Fprintf(out, "[vigilante] dynamic threshold crossed: source %s auto-blocked\n", env.Event.SrcAddr)
				}
			}
		},
	})
	if err != nil {
		return fmt.Errorf("init correlator: %w", err)
	}

	fmt.Fprintln(out, "[vigilante] scanning OS, processes, and network topology via github.com/webong/ext/res/system...")
	if err := corr.RefreshBaseline(ctx); err != nil {
		return fmt.Errorf("refresh baseline: %w", err)
	}

	switch *mode {
	case "inline":
		selected, err := tap.ParseProtocols(*transports)
		if err != nil {
			return err
		}
		if decoderEnabled {
			go func() {
				err := tap.RunDecoder(ctx, tap.DecoderOptions{Command: *decoderCommand, Args: decoderArgs, Interface: *passiveIface, KeyLogFile: *tlsKeyLog, KeyLogCredential: *tlsKeyCredential}, func(ev agent.PacketEvent) { _, _ = corr.ProcessPacket(ctx, ev) })
				if err != nil {
					fmt.Fprintf(out, "[vigilante] optional decoder stopped: %v; network enforcement remains active\n", err)
				}
			}()
		}
		queue := tap.NewMirrorQueue(*queueSize)
		queue.SetSampleRate(*sampleRate)
		registerQueue(queue)
		queue.Drain(ctx, 2, func(ctx context.Context, ev agent.PacketEvent) { _, _ = corr.ProcessPacket(ctx, ev) })
		fmt.Fprintf(out, "[vigilante] inline NFQUEUE %d; install scoped netfilter queue rules to select traffic\n", *inlineQueue)
		return tap.RunInline(ctx, uint16(*inlineQueue), queue, polGate, selected)
	case "demo":
		return runDemo(ctx, out, corr, store, *supervisedAgent, *sampleRate)
	case "http":
		return runHTTPProxy(ctx, out, corr, *listenAddr, *targetAddr, *queueSize, *tlsCert, *tlsKey, polGate, alertStore, *sampleRate, obsBridge, obsMetrics)
	case "tcp":
		return runTCPProxy(ctx, out, corr, *listenAddr, *targetAddr, *queueSize, polGate, *sampleRate, *tlsCert, *tlsKey, alertStore, obsBridge, obsMetrics)
	case "middleware":
		return runMiddlewareMode(ctx, out, corr, *listenAddr, *targetAddr, *queueSize, *tlsCert, *tlsKey, polGate, alertStore, *sampleRate, obsBridge, obsMetrics)
	case "sidecar":
		return runSidecar(ctx, out, corr, sidecarOptions{
			Engine:      polEngine,
			Listen:      *sidecarListen,
			Target:      *targetAddr,
			QueueSize:   *queueSize,
			SampleRate:  *sampleRate,
			Token:       firstNonEmpty(*sidecarToken, os.Getenv("VIGILANTE_SIDECAR_TOKEN")),
			AllowRemote: *sidecarAllowRemote,
			CacheTTL:    *sidecarCacheTTL,
		})
	case "gateway":
		gwPosture, gwExternal := splitGatewayArg(*gatewayPosture)
		if gwExternal != "" && *targetAddr == "" {
			// External forwards to the existing gateway, so target is optional.
			*targetAddr = gwExternal
		}
		return runGatewayMode(ctx, out, corr, *listenAddr, *targetAddr, *plannerURL, *plannerToken, *tlsCert, *tlsKey, *queueSize, polGate, alertStore, *sampleRate, gwPosture, gwExternal, obsBridge, obsMetrics)
	case "passive":
		if decoderEnabled {
			iface := *passiveIface
			if *captureFile != "" {
				iface = ""
			}
			return tap.RunDecoder(ctx, tap.DecoderOptions{Command: *decoderCommand, Args: decoderArgs, Interface: iface, CaptureFile: *captureFile, KeyLogFile: *tlsKeyLog, KeyLogCredential: *tlsKeyCredential}, func(ev agent.PacketEvent) { _, _ = corr.ProcessPacket(ctx, ev) })
		}
		return runPassiveMode(ctx, out, corr, *passiveIface, *passivePorts, *queueSize, *sampleRate, alertStore, obsBridge, obsMetrics)
	default:
		return fmt.Errorf("unsupported mode %q (choose demo, http, tcp, middleware, gateway, passive, sidecar, eval, agent-test, or agent-worker)", *mode)
	}
}

// sidecarOptions configures the ingress decision sidecar.
type sidecarOptions struct {
	Engine      *policy.Engine
	Listen      string
	Target      string
	QueueSize   int
	SampleRate  float64
	Token       string
	AllowRemote bool
	CacheTTL    time.Duration
}

// runSidecar serves the ingress decision API used by proxy plugins (Traefik's
// Yaegi middleware, nginx auth_request/mirror, or any external authz client).
// It runs the same policy engine and mirror pipeline as the standalone gateway:
// /v1/decide returns a JSON verdict, /v1/check returns 204/403, and
// /v1/observe only mirrors the request for agent triage.
func runSidecar(ctx context.Context, out io.Writer, corr *correlator.Correlator, opts sidecarOptions) error {
	if !isLoopbackListen(opts.Listen) {
		if !opts.AllowRemote {
			return fmt.Errorf("refusing to bind the sidecar on non-loopback %s: pass -sidecar-allow-remote if the proxy runs on another host", opts.Listen)
		}
		if opts.Token == "" {
			return fmt.Errorf("refusing an unauthenticated non-loopback sidecar on %s: set -sidecar-token or VIGILANTE_SIDECAR_TOKEN", opts.Listen)
		}
	}

	queue := tap.NewMirrorQueue(opts.QueueSize)
	queue.SetSampleRate(opts.SampleRate)

	// Label observations with the upstream host:port so the correlator can map
	// the flow back to the process that owns it.
	labelTarget := opts.Target
	if u, err := url.Parse(opts.Target); err == nil && u.Host != "" {
		labelTarget = u.Host
	}

	decider := ingress.New(ingress.Config{
		Policy:     opts.Engine,
		Queue:      queue,
		ListenAddr: opts.Listen,
		TargetAddr: labelTarget,
		CacheTTL:   opts.CacheTTL,
	})
	queue.Drain(ctx, 2, func(ctx context.Context, ev agent.PacketEvent) {
		_, _ = corr.ProcessPacket(ctx, ev)
	})

	srv := ingress.NewServer(decider, opts.Listen)
	srv.SetToken(opts.Token)
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	auth := "off"
	if opts.Token != "" {
		auth = "bearer"
	}
	fmt.Fprintf(out, "[vigilante] ingress sidecar on %s: /v1/decide (JSON), /v1/check (204/403), /v1/observe (mirror), auth=%s, cache=%s\n",
		opts.Listen, auth, opts.CacheTTL)
	if err := srv.ListenAndServe(); err != nil {
		return err
	}
	return nil
}

// isLoopbackListen reports whether addr binds only a loopback interface. An
// empty host (":9090") means all interfaces and is therefore not loopback.
func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// runMiddlewareMode embeds the Vigilante tap in-process behind an existing
// handler seam (tap.NewMirror): it observes every request and forwards to the
// upstream target, terminating TLS when configured. This is the mode to use
// when Vigilante runs inside the same process as the application.
func runMiddlewareMode(ctx context.Context, out io.Writer, corr *correlator.Correlator, listenAddr, targetRaw string, queueSize int, tlsCert, tlsKey string, gate tap.PolicyGate, alertStore *alert.Store, sampleRate float64, obsB *obs.Bridge, obsM func(http.ResponseWriter)) error {
	if !strings.Contains(targetRaw, "://") {
		targetRaw = "http://" + targetRaw
	}
	targetURL, err := url.Parse(targetRaw)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	queue := tap.NewMirrorQueue(queueSize)
	queue.SetSampleRate(sampleRate)
	registerQueue(queue)
	queue.Drain(ctx, 2, func(ctx context.Context, ev agent.PacketEvent) {
		_, _ = corr.ProcessPacket(ctx, ev)
	})
	fps := tap.NewFingerprintStore()
	queue.SetFingerprints(fps)

	handler := withStatus(
		tap.HTTPMiddlewareGate(responseFromContext(ctx).Wrap(httputil.NewSingleHostReverseProxy(targetURL), httpGate{gate}), queue, listenAddr, targetURL.Host, gate),
		queue, alertStatsOf(alertStore), obsB, obsM)
	srv := &http.Server{Addr: listenAddr, Handler: handler}
	if tlsCert != "" && tlsKey != "" {
		srv.TLSConfig = fps.TLSConfig(&tls.Config{MinVersion: tls.VersionTLS12})
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	scheme := "http"
	if tlsCert != "" && tlsKey != "" {
		scheme = "https"
	}
	fmt.Fprintf(out, "[vigilante] middleware tap active on %s://%s -> forwarding to %s\n", scheme, listenAddr, targetURL.String())
	if scheme == "https" {
		return srv.ListenAndServeTLS(tlsCert, tlsKey)
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// runGatewayMode runs Vigilante's ingress. In "local" posture Vigilante owns
// the public listener and forwarding (optionally consulting an upstream route
// planner); in "external:<url>" posture it attaches to an existing
// ingress/gateway process at that endpoint, mirroring the traffic it carries.
func runGatewayMode(ctx context.Context, out io.Writer, corr *correlator.Correlator, listenAddr, targetRaw, plannerURL, plannerToken, tlsCert, tlsKey string, queueSize int, gate tap.PolicyGate, alertStore *alert.Store, sampleRate float64, posture, externalURL string, obsB *obs.Bridge, obsM func(http.ResponseWriter)) error {
	srv, err := gateway.NewServer(gateway.Options{
		Mode:          gateway.Mode(posture),
		ListenAddr:    listenAddr,
		ExternalURL:   externalURL,
		TargetURL:     targetRaw,
		PlannerURL:    plannerURL,
		InternalToken: plannerToken,
		TLSCertFile:   tlsCert,
		TLSKeyFile:    tlsKey,
		QueueSize:     queueSize,
	}, func(ctx context.Context, ev agent.PacketEvent) {
		_, _ = corr.ProcessPacket(ctx, ev)
	})
	if err != nil {
		return err
	}
	srv.Queue().SetSampleRate(sampleRate)
	registerQueue(srv.Queue())
	if alertStore != nil {
		srv.SetExtraMetrics(func(w http.ResponseWriter) {
			stored, delivered, failed := alertStore.Stats()
			fmt.Fprintf(w, "vigilante_alerts_stored_total %d\nvigilante_alerts_delivered_total %d\nvigilante_alerts_failed_total %d\n",
				stored, delivered, failed)
			if obsM != nil {
				obsM(w)
			}
		})
	} else if obsM != nil {
		srv.SetExtraMetrics(func(w http.ResponseWriter) { obsM(w) })
	}
	if obsB != nil {
		srv.SetHandlerMount("/obs", obsB)
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	scheme := "http"
	if tlsCert != "" && tlsKey != "" {
		scheme = "https"
	}
	switch gateway.Mode(posture) {
	case gateway.ModeExternal:
		fmt.Fprintf(out, "[vigilante] gateway external posture: observing existing ingress at %s (no local listener; forwarding via it)\n", orDash(externalURL))
	default:
		fmt.Fprintf(out, "[vigilante] gateway %s ingress active on %s://%s -> forwarding to %s (planner: %s)\n",
			posture, scheme, listenAddr, targetRaw, orDash(plannerURL))
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// withStatus mounts the status endpoints (/healthz, /health, /ready, /metrics)
// and, when present, the obs ext plugin bridge (/obs/*) alongside the main
// handler: those paths are claimed, everything else goes to next (the tap).
func withStatus(next http.Handler, queue *tap.MirrorQueue, alert status.AlertStats, obsB *obs.Bridge, obsM func(http.ResponseWriter)) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/healthz", status.Handler(queue, alert))
	mux.Handle("/health", status.Handler(queue, alert))
	mux.Handle("/ready", status.Handler(queue, alert))
	mux.Handle("/metrics", withObsMetrics(status.Handler(queue, alert), obsM))
	if obsB != nil {
		mux.Handle("/obs/", http.StripPrefix("/obs", obsB))
		mux.Handle("/obs", http.StripPrefix("/obs", obsB))
	}
	mux.Handle("/", next)
	return mux
}

// withObsMetrics appends the obs plugin's per-severity metrics to /metrics
// output. It passes writes straight through and hooks WriteHeader so obs lines
// are emitted after the inner handler completes.
func withObsMetrics(inner http.Handler, obsM func(http.ResponseWriter)) http.Handler {
	if obsM == nil {
		return inner
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		inner.ServeHTTP(w, r)
		if r.URL.Path == "/metrics" || strings.HasSuffix(r.URL.Path, "/metrics") {
			obsM(w)
		}
	})
}

// alertStats adapts *alert.Store to the status package's counter signature.
func alertStatsOf(s *alert.Store) status.AlertStats {
	if s == nil {
		return nil
	}
	return func() (uint64, uint64, uint64) { return s.Stats() }
}

// currentQueue holds the most recently created mirror queue so the obs plugin
// can report queue counters in its summary. Set by each mode after it builds
// its queue; nil until a mode runs.
var currentQueue atomic.Pointer[tap.MirrorQueue]

// registerQueue publishes a queue for the obs summary to read.
func registerQueue(q *tap.MirrorQueue) { currentQueue.Store(q) }

// obsQueueProbe is the function passed to obs.NewService; it reads currentQueue.
func obsQueueProbe() obs.QueueCounters {
	q := currentQueue.Load()
	if q == nil {
		return obs.QueueCounters{}
	}
	enqueued, dropped := q.Stats()
	return obs.QueueCounters{Enqueued: enqueued, Dropped: dropped, SampledOut: q.SampledOut()}
}

// obsQueueStats adapts the probe func to obs.NewService's signature.
func obsQueueStats(probe func() obs.QueueCounters) func() obs.QueueCounters {
	return probe
}

type stringListFlag []string

func (f *stringListFlag) String() string         { return strings.Join(*f, ", ") }
func (f *stringListFlag) Set(value string) error { *f = append(*f, value); return nil }

// splitAgentArg parses an -agent value of the form "kind" or "cli:<command>",
// returning the kind and any attached command.
func splitAgentArg(raw string) (kind, command string) {
	kind, command, _ = strings.Cut(raw, ":")
	kind = strings.ToLower(strings.TrimSpace(kind))
	command = strings.TrimSpace(command)
	return kind, command
}

// splitGatewayArg parses a -gateway value of the form "posture" or
// "posture:<url>", returning the posture and any attached endpoint URL.
func splitGatewayArg(raw string) (posture, endpoint string) {
	posture, endpoint, _ = strings.Cut(raw, ":")
	posture = strings.ToLower(strings.TrimSpace(posture))
	endpoint = strings.TrimSpace(endpoint)
	if posture == "" {
		posture = "local"
	}
	return posture, endpoint
}

func orDash(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// splitCSV parses a comma-separated list, trimming and dropping empties.
func splitCSV(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if v := strings.TrimSpace(part); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// orNever renders a zero expiry as "never".
func orNever(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Format(time.RFC3339)
}

// actorView adapts the actor index into the obs read model, applying the
// suspicious filter and top-N limit.
func actorView(idx *actor.Index, in obs.ActorsInput) obs.ActorsOutput {
	out := obs.ActorsOutput{Actors: []obs.Actor{}}
	if idx == nil {
		return out
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 100
	}
	snap := idx.Snapshot()
	suspicious := 0
	for _, a := range snap {
		if a.Suspicious {
			suspicious++
		}
	}
	out.Count = len(snap)
	out.Suspicious = suspicious
	for _, a := range snap {
		if in.Suspicious && !a.Suspicious {
			continue
		}
		out.Actors = append(out.Actors, obs.Actor{
			Key:         a.Key,
			IP:          a.IP,
			Fingerprint: a.Fingerprint,
			UserAgent:   a.UserAgent,
			Tags:        a.Tags,
			FirstSeen:   a.FirstSeen,
			LastSeen:    a.LastSeen,
			Requests:    a.Requests,
			BySeverity:  a.BySeverity,
			Verdicts:    a.Verdicts,
			LastVerdict: a.LastVerdict,
			LastSummary: a.LastSummary,
			Risk:        a.Risk,
			Suspicious:  a.Suspicious,
		})
		if len(out.Actors) >= limit {
			break
		}
	}
	return out
}

// actionView adapts the host action registry into the obs read model. It is the
// data any consumer needs to render a response UI: what is available, what is
// in force, and what has been decided.
func actionView(r *action.Registry) obs.ActionsOutput {
	out := obs.ActionsOutput{
		Capabilities: []obs.ActionCapability{},
		Active:       []obs.ActiveDecision{},
		Decisions:    []obs.ActionDecision{},
	}
	if r == nil {
		return out
	}
	for _, c := range r.Capabilities() {
		scopes := make([]string, len(c.Scopes))
		for i, s := range c.Scopes {
			scopes[i] = string(s)
		}
		params := make([]obs.ActionParam, len(c.Params))
		for i, p := range c.Params {
			params[i] = obs.ActionParam{Name: p.Name, Label: p.Label, Type: p.Type, Required: p.Required, Default: p.Default}
		}
		out.Capabilities = append(out.Capabilities, obs.ActionCapability{
			ID:          c.ID,
			Label:       c.Label,
			Description: c.Description,
			Scopes:      scopes,
			DefaultTTL:  c.DefaultTTL,
			MaxTTL:      c.MaxTTL,
			Reversible:  c.Reversible,
			Destructive: c.Destructive,
			Params:      params,
		})
	}
	for _, e := range r.Active() {
		out.Active = append(out.Active, obs.ActiveDecision{
			ID:      e.ID,
			Action:  e.Action,
			Scope:   string(e.Scope),
			Target:  e.Target,
			Reason:  e.Reason,
			Actor:   e.Actor,
			Created: e.Created,
			Expires: e.Expires,
		})
	}
	for _, d := range r.Decisions() {
		out.Decisions = append(out.Decisions, obs.ActionDecision{
			ID:        d.ID,
			Action:    d.Action,
			Label:     d.Label,
			Scope:     string(d.Scope),
			Target:    d.Target,
			Actor:     d.Actor,
			Reason:    d.Reason,
			Operator:  d.Operator,
			Status:    string(d.Status),
			RevertRef: d.RevertRef,
			Detail:    d.Detail,
			StartedAt: d.StartedAt,
			ExpiresAt: d.ExpiresAt,
		})
	}
	return out
}

// headerValue looks up a header case-insensitively in a mirrored header map.
func headerValue(headers map[string]string, name string) string {
	for k, v := range headers {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

func runDemo(ctx context.Context, out io.Writer, corr *correlator.Correlator, store graph.Store, supervised bool, sampleRate float64) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("/api/v1/files", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprintf(w, `{"file":%q}`, r.URL.Query().Get("name"))
	})
	mux.HandleFunc("/api/v1/login", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"authenticated":false}`))
	})

	upstream := httptest.NewServer(mux)
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		return err
	}

	queue := tap.NewMirrorQueue(64)
	queue.SetSampleRate(sampleRate)
	middlewareServer := httptest.NewServer(tap.NewHTTPReverseProxyTap(upstreamURL, queue, "127.0.0.1:0"))
	defer middlewareServer.Close()

	fmt.Fprintf(out, "[vigilante] demo middleware active -> mirroring traffic to upstream %s\n\n", upstreamURL.Host)

	client := &http.Client{Timeout: 5 * time.Second}
	requests := []struct {
		method string
		path   string
		body   string
		header map[string]string
	}{
		{
			method: http.MethodGet,
			path:   "/api/v1/health",
			header: map[string]string{"Authorization": "Bearer super-secret-jwt"},
		},
		{
			method: http.MethodGet,
			path:   "/api/v1/files?name=../../../../etc/passwd",
		},
		{
			method: http.MethodPost,
			path:   "/api/v1/login",
			body:   `{"username":"admin' UNION SELECT password FROM users--"}`,
		},
	}

	for _, reqSpec := range requests {
		req, err := http.NewRequestWithContext(ctx, reqSpec.method, middlewareServer.URL+reqSpec.path, strings.NewReader(reqSpec.body))
		if err != nil {
			return err
		}
		for k, v := range reqSpec.header {
			req.Header.Set(k, v)
		}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	queued, _ := queue.Stats()
	for i := uint64(0); i < queued; i++ {
		ev := <-queue.Events()
		if _, err := corr.ProcessPacket(ctx, ev); err != nil {
			return err
		}
	}

	vigSnap, err := store.Snapshot(ctx, schema.Namespace)
	if err != nil {
		return err
	}
	sysSnap, err := store.Snapshot(ctx, system.Namespace)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "\n[vigilante] graph summary:\n")
	fmt.Fprintf(out, "  • %s namespace: %d vertices, %d edges (revision %d)\n",
		sysSnap.Namespace, len(sysSnap.Vertices), len(sysSnap.Edges), sysSnap.Revision)
	fmt.Fprintf(out, "  • %s namespace: %d vertices, %d edges (revision %d)\n",
		vigSnap.Namespace, len(vigSnap.Vertices), len(vigSnap.Edges), vigSnap.Revision)
	if supervised {
		if rtSnap, err := store.Snapshot(ctx, supervisor.RuntimeNamespace); err == nil {
			fmt.Fprintf(out, "  • %s namespace: %d vertices, %d edges (revision %d)\n",
				rtSnap.Namespace, len(rtSnap.Vertices), len(rtSnap.Edges), rtSnap.Revision)
		}
	}
	return nil
}

func runHTTPProxy(ctx context.Context, out io.Writer, corr *correlator.Correlator, listenAddr, targetRaw string, queueSize int, tlsCert, tlsKey string, gate tap.PolicyGate, alertStore *alert.Store, sampleRate float64, obsB *obs.Bridge, obsM func(http.ResponseWriter)) error {
	if !strings.Contains(targetRaw, "://") {
		targetRaw = "http://" + targetRaw
	}
	targetURL, err := url.Parse(targetRaw)
	if err != nil {
		return fmt.Errorf("invalid target URL: %w", err)
	}

	queue := tap.NewMirrorQueue(queueSize)
	queue.SetSampleRate(sampleRate)
	registerQueue(queue)
	queue.Drain(ctx, 2, func(ctx context.Context, ev agent.PacketEvent) {
		_, _ = corr.ProcessPacket(ctx, ev)
	})
	fps := tap.NewFingerprintStore()
	queue.SetFingerprints(fps)

	srv := &http.Server{
		Addr: listenAddr,
		Handler: withStatus(
			tap.HTTPMiddlewareGate(responseFromContext(ctx).Wrap(tap.NewHTTPReverseProxyTap(targetURL, queue, listenAddr), httpGate{gate}), queue, listenAddr, targetURL.Host, gate),
			queue, alertStatsOf(alertStore), obsB, obsM),
	}
	if tlsCert != "" && tlsKey != "" {
		srv.TLSConfig = fps.TLSConfig(&tls.Config{MinVersion: tls.VersionTLS12})
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	scheme := "http"
	if tlsCert != "" && tlsKey != "" {
		scheme = "https"
	}
	fmt.Fprintf(out, "[vigilante] %s tap listening on %s -> forwarding to %s\n", scheme, listenAddr, targetURL.String())
	if scheme == "https" {
		return srv.ListenAndServeTLS(tlsCert, tlsKey)
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func runTCPProxy(ctx context.Context, out io.Writer, corr *correlator.Correlator, listenAddr, targetAddr string, queueSize int, httpGate tap.PolicyGate, sampleRate float64, tlsCert, tlsKey string, alertStore *alert.Store, obsB *obs.Bridge, obsM func(http.ResponseWriter)) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	queue := tap.NewMirrorQueue(queueSize)
	queue.SetSampleRate(sampleRate)
	registerQueue(queue)
	queue.Drain(ctx, 2, func(ctx context.Context, ev agent.PacketEvent) {
		_, _ = corr.ProcessPacket(ctx, ev)
	})

	// Bridge the HTTP-shaped policy gate to a source-IP gate for TCP.
	var tcpGate tap.TCPGate
	if httpGate != nil {
		tcpGate = func(srcIP string) string {
			req := httptest.NewRequest(http.MethodGet, "http://tcp/", nil)
			req.RemoteAddr = net.JoinHostPort(srcIP, "0")
			return httpGate(req)
		}
	}

	// TCP has no HTTP listener of its own; expose status/obs on a small
	// sidecar port (listenAddr with the port offset by +10000 is fragile, so we
	// use an explicit admin listener only when obs is enabled).
	if obsB != nil || obsM != nil {
		adminAddr := adminAddrFor(listenAddr)
		go serveTCPAdmin(ctx, out, adminAddr, queue, alertStatsOf(alertStore), obsB, obsM)
	}

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	fmt.Fprintf(out, "[vigilante] TCP tap listening on %s -> forwarding to %s (policy gate: %v)\n", listenAddr, targetAddr, tcpGate != nil)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func(c net.Conn) {
			if err := tap.ProxyTCPConn(ctx, c, listenAddr, targetAddr, queue, tcpGate); err != nil && ctx.Err() == nil {
				fmt.Fprintf(out, "[vigilante] tcp conn: %v\n", err)
			}
		}(conn)
	}
}

// adminAddrFor derives a loopback admin address for TCP status/obs from the
// primary listen address (same host, port+10000), avoiding collisions with the
// data port.
func adminAddrFor(listenAddr string) string {
	host, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "127.0.0.1:0"
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return net.JoinHostPort(host, "0")
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, strconv.Itoa(port+10000))
}

// serveTCPAdmin runs the status/obs HTTP surface for TCP mode on a sidecar
// listener so /healthz, /metrics, and the obs dashboard remain reachable.
func serveTCPAdmin(ctx context.Context, out io.Writer, addr string, queue *tap.MirrorQueue, alertS status.AlertStats, obsB *obs.Bridge, obsM func(http.ResponseWriter)) {
	mux := withStatus(http.NotFoundHandler(), queue, alertS, obsB, obsM)
	srv := &http.Server{Addr: addr, Handler: mux}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	fmt.Fprintf(out, "[vigilante] tcp admin surface on http://%s (healthz/metrics/obs)\n", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Fprintf(out, "[vigilante] tcp admin: %v\n", err)
	}
}

func printVerdict(out io.Writer, env agent.EnrichedEnvelope, v agent.Verdict) {
	record := map[string]any{
		"flow_id":                v.FlowID,
		"trigger":                env.TriggerReason,
		"severity":               v.Severity,
		"action":                 v.Action,
		"summary":                v.Summary,
		"method":                 env.Event.Method,
		"path":                   env.Event.Path,
		"os":                     env.OS.OS + "/" + env.OS.Arch,
		"hostname":               env.OS.Hostname,
		"server_pid":             env.ServerProcess.PID,
		"server_process":         env.ServerProcess.Name,
		"dep_count":              len(env.DependencyGraph.Dependencies),
		"net_interfaces":         len(env.NetworkTopology.Interfaces),
		"graph_revision":         env.GraphRevision,
		"reverse_graph_queried":  v.ReverseGraphQueried,
		"reverse_observed_nodes": v.ReverseObservedNodes,
	}
	if v.MatchedHandler != "" {
		record["matched_handler"] = v.MatchedHandler
	}
	if v.InspectedSource != "" {
		record["inspected_source"] = v.InspectedSource
	}
	if len(v.MatchedAdvisories) > 0 {
		record["matched_advisories"] = v.MatchedAdvisories
	}
	if len(v.Recommendations) > 0 {
		record["recommendations"] = v.Recommendations
	}
	encoded, _ := json.MarshalIndent(record, "", "  ")
	fmt.Fprintln(out, string(encoded))
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
