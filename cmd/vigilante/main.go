// Command vigilante brings an agent into the network stack by mirroring incoming
// HTTP/TCP traffic into a non-blocking pipeline, enriching each flow with OS,
// server process, network topology, application dependency graphs, and indexed
// GitHub/local codebase context via github.com/webong/ext, and dispatching it
// to an ext.plugin/v1 agent.
package main

import (
	"context"
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
	"github.com/webong/vigilante/ext/obs"
	"github.com/webong/vigilante/ext/tap"
	"github.com/webong/vigilante/internal/alert"
	"github.com/webong/vigilante/internal/block"
	"github.com/webong/vigilante/internal/correlator"
	"github.com/webong/vigilante/internal/gateway"
	"github.com/webong/vigilante/internal/policy"
	"github.com/webong/vigilante/internal/repo"
	"github.com/webong/vigilante/internal/schema"
	"github.com/webong/vigilante/internal/status"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "vigilante:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("vigilante", flag.ContinueOnError)
	fs.SetOutput(out)

	mode := fs.String("mode", "demo", "Execution mode: demo, http, tcp, middleware, gateway, passive, or agent-worker")
	passiveIface := fs.String("passive-iface", "", "Interface to passively sniff in -mode passive (e.g. eth0; requires root/CAP_NET_RAW)")
	passivePorts := fs.String("passive-ports", "", "Comma-separated ports to capture in -mode passive (empty = all)")
	listenAddr := fs.String("listen", "127.0.0.1:8080", "Address for vigilante middleware to listen on")
	targetAddr := fs.String("target", "http://127.0.0.1:9000", "Upstream server URL (for http/gateway) or host:port (for tcp)")
	tlsCert := fs.String("tls-cert", "", "TLS certificate file for HTTPS on -listen (http/gateway modes)")
	tlsKey := fs.String("tls-key", "", "TLS private key file for HTTPS on -listen (http/gateway modes)")
	plannerURL := fs.String("planner-url", "", "Optional upstream gateway/route-planner URL for route decisions (gateway mode)")
	plannerToken := fs.String("planner-token", "", "Internal token for the upstream route planner (gateway mode)")
	gatewayPosture := fs.String("gateway", "local", "Gateway posture: local (Vigilante's own ingress, default) or external:<url> (attach to an ingress running elsewhere — recommended if you already run one)")
	policyFile := fs.String("policy", "", "Path to a policy file (YAML/JSON) with allow/deny/block rules")
	obsEnabled := fs.Bool("obs", true, "Enable the obs ext plugin (dashboard at /obs/dashboard + JSON API), when an alert store is present")
	blockMode := fs.String("block-mode", "log", "Block enforcement mode: log (dry-run), iptables, or nft")
	blockChain := fs.String("block-chain", "VIGILANTE", "iptables/nft chain name for block enforcement")
	blockThreshold := fs.Int("block-threshold", 0, "Auto-block a source after N qualifying verdicts within -block-window (0 = disabled)")
	blockWindow := fs.Duration("block-window", time.Minute, "Sliding window for -block-threshold")
	blockMinSev := fs.String("block-min-severity", "high", "Lowest verdict severity counted toward -block-threshold")
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
	agentKind := fs.String("agent", "", "Agent kind: builtin (default rule engine), cli:<command> (shell out to an external LLM/agent binary), or supervised (out-of-process via ext supervisor)")
	agentTimeout := fs.Duration("agent-timeout", 30*time.Second, "Per-triage timeout for -agent cli")
	agentIPC := fs.String("agent-ipc", "", "Internal IPC address when running in -mode agent-worker")
	configPath := fs.String("config", "", "Path to a config file (JSON or flat YAML) supplying defaults for any unset flag")

	if err := fs.Parse(args); err != nil {
		return err
	}

	// Apply config-file values for any flag the user did not set explicitly
	// (CLI flags always win).
	cfg, err := loadConfig(*configPath)
	if err != nil {
		return err
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	if !set["mode"] && cfg.Mode != "" {
		*mode = cfg.Mode
	}
	if !set["agent"] && cfg.Agent != "" {
		*agentKind = cfg.Agent
	}
	if !set["gateway"] && cfg.Gateway != "" {
		*gatewayPosture = cfg.Gateway
	}
	if !set["listen"] && cfg.Listen != "" {
		*listenAddr = cfg.Listen
	}
	if !set["target"] && cfg.Target != "" {
		*targetAddr = cfg.Target
	}
	if !set["repo"] && cfg.Repo != "" {
		*repoTarget = cfg.Repo
	}
	if !set["repo-ref"] && cfg.RepoRef != "" {
		*repoRef = cfg.RepoRef
	}
	if !set["repo-user"] && cfg.RepoUser != "" {
		*repoUser = cfg.RepoUser
	}
	if !set["repo-token"] && cfg.RepoToken != "" {
		*repoToken = cfg.RepoToken
	}
	if !set["repo-ssh-key"] && cfg.RepoSSHKey != "" {
		*repoSSHKey = cfg.RepoSSHKey
	}
	if !set["tls-cert"] && cfg.TLSCert != "" {
		*tlsCert = cfg.TLSCert
	}
	if !set["tls-key"] && cfg.TLSKey != "" {
		*tlsKey = cfg.TLSKey
	}
	if !set["planner-url"] && cfg.PlannerURL != "" {
		*plannerURL = cfg.PlannerURL
	}
	if !set["planner-token"] && cfg.PlannerToken != "" {
		*plannerToken = cfg.PlannerToken
	}
	if !set["policy"] && cfg.Policy != "" {
		*policyFile = cfg.Policy
	}
	if !set["block-mode"] && cfg.BlockMode != "" {
		*blockMode = cfg.BlockMode
	}
	if !set["block-chain"] && cfg.BlockChain != "" {
		*blockChain = cfg.BlockChain
	}
	if !set["alert-file"] && cfg.AlertFile != "" {
		*alertFile = cfg.AlertFile
	}
	if !set["alert-deliver-url"] && cfg.AlertDeliver != "" {
		*alertDeliver = cfg.AlertDeliver
	}
	if !set["alert-min-severity"] && cfg.AlertMinSev != "" {
		*alertMinSev = cfg.AlertMinSev
	}
	if !set["queue-size"] && cfg.QueueSize > 0 {
		*queueSize = cfg.QueueSize
	}
	if !set["sample-rate"] && cfg.SampleRate > 0 {
		*sampleRate = cfg.SampleRate
	}
	if !set["supervised-agent"] && cfg.Supervised {
		*supervisedAgent = true
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

	var polGate tap.PolicyGate
	var enforcer *block.Enforcer
	var threshold *block.Threshold
	if *policyFile != "" {
		engine, err := policy.Load(*policyFile)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "[vigilante] policy loaded from %s\n", *policyFile)
		polGate = func(r *http.Request) string {
			return string(engine.Evaluate(r).Action)
		}
	}
	{
		var err error
		enforcer, err = block.New(block.Options{
			Mode:  block.Mode(*blockMode),
			Chain: *blockChain,
			OnBlock: func(ip net.IP, rule string) {
				fmt.Fprintf(out, "[vigilante] BLOCK enforced (%s) ip=%s rule=%s\n", *blockMode, ip, rule)
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

	// Open the obs ext plugin (dashboard + query API) whenever an alert store
	// exists. It reads alerts via the store's Reader; metrics flow into /metrics.
	var obsBridge *obs.Bridge
	var obsClose func(context.Context) error
	var obsMetrics func(http.ResponseWriter)
	if alertStore != nil && *obsEnabled {
		obsSvc := obs.NewService(
			alertStore,
			obsQueueStats(obsQueueProbe),
			alertStore.Stats,
		)
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
		fmt.Fprintln(out, "[vigilante] obs plugin active: /obs/dashboard, /obs/alerts, /obs/summary (ext.plugin/v1 vigilante.obs@v1)")
	}

	var gw *agent.Gateway
	// Resolve the agent kind: explicit -agent wins; -supervised-agent maps to
	// "supervised"; empty means builtin.
	kind, cliCmd := splitAgentArg(*agentKind)
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
		fmt.Fprintf(out, "[vigilante] CLI agent: %s (timeout %s)\n", orDash(cliCmd), *agentTimeout)
		if cliCmd == "" {
			return fmt.Errorf("-agent cli:<command> requires a command")
		}
		cliHandler := agent.NewCLIHandler(agent.CLIOptions{
			Command: cliCmd,
			Args:    []string{},
			Timeout: *agentTimeout,
			OnError: func(err error) {
				fmt.Fprintln(out, "[vigilante] cli agent error (falling back to builtin):", err)
			},
		})
		gw, err = agent.NewInProcessGateway(ctx, store, repoIdx, cliHandler)
	default: // "builtin"
		gw, err = agent.NewInProcessGateway(ctx, store, repoIdx, nil)
	}
	if err != nil {
		return fmt.Errorf("init ext.plugin/v1 agent gateway: %w", err)
	}
	defer gw.Close(context.Background())

	corr, err := correlator.New(correlator.Options{
		SystemGraph: sysGraph,
		Gateway:     gw,
		Repo:        repoIdx,
		FallbackPID: os.Getpid(),
		OnVerdict: func(env agent.EnrichedEnvelope, v agent.Verdict) {
			printVerdict(out, env, v)
			// Persist/deliver the alert (Vigilante-owned; through the Gateway
			// Planner when one is configured).
			if alertStore != nil {
				alertStore.Record(alert.Record{
					Timestamp:  time.Now().UTC(),
					FlowID:     v.FlowID,
					Severity:   alert.Severity(v.Severity),
					Action:     v.Action,
					Summary:    v.Summary,
					Method:     env.Event.Method,
					Path:       env.Event.Path,
					SrcAddr:    env.Event.SrcAddr,
					TargetAddr: env.Event.TargetAddr,
					Handler:    v.MatchedHandler,
					Advisories: v.MatchedAdvisories,
				})
			}
			// Enforce agent-recommended blocks through the pluggable enforcer.
			if v.Action == "recommend-block" && enforcer != nil {
				if ip := net.ParseIP(env.Event.SrcAddr); ip != nil {
					// SrcAddr may be "ip:port"; strip the port.
					if host, _, err := net.SplitHostPort(env.Event.SrcAddr); err == nil {
						ip = net.ParseIP(host)
					}
					_ = enforcer.Block(ctx, ip, "agent-verdict")
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
	case "demo":
		return runDemo(ctx, out, corr, store, *supervisedAgent, *sampleRate)
	case "http":
		return runHTTPProxy(ctx, out, corr, *listenAddr, *targetAddr, *queueSize, *tlsCert, *tlsKey, polGate, alertStore, *sampleRate, obsBridge, obsMetrics)
	case "tcp":
		return runTCPProxy(ctx, out, corr, *listenAddr, *targetAddr, *queueSize, polGate, *sampleRate, *tlsCert, *tlsKey, alertStore, obsBridge, obsMetrics)
	case "middleware":
		return runMiddlewareMode(ctx, out, corr, *listenAddr, *targetAddr, *queueSize, *tlsCert, *tlsKey, polGate, alertStore, *sampleRate, obsBridge, obsMetrics)
	case "gateway":
		gwPosture, gwExternal := splitGatewayArg(*gatewayPosture)
		if gwExternal != "" && *targetAddr == "" {
			// External forwards to the existing gateway, so target is optional.
			*targetAddr = gwExternal
		}
		return runGatewayMode(ctx, out, corr, *listenAddr, *targetAddr, *plannerURL, *plannerToken, *tlsCert, *tlsKey, *queueSize, polGate, alertStore, *sampleRate, gwPosture, gwExternal, obsBridge, obsMetrics)
	case "passive":
		return runPassiveMode(ctx, out, corr, *passiveIface, *passivePorts, *queueSize, *sampleRate, alertStore, obsBridge, obsMetrics)
	default:
		return fmt.Errorf("unsupported mode %q (choose demo, http, tcp, middleware, gateway, passive, or agent-worker)", *mode)
	}
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

	handler := withStatus(
		tap.HTTPMiddlewareGate(httputil.NewSingleHostReverseProxy(targetURL), queue, listenAddr, targetURL.Host, gate),
		queue, alertStatsOf(alertStore), obsB, obsM)
	srv := &http.Server{Addr: listenAddr, Handler: handler}

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

	srv := &http.Server{
		Addr: listenAddr,
		Handler: withStatus(
			tap.HTTPMiddlewareGate(tap.NewHTTPReverseProxyTap(targetURL, queue, listenAddr), queue, listenAddr, targetURL.Host, gate),
			queue, alertStatsOf(alertStore), obsB, obsM),
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
