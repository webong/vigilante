# Vigilante

**Vigilante** is a network-stack middleware and context-enrichment pipeline built on [`github.com/webong/ext`](https://github.com/webong/ext).

As packets and requests enter a system, Vigilante non-blockingly copies them into an asynchronous ring buffer, joins each flow with live OS, server process, network topology, and application dependency state, projects the relationships into a shared `ext/res/system/graph` store, and dispatches the enriched context to an `ext.plugin/v1` agent.

## Architecture & `webong/ext` Integration

| Layer | Package | Responsibility |
| --- | --- | --- |
| **Sensor Network Tap** | `ext/tap` | Non-blocking HTTP reverse-proxy / middleware and TCP stream tee (`MirrorQueue`) plus a **passive AF_PACKET sensor** (`-mode passive`) that observes interface traffic *without* being in the forwarding path — Vigilante as a drop-in sensor. Drops mirrored copies on backpressure so primary traffic never stalls. Redacts secrets before agent dispatch. Exposes `tap.NewMirror` / `tap.PreviewRequest` for embedding and external ingress adapters. |
| **Redaction & Sampling** | `ext/redact` + `tap.MirrorQueue` | Scrubs JWTs, API keys, bearer/basic auth, secret key-values, and emails from paths/queries/body previews (deterministic, counted); lock-free `-sample-rate` dispatches only a fraction of flows to the agent under load. |
| **Agent Gateway + Backends** | `ext/agent` | One `ext.plugin/v1 vigilante.agent@v1` contract with selectable backends: **builtin** rule engine, **cli:&lt;cmd&gt;** (shells out to an external LLM/agent binary — envelope on stdin, JSON verdict on stdout, falls back to builtin), and **supervised** (out-of-process via `ext/res/system/supervisor` + jsonline). Reverse host callbacks (`read-source`, `query-graph`) available to all. Lives in `ext/` because the agent is itself an ext plugin. |
| **Dynamic Block Thresholds** | `internal/block.Threshold` | Auto-blocks a source after N qualifying verdicts in a sliding window (`-block-threshold`/`-block-window`/`-block-min-severity`); never blocks loopback. |
| **Delivery Retry** | `internal/alert` | Webhook delivery retries transient failures with exponential backoff (attempts + base backoff configurable). |
| **obs ext plugin** | `ext/obs` | Dashboard + JSON query API as a genuine `ext.plugin/v1` plugin behind an `engine.Session`; reads alerts from the core store, contributes per-severity metrics. |
| **Packaging** | `deploy/`, `Dockerfile`, `install.sh` | Hardened systemd unit, example config, multi-repo Docker build (context = parent of `vigilante/` + `ext/`), and one-command installer. |
| **Status Endpoints** | `internal/status` | Shared `/healthz`, `/health`, `/ready`, and `/metrics` (queue + alert counters) mounted on every HTTP-serving mode. |
| **Alert Store & Delivery** | `internal/alert` | Append-only JSONL verdict store with size-based rotation and severity filtering; pluggable delivery — direct webhook POST or via a webong/gateway Planner (`/vigilante/alerts`) so subscriber relays own fan-out/retries. Failures are counted, never block the hot path. |
| **Policy & Block Enforcement** | `internal/policy` + `internal/block` | Declarative allow/deny/block rules (path globs, hosts, methods, CIDRs) evaluated before forwarding; `block` verdicts enforced via a pluggable backend — dry-run `log`, `iptables`, or `nft` — with loopback/unspecified guards and idempotent chain provisioning. |
| **Gateway Ingress Layer** | `internal/gateway` | Vigilante's vendor-neutral ingress. Two postures: **local** (Vigilante owns the public listener, optional TLS, upstream forwarding, optional route-planner decisions, fail-open, `/health`, `/ready`, `/metrics`) and **external:&lt;url&gt;** (attach to an ingress running elsewhere — that peer keeps the listener, Vigilante mirrors its traffic). Does not depend on any specific gateway product. |
| **OS, Process & Socket Discovery** | `github.com/webong/ext/res/system` | Inventories host shells, filesystems, and running processes (`ScanHost`, `ScanProcesses`, `InspectProcess`) to map ports/sockets to PIDs, executable paths, open sockets, and memory-mapped shared libraries. |
| **Network Topology** | `github.com/webong/ext/res/system/network` | Zero-traffic observation of local interfaces, assigned IP addresses, route tables, and DNS resolver settings (`network.Discover`). |
| **Application Dependency Graph** | `internal/deps` | Extracts module dependency graphs from compiled Go binaries (`debug/buildinfo`), `go.mod`, `go.sum`, `package.json`, `package-lock.json`, `Cargo.lock`, `uv.lock`, `requirements.txt`, and `res/system` shared library mappings, plus CVE advisory matching. |
| **Codebase & Git Repo Indexer** | `internal/repo` | Clones or opens **any** Git repository — GitHub, GitLab, Bitbucket, Gitea, self-hosted — via a full URL (`https://`, `ssh://`, `git://`, `file://`, scp-like `git@host:path`), a `host/owner/repo` or `owner/repo` shorthand (`VIGILANTE_GIT_HOST` selects the default host), or a local directory (`-repo`). **Private repos** authenticate with an HTTPS token (`-repo-token` / `VIGILANTE_GIT_TOKEN`, handed to git via a private `GIT_ASKPASS` helper — never argv or `.git/config`), a specific SSH key (`-repo-ssh-key` / `VIGILANTE_GIT_SSH_KEY`), an ssh-agent, or a configured git credential helper. Computes its file tree digest, discovers HTTP/RPC route handlers and security-sensitive code sinks (`filesystem`, `sql`, `exec`), and serves root-jailed source snippets to the agent over `ext.plugin/v1` reverse calls (`vigilante.host@v1/read-source`). |
| **Transactional System Graph** | `internal/schema` + `res/system/graph` | Registers the `vigilante.net` schema alongside `ext.system` in the same `graph.Store`, linking `listener -> flow -> process-ref -> codebase -> route-handler`, `process-ref -> dependency`, and `flow -> agent-alert`. |
| **Agent Gateway** | `ext/agent` + `pkg/ext-go/engine` | Typed `ext.plugin/v1` contract (`vigilante.agent@v1` / `triage-flow`) using `engine/guest/author` and `engine.Session`. Supports in-process guests, `jsonline` subprocesses, and `res/system/supervisor`-managed agents with bidirectional reverse host callbacks (`query-graph` and `read-source`). |

## Quick Start

### 1. Run the Self-Contained End-to-End Demo
Spins up a local upstream server, places the Vigilante tap middleware in front of it, indexes the repository codebase, runs a live `ext/res/system` host/process/network scan, fires sample requests (normal, path traversal, and SQL injection), and outputs the agent's context-enriched verdicts (including the exact `file:line` route handler and source code snippet fetched by the agent):

```sh
# In-process ext.plugin/v1 agent:
go run ./cmd/vigilante -mode demo -repo .

# Out-of-process agent supervised by ext/res/system/supervisor over jsonline IPC:
go run ./cmd/vigilante -mode demo -repo . -supervised-agent

# Pointing at a remote repository on any Git host (shallow-cloned and indexed automatically):
go run ./cmd/vigilante -mode http -listen 127.0.0.1:8080 -target http://127.0.0.1:3000 -repo https://github.com/webong/ext
go run ./cmd/vigilante -mode http -listen 127.0.0.1:8080 -target http://127.0.0.1:3000 -repo git@gitlab.internal:platform/api.git

# Private repositories — HTTPS token (never placed in argv or .git/config):
VIGILANTE_GIT_TOKEN=ghp_xxx go run ./cmd/vigilante -mode demo -repo https://github.com/webong/vigilante

# Private repositories — a specific SSH key (works without ssh-agent, accepts new host keys non-interactively):
go run ./cmd/vigilante -mode demo -repo git@gitlab.internal:platform/api.git -repo-ssh-key /etc/ssh/vigilante_ed25519

# Other flags: -repo-ref <branch|tag>, -repo-user <https-user>, -repo-token <token>, -repo-ssh-key <path>
# Env fallbacks: VIGILANTE_GIT_HOST, VIGILANTE_GIT_USER, VIGILANTE_GIT_TOKEN, VIGILANTE_GIT_SSH_KEY
```

### 2. Agent Backends (builtin / CLI / supervised)
Vigilante's triage runs behind one `ext.plugin/v1 vigilante.agent@v1` contract;
the agent *implementation* is selectable:

```sh
# builtin (default): in-process rule/analysis engine
go run ./cmd/vigilante -mode demo -repo .

# cli:<command>: shell out to an external LLM/agent binary. The full enriched
# envelope (OS + process + deps + codebase) is written to the command's stdin;
# it prints a JSON Verdict on stdout (bare object, embedded, or ```fenced```).
# On any failure it falls back to the builtin engine, so a broken CLI never
# silences triage.
go run ./cmd/vigilante -mode demo -repo . -agent cli:claude -agent-timeout 60s
go run ./cmd/vigilante -mode demo -repo . -agent cli:/usr/local/bin/my-triage-agent

# supervised: out-of-process agent via ext/res/system/supervisor + jsonline IPC
go run ./cmd/vigilante -mode demo -repo . -agent supervised   # or -supervised-agent
```

The CLI agent sees the same context the builtin engine does (it's the same
`EnrichedEnvelope`), so it can reason over OS/process/dependency/codebase data
and call reverse host capabilities from its own environment. `-agent` accepts
`agent: cli:<cmd>` in the config file.

### 3. Run as an HTTP Reverse-Proxy Tap
```sh
go run ./cmd/vigilante \
  -mode http \
  -listen 127.0.0.1:8080 \
  -target http://127.0.0.1:3000 \
  -graph-file ./vigilante-graph.json
```

### 4. Run as a TCP Stream Tap
```sh
go run ./cmd/vigilante \
  -mode tcp \
  -listen 127.0.0.1:8080 \
  -target 127.0.0.1:5432
```

### 5. Terminate TLS on the Tap (http / gateway modes)
```sh
go run ./cmd/vigilante \
  -mode http \
  -listen :8443 \
  -target http://127.0.0.1:3000 \
  -tls-cert /etc/vigilante/fullchain.pem \
  -tls-key  /etc/vigilante/privkey.pem
```

### 6. Gateway Ingress (local or external)
Vigilante's `-mode gateway` runs its own ingress (**local** posture) or attaches
to an ingress/gateway **already running elsewhere** (**external** posture).
Vigilante is vendor-neutral — external works with any gateway that speaks plain
HTTP forwarding.

```sh
# local: Vigilante owns the listener + forwarding (optionally consulting a
# route planner, fail-open if it's unreachable):
go run ./cmd/vigilante \
  -mode gateway \
  -gateway local \
  -listen :8080 \
  -target http://127.0.0.1:3000 \
  -planner-url http://127.0.0.1:8081 \
  -planner-token "$INTERNAL_TOKEN"

# external: attach to an ingress already running elsewhere — that process
# keeps owning the listener/routing; Vigilante observes the traffic it carries
# (recommended if you already run a gateway):
go run ./cmd/vigilante -mode gateway -gateway external:http://gw.internal:5001 -repo .

# local with TLS termination on the public listener:
go run ./cmd/vigilante -mode gateway -gateway local -listen :8443 -target http://127.0.0.1:3000 \
  -tls-cert /etc/vigilante/fullchain.pem -tls-key /etc/vigilante/privkey.pem
```

`-gateway` also accepts `gateway: external:<url>` from the config file.
Health endpoints: `/health`, `/ready`, and `/metrics` (queue enqueued/dropped,
observed request count).

### 7. Passive Sensor Mode (observe real traffic — Linux)
Vigilante can act as a **drop-in sensor**, not just a gateway: `-mode passive`
sniffs an interface with `AF_PACKET` and feeds captured flows into the same
enrichment/agent pipeline **without being in the forwarding path**. Your app
keeps serving traffic unchanged; Vigilante just watches.

```sh
# Observe all IP traffic on eth0 (requires root or CAP_NET_RAW):
sudo go run ./cmd/vigilante -mode passive -passive-iface eth0 -repo auto

# Only capture traffic to/from specific service ports:
sudo go run ./cmd/vigilante -mode passive -passive-iface eth0 \
  -passive-ports 80,443,8080 -repo auto -alert-file /var/log/vigilante/alerts.jsonl
```

Linux-only (`AF_PACKET`). It never forwards or modifies packets; status/obs are
served on a loopback sidecar. This is the posture for observing production
traffic you don't control the ingress for.

**Cross-platform capture backends** (shared decode, per-OS capture):

| OS | Backend | Requirement |
|----|---------|-------------|
| **Linux** | `AF_PACKET` raw socket + BPF port filter | `root` / `CAP_NET_RAW` |
| **macOS** | system `tcpdump` (no cgo) parsing line output | `sudo` (BPF capture) |
| **Windows** | npcap `Packet.dll` (pure-Go `syscall`, no cgo) | npcap installed + run as Admin |

All three compile and vet clean. Linux and macOS are functional (macOS
smoke-tested — capture needs `sudo`); the Windows backend loads npcap's
`Packet.dll` at runtime and reports a clear error if npcap isn't installed.
The packet decode path (`DecodeFrame`) is shared and unit-tested on every
platform.

### 8. Embed the Tap In-Process (middleware mode)
`-mode middleware` wraps the mirror tap around an existing handler seam — use it
when Vigilante runs inside the same process as the application:

```sh
go run ./cmd/vigilante -mode middleware -listen :8080 -target http://127.0.0.1:3000
```

From Go code, embed directly with `tap.NewMirror`:

```go
queue := tap.NewMirrorQueue(256)
queue.Drain(ctx, 2, func(ctx context.Context, ev agent.PacketEvent) { /* triage */ })
http.ListenAndServe(":8080", tap.NewMirror(appHandler, queue, ":8080", "app:3000"))
```

### 9. Enforce Policy (allow / deny / block)
Vigilante owns request admission: a declarative policy file gates every request
before it is forwarded, and `block` verdicts are enforced through a pluggable
backend (dry-run `log` by default, or real `iptables` / `nft`).

```yaml
# vigilante-policy.yaml
deny_cidrs:
  - 192.0.2.0/24          # always denied, evaluated before rules
rules:
  - name: block-admin
    action: deny           # 403, not mirrored
    paths: [/admin/*]
  - name: block-git
    action: block          # mirrored for agent triage, then 403 + source block
    path_prefixes: ["/.git/"]
  - name: allow-health
    action: allow          # short-circuits remaining rules
    paths: [/healthz]
```

```sh
# Dry-run (log only — default):
go run ./cmd/vigilante -mode http -listen :8080 -target http://127.0.0.1:3000 \
  -policy vigilante-policy.yaml -block-mode log

# Enforce blocks via a dedicated iptables chain (requires root/CAP_NET_ADMIN):
go run ./cmd/vigilante -mode http -listen :8080 -target http://127.0.0.1:3000 \
  -policy vigilante-policy.yaml -block-mode iptables -block-chain VIGILANTE

# nftables:
go run ./cmd/vigilante ... -block-mode nft -block-chain VIGILANTE
```

Rules match on `methods`, `hosts`, `paths` (glob: `*` segment, `**` across
segments), `path_prefixes`, and `cidrs`. The first match wins; unmatched
requests are allowed (deny is opt-in). Agent verdicts with
`action: recommend-block` are also fed to the enforcer. Loopback and
unspecified addresses are never blocked.

**Dynamic thresholds** auto-block a source after repeated bad verdicts (applies
to HTTP and TCP sources):

```sh
# Block a source after 5 high+ verdicts within 1 minute:
go run ./cmd/vigilante -mode http ... \
  -block-threshold 5 -block-window 1m -block-min-severity high -block-mode log
```

### 10. Persist & Deliver Alerts
Vigilante owns alerting: every agent verdict is appended to a rotating JSONL
store and (optionally) POSTed as JSON to a webhook — directly, or through a
webong/gateway Planner so Gateway's subscriber relays handle fan-out, retries,
and queuing. Delivery failures are counted, never block the hot path.

```sh
# Store only:
go run ./cmd/vigilante -mode demo -repo . -alert-file /var/log/vigilante/alerts.jsonl

# Store + direct webhook (e.g. Slack incoming webhook, SIEM collector):
go run ./cmd/vigilante -mode http -listen :8080 -target http://127.0.0.1:3000 \
  -alert-file /var/log/vigilante/alerts.jsonl \
  -alert-deliver-url https://hooks.example.com/vigilante \
  -alert-min-severity high

# Deliver through an upstream gateway/route-planner (fan-out via subscriber relays):
go run ./cmd/vigilante -mode gateway -gateway local -listen :8080 -target http://127.0.0.1:3000 \
  -planner-url http://127.0.0.1:8081 -planner-token "$TOKEN" \
  -alert-file /var/log/vigilante/alerts.jsonl \
  -alert-deliver-url https://unused.example
  # -> alerts POST to <planner-url>/vigilante/alerts with the internal token
```

Flags: `-alert-file`, `-alert-deliver-url`, `-alert-min-severity`
(`info|low|medium|high|critical`), `-alert-max-bytes` (rotation, default 10 MiB),
`-alert-keep` (rotated files retained, default 3). Webhook delivery **retries**
transient failures with exponential backoff (default 3 attempts, 250ms base).
When `-mode gateway` runs with a store, `/metrics` also exposes
`vigilante_alerts_{stored,delivered,failed}_total`.

### 11. Config File (YAML or JSON) — friendly setup
For systemd/containers — or just a cleaner command line — put everything in a
config file and override per-deployment via CLI flags (flags always win).
**Every CLI flag has a config key**, so setup is one file instead of a long
command. See [`deploy/vigilante.yaml.example`](deploy/vigilante.yaml.example)
for the fully-commented reference.

```yaml
# vigilante.yaml
mode: http
listen: ":8080"
target: "http://127.0.0.1:3000"
repo: auto

agent: builtin            # builtin | cli:<cmd> | supervised
agent_timeout: 30s

policy: /etc/vigilante/policy.yaml
block_mode: log           # log | iptables | nft
block_threshold: 5        # auto-block after N high+ verdicts
block_window: 1m

alert_file: /var/log/vigilante/alerts.jsonl
alert_min_severity: high
alert_deliver_url: https://hooks.example.com/vigilante

queue_size: 1024
sample_rate: 1.0
obs: true                 # dashboard + JSON API at /obs/*
```

```sh
vigilante -config vigilante.yaml
vigilante -config vigilante.yaml -listen :9443 -tls-cert cert.pem -tls-key key.pem   # override
```

**Config features:**
- YAML (`key: value`, inline `# comments`) **or** JSON — same keys.
- Types coerced automatically: strings, ints, floats, bools, **durations** (`30s`, `1m`).
- **Unknown keys are rejected** with the list of valid keys, so typos surface immediately.
- Lists/objects (e.g. rich JSON) belong in the JSON form.

### 12. Install (personal computer or server)

**Binary + optional systemd service:**
```sh
./install.sh                 # build to /usr/local/bin/vigilante
sudo ./install.sh systemd     # install config + systemd unit, enable + start
```

**Container** (build context is the parent of `vigilante/` + `ext/`, because
`go.mod` uses `replace => ../ext`):
```sh
cd ..   # the directory containing both vigilante/ and ext/
docker build -f vigilante/Dockerfile -t vigilante:latest .
docker run -p 8080:8080 -v /var/log/vigilante:/var/log/vigilante vigilante:latest
```

Deploy assets: [`deploy/vigilante.service`](deploy/vigilante.service) (hardened
systemd unit), [`deploy/vigilante.json.example`](deploy/vigilante.json.example),
[`Dockerfile`](Dockerfile). For `-block-mode iptables|nft`, the unit needs
`CAP_NET_ADMIN` (commented in the unit file).

### 13. Dashboard & Plugin API (obs ext plugin)
With an alert store present (default on via `-obs`), the **obs ext plugin**
(`ext.plugin/v1 vigilante.obs@v1`) serves:

- `GET /obs/dashboard` — HTML status page (severity counts + recent alerts)
- `GET /obs/alerts?severity=&limit=` — JSON recent alerts
- `GET /obs/summary` — JSON severity + queue + store counters
- `/metrics` gains `vigilante_alerts_by_severity{severity=...}`

It lives in [`ext/obs`](ext/obs) (plugins live under `ext/`, not `internal/`),
runs behind a real `engine.Session`, and reads alerts from the core JSONL store
without owning persistence.

### 14. Health & Metrics (all modes)
Every HTTP-serving mode (`http`, `middleware`, `gateway`) exposes:
- `GET /healthz` (alias `/health`) → `ok`
- `GET /ready` → `ready`
- `GET /metrics` → `vigilante_queue_{enqueued,dropped,sampled_out}_total`,
  `vigilante_redact_hits_total`,
  `vigilante_alerts_{stored,delivered,failed}_total` (when an alert store is on)

### 15. Redaction & Sampling (safe at volume)
Mirrored traffic is scrubbed before it reaches the agent or the alert store:
paths, query strings, and body previews have JWTs, `sk-`/`ghp_`/`AKIA`/Slack
tokens, bearer/basic auth, `password`/`token`/`secret` key-values, and email
addresses replaced with `[REDACTED]` (sensitive headers were already masked).
Redaction is deterministic and counted in `vigilante_redact_hits_total`.

Sampling lets a busy server dispatch only a fraction of flows to the agent —
never affecting primary traffic:

```sh
# Triaged 1 in 10 flows (policy deny/block requests are still enforced):
go run ./cmd/vigilante -mode http -listen :8080 -target http://127.0.0.1:3000 \
  -sample-rate 0.1
```

`-sample-rate` accepts `0..1` (`<=0` or `1` = mirror all), can also be set as
`sample_rate` in the config file, and reports skipped flows via
`vigilante_queue_sampled_out_total`.

### 16. Run Tests
```sh
go test -race -v ./...
```
