# Vigilante

**Vigilante** is a network-stack middleware and context-enrichment pipeline built on [`github.com/webong/ext`](https://github.com/webong/ext).

As packets and requests enter a system, Vigilante non-blockingly copies them into an asynchronous ring buffer, joins each flow with live OS, server process, network topology, and application dependency state, projects the relationships into a shared `ext/res/system/graph` store, and dispatches the enriched context to an `ext.plugin/v1` agent.

## Architecture & `webong/ext` Integration

| Layer | Package | Responsibility |
| --- | --- | --- |
| **Hot-Path Network Tap** | `internal/tap` | Non-blocking HTTP reverse-proxy / middleware and TCP stream tee (`MirrorQueue`). Drops mirrored copies on backpressure so primary upstream traffic never stalls. Redacts sensitive auth/cookie headers before agent dispatch. Exposes `tap.NewMirror` / `tap.PreviewRequest` for in-process embedding and external ingress adapters. |
| **Redaction & Sampling** | `internal/redact` + `tap.MirrorQueue` | Scrubs JWTs, API keys, bearer/basic auth, secret key-values, and emails from paths/queries/body previews (deterministic, counted); lock-free `-sample-rate` dispatches only a fraction of flows to the agent under load. |
| **Status Endpoints** | `internal/status` | Shared `/healthz`, `/health`, `/ready`, and `/metrics` (queue + alert counters) mounted on every HTTP-serving mode. |
| **Alert Store & Delivery** | `internal/alert` | Append-only JSONL verdict store with size-based rotation and severity filtering; pluggable delivery — direct webhook POST or via a webong/gateway Planner (`/vigilante/alerts`) so subscriber relays own fan-out/retries. Failures are counted, never block the hot path. |
| **Policy & Block Enforcement** | `internal/policy` + `internal/block` | Declarative allow/deny/block rules (path globs, hosts, methods, CIDRs) evaluated before forwarding; `block` verdicts enforced via a pluggable backend — dry-run `log`, `iptables`, or `nft` — with loopback/unspecified guards and idempotent chain provisioning. |
| **webong/gateway Spinner Adapter** | `internal/gateway` | Runs Vigilante as the relay observation point for a [webong/gateway](https://github.com/webong/gateway) Spinner-style ingress: public listener with optional TLS, upstream forwarding, optional Planner route decisions (fail-open), and Spinner-parity `/health`, `/ready`, `/metrics` endpoints. Mirrors Spinner's config surface without importing its separate Go module. |
| **OS, Process & Socket Discovery** | `github.com/webong/ext/res/system` | Inventories host shells, filesystems, and running processes (`ScanHost`, `ScanProcesses`, `InspectProcess`) to map ports/sockets to PIDs, executable paths, open sockets, and memory-mapped shared libraries. |
| **Network Topology** | `github.com/webong/ext/res/system/network` | Zero-traffic observation of local interfaces, assigned IP addresses, route tables, and DNS resolver settings (`network.Discover`). |
| **Application Dependency Graph** | `internal/deps` | Extracts module dependency graphs from compiled Go binaries (`debug/buildinfo`), `go.mod`, `go.sum`, `package.json`, `package-lock.json`, `Cargo.lock`, `uv.lock`, `requirements.txt`, and `res/system` shared library mappings, plus CVE advisory matching. |
| **Codebase & Git Repo Indexer** | `internal/repo` | Clones or opens **any** Git repository — GitHub, GitLab, Bitbucket, Gitea, self-hosted — via a full URL (`https://`, `ssh://`, `git://`, `file://`, scp-like `git@host:path`), a `host/owner/repo` or `owner/repo` shorthand (`VIGILANTE_GIT_HOST` selects the default host), or a local directory (`-repo`). **Private repos** authenticate with an HTTPS token (`-repo-token` / `VIGILANTE_GIT_TOKEN`, handed to git via a private `GIT_ASKPASS` helper — never argv or `.git/config`), a specific SSH key (`-repo-ssh-key` / `VIGILANTE_GIT_SSH_KEY`), an ssh-agent, or a configured git credential helper. Computes its file tree digest, discovers HTTP/RPC route handlers and security-sensitive code sinks (`filesystem`, `sql`, `exec`), and serves root-jailed source snippets to the agent over `ext.plugin/v1` reverse calls (`vigilante.host@v1/read-source`). |
| **Transactional System Graph** | `internal/schema` + `res/system/graph` | Registers the `vigilante.net` schema alongside `ext.system` in the same `graph.Store`, linking `listener -> flow -> process-ref -> codebase -> route-handler`, `process-ref -> dependency`, and `flow -> agent-alert`. |
| **Agent Gateway** | `internal/agent` + `pkg/ext-go/engine` | Typed `ext.plugin/v1` contract (`vigilante.agent@v1` / `triage-flow`) using `engine/guest/author` and `engine.Session`. Supports in-process guests, `jsonline` subprocesses, and `res/system/supervisor`-managed agents with bidirectional reverse host callbacks (`query-graph` and `read-source`). |

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

### 2. Run as an HTTP Reverse-Proxy Tap
```sh
go run ./cmd/vigilante \
  -mode http \
  -listen 127.0.0.1:8080 \
  -target http://127.0.0.1:3000 \
  -graph-file ./vigilante-graph.json
```

### 3. Run as a TCP Stream Tap
```sh
go run ./cmd/vigilante \
  -mode tcp \
  -listen 127.0.0.1:8080 \
  -target 127.0.0.1:5432
```

### 4. Terminate TLS on the Tap (http / spinner modes)
```sh
go run ./cmd/vigilante \
  -mode http \
  -listen :8443 \
  -target http://127.0.0.1:3000 \
  -tls-cert /etc/vigilante/fullchain.pem \
  -tls-key  /etc/vigilante/privkey.pem
```

### 5. Run Behind / Alongside webong/gateway (Spinner ingress)
Vigilante can act as the relay observation point for a [webong/gateway](https://github.com/webong/gateway) Spinner-style ingress: Spinner owns the public listener, forwarding, and optional PHP Planner; Vigilante mirrors every proxied request and dispatches enriched flows to its agent.

```sh
# Spinner-style ingress with Vigilante as the relay observer (fail-open to the
# upstream if the Planner is unreachable):
go run ./cmd/vigilante \
  -mode spinner \
  -listen :8080 \
  -target http://127.0.0.1:3000 \
  -planner-url http://127.0.0.1:8081 \
  -planner-token "$INTERNAL_TOKEN"

# With TLS termination on the public listener:
go run ./cmd/vigilante -mode spinner -listen :8443 -target http://127.0.0.1:3000 \
  -tls-cert /etc/vigilante/fullchain.pem -tls-key /etc/vigilante/privkey.pem
```

Health endpoints follow Spinner parity: `/health`, `/ready`, and `/metrics`
(queue enqueued/dropped totals, observed request count).

### 6. Embed the Tap In-Process (middleware mode)
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

### 7. Enforce Policy (allow / deny / block)
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

### 8. Persist & Deliver Alerts
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

# Deliver through a Gateway Planner (fan-out via subscriber relays):
go run ./cmd/vigilante -mode spinner -listen :8080 -target http://127.0.0.1:3000 \
  -planner-url http://127.0.0.1:8081 -planner-token "$TOKEN" \
  -alert-file /var/log/vigilante/alerts.jsonl \
  -alert-deliver-url https://unused.example
  # -> alerts POST to <planner-url>/vigilante/alerts with the internal token
```

Flags: `-alert-file`, `-alert-deliver-url`, `-alert-min-severity`
(`info|low|medium|high|critical`), `-alert-max-bytes` (rotation, default 10 MiB),
`-alert-keep` (rotated files retained, default 3). When `-mode spinner` runs
with a store, `/metrics` also exposes `vigilante_alerts_{stored,delivered,failed}_total`.

### 9. Config File
For systemd/containers, put defaults in a config file and override per-deployment
via CLI flags (flags always win):

```json
// vigilante.json
{
  "mode": "http",
  "listen": ":8080",
  "target": "http://127.0.0.1:3000",
  "repo": "https://github.com/owner/app",
  "policy": "/etc/vigilante/policy.yaml",
  "block_mode": "log",
  "alert_file": "/var/log/vigilante/alerts.jsonl",
  "alert_min_severity": "high",
  "alert_deliver_url": "https://hooks.example.com/vigilante",
  "queue_size": 1024
}
```

```sh
go run ./cmd/vigilante -config vigilante.json
go run ./cmd/vigilante -config vigilante.json -listen :9443 -tls-cert cert.pem -tls-key key.pem  # override
```

Flat YAML (`key: value` lines) is also accepted; lists/objects belong in JSON.
Unknown keys are rejected to catch typos early.

### 10. Health & Metrics (all modes)
Every HTTP-serving mode (`http`, `middleware`, `spinner`) exposes:
- `GET /healthz` (alias `/health`) → `ok`
- `GET /ready` → `ready`
- `GET /metrics` → `vigilante_queue_{enqueued,dropped,sampled_out}_total`,
  `vigilante_redact_hits_total`,
  `vigilante_alerts_{stored,delivered,failed}_total` (when an alert store is on)

### 11. Redaction & Sampling (safe at volume)
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

### 12. Run Tests
```sh
go test -race -v ./...
```
