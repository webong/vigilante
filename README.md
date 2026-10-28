# Vigilante

Vigilante watches your service's network traffic and flags suspicious activity — path traversal, SQL injection, secret leaks — with full context about what's running, what's listening, and which dependencies are vulnerable.

Run it three ways:

- **As a proxy** in front of your app (HTTP or TCP, optional TLS).
- **As a passive sensor** on a network interface — no forwarding, just watching.
- **As an embedded tap** inside your Go HTTP server.

Every flow is enriched with live OS, process, socket, dependency-graph, and codebase context (from [`webong/ext`](https://github.com/webong/ext)), then triaged by a pluggable agent. Verdicts can enforce allow/deny/block policy and are delivered to a JSONL store, a webhook, or an upstream gateway.

## Quick start

```sh
git clone https://github.com/webong/vigilante.git
cd vigilante
go run ./cmd/vigilante -mode demo -repo .
```

That runs a self-contained demo: it indexes the repo, starts a tap in front of a test server, fires a few suspicious requests, and prints the agent's verdicts.

### In front of your app

```sh
go run ./cmd/vigilante -mode http -listen 127.0.0.1:8080 -target http://127.0.0.1:3000 -repo .
```

Point clients at `:8080`; Vigilante forwards to your app on `:3000` while analyzing traffic. Add `-tls-cert cert.pem -tls-key key.pem` for HTTPS.

### Watch traffic you don't control

```sh
sudo go run ./cmd/vigilante -mode passive -passive-iface eth0 -repo auto
```

Linux (`AF_PACKET`), macOS (system `tcpdump`), and Windows (npcap `Packet.dll`) are supported.

## Modes

| Mode | What it does |
| --- | --- |
| `demo` | Self-contained sample: test server + tap + suspicious requests. |
| `http` | Reverse-proxy tap in front of your app (optional TLS termination). |
| `tcp` | TCP stream tee to a backend (e.g. Postgres on `:5432`). |
| `middleware` | Embed the tap inside an existing Go HTTP handler. |
| `gateway` | Own the listener (`local`) or attach to an ingress elsewhere (`external:<url>`). |
| `passive` | Observe interface traffic without being in the forwarding path. |

## Pointing at your codebase

`-repo` accepts **any Git repository** — GitHub, GitLab, Bitbucket, Gitea, self-hosted — as a full URL (`https://`, `ssh://`, `git://`, `file://`, scp-like `git@host:path`), a `host/owner/repo` or `owner/repo` shorthand, or a local directory.

```sh
# public, any host
-repo https://github.com/webong/ext
-repo git@gitlab.internal:platform/api.git

# private — HTTPS token (handed to git via a private GIT_ASKPASS helper, never in argv or .git/config)
VIGILANTE_GIT_TOKEN=ghp_xxx go run ./cmd/vigilante -mode demo -repo https://github.com/you/private

# private — specific SSH key (or use ssh-agent / a git credential helper)
-repo git@gitlab.internal:platform/api.git -repo-ssh-key ~/.ssh/vigilante_ed25519

# branch/tag and default host/user
-repo-ref release-1.2 -repo-user oauth2   # VIGILANTE_GIT_HOST, VIGILANTE_GIT_USER
```

`-repo auto` discovers the source root automatically from the port → listening PID → executable. Env fallbacks: `VIGILANTE_GIT_HOST`, `VIGILANTE_GIT_USER`, `VIGILANTE_GIT_TOKEN`, `VIGILANTE_GIT_SSH_KEY`.

## Agent backends

Triage runs behind one `ext.plugin/v1` contract (`vigilante.agent@v1`); the implementation is selectable with `-agent`:

| Backend | What it is |
| --- | --- |
| `builtin` (default) | In-process rule/analysis engine. |
| `cli:<cmd>` | Shell out to an external LLM/agent binary — envelope on stdin, JSON verdict on stdout, falls back to builtin on failure. |
| `supervised` | Out-of-process agent via `ext/res/system/supervisor` + jsonline IPC. |

```sh
-agent builtin
-agent cli:claude
-agent cli:/usr/local/bin/my-triage-agent
-agent supervised
```

## Configuration

Every CLI flag also has a config key, so you can put setup in one file and override per-deployment with flags (flags always win). YAML (`key: value`, inline `# comments`) or JSON; unknown keys are rejected so typos surface immediately. See [`deploy/vigilante.yaml.example`](deploy/vigilante.yaml.example).

```yaml
# vigilante.yaml
mode: http
listen: ":8080"
target: "http://127.0.0.1:3000"
repo: auto

agent: builtin
agent_timeout: 30s

policy: /etc/vigilante/policy.yaml
block_mode: log            # log | iptables | nft

alert_file: /var/log/vigilante/alerts.jsonl
alert_min_severity: high
alert_deliver_url: https://hooks.example.com/vigilante

queue_size: 1024
sample_rate: 1.0
obs: true
```

```sh
vigilante -config vigilante.yaml
```

## Policy & blocking

A declarative policy file gates requests before forwarding. The first match wins; unmatched requests are allowed (deny is opt-in). Loopback and unspecified addresses are never blocked.

```yaml
deny_cidrs:
  - 192.0.2.0/24
rules:
  - name: block-admin
    action: deny            # 403, not mirrored
    paths: [/admin/*]
  - name: block-git
    action: block           # mirrored for triage, then 403 + source block
    path_prefixes: ["/.git/"]
  - name: allow-health
    action: allow
    paths: [/healthz]
```

Rules match on `methods`, `hosts`, `paths` (glob), `path_prefixes`, and `cidrs`. `block` verdicts are enforced via `-block-mode log` (dry-run, default), `iptables`, or `nft`. Auto-block a source after repeated bad verdicts with `-block-threshold N -block-window 1m -block-min-severity high`.

## Alerts

Every verdict is appended to a rotating JSONL store, and optionally POSTed to a webhook (directly, or through a webong/gateway Planner). Delivery failures are counted, never block the hot path.

```sh
-alert-file /var/log/vigilante/alerts.jsonl
-alert-deliver-url https://hooks.example.com/vigilante
-alert-min-severity high
```

## Dashboard & metrics

With an alert store present (default via `-obs`), the obs plugin serves `GET /obs/dashboard` (HTML), `/obs/alerts`, and `/obs/summary`. Every HTTP-serving mode exposes `GET /healthz`, `/ready`, and `/metrics`.

## Redaction & sampling

Mirrored traffic is scrubbed before it reaches the agent or the alert store — JWTs, `sk-`/`ghp_`/`AKIA`/Slack tokens, bearer/basic auth, secret key-values, and emails are replaced with `[REDACTED]`. For high-traffic servers, `-sample-rate 0.1` dispatches only a fraction of flows to the agent without affecting primary traffic.

## Install

```sh
./install.sh                  # build to /usr/local/bin/vigilante
sudo ./install.sh systemd     # optional: systemd unit + enable
```

Container (build context is the parent of `vigilante/`):

```sh
cd ..
docker build -f vigilante/Dockerfile -t vigilante:latest .
docker run -p 8080:8080 -v /var/log/vigilante:/var/log/vigilante vigilante:latest
```

## Embed in your Go service

```go
queue := tap.NewMirrorQueue(256)
queue.Drain(ctx, 2, func(ctx context.Context, ev agent.PacketEvent) {
    // enrich + triage
})
http.ListenAndServe(":8080", tap.NewMirror(appHandler, queue, ":8080", "app:3000"))
```

## Tests

```sh
go test -race -v ./...
```

---

## Architecture

Traffic hits the tap, is mirrored non-blockingly into a queue, and enriched with live host/process/dependency/codebase state. The enriched envelope goes to an `ext.plugin/v1` agent, which returns a verdict. Plugins live in `ext/`; host wiring lives in `internal/`.

| Layer | Package |
| --- | --- |
| Sensor tap + passive capture | `ext/tap`, `ext/redact` |
| Agent gateway + backends | `ext/agent` |
| OS/process/socket + network topology | `github.com/webong/ext/res/system` (+ `network`) |
| Dependency graph + CVE matching | `internal/deps` |
| Codebase/Git indexer | `internal/repo` |
| Policy, block, alerts, status | `internal/policy`, `internal/block`, `internal/alert`, `internal/status` |
| Dashboard plugin | `ext/obs` |
| Graph schema | `internal/schema` + `res/system/graph` |
