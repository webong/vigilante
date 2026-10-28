# Vigilante

Vigilante watches your service's network traffic and flags suspicious activity — path traversal, SQL injection, secret leaks — with full context about what's running, what's listening, and which dependencies are vulnerable.

Run it three ways:

- **As a proxy** in front of your app (HTTP or TCP, optional TLS).
- **As a passive sensor** on a network interface — no forwarding, just watching.
- **As an embedded tap** inside your Go HTTP server.

Every flow is enriched with live OS, process, socket, dependency-graph, and codebase context, then triaged by a pluggable agent. Verdicts can enforce allow/deny/block policy and are delivered to a JSONL store, a webhook, or an upstream gateway.

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
| `sidecar` | HTTP decision API (`/v1/decide`, `/v1/check`, `/v1/observe`) for proxy plugins. |

## Pointing at your codebase

`-repo` accepts **any Git repository** — GitHub, GitLab, Bitbucket, Gitea, self-hosted — as a full URL (`https://`, `ssh://`, `git://`, `file://`, scp-like `git@host:path`), a `host/owner/repo` or `owner/repo` shorthand, or a local directory.

```sh
# public, any host
-repo https://github.com/your-org/your-service
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
    paths:
      - /admin/*
  - name: block-git
    action: block           # mirrored for triage, then 403 + source block
    path_prefixes:
      - /.git/
  - name: allow-health
    action: allow
    paths:
      - /healthz
```

Rules match on `methods`, `hosts`, `paths` (glob), `path_prefixes`, and `cidrs`. `block` verdicts are enforced via `-block-mode log` (dry-run, default), `iptables`, or `nft`. Auto-block a source after repeated bad verdicts with `-block-threshold N -block-window 1m -block-min-severity high`.

## Actions

Detection is only half the job; an action is what the host is allowed to *do*
about it. Actions are pluggable, allowlisted, audited, and always time-bounded.

| Action | What it does |
| --- | --- |
| `block` (built-in) | Drops the source at the host firewall (`log`/`iptables`/`nft`). |
| `notify` (remote) | Calls any HTTP API — a WAF, load balancer, ticketing system, on-call pager — with a templated request. |

```sh
-action-allow block,notify     # only these ids may run; empty denies everything
-action-dry-run                # report what would happen, enforce nothing
-action-ttl 1h                 # default lifetime before the action is reverted
-action-max-ttl 24h            # host ceiling on any lifetime
-action-webhook https://api.cloudflare.com/client/v4/zones/$ZONE/rulesets/$ID/rules
-action-webhook-revert https://api.cloudflare.com/client/v4/zones/$ZONE/rulesets/$ID/rules/{ref}
-action-webhook-token "$CF_TOKEN"
```

Remote URLs and bodies are templates over `{target}`, `{scope}`, `{action}`,
`{reason}`, `{ttl}`, and `{ref}`. A create response may return `{"id": "..."}`
or `{"revert_ref": "..."}`; that handle is passed back as `{ref}` when the
decision expires or an operator reverts it. Nothing is hardcoded in the core, so
the same path covers a WAF rule, a load-balancer deny list, or a Slack message.

Applied decisions are pushed into an in-memory, TTL-bounded snapshot that the
request gate consults inline. Expired decisions are reverted automatically; a
crashed console can never leave a rule pinned forever. See
[`docs/adr/0001`](docs/adr/0001-stateless-core-stateful-plugins.md) for why the
core stays stateless and where state lives instead.

## Alerts

Every verdict is appended to a rotating JSONL store, and optionally POSTed to a webhook (directly, or through a webong/gateway Planner). Delivery failures are counted, never block the hot path.

```sh
-alert-file /var/log/vigilante/alerts.jsonl
-alert-deliver-url https://hooks.example.com/vigilante
-alert-min-severity high
```

## Data API & metrics

Vigilante ships data, not a UI. With an alert store present (default via
`-obs`), the obs plugin serves JSON and Prometheus text for anyone to build on;
the HTML dashboard is a sample, not the product. See
[`docs/adr/0003`](docs/adr/0003-api-first-data-not-ui.md).

| Endpoint | Returns |
| --- | --- |
| `GET /obs/alerts?severity=&limit=` | Recent alerts, newest first. |
| `GET /obs/summary` | Severity counts, queue counters, stored/delivered/failed. |
| `GET /obs/actions` | Action capabilities, active decisions, and the decision audit. |
| `GET /obs/actors?suspicious=&limit=` | Actors aggregated from flows: key (IP + TLS fingerprint), first/last seen, request counts, severity rollups, verdicts, tags, and a decaying risk score. |
| `GET /obs/dashboard` | Sample HTML that renders the same data as `/obs/alerts`. |
| `GET /metrics` | Prometheus text (queue, redaction, alert, severity counters). |
| `GET /healthz` `/ready` | Liveness and readiness. |

Actors are the stateful counterpart to the stateless core: the actor index is a
`flow.Sink` that folds every triaged flow into a bounded, in-memory view. Risk is
a transparent, decaying score — each flow adds severity-weighted points that age
out of a sliding window (`-actor-window`), and an actor is flagged suspicious at
`-actor-risk-threshold`. The `ai-agent`, `path-traversal`, `injection`, and `cve`
tags are derived from the verdict and user agent, not stored by hand.

Actors are keyed by address **and TLS ClientHello fingerprint (JA3)** when one is
available, so look-alike clients behind a NAT stay distinct. The fingerprint is
captured in the TLS-terminating modes (http/gateway/middleware with a cert) from
the parsed ClientHello, and from the raw ClientHello on the TCP tee.

The same data is available over `ext.plugin/v1` RPC (`vigilante.obs@v1`:
`summary`, `alerts`, `actions`, `dashboard`), so an out-of-process consumer can
run exactly like the agent does under `-agent supervised`.

Triaged flows are published to a bounded fan-out (`internal/flow`). The alert
store is the baseline sink; a stateful console is another `Sink` and never
backpressures live traffic — a full queue drops and counts.

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

## Inside your edge proxy

Run Vigilante as a plugin in the proxy you already operate, in [`pkg/`](pkg):

| Proxy | Integration |
| --- | --- |
| **Caddy** | Native module `http.handlers.vigilante` — `xcaddy build --with github.com/webong/vigilante/pkg/caddy` |
| **Traefik** | Yaegi middleware plugin, talking to `-mode sidecar` |
| **nginx** | `auth_request` + `mirror`, or an njs handler, talking to `-mode sidecar` |

```sh
# Decision API used by the Traefik and nginx plugins:
vigilante -mode sidecar -sidecar-listen 127.0.0.1:9090 \
  -target http://127.0.0.1:3000 -policy /etc/vigilante/policy.yaml
```

All three share the same policy engine, so rules behave identically. See
[`pkg/README.md`](pkg/README.md) for per-proxy setup.

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
