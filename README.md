# Vigilante

**Vigilante** is a network-stack middleware and context-enrichment pipeline built on [`github.com/webong/ext`](https://github.com/webong/ext).

As packets and requests enter a system, Vigilante non-blockingly copies them into an asynchronous ring buffer, joins each flow with live OS, server process, network topology, and application dependency state, projects the relationships into a shared `ext/res/system/graph` store, and dispatches the enriched context to an `ext.plugin/v1` agent.

## Architecture & `webong/ext` Integration

| Layer | Package | Responsibility |
| --- | --- | --- |
| **Hot-Path Network Tap** | `internal/tap` | Non-blocking HTTP reverse-proxy / middleware and TCP stream tee (`MirrorQueue`). Drops mirrored copies on backpressure so primary upstream traffic never stalls. Redacts sensitive auth/cookie headers before agent dispatch. Exposes `tap.NewMirror` / `tap.PreviewRequest` for in-process embedding and external ingress adapters. |
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

### 7. Run Tests
```sh
go test -race -v ./...
```
