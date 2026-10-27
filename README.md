# Vigilante

**Vigilante** is a network-stack middleware and context-enrichment pipeline built on [`github.com/webong/ext`](https://github.com/webong/ext).

As packets and requests enter a system, Vigilante non-blockingly copies them into an asynchronous ring buffer, joins each flow with live OS, server process, network topology, and application dependency state, projects the relationships into a shared `ext/res/system/graph` store, and dispatches the enriched context to an `ext.plugin/v1` agent.

## Architecture & `webong/ext` Integration

| Layer | Package | Responsibility |
| --- | --- | --- |
| **Hot-Path Network Tap** | `internal/tap` | Non-blocking HTTP reverse-proxy / middleware and TCP stream tee (`MirrorQueue`). Drops mirrored copies on backpressure so primary upstream traffic never stalls. Redacts sensitive auth/cookie headers before agent dispatch. |
| **OS, Process & Socket Discovery** | `github.com/webong/ext/res/system` | Inventories host shells, filesystems, and running processes (`ScanHost`, `ScanProcesses`, `InspectProcess`) to map ports/sockets to PIDs, executable paths, open sockets, and memory-mapped shared libraries. |
| **Network Topology** | `github.com/webong/ext/res/system/network` | Zero-traffic observation of local interfaces, assigned IP addresses, route tables, and DNS resolver settings (`network.Discover`). |
| **Application Dependency Graph** | `internal/deps` | Extracts module dependency graphs from compiled Go binaries (`debug/buildinfo`), `go.mod`, `package.json`, and `res/system` shared library mappings. |
| **Transactional System Graph** | `internal/schema` + `res/system/graph` | Registers the `vigilante.net` schema alongside `ext.system` in the same `graph.Store`, linking `listener -> flow -> process-ref -> dependency` and `flow -> agent-alert`. |
| **Agent Gateway** | `internal/agent` + `pkg/ext-go/engine` | Typed `ext.plugin/v1` contract (`vigilante.agent@v1` / `triage-flow`) using `engine/guest/author` and `engine.Session`. Supports in-process guests, `jsonline` subprocesses, or `res/system/supervisor`-managed agents. |

## Quick Start

### 1. Run the Self-Contained End-to-End Demo
Spins up a local upstream server, places the Vigilante tap middleware in front of it, runs a live `ext/res/system` host/process/network scan, fires sample requests (normal, path traversal, and SQL injection), and outputs the agent's context-enriched verdicts:

```sh
go run ./cmd/vigilante -mode demo
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

### 4. Run Tests
```sh
go test -race -v ./...
```
