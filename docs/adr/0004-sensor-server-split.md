# ADR 0004 — Split sensors from a central server, keep context at the edge

- Status: Accepted
- Date: 2026-10-30
- Deciders: Vigilante maintainers
- Related: [ADR 0001](0001-stateless-core-stateful-plugins.md), [ADR 0002](0002-open-ended-action-contract.md), [ADR 0003](0003-api-first-data-not-ui.md)

## Context

Every Vigilante deployment today is one process that captures, triages,
stores, reviews and enforces. That is the right default, but it does not
scale to a fleet: five reverse proxies mean five history stores, five review
queues and five dashboards, and an operator who blocks an actor on one
instance has not blocked it on the other four. ADR 0001 recorded this as its
first negative consequence ("per-instance decisions") and deferred a shared
decision bus.

The durable, actor-level half of the system now exists in core
(`internal/history`, `internal/behavior`, `ext/triage`, the review queue and
the dashboard), and it is exactly the half a fleet wants centralised. An actor
that spreads requests across instances is only visible when their flows meet
in one store.

Two things are different from a typical sensor/collector design, and they
drive the decision:

1. **Vigilante's per-flow triage needs local context.** The agent envelope
   carries the owning process, the dependency graph, the matched handler and
   source excerpts from the repository *on the host that served the request*.
   A central server does not have that host, that process table or that
   checkout.
2. **The request path must never wait on the network** (ADR 0001 §3).
   Enforcement is an in-memory, TTL-bounded snapshot; that has to stay true
   when the decisions come from somewhere else.

The dashboard's sensor endpoints also already exist and are misleading:
`POST /obs/api/sensors` returns a `vk_` key that is never stored, so a key the
UI hands out cannot authenticate anything. This ADR is also the fix for that.

## Decision

### 1. Two roles of the same binary; single-process stays the default

- A **sensor** is any existing mode (`http`, `tcp`, `middleware`, `gateway`,
  `passive`, `sidecar`) started with `-server <url>` and a sensor key. It
  keeps capture, enrichment, policy, the gate, the decision snapshot and
  per-flow agent triage.
- The **server** is `-mode server`. It owns history, behavior rules, actor
  triage, the review queue, the action registry for fleet decisions, sensor
  keys, and the dashboard.

Without `-server`, nothing changes: one process does both, as today. The split
is an opt-in deployment shape, not a new product.

### 2. Per-flow triage stays at the edge; actor analysis moves to the server

The sensor triages each flow with its local context and ships the **result**:
the published `flow.Event` (verdict, severity, findings, matched handler and
advisories, redacted headers, fingerprints). It never ships payload previews
or source excerpts. The server runs everything that needs many flows: history,
behavior scoring, LLM actor triage, suggestions.

This keeps the property that makes Vigilante different from a log collector
(code-aware verdicts) without shipping repositories or process tables off the
host.

### 3. Shipping is a `flow.Sink`, so it inherits the publisher's guarantees

The sensor's uplink is one more `flow.Sink` on the existing bounded publisher.
It batches events (by count or every 2s), gzips them and `POST`s them to
`/v1/ingest`. A slow or unreachable server never backpressures traffic:

- the sink's own buffer is bounded; overflow drops and counts;
- a failed upload keeps the newest events up to a cap and retries with backoff;
- every batch reports its drop count so the server can show loss per sensor.

Local sinks (the JSONL alert store, the in-memory actor index) keep working
beside it, so a sensor that loses its server still has local alerts.

### 4. Decisions flow down as a snapshot, pulled with an ETag

Sensors poll `GET /v1/decisions` (every 5s, `If-None-Match`) and receive the
server's full set of active, applied decisions. The server answers `304` when
nothing changed.

The sensor keeps them in a **second** `decision.Set`, separate from decisions
it made locally (its block threshold, its own actions), and replaces that set
wholesale on each change. The gate consults both and takes the strictest
outcome (`block`/`deny` > `challenge` > `rate_limit`). Keeping the sets apart
means a server sync can never erase a local decision, and a local decision can
never mask a stricter fleet one.

The ADR 0001 safety properties carry over unchanged: entries are TTL-bound, a
sensor that loses its server keeps the last snapshot and the entries expire on
their own, and static policy still runs first and can only be made stricter.

### 5. Executors run where their effect lives

The server's registry applies a decision once and pushes it to every sensor
through the snapshot; each sensor enforces it at L7 through its gate. Remote
executors (`notify`, `vigilante.action@v1` plugins for a WAF or CDN) run on the
server, once for the fleet. Host-local firewall executors (`block`) are
reconciled on each sensor as snapshots arrive: IP-scoped `block`/`deny`
decisions are programmed into the sensor's `block.Enforcer`, and revoked or
expired fleet blocks are removed unless a local decision still blocks the IP.

### 6. Sensors authenticate with per-sensor keys; the server trusts nothing inside a batch

- `vg_`-prefixed random keys, created from the dashboard or CLI, shown once,
  stored only as SHA-256. Deleting a sensor revokes its key immediately.
- The server stamps each event with the sensor ID derived from the key. It
  never trusts a sensor-supplied identity.
- A key authorises shipping and reading decisions; it cannot create decisions,
  read history or call the dashboard API.
- The server limits batch size (bytes, decompressed bytes, item count) and
  per-sensor request rate, and sanitizes every event: addresses must parse,
  timestamps outside `[-24h, +5m]` are reset to receipt time, strings are
  clipped, unknown verdicts and severities are normalised. The sensor is
  trusted with a key; the data in the batch came from the internet.
- The wire is HTTPS in production. A plain-HTTP server URL is refused unless
  it is loopback or explicitly allowed.

### 7. The protocol is core, not a plugin

Sensor and server are two instances of Vigilante's own core, not a
replaceable guest, so the wire types live in `internal/fleet`, versioned under
`/v1`. The ext.plugin/v1 contracts (agent, obs, triage, action) are unaffected
and run on whichever side owns their concern.

## Consequences

### Positive

- One history, one review queue and one dashboard for a fleet; actors that
  spread across instances are visible.
- A decision applied once is enforced everywhere within one poll interval.
- Resolves ADR 0001's per-instance-decision risk without putting a network
  call on the request path.
- Code-aware triage is unchanged and stays local.
- The dashboard's sensor management becomes real.

### Negative / risks

- **Enforcement lag.** A fleet decision takes up to one poll interval (5s) to
  reach a sensor. Local decisions remain immediate. Acceptable for actor-level
  decisions, which are made over minutes.
- **Loss under long outages.** A sensor's backlog is capped; a long server
  outage loses the oldest events. Drops are counted and reported per sensor,
  and local alerts are unaffected.
- **Server as a target.** The server holds history for the whole fleet. It
  needs TLS, the operator token, and network placement accordingly; sensor
  keys are scoped so a stolen one cannot read it.
- **Two decision sources.** Operators can see a local decision and a fleet
  decision for the same actor. The obs API reports each decision's source.
- **Clock skew.** Sensors and server compare timestamps; skew beyond the
  sanitization window is corrected to receipt time, which can reorder flows
  slightly in history.

## Alternatives considered

| Alternative | Why rejected |
| --- | --- |
| Ship raw requests and triage centrally (lookout's model) | Loses host, process and repository context, which is Vigilante's advantage; or ships source code off-host. |
| Push decisions to sensors (server-initiated) | Needs inbound connectivity to every sensor and per-sensor delivery state; pull with ETag is simpler and survives NAT. |
| Sensors query the server per request | Puts the network on the request path; violates ADR 0001. |
| A message broker (NATS, Kafka) between them | Another system to operate for a problem HTTP batching already solves at this scale; can be added later as another sink. |
| Shared database between instances | Couples every instance to one database's availability and schema; the request path would depend on it. |
| Merge fleet decisions into the local set | A sync could overwrite a local decision with the same key, and replacing the set wholesale would erase local ones. |
| Make the uplink an ext.plugin/v1 guest | Both ends are Vigilante core; a plugin boundary adds a contract without a second implementer. |

## Implementation plan

1. `internal/fleet`: wire types (`Batch`, `Decisions`), sanitization, key
   generation and hashing.
2. `internal/history`: sensors table (name, key hash, created, last seen,
   dropped), a sensor ID on flows and egress.
3. Server: `-mode server` mounting `/v1/ingest` and `/v1/decisions` beside
   the existing obs and dashboard routes; ingest feeds the publisher. Real
   dashboard sensor create/list/delete.
4. Sensor: `fleet.Uplink` sink (batch, gzip, backoff, drop counting) and the
   decision poller writing a remote `decision.Set`.
5. `internal/gate`: consult the local and remote sets and take the strictest
   outcome; the obs actions view shows each decision's source.
6. Flags and config: `-server`, `-sensor-key` (env `VIGILANTE_SENSOR_KEY`),
   `-server-insecure`; docs and an end-to-end test with one server and two
   sensors.

## Implementation map

| Concern | Package / file |
| --- | --- |
| Wire types, sanitization, keys | `internal/fleet` |
| Uplink sink and decision poller | `internal/fleet` |
| Server routes | `internal/fleet`, `cmd/vigilante` |
| Sensor registry | `internal/history` |
| Strictest-of-two gate | `internal/gate` |
| Dashboard sensors API | `ext/obs/extension.go` (`Extension.ServeHTTP`) |
