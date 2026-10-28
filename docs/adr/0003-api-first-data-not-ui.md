# ADR 0003 — Offer data over REST and RPC; ship no UI

- Status: Accepted
- Date: 2026-10-28
- Deciders: Vigilante maintainers
- Related: [ADR 0001](0001-stateless-core-stateful-plugins.md), [ADR 0002](0002-open-ended-action-contract.md)

## Context

The detection, state, and action machinery are now in place. The remaining
question is delivery: how does a consumer observe and drive Vigilante?

Two options exist. We could build the dashboard — actors, risk scores, triage
state, "Act now" — into the product. Or we could expose the data and the
decision surface as stable interfaces and let anyone build the presentation
layer they actually need (a SOC wallboard, a Slack bot, a CI gate, a
third-party incident tool).

The dashboard is one consumer among many, and it is the one most likely to be
rewritten for someone's particular workflow. Building it into the core would
couple the product to one rendering, and — worse — would tempt presentation
concerns (HTML, filters, charts) back into a core whose only job is to be a
reliable data and enforcement surface.

## Decision

### 1. Vigilante ships interfaces, not a UI

The product surface is data. Presentation is the consumer's concern. Anything
that renders pixels is a consumer, not the core.

### 2. Two interfaces, same data model

**REST (JSON over HTTP)** for humans, scripts, and web frontends:

| Endpoint | Returns |
| --- | --- |
| `GET /obs/alerts?severity=&limit=` | Recent alerts, newest first. |
| `GET /obs/summary` | Severity counts, queue counters, stored/delivered/failed. |
| `GET /obs/actions` | Capabilities (what is available), active decisions (what is in force), decisions (the audit). |
| `GET /obs/actors?suspicious=&limit=` | Actors aggregated from flows: key, first/last seen, counts, verdicts, tags, decaying risk. |
| `GET /metrics` | Prometheus text: queue, redaction, alert, and severity counters. |
| `GET /healthz` / `/ready` | Liveness and readiness. |
| `GET /obs/dashboard` | A **sample** HTML page that renders `/obs/alerts`. Not the product. |

**RPC (`ext.plugin/v1`)** for programs and out-of-process consumers:

| Contract | Operations | Surface |
| --- | --- | --- |
| `vigilante.obs@v1` | `summary`, `alerts`, `actions`, `actors`, `dashboard` | observation |
| `vigilante.agent@v1` | `triage-flow` | observation |
| flow (host → sink) | `ingest` | publication |

The RPC path is the same `ext.plugin/v1` machinery the agent and obs plugins
already use, with `inprocess`, `jsonline`, and (via the engine's transport
packages) subprocess/gRPC backends. A consumer runs out-of-process exactly like
`-agent supervised` runs the agent.

### 3. The data model is the contract

The wire types — `alert.Record`, `obs.ActionsOutput`, `obs.ActorsOutput`,
`decision.Entry` — are the API. They are versioned by the contract
(`vigilante.obs@v1`) and must not change in place. Consumers build against the
schema, so the schema is treated with the same care as a public API: additive
changes only, new contract versions for breaking changes.

Stateful data lives in a `flow.Sink`, never in the core: the actor index folds
every triaged flow into a bounded, in-memory view of who is doing what, scored
with a transparent, decaying risk number. That is a data service, exposed over
the same two interfaces as everything else.

### 4. The write path stays off REST until operator auth exists

Read endpoints are safe and unauthenticated (by design, for now). The action
registry is host-internal: decisions are executed in-process, or over a future
authenticated RPC. Exposing `execute`/`revert` over HTTP without authentication
would turn the data surface into a remote-control surface, which is a separate,
security-reviewed change (see ADR 0002 non-goals).

### 5. Streaming is a future addition, not a different model

Live flow delivery (SSE, WebSocket, a queue) would reuse the `flow.Sink` /
`flow.Event` contract. It is not built yet because it needs backpressure and
subscription semantics the request/response bridge does not have; when it is
added it is another transport over the same event type, not a new data model.

## Consequences

### Positive

- Anyone can build the dashboard, the bot, the CLI, or the integration without
  us. The "Act now" panel is generated from `/obs/actions`, so a custom UI gets
  new actions for free.
- The core stays free of presentation code and its churn.
- The schema as API forces stability where it matters and keeps churn where it
  does not (the sample dashboard).

### Negative / risks

- **Schema drift breaks consumers.** Mitigation: contract versioning and
  additive-only changes; the sample dashboard exercises the same endpoints, so
  it doubles as a smoke test.
- **No batteries-included UI.** Some users expect one. Mitigation: keep the
  sample dashboard small and honest, and document it as a reference, not a
  product.
- **Read is open.** Until operator auth exists, anyone who can reach the port can
  read alerts (including attacker metadata). Mitigation: bind to loopback by
  default (`-listen 127.0.0.1:8080`), as today, and revisit when the write path
  lands.

## Alternatives considered

| Alternative | Why rejected |
| --- | --- |
| Build the full dashboard in the core | Couples product to one UI; drags presentation concerns into a data/enforcement core. |
| REST only | Programs and in-network consumers get a friendlier surface over the existing ext.plugin/v1 RPC; the two share a model so supporting both is cheap. |
| RPC only | A plain `curl`-able surface is table stakes for a data product and for hand-debugging. |
| Write path over REST now | Remote control needs operator auth first; shipping it unauthenticated is a security hole. |
| Bespoke dashboard plugin in the core tree | One more thing to maintain that has nothing to do with detection or enforcement. |

## Implementation map

| Concern | Package / file |
| --- | --- |
| REST bridge | `ext/obs/obs.go` (`ServeHTTP`) |
| Actions read view | `ext/obs/obs.go` (`ActionsOutput`), `cmd/vigilante/main.go` (`actionView`) |
| Alert/summary read | `ext/obs/obs.go` |
| Actors read | `ext/obs/obs.go` (`ActorsOutput`), `internal/actor`, `cmd/vigilante/main.go` (`actorView`) |
| RPC contracts | `ext/obs`, `ext/agent`, `internal/flow` |
| Sample dashboard | `ext/obs/obs.go` (`renderDashboard`) — disposable |

## Non-goals

- Shipping a production dashboard, charting, or alerting UI.
- Operator authentication (tracked for the write path).
- Real-time push/streaming transport.
- A query language; filters are endpoint parameters for now.
