# ADR 0001 — Keep the core stateless; publish flows to plugins

- Status: Accepted
- Date: 2026-10-28
- Deciders: Vigilante maintainers
- Related: [ADR 0002](0002-open-ended-action-contract.md)

## Context

Vigilante's core is a stateless, per-flow pipeline:

```
capture → enrich → triage → publish
```

That shape is what makes it safe to put in front of production traffic: no
database, no per-request coordination, no unbounded memory, and a crash loses at
most the in-flight mirror queue. It also scales horizontally without a
consensus protocol, because instances never need to agree on anything.

The console we want is the opposite. It needs actor history (first/last seen,
request counts, risk over time), triage state (pending / triaged / dismissed),
a human decision queue, and long-lived decisions. Hosting that in the core would
mean a write path on the request hot path, a schema to migrate, and a recovery
story after every crash — the exact properties the core was built to avoid.

Two seams already existed but were wired as Go closures rather than contracts:

| Seam | Before | Problem |
| --- | --- | --- |
| `correlator.Options.OnVerdict` | in-process callback | Only one consumer; no replay; cannot be out-of-process |
| `tap.PolicyGate` | `func(*http.Request) string` | No way for a stateful consumer to feed decisions back |
| `block.Enforcer` | called directly from `main.go` | Every new response type grows the core |

The question this ADR answers: where does state live, and how do stateful
consumers influence a stateless request path without turning it stateful?

## Decision

### 1. The core owns capture, enrichment, triage, gating, and publication — nothing else

The core never stores actor history, operator state, or decisions across
requests beyond an in-memory, time-bounded snapshot. If a feature needs to
remember something between flows, it is a plugin.

### 2. Publication is a contract: `internal/flow`

```go
type Event struct { /* verdict + actor-relevant fields, no payloads */ }
type Sink  interface { Ingest(context.Context, Event) error }
```

`flow.Publisher` fans out over a **bounded** queue. A full queue drops and
counts; a slow sink never applies backpressure to traffic. The JSONL alert store
is the baseline sink (`flow.AlertSink`) and the durable replay source for any
stateful consumer that restarts.

This replaces the ad-hoc alert write in `main.go` and makes the console a normal
`Sink` rather than a special case.

### 3. Enforcement is a snapshot, not an RPC: `internal/decision`

Applied decisions are written to `decision.Set`, an in-memory TTL set keyed by
scope (`ip`, `cidr`, `actor`, `fingerprint`, `global`). The gate consults it
inline with O(1) exact-key lookup (plus a small CIDR scan).

Consequences that matter:

- The request path never calls a plugin, a database, or a network service.
- If every plugin dies, the core keeps the last snapshot and entries expire on
  their own; the owning registry reverts the external side when it returns.
- A crashed writer cannot pin a rule forever. This is the single most important
  safety property of the design.

Lookup precedence is exact IP → actor → fingerprint → CIDR → global. Identity
keys outrank a network range because they describe the actor, while a CIDR
describes a population that may contain it.

### 4. Static policy is always evaluated first: `internal/gate`

`gate.New` runs the configured policy, and only if it allows the request does it
consult the snapshot. The snapshot can only make the outcome **stricter**. A
missing, stale, or empty snapshot can never loosen a configured deny rule.

Unknown action identifiers fail closed (a decision is in force, so do not
forward). The tap only understands `allow`/`deny`/`block`; richer responses are
mapped by the ingress, not smuggled through the gate.

### 5. Stateful consumers write through the host, not around it

A console does not touch iptables, and it does not get a firewall handle. It
calls `action.Registry`, which validates the request against host policy,
executes the registered executor, audits the decision, and pushes it into the
snapshot. See [ADR 0002](0002-open-ended-action-contract.md).

## Consequences

### Positive

- Plugin latency, failure, and restarts cannot affect request latency.
- Horizontal scaling stays trivial: each instance enforces its own snapshot; the
  durable record is the shared alert store.
- The console can be rewritten, restarted, or run out-of-process without a core
  release.
- A compromised or buggy console is bounded by the allowlist, the TTL ceiling,
  and the snapshot's expiry.

### Negative / risks

- **Per-instance decisions.** A block applied on instance A is not enforced on
  instance B unless the console applies it to each. Mitigation: decisions are
  derived from the shared alert stream, and the console can target instances
  explicitly; a future shared decision bus is a plugin, not a core change.
- **Event loss on crash.** The publisher is best-effort. Mitigation: every
  published flow is written to the alert store (subject to
  `-alert-min-severity`), and a consumer replays from it on restart.
- **Snapshot divergence.** Two instances may briefly disagree. Mitigation: TTLs
  bound the divergence window; the firewall remains the authoritative control for
  `block`.
- **Temptation to add "just one" piece of state.** This is the real risk.
  Reviewers should reject core changes that persist per-actor state.

## Alternatives considered

| Alternative | Why rejected |
| --- | --- |
| Store actors/decisions in the core | Write path on the hot path; migration and recovery burden; breaks stateless scaling. |
| Keep callbacks only (no contract) | Single consumer, no replay, no out-of-process plugins, silent coupling. |
| Synchronous RPC to the console per request | Console latency and availability become traffic latency; violates the fail-open property. |
| Core-owned rule manager with persistence | Same state problem, plus distributed invalidation. |
| Let plugins program the firewall directly | Removes the host's authority, audit, TTL, and revert guarantees. |
| Push decisions into static policy files | Not dynamic, not auditable per decision, not revertible. |

## Implementation map

| Concern | Package / file |
| --- | --- |
| Flow event + fan-out | `internal/flow/flow.go` |
| Baseline durable sink | `internal/flow/alert_sink.go` |
| TTL snapshot | `internal/decision/decision.go` |
| Policy + snapshot composition | `internal/gate/gate.go` |
| Action authority | `internal/action/registry.go` |
| Wiring | `cmd/vigilante/main.go` |

## Non-goals

- A distributed decision store or consensus between instances.
- Operator authentication for the console. That is the console's concern; the
  core does not expose action execution over the wire yet.
- Replacing the firewall. `block` remains one action among many.
