# ADR 0001 — Stateless core, stateful plugins, open-ended actions

Status: accepted

## Context

Vigilante's core is a stateless per-flow pipeline: capture → enrich → triage →
publish. That is what makes it cheap to run, easy to reason about, and safe to
put in front of production traffic.

The console we want (actors, risk scores, triage state, decision queue,
"Act now") is the opposite: it needs memory, aggregation, human state, and
long-lived external changes. Making the core stateful to host it would undo the
property that makes the core trustworthy.

At the same time, "respond" is not one thing. Blocking at the host firewall is
the only action implemented today, but the useful set is open-ended: disable a
Cloudflare WAF rule, add a load-balancer deny entry, quarantine a workload, open
a ticket, page an engineer. Hardcoding each one in `main.go` grows the core
without bound.

## Decision

1. **The core stays stateless.** It owns capture, enrichment, triage, the
   pre-forward gate, and publication. It never owns actor history or operator
   state.

2. **Publication is a contract, not a callback.** `internal/flow` defines
   `Event` and `Sink`. The core publishes to a bounded fan-out; a slow sink is
   dropped and counted, never allowed to backpressure traffic. The JSONL alert
   store is the baseline sink and the replay source for stateful consumers.

3. **Responses are a contract, not a switch.** `internal/action` defines
   `Capability`, `Request`, `Decision`, and `Executor`. Actions live in
   `ext/action/*`; the console renders its "Act now" panel from
   `Registry.Capabilities()`, so a new action needs no UI change.

4. **The host keeps the authority.** `action.Registry` owns the allowlist
   (`-action-allow`), the dry-run switch, the TTL ceiling, confirmation for
   destructive actions, the audit trail, and revert. A capability is a
   declaration, not a grant.

5. **Enforcement is a snapshot, not an RPC.** Applied decisions are written to
   `internal/decision.Set`, an in-memory TTL set. The gate consults it inline.
   If every plugin dies, the core keeps the last snapshot, entries expire on
   their own, and the registry reverts the external side.

6. **Static policy is always evaluated first.** The snapshot can only make the
   outcome stricter. A missing or stale snapshot can never loosen a configured
   deny rule.

## Consequences

- A killed console cannot pin a firewall rule: decisions expire and the reaper
  reverts them.
- Plugins can be slow, remote, or unreliable without affecting latency.
- Adding Cloudflare means writing an executor and pointing `-action-webhook` at
  its API; no core change.
- The core will keep tempting us to add "just one" piece of state. The line is:
  if it needs to remember something between flows, it is a plugin.
- Scaling the core horizontally is still safe: each instance enforces its own
  snapshot, and the durable record is the shared alert store.

## Non-goals

- A distributed decision store. Decisions are per-instance and time-bounded.
- Operator authentication. The console's authn/authz is its own concern; the
  core does not expose action execution over the wire yet.
