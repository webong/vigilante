# Architecture Decision Records

Short, dated records of decisions that shape Vigilante's architecture. Each one
states the context, the decision, its consequences, and the alternatives that
were rejected — so a future reader can tell whether a constraint still applies.

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-stateless-core-stateful-plugins.md) | Keep the core stateless; publish flows to plugins and enforce from a TTL snapshot | Accepted |
| [0002](0002-open-ended-action-contract.md) | Open-ended actions behind a host-owned contract with allowlist, TTL, audit, and revert | Accepted |
| [0003](0003-api-first-data-not-ui.md) | Offer data over REST and RPC; ship no UI | Accepted |

## Writing a new ADR

1. Copy the structure of an existing record: Context, Decision, Consequences,
   Alternatives, Implementation map.
2. Number it `NNNN-short-title.md`.
3. Add it to the table above.
4. Never rewrite an accepted ADR's decision after the fact. Supersede it with a
   new record that links back.
