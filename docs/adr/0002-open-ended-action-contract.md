# ADR 0002 — Open-ended actions behind a host-owned contract

- Status: Accepted
- Date: 2026-10-28
- Deciders: Vigilante maintainers
- Related: [ADR 0001](0001-stateless-core-stateful-plugins.md)

## Context

"Respond to a detection" is not one operation. Blocking at the host firewall is
the only one implemented today, but the useful set is open-ended:

- disable a Cloudflare WAF rule or add an IP to its block list;
- add a deny entry at a load balancer or CDN;
- rate-limit or challenge at an ingress;
- quarantine a workload, revoke a token, rotate a credential;
- open a ticket, page an on-call engineer, post to a chat channel.

Each has a different API, a different notion of scope (IP, CIDR, actor,
fingerprint), and a different undo. Hardcoding them in `main.go` grows the core
without bound and makes the console's "Act now" panel a switch statement.

The constraint from [ADR 0001](0001-stateless-core-stateful-plugins.md): the core
stays stateless, and no action may run just because a plugin asked for it.

## Decision

### 1. One contract: `internal/action`

```go
type Executor interface {
    Capability() Capability
    Execute(ctx context.Context, req Request) (Result, error)
    Revert(ctx context.Context, d Decision) error
}
```

- `Capability` declares the id, label, supported scopes, TTL bounds,
  reversibility, destructiveness, and parameters. A console can render its
  action panel from the union of registered capabilities, so a new action needs
  no UI change.
- `Request` carries the scope, target, TTL, reason, operator, confirmation bit,
  and evidence.
- `Decision` is the audit record: id, status, revert handle, timestamps.
- `Result` returns the remote-side handle (`RevertRef`) and a human description.

Executors live in `internal/action/*`, beside the registry that authorizes them; they are Go `action.Executor` implementations, not `ext.plugin/v1` guests.

### 2. The registry owns the authority

`action.Registry` is the only path from a detection to an effect. It enforces:

| Rail | Behaviour |
| --- | --- |
| Allowlist | `-action-allow` is an explicit list. Empty denies every action, even a registered one. |
| Dry-run | `-action-dry-run` forces report-only; a dry run never enters the snapshot. |
| Scope validation | The requested scope must be declared by the capability. |
| Confirmation | Destructive actions require the confirmation bit or a non-automation operator label. |
| TTL | `-action-ttl` default, `-action-max-ttl` ceiling; the clamp is applied by the host, not the executor. |
| Audit | Bounded in-memory trail, newest first, with every status transition. |
| Revert | Expiry reaps and reverts; an operator can revert explicitly. |
| Enforcement | Only `applied` decisions enter the snapshot. Failures and dry runs never do. |

A capability is a declaration, not a grant. Registration does not imply
permission.

### 3. The built-in executor is the reference implementation

`internal/action/block` maps a decision onto `internal/block` and back. It is
deliberately thin: dry-run, TTL, audit, and revert all come from the registry.
That is how we know the contract is sufficient — the one case we already knew
fits without special cases.

### 4. Remote actions are template calls, not bespoke integrations

`internal/action/remote` covers any HTTP API with:

- `URL` / `Method` for the create call;
- `BodyTemplate` for the payload;
- `RevertURL` / `RevertMethod` for the undo;
- `Headers` for credentials (never in argv; prefer the config file);
- placeholders `{target}`, `{scope}`, `{action}`, `{reason}`, `{ttl}`, `{ref}`.

The create response may return `{"id": ...}` or `{"revert_ref": ...}`; the host
stores that handle and passes it back as `{ref}` on revert. This is enough to
express a Cloudflare ruleset change, a load-balancer deny entry, or a ticket,
without a per-vendor package.

A vendor with a stateful or non-HTTP protocol adds an executor package instead of
bending the template.

### 5. Every action is time-bounded and reversible by default

A decision always gets an expiry: the capability's default, the request's TTL, or
the host default (1 hour), clamped by the host ceiling. On expiry the registry
reverts the external change and removes the snapshot entry. Actions that cannot
be undone must say so in their capability; the registry still removes the
snapshot entry and records that the remote side was not reverted.

## Consequences

### Positive

- Adding a response type is a package, not a core change.
- The console's action panel can be generated, not maintained.
- Every effect is attributed (action, target, reason, operator, evidence) and
  reversible or explicitly not.
- A buggy executor cannot exceed the host ceiling or bypass the allowlist.

### Negative / risks

- **Revert is best-effort.** A remote that accepts creates but rejects deletes
  leaves residue. Mitigation: `RevertRef` is mandatory for remote actions, and
  failures are audited; operators can retry.
- **Template footguns.** A body template is code-like. Mitigation: templates are
  operator-supplied config, not plugin-supplied, and values are escaped in URLs.
- **Distributed fan-out.** Each instance enforces its own snapshot. Mitigation:
  the console applies a decision per instance (see ADR 0001).
- **No operator auth today.** The registry is in-process only. Exposing it over
  HTTP requires authentication and is intentionally out of scope for this ADR.

## Alternatives considered

| Alternative | Why rejected |
| --- | --- |
| `switch` on action name in `main.go` | Unbounded growth, no third-party actions, no generated UI. |
| Let executors program the firewall directly | Loses allowlist, audit, TTL, confirmation, and revert. |
| A single webhook with a fixed body | Cannot express scopes, revert handles, or vendor payloads. |
| Sync action call inside triage | Couples traffic latency and availability to a remote API. |
| Permanent blocks by default | One mistake becomes an outage that outlives the process. |

## Implementation map

| Concern | Package / file |
| --- | --- |
| Contract types | `internal/action/action.go` |
| Registry, allowlist, TTL, audit, revert | `internal/action/registry.go` |
| Enforcement snapshot | `internal/decision/decision.go` |
| Built-in block executor | `internal/action/block/block.go` |
| Remote/HTTP executor | `internal/action/remote/remote.go` |
| Wiring and flags | `cmd/vigilante/main.go` |
| Config keys | `cmd/vigilante/config.go`, `deploy/vigilante.yaml.example` |
| End-to-end test | `internal/gate/chain_test.go` |

## Example: Cloudflare WAF

```sh
-action-allow block,notify
-action-ttl 1h
-action-webhook "https://api.cloudflare.com/client/v4/zones/$ZONE/rulesets/$RULESET/rules"
-action-webhook-body '{"action":"block","expression":"ip.src eq {target}","description":"vigilante {reason}"}'
-action-webhook-revert "https://api.cloudflare.com/client/v4/zones/$ZONE/rulesets/$RULESET/rules/{ref}"
-action-webhook-token "$CF_API_TOKEN"
```

The create response's `result.id` must be mapped to `{"id": "..."}` by a thin
adapter, or the revert URL must accept the target as `{ref}`. Keeping the adapter
outside the core is deliberate: vendor response shapes belong with the vendor.
