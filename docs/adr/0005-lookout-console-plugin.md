# ADR 0005 — Extract the Lookout operator console as an `ext.plugin/v1` plugin

- Status: Accepted
- Date: 2026-10-30
- Deciders: Vigilante maintainers
- Related: [ADR 0001](0001-stateless-core-stateful-plugins.md), [ADR 0002](0002-open-ended-action-contract.md), [ADR 0003](0003-api-first-data-not-ui.md), [ADR 0004](0004-sensor-server-split.md)

## Context

[ADR 0003](0003-api-first-data-not-ui.md) established that Vigilante's core and
`ext/obs` expose data over REST and RPC rather than coupling the product to one
UI. As actor history (`internal/history`), behavioral analysis
(`internal/behavior`), LLM actor triage (`ext/triage`), and sensor management
([ADR 0004](0004-sensor-server-split.md)) matured, we also built a full first-party
operator console (**Lookout**): visitor lists, actor risk timelines, LLM triage
cards, human review queue approval/rejection/revocation, outbound TCP egress
views, and sensor key management.

Embedding that console directly inside `ext/obs` blurred two distinct concerns:

1. `ext/obs` is the machine-consumable observation and history REST/RPC data
   surface (`/obs/*`).
2. Lookout is an opinionated web application with bundled static assets,
   HMAC-signed operator cookie sessions, CSRF rules, and view-specific read
   models (`/lookout/*`).

## Decision

### 1. Lookout is a standalone `ext.plugin/v1` plugin in `ext/lookout`

The operator console lives in `ext/lookout` and mounts at `/lookout/` when a
history store is present (`-lookout`, enabled by default alongside
`-history-file`). `ext/obs` returns to its original scope: the `/obs/*`
observation and `/obs/history/*` REST data endpoints.

### 2. Two contracts: `vigilante.lookout@v1` (forward) and `vigilante.console@v1` (reverse)

- **Forward contract (`vigilante.lookout@v1`, operation `serve-http`)**:
  The host strips `/lookout` and forwards the HTTP request (`Method`, `Path`,
  `Query`, allowlisted `Headers`, bounded `Body`, `TLS` state) over the plugin
  session. The guest serves its embedded SPA bundle (`ext/lookout/web/dist/app`)
  and `/lookout/api/*` routes, managing operator login (`-lookout-token`,
  falling back to `-obs-token`) and `SameSite=Strict` session cookies itself.
- **Reverse contract (`vigilante.console@v1`)**:
  The guest holds no direct database or firewall handles. Instead, the host
  offers `vigilante.console@v1` on the session (`actors`, `flows`, `egress`,
  `suggestions`, `suggest`, `resolve-suggestion`, `execute-action`,
  `revert-action`, `triage-model`, `triage-actor`, `sensors`, `create-sensor`,
  `delete-sensor`). Every enforcement action still flows through the host's
  `action.Registry` ([ADR 0002](0002-open-ended-action-contract.md)).

## Consequences

### Positive

- **Clean separation of data and UI.** `ext/obs` remains a pure data contract;
  `ext/lookout` owns presentation, SPA routing, and cookie sessions.
- **Host authority is preserved.** Even when Lookout runs out of process over
  `jsonline`, it can only act by calling `vigilante.console@v1` reverse
  operations that the host authorizes and audits.
- **Replaceable console.** Operators who do not want the web console can disable
  it with `-lookout=false` while keeping `/obs/*` active for scripts and custom
  integrations.

### Negative / risks

- **Two HTTP bridges when both are enabled.** Mitigated by sharing the same
  underlying `history.Store`, `action.Registry`, and `triage.Service` in
  `CoreHost`.

## Implementation map

| Concern | Package / file |
| --- | --- |
| Forward & reverse contracts (`vigilante.lookout@v1`, `vigilante.console@v1`) | `ext/lookout/contract.go`, `ext/lookout/reverse.go` |
| Guest HTTP handler, session auth, SPA serving | `ext/lookout/guest.go`, `ext/lookout/console.go` |
| Host bridge & `CoreHost` | `ext/lookout/host.go` |
| Embedded frontend bundle | `ext/lookout/web` (`dist/app`) |
| CLI flags (`-lookout`, `-lookout-token`) | `cmd/vigilante/main.go`, `cmd/vigilante/config.go` |
