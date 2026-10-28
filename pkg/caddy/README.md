# Vigilante for Caddy

A native Caddy HTTP handler module (`http.handlers.vigilante`) that enforces
Vigilante policy before `reverse_proxy`, and optionally mirrors each request to
a Vigilante sidecar for full agent triage.

## Build

```sh
xcaddy build --with github.com/webong/vigilante/pkg/caddy
```

On a published tag the module resolves normally. From a checkout:

```sh
xcaddy build --with github.com/webong/vigilante/pkg/caddy=./pkg/caddy
```

## Caddyfile

```caddyfile
{
    order vigilante before reverse_proxy
}

:8080 {
    vigilante {
        policy /etc/vigilante/policy.yaml
        mirror http://127.0.0.1:9090
        fail_open true
        timeout 2s
    }
    reverse_proxy 127.0.0.1:3000
}
```

| Option | Meaning |
| --- | --- |
| `policy <path>` | Vigilante policy file (YAML or JSON). Evaluated in-process. |
| `endpoint <url>` | Delegate decisions to a sidecar instead of loading `policy` locally. |
| `mirror <url>` | Base URL of a sidecar; every request is posted to `/v1/observe`. |
| `fail_open <bool>` | Forward when a node/sidecar is unavailable. Default `true`. |
| `timeout <dur>` | Bound on a sidecar decision. Default `2s`. |

## JSON config

```json
{
  "handler": "vigilante",
  "policy": "/etc/vigilante/policy.yaml",
  "mirror": "http://127.0.0.1:9090",
  "fail_open": true,
  "timeout": "2s"
}
```

## Two ways to run

- **In-process policy only** — set `policy`. No sidecar, no agent, no external
  process. Good for blocking known-bad paths at the edge.
- **Sidecar for full triage** — set `endpoint` (decisions) and/or `mirror`
  (observation) to a `vigilante -mode sidecar` instance. Caddy stays a thin
  enforcement point; Vigilante owns policy, enrichment, and the agent.

## Status codes

- `allow` → `next.ServeHTTP` (upstream).
- `deny` → `403` without observation.
- `block` → observed for triage, then `403`.
- sidecar unreachable → `fail_open` decides.
