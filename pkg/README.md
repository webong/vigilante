# Ingress plugins

Vigilante ships as a standalone proxy, but you can also run it inside the edge
proxy you already operate. The `pkg/` tree holds those integrations.

| Folder | Host | Model | Talks to Vigilante via |
| --- | --- | --- | --- |
| [`ingress/`](ingress) | any | Go decision core + HTTP sidecar | in-process or HTTP |
| [`caddy/`](caddy) | Caddy | native Go module (`http.handlers.vigilante`) | in-process policy, optional sidecar mirror |
| [`traefik/`](traefik) | Traefik | Yaegi middleware plugin | sidecar `POST /v1/decide` |
| [`nginx/`](nginx) | nginx | `auth_request` + `mirror`, or an njs handler | sidecar `POST /v1/check` and `/v1/observe` |
| [`tap/`](tap) | your Go service | embeddable capture (mirror, TCP tee, passive, inline) | in-process |

Nothing here changes your proxy's forwarding path on its own: you opt in with a
middleware/handler, and the decision is always **allow by default** unless a
policy rule denies or blocks.

## The sidecar

Caddy can link the decision core directly. Traefik and nginx cannot, so run the
sidecar (same binary, one extra mode):

```sh
vigilante -mode sidecar \
  -sidecar-listen 127.0.0.1:9090 \
  -target http://127.0.0.1:3000 \
  -policy /etc/vigilante/policy.yaml \
  -repo auto \
  -alert-file /var/log/vigilante/alerts.jsonl
```

The sidecar runs the full Vigilante pipeline (policy, mirror queue, correlation,
agent triage, alerting) and exposes:

| Endpoint | Use |
| --- | --- |
| `POST /v1/decide` | JSON `RequestMeta` in, JSON `Decision` out. For Traefik and custom clients. |
| `POST /v1/check` | `204` allow / `403` deny+block. For nginx `auth_request`. |
| `POST /v1/observe` | `202`, mirrors the request for triage. For nginx `mirror`. |
| `POST /-/reload` | Recompiles the policy file; `422` with the error and old rules still active. |
| `GET /healthz`, `/ready` | Liveness/readiness (never authenticated). |
| `GET /metrics` | Prometheus counters, including cached decisions. |

`RequestMeta` is `{method, path, query, host, remote_addr, scheme, headers,
body_preview, body_bytes}`. The `/v1/check` and `/v1/observe` endpoints also
accept proxy headers (`X-Original-URI`, `X-Original-Method`, `X-Forwarded-For`,
`X-Forwarded-Host`) instead of a JSON body.

### Remote sidecar and authentication

A sidecar bound to loopback needs no token. A non-loopback bind requires **both**
`-sidecar-allow-remote` and a token, so a typo in `-sidecar-listen` cannot
silently expose policy decisions to the network:

```sh
VIGILANTE_SIDECAR_TOKEN=... vigilante -mode sidecar \
  -sidecar-listen 0.0.0.0:9090 \
  -sidecar-allow-remote \
  -policy /etc/vigilante/policy.yaml
```

Clients send `Authorization: Bearer <token>` (or `X-Vigilante-Token`). A
`401`/`403` from the sidecar is a configuration error, so the Traefik plugin
fails **closed** on it even when `failOpen` is true.

### Decision caching

`-sidecar-cache-ttl` (default `1s`, `0` disables) memoizes decisions for repeat
requests sharing method, host, path, query, and client address. Only policies
that inspect no request headers are cached; a policy reload clears the cache;
cache hits still mirror the observed flow. The point is to skip the decision
round trip on hot, repetitive traffic — never to skip triage.

## Caddy

```caddyfile
{
    order vigilante before reverse_proxy
}

:8080 {
    vigilante {
        policy /etc/vigilante/policy.yaml
        mirror http://127.0.0.1:9090
    }
    reverse_proxy 127.0.0.1:3000
}
```

Build Caddy with the module:

```sh
xcaddy build --with github.com/webong/vigilante/pkg/caddy
```

See [`caddy/`](caddy) for JSON config, sidecar delegation, and fail-open.

## Traefik

```yaml
# dynamic configuration
http:
  middlewares:
    vigilante:
      plugin:
        vigilante:
          endpoint: http://127.0.0.1:9090
          timeoutMs: 50
          failOpen: true
          cacheTTL: 1
          # token: ...            # when the sidecar requires auth
```

Traefik loads the plugin through Yaegi, so the plugin directory is
self-contained and calls the sidecar. The default decision timeout is 50ms: a
blocking middleware should fail open in a blink, not stall a request. Only
cacheable `allow` decisions are cached; a `deny` is always re-asked. See
[`traefik/`](traefik).

## nginx

```nginx
location / {
    auth_request /_vigilante_check;
    mirror /_vigilante_mirror;
    mirror_request_body on;
    proxy_pass http://app:3000;
}
```

Copy the two internal locations from [`nginx/vigilante.conf`](nginx/vigilante.conf),
or use the njs handler in [`nginx/vigilante.js`](nginx/vigilante.js) when you
want the decision inline. See [`nginx/`](nginx).

## Design notes

- **Policy is shared.** All adapters call the same `internal/policy` engine, so
  rules behave identically whether you front the app with Vigilante or with
  Caddy/Traefik/nginx.
- **Policy reloads in place.** A file-based policy is watched (2s), reloadable on
  `SIGHUP` and on `POST /-/reload`. An invalid file keeps the previous rules, and
  a successful reload drops every cached decision.
- **Deny is not mirrored; block is.** A `deny` rule rejects before observation;
  a `block` rule mirrors first (so triage sees the attempt) then rejects.
- **Fail-open by default, fail-closed on auth.** If a sidecar is unreachable, the
  plugin forwards the request and logs a warning. Set `fail_open: false` /
  `failOpen: false` to fail closed. Bad sidecar credentials always fail closed.
- **Hot path stays hot.** Observations are fire-and-forget; the sidecar never
  delays the proxied response. Decision timeouts are milliseconds, not seconds.
