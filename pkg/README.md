# Ingress plugins

Vigilante ships as a standalone proxy, but you can also run it inside the edge
proxy you already operate. The `pkg/` tree holds those integrations.

| Folder | Host | Model | Talks to Vigilante via |
| --- | --- | --- | --- |
| [`ingress/`](ingress) | any | Go decision core + HTTP sidecar | in-process or HTTP |
| [`caddy/`](caddy) | Caddy | native Go module (`http.handlers.vigilante`) | in-process policy, optional sidecar mirror |
| [`traefik/`](traefik) | Traefik | Yaegi middleware plugin | sidecar `POST /v1/decide` |
| [`nginx/`](nginx) | nginx | `auth_request` + `mirror`, or an njs handler | sidecar `POST /v1/check` and `/v1/observe` |

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
| `GET /healthz`, `/ready` | Liveness/readiness. |
| `GET /metrics` | Prometheus counters. |

`RequestMeta` is `{method, path, query, host, remote_addr, scheme, headers,
body_preview, body_bytes}`. The `/v1/check` and `/v1/observe` endpoints also
accept proxy headers (`X-Original-URI`, `X-Original-Method`, `X-Forwarded-For`,
`X-Forwarded-Host`) instead of a JSON body.

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
          timeout: 2
          failOpen: true
```

Traefik loads the plugin through Yaegi, so the plugin directory is
self-contained and calls the sidecar. See [`traefik/`](traefik).

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
- **Deny is not mirrored; block is.** A `deny` rule rejects before observation;
  a `block` rule mirrors first (so triage sees the attempt) then rejects.
- **Fail-open by default.** If a sidecar is configured and unreachable, the
  plugin forwards the request and logs a warning. Set `fail_open: false` /
  `failOpen: false` to fail closed.
- **Hot path stays hot.** Observations are fire-and-forget; the sidecar never
  delays the proxied response.
