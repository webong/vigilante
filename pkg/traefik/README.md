# Vigilante for Traefik

A Traefik middleware plugin that asks a Vigilante sidecar for a decision before
forwarding. Traefik loads plugins through Yaegi, so
[`vigilante.go`](vigilante.go) is self-contained (standard library only) and
speaks HTTP to the sidecar.

## 1. Run the sidecar

```sh
vigilante run middle -sidecar-listen 127.0.0.1:9090 \
  -target http://127.0.0.1:3000 -policy /etc/vigilante/policy.yaml
```

If Traefik runs on another host, bind the sidecar to a reachable address and
give it a token:

```sh
VIGILANTE_SIDECAR_TOKEN=... vigilante run middle \
  -sidecar-listen 0.0.0.0:9090 -sidecar-allow-remote \
  -target http://app:3000 -policy /etc/vigilante/policy.yaml
```

## 2. Enable plugins in Traefik

The plugin is installed separately from the Vigilante executable. Use Traefik's
[local plugin support](https://doc.traefik.io/traefik/master/reference/install-configuration/experimental/plugins/)
without assuming a published plugin version exists.

Download the Vigilante source archive matching your executable, then copy the
contents of `pkg/traefik/` (including `.traefik.yml`) to:

```text
plugins-local/src/github.com/webong/vigilante/pkg/traefik/
```

This path is relative to Traefik's working directory. For container deployments,
mount that directory inside the Traefik container. Add to the static configuration:

```yaml
experimental:
  localPlugins:
    vigilante:
      moduleName: github.com/webong/vigilante/pkg/traefik
```

Restart Traefik after changing its static configuration. A future catalog
installation can use `experimental.plugins` with an actually published version;
do not assume a sample version string is available.

## 3. Attach the middleware

```yaml
# dynamic configuration
http:
  routers:
    app:
      rule: Host(`api.example.com`)
      service: app
      middlewares: [vigilante]
  middlewares:
    vigilante:
      plugin:
        vigilante:
          endpoint: http://127.0.0.1:9090
          timeoutMs: 50
          failOpen: true
          cacheTTL: 1
          # token: change-me
  services:
    app:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:3000
```

| Option | Meaning |
| --- | --- |
| `endpoint` | Sidecar base URL (required). |
| `timeoutMs` | Decision timeout in milliseconds. Default `50`. |
| `timeout` | Legacy timeout in **seconds**; takes precedence when set. Leave it unset. |
| `failOpen` | Forward when the sidecar is unreachable. Default `true`. |
| `cacheTTL` | Reuse cacheable `allow` decisions for N seconds. Default `1`; `0` disables. |
| `cacheSize` | Maximum cached decisions. Default `4096`. |
| `token` | Sent as `Authorization: Bearer <token>`. |
| `forwardHeaders` | Headers sent to the sidecar for header rules. Default `["User-Agent","Content-Type","X-Forwarded-Proto"]`. |

Denied/blocked requests get `403`; the upstream is never called. Allowed
requests are forwarded untouched.

The timeout is deliberately short: this middleware sits in the request path, so
a slow sidecar should cost milliseconds, not seconds. Only `allow` decisions
marked cacheable are cached — a `deny` is re-asked on every request, so
tightening a rule takes effect immediately. A `401`/`403` from the sidecar means
the token is wrong; the plugin fails closed on it even with `failOpen: true`.
Policy changes need no Traefik restart: call `POST /-/reload` on the sidecar (or
let its file watcher pick the change up).
