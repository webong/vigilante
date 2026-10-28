# Vigilante for Traefik

A Traefik middleware plugin that asks a Vigilante sidecar for a decision before
forwarding. Traefik loads plugins through Yaegi, so
[`vigilante.go`](vigilante.go) is self-contained (standard library only) and
speaks HTTP to the sidecar.

## 1. Run the sidecar

```sh
vigilante -mode sidecar -sidecar-listen 127.0.0.1:9090 \
  -target http://127.0.0.1:3000 -policy /etc/vigilante/policy.yaml
```

## 2. Enable plugins in Traefik

```yaml
# traefik.yml (static)
experimental:
  plugins:
    vigilante:
      moduleName: github.com/webong/vigilante/pkg/traefik
      version: v0.1.0
```

Traefik fetches the plugin from its module path, so this directory must be
published (it is `pkg/traefik` in the Vigilante repository). For local
experimentation use `localPlugins`:

```yaml
experimental:
  localPlugins:
    vigilante:
      moduleName: github.com/webong/vigilante/pkg/traefik
```

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
          timeout: 2
          failOpen: true
  services:
    app:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:3000
```

| Option | Meaning |
| --- | --- |
| `endpoint` | Sidecar base URL (required). |
| `timeout` | Decision timeout in seconds. Default `2`. |
| `failOpen` | Forward when the sidecar is unreachable. Default `true`. |

Denied/blocked requests get `403`; the upstream is never called. Allowed
requests are forwarded untouched.
