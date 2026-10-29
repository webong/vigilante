# Vigilante for nginx

Two integrations, both talking to a Vigilante sidecar:

1. **`auth_request` + `mirror`** — no scripting; stock nginx with
   `ngx_http_auth_request_module`. See [`vigilante.conf`](vigilante.conf).
2. **njs access handler** — inline decisions, optional custom logic. See
   [`vigilante.js`](vigilante.js).

## Run the sidecar

```sh
vigilante -mode sidecar \
  -sidecar-listen 127.0.0.1:9090 \
  -target http://127.0.0.1:3000 \
  -policy /etc/vigilante/policy.yaml \
  -alert-file /var/log/vigilante/alerts.jsonl
```

## Option 1: auth_request (recommended)

Include the location blocks from [`vigilante.conf`](vigilante.conf) and add to
your application location:

```nginx
location / {
    auth_request /_vigilante_check;

    mirror /_vigilante_mirror;
    mirror_request_body on;

    proxy_pass http://app:3000;
}
```

- `/_vigilante_check` → sidecar `/v1/check`: `204` allows, `403` denies.
- `/_vigilante_mirror` → sidecar `/v1/observe`: a fire-and-forget copy for the
  agent. `mirror_request_body on` includes the request body.

Both subrequests forward `X-Original-URI`, `X-Original-Method`,
`X-Forwarded-For`, `X-Forwarded-Host`, and `X-Forwarded-Proto`, so policy sees
the real client address and path.

## Option 2: njs

```nginx
load_module modules/ngx_http_js_module.so;

http {
    js_import vigilante from /etc/nginx/njs/vigilante.js;

    server {
        set $vigilante_endpoint "http://127.0.0.1:9090";
        set $vigilante_token "";   # set when the sidecar requires auth

        location / {
            js_access vigilante.access;
            proxy_pass http://app:3000;
        }
    }
}
```

Requires njs ≥ 0.5 (`ngx.fetch`). The handler fails open if the sidecar is
unreachable, but fails closed on `401`/`403` (bad credentials or a policy deny).

## Notes

- `auth_request` is evaluated before `proxy_pass`, so a denied request never
  reaches the app.
- The mirror subrequest is asynchronous to the client: its latency does not
  affect the response.
- nginx needs `resolver` configured if you proxy to a hostname rather than an
  upstream block.
- If nginx runs on another host, start the sidecar with
  `-sidecar-listen 0.0.0.0:9090 -sidecar-allow-remote` plus a
  `VIGILANTE_SIDECAR_TOKEN`, and send `Authorization: Bearer <token>` from the
  subrequests. A non-loopback bind without a token is refused.
- Policy edits reload without restarting nginx or the sidecar: the sidecar
  watches the file, accepts `SIGHUP`, and exposes `POST /-/reload`.
- `-sidecar-cache-ttl` (default `1s`) skips decision round trips for repeated
  cacheable requests; /v1/observe still mirrors every flow.
