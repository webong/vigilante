# Vigilante

Give your AI agent a view of what's happening on your server.

Vigilante watches traffic, gathers useful context about your applications, and
passes it to the agent you choose. Your agent can investigate suspicious activity,
save findings, or send alerts. You decide whether Vigilante can also block traffic.

Use it with an agent on your machine or one in the cloud. Keep your existing web
server, put Vigilante in front of your app, or let it quietly watch.

## Get started

Vigilante runs as a single executable. You don't need Go or a source checkout to
use a prebuilt bundle.

**Release status:** bundles are configured for Linux, macOS, and Windows on
Intel/AMD and ARM64. The first public download is still pending on the
[releases page](https://github.com/webong/vigilante/releases). These instructions
assume you've received a bundle and installed its executable as `vigilante` on
your PATH (`vigilante.exe` on Windows).

For example, with a Linux Intel/AMD bundle already downloaded:

```sh
tar -xzf vigilante_linux_amd64.tar.gz
sudo install -m 755 vigilante-linux-amd64 /usr/local/bin/vigilante
```

Choose the matching archive for your platform. On macOS, the executable uses the
`darwin` name; on Windows, extract the ZIP and add its executable folder to PATH
after renaming the executable to `vigilante.exe`.

Try the built-in demonstration:

```sh
vigilante demo -repo ""
```

It runs a sample app, sends example requests, and prints the results. No agent
account is needed.

For your own app, save this as `vigilante.yaml`:

```yaml
mode: reverse
listen: "127.0.0.1:8080"
target: "http://127.0.0.1:3000"
agent: builtin
alert_file: ./alerts.jsonl
```

Then start Vigilante:

```sh
vigilante -config vigilante.yaml
```

Visit `http://127.0.0.1:8080`. Requests go to your app on port 3000, and findings go
to `alerts.jsonl`. Replace `builtin` with your preferred agent when you're ready.
The built-in detector catches a small set of common patterns; it isn't an AI agent.

## Choose how to use it

| Mode | Use it when… |
| --- | --- |
| **passive** | You want to watch traffic without changing where requests go. |
| **reverse** | You want Vigilante in front of an app or service. |
| **middle** | You already use nginx, Traefik, or another web server. |
| **inline** | You want to apply traffic rules directly on a Linux server or gateway. |

Select a mode in your YAML file or with `vigilante run <mode>`.

### Passive — watch without rerouting

```yaml
# passive.yaml
mode: passive
passive_iface: eth0
repo: /srv/my-app
agent: builtin
alert_file: ./alerts.jsonl
```

```sh
sudo vigilante -config passive.yaml
# Or:
sudo vigilante run passive -passive-iface eth0 -repo /srv/my-app
```

Replace `eth0` with your network interface and `/srv/my-app` with your app's source
directory. Capturing traffic requires permission from the operating system.
Native capture supports Linux, macOS, and Windows; the available detail differs
by platform. This mode observes traffic. It does not forward or reject requests.

### Reverse — put Vigilante in front of your app

```sh
vigilante run reverse -listen :8080 -target http://127.0.0.1:3000
```

Send clients to port 8080; your app stays on port 3000. To serve HTTPS, add your
certificate and key:

```sh
vigilante run reverse -listen :8443 -target http://127.0.0.1:3000 \
  -tls-cert cert.pem -tls-key key.pem
```

For a TCP service, such as a database:

```sh
vigilante run reverse -protocol tcp -listen :5433 -target 127.0.0.1:5432
```

The TCP option watches the connection; it doesn't automatically understand every
database protocol or decrypt encrypted connections.

### Middle — work with your existing web server

Your web server keeps handling requests. It asks Vigilante whether a request is
allowed and supplies information for the agent to investigate.

Start Vigilante beside it:

```yaml
# middle.yaml
mode: middle
sidecar_listen: "127.0.0.1:9090"
target: "http://127.0.0.1:3000"
agent: builtin
alert_file: ./alerts.jsonl
policy:
  rules:
    - name: protect-git-files
      action: block
      path_prefixes:
        - /.git/
```

```sh
vigilante -config middle.yaml
```

These examples assume your web server and Vigilante share a host. For separate
containers or machines, use a reachable address and configure
[authentication](pkg/README.md#remote-sidecar-and-authentication).

#### nginx

With nginx's `auth_request` module enabled, add these locations inside your
application's `server` block:

```nginx
location / {
    auth_request /_vigilante;
    proxy_pass http://127.0.0.1:3000;
}

location = /_vigilante {
    internal;
    proxy_pass http://127.0.0.1:9090/v1/check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URI $request_uri;
    proxy_set_header X-Original-Method $request_method;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Check with `nginx -t`, then reload nginx. This checks requests and supplies their
basic details for analysis, without copying request bodies. If Vigilante is
unavailable, this nginx setup rejects the request. See the
[nginx guide](pkg/nginx/README.md) for body mirroring and other options.

#### Traefik

Install the [Vigilante Traefik plugin](pkg/traefik/README.md#2-enable-plugins-in-traefik)
first, then add it to your dynamic configuration:

```yaml
http:
  routers:
    app:
      rule: Host(`app.example.com`)
      service: app
      middlewares: [vigilante]
  middlewares:
    vigilante:
      plugin:
        vigilante:
          endpoint: http://127.0.0.1:9090
          timeoutMs: 50
          failOpen: true
  services:
    app:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:3000
```

This example keeps your app available if Vigilante cannot be reached. Use
`failOpen: false` if you want requests refused instead. Plugin installation is
separate from installing Vigilante; the guide includes a local installation
option that does not depend on a published plugin version.

#### Apache HTTP Server

Apache can call middle mode through a Lua access hook. This is a custom setup
recipe, not a packaged Apache module. With `mod_lua`, LuaSocket, and the script
from the [Apache guide](docs/apache.md) installed, add:

```apache
<VirtualHost *:80>
    ServerName app.example.com
    LuaHookAccessChecker /etc/apache2/vigilante.lua check
    ProxyPass / http://127.0.0.1:3000/
    ProxyPassReverse / http://127.0.0.1:3000/
</VirtualHost>
```

The recipe checks request details and refuses requests if Vigilante is unavailable.
The guide explains dependencies and how to verify it before use.

#### Caddy and other servers

Caddy has a [native Vigilante module](pkg/caddy/README.md). Other servers can use
the same [decision and observation API](pkg/README.md#the-sidecar).

### Inline — apply rules to Linux traffic

Inline mode works at the network level, so applications keep their existing
addresses. It can accept or drop selected traffic using source-address rules.

```yaml
# inline.yaml
mode: inline
transports: tcp,udp,icmp,icmpv6
agent: builtin
alert_file: ./alerts.jsonl
policy:
  deny_cidrs:
    - 192.0.2.0/24
```

```sh
sudo vigilante -config inline.yaml -inline-queue 100
```

Linux must also be configured to send the chosen traffic to queue 100. Follow the
[inline setup guide](docs/reference.md#linux-inline-interception) to select that
traffic and remove the rules afterward. Starting Vigilante alone does not redirect
traffic. This mode requires Linux and network-administration permissions.

Use `transports: all` to select all IP protocols. Inline mode doesn't use HTTP paths
or request bodies to make its immediate packet decisions. The agent investigates
separately and can recommend actions for later traffic.

## Bring your own agent

Choose an agent independently of the mode. Put its settings in `agent.yaml` and
combine it with your deployment:

```sh
vigilante -config middle.yaml -config agent.yaml
```

For a local command-line agent, such as OpenCode:

```yaml
# agent.yaml
agent: cli
agent_command: opencode
agent_args:
  - run
  - '{prompt}'
agent_dir: /srv/my-app
agent_timeout: 2m
```

Install and authenticate the agent separately. It must run without interactive
prompts. Configure its model, skills, tools, and output destinations in the agent
itself. Other command-line agents can use the same configurable command and arguments.

For an agent service on another machine or in the cloud:

```yaml
agent: remote:https://agent.example.com/v1/triage
```

The service must accept Vigilante's request format; this isn't a direct connection
to an arbitrary model API. Set `VIGILANTE_AGENT_TOKEN` if it requires a bearer token.
The agent can handle storage and notifications itself, or return findings for
Vigilante to record and act on. See the [agent reference](docs/reference.md#agent-backends).

## Keep your settings together—or split them up

```sh
vigilante -config base.yaml -config production.yaml -config agent.yaml
```

Later files override earlier settings. Command-line flags override files.
Lists and the `policy`, `actions`, and `alerts` sections are replaced as a whole.
YAML and JSON are both supported.

Use `mode` to select any of the four modes. The queue number for inline mode is
currently a command-line option only. See the
[configuration reference](docs/reference.md#configuration-details) for all merge
rules and the [example configuration](deploy/vigilante.yaml.example).

## Decide what happens when something looks wrong

Start by collecting findings:

```yaml
alert_file: ./alerts.jsonl
alert_min_severity: high
```

You can also send findings to your own service with `alert_deliver_url`.
With an alert store enabled, reverse HTTP mode exposes recent findings
at `/obs/alerts` and a sample viewer at `/obs/dashboard` on their listener.
Middle mode provides `/healthz`, `/ready`, and `/metrics`; use your configured
alert file or delivery destination for its findings.

Blocking is a separate choice. Request rules can reject traffic in reverse,
middle, or inline mode. Agent-triggered host actions require your configured
permissions. The default firewall setting, `block_mode: log`, records intended
firewall actions; it does not disable request rules. See
[policy and actions](docs/reference.md#policy--blocking) before enabling enforcement.

## See inside encrypted traffic

When Vigilante serves HTTPS in reverse mode, it can inspect the requests it
decrypts. When it watches traffic elsewhere, it normally sees encrypted data.

If your application exports TLS session keys, Vigilante can use a separately
installed TShark 4.6+ to read HTTP/1, HTTP/2, and HTTP/3 traffic:

```sh
vigilante run passive -passive-iface eth0 -tls-keylog /run/my-app/sessions.keys
```

It needs matching session keys and a sufficiently complete capture. A certificate
alone is not enough. See [encrypted traffic setup](docs/reference.md#optional-plaintext-and-tls-context)
for saved captures, custom decoders, and current limits.

## More information

- [Technical reference](docs/reference.md): source context, policies, APIs, limitations, and deployment details.
- [Web server integrations](pkg/README.md): nginx, Traefik, Caddy, and the middle API.
- [Build and test from source](docs/reference.md#build-and-test-from-source): for contributors and custom builds.

Vigilante supplies evidence for investigation. What it can see depends on where
it runs and which information is available; a suspicious request is not proof that
an application is vulnerable.
