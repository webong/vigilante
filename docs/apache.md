# Apache with Vigilante middle mode

[Back to the usage guide](../README.md#apache-http-server)

This custom recipe lets Apache ask Vigilante about a request before forwarding it.
There is no packaged Apache adapter yet. It uses Apache 2.4's
[Lua access hook](https://httpd.apache.org/docs/2.4/mod/mod_lua.html#luahookaccesschecker)
and [LuaSocket](https://lunarmodules.github.io/luasocket/http.html).
It has not been validated in a live Apache deployment; verify it in staging before
using it for production traffic.

## 1. Start Vigilante

Use `middle.yaml` from the [README](../README.md#middle--work-with-your-existing-web-server):

```sh
vigilante -config middle.yaml
```

This example assumes Apache and Vigilante share a host and Vigilante listens on
`127.0.0.1:9090` without a token. For a remote service, configure authentication
and change the hook accordingly.

## 2. Install the hook

Enable Apache's `lua`, `proxy`, and `proxy_http` modules. Install LuaSocket for the
Lua version used by Apache. Package names and module-enabling commands depend on
your operating system.

Save this as `/etc/apache2/vigilante.lua`, readable by Apache:

```lua
local apache2 = require("apache2")
local http = require("socket.http")

-- Per-I/O timeout; shared by other LuaSocket users in this Lua state.
http.TIMEOUT = 0.2

function check(r)
    local ok, status = http.request {
        url = "http://127.0.0.1:9090/v1/check",
        method = "POST",
        redirect = false,
        headers = {
            ["content-length"] = "0",
            ["x-original-method"] = r.method,
            ["x-original-uri"] = r.unparsed_uri,
            ["x-forwarded-for"] = r.useragent_ip,
            ["x-forwarded-host"] = r.hostname,
            ["user-agent"] = r.headers_in["User-Agent"] or ""
        }
    }
    if ok and tonumber(status) == 204 then
        -- Continue normal processing, including Apache's other access checks.
        return apache2.DECLINED
    end
    if tonumber(status) == 401 or tonumber(status) == 403 then
        return 403
    end
    -- Refuse the request if Vigilante is unavailable or gives an unexpected reply.
    return 503
end
```

Add the hook to your application virtual host:

```apache
<VirtualHost *:80>
    ServerName app.example.com
    LuaHookAccessChecker /etc/apache2/vigilante.lua check
    ProxyPass / http://127.0.0.1:3000/
    ProxyPassReverse / http://127.0.0.1:3000/
</VirtualHost>
```

Keep the hook file outside the served document directory. If Apache is behind
another proxy, configure Apache's trusted client-IP handling so `useragent_ip`
represents the client you intend to evaluate.

## 3. Verify before enabling it

Run `apachectl configtest`, reload Apache, and check these cases in staging:

- A normal request reaches the application.
- A request to `/.git/config` receives `403` with the README's policy.
- Stopping Vigilante makes Apache return `503`.
- Allowed requests reach Vigilante's observation pipeline. Alert records depend
  on agent verdicts and the configured severity filter.

This recipe supplies method, URL, host, client address, and user agent. It does
not copy request bodies or forward all headers. Rules requiring missing headers
cannot be evaluated accurately. `/v1/check` already observes allowed and blocked
requests; a second observation request is not needed for this recipe.
