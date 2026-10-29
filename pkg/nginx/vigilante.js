// Vigilante nginx njs access handler.
//
// Use this instead of auth_request when you want the decision inline in njs
// (for example to block on a custom header or to add response headers).
//
// nginx.conf:
//
//   load_module modules/ngx_http_js_module.so;
//   http {
//     js_import vigilante from /etc/nginx/njs/vigilante.js;
//     server {
//       set $vigilante_endpoint "http://127.0.0.1:9090";
//       set $vigilante_token "";   # set when the sidecar requires auth
//       location / {
//         js_access vigilante.access;
//         proxy_pass http://app:3000;
//       }
//     }
//   }
//
// Requires njs >= 0.5 for ngx.fetch.

async function access(r) {
    const endpoint = r.variables.vigilante_endpoint || "http://127.0.0.1:9090";
    const token = r.variables.vigilante_token || "";

    const headers = {
        "X-Original-URI": r.variables.request_uri,
        "X-Original-Method": r.method,
        "X-Forwarded-For": r.variables.remote_addr,
        "X-Forwarded-Host": r.variables.host,
        "X-Forwarded-Proto": r.variables.scheme
    };
    if (token) {
        headers.Authorization = "Bearer " + token;
    }

    try {
        const resp = await ngx.fetch(endpoint + "/v1/check", {
            method: "POST",
            headers: headers,
            body: ""
        });

        // 401/403 is a real refusal: 403 a policy denial, 401 a bad token.
        // Both are configuration/authorization errors, so fail closed.
        if (resp.status === 401 || resp.status === 403) {
            r.return(403, "forbidden");
        }
    } catch (e) {
        // Fail open: a sidecar outage must never take the site down.
    }
}

export default { access };
