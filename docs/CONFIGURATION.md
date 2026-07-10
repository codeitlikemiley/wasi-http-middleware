# Configuration

Configuration is loaded once per component instance. Duplicate environment
keys, malformed values, and missing required values cause a deterministic
configuration error. Component instances must not be reused across tenants
with different configuration.

## Request ID

`request-id` has no configuration. It accepts exactly one non-empty
`x-request-id` containing at most 128 characters from
`A-Z a-z 0-9 - _ . : /`. Missing, duplicate, or invalid values are replaced
with a random 128-bit lowercase hexadecimal ID.

## Security headers

`security-headers` has no configuration. It replaces these response fields:

| Header | Value |
|---|---|
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |

CSP and HSTS are deliberately absent. CSP must reflect the application's
script/nonces and split-Wasm behavior. HSTS belongs at the TLS-terminating
boundary.

## CORS

| Variable | Required | Default | Meaning |
|---|---:|---|---|
| `WASI_MIDDLEWARE_CORS_ORIGINS` | yes | none | Comma-separated exact origins, or `*` without credentials |
| `WASI_MIDDLEWARE_CORS_METHODS` | no | `GET,HEAD,POST` | Comma-separated allowed request methods |
| `WASI_MIDDLEWARE_CORS_HEADERS` | no | `content-type,authorization` | Comma-separated allowed request headers |
| `WASI_MIDDLEWARE_CORS_ALLOW_CREDENTIALS` | no | `false` | Exactly `true` or `false` |

An empty origin set is invalid. `*` combined with credentials is invalid.
Unknown origins, methods, or requested headers receive 403. A valid `OPTIONS`
request with `Access-Control-Request-Method` receives 204 without invoking
authentication or the terminal service. Origin-dependent successes and
rejections include `Vary: Origin`. Exact origins must be serialized `http` or
`https` origins without user information, a path, query, or fragment. The
special `null` origin can be allowed explicitly. Non-CORS requests pass
through.

Example:

```text
WASI_MIDDLEWARE_CORS_ORIGINS=https://app.example,https://admin.example
WASI_MIDDLEWARE_CORS_METHODS=GET,HEAD,POST
WASI_MIDDLEWARE_CORS_HEADERS=content-type,authorization,x-request-id
WASI_MIDDLEWARE_CORS_ALLOW_CREDENTIALS=true
```

## Authentication policy

| Variable | Required | Default | Meaning |
|---|---:|---|---|
| `WASI_MIDDLEWARE_POLICY_URL` | yes | none | Absolute `http` or `https` policy endpoint, at most 2048 bytes |
| `WASI_MIDDLEWARE_POLICY_TIMEOUT_MS` | no | `2000` | Policy elapsed-time budget and transport timeout; range `1..=60000` |

The policy request is `POST application/json` and contains only:

```json
{
  "method": "GET",
  "scheme": "https",
  "authority": "app.example",
  "path": "/account",
  "request_id": "..."
}
```

The original `Authorization` value is forwarded as a header. Bodies, cookies,
and query strings are not sent. Before dispatch, the path is decoded exactly
once and the query is removed. Encoded separators, backslashes, controls,
double encoding, empty segments, and `.` or `..` segments are rejected with
400 rather than allowing the policy service and terminal router to disagree.
A literal dot inside a larger filename remains valid. A 200 response must
contain:

```json
{
  "subject": "user-1",
  "issuer": "identity.example",
  "scopes": ["read", "write"]
}
```

Policy status 401 becomes 401, and 403 becomes 403. Network failures, timeout,
oversized or malformed success bodies, unexpected status codes, and invalid
identity values become a generic 503. Duplicate or invalid authorization
fields are rejected before the policy call.

The component checks monotonic elapsed time after response headers and every
body frame. Host transport timeouts bound connect, first-byte, and between-byte
waits, while the elapsed check prevents a provider from extending the call by
dripping frames. Over-budget data is discarded and becomes 503. Deployment
deadlines remain necessary as the outermost bound.

## Spin inheritance

Spin middleware reads configuration inherited from the primary component.
Use the smallest list supported by the pinned vNext runtime:

```toml
dependencies.middleware = [
  { component = "request-id" },
  { component = "security-headers" },
  { component = "cors", inherit_configuration = ["environment"] },
  { component = "auth-policy", inherit_configuration = ["environment", "allowed_outbound_hosts"] },
]
```

The primary component must declare the environment values and exact policy
host in `allowed_outbound_hosts`. See the capability caveat in
[TRUST-BOUNDARY.md](TRUST-BOUNDARY.md).
