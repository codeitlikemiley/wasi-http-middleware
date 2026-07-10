# Architecture

## Composition model

Each middleware is a separately compiled component that imports and exports
`wasi:http/handler@0.3.0-rc-2026-03-15`. A host or build-time composer wires the
export of the inner component to the handler import of the next outer
component. There is no proxy process or network hop between middleware and the
application.

```text
client
  -> request-id
  -> security-headers
  -> cors
  -> auth-policy
  -> terminal service
```

Requests flow left to right. Responses unwind right to left. Consequently,
request ID and security headers also decorate authentication rejections and
CORS preflight responses.

Spin composes the ordered `dependencies.middleware` list when loading an HTTP
trigger. Wasmtime receives one component produced by `compose-wasmtime.sh`.
The same middleware artifacts can therefore be reused by different projects,
while each trigger selects its own chain and capability inheritance.

## Crate boundaries

- `wasi-http-policy-core` contains pure request ID, security-header, CORS, and
  external-policy decision logic.
- `wasi-http-metadata` owns the reserved trusted-header contract.
- `wasi-http-middleware-component-support` translates header fields and moves
  request/response body streams and trailers without collecting them.
- Each `components/*` crate owns only host interaction and one middleware
  policy.
- `passthrough` plus `test-components/*` are deterministic conformance fixtures
  and never ship as production middleware.

The policy crates do not depend on Spin or Leptos. The production components
generate their standard world with `wit-bindgen` and use the pinned `wasip3`
resource types.

## Streaming invariant

Middleware may copy bounded HTTP header fields, but it must transfer body and
trailer resources directly. It must not collect an application request or
response body. The only intentionally buffered body is the authentication
policy response, capped at 64 KiB because it is a small control-plane message.

The component ABI check verifies both handler sides and compares every import
against an exact per-component allowlist. Runtime tests exercise streamed
request bodies, delayed first bytes, successful trailers/body association,
failing response streams, client disconnects, and concurrent requests. The
pinned hosts differ when surfacing a failed stream: Wasmtime may commit a 200
before closing, while Spin can close before committing headers; neither path
may hang or silently report a complete body.

The two projects under `fixtures/spin/` reuse the same artifacts with different
middleware lists and CORS settings. Their contract check ensures configuration
does not bleed between projects. The public-stack project is a test fixture,
not an authenticated production manifest; the production manifest auditor
intentionally requires the complete default chain.

## Policy placement

Component middleware owns transport-wide concerns: correlation, conservative
response headers, CORS, and coarse authentication. Domain authorization stays
inside the terminal application, such as Leptos `ServerFn::middlewares()`.
Ingress still owns TLS, trusted client IPs, WAF rules, distributed rate limits,
global deadlines, and static asset policy.

HTTP middleware binaries cannot wrap Redis, MQTT, cron, or custom triggers
because those triggers export different WIT interfaces. A future adapter may
reuse the pure policy crates, but it is a separate component and compatibility
contract.
