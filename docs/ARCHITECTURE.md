# Architecture

## Composition model

Every portable middleware component imports and exports
`wasi:http/handler@0.3.0`.
WAC wires the terminal handler into each middleware at build time; there is no
sidecar process or network hop between middleware and the application.

```text
client
  -> request-id
  -> security-headers
  -> cors
  -> authn-policy
  -> terminal service
```

`secure-defaults` implements the same order in one component. Requests flow
inward and responses unwind outward, so CORS preflight precedes authentication
and request/security headers decorate controlled rejections.

## Crate boundaries

- `wasi-http-policy-core` contains pure request-ID, header, CORS, broker-response,
  and defensive path utilities.
- `wasi-http-metadata` owns the bounded `AuthContextV1` wire contract.
- `wasi-http-authn-runtime` validates broker configuration and owns broker I/O,
  deadlines, cancellation, and in-flight admission.
- `wasi-http-middleware-component-support` preserves message resources while
  applying header diffs.
- `components/*` exports standard middleware components only.
- `test-components/*` and `passthrough` are conformance fixtures, not production
  identity services.

The shared metadata and component-support crates are ordinary Rust library APIs.
Portable components contain no Leptos or Spin SDK dependency. Production
deployments use the shared policy and metadata crates in a trusted native
ingress; guest components remain experimental.

Request-ID acceptance, the security-header table, CORS `Vary` merging, and
broker-decision classification live in `wasi-http-policy-core`. Native
`wasi-http-authn` and the portable components call those functions rather than
keeping a second copy. `AuthContextV1` remains the unsigned base64url context
from this workspace. It is a different credential from `wasi-auth`'s
HMAC-SHA-256 trusted-context envelope.

## Streaming invariant

Application request and response bodies are never collected by middleware.
Header replacement transfers the original body and body-result resources. Each
wrapper relays the new message's `transmission_result` into the original
`consume_body` result; discarding either future can cancel an upstream producer
and lose the first frame when a stream immediately fails.

Regression coverage repeats an observably mid-stream sequence `first frame ->
stream close -> body-result error` through stacked components and requires
every response that committed headers to deliver the first frame before the
error. A separate immediate body-result error must not hang or report success;
it does not require a buffered frame to beat connection termination. Delayed
streams, trailers, disconnects, request bodies, and failing streams are also
covered. Malformed header blocks rejected by the host before guest invocation
cannot be made equivalent by middleware and are treated as a host boundary.

The authentication request JSON is bounded control-plane data. Broker response
bodies are buffered to at most 64 KiB; application bodies remain streaming.

## Authentication versus authorization

`authn-policy` verifies a credential and emits one request-only context. The
broker receives no route, method, authority, query, cookie, or body. The
application receives no `Authorization` header. It uses the canonical
`(issuer, subject)` pair and claims for domain authorization. In Leptos this
belongs in `ServerFn::middlewares()`, where resource ownership and business
rules are available.

Ingress still owns TLS, HSTS, WAF policy, proxy identity, distributed limits,
global deadlines, and static asset controls. `/pkg/...` split-Wasm assets stay
public unless the CDN/fileserver/ingress explicitly protects them.

## Host and trigger boundary

Wasmtime 50.0.0 runs the final WASI 0.3 behavioral suite. Official Spin 4.2.5
serves the same `wasi:http/handler@0.3.0` chain both as one WAC-composed
component and through native `dependencies.middleware`. The July Spin fork is
not a host. HTTP/1.1 trailers are delivered when the client sends
`TE: trailers`; HTTP/2 on Spin 4.2.5 writes them without that field.

HTTP middleware cannot wrap Redis, MQTT, cron, or custom triggers because they
export different WIT worlds. Future adapters may reuse pure policy crates, but
each adapter needs its own capability, lifecycle, and compatibility contract.
