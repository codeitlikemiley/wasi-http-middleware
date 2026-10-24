# Trust boundary

## Required invariant

The terminal trusts `x-wasi-auth-context` only when every externally reachable
route passes through the declared component boundary. No second trigger,
service address, or ingress route may reach it directly. Run
`audit-spin-manifest.py` for native Spin manifests. Official Spin 4.2.5 can
serve the final-WIT chain as a composed handler or through
`dependencies.middleware`. Those fixtures prove the host contract. They are
not a production deployment manifest: the terminal still trusts
`x-wasi-auth-context` only when no other route can reach it.

The context is metadata, not a credential. Middleware first strips the client
`Authorization` value and every reserved header, then inserts one validated
context. The terminal must reject the header when composition is not guaranteed.

This context is canonical base64url JSON (`AuthContextV1`). It is not the
HMAC-SHA-256 envelope produced by `wasi-auth`'s native trusted ingress
(`base64url(payload).base64url(mac)` in the same `x-wasi-auth-context` header,
bound to audience, method, path, request ID, and a short replay window).
`decode_auth_context` and `accept_trusted_ingress` reject that envelope. They
do not verify its MAC. A guest that needs the signed envelope must use
`wasi-auth`'s `TrustedContextCodec` and must not treat a successful
`AuthContextV1` decode as proof of that signature.

## Responsibilities

| Boundary | Responsibilities |
|---|---|
| Ingress/host | TLS/HSTS, WAF, trusted proxy data, global deadlines, distributed limits, static assets |
| Component boundary | Request ID, conservative response headers, CORS, credential verification, metadata sanitization |
| Authentication broker | Credential, issuer/key lifecycle, revocation, identity claims |
| Application | Resource ownership and domain authorization |

Request ID and security headers import no environment or outbound HTTP. CORS
imports environment only. Authentication imports environment, monotonic clocks,
random, and WASI HTTP client. Deployment must grant only the exact configured
broker origin. `authn-policy` sends no request authorization inputs beyond the
credential itself and immutable deployment/request IDs.

## Failure policy

- Invalid cached configuration returns generic 503, never a raw host error.
- Duplicate/oversized/malformed Authorization returns 400 without a broker call.
- Missing credentials return 401 in required mode or anonymous context in
  optional mode.
- Supplied invalid credentials return 401; optional mode never fails open.
- Broker 403 and every non-authentication status fail closed as generic 503;
  domain 403 decisions belong to a separate authorization provider.
- Broker failure, deadline, saturation, malformed success, or unknown status is
  503.
- Body-result errors propagate after already-delivered frames; middleware does
  not buffer or convert them into successful completion.

## Sensitive data

Never log credentials, cookies, bodies, raw queries, trusted identity values,
session IDs, or context headers. A request ID is loggable only after canonical
validation. Safe telemetry includes status, duration, byte counts, middleware
class, and coarse error class.

Canonical context values and sensitive inbound header values carry Rust's
`HeaderValue::is_sensitive` marker, and public authentication identity types
redact their `Debug` output. Treat these as defense in depth: application code
must still avoid logging decoded accessors and must configure host/proxy logs
to exclude request secrets.

The mock broker uses deterministic test tokens (`Bearer allow`, `readonly`,
`lowacr`, `no-relation`, `deny`, `error`, and failure variants). It must never
be deployed as an identity
provider. Local supply-chain signing keys are ephemeral and dry-run-only;
promotion requires CI keyless signing or an approved release identity.
