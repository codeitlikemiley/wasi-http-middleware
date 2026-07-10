# Trust boundary

## Required deployment invariant

The terminal application is trusted only when every externally reachable route
to it passes through the declared middleware chain. Never expose a second HTTP
trigger, service address, or ingress route that reaches the same terminal
component directly. Run `audit-spin-manifest.py` for every production manifest.
The audit also requires the primary component's outbound allowlist to equal the
single origin derived from `WASI_MIDDLEWARE_POLICY_URL`; adding another host
would silently broaden the authentication component's inherited network power.

`x-wasi-auth-*` fields are not credentials. They are trusted metadata only
after `auth-policy` has removed all client-supplied reserved fields, received an
allow decision, validated the response, and inserted canonical values. The
application must reject or ignore those fields when the composed boundary is
not guaranteed.

## Responsibilities

| Boundary | Responsibilities |
|---|---|
| Ingress/host | TLS, HSTS, WAF, trusted proxy/IP handling, global deadlines, distributed rate limiting, static assets |
| Component chain | Request ID, conservative headers, CORS, coarse authentication, metadata sanitization |
| Policy service | Credential verification, issuer/key lifecycle, revocation, central coarse policy |
| Application | Resource ownership and domain authorization |

## Capability isolation

Request ID and security headers require no inherited application capability.
CORS receives only environment configuration. Authentication receives only
environment configuration and the policy service's outbound host.

Spin currently inherits middleware capabilities from the primary component's
configuration. Therefore the primary component must also declare the policy
host and middleware environment values. Deny adapters prevent other
capabilities from reaching middleware, but they do not remove those declarations
from the primary component. If the terminal application must not possess the
policy-service network capability, move authentication to ingress or a
separately deployed policy proxy.

## Failure policy

- Invalid CORS configuration fails initialization; disallowed requests receive
  403.
- Invalid or duplicate authorization receives 400 without contacting policy.
- Missing credentials receive the policy service's 401 decision.
- Policy failure, timeout, invalid JSON, invalid identity, or an unknown status
  becomes 503. Authentication never fails open.
- Ambiguous or multiply encoded policy paths receive 400 before an outbound
  policy call.
- Middleware never returns raw host or policy error details to clients.

## Sensitive data

Do not log authorization values, cookies, bodies, raw queries, policy secrets,
or trusted identity header values. Request IDs are loggable only after
canonical validation. Production telemetry may record method, normalized path,
status, duration, byte counts, middleware class, and an error class.

The mock policy and echo components are test fixtures. Their deterministic
tokens and identity must never be deployed as a real identity provider.
