# Changelog

All notable changes are documented here.

## [Unreleased]

- Clarified that portable guest middleware remains an experimental
  interoperability path rather than a deprecated production fallback.
- Documented trusted native ingress as the production use of the shared policy,
  metadata, and in-process authentication crates.
- Canonicalized request IDs, security headers, `Vary` merging, and broker
  decision hooks through one implementation used by the native
  `wasi-http-authn` path and the portable components.
- Cross-origin requests whose method is outside the CORS allowlist now fail
  closed with 403 and `Vary: Origin` instead of reflecting
  `Access-Control-Allow-Origin`. Simple browser requests are included.
- `accept_trusted_ingress` requires the configured audience list to match
  exactly. HMAC-shaped `wasi-auth` trusted-context envelopes are rejected and
  are not treated as `AuthContextV1`.
- Recorded this repository as the canonical middleware source and the removal
  plan for `wasi-auth`'s vendored `legacy/wasi-http-middleware` copy. See
  [Canonical ownership](docs/CANONICAL.md).
- Pinned `wasip3` `0.9.0+wasi-0.3.0` and `wit-bindgen` `0.62.0`. Guest task
  spawn calls use `wasip3::spawn_local`. The library MSRV is 1.94; the
  quality-gate compiler is 1.99.0.
- Behavioral hosts are Wasmtime 50.0.0 and official Spin 4.2.5. Spin serves
  both the WAC-composed handler and native `dependencies.middleware`.
  HTTP/1.1 response trailers are still omitted by that Spin release; HTTP/2
  writes them.

## [0.2.0-alpha.2] - 2026-07-11

### Added

- A publishable, transport-neutral `wasi-http-authn` crate for trusted-ingress
  and statically dispatched terminal-broker authentication.
- Typed `VerifiedAuthContext` propagation through `http::Extensions` so trusted
  identity is removed from the wire before terminal application dispatch.

### Changed

- The guest `secure-defaults` stack is now a portable experimental fallback,
  not the recommended production architecture. It remains for this alpha and
  remains available as an experimental interoperability fixture.

## [0.2.0-alpha.1] - 2026-07-10

### Breaking

- Migrated every component from the March RC to final `wasi:http@0.3.0`.
- Replaced `auth-policy` and legacy identity headers with strict
  `authn-policy` and bounded `AuthContextV1` in `x-wasi-auth-context`.
- Renamed the deterministic policy fixture to `mock-authn-broker`.

### Added

- Required/optional authentication, immutable service/audience binding,
  HTTPS/Spin-internal/dev-loopback URL policy, RFC 6750 challenges, one total
  deadline, cancellation-safe bounded admission, and strict broker schemas.
- A fused `secure-defaults` component with golden parity against the separate
  request-ID/security/CORS/authn chain.
- ACR, AMR, issuer-scoped actor identity, roles, scopes, tenant/session claims,
  decision ID, and policy revision in the versioned context.
- Distinct immutable terminal service IDs and expected OAuth audiences, such as
  `orders-api` with `api://orders`.
- Wasmtime 46 behavioral suites, fuzz targets, final-WIT contract reports,
  deterministic SBOM/checksum evidence, local OCI layout, provenance, and
  ephemeral signature dry runs.

### Fixed

- Relayed forwarded request/response transmission results to prevent stacked
  middleware from canceling a producer and intermittently losing the first
  frame before a terminal stream error.
- Closed producers before publishing body results and joined outbound authn
  request transmission with body production, response collection, fail-fast
  cancellation, and the one absolute deadline.
- Removed credentials/spoofed metadata before downstream invocation and removed
  all trusted authentication metadata from client responses.
- Marked canonical authentication contexts, Authorization, cookies, and
  reserved trusted metadata as sensitive header values, and redacted public
  identity/authentication `Debug` implementations.

### Performance

- Reused a per-instance random request-ID prefix with a monotonic sequence,
  cached the deterministic anonymous authentication context, moved environment
  reads behind one-time initialization, and removed redundant header
  conversions while preserving immutable WASI resource lifecycles.

### Compatibility

- Wasmtime 46.0.1 is the only passing behavioral host in this alpha.
- Spin 4.0.0 lacks final-WASI resources and the pinned middleware revision is
  RC-only; both are explicit expected-incompatibility canaries.

## [0.1.0-alpha.1] - 2026-07-10

- Initial March-2026-RC request-ID, security-header, CORS, and external-policy
  middleware prototype.
