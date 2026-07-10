# Changelog

All notable changes are documented here.

## [Unreleased]

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
- Wasmtime 46 behavioral suites, fuzz targets, final-WIT contract reports,
  deterministic SBOM/checksum evidence, local OCI layout, provenance, and
  ephemeral signature dry runs.

### Fixed

- Relayed forwarded request/response transmission results to prevent stacked
  middleware from canceling a producer and intermittently losing the first
  frame before a terminal stream error.
- Removed credentials/spoofed metadata before downstream invocation and removed
  all trusted authentication metadata from client responses.

### Compatibility

- Wasmtime 46.0.1 is the only passing behavioral host in this alpha.
- Spin 4.0.0 lacks final-WASI resources and the pinned middleware revision is
  RC-only; both are explicit expected-incompatibility canaries.

## [0.1.0-alpha.1] - 2026-07-10

- Initial March-2026-RC request-ID, security-header, CORS, and external-policy
  middleware prototype.
