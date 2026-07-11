# WASI HTTP Middleware

Framework-neutral, streaming-safe HTTP middleware components for the final
`wasi:http/middleware@0.3.0` contract. They can wrap any matching terminal
service and do not depend on Spin SDK, Leptos, or an application framework.

> **Alpha:** `0.2.0-alpha.3` targets final WASI 0.3 with Wasmtime 46.0.1.
> Current Spin hosts do not yet link final `wasi:http@0.3.0`; their lanes are
> explicit expected-incompatibility canaries, not runtime support claims.

## Components

The reusable chain is outermost to innermost:

```text
request-id -> security-headers -> cors -> authn-policy -> application
```

- `request-id` validates or replaces `x-request-id` and returns it.
- `security-headers` applies `nosniff` and a conservative referrer policy.
- `cors` uses exact allowlists and completes preflight before authentication.
- `authn-policy` calls a credential-verification broker, fails closed, strips
  credentials and spoofed metadata, and injects one bounded versioned context.
- `secure-defaults` fuses the same four policies into one experimental portable
  component. It is retained for interoperability and conformance testing, but
  immutable WASI header rebuilding exceeds the production latency budget.
- `wasi-http-authn` authenticates an ordinary terminal `http::Request` and
  installs typed identity in `http::Extensions` without rebuilding WASI
  request and response resources.

The trusted `x-wasi-auth-context` header is request-only. Every authentication
component removes all `x-wasi-auth-*` response fields before returning to a
client. Resource/domain authorization stays in the application—for example,
Leptos `ServerFn::middlewares()`—and never receives the original credential.

Production deployments reuse the policy, metadata, and in-process
authentication crates inside a trusted native ingress. Portable guest
components do not carry a production recommendation.

## Build and verify

Install the exact tools in `compatibility.toml`, then run:

```bash
bash scripts/build-components.sh
bash scripts/check-component-contracts.sh
bash scripts/run-wasmtime-e2e.sh
bash scripts/run-wasmtime-secure-defaults-e2e.sh
bash scripts/compare-wasmtime-profiles.sh
bash scripts/generate-checksums.sh
bash scripts/generate-sbom.sh
```

Compose either distribution shape:

```bash
bash scripts/compose-wasmtime.sh artifacts/test-components/echo-service.wasm
bash scripts/compose-secure-defaults.sh artifacts/test-components/echo-service.wasm
```

Spin lanes prove the current incompatibility remains understood:

```bash
SPIN_COMPAT_PROFILE=stable-final bash scripts/run-spin-e2e.sh
SPIN_COMPAT_PROFILE=native-middleware \
  SPIN_BIN=/path/to/pinned-spin bash scripts/run-spin-e2e.sh
```

Both commands succeed only when Spin fails for the pinned final-WIT linker or
RC-middleware mismatch. They must be replaced by behavioral E2E when Spin ships
matching final WASI 0.3 host bindings.

Security and release evidence:

```bash
CARGO_FUZZ_BIN=/path/to/cargo-fuzz bash scripts/run-fuzz-smoke.sh
bash scripts/dry-run-supply-chain.sh
HOST=wasmtime bash scripts/soak-runtime.sh
```

The supply-chain dry run creates a local OCI layout, deterministic provenance,
and ephemeral-key signatures for both provenance and the OCI manifest. It
never pushes, tags, publishes, or retains the private key.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Configuration](docs/CONFIGURATION.md)
- [Trust boundary](docs/TRUST-BOUNDARY.md)
- [Support matrix](docs/SUPPORT.md)
- [Performance](docs/PERFORMANCE.md)
- [Release process](docs/RELEASE.md)
- [Security policy](SECURITY.md)

`wasm32-wasip2` is the Rust compilation target used to emit components; the
public HTTP ABI is asynchronous WASI 0.3, not Preview 2 HTTP.

## License

Apache-2.0 or MIT, at your option.
