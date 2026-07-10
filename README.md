# WASI HTTP Middleware

Reusable, streaming-safe HTTP middleware components for WASIp3 services. The
components implement the standard `wasi:http/middleware` world and can wrap any
compatible terminal service; they are not tied to Spin, Wasmtime, Leptos, or a
particular guest language.

> **Alpha:** `0.1.0-alpha.1` targets
> `wasi:http@0.3.0-rc-2026-03-15`. Spin middleware composition is pinned to a
> post-release vNext revision. Do not describe this repository as stable until
> the promotion gates in [RELEASE.md](docs/RELEASE.md) pass.

## Components

The default order is outermost to innermost:

```text
request-id -> security-headers -> cors -> auth-policy -> application
```

- `request-id` validates or generates `x-request-id` and returns the canonical
  value on the response.
- `security-headers` replaces unsafe values with `X-Content-Type-Options:
  nosniff` and `Referrer-Policy: strict-origin-when-cross-origin`.
- `cors` enforces an explicit origin, method, header, and credential policy and
  short-circuits valid preflight requests before authentication.
- `auth-policy` strips client-supplied `x-wasi-auth-*` values, calls a policy
  service, fails closed, and inserts validated identity metadata.

`passthrough` is a conformance-only component used to prove composition and
stream forwarding. It is not a release artifact.

## Build and inspect

Install the Rust toolchain and tools pinned in `compatibility.toml`, then run:

```bash
bash scripts/build-components.sh
bash scripts/check-component-contracts.sh
bash scripts/generate-checksums.sh
bash scripts/generate-sbom.sh
```

To precompose the chain for Wasmtime:

```bash
bash scripts/compose-wasmtime.sh \
  artifacts/test-components/echo-service.wasm
```

The runtime tests use the deterministic echo and policy fixtures:

```bash
bash scripts/run-wasmtime-e2e.sh
SPIN_BIN=/path/to/pinned/spin bash scripts/run-spin-e2e.sh
```

The Spin runner exits with status 77 and a `SKIP` message only when the exact
pinned vNext binary is unavailable. Missing fixtures, invalid manifests, failed
requests, and ABI mismatches are errors.

Two committed Spin projects demonstrate artifact reuse and per-project policy:

- `fixtures/spin/full-chain` uses the complete authenticated chain.
- `fixtures/spin/public-stack` reuses request-ID, security-header, and CORS
  artifacts with an independent origin policy.

Performance and endurance runners are also local and deterministic:

```bash
bash scripts/benchmark-components.sh
HOST=wasmtime bash scripts/soak-runtime.sh
HOST=spin SPIN_BIN=/path/to/pinned/spin bash scripts/soak-runtime.sh
```

The benchmark intentionally exits nonzero when the five-percent promotion
budget is missed; the alpha does not hide a failing measurement.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Configuration](docs/CONFIGURATION.md)
- [Trust boundary](docs/TRUST-BOUNDARY.md)
- [Support matrix](docs/SUPPORT.md)
- [Performance and soak evidence](docs/PERFORMANCE.md)
- [Release process](docs/RELEASE.md)
- [Security policy](SECURITY.md)

`wasm32-wasip2` is the Rust compilation target used to produce a component. It
does not mean these components support the synchronous WASI Preview 2 HTTP
handler contract; their public ABI is the pinned asynchronous WASIp3 world.

## License

Licensed under either the Apache License, Version 2.0 or the MIT License, at
your option.
