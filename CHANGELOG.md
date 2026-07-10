# Changelog

All notable changes to this project are documented here.

## [Unreleased]

## [0.1.0-alpha.1] - 2026-07-10

### Added

- Framework-neutral request-ID, security-header, CORS, and fail-closed external
  authentication middleware for the pinned WASIp3 March 2026 RC.
- Strict policy-path normalization, trusted identity metadata, a two-second
  default elapsed/transport budget, and a 64 KiB policy-response limit.
- Deterministic Wasmtime precomposition and two reusable Spin vNext projects
  with fine-grained capability inheritance.
- Exact ABI/import audits, negative manifest tests, checksums, CycloneDX SBOMs,
  expanded HTTP/stream/disconnect/concurrency contracts, browser integration,
  and scheduled 100-concurrency endurance gates.

### Compatibility

- Rust 1.93.0, Wasmtime 45.0.0, `wasm-tools` 1.248.0, WAC 0.10.1, Spin runtime
  `27451471...`, and Spin SDK `14e675aa...` are pinned in
  `compatibility.toml`.
- Stable Spin, WASIp2 middleware, WebSockets, and non-HTTP trigger adapters are
  not supported by this alpha.

### Known promotion blocker

- The raw pass-through, request-ID, and security-header Wasmtime
  microbenchmarks exceed the five-percent overhead budget. The alpha records
  the measurements and keeps the benchmark canary non-blocking; a stable
  release cannot waive this gate.
