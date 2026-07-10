# Release process

## Compatibility lock

`compatibility.toml` is the release source of truth. Blocking CI must use the
exact Rust, WIT, `wasip3`, `wit-bindgen`, Spin revision, Wasmtime, `wasm-tools`,
and WAC versions recorded there. A non-blocking canary may follow upstream
heads, but it cannot replace the pinned lane.

Changing the WIT package version requires rebuilding every component and
terminal fixture, regenerating ABI reports, rerunning both runtime suites, and
reviewing compatibility as a release-level change.

## Required gates

```bash
cargo fmt --all -- --check
cargo clippy --workspace --locked --all-targets --all-features -- -D warnings
cargo test --workspace --locked --all-features
cargo test --workspace --locked --doc
RUSTDOCFLAGS='-Dmissing-docs -Drustdoc::broken-intra-doc-links' \
  cargo doc --workspace --locked --no-deps --all-features
cargo audit --deny warnings
cargo deny check
bash scripts/build-components.sh
bash scripts/check-component-contracts.sh
bash scripts/run-wasmtime-e2e.sh
SPIN_BIN=/path/to/the-pinned-spin bash scripts/run-spin-e2e.sh
bash scripts/generate-checksums.sh
bash scripts/generate-sbom.sh
HOST=wasmtime bash scripts/soak-runtime.sh
HOST=spin SPIN_BIN=/path/to/the-pinned-spin bash scripts/soak-runtime.sh
```

`check-component-contracts.sh` validates with
`--features component-model,cm-async`, records the generated WIT, requires one
imported and one exported pinned HTTP handler, compares all imports with exact
allowlists, runs negative deployment-audit cases, and checks two reusable Spin
projects for artifact and configuration isolation.

Wasmtime 45 must be started with `-W component-model-async=y -S p3=y`; enabling
generic WASI HTTP without the P3 host implementation does not satisfy the
resource types in this release candidate.

WAC 0.10.1 is the minimum pinned composer. WAC 0.8.0 cannot decode this async
component shape and fails before composition; that older version is not a
supported fallback.

`benchmark-components.sh` records the unwrapped, pass-through, request-ID, and
security-header microbenchmarks. It remains a non-blocking alpha canary because
the pinned Wasmtime tuple does not yet meet the five-percent raw echo-service
budget; see [PERFORMANCE.md](PERFORMANCE.md). It becomes blocking before a
stable release.

## Alpha artifacts

The release directory contains:

```text
artifacts/components/auth-policy.wasm
artifacts/components/cors.wasm
artifacts/components/request-id.wasm
artifacts/components/security-headers.wasm
artifacts/SHA256SUMS
artifacts/sbom/*.cdx.json
reports/wit/*.wit
```

The pass-through component, test components, and composed E2E binaries are not
release artifacts. Review the WIT reports and SBOMs before signing. Publishing,
pushing, tagging, and creating a remote are separate operator actions and are
intentionally absent from the scripts.

## Stable promotion

Do not remove the alpha suffix until a stable Spin and SDK release implements
the same middleware contract and WIT version, all Git-head dependencies are
gone, runtime/browser/security/performance tests pass, a ten-minute
100-concurrency soak reaches a stable memory plateau, and the produced Wasm
artifacts have checksums, SBOMs, signatures, and provenance.

Until then, a Spin E2E exit status of 77 means only that the exact pinned vNext
binary was unavailable. Release CI must provide that binary; it must not treat
77 as success.
