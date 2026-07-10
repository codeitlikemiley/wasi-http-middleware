# Release process

## Compatibility lock

`compatibility.toml` pins Rust, final WIT, `wasip3`, `wit-bindgen`, Wasmtime,
`wasm-tools`, WAC, Spin canaries, fuzzing, and supply-chain tools. A release
changes the file and workspace package version together. WIT changes require
rebuilding every component, regenerating reports/SBOMs/checksums, and rerunning
all behavioral and incompatibility gates.

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
bash scripts/run-wasmtime-secure-defaults-e2e.sh
bash scripts/compare-wasmtime-profiles.sh
SPIN_COMPAT_PROFILE=stable-final bash scripts/run-spin-e2e.sh
CARGO_FUZZ_BIN=/path/to/cargo-fuzz bash scripts/run-fuzz-smoke.sh
bash scripts/generate-checksums.sh
bash scripts/generate-sbom.sh
bash scripts/dry-run-supply-chain.sh
HOST=wasmtime bash scripts/soak-runtime.sh
```

The Spin command is an expected-incompatibility canary. A successful Spin host
startup fails the canary until the repository replaces it with behavioral E2E.
The pinned native-middleware commit runs separately with
`SPIN_COMPAT_PROFILE=native-middleware`.

Component contracts validate async component-model encoding, exact imports,
one handler import/export, forbidden capabilities, deterministic WIT reports,
fixture isolation, and negative manifest audit cases. The two Wasmtime profiles
must also match golden status/header/body signatures, including CORS failure and
terminal stream errors.

## Artifact set

Production components:

```text
artifacts/components/request-id.wasm
artifacts/components/security-headers.wasm
artifacts/components/cors.wasm
artifacts/components/authn-policy.wasm
artifacts/components/secure-defaults.wasm
```

`artifacts/SHA256SUMS` also pins conformance/test components so integration
fixtures cannot silently drift. Deterministic CycloneDX files live under
`artifacts/sbom/`; exact component WIT lives under `reports/wit/`.

`dry-run-supply-chain.sh` builds a local OCI layout, creates deterministic
in-toto/SLSA-shaped provenance, generates an ephemeral local key, and signs and
verifies both provenance and the fetched OCI manifest. It performs no registry
push and deletes the private key. Promotion must replace the ephemeral key with
CI keyless signing or an approved release identity.

After the final version commit, regenerate all checksums, SBOMs, WIT reports,
and provenance because package versions and source revision are embedded.
Push, tag, registry upload, crates.io publication, and GitHub release creation
remain separate operator actions.

## Stable promotion

Do not remove the alpha suffix until claimed hosts implement the same final WIT,
performance/soak gates are blocking and green, identity/security review is
complete, and signed release provenance is verifiable without insecure flags.
