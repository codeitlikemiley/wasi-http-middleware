# Tested compatibility

This is the exact compatibility matrix exercised for `0.2.0-alpha.3`. A pinned
test result is not automatically a production-support promise; see
[Support matrix](SUPPORT.md) for promotion status.

| Surface | Tested version | Result |
|---|---|---|
| Rust quality gate | 1.99.0 (`b940084d7`, 2026-09-28) | `rust-toolchain.toml` and CI. Not `stable` |
| Rust MSRV | 1.94.0 (`4a4ef493e`, 2026-03-02) | `package.rust-version`. Host and `wasm32-wasip2` `cargo check` compile `wasip3` 0.9.0 |
| Rust compilation target | `wasm32-wasip2` | Emits components; this does not make the public HTTP ABI Preview 2 |
| `wasip3` crate | `0.9.0+wasi-0.3.0` | Final WASI 0.3 bindings. `spawn` was renamed to `spawn_local` |
| `wit-bindgen` | 0.62.0 | One guest generator, shared with `wasip3` 0.9.0. Resolves `wit-component` 0.259.0 |
| Preview 2 adapter | `0.2.12` | Reactor imports linked by the `wasm32-wasip2` target. Not a middleware policy capability |
| Public HTTP WIT | `wasi:http@0.3.0` | Exact final asynchronous component ABI |
| Wasmtime | 50.0.0 (`ebe5e8df1`, 2026-10-20) | Passing behavioral reference host |
| Spin | 4.2.5 (`e09d7d5`, 2026-10-23) | Official `spinframework/spin` linux-amd64 release. Composed `wasi:http/handler@0.3.0` and native `dependencies.middleware` both pass |
| `spin-sdk` pin | git `3cf30012b50a1afb750dac3d28aa6da4a32c3468` | Recorded for consumers and tests that import the SDK. This workspace does not depend on the crate |
| `wasm-bindgen` | 0.2.126 | Used only by the tested sibling Leptos browser bridge; not a dependency or ABI of this server-component workspace |

## What the Spin result means

The host is the official Spin 4.2.5 release binary, not a fork and not a
source build. Two profiles are positive gates:

- `release-composed` serves the WAC-composed chain as `wasi:http/handler@0.3.0`.
- `release-native` serves the same policies through `dependencies.middleware`.

Both profiles run the shared HTTP contract, including request IDs, CORS,
security headers, required authentication, streaming bodies, and cancellation.
HTTP/1.1 trailers follow Hyper 1.11 and RFC 9110 §6.5.1: the response declares
`Trailer: x-echo-trailer`, a request with `TE: trailers` receives
`x-echo-trailer: preserved`, and the same response omits that field when `TE`
is absent. That is the contract, not a host defect.

Spin 4.2.5 also writes `x-echo-trailer` on HTTP/2 prior knowledge. `wasmtime
serve` 50.0.0 does not complete that request. With either
`-W component-model-async=y -S p3=y -S cli=y -S http=y` or
`-S cli,http,p3 -W component-model-async,component-model-error-context`, the
server logs `hyper::Error(Parse(VersionH2))` and curl exits 56. Wasmtime
HTTP/2 trailers are unverified because this `serve` command rejects the
HTTP/2 preface.

Building `codeitlikemiley/spin` is not a gate. `scripts/bootstrap-spin-main.sh`
refuses that path. `scripts/bootstrap-spin-release.sh` downloads
`spin-v4.2.5-linux-amd64.tar.gz`.

```bash
SPIN_BIN="$(bash scripts/bootstrap-spin-release.sh)"
SPIN_COMPAT_PROFILE=release-composed \
  SPIN_BIN="$SPIN_BIN" bash scripts/run-spin-e2e.sh
SPIN_COMPAT_PROFILE=release-native \
  SPIN_BIN="$SPIN_BIN" bash scripts/run-spin-e2e.sh
```

`compatibility.toml` is the machine-readable authority for these versions and
full revisions. Any change requires rebuilding components and rerunning the
contract, runtime, streaming, and performance gates before updating this page.
