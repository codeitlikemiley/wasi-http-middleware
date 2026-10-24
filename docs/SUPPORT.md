# Support matrix

This matrix describes `0.2.0-alpha.3`; it is not a stable-support promise.

| Capability | Status | Notes |
|---|---|---|
| Rust quality gate | Tested | Exact Rust 1.99.0. Not `stable` |
| Rust MSRV | Tested | `package.rust-version` 1.94. Host and `wasm32-wasip2` checks compile |
| Final WASI 0.3 HTTP middleware | Alpha | Exact `wasi:http/middleware@0.3.0` |
| `wasip3` / `wit-bindgen` | Tested | `wasip3` `0.9.0+wasi-0.3.0` with one `wit-bindgen` 0.62.0 |
| Rust build target | Build detail | `wasm32-wasip2` emits the component; public ABI is WASI 0.3 |
| Wasmtime 50.0.0 | Behavioral host | Composition, security, streaming, parity, and concurrency runners. Ten-minute soak is scheduled, not part of this change's local run |
| Spin 4.2.5 composed handler | Tested | Official release serves the WAC-composed final chain |
| Spin 4.2.5 native middleware | Tested | Official release serves `dependencies.middleware` for these final-WIT components |
| `spin-sdk` `3cf30012...` | Consumer pin | Not a crate dependency of this workspace |
| `wasm-bindgen` 0.2.126 | Sibling browser test only | Not used by this server-component workspace or its public ABI |
| Other final-WASI hosts | ABI candidate | Must pass the complete contract before a support claim |
| Separate four-component chain | Implemented | Request ID, security, CORS, strict authn |
| Fused `secure-defaults` | Experimental | Golden-equivalent portable interoperability and conformance fixture |
| In-process `wasi-http-authn` | Alpha | Trusted-ingress and terminal-broker boundary using typed request extensions |
| Request/response streaming | Implemented | No application-body collection |
| Mid-stream frame then error | Implemented | First frame preserved before terminal error; separate immediate-error no-hang gate |
| Trailers | Forwarded | Body is preserved. HTTP/1.1 fields arrive only with `TE: trailers` and a declared `Trailer` name. Spin 4.2.5 also writes them on HTTP/2. Wasmtime 50 `serve` rejects the HTTP/2 preface (`Parse(VersionH2)`) |
| CORS preflight | Implemented | Exact allowlists; executes before authn |
| Required/optional authn | Implemented | Optional applies only to absent credentials |
| Versioned trusted context | Implemented | Bounded request-only base64url V1 envelope |
| Domain authorization | Application-owned | E.g. Leptos `ServerFn::middlewares()` |
| Disconnect/concurrency | Covered | Wasmtime recovery and concurrent-request contracts |
| Islands/split Wasm | Sibling integration | `leptos_wasi`; `/pkg/...` remains public at static boundary |
| WebSockets/upgrades | Not claimed | No component conformance coverage |
| WASIp2 HTTP middleware | Unsupported | Different synchronous handler contract |
| Redis/MQTT/cron/custom triggers | Unsupported | Require trigger-specific adapters |
| Static/range/cache policy | Out of scope | Fileserver/CDN/ingress responsibility |
| Distributed rate limiting | Out of scope | Requires shared host/service state |

Malformed host header blocks may be rejected before guest invocation and are
not a middleware parity surface. The authn broker is never sent method, path,
query, authority, cookies, or application body.

Stable promotion requires a final-WASI Spin host (if Spin support is claimed),
blocking performance budgets, signed release provenance under an approved CI
identity, scheduled memory plateau evidence, and no skipped production path.
The exact version evidence and commands are recorded in
[Tested compatibility](COMPATIBILITY.md).
