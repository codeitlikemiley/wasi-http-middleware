# Support matrix

This matrix describes `0.1.0-alpha.1`; it is not a stable-support promise.

| Capability | Status | Notes |
|---|---|---|
| WASIp3 HTTP service | Alpha | Pinned `0.3.0-rc-2026-03-15` ABI |
| `wasm32-wasip2` Rust target | Build target | Produces the WASIp3 component; not a Preview 2 middleware API |
| Spin stable | Unsupported | Stable releases without trigger middleware cannot load this chain |
| Spin pinned vNext | Experimental | Exact runtime revision is in `compatibility.toml` |
| Wasmtime 45 | Experimental | Requires deterministic build-time composition |
| Other WASIp3 HTTP services | ABI-compatible | Language/framework independent after matching WIT versions |
| WASIp2 HTTP handlers | Unsupported | No equivalent asynchronous sandwich composition contract |
| Redis/MQTT/cron/custom triggers | Unsupported | Require trigger-specific WIT adapters |
| Request/response streaming | Implemented | Header reconstruction transfers body streams without collection |
| HTTP trailers | Forwarded, host-dependent | Futures remain attached to the body; the pinned Wasmtime HTTP/1 bridge does not expose them to clients |
| CORS preflight | Implemented | Explicit allowlists; executes before auth in the default chain |
| External auth policy | Implemented | Fail closed; 64 KiB maximum policy response |
| Policy path normalization | Implemented | Strict one-pass decoding rejects ambiguous routing forms |
| Policy elapsed budget | Implemented | Monotonic checks plus host transport timeouts; deployment deadline still required |
| Disconnect/concurrency | Covered | Recovery and 100-concurrent-request contracts run on both pinned hosts |
| Browser islands/split WASM | Integration-tested | Covered by the sibling `leptos_wasi` 0.4.1 fixture |
| WebSockets/upgrades | Not claimed | No conformance coverage |
| Range/static asset policy | Out of scope | Configure fileserver, CDN, or ingress separately |
| Distributed rate limiting | Out of scope | Requires shared host/service state |

Known promotion gaps are stable Spin/WIT alignment, WebSockets/upgrades,
cross-host trailer exposure, signed provenance, and the raw microservice
overhead budget described in [PERFORMANCE.md](PERFORMANCE.md). Scheduled
ten-minute soaks provide the memory/concurrency gate. The scripts fail on
missing fixtures or contract mismatches rather than marking them as passed.
