# Performance and soak evidence

## Reproducible commands

`benchmark-components.sh` runs three warmed Wasmtime 46 samples for the
unwrapped echo service, pass-through, request-ID, and security-header profiles.
It records JSON under `reports/performance/` and flags the historical
five-percent budget without failing the release. The tiny echo service measures
raw component-boundary overhead; it is not an application capacity forecast or
the stable-promotion gate.

```bash
bash scripts/benchmark-components.sh
```

The final local 2026-07-10 run at 20,000 requests and concurrency 100 measured:

| Profile | Median requests/s | Throughput regression | Median p99 | p99 regression |
|---|---:|---:|---:|---:|
| Pass-through | 46,504 | 21.8% | 8.40 ms | 68.7% |
| Request ID | 38,531 | 35.2% | 9.85 ms | 97.8% |
| Security headers | 53,108 | 10.7% | 6.03 ms | 21.1% |

The unwrapped baseline was 59,454 requests/s with 4.98 ms p99. These results
remain visible because the boundary is not free; host load and machine policy
still make them diagnostic rather than portable capacity claims.

Blocking performance acceptance runs in the sibling `leptos_wasi` integration
against its realistic SSR/server-function/static workload. The fused
`secure-defaults` profile may regress median throughput or p99 by at most ten
percent versus that same workload unwrapped. Stable promotion remains blocked
if either realistic measurement misses.

`soak-runtime.sh` runs the complete authenticated chain with a default ten
minutes, 100 concurrent clients, and 100 requests per second. It rejects client
errors, unexpected statuses, sensitive log values, and sustained second-half
RSS growth.

```bash
HOST=wasmtime bash scripts/soak-runtime.sh
```

Spin soak is deliberately disabled: Spin 4.0.0 lacks final
`wasi:http@0.3.0` resources and the pinned middleware commit is RC-only. An
expected linker failure is not endurance evidence.

## Streaming performance invariant

Middleware copies bounded headers but never collects application bodies.
Delayed first bytes must arrive before a stream finishes. A first frame
followed by a short observable interval and a body-result error is repeated
through stacked middleware; every response that commits headers must preserve
the first frame, then expose the terminal error. A separate immediate-error
case requires cancellation without a hang or false success but does not assume
socket delivery won its scheduler race. The sibling Leptos transport suite
also verifies the relay with an observable mid-stream failure.

## Alpha promotion status

The raw five-percent budget remains a visible historical diagnostic. A local
smoke run may use reduced request/duration values to validate tooling, but it is
not substitute evidence for the default benchmark, the sibling realistic
ten-percent gate, or ten-minute soak. Generated JSON remains local because host
load, CPU policy, and background activity make it non-portable.
