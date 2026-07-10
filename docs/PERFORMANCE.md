# Performance and soak evidence

## Reproducible commands

`benchmark-components.sh` runs three warmed Wasmtime samples for the unwrapped
echo service and for pass-through, request-ID, and security-header composition.
It records JSON under `reports/performance/` and fails when median throughput or
median p99 latency regresses by more than five percent.

`soak-runtime.sh` runs the complete authenticated chain with 100 concurrent
clients at a controlled 100 requests per second. The default duration is ten
minutes. It rejects non-200 responses, client errors, sensitive values in host
logs, and sustained resident-memory growth during the second half. Wasmtime
and Spin use separate reports under `reports/soak/`.

The rate limit is deliberate: the pinned Wasmtime P3 host creates enough
short-lived outbound policy connections under an unlimited localhost
microbenchmark to exhaust transport resources. Throughput saturation belongs
in the benchmark; the soak measures endurance at a declared load.

## Alpha promotion status

The raw echo-service benchmark currently exceeds the five-percent component
overhead budget on the pinned local tuple. This is a measured stable-promotion
blocker, not a skipped or softened assertion. The benchmark script exits
nonzero and CI records it as an alpha canary. A realistic application benchmark
can supplement, but cannot erase, the raw component-boundary result.

The final 2026-07-10 three-sample medians were:

| Profile | Requests/s | Throughput regression | p99 | p99 regression |
|---|---:|---:|---:|---:|
| Unwrapped | 72,129 | baseline | 3.79 ms | baseline |
| Pass-through | 63,249 | 12.3% | 4.27 ms | 12.8% |
| Request ID | 44,813 | 37.9% | 5.99 ms | 58.1% |
| Security headers | 51,216 | 29.0% | 5.35 ms | 41.2% |

These numbers describe a deliberately tiny terminal service under saturation,
so they are not an application capacity forecast. They do establish that the
five-percent raw overhead gate is not met by this RC host/component tuple.

## 0.1.0-alpha.1 endurance result

The 2026-07-10 local release run used the pinned Wasmtime 45 and Spin
`27451471...` binaries, 100 concurrent clients, 100 requests per second, and a
ten-minute duration per host:

| Host | Requests | Unexpected | p99 | App RSS start/end | App RSS peak |
|---|---:|---:|---:|---:|---:|
| Wasmtime | 60,000 | 0 | 8.77 ms | 25.2 / 27.1 MiB | 39.5 MiB |
| Spin | 60,000 | 0 | 9.42 ms | 10.6 / 10.6 MiB | 16.1 MiB |

Both runs recorded 120 memory samples, reached a plateau, had no hung requests,
and passed the sensitive-log scan. Reports remain local generated artifacts;
rerun the gate on the release machine instead of treating this table as a
portable capacity promise.
