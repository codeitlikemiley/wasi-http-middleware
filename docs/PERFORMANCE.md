# Performance and soak evidence

## Reproducible commands

`benchmark-components.sh` runs three warmed Wasmtime 46 samples for the
unwrapped echo service, pass-through, request-ID, and security-header profiles.
It records JSON under `reports/performance/` and reports any median throughput
or p99 regression over five percent. The tiny echo service is a component
boundary microbenchmark, not an application capacity forecast.

```bash
bash scripts/benchmark-components.sh
```

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
Delayed first bytes must arrive before a stream finishes. A frame immediately
followed by a body-result error is repeated through stacked middleware; every
response that commits headers must preserve the first frame, then expose
`None` or the terminal error. The relay fix is also verified by the sibling
Leptos transport suite.

## Alpha promotion status

Raw per-component five-percent budgets remain promotion gates. A local smoke
run may use reduced request/duration values to validate tooling, but it is not
substitute evidence for the default benchmark or ten-minute soak. Generated
reports remain local because host load, CPU policy, and background activity
make checked-in capacity numbers misleading.
