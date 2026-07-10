#!/usr/bin/env python3
"""Aggregate component benchmarks and enforce the alpha regression budget."""

from __future__ import annotations

import json
import pathlib
import statistics
import sys


PROFILES = ["baseline", "passthrough", "request-id", "security-headers"]
MAX_REGRESSION = 0.05


def samples(root: pathlib.Path, profile: str) -> tuple[list[float], list[float]]:
    throughput: list[float] = []
    p99: list[float] = []
    for path in sorted(root.glob(f"wasmtime-{profile}-*.json")):
        data = json.loads(path.read_text())
        if data["summary"]["successRate"] != 1.0 or data["errorDistribution"]:
            raise RuntimeError(f"benchmark errors in {path}")
        throughput.append(float(data["summary"]["requestsPerSec"]))
        p99.append(float(data["latencyPercentiles"]["p99"]))
    if len(throughput) < 3:
        raise RuntimeError(f"expected at least three benchmark samples for {profile}")
    return throughput, p99


def main() -> int:
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "reports/performance")
    values = {profile: samples(root, profile) for profile in PROFILES}
    baseline_rps = statistics.median(values["baseline"][0])
    baseline_p99 = statistics.median(values["baseline"][1])
    output = {
        "max_regression": MAX_REGRESSION,
        "baseline": {"requests_per_second": baseline_rps, "p99_seconds": baseline_p99},
        "profiles": {},
    }
    failed = False
    for profile in PROFILES[1:]:
        rps = statistics.median(values[profile][0])
        p99 = statistics.median(values[profile][1])
        throughput_regression = max(0.0, 1.0 - rps / baseline_rps)
        latency_regression = max(0.0, p99 / baseline_p99 - 1.0)
        output["profiles"][profile] = {
            "requests_per_second": rps,
            "p99_seconds": p99,
            "throughput_regression": throughput_regression,
            "p99_regression": latency_regression,
        }
        failed |= throughput_regression > MAX_REGRESSION
        failed |= latency_regression > MAX_REGRESSION

    summary = root / "wasmtime-summary.json"
    summary.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(summary.read_text(), end="")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
