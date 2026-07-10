#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

host="${HOST:-wasmtime}"
duration="${SOAK_DURATION:-10m}"
concurrency="${SOAK_CONCURRENCY:-100}"
queries_per_second="${SOAK_QPS:-100}"
sample_seconds="${SOAK_SAMPLE_SECONDS:-5}"
require_version wasmtime "$(compat_value wasmtime)"
require_version oha "$(compat_value oha)"
require_command curl
require_command python3
require_command ps

if [[ "${SOAK_SKIP_BUILD:-0}" != "1" ]]; then
    bash "${REPO_ROOT}/scripts/build-components.sh"
fi

case "${host}" in
    wasmtime)
        app_port="${SOAK_APP_PORT:-19300}"
        policy_port="${SOAK_POLICY_PORT:-19301}"
        ;;
    spin)
        app_port="19100"
        policy_port="19101"
        spin_revision="$(compat_value spin_runtime_revision)"
        spin_short_revision="${spin_revision:0:7}"
        spin_bin="${SPIN_BIN:-spin}"
        if ! command -v "${spin_bin}" >/dev/null 2>&1; then
            echo "error: pinned Spin is required for the soak" >&2
            exit 1
        fi
        if [[ "$("${spin_bin}" --version 2>&1)" != *"${spin_short_revision}"* ]]; then
            echo "error: Spin does not match ${spin_revision}" >&2
            exit 1
        fi
        ;;
    *)
        echo "error: HOST must be wasmtime or spin" >&2
        exit 2
        ;;
esac

app_address="127.0.0.1:${app_port}"
policy_address="127.0.0.1:${policy_port}"
policy_url="http://${policy_address}/check"
report_directory="${REPORT_ROOT}/soak"
mkdir -p "${report_directory}"
result="${report_directory}/${host}.json"
memory="${report_directory}/${host}-memory.tsv"
summary="${report_directory}/${host}-summary.json"
: >"${memory}"

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/wasi-http-soak.XXXXXX")"
policy_pid=""
app_pid=""
load_pid=""
cleanup() {
    [[ -n "${load_pid}" ]] && kill "${load_pid}" >/dev/null 2>&1 || true
    [[ -n "${app_pid}" ]] && kill "${app_pid}" >/dev/null 2>&1 || true
    [[ -n "${policy_pid}" ]] && kill "${policy_pid}" >/dev/null 2>&1 || true
    wait "${load_pid}" >/dev/null 2>&1 || true
    wait "${app_pid}" >/dev/null 2>&1 || true
    wait "${policy_pid}" >/dev/null 2>&1 || true
    rm -rf "${temporary_directory}"
}
trap cleanup EXIT

wasmtime serve \
    -W component-model-async=y \
    -S p3=y \
    -S cli=y \
    -S http=y \
    --addr "${policy_address}" \
    "$(test_component_file mock-policy)" \
    >"${temporary_directory}/policy.log" 2>&1 &
policy_pid=$!

for _ in $(seq 1 100); do
    status="$(curl --silent --max-time 1 --request POST --output /dev/null --write-out '%{http_code}' "${policy_url}" || true)"
    [[ "${status}" == "401" ]] && break
    sleep 0.05
done
if [[ "${status:-000}" != "401" ]]; then
    cat "${temporary_directory}/policy.log" >&2
    exit 1
fi

if [[ "${host}" == "wasmtime" ]]; then
    composed="${ARTIFACT_ROOT}/composed/soak-full-chain.wasm"
    bash "${REPO_ROOT}/scripts/compose-wasmtime.sh" \
        "$(test_component_file echo-service)" "${composed}"
    wasmtime serve \
        -W component-model-async=y \
        -S p3=y \
        -S cli=y \
        -S http=y \
        -S inherit-network=y \
        --env "WASI_MIDDLEWARE_CORS_ORIGINS=https://app.example" \
        --env "WASI_MIDDLEWARE_CORS_METHODS=GET,HEAD,POST" \
        --env "WASI_MIDDLEWARE_CORS_HEADERS=content-type,authorization" \
        --env "WASI_MIDDLEWARE_CORS_ALLOW_CREDENTIALS=false" \
        --env "WASI_MIDDLEWARE_POLICY_URL=${policy_url}" \
        --env "WASI_MIDDLEWARE_POLICY_TIMEOUT_MS=2000" \
        --addr "${app_address}" \
        "${composed}" >"${temporary_directory}/application.log" 2>&1 &
    app_pid=$!
else
    rm -rf "${REPO_ROOT}/fixtures/spin/full-chain/.spin"
    "${spin_bin}" up \
        --from "${REPO_ROOT}/fixtures/spin/full-chain/spin.toml" \
        --listen "${app_address}" \
        >"${temporary_directory}/application.log" 2>&1 &
    app_pid=$!
fi

for _ in $(seq 1 150); do
    status="$(curl --silent --max-time 1 --header 'Authorization: Bearer allow' --output /dev/null --write-out '%{http_code}' "http://${app_address}/" || true)"
    [[ "${status}" == "200" ]] && break
    sleep 0.05
done
if [[ "${status:-000}" != "200" ]]; then
    cat "${temporary_directory}/application.log" >&2
    exit 1
fi

NO_COLOR=false oha \
    -z "${duration}" \
    -w \
    -c "${concurrency}" \
    -q "${queries_per_second}" \
    --latency-correction \
    --no-tui \
    --output-format json \
    --output "${result}" \
    -H 'Authorization: Bearer allow' \
    "http://${app_address}/" &
load_pid=$!
started="$(date +%s)"
while kill -0 "${load_pid}" >/dev/null 2>&1; do
    application_rss="$(ps -o rss= -p "${app_pid}" | tr -d ' ' || true)"
    policy_rss="$(ps -o rss= -p "${policy_pid}" | tr -d ' ' || true)"
    if [[ -n "${application_rss}" && -n "${policy_rss}" ]]; then
        printf '%s\t%s\t%s\n' "$(( $(date +%s) - started ))" "${application_rss}" "${policy_rss}" >>"${memory}"
    fi
    sleep "${sample_seconds}"
done
wait "${load_pid}"
load_pid=""

assert_logs_do_not_contain_secrets \
    "${temporary_directory}/policy.log" \
    "${temporary_directory}/application.log"
if [[ "${host}" == "spin" ]]; then
    assert_logs_do_not_contain_secrets \
        "${REPO_ROOT}/fixtures/spin/full-chain/.spin/logs/application_stdout.txt" \
        "${REPO_ROOT}/fixtures/spin/full-chain/.spin/logs/application_stderr.txt"
fi
if ! python3 "${REPO_ROOT}/scripts/check-soak.py" "${result}" "${memory}" "${summary}"; then
    cat "${temporary_directory}/policy.log" >&2
    cat "${temporary_directory}/application.log" >&2
    exit 1
fi
