#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

wasmtime_version="$(compat_value wasmtime)"
require_version wasmtime "${wasmtime_version}"
require_command curl

echo_component="${E2E_APP_COMPONENT:-$(test_component_file echo-service)}"
policy_component="${E2E_POLICY_COMPONENT:-$(test_component_file mock-policy)}"
require_file "${echo_component}"
require_file "${policy_component}"

app_port="${E2E_APP_PORT:-19090}"
policy_port="${E2E_POLICY_PORT:-19091}"
app_address="127.0.0.1:${app_port}"
policy_address="127.0.0.1:${policy_port}"
policy_url="http://${policy_address}/check"
if [[ -n "${E2E_COMPOSED_COMPONENT:-}" ]]; then
    composed="${E2E_COMPOSED_COMPONENT}"
    require_file "${composed}"
else
    composed="${ARTIFACT_ROOT}/composed/e2e-full-chain.wasm"
    bash "${REPO_ROOT}/scripts/compose-wasmtime.sh" "${echo_component}" "${composed}"
fi

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/wasi-http-wasmtime.XXXXXX")"
policy_pid=""
app_pid=""
cleanup() {
    [[ -n "${app_pid}" ]] && kill "${app_pid}" >/dev/null 2>&1 || true
    [[ -n "${policy_pid}" ]] && kill "${policy_pid}" >/dev/null 2>&1 || true
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
    "${policy_component}" \
    >"${temporary_directory}/policy.log" 2>&1 &
policy_pid=$!

policy_ready=false
for _ in $(seq 1 100); do
    status="$(curl --silent --max-time 1 --request POST --output /dev/null --write-out '%{http_code}' "${policy_url}" || true)"
    if [[ "${status}" == "401" ]]; then
        policy_ready=true
        break
    fi
    sleep 0.1
done
if [[ "${policy_ready}" != "true" ]]; then
    echo "error: Wasmtime mock policy did not become ready" >&2
    cat "${temporary_directory}/policy.log" >&2
    exit 1
fi

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
    "${composed}" \
    >"${temporary_directory}/app.log" 2>&1 &
app_pid=$!

ready=false
for _ in $(seq 1 100); do
    status="$(curl --silent --max-time 1 --output /dev/null --write-out '%{http_code}' "http://${app_address}/" || true)"
    if [[ "${status}" != "000" ]]; then
        ready=true
        break
    fi
    sleep 0.1
done
if [[ "${ready}" != "true" ]]; then
    echo "error: Wasmtime E2E service did not become ready" >&2
    cat "${temporary_directory}/policy.log" >&2
    cat "${temporary_directory}/app.log" >&2
    exit 1
fi

if ! bash "${REPO_ROOT}/scripts/exercise-http-contract.sh" "http://${app_address}"; then
    cat "${temporary_directory}/policy.log" >&2
    cat "${temporary_directory}/app.log" >&2
    exit 1
fi
assert_logs_do_not_contain_secrets \
    "${temporary_directory}/policy.log" \
    "${temporary_directory}/app.log"
assert_log_occurrences \
    115 \
    "wasi-http-middleware-test: terminal-invocation" \
    "${temporary_directory}/app.log"

echo "Wasmtime ${wasmtime_version} middleware E2E passed"
