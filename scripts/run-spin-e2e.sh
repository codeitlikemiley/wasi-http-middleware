#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

spin_revision="$(compat_value spin_runtime_revision)"
spin_short_revision="${spin_revision:0:7}"
spin_bin="${SPIN_BIN:-spin}"
if ! command -v "${spin_bin}" >/dev/null 2>&1; then
    echo "SKIP: pinned Spin ${spin_revision} is unavailable" >&2
    exit 77
fi
spin_version="$(${spin_bin} --version 2>&1 || true)"
if [[ "${spin_version}" != *"${spin_short_revision}"* ]]; then
    echo "SKIP: expected pinned Spin ${spin_revision}; found ${spin_version}" >&2
    exit 77
fi

wasmtime_version="$(compat_value wasmtime)"
require_version wasmtime "${wasmtime_version}"
require_command curl
require_command python3

policy_component="${E2E_POLICY_COMPONENT:-$(test_component_file mock-policy)}"
require_file "$(test_component_file echo-service)"
require_file "${policy_component}"
for component in "${COMPONENTS[@]}"; do
    require_file "$(component_file "${component}")"
done

app_port="${E2E_SPIN_PORT:-19100}"
policy_port="${E2E_SPIN_POLICY_PORT:-19101}"
if [[ "${policy_port}" != "19101" ]]; then
    echo "error: committed Spin fixtures pin the mock policy to port 19101" >&2
    exit 1
fi
app_address="127.0.0.1:${app_port}"
policy_address="127.0.0.1:${policy_port}"
policy_url="http://${policy_address}/check"

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/wasi-http-spin.XXXXXX")"
full_manifest="${REPO_ROOT}/fixtures/spin/full-chain/spin.toml"
public_manifest="${REPO_ROOT}/fixtures/spin/public-stack/spin.toml"
rm -rf \
    "${REPO_ROOT}/fixtures/spin/full-chain/.spin" \
    "${REPO_ROOT}/fixtures/spin/public-stack/.spin"
policy_pid=""
spin_pid=""
cleanup() {
    [[ -n "${spin_pid}" ]] && kill "${spin_pid}" >/dev/null 2>&1 || true
    [[ -n "${policy_pid}" ]] && kill "${policy_pid}" >/dev/null 2>&1 || true
    wait "${spin_pid}" >/dev/null 2>&1 || true
    wait "${policy_pid}" >/dev/null 2>&1 || true
    rm -rf "${temporary_directory}"
}
trap cleanup EXIT

python3 "${REPO_ROOT}/scripts/check-spin-fixtures.py"
python3 "${REPO_ROOT}/scripts/audit-spin-manifest.py" "${full_manifest}"

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

"${spin_bin}" up \
    --from "${full_manifest}" \
    --listen "${app_address}" \
    >"${temporary_directory}/spin.log" 2>&1 &
spin_pid=$!

ready=false
for _ in $(seq 1 150); do
    status="$(curl --silent --max-time 1 --output /dev/null --write-out '%{http_code}' "http://${app_address}/" || true)"
    if [[ "${status}" != "000" ]]; then
        ready=true
        break
    fi
    if ! kill -0 "${spin_pid}" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
if [[ "${ready}" != "true" ]]; then
    echo "error: pinned Spin E2E service did not become ready" >&2
    cat "${temporary_directory}/policy.log" >&2
    cat "${temporary_directory}/spin.log" >&2
    exit 1
fi

if ! bash "${REPO_ROOT}/scripts/exercise-http-contract.sh" "http://${app_address}"; then
    cat "${temporary_directory}/policy.log" >&2
    cat "${temporary_directory}/spin.log" >&2
    exit 1
fi
assert_logs_do_not_contain_secrets \
    "${temporary_directory}/policy.log" \
    "${temporary_directory}/spin.log" \
    "${REPO_ROOT}/fixtures/spin/full-chain/.spin/logs/application_stderr.txt"
assert_log_occurrences \
    115 \
    "wasi-http-middleware-test: terminal-invocation" \
    "${REPO_ROOT}/fixtures/spin/full-chain/.spin/logs/application_stderr.txt"

kill "${spin_pid}" >/dev/null 2>&1 || true
wait "${spin_pid}" >/dev/null 2>&1 || true
spin_pid=""

"${spin_bin}" up \
    --from "${public_manifest}" \
    --listen "${app_address}" \
    >"${temporary_directory}/public-spin.log" 2>&1 &
spin_pid=$!

ready=false
for _ in $(seq 1 150); do
    status="$(curl --silent --max-time 1 --output /dev/null --write-out '%{http_code}' "http://${app_address}/" || true)"
    if [[ "${status}" != "000" ]]; then
        ready=true
        break
    fi
    if ! kill -0 "${spin_pid}" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
if [[ "${ready}" != "true" ]]; then
    echo "error: second Spin fixture did not become ready" >&2
    cat "${temporary_directory}/public-spin.log" >&2
    exit 1
fi

public_headers="${temporary_directory}/public-headers"
public_body="${temporary_directory}/public-body"
status="$(curl --silent --show-error --max-time 10 \
    --output "${public_body}" \
    --dump-header "${public_headers}" \
    --write-out '%{http_code}' \
    --header 'x-wasi-test-count: 1' \
    --header 'Origin: https://public.example' \
    "http://${app_address}/")"
if [[ "${status}" != "200" ]] \
    || ! grep -Eiq '^access-control-allow-origin:[[:space:]]*https://public\.example[[:space:]]*\r?$' "${public_headers}" \
    || ! grep -Eiq '^x-request-id:[[:space:]]*[A-Za-z0-9._:/-]{1,128}[[:space:]]*\r?$' "${public_headers}" \
    || ! grep -Eiq '^x-content-type-options:[[:space:]]*nosniff[[:space:]]*\r?$' "${public_headers}"; then
    echo "error: public Spin fixture did not apply its isolated stack" >&2
    cat "${public_headers}" >&2
    exit 1
fi

status="$(curl --silent --show-error --max-time 10 \
    --output "${public_body}" \
    --dump-header "${public_headers}" \
    --write-out '%{http_code}' \
    --header 'Origin: https://app.example' \
    "http://${app_address}/")"
if [[ "${status}" != "403" ]] \
    || ! grep -Eiq '^vary:[[:space:]]*Origin[[:space:]]*\r?$' "${public_headers}"; then
    echo "error: public Spin fixture leaked configuration from the full-chain project" >&2
    cat "${public_headers}" >&2
    exit 1
fi

status="$(curl --silent --show-error --max-time 10 \
    --request OPTIONS \
    --output "${public_body}" \
    --write-out '%{http_code}' \
    --header 'Origin: https://public.example' \
    --header 'Access-Control-Request-Method: GET' \
    "http://${app_address}/")"
if [[ "${status}" != "204" ]]; then
    echo "error: public Spin fixture preflight did not short-circuit" >&2
    exit 1
fi

assert_logs_do_not_contain_secrets "${temporary_directory}/public-spin.log"
assert_log_occurrences \
    1 \
    "wasi-http-middleware-test: terminal-invocation" \
    "${REPO_ROOT}/fixtures/spin/public-stack/.spin/logs/application_stderr.txt"

echo "Spin ${spin_revision} middleware E2E passed for two reusable projects"
