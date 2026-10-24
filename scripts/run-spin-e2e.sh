#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

profile="${SPIN_COMPAT_PROFILE:-release-composed}"
if [[ -z "${SPIN_BIN:-}" ]]; then
    spin_bin="$(bash "${REPO_ROOT}/scripts/bootstrap-spin-release.sh")"
else
    spin_bin="${SPIN_BIN}"
fi
require_command "${spin_bin}"
spin_version="$("${spin_bin}" --version 2>&1)"
expected_version="$(compat_value spin_release)"
wasmtime_version="$(compat_value wasmtime)"
wasmtime_bin="$(resolve_pinned_tool WASMTIME_BIN wasmtime "${wasmtime_version}")"
require_command curl

python3 "${REPO_ROOT}/scripts/check-spin-fixtures.py"
bash "${REPO_ROOT}/scripts/build-components.sh"

case "${profile}" in
    release-composed)
        manifest="${REPO_ROOT}/fixtures/spin/composed-final/spin.toml"
        bash "${REPO_ROOT}/scripts/compose-wasmtime.sh" \
            "$(test_component_file echo-service)" \
            "${ARTIFACT_ROOT}/composed/full-chain.wasm"
        ;;
    release-native)
        manifest="${REPO_ROOT}/fixtures/spin/full-chain/spin.toml"
        ;;
    *)
        echo "error: unknown SPIN_COMPAT_PROFILE: ${profile}" >&2
        echo "expected release-composed or release-native" >&2
        exit 2
        ;;
esac

if [[ "${spin_version}" != *"${expected_version}"* ]]; then
    echo "SKIP: expected Spin ${expected_version}; found ${spin_version}" >&2
    exit 77
fi

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/wasi-http-spin.XXXXXX")"
spin_pid=""
policy_pid=""
cleanup() {
    [[ -n "${spin_pid}" ]] && kill "${spin_pid}" >/dev/null 2>&1 || true
    [[ -n "${policy_pid}" ]] && kill "${policy_pid}" >/dev/null 2>&1 || true
    [[ -n "${spin_pid}" ]] && wait "${spin_pid}" >/dev/null 2>&1 || true
    [[ -n "${policy_pid}" ]] && wait "${policy_pid}" >/dev/null 2>&1 || true
    rm -rf "${temporary_directory}"
}
trap cleanup EXIT
rm -rf "$(dirname "${manifest}")/.spin"
port="${E2E_SPIN_PORT:-19100}"
policy_port="${E2E_POLICY_PORT:-19101}"
policy_url="http://127.0.0.1:${policy_port}/authenticate"

"${wasmtime_bin}" serve \
    -W component-model-async=y \
    -S p3=y \
    -S cli=y \
    -S http=y \
    --addr "127.0.0.1:${policy_port}" \
    "$(test_component_file mock-authn-broker)" \
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
    echo "error: mock authentication broker did not become ready" >&2
    cat "${temporary_directory}/policy.log" >&2
    exit 1
fi

"${spin_bin}" up \
    --from "${manifest}" \
    --listen "127.0.0.1:${port}" \
    --state-dir "${temporary_directory}/state" \
    >"${temporary_directory}/spin.log" 2>&1 &
spin_pid=$!

base_url="http://127.0.0.1:${port}"
ready=false
status="000"
for _ in $(seq 1 200); do
    if ! kill -0 "${spin_pid}" >/dev/null 2>&1; then
        cat "${temporary_directory}/spin.log" >&2
        echo "error: Spin exited before readiness" >&2
        exit 1
    fi
    status="$(curl --silent --output /dev/null --write-out '%{http_code}' "${base_url}/" || true)"
    if [[ "${status}" == "401" ]]; then
        ready=true
        break
    fi
    sleep 0.05
done
if [[ "${ready}" != "true" ]]; then
    cat "${temporary_directory}/spin.log" >&2
    echo "error: Spin ${profile} did not serve required-auth HTTP 401 (last status ${status})" >&2
    exit 1
fi

if ! STREAM_FAILURE_REPEATS="${STREAM_FAILURE_REPEATS:-25}" \
    IMMEDIATE_FAILURE_REPEATS="${IMMEDIATE_FAILURE_REPEATS:-25}" \
    bash "${REPO_ROOT}/scripts/exercise-http-contract.sh" "${base_url}"; then
    cat "${temporary_directory}/spin.log" >&2
    cat "${temporary_directory}/policy.log" >&2
    exit 1
fi

h2_header="${temporary_directory}/trailers-h2.headers"
h2_body="${temporary_directory}/trailers-h2.body"
h2_status="$(curl --silent --show-error --max-time 10 \
    --http2-prior-knowledge \
    --dump-header "${h2_header}" \
    --output "${h2_body}" \
    --write-out '%{http_code}' \
    --header 'Authorization: Bearer allow' \
    "${base_url}/trailers")"
if [[ "${h2_status}" != "200" || "$(cat "${h2_body}")" != "body with trailer" ]]; then
    echo "error: HTTP/2 trailer request lost its body (status ${h2_status})" >&2
    cat "${h2_header}" >&2
    exit 1
fi
if ! grep -Eiq '^x-echo-trailer:[[:space:]]*preserved' "${h2_header}"; then
    echo "error: HTTP/2 did not write x-echo-trailer" >&2
    cat "${h2_header}" >&2
    exit 1
fi

assert_logs_do_not_contain_secrets \
    "${temporary_directory}/spin.log" \
    "${temporary_directory}/policy.log"
echo "Spin ${expected_version} ${profile} passed"
