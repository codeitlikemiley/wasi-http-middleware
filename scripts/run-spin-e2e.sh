#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

spin_bin="${SPIN_BIN:-spin}"
profile="${SPIN_COMPAT_PROFILE:-stable-final}"
if ! command -v "${spin_bin}" >/dev/null 2>&1; then
    echo "SKIP: Spin compatibility canary binary is unavailable" >&2
    exit 77
fi
spin_version="$(${spin_bin} --version 2>&1 || true)"

python3 "${REPO_ROOT}/scripts/check-spin-fixtures.py"
python3 "${REPO_ROOT}/scripts/audit-spin-manifest.py" \
    "${REPO_ROOT}/fixtures/spin/full-chain/spin.toml"

case "${profile}" in
    stable-final)
        expected_version="$(compat_value spin_stable)"
        manifest="${REPO_ROOT}/fixtures/spin/composed-final/spin.toml"
        expected_error='wasi:http/types@0\.3\.0|resource implementation is missing|failed to instantiate'
        bash "${REPO_ROOT}/scripts/compose-wasmtime.sh" \
            "$(test_component_file echo-service)" \
            "${ARTIFACT_ROOT}/composed/full-chain.wasm"
        ;;
    native-middleware)
        revision="$(compat_value spin_middleware_revision)"
        expected_version="${revision:0:7}"
        manifest="${REPO_ROOT}/fixtures/spin/full-chain/spin.toml"
        expected_error='wasi:http/handler@0\.3\.0|wasi:http/types@0\.3\.0|resource implementation is missing|failed to (compose|instantiate)'
        ;;
    *)
        echo "error: unknown SPIN_COMPAT_PROFILE: ${profile}" >&2
        exit 1
        ;;
esac
if [[ "${spin_version}" != *"${expected_version}"* ]]; then
    echo "SKIP: expected Spin ${expected_version}; found ${spin_version}" >&2
    exit 77
fi

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/wasi-http-spin-canary.XXXXXX")"
spin_pid=""
cleanup() {
    [[ -n "${spin_pid}" ]] && kill "${spin_pid}" >/dev/null 2>&1 || true
    [[ -n "${spin_pid}" ]] && wait "${spin_pid}" >/dev/null 2>&1 || true
    rm -rf "${temporary_directory}"
}
trap cleanup EXIT
rm -rf "$(dirname "${manifest}")/.spin"

"${spin_bin}" up \
    --from "${manifest}" \
    --listen "127.0.0.1:${E2E_SPIN_PORT:-19100}" \
    >"${temporary_directory}/spin.log" 2>&1 &
spin_pid=$!

exited=false
for _ in $(seq 1 100); do
    if ! kill -0 "${spin_pid}" >/dev/null 2>&1; then
        exited=true
        break
    fi
    sleep 0.1
done
if [[ "${exited}" != "true" ]]; then
    echo "error: Spin unexpectedly hosted final WASI 0.3 artifacts" >&2
    cat "${temporary_directory}/spin.log" >&2
    exit 1
fi
set +e
wait "${spin_pid}"
spin_exit=$?
set -e
spin_pid=""
if [[ "${spin_exit}" == "0" ]]; then
    echo "error: Spin compatibility canary unexpectedly succeeded" >&2
    cat "${temporary_directory}/spin.log" >&2
    exit 1
fi
if ! grep -Eiq "${expected_error}" "${temporary_directory}/spin.log"; then
    echo "error: Spin failed for an unexpected reason" >&2
    cat "${temporary_directory}/spin.log" >&2
    exit 1
fi
assert_logs_do_not_contain_secrets "${temporary_directory}/spin.log"

echo "expected incompatibility confirmed: ${profile} cannot host final wasi:http@0.3.0"
