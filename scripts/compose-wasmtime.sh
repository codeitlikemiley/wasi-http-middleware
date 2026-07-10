#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

wac_version="$(compat_value wac)"
wasm_tools_version="$(compat_value wasm_tools)"
wasi_http_version="$(compat_value wasi_http)"
require_version wac "${wac_version}"
require_version wasm-tools "${wasm_tools_version}"

terminal="${1:-$(test_component_file echo-service)}"
output="${2:-${ARTIFACT_ROOT}/composed/full-chain.wasm}"
require_file "${terminal}"
for component in "${COMPONENTS[@]}"; do
    require_file "$(component_file "${component}")"
done

mkdir -p "$(dirname "${output}")"
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/wasi-http-compose.XXXXXX")"
trap 'rm -rf "${temporary_directory}"' EXIT

current="${terminal}"
stage=0
for component in auth-policy cors security-headers request-id; do
    stage=$((stage + 1))
    next="${temporary_directory}/stage-${stage}.wasm"
    wac plug \
        --plug "${current}" \
        "$(component_file "${component}")" \
        --output "${next}"
    current="${next}"
done

wasm-tools validate --features component-model,cm-async "${current}"
report="${temporary_directory}/composed.wit"
wasm-tools component wit "${current}" >"${report}"
handler="wasi:http/handler@${wasi_http_version}"
grep -Fqx "  export ${handler};" "${report}" || {
    echo "error: composed component does not export ${handler}" >&2
    exit 1
}
if grep -Fqx "  import ${handler};" "${report}"; then
    echo "error: composed component still imports ${handler}" >&2
    exit 1
fi

cp "${current}" "${output}"
echo "wrote composed service to ${output}"
