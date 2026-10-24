#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

wasm_tools_version="$(compat_value wasm_tools)"
wasi_http_version="$(compat_value wasi_http)"
wasm_tools_bin="$(resolve_pinned_tool WASM_TOOLS_BIN wasm-tools "${wasm_tools_version}")"
require_command python3

python3 "${REPO_ROOT}/scripts/test_audit_spin_manifest.py"
python3 "${REPO_ROOT}/scripts/check-spin-fixtures.py"

mkdir -p "${REPORT_ROOT}/wit"
rm -f "${REPORT_ROOT}/wit/"*.wit

fail_contract() {
    local component="$1"
    local message="$2"
    echo "error: ${component}: ${message}" >&2
    return 1
}

check_handler_contract() {
    local component="$1"
    local report="$2"
    local handler="wasi:http/handler@${wasi_http_version}"

    grep -Fqx "  import ${handler};" "${report}" \
        || fail_contract "${component}" "missing imported ${handler}"
    grep -Fqx "  export ${handler};" "${report}" \
        || fail_contract "${component}" "missing exported ${handler}"

    local handler_edges
    handler_edges="$(grep -Ec '^[[:space:]]+(import|export) wasi:http/handler@' "${report}")"
    [[ "${handler_edges}" == "2" ]] \
        || fail_contract "${component}" "expected exactly one handler import and export"
}

check_forbidden_capabilities() {
    local component="$1"
    local report="$2"
    local forbidden='^[[:space:]]+import (wasi:filesystem/|wasi:keyvalue/|wasi:sockets/|fermyon:spin/(key-value|sqlite|mysql|postgres|redis|mqtt)|spin:(key-value|sqlite|mysql|postgres|redis|mqtt)/)'
    if grep -Eq "${forbidden}" "${report}"; then
        grep -E "${forbidden}" "${report}" >&2
        fail_contract "${component}" "imports an undeclared persistent-data or raw-network capability"
    fi
}

check_component_capabilities() {
    local component="$1"
    local report="$2"
    local environment="wasi:cli/environment@${wasi_http_version}"
    local client="wasi:http/client@${wasi_http_version}"

    case "${component}" in
        passthrough|request-id|security-headers)
            if grep -Eq "^[[:space:]]+import (${environment}|${client});" "${report}"; then
                fail_contract "${component}" "must not import environment or outbound HTTP"
            fi
            ;;
        cors)
            grep -Fqx "  import ${environment};" "${report}" \
                || fail_contract "${component}" "must import only its environment configuration"
            if grep -Fqx "  import ${client};" "${report}"; then
                fail_contract "${component}" "must not import outbound HTTP"
            fi
            ;;
        authn-policy|secure-defaults)
            grep -Fqx "  import ${environment};" "${report}" \
                || fail_contract "${component}" "must import environment configuration"
            grep -Fqx "  import ${client};" "${report}" \
                || fail_contract "${component}" "must import the WASIp3 HTTP client"
            ;;
        *)
            fail_contract "${component}" "unknown component policy"
            ;;
    esac
}

# `wasm32-wasip2` links the Rust/WASIp3 adapter. wasip3 0.9 emits that
# adapter at WASI 0.2.12. Those imports are not middleware policy imports.
adapter_imports() {
    local adapter="$1"
    cat <<EOF
wasi:cli/environment@${adapter}
wasi:cli/exit@${adapter}
wasi:cli/stderr@${adapter}
wasi:cli/stdin@${adapter}
wasi:cli/stdout@${adapter}
wasi:cli/terminal-input@${adapter}
wasi:cli/terminal-output@${adapter}
wasi:cli/terminal-stderr@${adapter}
wasi:cli/terminal-stdin@${adapter}
wasi:cli/terminal-stdout@${adapter}
wasi:clocks/monotonic-clock@${adapter}
wasi:io/error@${adapter}
wasi:io/poll@${adapter}
wasi:io/streams@${adapter}
EOF
}

check_exact_imports() {
    local component="$1"
    local report="$2"
    local expected="${report}.expected-imports"
    local actual="${report}.actual-imports"
    local adapter
    adapter="$(compat_value wasi_p2_adapter)"

    grep -E '^[[:space:]]+import ' "${report}" | sed -E 's/^[[:space:]]+import //; s/;$//' | LC_ALL=C sort >"${actual}"
    adapter_imports "${adapter}" >"${expected}"
    case "${component}" in
        passthrough|security-headers)
            cat >>"${expected}" <<EOF
wasi:http/handler@${wasi_http_version}
wasi:http/types@${wasi_http_version}
EOF
            ;;
        request-id)
            cat >>"${expected}" <<EOF
wasi:http/handler@${wasi_http_version}
wasi:http/types@${wasi_http_version}
wasi:random/random@${wasi_http_version}
EOF
            ;;
        cors)
            cat >>"${expected}" <<EOF
wasi:cli/environment@${wasi_http_version}
wasi:http/handler@${wasi_http_version}
wasi:http/types@${wasi_http_version}
wasi:random/insecure-seed@${adapter}
EOF
            ;;
        authn-policy|secure-defaults)
            cat >>"${expected}" <<EOF
wasi:cli/environment@${wasi_http_version}
wasi:clocks/monotonic-clock@${wasi_http_version}
wasi:clocks/types@${wasi_http_version}
wasi:http/client@${wasi_http_version}
wasi:http/handler@${wasi_http_version}
wasi:http/types@${wasi_http_version}
wasi:random/insecure-seed@${adapter}
wasi:random/random@${wasi_http_version}
EOF
            ;;
        *)
            fail_contract "${component}" "unknown exact import policy"
            ;;
    esac
    LC_ALL=C sort -o "${expected}" "${expected}"
    if ! diff -u "${expected}" "${actual}"; then
        rm -f "${expected}" "${actual}"
        fail_contract "${component}" "component imports differ from the exact allowlist"
    fi
    rm -f "${expected}" "${actual}"
}

for component in "${COMPONENTS[@]}" "${CONFORMANCE_COMPONENTS[@]}"; do
    if [[ "${component}" == "passthrough" ]]; then
        artifact="$(test_component_file "${component}")"
    else
        artifact="$(component_file "${component}")"
    fi
    report="${REPORT_ROOT}/wit/${component}.wit"
    require_file "${artifact}"

    "${wasm_tools_bin}" validate --features component-model,cm-async "${artifact}"
    temporary_report="${report}.tmp"
    "${wasm_tools_bin}" component wit "${artifact}" >"${temporary_report}"
    mv "${temporary_report}" "${report}"

    check_handler_contract "${component}" "${report}"
    check_forbidden_capabilities "${component}" "${report}"
    check_component_capabilities "${component}" "${report}"
    check_exact_imports "${component}" "${report}"
done

echo "validated production and conformance middleware component contracts"
