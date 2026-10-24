#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

version="$(compat_value spin_release)"
destination="${REPO_ROOT}/target/tools/spin-${version}"
binary="${destination}/spin"
archive="${destination}/spin-v${version}-linux-amd64.tar.gz"
url="https://github.com/spinframework/spin/releases/download/v${version}/spin-v${version}-linux-amd64.tar.gz"

if [[ -x "${binary}" ]] && "${binary}" --version 2>&1 | grep -Fq "${version}"; then
    printf '%s\n' "${binary}"
    exit 0
fi

mkdir -p "${destination}"
curl --fail --silent --show-error --location --output "${archive}" "${url}"
tar -xzf "${archive}" -C "${destination}" spin
chmod 0755 "${binary}"
"${binary}" --version 2>&1 | grep -Fq "${version}"
printf '%s\n' "${binary}"
