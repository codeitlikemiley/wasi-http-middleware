#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

version="$(compat_value spin_release)"
echo "error: building a Spin fork is not a host for this repository." >&2
echo "Use the official spinframework/spin v${version} linux-amd64 release:" >&2
echo "  bash scripts/bootstrap-spin-release.sh" >&2
exit 2
