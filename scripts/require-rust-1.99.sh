#!/usr/bin/env bash

# The quality gate is Rust 1.99.0. Current stable is 1.99.1, and its
# rustfmt and clippy are not the same tools. `rust-toolchain.toml` selects
# 1.99.0 inside this repository; this check fails the job if that override
# is missing and Cargo would use stable instead.

set -euo pipefail

rustc --version
active="$(rustup show active-toolchain)"
printf '%s\n' "${active}"
case "${active}" in
    1.99.0-*) ;;
    *)
        echo "expected Rust 1.99.0; refusing current stable" >&2
        exit 1
        ;;
esac

if command -v rustfmt >/dev/null 2>&1; then
    rustfmt --version
    compiler_commit="$(rustc --version | sed -n 's/.*(\([0-9a-f]\{9\}\).*/\1/p')"
    if [[ -z "${compiler_commit}" ]] || ! rustfmt --version | grep -Fq "${compiler_commit}"; then
        echo "rustfmt is not the rustfmt shipped with this Rust 1.99.0 compiler" >&2
        exit 1
    fi
fi
