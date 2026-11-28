#!/bin/bash
set -euo pipefail

CDPATH= cd -- "$(dirname -- "$0")/.."

target=$(rustc -vV | sed -n 's/^host: //p')
case "$target" in
    aarch64-apple-darwin | x86_64-apple-darwin) ;;
    *)
        printf 'A macOS Rust toolchain is required (host: %s).\n' "$target" >&2
        exit 1
        ;;
esac

OPENSSL_DIR=$(python3 scripts/build-openssl.py "$target")
export OPENSSL_DIR OPENSSL_STATIC=1 OPENSSL_NO_VENDOR=1

exec cargo build --locked --release -p tzap --bin tzap
