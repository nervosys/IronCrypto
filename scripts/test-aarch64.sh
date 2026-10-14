#!/usr/bin/env bash
#
# Run the ARMv8 backends' tests on an x86-64 Linux host, under QEMU user-mode
# emulation.
#
# The AES, PMULL GHASH, SHA-256 and SHA-512 backends behind the
# `aarch64-crypto` feature cannot execute on x86-64, and the arm64 CI job is
# blocked with the rest of CI (docs/CI.md). This runs their differential tests,
# and the facade's vector suites, on `qemu-aarch64 -cpu max`, which implements
# FEAT_AES, FEAT_PMULL, FEAT_SHA256 and FEAT_SHA512.
#
# What this establishes: the kernels compute what the portable code computes,
# with the instructions as QEMU models them. What it does not: anything about
# speed (emulated timings mean nothing), or behaviour on a real core. Run it on
# arm64 hardware when there is some.
#
# Needs, all installable without root:
#   - qemu-aarch64 on PATH, or QEMU_AARCH64 naming it. Debian's `qemu-user`
#     package ships a static one; `apt-get download qemu-user && dpkg -x
#     qemu-user_*.deb ~/qemu` puts it in ~/qemu/usr/bin.
#   - rustup target add aarch64-unknown-linux-musl
#   - nothing else: the musl target links statically with rust-lld, which
#     ships with the toolchain, so no cross gcc and no sysroot.
#
# Usage:
#   scripts/test-aarch64.sh            # the backends' crates, then the facade
#   scripts/test-aarch64.sh --quick    # the backends' crates only
#
# It fails if any backend test reports that it skipped for want of the
# instructions: a pass that never reached the backend is not a pass.

set -euo pipefail

quick=0
if [ "${1:-}" = "--quick" ]; then
    quick=1
fi

cd "$(dirname "${BASH_SOURCE[0]}")/.."

target=aarch64-unknown-linux-musl
qemu="${QEMU_AARCH64:-qemu-aarch64}"
if ! command -v "$qemu" >/dev/null 2>&1; then
    echo "qemu-aarch64 not found; set QEMU_AARCH64 or put it on PATH (see this script's header)" >&2
    exit 1
fi
if ! rustup target list --installed 2>/dev/null | grep -qx "$target"; then
    echo "$target not installed; rustup target add $target" >&2
    exit 1
fi

: "${CARGO_TARGET_DIR:=target/aarch64-qemu}"
export CARGO_TARGET_DIR
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUNNER="$qemu -cpu max"

log="$(mktemp)"
trap 'rm -f "$log"' EXIT

printf '\n=== backends: ic-core, ic-hash, ic-cipher, ic-ontology ===\n'
cargo test --target "$target" -p ic-core -p ic-hash -p ic-cipher -p ic-ontology \
    --features ic-cipher/aarch64-crypto,ic-hash/aarch64-crypto \
    -- --nocapture 2>&1 | tee "$log"

# The tests skip, with a message, where the CPU lacks the instructions. Under
# -cpu max it has them all, so a skip here means the backend never ran.
if grep -E "not exercised|extension not available|skipping" "$log"; then
    echo "a backend test skipped; the ARM kernels were not exercised" >&2
    exit 1
fi
for want in "aes Armv8, ghash carry-less" "sha-256 backend: ARMv8 SHA2; sha-512 backend: ARMv8 SHA512"; do
    if ! grep -qF "$want" "$log"; then
        echo "expected the report \"$want\"; the ARM backends were not selected" >&2
        exit 1
    fi
done

if [ "$quick" -eq 1 ]; then
    printf '\naarch64 backends passed under QEMU (facade skipped)\n'
    exit 0
fi

printf '\n=== facade: ironcrypto, with the vector suites ===\n'
# Release, because the facade's suites -- RSA, SLH-DSA, the KDFs -- are slow
# enough emulated in a debug build to be impractical.
cargo test --release --target "$target" -p ironcrypto --features aarch64-crypto

printf '\naarch64 backends and facade passed under QEMU\n'
