#!/usr/bin/env bash
#
# Everything CI gates on, in one command.
#
# The point is that there is exactly one thing to run, and it exits non-zero if
# anything fails. A chain of commands assembled by hand at a prompt can be
# mis-composed -- `a && b; c` runs c whether or not b succeeded -- and that is
# not a hypothetical: it is how a commit that did not compile reached master in
# this repository. One script, `set -e`, no chaining decisions left to whoever
# is typing.
#
# Usage:
#   scripts/check.sh          # everything
#   scripts/check.sh --quick  # skip the cross-compilation, for a tight loop
#
# The hook in .githooks/pre-commit runs the quick form. CI runs the same steps,
# on purpose: a local check that gates on less than CI trains people to push and
# find out.
#
# "The same steps" is kept true by sharing the scripts rather than by copying
# them. CI used to write each one out again, and its copy of the dependency
# check named the workspace crates under the old `ac-` prefix -- so after the
# rename it reported every one of them as a third-party dependency and the job
# failed on every push, which is what two copies of a rule eventually do.

set -euo pipefail

quick=0
if [ "${1:-}" = "--quick" ]; then
    quick=1
fi

# Keep build artifacts out of the way of any parallel work on this machine.
: "${CARGO_TARGET_DIR:=target}"
export CARGO_TARGET_DIR

# qemu-aarch64 may be on PATH under either name (Debian's qemu-user-static
# ships qemu-aarch64-static), or in ~/.local/bin after a no-root install
# (docs/CI.md). Find one, so the ARMv8 step below is not skipped.
if [ -z "${QEMU_AARCH64:-}" ]; then
    for q in qemu-aarch64 qemu-aarch64-static \
        "$HOME/.local/bin/qemu-aarch64" "$HOME/.local/bin/qemu-aarch64-static"; do
        if command -v "$q" >/dev/null 2>&1; then
            QEMU_AARCH64="$q"
            export QEMU_AARCH64
            break
        fi
    done
fi

step() {
    printf '\n=== %s ===\n' "$1"
}

step "formatting"
cargo fmt --all --check
cargo fmt --manifest-path scripts/ct-audit/Cargo.toml --check

step "clippy"
# -D warnings is the point. Without it clippy reports problems and exits zero,
# so a warning lands on master and nobody finds out. CI omitted this for a long
# time while every local run included it, which is the worst of both: the rule
# was enforced by habit rather than by the build.
cargo clippy --workspace --all-targets --all-features -- -D warnings
# And with default features, which is what a dependent builds. Code used only
# by a feature-gated caller, such as the benchmark internals, is dead here, and
# --all-features alone never sees the warning.
cargo clippy --workspace --all-targets -- -D warnings

step "tests"
cargo test --workspace --all-features

step "zero third-party dependencies"
# In its own script, because CI needs the same check and the two copies that
# used to exist drifted apart. See scripts/no-third-party.sh.
"$(dirname "${BASH_SOURCE[0]}")/no-third-party.sh"

step "advisory floors"
# After the dependency check, because it only means anything if that one
# passed: floors on a surface that just grew would be floors on the wrong set.
# Offline -- it compares compiled versions against a table -- so it can gate a
# commit. `cargo audit` runs too when installed and gates on a vulnerability in
# a crate the build compiles; an advisory database that cannot be fetched is
# only a warning, so the check still runs offline. See scripts/advisories.sh.
"$(dirname "${BASH_SOURCE[0]}")/advisories.sh"

if [ "$quick" -eq 1 ]; then
    printf '\nquick check passed (cross-compilation skipped)\n'
    exit 0
fi

step "declared minimum Rust version"
# Cargo.toml's rust-version is a promise to every dependent, and nothing checked
# it: it said 1.75 while the SIMD backends needed 1.87. Build the workspace with
# exactly that toolchain, in its own target directory so its artefacts do not
# mix with the current compiler's.
msrv="$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml)"
if [ -z "$msrv" ]; then
    echo "rust-version not found in Cargo.toml" >&2
    exit 1
fi
if rustup toolchain list 2>/dev/null | grep -q "^$msrv[-.]"; then
    echo "-- $msrv"
    CARGO_TARGET_DIR="$CARGO_TARGET_DIR/msrv-$msrv" cargo "+$msrv" check --workspace --all-targets
else
    printf '\nrust-version %s: NOT CHECKED, toolchain not installed.\n' "$msrv"
    printf 'install with `rustup toolchain install %s --profile minimal`\n' "$msrv"
fi

step "approved-only build"
# The same crates built with --cfg ic_approved_only, which nothing above
# builds. See scripts/approved-only.sh.
"$(dirname "${BASH_SOURCE[0]}")/approved-only.sh"

step "compiled-code constant-time probes"
# Fail if a required target is absent: a skipped probe is not verification.
# Its five: rustup target add x86_64-unknown-linux-gnu thumbv6m-none-eabi
# thumbv7em-none-eabihf riscv32imac-unknown-none-elf aarch64-unknown-linux-gnu
# The isolated harness uses LTO over the real library implementations.
python scripts/test-check-ct.py
python scripts/check-ct.py

step "no_std cross-compilation"
# The same four CI builds. `wasm32-unknown-unknown` used to be in CI's list and
# not here, so it was never cross-compiled locally -- which mattered the moment
# CI stopped running.
#
# A --no-default-features build on a host with std proves nothing; these targets
# have no std at all, so they are the real check.
skipped=""
built=0
for target in thumbv7em-none-eabihf thumbv6m-none-eabi riscv32imac-unknown-none-elf wasm32-unknown-unknown; do
    if rustup target list --installed 2>/dev/null | grep -qx "$target"; then
        echo "-- $target"
        cargo build -p ironcrypto --no-default-features --target "$target"
        built=$((built + 1))
    else
        echo "-- $target (not installed)"
        skipped="$skipped $target"
    fi
done

if [ -n "$skipped" ]; then
    # Said plainly rather than buried, because "checks passed" after building
    # none of them is the kind of pass that teaches people to trust a gate that
    # did nothing. Install with: rustup target add <target>
    printf '\nno_std: built %d of 4. NOT CHECKED:%s\n' "$built" "$skipped"
    printf 'no_std: install with `rustup target add%s`\n' "$skipped"
fi

step "aarch64 crypto extensions"
# The ARM AES, PMULL GHASH and SHA-2 backends are off by default. A library
# crate produces an rlib, so this needs no linker and no Apple SDK -- any
# machine with the target installed can check that the intrinsics at least
# build.
#
# Compiling is not running. The software models (aes/armv8_model.rs,
# armv8_ghash_model.rs, sha2/armv8_model.rs) check the structure on every host;
# the first caught the AES decryption key schedule being wrong. What executes
# the instructions is scripts/test-aarch64.sh under QEMU, run below where it
# can be, and CI's arm64 job on macos-latest.
if rustup target list --installed 2>/dev/null | grep -qx aarch64-apple-darwin; then
    cargo build -p ic-cipher -p ic-hash --target aarch64-apple-darwin \
        --features ic-cipher/aarch64-crypto,ic-hash/aarch64-crypto
else
    echo "aarch64-apple-darwin not installed; the ARM backends were NOT compiled"
    echo "install with: rustup target add aarch64-apple-darwin"
fi
if [ "$(uname -s)" = "Linux" ] && command -v "${QEMU_AARCH64:-qemu-aarch64}" >/dev/null 2>&1 \
    && rustup target list --installed 2>/dev/null | grep -qx aarch64-unknown-linux-musl; then
    "$(dirname "${BASH_SOURCE[0]}")/test-aarch64.sh" --quick
else
    echo "qemu-aarch64 or aarch64-unknown-linux-musl absent; the ARM backends were NOT run here"
    echo "see scripts/test-aarch64.sh"
fi

step "docs"
# RUSTDOCFLAGS, or a broken intra-doc link is a warning here and an error in CI.
# Nine of them had accumulated exactly that way: warnings locally, errors in a
# CI job that was not running, so neither was ever read.
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

if [ -n "$skipped" ]; then
    printf '\nall checks passed, except the no_std targets listed above\n'
else
    printf '\nall checks passed\n'
fi
