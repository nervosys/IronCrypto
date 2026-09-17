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

step() {
    printf '\n=== %s ===\n' "$1"
}

step "formatting"
cargo fmt --all --check

step "clippy"
# -D warnings is the point. Without it clippy reports problems and exits zero,
# so a warning lands on master and nobody finds out. CI omitted this for a long
# time while every local run included it, which is the worst of both: the rule
# was enforced by habit rather than by the build.
cargo clippy --workspace --all-targets --all-features -- -D warnings

step "tests"
cargo test --workspace --all-features

step "zero third-party dependencies"
# In its own script, because CI needs the same check and the two copies that
# used to exist drifted apart. See scripts/no-third-party.sh.
"$(dirname "${BASH_SOURCE[0]}")/no-third-party.sh"

if [ "$quick" -eq 1 ]; then
    printf '\nquick check passed (cross-compilation skipped)\n'
    exit 0
fi

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
        cargo build -p iron-crypto --no-default-features --target "$target"
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
# The ARM AES backend is off by default and had never been compiled anywhere.
# A library crate produces an rlib, so this needs no linker and no Apple SDK --
# any machine with the target installed can check that the intrinsics at least
# build.
#
# Compiling is not running. What argues these are correct is the software model
# in crates/ic-cipher/src/aes/armv8_model.rs, which is what caught the
# decryption key schedule being wrong. CI runs the tests for real on
# macos-latest, which is arm64.
if rustup target list --installed 2>/dev/null | grep -qx aarch64-apple-darwin; then
    cargo build -p ic-cipher --target aarch64-apple-darwin --features aarch64-crypto
else
    echo "aarch64-apple-darwin not installed; the ARM backend was NOT compiled"
    echo "install with: rustup target add aarch64-apple-darwin"
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
