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
# The hook in .githooks/pre-commit runs the quick form. CI runs the full form,
# and the two are kept identical on purpose: a local check that gates on less
# than CI trains people to push and find out.

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
# The claim the SBOM, CWE-1104 and T1195.001 all rest on. Asserted here rather
# than trusted, because it is the kind of thing a single convenient `cargo add`
# would quietly end.
external=$(cargo tree --workspace --edges normal,build --prefix none 2>/dev/null \
    | awk '{print $1}' \
    | grep -v '^$' \
    | grep -vE '^(ic-[a-z0-9]+|iron-crypto)$' \
    | sort -u || true)
if [ -n "$external" ]; then
    echo "third-party crates found:"
    echo "$external"
    exit 1
fi
echo "none"

if [ "$quick" -eq 1 ]; then
    printf '\nquick check passed (cross-compilation skipped)\n'
    exit 0
fi

step "no_std cross-compilation"
for target in thumbv7em-none-eabihf thumbv6m-none-eabi riscv32imac-unknown-none-elf; do
    if rustup target list --installed 2>/dev/null | grep -qx "$target"; then
        echo "-- $target"
        cargo build -p iron-crypto --no-default-features --target "$target"
    else
        echo "-- $target (not installed, skipped)"
    fi
done

step "docs"
cargo doc --workspace --no-deps --all-features

printf '\nall checks passed\n'
