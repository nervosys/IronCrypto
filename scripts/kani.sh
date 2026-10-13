#!/usr/bin/env bash
#
# Run the Kani proofs: every crate that has them, or the arguments given.
#
#   scripts/kani.sh               # all
#   scripts/kani.sh -p ic-core    # one crate
#
# Needs cargo-kani (cargo install --locked kani-verifier && cargo kani setup),
# which runs on Linux. See docs/PROOFS.md for what is proved.

set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
if [ $# -eq 0 ]; then
    set -- -p ic-core -p ic-ec -p ic-mldsa
fi
cargo kani "$@"
