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
    set -- -p ic-core -p ic-ec -p ic-mldsa -p ic-mlkem
fi
# Function contracts (`proof_for_contract`, `stub_verified`) and the stubbing
# they use are unstable in Kani 0.68, so both flags are passed for every crate.
# Some ic-ec proofs name Bitwuzla as their solver; it must be on PATH.
#
# --no-assert-contracts: a plain `#[kani::proof]` does not also check the
# contracts of the functions it calls. Every contract is checked by its own
# `proof_for_contract` harness regardless. P-256's schoolbook harnesses need
# it: they replace the multiplication inside `mac` with an arbitrary product,
# so `mac` does not meet its contract there, by design (docs/PROOFS.md, "The
# products").
cargo kani -Z function-contracts -Z stubbing --no-assert-contracts "$@"
