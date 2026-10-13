#!/usr/bin/env bash
#
# The build with only the FIPS-approved algorithms, `--cfg ic_approved_only`.
#
# A cfg rather than a Cargo feature (see ic_core::APPROVED_ONLY), which means
# nothing else in this repository's checks builds it: they all run without the
# flag. So it is checked here, on its own: clippy, the tests, the documentation
# tests -- which include the compile_fail examples in the ironcrypto crate
# documentation that show a non-approved algorithm is absent, not merely
# refused -- and one no_std target.
#
# Its own target directory, because RUSTFLAGS is part of what Cargo fingerprints
# and sharing one would rebuild the workspace on every switch between the two.
#
# Two passes. In that build a primitive refuses until ic_fips::initialize has
# passed the self-tests, and the suites below call primitives directly from
# crates that cannot depend on ic_fips; so the first pass adds
# --cfg ic_startup_gate_off, which turns that gate off and nothing else. The
# second builds without it and runs the tests that show the gate refusing.
#
# ic-cli is not built: it is a tool that offers every algorithm, and has no
# approved-only form.
#
# In its own script so that scripts/check.sh and CI run the same steps.

set -euo pipefail

: "${CARGO_TARGET_DIR:=target}"
base_target="$CARGO_TARGET_DIR"
base_rustflags="${RUSTFLAGS:-}"
base_rustdocflags="${RUSTDOCFLAGS:-}"

export CARGO_TARGET_DIR="$base_target/approved-only"
export RUSTFLAGS="$base_rustflags --cfg ic_approved_only --cfg ic_startup_gate_off"
export RUSTDOCFLAGS="$base_rustdocflags --cfg ic_approved_only --cfg ic_startup_gate_off"

packages=(
    -p ironcrypto -p ic-core -p ic-hash -p ic-mac -p ic-cipher -p ic-kdf -p ic-ec
    -p ic-hpke -p ic-sig -p ic-ontology -p ic-fips -p ic-rustls
)

echo "-- clippy"
cargo clippy "${packages[@]}" --all-targets -- -D warnings

echo "-- tests"
cargo test "${packages[@]}"

target=thumbv7em-none-eabihf
if rustup target list --installed 2>/dev/null | grep -qx "$target"; then
    echo "-- $target"
    cargo build -p ironcrypto --no-default-features --target "$target"
else
    echo "-- $target not installed; the approved-only no_std build was NOT checked"
fi

echo "-- the startup gate, without the test switch"
export CARGO_TARGET_DIR="$base_target/approved-only-gated"
export RUSTFLAGS="$base_rustflags --cfg ic_approved_only"
export RUSTDOCFLAGS="$base_rustdocflags --cfg ic_approved_only"
cargo test -p ic-fips --test startup_gate --test error_state
