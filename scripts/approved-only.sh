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
# ic-cli is not built: it is a tool that offers every algorithm, and has no
# approved-only form.
#
# In its own script so that scripts/check.sh and CI run the same steps.

set -euo pipefail

: "${CARGO_TARGET_DIR:=target}"
export CARGO_TARGET_DIR="$CARGO_TARGET_DIR/approved-only"
export RUSTFLAGS="${RUSTFLAGS:-} --cfg ic_approved_only"
export RUSTDOCFLAGS="${RUSTDOCFLAGS:-} --cfg ic_approved_only"

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
