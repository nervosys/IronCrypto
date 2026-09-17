# Contributing to IronCrypto

Thank you for your interest in contributing! We welcome contributions from the community.

## Before you commit

```sh
scripts/check.sh            # everything CI gates on
scripts/check.sh --quick    # skips cross-compilation, for a tight loop
```

One script rather than a chain of commands, because a chain assembled at a
prompt can be mis-composed. `a && b; c` runs `c` whether or not `b` succeeded,
and that is not hypothetical — it is how a commit that did not compile reached
master in this repository. The script uses `set -e`, so there is no composition
decision left to whoever is typing.

Enable the hook to have it run automatically:

```sh
git config core.hooksPath .githooks
```

It runs the quick form and refuses a commit that fails. `git commit --no-verify`
skips it once. That escape hatch is deliberate: a hook nobody can bypass gets
disabled entirely the first time someone needs to commit a work in progress, and
then it protects nothing. Using it should be a decision, not a habit.

The local check and CI gate on the same things on purpose. A local check that
covers less trains people to push and find out.

## Contributor License Agreement (CLA)

Before your contribution can be accepted, you must agree to our
[Contributor License Agreement](CLA.md). By submitting a pull request, you
indicate your agreement to the CLA terms.

**Why a CLA?** IronCrypto is dual-licensed under the AGPL v3 (open source)
and a commercial license. The CLA ensures that contributions can be distributed
under both licenses, enabling the project to remain sustainable while staying
open source.

## Getting Started

1. **Fork** the repository and create a feature branch from `master`.
2. **Build** with `cargo build --workspace`.
3. **Test** with `cargo test --workspace`.
4. **Lint** — zero warnings is the standard (`cargo clippy --workspace --all-targets`).
5. **Format** with `cargo fmt --all`.

## Rules specific to this project

These are not style preferences; a change that breaks one of them will be sent
back regardless of how good the rest of it is.

### Zero dependencies

Do not add a crate to any `Cargo.toml` under `crates/`. The workspace depends on
nothing outside itself — no `serde`, no `zeroize`, no C, no build scripts. JSON,
hex, base64, and secret erasure are already implemented here. CI enforces this
with a `cargo tree` check.

### `no_std` first

Every crate must build without the standard library. Gate anything needing
allocation behind `#[cfg(feature = "std")]`. CI cross-compiles to
`thumbv7em-none-eabihf`, `thumbv6m-none-eabi`, `riscv32imac-unknown-none-elf`,
and `wasm32-unknown-unknown`, because `--no-default-features` on a host that has
`std` available proves nothing.

### Nothing panics on caller input

Return `ic_core::Result`. No `unwrap`, `expect`, or slice indexing that a caller
can drive out of bounds.

### Constant time on secrets

No branches or memory indices driven by key material. Compare tags with
`ic_core::ct::verify`, never `==`. If you cannot see how to avoid a
secret-dependent branch, open an issue rather than writing the code.

### Test vectors must be real

Use vectors from the published standard and cite it in a comment. **If you
cannot verify a vector against an authoritative source, do not invent one.**
Write a property test, or transcribe the specification's pseudocode
independently and compare against it — both patterns already exist in the
repository (`ic-drbg/src/hmac_drbg.rs`, `ic-kdf/src/pbkdf2.rs`). Record the
provenance in `docs/FIPS.md`.

An asserted constant that nobody checked is worse than no test: it looks like
verification and is not.

### Every algorithm needs three things

1. An entry in `crates/ic-ontology/src/registry.rs`.
2. A `SelfTest` implementation registered in `crates/ic-fips/src/selftest.rs`
   (bump `TEST_COUNT` and recompute the integrity tag).
3. Parameter bounds in the ontology that match the type's constants — the
   cross-layer tests in `iron-crypto` will fail otherwise.

If an algorithm is *not* implemented, it still gets an ontology entry with
`status: Planned` and a `notes` field explaining what a caller should do
instead. Those entries are load-bearing: they are what stops an agent from
substituting something inappropriate.

## Never claim FIPS validation

This module is not CMVP validated. Do not say or imply that it is — in code,
comments, documentation, commit messages, or pull request descriptions.
`ic_ontology::runtime::has("fips-validated")` returns `false` and must keep
returning `false` until a certificate actually exists.

## Pull Request Process

1. Ensure your PR has a clear title and description.
2. Link any related issues.
3. All CI checks must pass.
4. Maintainers will review and may request changes.

Changes to cryptographic primitives will be reviewed more slowly and more
sceptically than changes to tooling or documentation. That is not distrust of
you; it is the appropriate posture for the subject matter.

## Reporting security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## Code of Conduct

Be respectful, constructive, and inclusive.
