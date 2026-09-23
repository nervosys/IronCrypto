# Working in this repository

Instructions for coding agents. Humans may also find them useful.

## Before choosing an algorithm, ask

Do not select a primitive from memory. Ask the library:

```console
$ icrypto recommend <intent> [--fips] [--post-quantum] [--aes-hardware] --json
```

Intents: `encrypt-message`, `hash-data`, `authenticate-message`, `derive-key`,
`hash-password`, `agree-key`, `sign-data`, `generate-random`.

The response carries the choice, the reasoning, the rejected alternatives with
reasons, the exact Rust path, and the constraints you must honour.

## When the answer is "no", stop

If `status` is `unavailable`, the correct algorithm exists but is not in this
build. **Do not substitute.** Report it to the user and suggest a validated
module. Substituting Ed25519 for ECDSA under a FIPS requirement silently breaks
the requirement, which is worse than failing.

If `status` is `impossible`, nothing in the registry meets those constraints.

## Before writing a call, read the entry

```console
$ icrypto ontology show <algorithm> --json
```

`parameters` gives exact byte bounds. `constraints` gives the rules, each with a
`severity`:

- `critical` — do not emit code that violates it. Find another approach.
- `serious` — do not violate it without saying so to the user.
- `advisory` — prefer to honour it.

## Rules that are always in force

- **Never reuse a `(key, nonce)` pair.** Under GCM this leaks the
  authentication subkey; under ChaCha20-Poly1305 it XORs plaintexts. Derive
  nonces from a counter.
- **Never use an unauthenticated mode alone.** `aes-cbc` and `aes-ctr` need a
  MAC. Prefer an AEAD.
- **Never compare tags with `==`.** Use `ic_core::ct::verify`.
- **Never hash a password with a plain hash.** Use `ic_kdf::pbkdf2` with at
  least 600 000 iterations and 16 bytes of fresh salt.
- **Never use raw OS bytes as key material.** Use `ic_drbg::Rng::from_os()`.
- **Never use the raw X25519 shared secret as a key.** Run it through HKDF with
  both public keys as `info`.
- **Wrap secrets in `Zeroizing`.** Round keys, derived keys, shared secrets.

## Repository conventions

- **Zero dependencies.** Do not add a crate to any `Cargo.toml` under
  `crates/`. If you need JSON, hex, base64, or zeroization, it is already here.
- **`no_std` first.** New code must compile without `std`. Gate anything that
  needs allocation behind `#[cfg(feature = "std")]`.
- **Nothing panics on caller input.** Return `ic_core::Result`. No `unwrap` on
  anything a caller controls.
- **Constant time on secrets.** No branches or table indices driven by key
  material. If you cannot avoid one, do not write the code — ask.
- **Every algorithm gets a `SelfTest`.** Register it in
  `crates/ic-fips/src/selftest.rs`, bump `TEST_COUNT`, and recompute the
  integrity tag.
- **Every algorithm gets an ontology entry**, implemented or not.

## Test vectors

Use vectors from the published standard, and cite it in a comment. If you cannot
verify a vector from an authoritative source, **do not invent one**. Write a
property test, or transcribe the specification's pseudocode independently and
compare against it — both patterns are already in the repository
(`ic-drbg/src/hmac_drbg.rs`, `ic-kdf/src/pbkdf2.rs`). Then record the provenance
in `docs/FIPS.md`.

An asserted constant that nobody checked is worse than no test: it looks like
verification and is not.

A vector you did check constrains only what its own bytes exercise. "Checked
against the RFC" reads like a completeness claim and is not one. Where the code
branches on something the vectors do not vary -- a header form, a key length, a
padding choice -- test that distinction separately, against the rule rather than
against a value. RFC 9001's three header-protection vectors all pass against an
inverted long/short header rule, because the bit that separates the two happens
to be zero in every one of them; `crates/ic-rustls/src/quic.rs` carries the test
that does separate them, and `docs/FIPS.md` records why it has to exist.

Break the thing and confirm the test fails. A test that passes on the broken
code told you nothing, and finding that out costs one build.

## Measuring a change

`bench/` compares this library against RustCrypto and dalek. It is excluded
from the workspace, so their crates never enter the dependency graph.

Compare a change against itself, under the same conditions, minutes apart. Two
runs taken an hour apart on a machine that is also compiling are not a
comparison: a SHA-512 change here once scored as 1.24x faster across runs and
was a regression under a controlled A/B. Prefer `git stash`, measure, restore,
measure. Trust only effects large enough to clear the noise you can see in the
spread, and report a figure that lands either side of parity as parity.

Before reaching for intrinsics, find out where the time goes. ECDH is one
scalar multiplication, so it separates that cost from the rest of a signature;
splitting an AEAD tells you whether the cipher or the MAC is the limit. Both
diagnostics changed what was worth doing here.

The changes that paid were ones the compiler cannot make: breaking a serial
dependency chain, selecting a hardware instruction, changing the algorithm.
Hand-unrolling and rearranging scalar code did not pay, twice, because LLVM had
already done it -- see the note above `Core512` in `crates/ic-hash/src/sha2.rs`.

## Before you finish

```console
$ cargo test --workspace
$ cargo build -p iron-crypto --no-default-features --target thumbv7em-none-eabihf
$ cargo clippy --workspace --all-targets
```

The cross-layer tests in `iron-crypto` and `ic-fips` will fail if the
ontology and the implementations disagree. That failure is the point — fix the
disagreement, do not relax the test.

## Never claim FIPS validation

This module is not CMVP validated. Do not say or imply that it is, in code,
comments, documentation, commit messages, or conversation.
`ic_ontology::runtime::has("fips-validated")` returns `false`, and it must keep
returning `false` until a certificate actually exists.
