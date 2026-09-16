# Working in this repository

Instructions for coding agents. Humans may also find them useful.

## Before choosing an algorithm, ask

Do not select a primitive from memory. Ask the library:

```console
$ acrypto recommend <intent> [--fips] [--post-quantum] [--aes-hardware] --json
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
$ acrypto ontology show <algorithm> --json
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
- **Never compare tags with `==`.** Use `ac_core::ct::verify`.
- **Never hash a password with a plain hash.** Use `ac_kdf::pbkdf2` with at
  least 600 000 iterations and 16 bytes of fresh salt.
- **Never use raw OS bytes as key material.** Use `ac_drbg::Rng::from_os()`.
- **Never use the raw X25519 shared secret as a key.** Run it through HKDF with
  both public keys as `info`.
- **Wrap secrets in `Zeroizing`.** Round keys, derived keys, shared secrets.

## Repository conventions

- **Zero dependencies.** Do not add a crate to any `Cargo.toml` under
  `crates/`. If you need JSON, hex, base64, or zeroization, it is already here.
- **`no_std` first.** New code must compile without `std`. Gate anything that
  needs allocation behind `#[cfg(feature = "std")]`.
- **Nothing panics on caller input.** Return `ac_core::Result`. No `unwrap` on
  anything a caller controls.
- **Constant time on secrets.** No branches or table indices driven by key
  material. If you cannot avoid one, do not write the code — ask.
- **Every algorithm gets a `SelfTest`.** Register it in
  `crates/ac-fips/src/selftest.rs`, bump `TEST_COUNT`, and recompute the
  integrity tag.
- **Every algorithm gets an ontology entry**, implemented or not.

## Test vectors

Use vectors from the published standard, and cite it in a comment. If you cannot
verify a vector from an authoritative source, **do not invent one**. Write a
property test, or transcribe the specification's pseudocode independently and
compare against it — both patterns are already in the repository
(`ac-drbg/src/hmac_drbg.rs`, `ac-kdf/src/pbkdf2.rs`). Then record the provenance
in `docs/FIPS.md`.

An asserted constant that nobody checked is worse than no test: it looks like
verification and is not.

## Before you finish

```console
$ cargo test --workspace
$ cargo build -p agentic-crypto --no-default-features --target thumbv7em-none-eabihf
$ cargo clippy --workspace --all-targets
```

The cross-layer tests in `agentic-crypto` and `ac-fips` will fail if the
ontology and the implementations disagree. That failure is the point — fix the
disagreement, do not relax the test.

## Never claim FIPS validation

This module is not CMVP validated. Do not say or imply that it is, in code,
comments, documentation, commit messages, or conversation.
`ac_ontology::runtime::has("fips-validated")` returns `false`, and it must keep
returning `false` until a certificate actually exists.
