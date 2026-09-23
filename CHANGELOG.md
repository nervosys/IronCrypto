# Changelog

All eighteen crates share a version and are released together, so this covers
all of them.

## 0.1.3

Metadata and documentation. No code path changed; the one addition is a
registry entry for an algorithm this library does not implement.

### Fixed

- **`ic-mldsa`'s crate description said "incomplete, no signature scheme yet".**
  It has had `sign`, `verify`, the prehash variants and a deterministic variant
  for some time, and passes 55 of NIST's ACVP vectors. The description was
  written before any of that and never updated, so crates.io was telling people
  the crate was a stub.
- **`ic-mlkem`'s said "experimental, not vector-tested".** It passes 50 ACVP
  cases. Same cause.
- **`SECURITY.md` still called ML-KEM-768, ML-DSA-65 and AES-GCM-SIV
  experimental** and said no ACVP or RFC vector was wired in. All three have
  been vector-tested since before 0.1.1; the ontology and the README were
  updated at the time and this file was not.

A crate description is fixed to the version that carried it, so the wrong text
stays visible on 0.1.2 and earlier. This release is what replaces it.

### Added

- An ontology entry for **SLH-DSA (FIPS 205)**, with status `planned` and no
  code behind it. This library implements ML-DSA-65 and not SLH-DSA, and
  without an entry a request for it resolved to nothing at all rather than to
  an absence — `ic ontology show slh-dsa` now explains what it is, why someone
  would want it over ML-DSA, and that it is not here. `recommend` still returns
  ML-DSA-65, since a planned entry is not selectable.

## 0.1.2

Performance, and one addition to the public API. No algorithm changed, no
encoding changed, and every published test vector passes exactly as before.

### Added

- `ic_ec::Ed25519VerifyKey`, a public key with its curve point already
  recovered. Verification needs the key as a point, and decompressing one is a
  field exponentiation — about two microseconds against the twenty a
  verification takes. A caller checking more than one signature against the
  same key should hold one of these rather than pay that each time, which is
  the same reason `Ed25519Key` exists on the signing side.
  `Ed25519::verify` still takes bytes and builds one per call, so nothing that
  worked before needs changing.

### Changed

- **SHA-512 is about 1.5x faster**, from 715 to roughly 1075 MiB/s, and now
  within a few percent of RustCrypto. Its message schedule is computed with
  AVX2 and interleaved into the rounds four words at a time, where it runs in
  the issue slots the round chain leaves empty. Runtime-detected; targets
  without AVX2 keep the portable path.
- **Ed25519 signing is about 1.9x faster**, from 1.6x behind dalek to 1.17x
  ahead. Three things, in the order they were found: scalar reduction was long
  division, one bit at a time, and now folds using the six digits of
  `L - 2^252`; additions take their right-hand side in Niels form, which is
  four multiplications instead of nine, or three when the stored point is
  affine; and doublings stop at the completed form, since a doubling never
  reads `T`.
- **Ed25519 verification is about 1.3x faster** in absolute terms, though it
  remains roughly 1.25x behind dalek. It shares the changes above, and no
  longer inverts a field element to leave the doubling chain — that conversion
  is four multiplications, and the inversion was running whenever the scalar
  was even.
- Curve25519 field elements carry their reduction differently: both
  `carry_reduce` and `weak_reduce` take their five carries at once rather than
  walking the limbs in order. Same values, shorter dependency chain.

### Notes

`README.md` carries the measured comparison against RustCrypto and dalek, and
what the two rows still behind — SHA-512 and Ed25519 verification — are made
of. The source records the attempts that did not work, so they are not tried
again.

## 0.1.1

The first complete release: all eighteen crates, built from one tree.

0.1.0 reached crates.io as thirteen of the eighteen. `ic-ec` never published —
`cargo publish` refuses a dirty working tree, and that crate was being edited
when the publisher reached it — so `iron-crypto`, `ic-cli`, `ic-fips`,
`ic-mlkem` and `ic-rustls` had nothing to depend on and did not publish either.
0.1.1 has all of them, and carries the portable AES and SHA-3 work that
predates it.

## 0.1.0

Partial; see above. Prefer 0.1.1 or later.
