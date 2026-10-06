# Changelog

All nineteen crates share a version and are released together, so this covers
all of them.

## Unreleased

### Added

- **HPKE with DHKEM(P-384, HKDF-SHA384)**, KEM `0x0011` with KDF `0x0002`, in
  `ic_hpke::p384`: `KeyPair` with `generate`, `from_private` and RFC 9180's
  `DeriveKeyPair`, and `setup_sender`, `setup_receiver` and
  `setup_sender_with_ephemeral`, returning the same `Context` as the X25519
  suite. With AES-256-GCM it is the HPKE of MLS cipher suite 7
  (`MLS_256_DHKEMP384_AES256GCM_SHA384_P384`), requested by IronPrivacyGuard.
  Public keys and encapsulations are uncompressed points, each validated on
  the curve; compressed points are refused. No published HPKE vector uses
  P-384, so `testvectors/hpke-p384.json` comes from an independent
  implementation that first reproduces the CFRG's twelve P-256 and P-521
  base-mode vectors and exchanges a message each way with
  pyca/cryptography's HPKE. A known-answer self-test joins the table (73).
- **The ontology entry says it is not FIPS-approved, and why.** Its
  primitives are approved -- ECDH P-384, HMAC-SHA384, AES-GCM -- but DHKEM
  extracts from `"HPKE-v1" || suite || label || Z` where SP 800-56C's
  two-step KDF extracts from `Z` alone.

### Changed

- `ic-hpke`'s key schedule and labeled HKDF run over SHA-256 or SHA-384. The
  X25519 suite's API and outputs are unchanged, and its vectors still pass.

## 0.2.14

Changes that make the library harder to misuse by an agent, and easier for
one to use correctly.

### Added

- **`ic_cipher::Sealer` and `Opener`: AEAD encryption that chooses its own
  nonces.** A sealer builds each nonce as SP 800-38D section 8.2.1's
  deterministic construction does -- a 4-byte sender tag, then a 64-bit
  counter -- returns it, and refuses rather than wraps when the counter runs
  out. An opener accepts only its sender's tag and only counters it has not
  passed, so replays and reordering are refused before the AEAD runs. Both
  work over AES-GCM, ChaCha20-Poly1305 and AES-GCM-SIV. A counter is unique
  only within its sealer; the documentation says what that requires of the
  key, and `Sealer::resume` restores a persisted counter. In the prelude.
- **The MCP `crypto_seal` tool draws the nonce when none is given**, returns
  it, and refuses a (key, nonce) pair it has already sealed under in this
  process. It keeps an HMAC of each pair under a per-process key, never the
  key. `ic seal` takes `random` in place of a nonce and prints the nonce used.
- **The documentation's Rust compiles and its sample output is checked.** The
  Rust blocks in the README, `docs/FIPS.md` and `docs/ONTOLOGY.md` run as
  doctests of `ironcrypto`; five of the six in `docs/` did not compile, and one
  was a diagram. The README's `ic recommend` sample and `docs/ONTOLOGY.md`'s
  `ic ontology show` sample are compared word for word with what the commands
  print. The registry's own examples were already compiled, by
  `examples_compile.rs`.
- **MCP tools to open, verify and derive.** `crypto_open` is `crypto_seal`'s
  inverse, and a wrong key, nonce, associated data or tag gives one error and
  no plaintext. `crypto_verify` checks ECDSA, Ed25519, ML-DSA and RSA
  signatures and answers `valid: true` or `false`, keeping errors for input
  it cannot interpret; RSA keys may be a SubjectPublicKeyInfo or a PKCS#1
  `RSAPublicKey`. `crypto_derive` is HKDF, checked against RFC 5869 A.1. An
  agent that needed any of these used to write and compile Rust for it.
  `crypto_seal` and `crypto_open` also take AES-GCM-SIV.
- **`ic lint` and the MCP `crypto_lint` tool** check Rust source for the
  known misuses -- literal nonces and keys, tags compared with `==`, passwords
  through a plain hash or PBKDF2 below 600 000 iterations, raw OS randomness,
  raw shared secrets as keys, CBC or CTR with no MAC -- and name the rule each
  finding breaks. They match text a line at a time, and every report says
  that a finding can be wrong, that no findings is not proof, and which rule
  (`wrap-secrets`) is not checked at all.
- **A rule against keys written into code**, `no-literal-key`, joins the
  always-in-force rules.
- **The always-in-force rules ship with the library**, as
  `ic_ontology::RULES`: nonce reuse, unauthenticated modes, tag comparison,
  password hashing, raw OS bytes, raw shared secrets, and wiping secrets, each
  with the reason and what to call instead. They were only in the
  repository's `AGENTS.md`, which no published package contains. The MCP
  server now sends them in its `instructions` when a client connects, the new
  `crypto_rules` tool and `ic rules` command return them, and the `ironcrypto`
  documentation lists them. A test fails if `AGENTS.md`, that documentation
  and `RULES` disagree.
- **Every package carries the README**, so the crates.io pages are no longer
  blank.

### Changed

- **The examples no longer teach nonce reuse.** The first example in the
  `ironcrypto` and `ic-cipher` documentation sealed under a constant key and
  an all-zero nonce, and the registry's AEAD examples passed an undefined
  `nonce`; all now use `Sealer`. The `prefer-counter-nonce` constraint and
  `AGENTS.md` name it as the first choice.

## 0.2.13

From a security audit on 2026-10-06 against CVE and RustSec, MITRE ATT&CK,
NIST FIPS 140-3 and CMMC 2.0. What it left open is recorded where it lives:
the knowledgebase's Partial and Unmet entries, and `docs/FIPS.md`.

### Security

- **PBKDF2 and SP 800-108 now have known-answer self-tests.** Both are
  approved KDFs available in the registry, and both were on the CAST
  exemption list with the reason "covered by the SHA-256 instantiation" --
  while being the SHA-256 instantiations, with no test behind them. 72 CASTs,
  where there were 70.
- **ECDSA `verify_prehash` refuses a digest narrower than the curve's
  strength**: 32 bytes on P-256, 48 on P-384, 64 on P-521. It accepted any of
  28, 32, 48 or 64 on every curve, so SHA-224 could stand under P-521; the
  ontology constraint said the hash had to be at least as strong as the curve
  and nothing enforced it. Calls that pass a strong-enough digest are
  unchanged; weaker ones now fail with `InvalidLength`. `ic_ec::min_prehash_len`
  gives each curve's floor.
- **Private-key types no longer print key material through `Debug`.**
  `ic_pkix::PrivateKeyInfo` and `MlDsaPrivateKey` derived `Debug`, which
  printed RSA primes, EC scalars and ML-DSA seeds, and `PartialEq`, which
  compared them with a short-circuiting `==`. `Debug` now shows the algorithm
  and public parts; equality compares secret parts in constant time. A test
  fails if any key-holding type derives either again.
- **DER writing leaves no stray key bytes.** `Writer::finish` wipes the part
  of the buffer past the encoding, which held a second copy of it, and the
  private-key `to_der`s wipe their output when a write fails part way.
- **ML-DSA reduces before each inverse NTT of an accumulated sum**, as FIPS
  204's reference code does. The inverse transform's first lane adds all 256
  inputs unreduced, and a worst-case sum of products overflows `i32`, which
  with overflow checks on is a panic. No input reaching it was found;
  outputs are unchanged.
- **HPKE wipes its base nonce** with the rest of a context's secrets.
- **Shamir refuses, rather than panics on, a secret too long for its share
  count** on 32-bit targets, where the output length could overflow.
- **`ic_hpke::doc_rng` is gone.** It was public, though hidden from the
  documentation, and produced a fixed, predictable stream; the example uses
  `ic_drbg::Rng::from_os()`.
- **`ic-rustls` requires rustls 0.23.45**, the version that fixed
  RUSTSEC-2026-0285, so a downstream build cannot resolve an older one.

### Changed

- **The FIPS posture says what the gate covers.** The self-tests, the error
  state and approved mode gate services requested through `ic_fips::check` or
  `guarded`; a primitive called directly does not consult them, because the
  primitive crates cannot depend on the policy crate. `docs/FIPS.md` said no
  service was available before `initialize()`, and the knowledgebase marked
  the self-test and error-state requirements met; both now say partial, with
  the gap, and enforcing the boundary is listed among what validation would
  still require.
- **CMMC practices that protect CUI are partial, not met**, since for CUI each
  also requires FIPS-validated cryptography (SC.L2-3.13.11), which this module
  does not have. The CWE and ATT&CK mappings cover the code added since 0.2.7
  -- HPKE, Shamir, `verify_prehash`, ML-DSA PKCS#8 -- and CWE-323 is partial
  rather than not applicable, since HPKE contexts enforce their own nonces.
- **CI runs with a read-only token and pins its actions to commit SHAs**; the
  self-hosted checkout keeps no token on disk. The advisory floors table cites
  every advisory below each floor, and warns once its review is a month old.

## 0.2.12

### Added

- **`ic_hpke::KeyPair::derive`**, RFC 9180's `DeriveKeyPair` for
  DHKEM(X25519): a key pair from at least 32 bytes of input keying material,
  deterministically. MLS's TreeKEM derives every node key this way, and
  IronPrivacyGuard needs it for MLS. Checked against RFC 9180 A.1.1, whose
  `ikmE` and `ikmR` now derive the appendix's keys.

## 0.2.11

### Added

- **Shamir secret sharing, `ic_cipher::shamir`.** Split a secret into up to
  255 shares, any `threshold` of which recover it and fewer of which reveal
  nothing, over GF(2^8) with `ic_cipher::gf`'s branch-free, table-free
  arithmetic. `split` and `combine` work in caller storage under `no_std`;
  `split_vec` and `combine_vec` return shares and a secret that wipe on drop.
  Shares carry no integrity, so the intended use is splitting a random key
  that protects data under an AEAD. IronPrivacyGuard wanted it for key
  backups. A module rather than a crate, so no new package. It has a
  self-test and an ontology entry, `shamir-gf256`, citing Shamir's 1979
  paper.
- **Two ontology terms.** `Class::SecretSharing` (`secret-sharing`) for
  Shamir, and `Body::Literature` in the standards knowledgebase for a
  construction no standards body defines, located by DOI. Both enums are
  exhaustive, so code outside this workspace that matches on either without a
  wildcard arm needs one; nothing in this workspace or its known dependents
  does.

- **HPKE, RFC 9180, in a new crate, `ic-hpke`.** Base mode with
  DHKEM(X25519, HKDF-SHA256) and HKDF-SHA256, over AES-128-GCM, AES-256-GCM or
  ChaCha20-Poly1305, with the exporter. Key pairs, sender and receiver setup
  (the sender's with a fresh ephemeral key, or a given one for test vectors),
  and contexts that seal and open in place, or into a `Vec` under `std`.
  Contexts refuse rather than reuse a nonce, a failed open does not advance the
  sequence, and an all-zero DH output is refused. No PSK, auth or auth-PSK
  modes. IronSocketLayer (for Encrypted Client Hello) and IronPrivacyGuard (for
  MLS) each needed it; both can now use this one. It has a self-test, an
  ontology entry, `hpke-x25519-sha256`, not FIPS-approved because X25519 is
  not, and RFC 9180 in the standards knowledgebase with two requirements tied
  to tests. Checked against RFC 9180 A.1.1 and an independent implementation
  written from the specification.

- **ML-DSA private keys in PKCS#8.** `ic_pkix::MlDsaPrivateKey` reads and
  writes RFC 9881's three forms -- the seed, the expanded key, and both -- for
  ML-DSA-44, -65 and -87, as strictly as `PrivateKeyInfo`, and writes back
  exactly what it read. `PrivateKeyInfo` is unchanged and still reports an
  ML-DSA key as `Unsupported` with its OID, so code matching on it keeps
  compiling. `ic-pkix` performs no cryptography, so whether a `both` key's
  halves agree is checked by regenerating the key with `ic_mldsa`, as the
  module documents. IronSocketLayer parsed these itself; it can now use this.
  Checked against keys OpenSSL 3.5.7 wrote in each form.

- **ECDSA verification over a caller-supplied digest.**
  `EcdsaP256Sha256::verify_prehash`, `EcdsaP384Sha384::verify_prehash` and
  `EcdsaP521Sha512::verify_prehash` take a digest instead of a message, for
  signatures made with a hash other than the curve's own, such as P-384 with
  SHA-512. The digest becomes the scalar as FIPS 186-5 specifies, truncated to
  the order's width when longer. Widths are limited to SHA-224 through SHA-512
  (`ic_ec::PREHASH_LENS`); SHA-1's 20 bytes are refused. The ontology's ECDSA
  entries gain a serious constraint: the caller must choose a hash at least as
  strong as the curve and bind which one it was. Checked against RFC 6979's
  P-256 and P-384 signatures for all four SHA-2 hashes, and P-521 signatures
  from OpenSSL.

### Fixed

- **`rust-version` is now 1.87, the oldest toolchain the workspace builds
  on.** It said 1.75, which stopped being true when the SIMD backends began
  calling `core::arch` intrinsics inside `#[target_feature]` functions without
  `unsafe`; on 1.75 to 1.86 `ic-cipher` does not compile. Found by
  IronSocketLayer's release check. The full gate and a new CI job now build the
  workspace with exactly the declared toolchain, so the number cannot drift
  again unnoticed. Length checks use `is_multiple_of`, which clippy asks for
  from 1.87; each tests a public length, and the compiled-code probes are
  unchanged.

## 0.2.10

### Performance

- **ML-DSA signing needs under half the stack it did in 0.2.9.** Signing no
  longer holds `s1`, `s2` and `t0` decoded: each row is decoded and
  transformed from the encoded key where it is used, then wiped. Hints are
  held as 32-byte bitmaps rather than 256-byte boolean arrays, and products
  accumulate in place. Verification decodes hints the same way. Full call
  depth on Cortex-M4 (thumbv7em, fat LTO, linked), before and after:

  | | sign | verify |
  |---|---|---|
  | ML-DSA-44 | 27.1 to 13.1 KB | 16.7 to 12.0 KB |
  | ML-DSA-65 | 34.8 to 15.2 KB | 18.2 to 13.0 KB |
  | ML-DSA-87 | 43.8 to 17.6 KB | 20.3 to 17.5 KB |

  **Signing is slower for it**, because `s1` and `s2` are decoded again on
  every rejection attempt: on x86-64, alternating old and new builds and
  averaging over 64 messages, ML-DSA-44 signing takes 1.075x as long, -65
  1.073x and -87 1.058x. Key generation, which signs a consistency probe,
  takes 1.04x to 1.06x as long; verification is about 1% faster. Outputs are
  identical: every ACVP case and the OpenSSL fixtures pass.

### Tests

- ML-DSA signing and verification are compared with the forms that held the
  key and the hints whole, kept under `cfg(test)`, for all three parameter
  sets: byte-identical signatures, deterministic and hedged, and the same
  verdict on valid signatures and on damage to the challenge, `z`, the hint
  indices and the hint counts.
- The hint bitmaps' packing and unpacking are compared with the boolean
  forms over random patterns either side of the weight limit and over
  arbitrary bytes.

## 0.2.9

### Performance

- **ML-KEM uses between a quarter and a half of the stack it did.** Key generation,
  encapsulation and decapsulation no longer hold the matrix `A`: each entry
  is sampled from `rho` where it is used, giving the same values, and the
  vectors are carried a row or an element at a time, with products
  accumulated in place. Every operation uses each entry of `A` once, so
  nothing is sampled twice. Full call depth on Cortex-M4 (thumbv7em, fat LTO,
  linked), before and after:

  | | keygen | encapsulate | decapsulate |
  |---|---|---|---|
  | ML-KEM-512 | 22.9 to 11.7 KB | 13.4 to 5.5 KB | 16.0 to 7.2 KB |
  | ML-KEM-768 | 32.7 to 12.8 KB | 18.9 to 6.8 KB | 21.6 to 8.8 KB |
  | ML-KEM-1024 | 44.5 to 14.2 KB | 25.4 to 7.3 KB | 28.3 to 9.8 KB |

  Key generation includes its pairwise consistency test, an encapsulation
  and a decapsulation. On x86-64, alternating old and new builds, ML-KEM-512
  is at parity, ML-KEM-768 about 3% slower and ML-KEM-1024 about 8% faster.
  Outputs are identical: every ACVP case and the OpenSSL fixtures pass.

### Tests

- K-PKE key generation, encryption and decryption are each compared with the
  held-matrix form they replaced, for all three ML-KEM parameter sets,
  including decryption of ciphertexts that encrypt nothing.
- Decapsulation is checked against FIPS 203's rule for every set: `K` for a
  valid ciphertext, and exactly `J(z || c)` for a tampered one, where the
  tests had checked only that the secret changed.
- `bench`'s `stack mlkem` group measures ML-KEM's peak stack and time.

## 0.2.8

### Renamed

- **The facade crate is now `ironcrypto`**, imported as `ironcrypto::`. It
  was `iron-crypto`, imported as `iron_crypto::`; that package stays on
  crates.io at 0.2.7 and receives no further releases. To move, change the
  dependency to `ironcrypto = "0.2.8"` and the paths from `iron_crypto::` to
  `ironcrypto::`; nothing else differs. The seventeen `ic-*` crates keep
  their names. The MCP server reports itself as `ironcrypto`.

### Performance

- **ML-DSA uses between a third and a tenth of the stack it did.** Signing, verification
  and key generation no longer hold the matrix `A`: each entry is sampled from
  `rho` where it is used, giving the same values, and keys,
  signatures and `w1` are encoded a row at a time. Peak stack on x86-64,
  measured by `bench`'s `stack` subcommand:

  | | sign | verify | keygen |
  |---|---|---|---|
  | ML-DSA-44 | 104.2 to 29.2 KiB | 66.8 to 18.3 KiB | 148.1 to 33.1 KiB |
  | ML-DSA-65 | 158.6 to 37.6 KiB | 106.4 to 19.8 KiB | 224.7 to 43.5 KiB |
  | ML-DSA-87 | 242.6 to 47.7 KiB | 174.5 to 17.8 KiB | 345.0 to 55.0 KiB |

  **Signing is slower for it.** It now samples `A` once per attempt rather
  than once per signature, and averaged over 64 messages it takes 1.66x
  (ML-DSA-44), 1.69x (-65) and 1.88x (-87) as long. Key generation, which
  signs a consistency probe, takes 1.4x to 1.55x as long. Verification is
  unchanged. Outputs are identical: every ACVP case passes.

### Changed

- **The curve tables no longer allocate.** Under `std`, P-256, P-384 and
  P-521 built their generator tables into a `Vec` on first use, so the first
  ECDSA operation of a process allocated; a caller that forbids allocation
  after start-up met that inside its first TLS handshake. Every table now
  lives in statics, a `OnceLock` per window, built where it is stored. That
  also stops Ed25519 building its 30 KiB table on the caller's stack before
  moving it in: the first Ed25519 signature now peaks at 8.1 KiB of stack
  rather than 36.4, and the first verification at 6.6 KiB rather than 24.9.
  Steady-state speed is unchanged within measurement noise.

- **HMAC-SHA384 and HMAC-SHA512 use less stack.** Their digest states carry
  SHA-512's 640-byte message schedule, so each HMAC is 1.7 KiB, and key setup
  built both states as locals before moving them into the result, beside a
  third for a long key. They are now absorbed in place, the long-key hash
  runs out of line, and for these two digests key setup and finalization stay
  out of line, so a caller that inlined them -- HKDF, say -- no longer
  carries their frames at once. One HMAC-SHA384 tag on Cortex-M4 (fat LTO,
  full call depth) now needs 7.9 KiB rather than 11.1, and HKDF-SHA384
  11.4 KiB rather than 14.8; on x86-64 HKDF-SHA384 needs 9.3 KiB rather than
  16.4. HMAC-SHA256 is unchanged in shape and stays inlined; timing is at
  parity for all of them.

### Added

- `ic_ec::prepare()` builds every curve table now rather than on first use,
  for callers that want the first operation to cost what later ones do. It
  is idempotent and does nothing under `no_std`, which has no tables.

### Tests

- `ic-ec/tests/cold_tables.rs` runs every curve's first use in a fresh
  process under a counting allocator and fails on any allocation. It fails on
  the previous tables, three allocations, one per NIST curve.
- RFC 4231 case 6, a key longer than the block, is now checked for
  HMAC-SHA384 and HMAC-SHA512 as well as HMAC-SHA256.
- `bench` measures peak stack per operation by painting it, byte-granular on
  any host, beside the time each operation takes.
- On-demand rows of `A`, and key generation's row-at-a-time encoding, are each
  checked against the held-matrix form for all three ML-DSA parameter sets.

## 0.2.7

### Security

- `Choice::mask` now hides its input range before negation as well as its
  output. Fat LTO on Cortex-M0 otherwise branches on the secret flag in byte
  selection, conditional copy and conditional swap. Results are unchanged.

### Tests

- Six additional core-helper probes gate byte selection and four-byte
  equality, zero checking, big-endian ordering, conditional copy and swap.
  The gate now checks nineteen probes on each of four targets.

## 0.2.6

### Security

- ML-DSA reduction and decomposition and ML-KEM compression now hide both
  the input and result ranges of sign extraction. Fat LTO on Cortex-M0
  turned their masks back into secret-dependent branches even after the
  division fixes in 0.2.5. Numerical results are unchanged.

### Tests

- `ic timing` now measures ML-DSA rounding and ML-KEM compression with
  fixed versus random synthetic coefficient batches. Input preparation is
  outside the timed region; all outputs are retained. These measurements
  report evidence on the running host and do not gate CI.
- Thirteen compiled-code probes reject branches, division and unresolved
  calls on x86-64, Cortex-M0, Cortex-M4 and RISC-V, in CI and the full local
  gate. Their coverage and limitations are in `docs/CONSTANT_TIME.md`.

## 0.2.5

### Security

- **ML-DSA and ML-KEM no longer divide secret-dependent values.** ML-DSA's
  `decompose` and `power2round` divided by `2*gamma2` and reduced modulo `q`
  by division, on signing's `w - c*s2` and key generation's `t0` -- on every
  target, x86-64 included -- and `decompose` branched on its fold. The module
  said those values were public; they are not. Both now use shifts, masks and
  small multiplications (FIPS 204's reference forms), checked against
  Algorithms 35 and 36 over every residue. ML-DSA's secret-coefficient
  sampler and ML-KEM's compression each compiled to a division-library call
  on Cortex-M0, which has no high-half multiply; ML-KEM's is the KyberSlash
  channel, in `decapsulate`. Both are now multiplications. Outputs are
  unchanged -- every ACVP vector passes -- and x86-64 timing measured at
  parity.
- **AES-KWP unwrap no longer branches on the unauthenticated length.** The
  length field is decrypted before anything is authenticated; its
  plausibility check short-circuited and the padding check looped from it, so
  timing on a forged ciphertext revealed whether it decrypted to a plausible
  length and that length mod 8. Both are now masks over fixed work, and the
  compiled check has no branches on x86-64, Cortex-M0, Cortex-M4 or 32-bit
  RISC-V. Results are unchanged: the SP 800-38F length rule and the zero
  padding rule are the same, and every vector passes.
- **Hex and Base64 no longer branch on the characters of a secret.** PEM
  private keys are Base64 and the CLI takes keys as hex. The decoders' source
  was branch-free, but checking each character's validity with an early
  return let every compiler targeted here -- x86-64, Cortex-M0 and M4, 32-bit
  RISC-V -- compile the character-class test into short-circuit branches,
  revealing each secret character's class; and the encoders looked characters
  up in a table indexed by secret bits. Encoding is now arithmetic, and
  decoding accumulates validity and rejects once at the end, leaving nothing
  decoded behind. The compiled code was re-read on all four targets. Also
  stricter: `=` is accepted only as trailing padding, where it was accepted
  anywhere and decoded as zero.
- **Curve and RSA arithmetic is constant time on 32-bit RISC-V.** It used
  `u128` sums, and on `riscv32` the compiler builds 128-bit carries from
  comparisons joined by branches -- on secret data, as `SECURITY.md` recorded:
  20 per Curve25519 field multiplication, 100 to 248 per NIST point addition,
  6 in RSA's Montgomery multiplication. On `riscv32` none of it uses `u128`
  now. Curve25519 has a field of ten 26- and 25-bit limbs; the NIST fields and
  RSA keep their representation and run on 32-bit words with `u64` sums,
  computing bit for bit what the 64-bit code does. Every remaining branch in
  the compiled code was traced to a public value. `--cfg ic_limb32` selects
  the 32-bit forms on any target, which is how every vector is run against
  them; under test each is also compared with its 64-bit counterpart. 64-bit
  targets are unchanged and measured at parity.
- **RSA's CRT recombination** computed `q * h` with a function documented as
  used only by key generation. It is on every private operation, and both
  operands are secret. It branches only on widths, which are public; its
  documentation now says so, and on `riscv32` its products are the 32-bit
  form.

### Performance

- **NIST generator multiplication about 35-50% faster, and ECDSA signing
  about 15-30%**, on P-256 in paired A/B runs (34 to 17-23 microseconds for
  `k*G`). The generator table now accumulates in homogeneous projective
  coordinates with Renes, Costello and Batina's complete addition, adding
  affine table entries, where the Jacobian addition it replaces had to
  compute an addition and a doubling and select between them. Only there:
  moving every point to those formulas was tried and measured, and made
  variable-base multiplication, and so ECDH, slower (71 to 90 microseconds),
  because their doubling costs more. Results are unchanged; every existing
  vector still passes.

### Tests

- The complete group law, Jacobian and projective, is checked on all three
  curves against a textbook affine reference, including equal, opposite and
  identity operands.

## 0.2.4

X.509 certificate issuance, and interoperability tests against OpenSSL.
Additions only: no existing code path changed, so everything 0.2.3 produced,
this produces.

### Added

- **X.509 certificate issuance**, `ic_pkix::cert`, for one profile: a CA and
  the leaves it signs, with basic constraints, key usage, extended key usage
  (TLS server and client), subject alternative names (DNS and IP) and key
  identifiers, signed with ECDSA P-256 or P-384, Ed25519, or ML-DSA-44, -65 or
  -87 (RFC 9881). Signing stays with the caller, since this crate performs no
  cryptography: `write_tbs_certificate` gives the bytes to sign and
  `write_certificate` wraps the signature. `write_ml_dsa_public_key` gives the
  `SubjectPublicKeyInfo` for an ML-DSA subject. Parsing certificates remains
  out of scope. Ed25519 and ML-DSA certificates are byte for byte those
  OpenSSL 3.5.7 issues from the same inputs; ECDSA chains issued here pass
  OpenSSL's `-x509_strict`. Requested by HyperMachine, to drop `rcgen` and
  with it `ring`.

### Tests

- **All six ML-KEM and ML-DSA parameter sets are checked against OpenSSL
  3.5.7**, from fixtures OpenSSL produced: keys regenerated from OpenSSL's
  seeds match OpenSSL's, deterministic ML-DSA signatures equal OpenSSL's byte
  for byte with and without a context string, OpenSSL's hedged signatures
  verify, and OpenSSL's ML-KEM ciphertexts decapsulate to its secrets. The
  NIST vectors show each set is correct; these show it reads other
  implementations' keys, ciphertexts and signatures the same way. The reverse
  directions -- OpenSSL decapsulating ciphertexts made here and verifying
  hedged signatures made here -- were checked by hand for all six, since they
  need OpenSSL at test time. `SECURITY.md` says which is which.

## 0.2.3

Every parameter set of both post-quantum standards, and faster AES-GCM.
Everything is added; nothing is removed or changed. Every key, signature,
MAC, ciphertext and shared secret the previous release could produce, this
one produces byte for byte.

### Added

- **ML-KEM-512 and ML-KEM-1024**, as `ic_mlkem::MlKem512` and
  `ic_mlkem::MlKem1024`, each checked against every NIST ACVP key-generation
  and encapsulation case for its parameter set: 25 of each, from the same
  pinned ACVP-Server commit as ML-KEM-768's. FIPS 203's three sets differ in
  five numbers, so the scheme is now written once, as ML-KEM-768's code with
  those five lifted out, and instantiated per set. ML-KEM-768 is byte for byte
  what it was, and its vectors, tests and self-test pass unchanged. Each new
  set has an ontology entry, a FIPS self-test (`TEST_COUNT` is 66, the
  integrity tag recomputed), a compiled example and hostile-ciphertext
  coverage. `recommend --post-quantum` still offers ML-KEM-768, now with
  ML-KEM-1024 as the alternative and a stated reason for passing over 512.
  Requested by HyperMachine, which offers all three and could not migrate one
  without the others.
- **ML-DSA-44 and ML-DSA-87**, as `ic_mldsa::sign44` and `ic_mldsa::sign87`,
  with the same functions as `ic_mldsa::sign` (ML-DSA-65). Each is checked
  against every NIST ACVP key-generation case and every external, pure
  signature case for its set -- 25 and 30, the signatures 15 deterministic and
  15 hedged -- from the same pinned commit. The scheme is ML-DSA-65's code
  with its parameters lifted into a macro; what does not depend on the set,
  the message framing and `PreHash`, is shared, so all three modules take the
  same `PreHash` type. ML-DSA-65 is byte for byte what it was. Each new set
  has an ontology entry, a FIPS self-test (`TEST_COUNT` is 68), a compiled
  example, and the full hostile-input suite, which now runs unchanged against
  every set. `recommend --post-quantum` still offers ML-DSA-65 for
  signatures, with ML-DSA-87 as the alternative. Also requested by
  HyperMachine.

### Fixed

- `recommend` said a fallback choice was "the only available algorithm" for
  its policy whether or not it was. That was true while every family had one
  member; with three ML-KEM sets it would have told a caller there was no
  choice when there was. It now says so only when it is so.

### Changed

- **AES-GCM counter mode has an AES-NI kernel of its own**, and AES-128-GCM
  over 16 KiB goes from 3.1 to 4.1 GiB/s; AES-256-GCM is now about 2.5 to
  3x ahead of RustCrypto. GCM used to reach AES through `encrypt_blocks`
  eight blocks per call, building the counters and XORing the keystream a
  byte at a time around each call, which ran at 8.5 GiB/s where one call
  runs at 15. `aes::x86::ctr32_xor` builds the counters in place, XORs the
  keystream from registers, and is one call per message. It is reached
  through a crate-private `Ctr32` trait, so no public trait changed; every
  other backend keeps the previous loop, which the kernel is tested against
  at every length from 0 to 300 bytes and at counters that wrap inside the
  32-bit field partway through a group.

## 0.2.2

A crash fix, a constant-time fix, and speed. One addition to the public
API, `Hkdf::expand_from`; nothing removed or changed. Every key, signature,
MAC and shared secret is what 0.2.1 produced.

### Fixed

- **RSA-4096 key generation panicked, every time.** So did
  `RsaPrivateKey::from_primes` with 2048-bit primes, which is how
  `ic-rustls` loads an RSA-4096 key whose PKCS#8 carries its primes: "index
  out of bounds: the len is 64 but the index is 64". Computing
  `d = (1 + m*k) / e` needs a word more than the modulus, and at 4096 bits
  the modulus fills every word a `Uint` has. The multiply dropped its top
  carry, and the addition and division then indexed past the end. A fix that
  only bounded those loops would have derived a wrong `d` without a panic;
  the intermediate now has its own buffer one limb wider, and the result must
  divide exactly and fit. 2048 and 3072 were unaffected. Under
  `panic = "abort"` the panic takes the process down. Reported from
  HyperMachine, which found it by generating a 4096-bit key.

### Security

- **NIST-curve field subtraction branched on a secret on Cortex-M0.** Adding
  the modulus back after a borrow added it as a constant, and the compiler
  specialised the carry chain around P-256's and P-384's limbs, which are 0
  and 2^32 - 1, into selects. Cortex-M0 has no conditional move, so each
  select became a branch on the borrow: 8 per P-256 point addition and 6 per
  doubling, in the arithmetic of ECDSA signing, ECDH and key generation.
  Subtraction now adds `m & mask`, with the mask behind `black_box`. That
  leaves nothing to specialise, and it is one addition where it was an
  addition and a selection. Every NIST point, field and lookup function now
  compiles for `thumbv6m` with no branch on secret data. Found by reading the
  generated code, not by a test: the source had no branch to find.
- Every runtime selection in the NIST field code goes through a new
  `select_ct`, which puts the same `black_box` barrier on its mask that
  `ic_core::ct::Choice` does. This is defence in depth: with rustc 1.98,
  removing it brings no branch back. It costs up to 5% on x86-64. The curve
  constants computed at compile time use `to_mont_const` and
  `mont_mul_const`, which cannot use the barrier. The runtime versions keep
  the original names, so a constant that reached for one would not compile.

### Changed

- **SHA-256 on short inputs, and so HMAC and HKDF, is 2 to 3 times faster**
  on x86-64 with SHA-NI. A block assembled in SHA-256's internal buffer --
  the tail of any message not a multiple of 64 bytes, and every final
  padding block -- was compressed by the portable round function, which also
  wipes its schedule with volatile stores on every block. Only whole blocks
  passed straight to `update` reached SHA-NI. Short messages are mostly such
  blocks, so a 200-byte hash ran at a third of the bulk rate, and HMAC, which
  finishes two hashes per tag, fared worse. Measured, best of nine: SHA-256
  of 200 bytes from 278 to 141 ns, HMAC-SHA256 of 200 bytes from 785 to
  304 ns, a 32-byte HKDF-Expand from 697 to 244 ns. Found from an
  IronSocketLayer measurement against ring. Bulk hashing is unchanged.
- **AES-GCM is about 1.75x faster** on x86-64 with `PCLMULQDQ`: AES-128-GCM
  over 16 KiB from 1.8 to 3.1 GiB/s, and AES-256-GCM from 1.4x to about 2.0x
  ahead of RustCrypto. Splitting the AEAD showed GHASH was three quarters of
  its time, at 2.6 GiB/s against 15 for raw AES-NI. The four-block path
  called the multiply per product, and every call swapped `H` into register
  order again, reduced its own product, and returned it through memory. A
  new kernel takes eight blocks per group, keeps the accumulator in a
  register for the whole buffer, and sums the eight products unreduced
  before one reduction, which is sound because every step after the
  multiplies is linear over GF(2). GHASH alone is now 6.6 GiB/s. `H^5` to
  `H^8` are computed only once an input reaches eight blocks, so short
  messages pay nothing for them.
- `Zeroize` for byte slices writes eight bytes per volatile store instead of
  one, and SHA-256 no longer wipes its state twice on finalisation. Short
  HMAC-SHA256 moved from 1.3x to about 1.15x behind RustCrypto, whose `hmac`
  does not wipe at all.
- HMAC key setup builds one pad and wipes the block it used, 64 bytes for
  SHA-256, where it built two and wiped both at the widest digest's 144:
  123 to 92 ns. When a key longer than a block is hashed first, that hash is
  now wiped too; it is key-equivalent and was left on the stack.

### Added

- `Hkdf::expand_from`, HKDF-Expand from a MAC already keyed with the PRK, for
  deriving several outputs from one secret -- a TLS 1.3 key, IV and finished
  key -- without keying for each. Byte-for-byte `expand`'s output; it shares
  the one expansion loop rather than copying it. Worth about 8% on that
  three-label pattern now that key setup is cheap. Additive, so `expand` and
  every existing caller are unchanged.

- GHASH's powers of `H` are wiped when it is dropped. Only `H` and the
  accumulator were before, so `H^2` to `H^4`, as key-derived as `H`, stayed
  in memory after every AES-GCM operation.

### Documentation

- **On 32-bit RISC-V the curve and RSA arithmetic is not constant time**, and
  `SECURITY.md` now says so, with a table of what was checked on which target.
  Without a carry flag or a conditional move, the compiler builds 64- and
  128-bit carries from 32-bit comparisons joined by branches, in the Ed25519
  and X25519 field, the NIST fields and RSA's Montgomery multiplication. The
  fix is a field implementation on 32-bit limbs, and it has not been written.
  The README's "portable constant-time everywhere" was wrong for that target
  and now says so.

## 0.2.1

Performance, and one fix that was also a performance problem. No public API
changed, no algorithm changed, and every key, signature and shared secret is
byte for byte what 0.2.0 produced.

### Fixed

- **Deriving a NIST-curve public key skipped the generator table.** ECDSA and
  ECDH public-key derivation on P-256, P-384 and P-521 multiplied the
  generator with `mul_scalar` directly, not through `mul_generator`, the
  funnel whose documentation said every generator multiplication went through
  it. The answers were right, so no test noticed. With `std`, a P-256 public
  key took 185 µs where signing, which does use the table, took 54 µs. It now
  takes 38 µs, and P-384 and P-521 are faster by the same factor, about 4.6
  to 4.9x.

### Changed

- **ECDH on the NIST curves is 2.2 to 2.5 times faster**, with or without
  `std`. Multiplying an arbitrary point used a double-and-add-always ladder,
  one addition per bit. It now walks the scalar four bits at a time against
  `1..=8` times the point, built per call and selected with conditional
  moves: the same signed radix-16 recoding and constant-time lookup as the
  generator table, which it now shares. It is still constant time, and it
  needs no storage beyond eight points on the stack. Measured with `std`,
  medians of interleaved runs: P-256 216 to 88 µs, P-384 787 to 363 µs,
  P-521 1909 to 872 µs.
- **ECDSA on `no_std` is about twice as fast.** Without the table, the
  generator is multiplied the windowed way above, so signing and key
  generation get that speed-up. Verification was running the generator half
  through the constant-time ladder although every input to it is public. It
  now computes both halves over one shared chain of doublings in variable
  time, 2.4x faster on every curve: P-256 261 to 110 µs.

- **Ed25519 on `no_std` is two to three times faster.** Embedded builds had
  none of the work that made the `std` path fast, because that work was tied
  to a 40 KB table cached in a `OnceLock`. The parts that need no storage now
  run there too. Signing multiplies the basepoint with the table's signed
  radix-16 method against one window of eight multiples, built on the stack
  and discarded: 252 doublings and 64 additions, where the bit-at-a-time
  ladder did 256 of each, still constant time. Verification computes `[S]B`
  and `[k]A` over one shared chain of doublings, as `std` does, with the
  basepoint's odd multiples built per call. The basepoint itself is now a
  constant rather than decompressed, a field square root, on every call.
  Measured on one x86-64 machine with `ic-ec` built without `std`, medians of
  four interleaved rounds: signing 88 to 45 µs, verification 134 to 46 µs,
  public-key derivation 87 to 43 µs. Verification without `std` now matches
  verification with it. The `std` path is unchanged within noise; its
  verification loop is now shared with the `no_std` one and was measured
  before and after.

### Tests

- On all three NIST curves, the windowed multiplication is held to the old
  ladder, kept as a test-only reference. The checks run on the generator,
  another point and the identity, with `n - 1` (whose top nibble exercises the
  extra carry digit) and runs of 7, 8 and 9. The shared-doubling verification
  is held to two separate ladders and to the `std` path. Dropping the carry
  digit, dropping the sign, or crossing the two tables each fails them. The
  new builds reproduce the old builds' public keys, RFC 6979 signatures and
  ECDH shared secrets byte for byte, with and without `std`.
- `iron-crypto` checks that no code outside the funnels multiplies a base
  point directly. Whitespace is removed before matching, since the offending
  calls were split across lines. The test fails against the old
  `ecdsa.rs`.
- The new Ed25519 paths are compiled into the ordinary test suite, which runs with
  `std` and so would otherwise never execute them: the windowed multiplication
  against the ladder on scalars chosen for the recoding's carries, and the
  table-free verification against both the tabled one and two independent
  ladders. Dropping the sign, shifting the lookup by one, or swapping
  addition for subtraction each fails them. Separately, an `ic-ec` built
  without `std` passes the RFC 8032 self-test and produces the `std` build's
  public keys and signatures byte for byte, over 64 keys.
- The basepoint's constant limbs were computed outside the crate from
  `y = 4/5` and the curve equation. A test holds every coordinate, `T`
  included, to what decompressing the RFC 8032 encoding gives. A wrong `T`
  compresses correctly and corrupts every addition, so compression alone would
  not catch it; the test fails when one limb of `T` is off by one.

## 0.2.0

Contains breaking changes to `ic-pkix` and `ic-ec`, and removes a handful of
public items elsewhere; see below. Under Cargo's rules for `0.x` versions that
makes this 0.2.0 rather than 0.1.4: a `0.1` requirement will not pick it up
until the dependent says so.

### Fixed

- **`ic-pkix` refused P-521 keys as an unsupported curve.** `ic-ec` implements
  P-521 -- ECDSA and ECDH -- and the encoding layer had simply never been told
  its OID, so a P-521 key could be generated and used but not exported or read
  back. It now parses and writes P-521 SPKI, PKCS#8 and bare SEC1 keys.
- **An EC key on a curve this build does not implement was an error**, though
  `Unsupported` exists precisely so such keys are reported rather than refused
  and the caller can say what it found. Every other unimplemented algorithm
  already worked that way. These keys now come back as `Unsupported`, carrying
  the named curve's OID rather than `id-ecPublicKey` -- which every EC key
  shares, and which would say nothing about what is missing. As before, the
  writer will not emit one.

- **`recommend` chose AES-GCM on 32-bit x86, where it is about forty times
  slower than ChaCha20-Poly1305.** The ontology reported
  `hardware-accelerated` whenever the CPU had AES-NI and `PCLMULQDQ`, but the
  carry-less GHASH exists only on x86-64 with `std`; everywhere else AES-GCM
  runs on the portable GHASH. Measured on one machine, a 32-bit build ran
  AES-256-GCM at 10.7 MiB/s against 450 MiB/s for the ChaCha20-Poly1305 it
  had rejected. The report and the dispatch now use one predicate,
  `ic_core::cpu::has_ghash_clmul`, so they cannot disagree. The same fix
  covers a `no_std` x86-64 build with `+aes,+pclmulqdq`. x86-64 with `std` is
  unaffected.
- **CI had been failing on every push since before 0.1.2**, so none of its
  checks were gating anything. The four `no_std` builds failed on an unused
  import inside `ic-ec`'s generator-table macro, which only CI's
  `-D warnings` turns into an error. The zero-dependency job never ran its
  check at all: the scripts in `scripts/` were committed without the
  executable bit. Both are fixed, and every job passes locally under CI's
  flags.

### Breaking

- `ic_pkix::KeyAlgorithm` gains a variant, `EcP521`. The enum is not
  `#[non_exhaustive]` -- deliberately, since its documentation asks callers to
  match on it exhaustively -- so a downstream `match` without a wildcard arm
  stops compiling. The fix on that side is one arm; `ic-cli` needed exactly
  that.
- `PublicKeyInfo::from_der` and `PrivateKeyInfo::from_der` now return
  `Ok(Unsupported { .. })` for an unknown curve where they returned `Err`. A
  caller that relied on the error to reject such keys still rejects them if it
  handles `Unsupported`, which it already had to for unknown algorithms.
- **`ic-ec`'s internals are no longer public.** The `field`, `scalar` and
  `nist` modules were `pub` because the crate's own benchmarks reached into
  them, which made every limb layout and helper part of the semver contract.
  The supported API -- `Ed25519`, `X25519`, `P256`, `P384`, `P521` and their
  key types -- is unchanged. Going with them: `EcdsaCurve::SIGNATURE_ID`, which
  duplicated `Algorithm::ID` and was never read, and the `generator_table_for!`
  macro, which was `#[macro_export]`ed to the crate root and expanded to paths
  that are now private. `ed25519::Point::mul_scalar_vartime` is crate-private.
- The `*_for_bench` functions in `ic-ec` sit behind a new `bench-internals`
  feature, which `bench/` turns on. Nothing under that feature is covered by
  semver.
- `ic_mlkem::sample::matrix_xof` and `ic_mldsa::sample::{matrix_xof,
  bounded_xof}` were `#[doc(hidden)] pub` -- hidden, but still public API --
  and nothing outside their own tests called them. They are now test-only.

### Documentation

- **The post-quantum crates' front pages on docs.rs still called them
  unverified.** 0.1.3 corrected their crates.io descriptions and `SECURITY.md`,
  but `ic-mldsa`, `ic-mlkem` and `ic-cipher`'s AES-GCM-SIV module docs, the
  `iron-crypto` front page, `ic-vectors`, and the SBOM `ic sbom` emits all
  still said "experimental" or "no signature scheme yet". All now state what
  the ontology records: 50 ACVP cases for ML-KEM-768, 55 for ML-DSA-65, all 50
  RFC 8452 cases for AES-GCM-SIV.
- The facade says that ARM gets hardware AES but not hardware GHASH, so
  AES-GCM there is limited by a portable GHASH and `recommend` prefers
  ChaCha20-Poly1305.

- `der::Writer` now says, with a doctest, that fields are pushed last first.
  Pushing them in their natural order produces valid DER with the fields
  reversed -- it parses, and means something else -- and nothing said so. The
  writer's direction is unchanged: building backwards is what lets it emit a
  length before the content it measures, in one pass and without allocating.

### Tests

- Keys generated by OpenSSL 3.5.7 are now checked in both crates. `ic-pkix`
  round-trips OpenSSL's P-521 SPKI and PKCS#8 byte for byte, which exercises the
  writer's long-form lengths against an independent encoder; the existing
  round-trip tests only ever compared this crate's output with itself.
  `iron-crypto` confirms that `ic-ec` derives OpenSSL's public point from
  OpenSSL's private scalar, and that a signature made with the parsed key
  verifies under OpenSSL's separate public-key file.
- Two guards in `ic-cli`, so the drift above cannot recur silently. One holds
  every crate description, every module doc and every SBOM entry to the
  ontology: a crate with no `experimental` entry may not describe itself as
  untested. Run against 0.1.3's docs it reports fourteen claims in eight
  files. The other checks that each crate's `std` feature turns on `std` in
  every dependency that has one. A workspace build unifies features, so a
  missing forward never shows up in the test suite -- only for a caller who
  depends on that crate directly, who would silently lose SHA-NI, AVX2 and
  AES-NI.
- `iron-crypto` checks the ontology's backend report against what AES-GCM
  actually runs. `ic-ontology` cannot see `ic-cipher`, and its own test
  compared the report with the formula it was computed from, so it passed on
  32-bit x86. The new test fails there against the old predicate and passes
  against the new one. CI gains a native 32-bit x86 job so it runs there.

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
