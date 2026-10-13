# Changelog

All twenty-two crates share a version and are released together, so this covers
all of them.

## Unreleased

The next release is 0.3.0: the changes under **Breaking** change signatures
every caller of a hash function uses.

### Breaking

- **Hashes, XOFs and MACs refuse in the error state.** They were the gate's
  stated limit: `Digest::finalize` had no error to return, so a hash went on
  working after the module had failed. Now every interface that produces
  output returns a `Result` and refuses with `ModuleErrorState`:
  `Digest::finalize` and `digest`; `Xof::finalize_xof`; SHAKE's `xof` and
  `XofReader::read`; cSHAKE's `finalize_xof` and `xof`; TupleHash's and
  ParallelHash's `finalize`, `hash` and `hash_xof`; BLAKE3's `finalize`,
  `hash`, `keyed_hash`, `derive_key` and `Blake3Reader::fill`;
  `Mac::finalize`; KMAC's `finalize`, `finalize_xof`, `mac` and `mac_xof`;
  and ML-KEM's `keygen_deterministic` and `encapsulate_deterministic`.
  BLAKE2's already returned one and now also refuses. Creating a hasher and
  `update` are unchanged.

  To migrate, add `?` where the output is used:
  `let d = Sha256::digest(data)?;`.

  The primitives call one another through `ic_core::traits::internal`, a
  hidden module holding the old infallible traits; each primitive refuses at
  its own entry instead. It is not API and not covered by semver.
  `crates/ironcrypto/tests/error_state.rs` no longer exempts hashes: every
  implemented algorithm must be shown refusing.
- **ParallelHash refuses a zero block size** with `InvalidParameter`. It
  used to panic, on a caller's input.

### Added

- **Wycheproof's primality cases** run against RSA key generation's
  Miller-Rabin test, through a hidden test-only `ic_rsa::key::probable_prime_be`:
  283 of 317 agree with their label, 14 signed values are skipped and counted,
  and 20 composites that the fixed bases accept are listed by tcId as known
  failures, since key generation's candidates come from the DRBG.
- **Prepared ML-KEM keys**, for every parameter set:
  `PreparedEncapsulationKey` and `PreparedDecapsulationKey` in
  `ic_mlkem::{kem512, kem, kem1024}`, aliased at the crate root as
  `MlKem768PreparedEncapsulationKey` and so on. `new` takes the key bytes
  once: the encapsulation key gets FIPS 203's modulus check (an invalid key
  is refused there, with `MalformedEncoding`), and the decapsulation key the
  hash check; both then hold `H(ek)`, `t` and the expanded matrix `A^T`, so
  `encapsulate`, `encapsulate_deterministic` and `decapsulate` do only the
  per-message work. The output is byte for byte the unprepared functions',
  which tests hold them to over random keys and messages on both the
  lane-scheduled and the streaming form, and through the ACVP encapsulation
  vectors and Wycheproof ML-KEM, every modulus-overflow key included. No
  allocation: about 6 KiB (encapsulation) and 7.5 KiB (decapsulation) for
  ML-KEM-768, up to 12 KiB for ML-KEM-1024. The decapsulation key wipes `s`
  and `z` on drop. Everything refuses in the error state, constructors
  included.

- **`crypto_seal` refuses a nonce the agent supplies** unless it also sets
  `protocol_nonce: true`. Omitting the nonce, which draws one that is never
  reused, is the path an agent should take; passing its own now has to be
  said on purpose. AGENTS.md and `ic_ontology::RULES` say so.
- **Every test suite Graviola runs, run here.** NIST CAVP's SHA-2, SHA-3,
  SHAKE and HMAC response files in full, Monte chains included, and
  Wycheproof's ML-KEM (all three parameter sets, where Graviola runs one),
  ECDSA in P1363 form and under other hashes, and AES-GMAC: about 12,000
  cases from `scripts/gen_coverage_vectors.py`, every source pinned by
  SHA-256, run by `ironcrypto/tests/coverage_vectors.rs`. All pass.
- **`bench -- graviola`**, a per-operation comparison with Graviola 0.4.1.
- **The P-256 compiled-code probes gate on the 32-bit targets too.** They
  were built and reported there, not gated. Cortex-M0's `__aeabi_lmul` is
  now disassembled from the toolchain's `compiler_builtins` and checked like
  a probe (it is branch-free), and the Montgomery loop's counter branches and
  RISC-V's constant `memset` are excused by rules about the surrounding
  instructions, each capped at the number that was read; a branch on a
  value, a `memset` of a computed length, or one more loop fails. Turning the
  constant-time select into a branch failed all four targets. `check-ct.py`
  needs `rustup component add llvm-tools` for the M0 check, and fails
  without it.
- **A build with only the FIPS-approved algorithms**, `--cfg ic_approved_only`
  in `RUSTFLAGS` and `RUSTDOCFLAGS`. Approved mode used to refuse a
  non-approved algorithm only through `ic_fips::check` and `guarded`; a direct
  call went through. In this build the twenty-one algorithms approved mode
  does not permit are not compiled, so a call to one does not compile:
  ChaCha20-Poly1305 and its relatives, AES-GCM-SIV, Shamir sharing, BLAKE2 and
  BLAKE3, Argon2, scrypt, bcrypt, yescrypt, passphrase sealing,
  `ic_kdf::password`, X25519, Ed25519, hashing to P-256, the OPRF, OPAQUE and
  HPKE. Their ontology entries report `excluded`, `recommend` answers every
  policy as a FIPS one, the CAST table drops to 64 with its own integrity tag,
  the module comes up in approved mode and refuses to leave it, and
  `ic_fips::check` gives the reason as `NotApprovedInFipsMode`. Every
  operation that can refuse does so until `ic_fips::initialize` has passed
  the self-tests, so a direct call can no longer run untested. An Ed25519 key,
  which arrives as data, is refused at run time by `ic_sig` and `ic_rustls`,
  whose provider offers only AES-GCM, P-256 and P-384, ECDSA and RSA. A cfg
  rather than a Cargo feature: removing API is not additive, and a feature any
  dependency enabled would strip the algorithms from every crate in the graph.
  Three `compile_fail` examples in the `ironcrypto` documentation show the
  absence, and `scripts/approved-only.sh` builds and tests this configuration
  in the local gate and in CI. It does not make the module validated.
- **OPAQUE (RFC 9807)**, as `ic_hpke::opaque`: password authentication in
  which the server never sees the password, and a stolen database cannot be
  attacked without also the server's key. OPAQUE-3DH over P-256 with HKDF,
  HMAC and SHA-256, the second of RFC 9807's recommended configurations,
  with Argon2id or scrypt as the key stretching function. Registration,
  the three-message login with its session key and export key, and fake
  records so that unknown identifiers cannot be told from known ones.
  Every message and key matches RFC 9807's P-256 vectors, C.1.5, C.1.6
  and the fake-record C.2.3; every byte of every message changed in turn
  makes the login fail.
- **Oblivious pseudorandom functions (RFC 9497)**, as `ic_ec::oprf`, with
  the P256-SHA256 suite, in all three modes: the base OPRF, the verifiable
  VOPRF, whose server proves which key it used, and the partially
  oblivious POPRF, which binds a public `info` -- how a password-hardening
  service tweaks its key per user or per epoch. Batching, with the
  batched proof. Elements are validated on receipt.
- **Hashing to P-256 (RFC 9380)**, as `ic_ec::hash_to_curve`:
  `expand_message_xmd` with SHA-256 and `P256_XMD:SHA-256_SSWU_RO_`, in
  constant time, since the input is usually a password. Both are checked
  against every P-256 vector in RFC 9380 appendices J.1.1 and K.1 and RFC
  9497 appendix A.3, stage by stage, and six ways of getting them wrong
  each fail.
- **scrypt (RFC 7914)**, as `ic_kdf::scrypt`, with PHC strings in
  `ic_kdf::scrypt::phc` in the form the RustCrypto `scrypt` crate writes.
  The IETF's password-storage guidance recommends it where Argon2 is not
  available; it is also what PBES2-scrypt keys, many wallets and yescrypt
  use. Checked against all four of RFC 7914's vectors -- the 1 GiB one in
  a release build -- eight of OpenSSL's, and the RustCrypto crate's PHC
  strings both ways. Its memory access depends on the password, by
  design, as Argon2d's does; the ontology says so.
- **bcrypt and yescrypt verification**, as `ic_kdf::bcrypt` and
  `ic_kdf::yescrypt`, for moving stored hashes to Argon2id: check the
  password at the next login, then rehash. Neither makes new hashes.
  bcrypt takes `$2a$`, `$2b$` and `$2y$` and refuses `$2x$`; yescrypt
  takes `$y$` in the default, WORM and classic flavors with `p` and `t`,
  and `$7$`, which is what libxcrypt writes for current Debian, Ubuntu
  and Fedora. Both refuse a stored hash that would cost too much before
  doing any work: bcrypt above cost 16, yescrypt above 4 GiB or eight
  passes through it. Their table lookups depend on the password, by
  design; the ontology marks both verify-only and says why. Checked
  against 51 verdicts of pyca/bcrypt and 34 of libxcrypt.
- **`ic_kdf::password`**, one door for stored hashes of any of those
  formats: `verify` reads the prefix, checks the password with the module
  that owns the format, and says whether to replace it with Argon2id at
  the caller's parameters; `verify_and_upgrade` also returns the new PHC
  string. An Argon2 hash is replaced when it falls short of the
  parameters; scrypt, bcrypt and yescrypt hashes always are.
- **`needs_rehash`** for Argon2 and scrypt PHC strings: whether a stored
  hash falls short of current parameters and should be made again after
  the next successful login, which is how NIST SP 800-63B-4 and the IETF
  guidance ask for costs to rise over time. The Argon2 form can also
  require a given `keyid`, so a rotated pepper reaches every stored hash.
- **Everything the `argon2` crate offers, in `ic_kdf::argon2`.** Version 1.0
  beside 1.3, so hashes made before RFC 9106 verify (`argon2_versioned`);
  Argon2 over memory the caller provides, for targets with no allocator
  (`argon2_with_memory`, `fill_memory`, the public `Block`);
  `Argon2Params::DEFAULT` (19 MiB, t=2, p=1) and `block_count`; and PHC
  strings in `ic_kdf::argon2::phc` -- `hash_password` under a drawn salt,
  `verify_password` in constant time, a secret and its `keyid`, associated
  `data`, and `verify_password_bounded` for a hash from elsewhere, since a
  hash's parameters decide what verifying it costs. Lanes run on threads
  under `std`, the compression function uses AVX2 where the CPU has it, and
  the arena is allocated as pages the operating system zeroes lazily.
  Against argon2 0.6.0 with its `parallel` and `zeroize` features, on one
  x86-64 machine: 19 MiB over two passes, 10.6 ms against 12.2; 64 MiB over
  three passes and four lanes, 34 ms against 31; 256 MiB over one pass and
  four lanes, 86 ms against 65 -- where this was 130 before. Checked
  against libargon2 at both versions, libsodium's PHC strings, and
  argon2 0.6.0's outputs. Two behaviours differ from it on
  purpose: a PHC string with no `v=` field is read as version 1.0, as
  libargon2 reads it, and parsing accepts only the canonical form. A
  failed allocation for the memory is now an error rather than an abort,
  since a stored hash chooses its size.
- **XChaCha20-Poly1305**, as `ic_cipher::XChaCha20Poly1305`: ChaCha20-Poly1305
  with a 192-bit nonce, long enough to draw at random for every message, so
  nothing has to keep a counter. `seal_with_random_nonce` draws the nonce and
  returns it. It is the construction libsodium, Go and Tink implement, from
  draft-irtf-cfrg-xchacha-03, an Internet-Draft that expired without becoming
  an RFC. Checked against the draft's HChaCha20, XChaCha20 and AEAD vectors
  and all 315 of Project Wycheproof's cases. Not FIPS-approved, and refused in
  approved mode. Also through `ic seal`, `ic open` and their MCP tools.
- **Passphrase sealing**, as `ic_kdf::passphrase`: a secret at rest under
  a passphrase, such as a CA's signing key, in one call each way. Argon2id
  derives the key and XChaCha20-Poly1305 seals, in a versioned container
  whose header -- parameters, salt, nonce -- is authenticated. Both sides
  refuse Argon2 parameters under a floor of 19 MiB over two passes, and
  `open` refuses parameters past a ceiling before deriving anything, so a
  hostile container cannot force an unbounded allocation. A second
  implementation over libsodium and the Argon2 reference code sealed the
  test containers. Not FIPS-approved. Asked for by AgentMesh, so that it
  does not compose its own.
- **URI alternative names in issued certificates**, as
  `SubjectAltName::Uri`: an absolute URI, such as a SPIFFE ID or an agent
  handle, written as given. Asked for by AgentMesh, which names each agent
  by one.
- **PKCS#10 certification requests**, written by `ic_pkix::csr`: the key
  holder's half of asking a CA for a certificate, signed through any signer
  as certificates are. Reading a request is the CA's side and is not here.
  Both the request and a certificate with a URI name are checked byte for
  byte against OpenSSL's.
- **BLAKE2s (RFC 7693) and BLAKE3**, as `ic_hash::Blake2s` and
  `ic_hash::Blake3`. BLAKE2s is BLAKE2b's 32-bit sibling, which WireGuard
  and Noise use. BLAKE3 offers a hash, a keyed hash, a key derivation
  function and an extendable output; this is the portable serial form,
  the same tree as the SIMD implementations without their speed on large
  inputs. Checked against the BLAKE2 team's 256 keyed BLAKE2s vectors,
  RFC 7693's BLAKE2s vector and its Appendix E self-test -- now also run
  for BLAKE2b -- and the BLAKE3 team's vectors: 35 input lengths to
  100 KiB in all three modes, to 131 bytes of output.

### Security

- **Ed25519 signing no longer branches on whether a secret scalar is at
  least L.** `scalar::conditional_subtract_l` was branch-free in source, and
  under LTO rustc 1.99 compiled its masked merge to a `js` on the borrow:
  nine jumps per signature on the nonce and on S, found by the Valgrind
  harness. The borrow and the mask now pass through barriers, and the
  reduction and `mul_add` are written straight-line; Valgrind reports 0.
  Two compiled-code probes, `ct_ed25519_reduce_wide` and
  `ct_ed25519_mul_add`, hold this on all four gated targets, and fail on all
  four with the barriers removed. One new, narrow rule excuses Cortex-M0's
  jumps over literal pools in those two probes, with a ceiling.

### Changed

- **The constant-time gate covers P-256's field and scalar arithmetic.**
  Sixteen compiled-code probes check the operations hashing to the curve
  and the OPRF apply to password- and key-derived values; the checker now
  follows calls into bodies it can read instead of rejecting them. They
  gate on x86-64, where they have no branch or call. On 32-bit targets
  they are reported, not gated: what remains there is the Montgomery
  loop's counter, a fixed-size `memset` and M0's runtime multiply, each
  read and recorded in `docs/CONSTANT_TIME.md`. Byte-to-limb conversion
  now works in whole words, which removed the last branch on x86-64 and
  a variable-shift branch on 32-bit RISC-V. `ic timing` gained
  `hash-to-curve`, `oprf-evaluate`, `blake2s-keyed` and `blake3-keyed`.
- **Ontology entries for Blowfish, the Salsa20/8 core and HChaCha20**,
  each `excluded` as a primitive of its own: they are implemented only
  inside bcrypt, scrypt and yescrypt, and XChaCha20-Poly1305, which now
  name them as what they are built on.
- **scrypt's password-dependent memory access is a serious constraint**,
  as bcrypt's and yescrypt's are, not an advisory one: an agent choosing
  scrypt must say so.
- **bcrypt wipes its key schedule's running block** after use, as it
  already wiped the schedule itself.
- **The frameworks knowledgebase follows the new work.** CWE-916,
  password hashes with too little computational effort, is a new control,
  met by `needs_rehash` and `ic_kdf::password`. ATT&CK T1110, brute force,
  now names scrypt and OPAQUE, whose stolen database cannot be attacked
  offline without the server's key. CWE-208's evidence describes the new
  timing targets and the P-256 compiled-code probes, and why bcrypt, scrypt
  and yescrypt stand outside both.
- **`ic lint` no longer reports scrypt's single PBKDF2 pass.** The
  iteration check skipped nothing, so ic-kdf's crate-private
  `pbkdf2::derive`, which scrypt and yescrypt run once by definition, was
  reported as a password hashed at one iteration. Callers cannot reach that
  form; the public `pbkdf2` at one iteration is still reported. A zeroed
  buffer bound to a key's name is no longer reported in widths other than
  bytes either, as `let mut key_words = [0u32; 8];`.
- **Ed25519 verification is strict.** It now refuses a public key or a
  signature R of small order, and a non-canonical encoding of either, as
  ed25519-dalek's `verify_strict` and libsodium do. RFC 8032's cofactorless
  equation alone accepts a signature under the identity key for any
  message, and this accepted an encoding whose y field is p or more, which
  section 5.1.3 says must not decode. No key or signature a correct signer
  makes is affected. The degenerate encodings are derived from the curve
  equation and checked against libsodium. Reported by the TUNDRA session.
- **A dead-code warning on Rust 1.90 is gone**: an associated constant
  nothing read. A dependent that denies warnings can now build this.
  Reported by the TUNDRA session.
- **PBKDF2 is about 1.7 times faster.** It keyed its MAC again on every
  iteration; it now keys it once and clones it, which for HMAC removes two of
  the four compressions each iteration took. PBKDF2 applies one PRF under one
  key, so the output is unchanged: the test that rebuilds the XOR chain from
  HMAC directly, and Project Wycheproof's cases, hold it. HMAC-SHA-512 at
  600 000 iterations went from about 355 ms to about 200 ms on an x86-64
  machine, measured before and after a few minutes apart. Reported by the Lit
  project, which found ic-hash's SHA-512 faster than RustCrypto's and this
  PBKDF2 slower than theirs.

### Performance

- **P-384 is about 1.5 times faster on x86-64, and its ECDH is level with
  Graviola.** On a Ryzen 9 9900X (Zen 5), `bench` with the new
  `graviola-p384` mode (P-384 ECDH, signing and verification for both
  libraries, also in `graviola`), the master branch before this work
  (9f7d64b) and this build run alternately, five rounds each, with Graviola
  0.4.1 in every run. Another workload held the machine near full load
  throughout, which raised every figure, Graviola's from about 80 to
  103-138 us for ECDH; so the table gives each range, best to worst, and the
  ratio to Graviola within the same run, which load moves less:

  | operation | before | after | Graviola | before / Graviola | after / Graviola |
  |---|---|---|---|---|---|
  | P-384 ECDH | 183-232 | 117-141 | 103-138 | 1.61-2.03 | 0.94-1.25 |
  | ECDSA P-384 sign | 76-88 | 46-58 | 125-155 | 0.56-0.68 | 0.30-0.42 |
  | ECDSA P-384 verify | 206-255 | 160-203 | 228-300 | 0.90-1.00 | 0.58-0.79 |

  ECDH is parity, not a lead: the ratio lands either side of one. It is
  also not quite like for like, in Graviola's favour: Graviola parses the
  peer's key and builds its window table outside the timed loop, where
  `EcdhP384::agree` decodes, validates and builds its window in every call.

  Where the time went, measured first: ECDH already ran the one-block
  MULX/ADX point formulas, 385 doublings and 77 additions; those were
  about 85 percent of it and inversion by Fermat about 10. Every field
  multiplication in them was CIOS generic in the modulus, 72 `mulx`, with
  squaring done as multiplication and each final correction copied through
  memory. Now (`scripts/gen_p384_x86_point.py`, regenerated): Montgomery
  reduction by P-384's shape, two `mulx` per word by constants instead of
  six; a squaring of its own, 21 `mulx` for the product where
  multiplication takes 36; corrections by masked addition in registers;
  and the doubling's small multiples folded into three fused `c*a - d*b`
  operations, eight additive steps where it had fifteen. A doubling went
  from 2,626 instructions to 2,426, near Graviola's; its multiplication is
  285 instructions and squaring 226, against s2n-bignum's 263 and 230. `Fp`
  multiplies and squares through the same blocks, and P-384's field
  inverts by Bernstein-Yang divsteps on 64-bit targets, 18 batches of 62
  for the 1111 steps their Theorem 11.2 requires at 384 bits: 2.4 us where
  the addition chain took 6.8 to 10.9, and the old windowed exponentiation
  about 20. 32-bit targets use the addition chain. The variable-base window
  and the generator table are read by the SSE2 scan P-256 uses. Signing and
  verification gain from the same field and the scan.

  Tested against the generic arithmetic: each field operation on every pair
  of 74 edge values, on sums and differences landing on 0, p - 1, p and
  p + 1, on a million random pairs, and on operands built so that every word
  of the reduction takes its rare carry; the divsteps against a branching
  transcription of the paper's definition. See `docs/FIPS.md`. Four new
  x86-64 compiled-code probes: the specialised squaring and the three
  divsteps inversions, P-256's two among them, whose 59-step batches and ten
  rounds are now written out too. The first run of the P-384 inversion probe
  found a branch the new code had introduced, and it was removed before
  landing; see `docs/CONSTANT_TIME.md`. P-256's inversion time is unchanged
  (1.09-1.50 us against 1.23-1.61 for the scalar ring, interleaved).

- **ML-KEM-768 encapsulation to a prepared key takes about half the time.**
  On a Ryzen 9 9900X (Zen 5), best of four runs of `bench graviola`, the
  builds before and after run alternately minutes apart, with Graviola
  0.4.1 alongside, in microseconds (spread across runs in brackets):

  | operation   | unprepared | prepared        | Graviola        |
  |-------------|------------|-----------------|-----------------|
  | encapsulate | 5.2 (5.2-6.2) | 2.6 (2.6-3.2) | 4.6 (4.6-5.5) |
  | decapsulate | 6.1 (6.1-6.7) | 4.4 (4.4-4.9) | 5.9 (5.9-6.3) |

  Graviola's encapsulation key holds `A^T` too, parsed once outside the
  loop; its `DecapKey` always does. The unprepared functions are unchanged
  (parity with the build before). The keygen row is relabelled, since
  IronCrypto's `keygen` runs the pairwise-consistency test and Graviola's
  `generate` does not, and a like-for-like row is added:
  `keygen_deterministic` from one 64-byte operating-system draw, 6.4 us
  against Graviola's 7.5.

- **AES-GCM on x86-64 runs as one fused pass.** `H` and its powers are
  computed once per key instead of once per call, and counter mode and GHASH
  are stitched: the previous group's ciphertext is multiplied in between the
  AES rounds of the next, with one reduction per group. Three kernels, chosen
  at run time: AES-NI with `PCLMULQDQ`, eight blocks at a time; `VAES` and
  `VPCLMULQDQ` on 256-bit registers, sixteen; and the same on 512-bit
  registers, thirty-two, where the CPU has AVX-512. Sealing with AES-256-GCM
  on a Ryzen 9 9900X (Zen 5), before and after, best of runs taken minutes
  apart, with Graviola 0.4.1 measured alongside:

  | message | before    | after      | Graviola   |
  |---------|-----------|------------|------------|
  | 4 MiB   | 5.4 GB/s  | 25.4 GB/s  | 17.4 GB/s  |
  | 1 KiB   | 3.3 GB/s  | 13.0 GB/s  | 10.0 GB/s  |
  | 64 B    | 0.58 GB/s | 1.15 GB/s  | 0.82 GB/s  |

  AES-128-GCM: 6.1 to 28.7 GB/s at 4 MiB, 3.7 to 17.0 at 1 KiB, 0.65 to
  1.57 at 64 bytes. The 512-bit loops are inline assembly, because their
  intrinsics need Rust 1.89 and the MSRV is 1.87. Every kernel is held to an
  independent byte-at-a-time GCM over the portable AES and GHASH at every
  length to 600 bytes and beyond, and the portable path, `no_std` builds and
  the failure behaviour of opening -- nothing released on a bad tag -- are
  unchanged.
- **ML-KEM is five to nine times faster on x86-64**, at every parameter
  set. Best of nine batches on a Ryzen 9 9900X (Zen 5), the old and new
  builds run alternately minutes apart, in microseconds:

  | | before | after | Graviola 0.4.1 |
  |---|---|---|---|
  | ML-KEM-768 keygen, no pairwise test | 27.5 | 6.0 | 7.6 |
  | ML-KEM-768 keygen, with it | 106 | 18.7 | -- |
  | ML-KEM-768 encapsulate | 40.4 | 5.4 | 4.6 |
  | ML-KEM-768 decapsulate | 46.8 | 6.1 | 5.8 |
  | ML-KEM-512 keygen / encapsulate / decapsulate | 18.6 / 25.9 / 30.6 | 4.0 / 4.1 / 4.2 | -- |
  | ML-KEM-1024 keygen / encapsulate / decapsulate | 45.8 / 72.0 / 72.5 | 8.3 / 7.9 / 8.7 | -- |

  `keygen` runs the FIPS 140-3 pairwise consistency test, an encapsulation
  and a decapsulation, and Graviola's does not; `keygen_deterministic` is
  the comparable row. Graviola's encapsulation key holds `A^T`, expanded
  once when the key is parsed, and its decapsulation neither expands the
  matrix nor checks `H(ek)`; this API takes key bytes and does all of it on
  every call. Graviola parsing the key on every call encapsulates in 8.7.
  Decapsulation landed either side of Graviola's across runs and is parity.

  Where the time went, and what replaced it:

  - Keccak was most of it. `ic-hash` gains a four-way Keccak-f[1600] -- four
    states in AVX2 registers, with AVX-512VL's rotate and three-input logic
    where present, emitted with `asm!` because their intrinsics postdate the
    1.87 MSRV -- as a hidden, internal type, `KeccakX4`. ML-KEM runs every
    Keccak call an operation makes through a lane scheduler, a queue per
    lane: in encapsulation `H(ek)` occupies one lane while the other three
    expand all of `A^T` in the same permutations, and decapsulation's hash
    check, `J(z || c)`, `A^T` and the re-encryption noise share one schedule.
  - The NTT, inverse NTT, base multiplication, reductions, compression, the
    12-bit decode, CBD for eta 2 and the SampleNTT rejection step have AVX2
    forms, each producing the portable code's integers coefficient for
    coefficient and compared exactly against it.
  - Portable gains, for every target: byte encoding and decoding eight
    coefficients at a time instead of a bit at a time, CBD a word at a time,
    the sponge squeezing whole lanes instead of a byte per loop trip, the
    scalar permutation compiled for BMI1/BMI2 where present, and the
    encapsulation key's modulus check as a test of every 12-bit field
    against `q`, the same predicate as FIPS 203's round trip.

  The vector paths need `std`, for runtime detection; `no_std` builds keep
  the streaming code, which never holds the matrix. Hosted x86-64 builds now
  hold `A^T` and the noise during an operation: peak stack for ML-KEM-768
  decapsulation went from 8.7 to 12.9 KiB, and for key generation with its
  pairwise test from 13.6 to 17.6 KiB.

  No result changes. The ACVP key-generation and encapsulation vectors for
  all three sets and the OpenSSL interoperability cases pass, and the
  lane-scheduled path is compared with the streaming one and the held-matrix
  reference, through the whole KEM, for every set.

- **X25519 and Ed25519 are faster than Graviola 0.4.1 on x86-64.** Two
  backends for GF(2^255 - 19), chosen at run time on the CPU's features alone,
  with the portable field as fallback and reference:
  - four 64-bit limbs on `MULX`/`ADCX`/`ADOX` (`ic-ec/src/fe64.rs`), with
    X25519's ladder step and each Edwards group operation one assembly
    block, and a constant-time Bernstein-Yang divstep inversion in place of
    Fermat's chain;
  - four field elements at once on AVX-512 IFMA (`ic-ec/src/f51x4.rs`):
    a doubling is one four-lane squaring and one four-lane multiplication,
    a mixed addition two multiplications, X25519's step three.

  Also: X25519's ladder chooses its doubling input by selection instead of
  swapping both points; signing runs its odd and even digits as two
  accumulators; one-shot verification decompresses the key and R with their
  exponentiations interleaved. Ryzen 9 9900X (Zen 5, IFMA), `bench/`'s
  `graviola` mode, master and this build alternated four rounds each, best
  and worst, the machine shared with other builds throughout:

  | | before | after | Graviola 0.4.1 |
  |---|---|---|---|
  | X25519 agreement | 22.0-23.7 us | 11.7-12.2 us | 13.2-13.6 us |
  | Ed25519 sign, cached key | 11.7-13.1 us | 4.6-4.8 us | 5.3-6.0 us |
  | Ed25519 verify, from bytes | 35.0-37.8 us | 17.3-17.6 us | 22.4-24.1 us |

  On a quieter run earlier the day, before: 21.6-21.9, 8.6-8.7 and
  27.6-28.4 us against Graviola's 12.8-12.9, 4.2 and 17.2. Every operation is
  compared with the portable field's (millions of random and edge-value
  field operations; every ladder against RFC 7748's 1,000-iteration vector;
  each assembly block against the formula it transcribes), and the whole
  suite also passes with both backends removed by `--cfg ic_ec_portable`.
  Thirteen x86-64 compiled-code probes hold the new secret-handling code to
  having no branch. `ic-ec` is `deny(unsafe_code)` rather than `forbid`,
  allowed in `fe64` and `f51x4` only. `ic_ec::curve25519_backend()` reports
  which backend runs, and `ic_core::cpu::has_bmi2_adx()` is new.

- **RSA-2048 signing is about five times faster, and verification about
  four.** The private exponentiation uses a fixed four-bit window, a quarter
  of the multiplications, with the multiplier read from its table by a
  masked scan of every entry. On x86-64, whole exponentiations at 1024, 1536
  and 2048 bits run on AVX-512 IFMA in radix 2^52, and single Montgomery
  products on `MULX`/`ADCX`/`ADOX` assembly, each chosen at run time with the
  portable path as fallback and reference; `ic_rsa::uint::backend_for` says
  which runs. `R^2` per key takes a few doublings and about ten squarings
  instead of 128 doublings a word. CRT and its verify-after-sign check are
  unchanged, and nothing branches on or indexes by the exponent. Against
  Graviola 0.4.1 (s2n-bignum) on an AMD Ryzen 9 9900X, `bench graviola`,
  best of several runs:

  | | before | after | Graviola |
  |---|---|---|---|
  | PKCS#1 v1.5 sign | 1290 us | 255 to 300 us | 345 us |
  | PSS sign | 1688 us | 265 to 300 us | 365 to 400 us |
  | PKCS#1 v1.5 verify | 33.0 us | 7.5 to 8.5 us | 9 to 10.5 us |

  The machine had other builds running throughout, and Graviola's own figures
  moved by a third between runs; under the heaviest load the margin on PKCS#1
  v1.5 signing narrowed to about 1.1 times. The before and after columns were
  taken minutes apart under the same load. The portable path, used on every
  other CPU, is about twice as fast as before from the window alone.
- **SHA-3 is about 10% faster** on x86-64 without an and-not instruction:
  Keccak-f holds six lanes complemented, so chi needs one NOT a plane instead
  of five. From 654 to about 690 MiB/s for SHA3-256 over 4 MiB, against
  Graviola's 690 to 735 -- within noise of parity rather than ahead.
- **A short HMAC-SHA256 is about 13% faster**: 265 to 230 ns for 200 bytes,
  measured A/B. `mac` runs its own one-pass path, issuing the outer pad's
  compression before the message so it overlaps the inner hash, and SHA-256
  writes its padding into the block buffer instead of a copy. At parity with
  Graviola, from 1.16 times slower.
- **P-256 is about three times faster, and on x86-64 at or ahead of
  Graviola.** Microseconds per operation on a Ryzen 9 9900X (Zen 5), best of
  four interleaved rounds of the master branch before this work and of this
  build, Graviola 0.4.1 measured in the same runs (its range across the two
  binaries in brackets):

  | operation | before | after | Graviola |
  |---|---|---|---|
  | P-256 ECDH | 68.4 | 24.8 | [25.7, 26.3] |
  | ECDSA P-256 sign | 28.0 | 7.5 | [7.8, 8.0] |
  | ECDSA P-256 verify | 81.9 | 26.8 | [30.0, 30.6] |
  | P-256 public key | 19.4 | 5.7 | -- |
  | P-384 ECDH | 233 | 135 | [80, 80] |
  | ECDSA P-384 sign | 98 | 50 | [86, 88] |
  | ECDSA P-384 verify | 276 | 145 | [154, 171] |

  ECDH and signing lead by three to six percent, which is within the noise
  of a shared machine: call them parity. Verification leads by more than
  ten. P-384 signing and verification lead too; P-384 ECDH remains
  slower: its field arithmetic here is generic in the modulus, where
  Graviola's is specialised to the prime.

  What changed: P-256's field reduction uses the prime's shape, in x86-64
  assembly (baseline `mul`/`adc`/`cmov`, and MULX/ADCX/ADOX where BMI2 and
  ADX are present, detected once) and in portable Rust on other 64-bit
  targets; on x86-64 with BMI2/ADX each point formula of P-256 and P-384 is
  one generated assembly block (`scripts/gen_p256_x86_point.py`,
  `scripts/gen_p384_x86_point.py`, `scripts/gen_mont_x86.py`). The generator
  table uses signed six-bit windows on P-256 (five on P-384, four on P-521)
  with affine entries and no doublings, read by a masked SSE2 or AVX2 scan;
  variable-base multiplication uses five-bit windows. Additions that cannot
  meet equal points skip the doubling the complete law computes, with the
  argument in the code and the edge scalars in the tests. P-256 inverts by
  Bernstein-Yang divsteps on 64-bit targets. Verification uses
  variable-time paths on its public inputs, reads the generator table by
  index, and checks `r` against the Jacobian x-coordinate without
  inverting. RFC 6979 keys each HMAC once.

  Nothing about what is computed changed: RFC 6979 signatures, every NIST,
  Wycheproof and ACVP vector, and the error-state gate are as before. `ic-ec`
  now denies `unsafe` instead of forbidding it, and allows it in the
  assembly modules alone. Every exponentiation is now a fixed four-bit
  window read by masked scan, so no inversion or square root branches on its
  exponent; Valgrind's secret-dependence harness had reported that branch in
  the ECDSA nonce inversion, and reports nothing in an inversion now. Ten
  x86-64 compiled-code probes cover the new assembly (`scripts/check-ct.py`),
  all passing; see `docs/CONSTANT_TIME.md`.

### Fixed

- **ML-KEM's 12-bit decode reduced modulo q with `%`**, on what is, in a
  decapsulation key, the secret vector. It is now a subtraction and a sign
  mask, and `scripts/check-ct.py` has probes for it and six other scalar
  ML-KEM helpers. Its first run found Cortex-M0 compiling the new mask
  into a branch; the barriers `compress` already uses removed it, and all
  twenty-six probes pass on all four targets.


## 0.2.24

### Added

- **Two error kinds for keys held elsewhere:** `ErrorKind::ProviderUnavailable`
  and `ErrorKind::ProviderRefused`. An implementation of `Signer` over a
  token, a TPM or a key service had no kind for "the device failed" or "the
  device said no" -- `Internal` means a bug in this library, and
  `InvalidParameter` blames the caller. The first is retryable and the
  second is not, which matters: retrying a refused PIN locks a token.
  Nothing in this library returns either. `ErrorKind` is `non_exhaustive`,
  so this breaks no caller. Found by IronKeys' PKCS#11 provider.
- **RSA-PSS signing is checked against NIST's values.** It was the one
  algorithm here with no outside vector, because a PSS signature is
  randomized. NIST's CAVP file `SigGenPSS_186-3.txt` publishes the salt, and
  its twenty signatures with a salt as long as the hash -- SHA-256 and
  SHA-384 at 3072 bits -- are now reproduced byte for byte through the
  public `sign`. Its other forty, made with salts of other lengths, are
  refused by the verifier, as a PSS this library does not have. No change
  to the code.
- **Certificate signatures PyCA made, as a test of `ic_sig::verify`.** 22
  self-signed certificates that IronPrivacyGuard generated to test code it
  has since replaced with this function: sixteen that verify, two whose key
  is not one for the algorithm the certificate names, and four RSA-PSS
  signatures with the wrong salt length or mask function. All are judged as
  they should be, with no change to the code.

## 0.2.23

### Added

- **The controls export has a named, kept shape.** `ic ontology controls
  --json` and its MCP tool now carry `"schema": "ironcrypto-controls/1"` and
  the IronCrypto `version` the mappings were read from. Within one schema
  number fields are only added. `docs/ONTOLOGY.md` lists them and what a
  reader must carry over to avoid overstating them, and a test fails if they
  change without the number changing. For tools that build compliance
  evidence from these mappings, IronEvidence first among them.

### Changed

- **`SoftwareSigner::from_pkcs8` uses much less stack for most keys.** Its
  loaders for each key family were inlined into one function, which then had
  the largest family's frame for every key: 16 KB on `thumbv7em-none-eabihf`
  whatever was being loaded, plus 10 KB more for ML-DSA. Each family now
  loads in a function of its own. Measured there at `opt-level = "s"`: about
  3 KB for an EC, Ed25519 or SLH-DSA key, down from 16; about 10 KB for
  ML-DSA, down from 26; and about 18 KB for RSA, up from 16, since RSA no
  longer shares a frame. No behaviour changed. Prompted by IronSocketLayer,
  which found the same effect in its own signer.

## 0.2.22

### Added

- **`ic rand <bytes>`, for what `openssl rand` is for.** The command was
  already there as `ic random`, hex only. It now answers to `rand` as well and
  writes `--hex` (the default) or `--base64`; OpenSSL's one-dash spellings,
  `-hex` and `-base64`, are taken too. `--json` names the encoding and carries
  the value under that name. The MCP tool `crypto_random` takes the same
  `encoding`. One to 1024 bytes, from the OS-seeded DRBG as before.

## 0.2.21

### Added

- **`ic_sig::SoftwareSigner`, a `Signer` for a private key held in memory.**
  `ic_core::sig::Signer` has been the interface for keys in an HSM, a TPM or
  a key service since 0.2.16, and nothing in this library implemented it.
  `SoftwareSigner::from_pkcs8` reads RSA, ECDSA over P-256, P-384 and P-521,
  Ed25519, ML-DSA and SLH-DSA keys and signs in the encodings `ic_sig::verify`
  accepts. The public half is always computed from the private one; a file
  whose stated public key, modulus, expanded key or root disagrees with it
  is refused. An ML-DSA key must carry its seed. HSS/LMS is not offered:
  this library verifies it and does not sign with it.
- **Checked against OpenSSL-made private keys**, one per algorithm, 21 in
  all: each is read, gives the public key OpenSSL derived byte for byte, and
  signs what `verify` accepts. Its Ed25519 and RSA PKCS#1 v1.5 signatures
  equal OpenSSL's, which is also the first outside value the RSA
  private-key operation with the CRT has been held to.

### Fixed

- **`ic_pkix::ecdsa_signature::max_der_len(132)` was 140, which is not a
  bound on anything.** The worst 132 bytes encode to 141, since 138 bytes of
  content take a three-byte header, and a real P-521 signature needs at most
  139. It returns 141 now and its documentation says which figure is which.
  Nothing overflowed: `to_der` checks its buffer. But a signer that compared
  its caller's buffer with 140 refused the 139-byte buffer that
  `SignatureAlgorithm::max_signature_len` says always suffices. The values
  for P-256 and P-384, 72 and 104, were right and are unchanged. Reported by
  IronSocketLayer.

## 0.2.20

### Security

- **Poly1305 computed a wrong tag, or stopped the process, for messages a
  peer can choose.** Every release from 0.2.5 to 0.2.19 is affected, in
  `Poly1305` and so in ChaCha20-Poly1305 wherever it is used: the AEAD, the
  `ic-rustls` TLS and QUIC suites, and HPKE with that cipher. The path that
  absorbs four blocks at once summed four products before reducing them, and
  the reduction kept its carries in 32 bits, which four products overflow.
  It takes a message of 64 bytes or more whose bytes are large. By a model
  of the old arithmetic over 2,000 random keys, a kilobyte of `0xff` bytes
  reaches it under about one key in twenty, 64 such bytes under about one in
  a thousand, and random data under none. ChaCha20-Poly1305 makes a new
  Poly1305 key for every nonce, so a peer who sends such messages gets
  there in a few dozen tries. What happens then depends on the build. With overflow checks on,
  which is how this workspace builds and how any debug build does, the
  process panics, and under `panic = "abort"` it ends: a peer who can send
  such a ciphertext to be opened can stop the process, before
  authentication and without the key. With overflow checks off, which is
  Cargo's default for a release build of a crate that depends on this one,
  the tag is computed wrong: the two ends of a connection still agree with
  each other, since both make the same mistake, but they disagree with every
  correct implementation on those messages. The carries are 64-bit now.
  Found by running Project Wycheproof's ChaCha20-Poly1305 cases; the test
  that should have caught it compared the two paths only on evenly spread
  bytes, and now compares them on the largest ones too.
  Advisory: [GHSA-xr22-8pqp-gwfh](https://github.com/nervosys/IronCrypto/security/advisories/GHSA-xr22-8pqp-gwfh).

### Added

- **HashSLH-DSA, the pre-hash interface of FIPS 205**, in `ic-slhdsa`:
  `hash_sign`, `hash_sign_deterministic`, `hash_sign_with_randomness` and
  `hash_verify`, with a `PreHash` of the twelve functions NIST's vectors
  exercise -- SHA-2, SHA-3, SHAKE128 and SHAKE256. A pure signature and a
  pre-hash one never verify as each other, nor does a pre-hash signature
  under another function. `PreHash::suits` says whether a function keeps a
  parameter set's strength; nothing enforces it, and the ontology records
  that as a partial requirement. Pure signing is still the one to prefer.
- **Checked against NIST's ACVP pre-hash vectors.** Bundled: 48 signing
  cases covering every function and 28 verification cases. The complete
  files -- now 624 signing and 504 verification cases across all three
  interfaces -- were run once and all pass.

- **`ic_sig::verify` verifies SLH-DSA and HSS/LMS.** `SignatureAlgorithm`
  gains `HssLms` and one algorithm for each of SLH-DSA's twelve parameter
  sets, and `PublicKey::from_spki` reads their keys: SLH-DSA per RFC 9909,
  pure with an empty context, and HSS/LMS per RFC 9708. Certificate and
  firmware-signing code now reaches both through the call it already uses.
  An HSS/LMS key names its own parameters, so `classical_bits` reads its
  strength from the key. RFC 9909's pre-hash key types are not read; such a
  key is `Unsupported`. Both enums are `non_exhaustive`, so this breaks no
  caller that compiled before.
- **Checked against OpenSSL for every SLH-DSA parameter set**, with a key and
  a signature OpenSSL 3.5.7 made for each, and against the RFCs' own test
  cases for HSS/LMS.

### Changed

- **The module's error state now stops the primitives, not only the policy
  layer.** Until now `ic_fips::enter_error_state` and a failed self-test
  stopped services requested through `ic_fips::check`, and a cipher or a
  signature called directly went on working. The state is now a flag in
  `ic_core::module` that every primitive crate reads. Once it is set, every
  operation that returns a `Result` returns `ModuleErrorState` -- sealing and
  opening, signing and verifying, key generation and agreement, key
  derivation, random generation, making a MAC or a cipher key -- and ML-DSA's
  `bool` interfaces return `false`. Keys and generators made before the
  failure are refused too. Nothing changes for a module that has not failed:
  the cost is one byte load per operation, and no signature changed.
- **A failed pairwise consistency test now puts the module into its error
  state**, for ML-KEM, ML-DSA, RSA and HPKE key generation. Until now it
  withheld the key and the module went on. The test's input is the module's
  own output, so a failure cannot be caused from outside.
- What cannot refuse is documented rather than implied: hash functions and
  XOFs, KMAC other than `verify`, a MAC object's `update` and `finalize`, and
  ML-KEM's deterministic interfaces have no error to return, and a block
  cipher object's per-block methods are left ungated by decision.
  `docs/FIPS.md` and `ic_core::module` say so, and a test enters the error
  state and requires every implemented algorithm in the ontology to be shown
  refusing. Running the self-tests before first use is still enforced only
  through `ic_fips::check`.

- **HPKE's `KeyPair::generate` runs a pairwise consistency test**, for
  X25519 and P-384: the public key is computed from the private key a second
  time and must match, or the key is withheld with `SelfTestFailed`. The
  ephemeral key `setup_sender` makes is not tested, so sending costs what it
  did.
- **SLH-DSA's `keygen` runs one too, and is much slower for it.** It signs
  with the new key and verifies the signature, which takes nine to thirty-six
  times what generating the key alone did: about 10 ms for the fastest
  parameter set and about 2 s for the slowest. It also needs the stack for
  one signature, up to 49,856 bytes. `keygen_internal` is unchanged, for a
  caller that cannot afford either.

- **The DRBGs are checked against NIST's ACVP vectors**, which neither was
  before: CTR_DRBG had no known answer of any kind. 210 cases -- CTR_DRBG
  over AES-256, and HMAC_DRBG over six hashes, with and without prediction
  resistance -- each driving instantiate, reseed and generate. All passed
  with no change to either mechanism.
- **`Rng` refuses entropy from a source that has stopped.** A seed from the
  operating system with eight equal bytes in a row, or a second draw that
  begins as the first did, is refused with `EntropyFailure` and puts the
  module into its error state. This catches a source returning zeroes; it is
  not an SP 800-90B health test and does not catch a weak or replayed one.
- **ECDSA, RSA PKCS#1 v1.5 verification and cSHAKE are checked against
  NIST's ACVP vectors.** ECDSA: 206 cases over P-256, P-384 and P-521,
  signing compared byte for byte and verification against NIST's verdicts
  -- the first published values P-521 has been held to. RSA: 108
  verification cases with SHA-256 at three modulus sizes. cSHAKE: the five
  of NIST's cases that are whole bytes. Everything passed with no change to
  the code. RSA-PSS and PBKDF2 are still not covered: NIST's samples use
  hashes this library does not pair with them.
- **TupleHash and ParallelHash are checked against NIST's ACVP vectors**:
  all 400 TupleHash cases, and the 13 ParallelHash cases that are whole
  bytes. KMAC gains one published value, for KMAC128; NIST's other KMAC
  cases are bit-oriented. Everything passed with no change to the code.
- **RSA verification, ECDH, KMAC and PBKDF2 are checked against Project
  Wycheproof**: 4,437 cases, among them 1,523 forged or malformed RSA
  signatures and 70 invalid ECDH public keys. Every verdict is honoured
  with no change to the code. These are the first outside values for
  RSA-PSS verification, KMAC256, PBKDF2, and ECDH on P-384 and P-521.
- **RSA PKCS#1 v1.5 signing is checked against Wycheproof's signatures**:
  77 of them, compared byte for byte, at three modulus sizes and three
  hashes. These reach the private-key operation without the CRT. RSA-PSS
  signing, which is randomized, is still held only by this library's own
  verifier.
- **Signatures, key agreement, AEADs, MACs, HKDF and key wrap are run
  against Project Wycheproof's malformed and edge-case inputs**: 4,546
  cases, among them 930 ECDSA signatures made wrong in their DER encoding
  or their values, all refused through `ic_sig::verify`. This is what
  found the Poly1305 defect above; nothing else in it needed a change.
- **The DRBG self-tests are known-answer tests now.** Each runs a NIST case
  through instantiate, reseed and generate. CTR_DRBG's used to check only
  that its output was reproducible and not constant, and HMAC_DRBG's
  compared against a value this implementation had produced.

### Fixed

- The README's algorithm table still said SLH-DSA was not implemented. It
  has been since 0.2.19.
- The ontology gave the longest HSS/LMS signature as 74,984 bytes. It is
  74,988: the count of signed public keys at its front was left out.

## 0.2.19

### Added

- **SLH-DSA, FIPS 205, in a new crate `ic-slhdsa`.** The stateless hash-based
  signature standard: all twelve parameter sets -- SHA-2 and SHAKE, at
  security categories 1, 3 and 5, small-signature and fast-signing -- with key
  generation, signing and verification for the pure interface and its
  context string. Signing is hedged by default, as the standard recommends,
  and deterministic on request. Nothing allocates: keys and signatures of
  7,856 to 49,856 bytes are written into the caller's buffers, and a long
  message is hashed in place. The ontology entry, `slh-dsa`, moves from
  planned to available. HashSLH-DSA and SP 800-230's parameter sets are not
  implemented.
- **Checked against NIST's ACVP vectors for every parameter set.** Bundled:
  all 120 key-generation cases, 48 signing cases and 30 verification cases,
  including NIST's invalid signatures. The complete files -- 336 signing
  cases compared byte for byte and 336 verification cases -- were run once
  and all pass; `scripts/gen_slh_dsa_vectors.py --full` and
  `IC_SLH_DSA_FULL` repeat that. A known-answer self-test joins the table
  (75). Twenty-two crates now.

## 0.2.18

### Added

- **A CNSA 2.0 profile**, `ic_ontology::profile::CNSA_2_0`: the suite as a list
  of algorithms rather than a strength floor, since that is what it is --
  ML-KEM-1024, ML-DSA-87, AES-256, SHA-384 or SHA-512, and LMS and XMSS. Each
  member carries its role and whether this build implements it, and
  `choose(intent)` answers from the suite or not at all: it names no password
  hash and no random bit generator, so those intents have no answer under it.
  `ic profile cnsa-2.0` and the MCP `crypto_profile` tool return it. The list
  is from the NSA-authored IETF drafts `draft-jenkins-cnsa2-pkix-profile-05`
  and `draft-becker-cnsa2-tls-profile-05`; NSA's own advisory was not read,
  and no transition date is recorded. `Policy::CNSA` is unchanged and now
  says it is the CNSA 1.0 threshold.
- **An ontology entry for XMSS**, as planned and not implemented: it is in
  CNSA 2.0 and SP 800-208, and asking for it should resolve to an absence.

### Changed

- The SP 800-53 mapping for SI-7(15), code authentication, said LMS was not
  implemented. It is, as of 0.2.17; XMSS is what is missing.

## 0.2.17

### Added

- **HSS/LMS signature verification, in a new crate `ic-lms`.** The stateful
  hash-based signatures of RFC 8554, with RFC 9858's parameter sets, as NIST
  SP 800-208 approves them and CNSA 2.0 names for signing firmware and
  software: SHA-256, SHA-256/192, SHAKE256/256 and SHAKE256/192, at every
  Winternitz width and tree height, in hierarchies of one to eight levels.
  `ic_lms::verify(public_key, message, signature)`, `verify_lms` for the bare
  forms, and `parameters` for a caller with a policy on parameter sets. No
  allocation, no panic on any input, at most 8670 hash calls per level.
- **It verifies and does not sign, on purpose.** An LMS private key is a set
  of one-time keys; signing twice with one lets a forger sign anything, and
  keeping the count right across crashes, restores and copies is a device's
  job. SP 800-208 requires hardware for it. The ontology says so as a
  critical constraint.
- **Checked against every published case**: RFC 8554 appendix F's two and RFC
  9858 appendix A's four, read out of the RFCs' text by script rather than
  typed. An independent implementation, required to reproduce RFC 9858's keys
  and signatures from their published seeds, supplies 21 more cases for the
  parameter sets the RFCs do not cover. A known-answer self-test joins the
  table (74). Twenty-one crates now.

## 0.2.16

### Added

- **A new crate, `ic-sig`: one `verify` for every signature algorithm**, over
  a public key parsed from a `SubjectPublicKeyInfo` and a signature in the
  encoding X.509 and TLS 1.3 carry. It is what a certificate validator or a
  handshake calls, and it existed twice outside this library --
  IronSocketLayer and IronPrivacyGuard each dispatched to IronCrypto's
  schemes themselves. It implements no algorithm: ECDSA on P-256, P-384 and
  P-521, Ed25519, RSA PKCS#1 v1.5 and PSS, and ML-DSA-44, -65 and -87 are
  `ic-ec`'s, `ic-rsa`'s and `ic-mldsa`'s. A signature that does not verify is
  one failure whether malformed, mis-sized or wrong; a key that cannot serve
  the algorithm named is the caller's error. RSA exponents above 2^32 - 1
  are refused, since the cost of verification is otherwise the peer's to
  set. Checked against signatures and certificates OpenSSL made. Re-exported
  as `ironcrypto::sig`. Twenty crates now.
- **`ic_core::sig::Signer`, an interface for a private key that can sign
  wherever it is held**, with `SignatureAlgorithm` and `Custody`. A TLS
  handshake or a certificate issuer written against it serves a key in an
  HSM, a TPM or a key service as it does one in memory. The interface is
  blocking and allocation-free; nothing implements it in this release.
- **NIST SP 800-53 Revision 5 controls in the frameworks knowledgebase**,
  beside CWE, ATT&CK and CMMC: the twelve that name a cryptographic mechanism
  -- SC-8(1), SC-12, SC-12(2), SC-13, SC-17, SC-23, SC-28(1), IA-5(1), IA-7,
  SI-7(6), SI-7(15) and CM-3(6). Titles and statements are the catalogue's,
  release 5.2.0, read from NIST's OSCAL content, and each says whether NIST's
  High baseline includes it. SC-13 and SC-12(2) are unmet, for the reason
  CMMC's SC.L2-3.13.11 is: no CMVP certificate. The rest are partial, with
  the mechanism pointed at and the gap named, or not applicable to a library.
  `ic ontology controls --framework sp800-53` and the MCP `crypto_controls`
  tool return them. FedRAMP's own baseline is not mapped: its published
  sources were being restructured, and a list from memory is not one to
  attest against.

## 0.2.15

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
