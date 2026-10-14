# FIPS 140-3 posture

## The headline

**IronCrypto is not a FIPS-validated cryptographic module.** It has not been
submitted to the CMVP, holds no certificate number, and appears on no vendor
list. Nothing in this document should be read as a validation claim.

What it *is*: a module that implements the operational discipline FIPS 140-3
requires, so that (a) it behaves correctly for callers who have a FIPS policy
to satisfy, and (b) the distance to an actual validation is a known quantity
rather than a rewrite.

The runtime says this too:

```console
$ ic capabilities --json | jq -r '.validationStatement'
IronCrypto implements the FIPS 140-3 operational discipline (approved-mode
policy, pre-operational and conditional self-tests, a latching error state, and
service indicators). It has NOT been submitted to or validated by the CMVP, and
holds no certificate number. Do not represent it as FIPS validated.
```

`ic_ontology::runtime::has("fips-validated")` returns `false`.

## What is implemented

### Module boundary and state machine

`ic-fips` defines the boundary. The module moves through:

```text
Uninitialized ──initialize()──> SelfTestInProgress ──all pass──> Operational(Unrestricted)
                                        │                               ↕ set_mode()
                                        │                        Operational(Approved)
                                        └──any fail──> Error (latched)
```

No service requested through `ic_fips::check` or `guarded` is available before
`initialize()`. The error state **latches**: once entered, `check`,
`initialize`, and `set_mode` all fail with `ModuleErrorState` until the process
restarts. There is deliberately no API to clear it.

**The error state reaches the primitives; the rest of the gate is opt-in.**
The primitive crates cannot depend on `ic-fips`, which depends on them, so
the one fact they all need is held below them: `ic_core::module` keeps a flag
that can be set and never cleared, and `ic_fips::enter_error_state` and a
failed `initialize()` set it. Every operation that can report an error
consults it first. Once it is set, a caller who goes straight to
`ic_cipher::Aes256Gcm::new`, `ic_hpke::setup_sender` or `ic_sig::verify` gets
`ModuleErrorState`, as one who goes through `ic_fips::check` does; the
interfaces that answer with a `bool` answer `false`. A key or a generator
made before the failure is refused the same way.

What that leaves:

- **In the default build, nothing makes a direct caller run the
  self-tests.** A primitive called before `initialize()` works. Self-tests
  before first use, and approved mode, hold only for services requested
  through `ic_fips::check` or `guarded`. A build with `--cfg ic_approved_only`
  (below) closes both: it does not contain the algorithms approved mode
  refuses, and every operation that can refuse does so until `initialize()`
  has passed the known-answer tests.
- **Hashes, XOFs and MACs refuse on output** (0.3.0). `Digest::finalize`
  and `digest`, `Xof::finalize_xof`, SHAKE's `xof` and its reader's `read`,
  cSHAKE, TupleHash, ParallelHash, BLAKE2's `finalize_into`, BLAKE3's
  reader and everything built on it, `Mac::finalize`, KMAC's `mac` and
  `finalize`, and ML-KEM's `keygen_deterministic` and
  `encapsulate_deterministic` return `ModuleErrorState` in the error state.
  They used to have no error to return and went on working; that was a
  breaking change to make. Creating a hasher and feeding it input produce no
  output and are not refused. The primitives call each other through
  `ic_core::traits::internal`, hidden and not API, which does not refuse:
  each refuses at its own entry instead, which is where a module boundary
  refuses a service.
- **A block cipher object's per-block methods are left ungated by decision.**
  They are the inner loop of every mode, each of which refuses at its own
  entry, as does making the key.

`crates/ironcrypto/tests/error_state.rs` holds this to the ontology rather
than to a list: it enters the error state and requires every algorithm the
registry marks implemented to be shown refusing, with no exceptions since the
hash functions and XOFs began to refuse. An algorithm added without the check
fails that test, and removing the check from `Digest::finalize` fails it.

The checks themselves were tested two ways, and the first is recorded because
of what it failed to show. Removing each of the 95 checks in turn failed the
test for 35 of them and passed for 60. That is not sixty untested checks: most
gated functions sit inside or outside another that refuses too -- an AEAD
around its stream cipher, HKDF around HMAC, a signature around its key
operation -- so removing one alone changes nothing a caller can see, and
removal cannot tell a redundant check from one nothing calls. So each check
was instead turned into a panic that fires only in the error state, which
asks the question that matters: does the test reach it while the module has
failed? After direct calls were added for the functions that first run showed
it had never called, it reached 94 of 95; the last, `Rng`'s
`RandomSource::fill`, was called only through its inherent twin, and has a
call of its own now and is reached. Both runs were done by scripts that are
not in the repository and are not part of the suite; a check added later is
held by the ontology test above and not by them.

What remains for a validated module is the first gap above in the default
build, and the per-block methods by decision; see the list below.

The module comes up *unrestricted*. Entering approved mode is an explicit
operator decision, never a default a caller might not have noticed. A build
with `--cfg ic_approved_only` is the exception: that decision was made when the
build was configured, so it comes up approved and `set_mode(Unrestricted)` is
refused.

### Approved mode of operation

In approved mode, `ic_fips::check(id)` refuses any algorithm the ontology does
not mark as permitted. The policy is data, not a hard-coded list — it reads
`FipsStatus::permitted_in_approved_mode()` straight from the registry, so the
policy and the documentation cannot drift apart.

```rust
use ic_fips::{Mode, ServiceIndicator};

fn main() -> ic_core::Result<()> {
    ic_fips::initialize()?;
    ic_fips::set_mode(Mode::Approved)?;
    assert_eq!(ic_fips::check("aes-256-gcm")?, ServiceIndicator::Approved);
    assert!(ic_fips::check("chacha20-poly1305").is_err()); // NotApprovedInFipsMode
    Ok(())
}
```

### A build with only the approved algorithms

`check` refuses a non-approved algorithm only when it is asked. Building with
`--cfg ic_approved_only`, in `RUSTFLAGS` and in `RUSTDOCFLAGS`, removes them
instead:

```toml
# The application's .cargo/config.toml
[build]
rustflags = ["--cfg", "ic_approved_only"]
rustdocflags = ["--cfg", "ic_approved_only"]
```

- **Every algorithm approved mode does not permit is left out of the build**:
  ChaCha20-Poly1305, XChaCha20-Poly1305, Poly1305, AES-GCM-SIV, Shamir
  sharing, BLAKE2b, BLAKE2s, BLAKE3, Argon2, scrypt, bcrypt, yescrypt,
  passphrase sealing, `ic_kdf::password`, X25519, Ed25519, hashing to P-256,
  the OPRF, OPAQUE and HPKE. A call to one does not compile. The documentation
  of the `ironcrypto` crate carries three examples that compile in the default
  build and are `compile_fail` in this one, and the documentation tests run
  both ways.
- **The ontology agrees.** Each of those entries reports `excluded` with no
  Rust path, `ic_ontology::runtime::has("approved-only")` is true, and
  `recommend` answers every policy as `FIPS_APPROVED` does. An entry that is
  not approved takes its status from one constant, and a test that runs only
  in this build fails if any entry not approved still says `available`.
- **The self-tests agree.** The CAST table drops the same twenty-one entries:
  64 tests rather than 85, with an integrity tag of its own. A test checks that
  a row is behind the cfg exactly when the ontology says its algorithm is not
  approved.
- **`ic_fips::check`** refuses those algorithms with `NotApprovedInFipsMode`,
  the reason, rather than `Unsupported`.
- **Self-tests before first use, whoever the caller.** Every operation that
  can refuse returns `ModuleErrorState` until `ic_fips::initialize()` has run
  the known-answer tests and they have passed, so a primitive called directly
  cannot run untested. The gate lives in `ic_core::module`, which every
  primitive already consults for the error state. While the tests run, the
  primitives they call are let through, and without `std` a second thread
  calling in that window cannot be told apart from the tests and is let
  through too; start threads that use the library after `initialize`
  returns. `crates/ic-fips/tests/startup_gate.rs` shows the refusal, and
  fails if the gate is removed. The repository's own suites call primitives
  from crates that cannot depend on `ic-fips`, so `scripts/approved-only.sh`
  runs them with a second cfg, `ic_startup_gate_off`, which turns off this
  gate and nothing else, and then runs `startup_gate.rs` without it. That
  cfg is a test switch: a build with it does not test before use.
- **What arrives as data cannot be refused at compile time.** An Ed25519 public
  key in a certificate, or an Ed25519 private key handed to `ic_sig`'s signer
  or to `ic_rustls`'s key provider, is refused with `NotApprovedInFipsMode` at
  run time. `ic_rustls` offers only its six AES-GCM suites, P-256 and P-384
  for key exchange, and ECDSA and RSA signatures.
- **`ic-cli` is not part of it.** It is a tool that offers every algorithm.

A cfg rather than a Cargo feature. Removing API is not additive, and Cargo
unifies features across a dependency graph, so a feature any dependency turned
on would remove these algorithms from every other crate in the build, and
`--all-features` -- which this repository's checks use, as does much tooling --
would build only this configuration. A cfg is set by whoever builds the final
binary, which is who decides where the boundary lies. `scripts/approved-only.sh`
checks this build in the local gate and in CI.

It does not make the module validated, and nothing in it says otherwise:
`has("fips-validated")` is false in this build as in every other, and
`ic_rustls` still reports `fips() == false`.

### Service indicator

FIPS 140-3 requires the module to tell the caller whether the service just used
was an approved one. `check` returns that indicator, and `guarded` pairs it with
the operation:

```rust
use ic_core::traits::Digest;
use ic_fips::ServiceIndicator;
use ic_hash::Sha256;

fn main() -> ic_core::Result<()> {
    ic_fips::initialize()?;
    let data = b"payload";
    let (digest, indicator) = ic_fips::guarded("sha2-256", || Sha256::digest(data))?;
    assert_eq!(indicator, ServiceIndicator::Approved);
    assert_eq!(digest?.len(), 32);
    Ok(())
}
```

Three values: `Approved`, `ApprovedAsComponent` (a raw block cipher used inside
a mode), `NotApproved`.

### Cryptographic algorithm self-tests

85 known-answer tests, one per implemented algorithm except six variants whose
computation another test covers (listed in `selftest.rs`), run by `initialize()` and
individually addressable:

```console
$ ic selftest
  PASS sha2-224
  PASS sha2-256
  ...
  PASS ed25519
  PASS ecdh-p256
  PASS ecdsa-p256-sha256
  PASS ecdh-p384
  PASS ecdsa-p384-sha384

75 passed, 0 failed; integrity check passed
```

Each test is the algorithm's own `SelfTest::self_test()` — the same code path
the unit tests exercise, not a reimplementation. The runner never
short-circuits: one failing algorithm must not hide the status of the rest,
because the report is what an operator uses to decide whether the build is
salvageable.

A test suite asserts that every `available` ontology entry has a CAST
registered, so adding an algorithm without a self-test fails CI.

### Vector provenance

Every row below names where the values came from. That is a rule the code
enforces rather than a convention: a file loaded through `ic-vectors` must
carry a `source`, and one that does not is refused rather than loaded with its
provenance recorded as unknown. `crates/ic-vectors` is how an
`experimental` algorithm becomes verified -- it is how ML-KEM-768, ML-DSA-65
and AES-GCM-SIV did -- and `experimental` means precisely that nothing has
checked it against values produced by something other than itself, so a file
of unknown origin would conceal that gap rather than close it.


| algorithm family | vectors |
|---|---|
| SHA-2, SHA-3, SHAKE | FIPS 180-4 / FIPS 202 published values |
| AES | FIPS 197 Appendix C, SP 800-38A F.1.1 |
| AES-CBC, AES-CTR | SP 800-38A F.2 / F.5 |
| AES Key Wrap | RFC 3394 sections 4.1 through 4.6, all six published vectors across three KEK sizes |
| AES Key Wrap with padding | RFC 5649 section 6, both published vectors, including the single-block path |
| AES-GCM | the McGrew–Viega specification test cases |
| AES-GCM on x86-64, the twisted GHASH reduction | No vector: an arithmetic identity. The x86-64 kernels multiply by powers of `H` twisted by `x^-1` and reduce with two carry-less multiplies (`ic-cipher/src/gcm_x86_asm.rs`, `x8_reduce!`). `scripts/check_gcm_twist.py` models the twist, the Karatsuba product, the reduction and an eight-block aggregate on Python integers and compares them with SP 800-38D section 6.3 Algorithm 1, transcribed from the standard, over 5,049 products (edge values included) and 1,000 groups; removing the twist's XOR or the second fold's product fails it. The kernels themselves are checked against an independent byte-at-a-time GCM at every length to 600 bytes and beyond, every key size, every buffer alignment (`gcm::fused_tests`), and through the vectors above and Wycheproof. That checks the instructions as written; the script checks that the scheme they implement is the field multiply |
| CMAC | SP 800-38B examples for all three key sizes |
| HMAC | RFC 4231 (case 6, the hashed long key, for SHA-256, SHA-384 and SHA-512; the SHA-384 and SHA-512 tags also checked against Python's `hmac`); NIST HMAC-SHA3 samples |
| HKDF | RFC 5869 test cases 1–3 |
| ChaCha20, Poly1305, ChaCha20-Poly1305 | RFC 8439. **RFC 8439's vectors did not catch a wrong Poly1305**, and neither did the test comparing its four-block path with its one-block path: from 0.2.5 to 0.2.19 the reduction after four summed products kept its carries in 32 bits, which overflow when the message limbs are large. Messages of evenly spread bytes, which is what both had, never reach it; by a model of the old arithmetic over 2,000 random keys, a kilobyte of `0xff` bytes does under about one key in twenty, and 64 such bytes under about one in a thousand. Project Wycheproof's cases found it on 2026-10-09 (see the Wycheproof row). The comparison now also runs on messages of `0xff`, `0xfe` and `0x80` bytes under 64 keys, among them the largest `r` clamping allows, and fails on the old reduction with overflow checks on and with them off |
| Inputs made wrong on purpose: ECDSA and Ed25519 signatures, X25519, AES-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, AES-GCM-SIV, HMAC, AES-CMAC, HKDF, AES Key Wrap | Project Wycheproof (C2SP/wycheproof 12fd3aaf33eb), converted by `scripts/gen_wycheproof_vectors.py`, which checks each file against a pinned digest; run by `ironcrypto/tests/wycheproof_inputs.rs`. Not a standard: cases built to catch mistakes, each marked valid, invalid or acceptable. 4,861 cases, every verdict honoured. **ECDSA** through `ic_sig::verify`, key as SubjectPublicKeyInfo and signature in DER: 600 valid and 930 invalid over the three curves, most of the invalid ones encodings -- a long-form length, an extra leading zero, trailing bytes -- and each refused as a failed signature. **Ed25519**: 88 valid, 63 invalid. **X25519**: 264 valid; of 254 marked acceptable, the 31 whose shared secret is zero -- points of low order -- are refused and the 223 on the twist or not reduced are accepted and give Wycheproof's secret. **AEADs**: 867 valid and 267 invalid across AES-GCM at three key sizes, ChaCha20-Poly1305, XChaCha20-Poly1305 and AES-GCM-SIV; 24 more are shapes this library does not take -- an empty GCM nonce, a ChaCha20-Poly1305 nonce that is not twelve bytes, an XChaCha20-Poly1305 nonce that is not twenty-four -- and are refused. AES-GCM nonces of other lengths are taken, as SP 800-38D allows, and match. **These found a defect**: Poly1305's four-block path, in the row above. **MACs**: HMAC with SHA-256, SHA-384 and SHA-512, 198 valid and 324 invalid, tags truncated among them; AES-CMAC, 63 valid and 248 invalid, five of those keys of no AES length. **HKDF**: 243 valid, 9 refused for asking more than 255 blocks. **Key wrap**: 113 valid, 303 invalid, and 3 acceptable that are refused |
| X25519 | RFC 7748 §5.2 and §6.1, including §5.2's iterated test after 1 and 1,000 iterations, run through every ladder the build has |
| Ed25519 | RFC 8032 §7.1 |
| SHA-2, SHA-3, SHAKE and HMAC, every CAVP case; ML-KEM, ECDSA in P1363 and other hashes, and AES-GMAC from Wycheproof | Added on 2026-10-13 so that every suite Graviola 0.4.1 runs is run here too. `scripts/gen_coverage_vectors.py` converts NIST CAVP's byte-oriented `shabytetestvectors.zip`, `sha-3bytetestvectors.zip`, `shakebytetestvectors.zip` and `hmactestvectors.zip`, each checked against a pinned SHA-256, and nine more Project Wycheproof files at the commit pinned above, each also pinned; `ironcrypto/tests/coverage_vectors.rs` runs them. **Hashes**: every ShortMsg, LongMsg and Monte case of SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224 and SHA-512/256 (1,886), and of SHA3-224 to SHA3-512, with SHAKE128 and SHAKE256 including VariableOut and their Monte chains (4,642); the Monte chains are computed in the test from NIST's seeds and compared at each of NIST's 100 checkpoints. These are the first published SHA-2 and SHA-3 values the suite carries beyond the self-tests. **HMAC**: 900 cases with SHA-256, SHA-384 and SHA-512, truncated tags among them; the SHA-1 and SHA-224 groups are left out, as this library has neither as an HMAC hash. **ML-KEM**: all three parameter sets, where Graviola runs ML-KEM-768 only: key generation from a 64-byte seed, 300 cases; decapsulation, 483 accepted with the right secret, malleated ciphertexts and one built to defeat a `strcmp` comparison among them, and 120 wrong-length inputs refused; encapsulation, 399 accepted byte for byte and 396 refused, among them the keys that fail FIPS 203's modulus check. Disabling that check fails the test. **ECDSA**: signatures as IEEE P1363 `r || s` over P-256, P-384 and P-521, and in DER for P-256 with SHA-512 and P-384 with SHA-512, 1,956 cases all judged as marked; the 472 for P-384 with SHA-256 are refused by this library's rule that a digest must be as strong as the curve, which Graviola does not have. **AES-GMAC**: 414 cases at 96- and 128-bit IVs, each valid tag both verified and recomputed. |
| RSA key generation's primality test, Miller-Rabin | Project Wycheproof (C2SP/wycheproof 12fd3aaf33eb), `testvectors_v1/primality_test.json`, SHA-256 `31ec21fb04bffef38d42a04339932be806d679fbb33714d16c6bed3748dbd8d8`, converted by `scripts/gen_coverage_vectors.py`, which checks that digest before converting; run by `ironcrypto/tests/coverage_vectors.rs` (`wycheproof_primality_every_case`) against `ic_rsa::key::probable_prime_be`, a hidden, test-only entry point to the decision key generation makes: trial division, then 8 Miller-Rabin rounds with bases drawn at random from the RNG the caller passes, as FIPS 186-5 B.3.1 specifies (`is_probable_prime`); the test seeds its RNG with a constant. 317 cases. 66 valid and 237 invalid agree; disagreements: 0. 14 signed values are skipped and counted, the 8 marked acceptable and 6 invalid, since the API takes unsigned integers; none is wider than 4096 bits. The 20 composites that the earlier fixed bases (the first eight primes, 2 to 19) accepted, tcIds 22 to 25, 31, 32, 38, 87 and 105 to 116, are now refused. A fixed base of 2 fails the test with 74 disagreements, and one round with random bases fails it with 35 (both measured). A new disagreement fails the test. Not a standard: cases built to catch mistakes. Not a standard: cases built to catch mistakes |
| Ed25519, strict verification | `testvectors/ed25519-degenerate-points.json`, from `scripts/gen_ed25519_degenerate_points.py`, run on 2026-10-12: the 8 small-order points and the 23 encodings whose y field is p or more and that name a curve point, derived from RFC 8032's curve equation, each small-order one shown to have order dividing 8, and every one refused by libsodium's `crypto_core_ed25519_is_valid_point` (PyNaCl 1.5.0). `ironcrypto/tests/ed25519_strict.rs` refuses each as a public key and as the R of a signature under a real key. The unit tests isolate each check: a signature under the identity key satisfies the cofactorless equation for any message, one with an identity R made with the real key satisfies it too, and both are refused; the canonical encoding of y = 3 decodes and its alias y + p does not. Removing the canonical check, the small-order check on the key, or the one on R each fails a test. Reported by the TUNDRA session, which found the key check missing beside the others. Project Wycheproof's Ed25519 cases still pass unchanged |
| NIST field and RSA arithmetic on 32-bit words (`narrow` in `ic-ec/src/nist/arith.rs` and `ic-rsa/src/uint.rs`, used on `riscv32`) | compared bit for bit with the 64-bit forms: for the NIST fields, `adc`, `sbb` and Montgomery multiplication on all six moduli, 256 operand pairs each including 0, 1, m - 1 and all ones; for RSA, the three word operations on 31 values, every pair, with edge carries. Every NIST and RSA vector and the rustls suite pass with them selected by `--cfg ic_limb32`. Using the high half of `-m^-1`, ignoring an incoming borrow, dropping the final carry of a Montgomery step, and in RSA dropping any of four inter-column carries each fail both. One mutation of `sbb`, reading bit 62 of the borrow for bit 63, is equivalent -- both are set whenever a 32-bit subtraction wraps -- and is not a gap |
| RSA Montgomery arithmetic on x86-64 (`ic-rsa/src/uint/x86.rs`, `MULX`/`ADCX`/`ADOX`; `ic-rsa/src/uint/ifma.rs`, AVX-512 IFMA in radix 2^52) and the four-bit window | No published value tests Montgomery arithmetic itself; the portable path is the reference. `uint::tests` compares the selected backend with it -- multiplication and squaring at every width that is a multiple of four words up to 64, exponentiation and the public-exponent path at 8, 16, 24 and 32 words, exponent lengths that do and do not fill their top window, including 0 and 2 bits, an all-ones exponent and a zero one -- on six moduli a width (three random with the top bit set, all ones, a lone top bit plus one, a top word of one) and operands 0, 1, 2, n - 1, n - 2 and random. One IFMA product is also checked on its own, at each of the three widths: two of them, by the operands and then by `R'^2`, give `a * b mod n`; every output is normalised, zero above its limbs and below `2^(B+1)`; a product written over its input, and a squaring, give what the product into a separate array gives; and the conversions into and out of radix `2^52` invert each other on every operand. `R'^2` computed with one bit too many fails these and the exponentiation comparison. `the_fast_backends_are_selected_where_the_cpu_has_them` asserts which backend runs, so the comparison cannot silently be the portable path against itself; the KATs run once on each. Outside values reach the new code through the rows below: OpenSSL's CRT-capable keys sign byte for byte as OpenSSL does (IFMA at 1024 and 1536 bits, on a CPU that has it), Wycheproof's signatures without primes go through the 2048- to 4096-bit exponentiation, and the CAVP PSS signatures through 3072. Dropping an `ADOX` carry in the reduction pass, taking the floor rather than the ceiling for the carry out of lane 0, and leaving one of the four IFMA accumulator sets out of the column read back each fail the differential tests and the KATs; `--cfg ic_limb32` turns both backends off and passes. Measured on one CPU, AMD Zen 5, which has both; the ADX-only path runs here on widths IFMA does not take |
| Keccak-f[1600] with lane complementing (`ic-hash/src/sha3.rs`) | FIPS 202 values and the SP 800-185 and ACVP rows above, plus `rho_and_pi_agree_with_the_lane_cycle`, which compares the permutation with a table-driven one using the textbook chi on 2,000 arbitrary states and the 25 single-lane states. Removing the NOT from one plane's chi fails all of them. The formulas are the Keccak team's ("bebigokimisa", Keccak implementation overview section 2.2), checked here against the textbook chi rather than taken on trust |
| SHA-256 padding written into the block, and HMAC's one-pass tag (`ic-hash/src/sha2.rs`, `ic-mac/src/hmac.rs`) | `padding_matches_fips_180_4_at_every_short_length`: every length 0 to 200 against the padding of FIPS 180-4 section 5.1.1 built separately and compressed with the portable round function, fed whole and in two pieces; finishing at 57 bytes and above without the extra block fails it, and the 56-byte two-block vector. `the_one_shot_path_matches_the_streaming_one`: `mac` against `new`, `update` and `finalize` for every HMAC digest, keys of 0, 1, 20, block - 1, block, block + 1 and 2 blocks + 3 bytes, and eleven message lengths either side of block boundaries. Treating a key of exactly one block as long fails it, and no RFC 4231 case does: none has such a key |
| Core `Choice::mask`, byte selection and four-byte conditional copy/swap | truth-table properties over all 256 input flags, including every nonzero value; no asserted external vector. Fixed-size LTO probes on x86-64, Cortex-M0/M4, RISC-V and AArch64 check compiled control flow. Removing the input barrier before mask negation reproduced secret-dependent branches in all three Cortex-M0 paths; restoring it passed. Scope and limitations are in `docs/CONSTANT_TIME.md` |
| ML-DSA `power2round`, `decompose`, reduction mod q (`ic-mldsa/src/rounding.rs`); ML-KEM `compress` (`ic-mlkem/src/encode.rs`) | the constant-time forms against FIPS 204 Algorithms 35 and 36 as written, kept in the tests as oracles, on every residue in `[0, q)` for both `gamma2`, plus negative bands; `reduce_q` against `rem_euclid` on every value within `4q` of zero and of both ends of `i32` and on every multiple of `2^16` either side; `compress` against the formula for every `x < q` and `d` from 1 to 12. A wrong folding constant, rounding half up, a dropped fold, a dropped centring, an off-by-one in the mod-5 constant, a missing correction and an overshooting estimate each fail. Two mutations are equivalent and recorded as such: a centring threshold anywhere between `gamma2` and `q - gamma2`, and a compression constant one lower, whose estimate the correction still absorbs |
| GF(2^255 - 19) on four 64-bit limbs with MULX/ADX (`ic-ec/src/fe64.rs`), and four elements at once on AVX-512 IFMA (`ic-ec/src/f51x4.rs`), x86-64 only | no vector is asserted for them beyond RFC 7748 and 8032, which pass through each with it selected; the evidence is differential. The four-limb field is compared with the five-limb one on every operation over fifteen edge values crossed with each other -- 0, 1, p - 1, p, p + 1, 2p - 1, 2^255 - 1, 2^255, 2^256 - 38, 2^256 - 1 and the values whose carry folds twice -- and two million random pairs biased toward all-ones and single-bit limbs, then on 200,000 chained steps whose outputs feed the next. Its divstep inversion (Bernstein-Yang, written from the published analysis of libsecp256k1's `modinv64`) is compared with Fermat's on the five-limb field over the edges and 100,000 random values. The four-lane field is compared with the four-limb one on 400,000 random quadruples for multiplication, squaring and their composition. Every X25519 ladder -- the portable one, the RFC's swap form kept as an oracle, the four-limb block and generic ones, and the four-lane one -- produces the RFC 7748 iterated results and agrees with the others on 400 more inputs, the small-order and non-canonical u among them. Each assembly block of an Edwards group operation is compared with the method it transcribes, and the basepoint and double-scalar multiplications of each backend with the portable ones. A wrong reduction constant in the multiplication fails the field comparisons, every ladder and the RFC 7748 and 8032 vectors; dropping the second carry fold of an addition fails only the edge-value comparison, which is what the edge values are for. The whole `ic-ec` and `ironcrypto` suites also pass with both removed by `--cfg ic_ec_portable` |
| P-384's field specialised to its prime on x86-64 with MULX/ADX (`ic-ec/src/nist/p384_x86_point.rs`, generated by `scripts/gen_p384_x86_point.py`), and divsteps inversion at 384 bits (`ic-ec/src/nist/safegcd.rs`) | No published value tests the field arithmetic itself; the generic Montgomery word loop and carry-chain code in `nist/arith.rs` are the reference, and every P-384 vector above (RFC 6979 A.2.6, Wycheproof ECDH, ACVP ECDSA) passes through the new code. `p384_x86::tests` compares multiplication, squaring, addition, subtraction and the doubling's three fused `c*a - d*b` operations with the generic ones on every pair of 74 edge values -- 0, 1, 2, p - 1, p - 2, p - 3, (p +- 1)/2, 2^384 - p and its neighbours, powers of two at and around 32, 64, 96, 128 and the word boundaries, p less each, words of ones and zeros -- on sums landing on p - 1, p and p + 1 and differences on 0 and -1, and on a million random pairs, half built from whole words of zeros and ones. The reduction's top-word carry occurs about once in 2^32 words of random input, so a second test builds operands from chosen Montgomery digits, `a b = -M p mod 2^384` with every word of `M` within 2^31 of 2^64 -- for squaring through a 2-adic square root -- so that every word of the reduction carries. The point formulas are compared with `point.rs`'s field-operation formulas bit for bit on 50,000 arbitrary coordinate triples and on curve points with the exceptional cases. Breaking the reduction constant, the final correction's carry, the subtraction's mask, the reduction's top-word carry (in multiplication and squaring together, and in squaring alone), the fused operation's top word and its copy of p each fail. One mutation, dropping the fused operation's top-word carry, was equivalent -- the top is at most 21 there -- and that arithmetic was removed rather than kept untested. The inversion's step count rests on Bernstein and Yang, "Fast constant-time gcd computation and modular inversion", TCHES 2019, Theorem 11.2: floor((49d + 80)/17) = 1111 divsteps at d = 384, against 1116 taken. Its batch is held to a branching transcription of the paper's divstep on exact integers over 20,000 starts, which is what tells it from a step that also converges (`delta >= 0` for `delta > 0` passes the inversion tests and fails this one); P-256's half-delta batch is held to its definition the same way, and a wrong `zeta` update that still converges fails only that. The 384-bit inversion is checked against a schoolbook product and long division sharing nothing with it on 3,000 inputs and by double inversion on 17,000 more, every power of two below p among them, and Fermat's addition chain and the generic windowed exponentiation agree with it on 2,000 more |
| P-256 and P-384 scalar multiplication on AVX-512 IFMA (`ic-ec/src/nist/ifma.rs`, and `nist/ifma_kernels.rs` generated by `scripts/gen_nist_ifma.py`), x86-64 only | No published value tests these arithmetics; the evidence is differential, at three levels, with the generic Montgomery word loop in `nist/arith.rs` and the MULX/ADX code as the references. Before it writes anything the generator bounds every limb and value of every kernel by interval arithmetic and runs the emitted instructions in a simulator on random inputs and on inputs at the edges of their promised bounds (every limb at its largest, every limb zero, mixtures), against the formulas on integers modulo p and against the bounds it claims. Each formula is first checked against textbook affine addition and doubling on random curve points, under every mask. In the crate, `nist::ifma::tests`: the lane-wise product and a linear combination with subtraction, addition and small multiples, against the word loop and the MULX code, on 4,194,304 P-256 and 2,097,152 P-384 lane values under `--release` (random within the bounds, a quarter at their edges) and on every pair of 0, 1, 2, p - 2, p - 1, p, p + 1, 2p - 1, 2p, the field width's all-ones, the power of two above it and the bounds' largest value that the bounds can hold (265 pairs); every point kernel against `point.rs`'s formula, coordinate for coordinate, on 50,000 P-256 and 20,000 P-384 arbitrary coordinate triples with 0, 1, p - 1 and p - 2 mixed in, under every mask combination, and the four-lane addition on 12,500 and 5,000 quadruples with random masks per lane; and the three multiplications whole against their MULX counterparts on 1,351 P-256 and 879 P-384 scalars -- 0 to 40, n - 40 to n - 1, powers of two, single-byte fills and random ones -- on the generator, another point and the identity. On a CPU with IFMA every signing and key-derivation vector in the tables above (RFC 6979, ACVP) and every ECDH one (CAVP, Wycheproof) runs through this path; verification does not use it. The whole `ic-ec` and `ironcrypto` suites also pass under `--cfg ic_no_avx512`, which removes it. Nine mutations each fail these tests: a carry dropped from a normalisation, the reduction constant `(2^32 - 1) 2^16` off by one bit, a lane permutation, P-384's fold shifted by 31 for 32, a high half of a P-384 product dropped, the four-lane addition's blend made unconditional, P-384's conversion constant read from the wrong place, P-256's limb packing shifted by one bit, and the digit's sign ignored. Measured on one CPU with IFMA, AMD Zen 5 |
| GF(2^255 - 19) on 32-bit limbs (`ic-ec/src/field32.rs`, used on `riscv32`) | the RFC 7748 and 8032 vectors, and the whole `ic-ec` and `ironcrypto` suites, pass with it selected on a host by `--cfg ic_limb32`. Under ordinary test it is compared with the five-limb field on 29 operands chosen for their bounds, every pair, for every operation. Its straight-line multiplication, squaring and byte packing were generated by `scripts/gen_fe32.py`, which checks each against integer arithmetic mod p on random operands before printing it. A wrong reduction constant, a missing doubling of odd-limb products in either multiplication, an off-by-one in the final subtraction of p, a dropped last byte, a wrong limb of 2p and an unscaled top carry each fail both the comparison and the suite run under `ic_limb32` |
| ML-KEM-768 | ACVP `ML-KEM-keyGen-FIPS203` and `ML-KEM-encapDecap-FIPS203`, every ML-KEM-768 case in both: 25 key generation and 25 encapsulation. Key generation is deterministic in its seed, so each case pins the sampler, the NTT, the compression and the key encoding together. The NTT is also checked against schoolbook multiplication and the samplers against FIPS 203's pseudocode, which is what localises a failure when one happens. Registered `available` |
| ML-KEM-512, ML-KEM-1024 | The same two ACVP files, every case of each set: 25 key generation and 25 encapsulation apiece, from the same pinned commit (usnistgov/ACVP-Server 975de31eb83d). The scheme is ML-KEM-768's code instantiated with each set's five parameters, so a set is registered only on its own vectors: they are what differs. The extraction was checked by regenerating ML-KEM-768's vendored files from the same download, which matched byte for byte. Setting ML-KEM-512's `eta1` to 2 fails its key generation and encapsulation vectors; setting ML-KEM-1024's `dv` to 4 fails its encapsulation vectors and leaves key generation passing, as it should, since `dv` only shapes ciphertexts. Registered `available` |
| ML-DSA-65 | ACVP `ML-DSA-keyGen-FIPS204` and `ML-DSA-sigGen-FIPS204`, every ML-DSA-65 case in the external pure groups: 25 key generation, 15 deterministic signatures and 15 hedged ones using the randomness each vector specifies. The NTT is also checked against schoolbook multiplication, the packing against a bit-at-a-time reference, and rounding and hints against the equations that define them. Registered `available`; the pure and pre-hash variants are both present and are asserted not to accept each other's signatures |
| ML-DSA-44, ML-DSA-87 | The same two ACVP files, every case of each set: 25 key generation, and 30 signatures from the external pure groups, 15 deterministic and 15 hedged, from the same pinned commit (usnistgov/ACVP-Server 975de31eb83d). The scheme is ML-DSA-65's code instantiated with each set's parameters, registered on its own vectors. The extraction was checked by regenerating ML-DSA-65's vendored files from the same download, which matched byte for byte. Setting ML-DSA-44's `tau` to 49 fails its signature vectors and leaves key generation passing; giving ML-DSA-87 ML-DSA-44's `gamma2` fails both, since key generation runs a sign-and-verify consistency check. The hostile-input suite in `ic-mldsa/tests/robustness.rs` runs unchanged against each set. Registered `available` |
| All six ML-KEM and ML-DSA sets, against OpenSSL | `testvectors/openssl-ml-kem.json` and `openssl-ml-dsa.json`, produced by OpenSSL 3.5.7 on 2026-09-29 with the commands recorded in each file. `ironcrypto/tests/openssl_interop.rs` regenerates OpenSSL's keys from its seeds, requires deterministic ML-DSA signatures to equal OpenSSL's byte for byte, verifies OpenSSL's hedged signatures, and decapsulates OpenSSL's ciphertexts to its secrets. Giving ML-DSA-87 an `omega` of 80 fails it at the first ML-DSA-87 signature while its keys still match. The reverse directions were run once by hand the same day: a small program encapsulated to each OpenSSL ML-KEM key and signed, hedged, under each OpenSSL ML-DSA key, and `openssl pkeyutl -decap` recovered the same secret and `openssl pkeyutl -verify -rawin` accepted every signature, for all six sets. These are interoperability checks, not vectors from a standard |
| Shamir secret sharing (`ic_cipher::shamir`) | No standard publishes vectors for it. `testvectors/shamir-gf256.json` comes from `scripts/gen_shamir_vectors.py`, written from Shamir's 1979 construction with its own GF(2^8) arithmetic (a branching multiply, inversion by search) and sharing nothing with `ic_cipher::gf`; it recombines every case from up to twenty subsets before writing it. Under the same fixed coefficient stream, `ironcrypto/tests/shamir.rs` requires every share byte for byte, from 2-of-2 to 255-of-255, and the unit tests recover the secret from every subset of at least the threshold. Dropping Horner's last multiply, a Lagrange denominator missing `x_i`, one set of coefficients for every byte, and accepting index 0 each fail them. An independent-implementation check, not published values |
| HPKE (`ic_hpke`) | RFC 9180 appendix A.1.1 (base mode, AES-128-GCM): the encapsulation, base nonce, exporter secret and first ciphertext, as transcribed for IronSocketLayer. `scripts/gen_hpke_vectors.py`, an RFC 9180 implementation written from the specification on pyca/cryptography's X25519 and AEADs and Python's `hmac`, refuses to run unless it reproduces those four values, so two independent paths agree on them; the self-test checks the first ciphertext. `testvectors/hpke-x25519.json` carries A.1.1's inputs through all three AEADs, six sequence numbers each and three exports, and `ironcrypto/tests/hpke.rs` runs every case from both sides. `DeriveKeyPair` is checked against A.1.1 too: its `ikmE` and `ikmR` must derive the appendix's `skEm`, `pkEm` and `skRm`, and the two `ikm` values were confirmed by an independent derivation reaching those same keys. Only the A.1.1 values are published; the rest are that implementation's outputs |
| HPKE with DHKEM(P-384, HKDF-SHA384) (`ic_hpke::p384`) | No published HPKE vector uses P-384: RFC 9180's appendix and the CFRG's full test-vectors.json cover P-256 and P-521 only. `testvectors/hpke-p384.json` comes from `scripts/gen_hpke_p384_vectors.py`, an implementation of every NIST-curve DHKEM written from RFC 9180 on pyca/cryptography's ECDH and Python's `hmac`, sharing nothing with `ic-hpke`. Before writing it must reproduce all twelve base-mode P-256 and P-521 cases of the CFRG test-vectors.json (fetched 2026-10-06, SHA-256 pinned in the script) -- DeriveKeyPair, enc, the shared secret, the key schedule, every encryption and export -- since P-384 is the same construction with other parameters; must find that OpenSSL accepts each curve order less one as a private key and refuses the order itself; and must exchange a P-384 message each way with pyca/cryptography's own HPKE. The self-test (`HpkeP384::self_test`) pins the AES-256-GCM case: both keys by DeriveKeyPair, then the first encryption. The rejection loop of DeriveKeyPair, which real candidates all but never exercise, is tested against its rule with zero, the order and an all-ones candidate. An independent-implementation and interoperability check, not published values |
| Signature verification by algorithm (`ic_sig::verify`) | It implements no algorithm, so what is checked is the dispatch and the encodings. `testvectors/openssl-sig.json`, from `scripts/gen_sig_vectors.py` with pyca/cryptography 50.0.0 (its bundled OpenSSL reports 4.0.1): ECDSA on P-256, P-384 and P-521, Ed25519, and RSA PKCS#1 v1.5 and PSS with SHA-256, -384 and -512 at 2048 and 3072 bits, three messages each, with keys as SubjectPublicKeyInfo and ECDSA signatures in DER. ML-DSA-65 and -87 and Ed25519 are also checked on the certificates OpenSSL 3.5.7 issued in `testvectors/openssl-x509.json`: each CA's signature on itself and on its leaf. ML-DSA-44 has no OpenSSL-made case and is checked by signing with `ic_mldsa` and verifying here. Against the rule rather than a value: every case is refused with a changed message, a changed or truncated signature, and under every other algorithm -- as a failed signature where the key serves that algorithm, as the caller's error where it does not. Accepting any algorithm for any key, accepting ML-DSA keys with parameters, and dropping the RSA exponent bound each fail a test; the last did not at first, because the test used an even exponent that `ic_rsa` refuses on its own. **SLH-DSA and HSS/LMS keys** are read per RFC 9909 and RFC 9708, whose text was fetched from rfc-editor.org on 2026-10-08; every object identifier is held to its dotted form by `ic_pkix`'s table test. For SLH-DSA, `testvectors/openssl-slh-dsa.json`, from `scripts/gen_slh_dsa_sig_vectors.py` with the OpenSSL 3.5.7 command, carries one generated key and one hedged pure signature for each of the twelve parameter sets. The algorithm is held by NIST's vectors; what these hold is the key encoding, and they are needed for it: a SHA-2 set and the SHAKE set of the same size have keys and signatures of the same lengths, so only a real signature tells a table that confuses them from one that does not, and reading one set's identifier as another's fails this test in each of the three ways tried. HSS/LMS has no second implementation here -- OpenSSL 3.5 does not verify it -- so the six test cases of RFC 8554 and RFC 9858 are wrapped by the test in RFC 9708's key encoding; that checks the dispatch and not the encoding against anyone else's reading of it, which rests on the RFC's text alone. Allowing parameters on either key, not reading an HSS/LMS key when it is parsed, reporting a bad HSS/LMS key as a bad signature, verifying SLH-DSA under a non-empty context, and a wrong longest-signature figure each fail a test. RFC 9909's pre-hash key types are not read. Interoperability checks against an independent implementation, not values from a standard. **Certificates PyCA signed** are a third source, added 2026-10-10: `testvectors/pyca-x509-signatures.json`, 22 self-signed certificates that IronPrivacyGuard generated with pyca/cryptography to test certificate-signature code it has since replaced with this function, copied unchanged from its commit 1ffc55e by `scripts/import_x509_signature_vectors.py`. The keys were discarded, so the file cannot be regenerated here. The script adds its own reading of each case: the algorithm the certificate names, and what `verify` must do. Sixteen verify. Two are refused as a key that is not the algorithm's -- a P-256 key under ecdsa-with-SHA384 and the reverse, since X.509's ECDSA identifiers name a hash and no curve and this library's algorithms fix both. Four are RSA-PSS signatures over SHA-256 with an empty salt or with MGF1 over SHA-384, at 2048 and 4096 bits, and are refused as failed signatures under every PSS algorithm, because the salt length and mask function are fixed by the algorithm and not searched for. Taking the salt length from the signature accepts the empty-salt ones and fails this test. One verdict differs from IronPrivacyGuard's on purpose: it refused P-521 by policy, and this library verifies it |
| Signing through `ic_core::sig::Signer` with a key in memory (`ic_sig::SoftwareSigner`) | It implements no algorithm: what is checked is the reading of the key file, the dispatch and the encodings. `testvectors/openssl-private-keys.json`, from `scripts/gen_signer_vectors.py` with the OpenSSL 3.5.7 command, carries one PKCS#8 key per algorithm -- ECDSA over the three curves, Ed25519, RSA at 2048 and 3072 bits, ML-DSA-44, -65 and -87, and SLH-DSA in all twelve parameter sets -- with the SubjectPublicKeyInfo OpenSSL derived. Each key is read and reports that public key byte for byte; signs under every algorithm it lists; and `ic_sig::verify` accepts each signature and refuses it for another message. Its Ed25519 and RSA PKCS#1 v1.5 SHA-256 signatures equal OpenSSL's, and since OpenSSL's RSA keys carry their primes, that is an outside value for the RSA private-key operation **with** the CRT, which Wycheproof's signatures, having no primes, did not reach. The six small-signature SLH-DSA keys are skipped by default and were run once, on 2026-10-09, with `IC_SLOW_SLH_DSA`. Against the rule rather than a value: an algorithm the key does not list is refused; a buffer one byte short is refused with nothing written and nothing drawn from the random source; a stated EC public key, RSA modulus, ML-DSA expanded key or SLH-DSA root that is not the private half's is refused; an ML-DSA key without its seed is refused; and an RSA key lists PSS before PKCS#1 v1.5. Removing each of those checks, leaving an ECDSA signature in fixed-width form, and signing SLH-DSA under a context each fail a test; two of the nine did not at first, the RSA modulus check and the order, and have a test now. RSA-PSS, ECDSA, ML-DSA and SLH-DSA signatures are randomized or made deterministically in a way OpenSSL does not by default, so for those what is held is that the verifier accepts them. Interoperability checks against an independent implementation, not values from a standard |
| SLH-DSA, all twelve parameter sets (`ic_slhdsa`) | NIST ACVP `SLH-DSA-keyGen-FIPS205`, `SLH-DSA-sigGen-FIPS205` and `SLH-DSA-sigVer-FIPS205`, from the pinned commit (usnistgov/ACVP-Server 975de31eb83d), converted by `scripts/gen_slh_dsa_vectors.py`, which checks each file against a pinned digest. The implementation was written from the text of FIPS 205, fetched from nvlpubs.nist.gov on 2026-10-08. The originals are about 70 MB, so three subsets are bundled: every key-generation case (120, ten per set); for signing, 96 cases with NIST's signature held as its SHA-256 and length -- for each set and variant (deterministic, hedged), the shortest-message case of the pure and internal interfaces and two pre-hash cases, rotated so that all twelve pre-hash functions are signed under; and for verification, 58 cases -- the pure cases of the six sets with the smallest signatures, both passing and three failing per set, and all fourteen pre-hash cases of each of the two smallest. **The whole of all three interfaces was run once**, on 2026-10-08 in an optimised build with `IC_SLH_DSA_FULL` pointing at the full conversion: 120 key-generation, 624 signature-generation compared byte for byte (288 of them pre-hash), and 504 verification cases (168 pre-hash), all passing; that run is repeatable from the script and is not part of the suite. By default the suite runs all ten key-generation cases of each `f` set and two of each `s` set, the 48 `f`-set signing cases, and all 58 verification cases; `IC_SLOW_SLH_DSA` adds the rest of what is bundled. FIPS 205 prints the object identifiers of four pre-hash functions only -- SHA-256, SHA-512, SHAKE128 and SHAKE256 -- and a unit test holds those four to the printed bytes. The other eight were written from NIST's hash-algorithm arc and are held by the vectors alone: the identifier is part of what is signed, so a wrong one changes the signature, and the `f`-set signing cases, which run by default, cover all twelve. Moving one identifier, swapping two, dropping the identifier, changing the domain byte, dropping the context length, shortening the SHAKE128 digest and substituting SHA-224 for SHA-512/224 were each tried, and each fails the vector test. The verification cases say less than their count suggests: only two of each group's fourteen are valid, so they show a function accepted for few of the twelve, and the signing cases are what constrain the rest. Writing it, the overflow check found a mask that assumed the tree index was under 64 bits, which in the 256f sets it is not. The self-test is an ACVP key-generation case and a sign-verify round trip, not a pinned signature. Published NIST values |
| HSS/LMS verification (`ic_lms`) | All six published cases: RFC 8554 appendix F's two (SHA-256, W=8 and W=4, two levels each) and RFC 9858 appendix A's four (SHA-256/192 at W=8 and at W=4 with H=20, SHAKE256/192, SHAKE256/256). `scripts/gen_lms_vectors.py` reads them out of the RFCs' own text, fetched from rfc-editor.org on 2026-10-08 and checked against pinned digests, so none was typed by hand; the first extraction dropped every value's short last line, which the script's own verifier caught by refusing the result. Those six leave W=1 and W=2 untested for every hash, W=4 for three of the four, and any hierarchy mixing hashes, so the same script holds a verifier and a signer written from the RFCs' pseudocode, sharing nothing with `ic_lms`. Before writing anything it must verify all six published cases and refuse each with a changed message, and its signer must reproduce three of RFC 9858's public keys and signatures byte for byte from their published SEED and I, and the one-time signature of the fourth, whose 2^20-leaf tree is too large to rebuild in Python. It then adds 21 cases: every hash at every Winternitz width, the first and last leaf of a tree, H=10, the empty message, and a three-level hierarchy over three hashes. `testvectors/lms.json` holds all 27, and `ironcrypto/tests/lms.rs` requires each to verify and to be refused with the message changed, lengthened or shortened, a bit changed at about a hundred positions across the signature, the signature truncated or extended, and the key's root or identifier changed. The parameter tables are checked against the RFCs' tables as typed and re-derived by RFC 8554 appendix B's computation of p and ls. Accepting trailing bytes, not checking the level count, and accepting a tree whose LM-OTS and LMS hashes differ each fail a test. Not checking the leaf number failed none at first: no such signature can verify, and what the check prevents is an overflow, which is a panic here; a test for exactly that was added. The self-test is RFC 9858 A.1. Published values for the six; an independent implementation anchored on them for the rest |
| ML-DSA PKCS#8 private keys (`ic_pkix::MlDsaPrivateKey`) | `testvectors/openssl-ml-dsa-pkcs8.json`: two keys per parameter set, each written by OpenSSL 3.5.7 in RFC 9881's three forms (seed, expanded key, both), with OpenSSL's own `-text` account of the seed and expanded key; `scripts/gen_mldsa_pkcs8.py` records the commands. `ironcrypto/tests/openssl_interop.rs` requires the parser to find OpenSSL's seed and expanded key in each form, the writer to reproduce OpenSSL's bytes, and `ic_mldsa` to regenerate OpenSSL's expanded key from the seed. A constructed seed tag, the `both` fields read or written in the wrong order, and an ML-DSA-87 expanded length off by one each fail it. An interoperability check, not a vector from a standard |
| X.509 URI names and PKCS#10 requests (`ic_pkix::cert`, `ic_pkix::csr`) | `testvectors/openssl-x509-uri-csr.json`, from `scripts/gen_x509_uri_csr_vectors.py` with OpenSSL 3.5.7 on 2026-10-12: an Ed25519 key's request for a DNS name and the URI `nanda:ed25519:node-7:worker`, passing `openssl req -verify`, and the leaf OpenSSL issued from it under an Ed25519 CA, passing `openssl verify -x509_strict`. The keys come from seeds that are SHA-256 of labels in the script, and rerunning it reproduces the file byte for byte. `ironcrypto/tests/x509_issuance.rs` writes the request and both certificates and requires each byte for byte. Writing the URI with the `dNSName` tag, leaving the requested extensions out of the attribute's `SET`, request version 1, and the attributes as a `SET` rather than `[0]` each fail it. Which URIs are written is held to the rule rather than a value: a scheme RFC 3986 allows, a colon, something after it, printable ASCII without spaces |
| X.509 issuance (`ic_pkix::cert`) | `testvectors/openssl-x509.json`: a CA and a leaf that OpenSSL 3.5.7 issued for Ed25519, ML-DSA-65 and ML-DSA-87 with every input fixed and ML-DSA signing deterministically, each chain passing `openssl verify -x509_strict`. `ironcrypto/tests/x509_issuance.rs` issues the same six certificates and requires them byte for byte. A key-usage unused-bit count off by one, extended key usage written before key usage, and `GeneralizedTime` chosen from 2026 rather than 2050 each fail it -- the second only for the leaves, which are the certificates carrying both extensions. ECDSA signatures are random, so P-256 and P-384 chains issued here were checked by `openssl verify -x509_strict` instead, on 2026-09-29, and passed. The OIDs are rebuilt from their dotted arcs, and the time encoding is tested against a day-by-day calendar count from 1970 into 2100 |
| POLYVAL | checked against the GHASH construction of RFC 8452 Appendix A, over a GHASH the published GCM vectors validate |
| AES-GCM-SIV | RFC 8452 appendix C, all 50 published cases across C.1, C.2 and C.3, for both key lengths and in both directions. That includes the counter-wrap tests of C.3, which exist because an implementation can pass every other case and still get the block counter wrong. Registered `available` |
| XChaCha20-Poly1305 | draft-irtf-cfrg-xchacha-03, fetched from ietf.org on 2026-10-12 (SHA-256 `fa796b50265eeee383d40e82fed880267c7835e1b3d64c50c4f06162adaa1cfd`): the HChaCha20 subkey of section 2.2.1; the XChaCha20 keystream of appendix A.3.2 at block counters 0 and 1; and the AEAD of appendix A.3.1, its one-time Poly1305 key as well as its ciphertext and tag, which is also the CAST. The draft expired in 2020 without becoming an RFC and is not normative; the ontology records it as informational. Also Project Wycheproof's `xchacha20_poly1305_test.json` at the commit pinned above: 246 valid accepted, 60 invalid refused, 9 nonces that are not 24 bytes refused. The vectors vary every nonce byte at once, so a test changes one byte of each half and requires the ciphertext to change. Taking the subkey's second half from the third row instead of the fourth, adding the input back after the rounds, reading the HChaCha20 nonce big-endian, taking the inner nonce from bytes 12 to 20, and a non-zero four-byte prefix each fail both the draft's vectors and Wycheproof's |
| BLAKE2b | RFC 7693 Appendix A, and the Appendix E self-test, which hashes unkeyed and keyed BLAKE2b at four output lengths over six input lengths and compares the hash of the results with `blake2b_res` |
| BLAKE2s (`ic_hash::Blake2s`) | RFC 7693 Appendix B (BLAKE2s-256 of "abc", the CAST) and the Appendix E self-test against `blake2s_res`, which varies the output and key lengths. `testvectors/blake2s-kat.json`, from `scripts/gen_blake_vectors.py`: the BLAKE2 team's `testvectors/blake2s-kat.txt` at ed1974ea, pinned by SHA-256 -- keyed BLAKE2s-256 of inputs of 0 to 255 bytes -- each line also checked against Python's hashlib.blake2s when transcribed. A wrong rotation, a dropped key length in the parameter block, and compressing a full buffer as non-final each fail. No vector reaches 2^32 bytes, so the counter's high word is tested against the rule, low word first, in `counter_words`, which BLAKE3 shares; shifting it by 31 fails that test |
| BLAKE3 (`ic_hash::Blake3`) | Transcribed from the authors' `reference_impl/reference_impl.rs`. `testvectors/blake3.json`, from `scripts/gen_blake_vectors.py`: the BLAKE3 team's `test_vectors/test_vectors.json` at f55849f8, pinned by SHA-256 -- 35 input lengths from 0 to 102400 bytes, across every block, chunk and subtree boundary, each in hash, keyed_hash and derive_key mode to 131 bytes of extended output, also fed and read back in uneven pieces. The CAST is the one-byte input. Dropping CHUNK_END, ROOT, or DERIVE_KEY_CONTEXT, merging subtrees on the wrong count, numbering parent nodes from 1, setting CHUNK_START on the second block, and stepping the output counter by 2 each fail; permuting the message after the seventh round survives because the permuted block is never used |
| cSHAKE | checked against a Keccak written from FIPS 202 in-test and anchored to the published SHA3-256 answer, plus SP 800-185 section 3.3's identity with SHAKE. Five published values were wired in on 2026-10-09, from NIST ACVP `cSHAKE-128-1.0` and `cSHAKE-256-1.0` (usnistgov/ACVP-Server 975de31eb83d, converted by `scripts/gen_acvp_sig_vectors.py`): the cases whose message and output are whole bytes, five of two hundred, the rest being bit-oriented. Each has a function name and a customization string, and swapping the two fails them |
| TupleHash | NIST ACVP `TupleHash-128-1.0` and `TupleHash-256-1.0`, from the pinned commit (usnistgov/ACVP-Server 975de31eb83d), converted by `scripts/gen_acvp_sp800_185_vectors.py`, which checks each file against a pinned digest and keeps the cases whose every length is whole bytes: all 400 functional cases, fixed-length and XOF at both sizes, with tuples of up to ten elements, some of them empty. Encoding an element's length in bytes where the standard says bits, and leaving the output length out of a fixed-length digest, each fail them. Also rebuilt in-test from SP 800-185 section 5.1 over cSHAKE. Published NIST values |
| ParallelHash | NIST ACVP `ParallelHash-128-1.0` and `ParallelHash-256-1.0`, from the pinned commit (usnistgov/ACVP-Server 975de31eb83d), converted by `scripts/gen_acvp_sp800_185_vectors.py`, which checks each file against a pinned digest and keeps the cases whose every length is whole bytes: 13 of 400, the rest being bit-oriented -- 3 for ParallelHash128 and 10 for ParallelHash256, fixed-length and XOF among each. Few, and enough to fail when the block size is encoded in bits, when the block count is off by one, and when the fixed-length and XOF endings are exchanged. Also rebuilt in-test from SP 800-185 section 6.2 over cSHAKE. Published NIST values |
| KMAC | rebuilt in-test from SP 800-185's own definition over cSHAKE, so the key encoding, padding width and trailing length are each checked against the specification rather than against a value this code produced. **One published value**, for KMAC128: of the 1,600 cases in NIST ACVP `KMAC-128-1.0` and `KMAC-256-1.0` three are whole bytes, all verification cases, and only one of those gives a MAC that is right -- a 478-byte MAC under a 492-byte key, longer than the sponge's rate. The other two are MACs NIST says are wrong, which a wrong KMAC would disagree with too. KMAC256 has no published value here. The valid case at first failed, and so did a KMAC written out separately from the standard: the converter was reading an empty field where NIST keeps a hex customization string in another. Project Wycheproof (C2SP/wycheproof 12fd3aaf33eb), converted by `scripts/gen_wycheproof_vectors.py`, which checks each file against a pinned digest adds what NIST's sample does not: 435 cases for KMAC128 and KMAC256 with no customization string, 165 MACs that are right and 270 altered ones, all judged as marked. So KMAC256 has published values now, 99 of them; neither function has one with a customization string but for the single NIST case above |
| OPAQUE (`ic_hpke::opaque`) | RFC 9807 appendices C.1.5 and C.1.6 (real, the second with client and server identities) and C.2.3 (a login answered from a fake record), the three P256-SHA256 vectors, transcribed by `scripts/gen_opaque_vectors.py`, which pins the RFC's digest and checks each vector's configuration, into `testvectors/rfc9807-p256.json`. Each vector's draws are handed out in protocol order by a scripted source, so the registration request, response and record, KE1, KE2 and KE3, the session key and the export key are all compared byte for byte, the server's half also on its own. The vectors use the Identity KSF; the Argon2id and scrypt KSFs are the functions those rows hold, at RFC 9807's parameters. Every byte of KE1, KE2 and KE3 changed in turn ends the login in an error; a wrong password and a different context are refused. The Expand-Label prefix without its hyphen, the identity defaults swapped, and the preamble one byte short each fail the vectors. The CAST is C.1.5's registration |
| Hashing to P-256 and the OPRF (`ic_ec::hash_to_curve`, `ic_ec::oprf`) | RFC 9380 appendix J.1.1 (P256_XMD:SHA-256_SSWU_RO_, five messages) and K.1 (expand_message_xmd with SHA-256, ten), and RFC 9497 appendix A.3 (P256-SHA256: two OPRF, three VOPRF and three POPRF vectors, two of them batches of two), transcribed from the RFC texts by `scripts/gen_oprf_vectors.py`, which pins each file's digest, into `testvectors/rfc9380-p256.json` and `testvectors/rfc9497-p256.json`. The first J.1.1 vector is also checked stage by stage -- both field elements, both mapped points, the sum -- in `ic-ec`. The OPRF vectors are run with a scripted random source that hands out the RFC's blinds and proof nonces, so the derived keys, blinded and evaluated elements, proofs and outputs are all compared, and each output is also computed by the server's direct evaluation; a proof with one bit changed is refused with nothing written. SSWU with Z = -11, the sign of y left unfixed, the wide reduction multiplying by 2^120 rather than 2^256, the finalize label misspelt, the composite index left out of the proof transcript, and the proof response's sign flipped each fail. The CASTs are A.3.1.1 and J.1.1's "abc" |
| scrypt (`ic_kdf::scrypt`) | RFC 7914 §8 (the Salsa20/8 core) and §12, all four vectors; the fourth, N = 2^20 and 1 GiB, runs when `IC_SLOW_SCRYPT` is set and was run on 2026-10-12 in a release build, where it takes 2.5 s. `testvectors/scrypt-openssl.json`, from `scripts/gen_scrypt_vectors.py`: eight outputs from OpenSSL's EVP_PBE_scrypt through Python's hashlib, which the script first checks against RFC 7914, varying N, r and p independently, with empty and odd-length inputs and outputs either side of a SHA-256 block. PHC strings were checked on 2026-10-12 against the RustCrypto `scrypt` crate 0.11.0 both ways, at three parameter sets: each verifies the other's and refuses a wrong password, and both write the same canonical form |
| bcrypt verification (`ic_kdf::bcrypt`) | `testvectors/bcrypt.json`, from `scripts/gen_bcrypt_vectors.py`: 51 hashes and verdicts from pyca/bcrypt 4.2.1, which is built on the Rust `bcrypt` crate, made on 2026-10-12 -- the `$2a$`, `$2b$` and `$2y$` prefixes, costs 4 to 10, the empty password, passwords of 71, 72 and 73 bytes either side of the limit, non-ASCII, and wrong passwords; every verdict matches. The classic `U*U` hash under `$2a$05$CCCC...` is among them and is the CAST. The Blowfish tables in `crates/ic-kdf/src/bcrypt/tables.rs` are generated by `scripts/gen_blowfish_tables.py`, which computes the hexadecimal digits of pi and checks the first and last P entry and the first word of each S-box against Schneier's published values. Dropping the key's terminating zero, swapping the last two P entries, a wrong S-box in F, the key in place of the salt in the expensive loop, one round fewer, and 63 encryptions in place of 64 each fail the vectors. Every character of a stored hash changed in turn is refused without a panic, and a cost above the default ceiling is refused before any work |
| yescrypt verification (`ic_kdf::yescrypt`) | Transcribed from Openwall's `yescrypt-ref.c` and `yescrypt-common.c` (openwall/yescrypt at 86ea42c2), which are the definition: yescrypt has no specification apart from that code. `testvectors/yescrypt-libxcrypt.json`, from `scripts/gen_yescrypt_vectors.py`: 34 hashes and verdicts from libxcrypt 4.4.38 (Debian libcrypt1 1:4.4.38-1) through ctypes, made on 2026-10-12 -- libxcrypt's own `$y$` salts at three costs, and settings written by the script to reach what those do not vary: the 16 MiB prehashed path, two lanes, t = 1 and 3, r = 1, WORM with and without t and with three lanes, classic scrypt in `$y$` form, empty and 64-byte salts, and `$7$` with one- and two-character p. A mistake in the script's encoding gives libxcrypt a different setting, never a wrong vector. Every verdict matches. Breaking the Salsa20 word shuffle, the S-box write rounds, the prehash key, the ClientKey label, the second pass's flags, the loop counts, the write-index mask, the wrap threshold, or the `$7$` field width each fails the vectors; `t = 1` rounding for the non-read-write flavors survives because it cannot differ there, N being a power of two. A `t` or lane count that would run for minutes inside the memory ceiling is refused, and the test was seen to take 92 s with the work ceiling removed |
| Argon2id, Argon2i, Argon2d | RFC 9106 §5.1–5.3, all three variants |
| Argon2 beyond RFC 9106's vectors, and PHC strings (`ic_kdf::argon2`, `ic_kdf::argon2::phc`) | `testvectors/argon2-reference.json`, from `scripts/gen_argon2_vectors.py` on 2026-10-12. 42 raw tags from libargon2, the reference implementation by Argon2's authors, through argon2-cffi 23.1.0's full `argon2_ctx` binding: versions 1.0 and 1.3, all three variants, one to four lanes, memory that rounds, tags of 4 to 128 bytes, secrets and associated data empty and not. All match, through both the allocating path and caller-provided memory, which is shown wiped afterwards. 19 PHC strings from libargon2's encoder and from libsodium's `crypto_pwhash_str` (PyNaCl 1.5.0), an independent Argon2id, each verified or refused as recorded; the three with `v=` removed verify as version 1.0, which is what libargon2's own decoder was shown to do. RFC 9106's four-lane vectors pass on threads and, forced, one lane at a time. Separately, outputs were compared with argon2 0.6.0 (RustCrypto) at 19 MiB, 64 MiB and 256 MiB with one to four lanes, and agreed. The AVX2 compression function is held to the scalar one, which these vectors hold, block for block over 200 generated pairs in both its overwriting and its XORing form, and the scalar one is run against RFC 9106 on a machine with AVX2 by a test switch. Version 1.0 XORing as 1.3 does, the version left out of `H0`, an off-by-one in the threaded view of other lanes, a missing `v=` read as 1.3, and comparing only part of the hash each fail a test |
| Passphrase sealing (`ic_kdf::passphrase`) | The container format is this library's own, so no standard holds it; a second implementation does. `scripts/gen_passphrase_vectors.py` writes the format from its description over argon2-cffi 23.1.0, which wraps the Argon2 reference code, and PyNaCl 1.5.0, which wraps libsodium, run on 2026-10-12 in an isolated environment; before it seals anything it checks libsodium against draft-irtf-cfrg-xchacha-03's AEAD vector. `testvectors/passphrase.json`: one container under the floor, whose bytes are the CAST, and three at it -- an empty plaintext, a 48-byte key under a non-ASCII passphrase, and two lanes -- which open here to their plaintexts through the public API, refuse the wrong passphrase and a changed byte as authentication failures, and leave the output zeroed. Rerunning the script reproduces the file byte for byte. Not binding the header as associated data, Argon2i in place of Argon2id, and the memory field written little-endian each fail. Every header byte is shown to be authenticated, parameters past the ceiling are refused before any derivation, and the floor is refused on both sides |
| ECDSA P-256 | RFC 6979 A.2.5 (`sample` and `test`), including the published `k` and public key |
| ECDSA P-384 | RFC 6979 A.2.6 (`sample` and `test`), including the published public key |
| ECDH P-256 | NIST CAVP ECC CDH, first published case. Project Wycheproof (C2SP/wycheproof 12fd3aaf33eb), converted by `scripts/gen_wycheproof_vectors.py`, which checks each file against a pinned digest: 1,806 cases over P-256, P-384 and P-521, the first values from outside this library for ECDH on the two larger curves. 1,733 shared secrets match, most of them chosen to hit edge cases of point doubling and of the arithmetic; all 70 invalid keys are refused -- points not on the curve, the invalid-curve attack, and bad encodings -- and the three compressed points Wycheproof marks acceptable either way are accepted and give its shared secret. Not checking that a decoded point is on the curve accepts one of the invalid-curve cases |
| P-521 domain parameters | the base point satisfies the curve equation and `[n]G` is the identity, both checked in-test; a mistyped digit in `b`, `Gx`, `Gy` or `n` fails one of the two |
| ECDSA P-521 | NIST ACVP `DetECDSA-SigGen-FIPS186-5` and `ECDSA-SigVer-FIPS186-5`, from the pinned commit (usnistgov/ACVP-Server 975de31eb83d), converted by `scripts/gen_acvp_sig_vectors.py`, which checks each file against a pinned digest: 11 signing cases with SHA-512, each giving the private key, the public key derived from it and the signature deterministic ECDSA must produce, and 14 verification cases with NIST's verdicts. Until 2026-10-09 this curve had no published value; it was right, and every case passed unchanged. Also cross-checked against an independent RFC 6979 implementation written from the specification text. Published NIST values |
| ECDSA P-256, P-384 and P-521, NIST's cases | the same two ACVP files, in `testvectors/acvp-ecdsa.json`: 206 cases. Signing under each curve's own hash is compared byte for byte, 11 cases a curve; the signatures NIST made under the other hashes this library has that are wide enough for the curve -- SHA-384, SHA-512, SHA-512/256 and the SHA-3 functions -- are verified through `verify_prehash`, 110 cases; and 63 verification cases carry NIST's verdict, 54 of them invalid by a changed message, key, `r` or `s`, or a zeroed `r` or `s`. Half of NIST's signing file is not used: the groups marked `conformance: SP800-106` sign a randomized message, which is not implemented, and converting them by mistake at first made a correct signer look wrong until two independent RFC 6979 computations agreed with NIST's plain groups and not with those. P-384 has no verification case under SHA-384 in NIST's sample. Making the nonce derivation's second round use the wrong byte, and taking one HMAC block where P-521 needs two, each fail these. **One mutation does not**: removing the verifier's explicit check that `r` and `s` are not zero changes nothing -- NIST's zeroed cases, and a test added for both zero at once, are still refused by the arithmetic after it. That check is held by no test and cannot be: nothing reaches past it. Published NIST values |
| ECDSA `verify_prehash`, every curve with SHA-224, -256, -384 and -512 | `crates/ic-ec/tests/ecdsa_prehash.rs`, generated by `scripts/gen_ecdsa_prehash.py` with pyca/cryptography 50.0.0 (OpenSSL 3.5.7) deterministic ECDSA. The P-256 and P-384 keys are RFC 6979's, and the generator refuses to run unless it reproduces the RFC values for their native hashes that the unit tests above check, so those 16 signatures are RFC 6979 A.2.5 and A.2.6's for each hash; the P-521 key is the generator's own, so its 8 are an interoperability check rather than published values. Beyond the values, the test checks FIPS 186-5's truncation as a rule: bytes of a digest past the order's width change nothing, and bytes within it are bound |
| HMAC_DRBG | NIST ACVP `hmacDRBG-1.0`, from the pinned commit (usnistgov/ACVP-Server 975de31eb83d), converted by `scripts/gen_drbg_vectors.py`, which checks each file against a pinned digest: every case of the groups for SHA-256, SHA-384, SHA-512, SHA-512/256, SHA3-256 and SHA3-512, with and without prediction resistance, 180 cases. Each drives instantiate, reseed and generate, and compares the second generate's output, 512 bytes. The groups for SHA-1, SHA-224, SHA-512/224, SHA3-224 and SHA3-384 are not run: there is no HMAC for those here. With prediction resistance each generate is run as SP 800-90A section 9.3.1 defines it, a reseed with the additional input and then a generate with none; the library has no prediction-resistance flag of its own. Leaving the nonce out of instantiate, ignoring the additional input in reseed and skipping it in generate each fail the vectors. The self-test is the first case without prediction resistance, copied into `ic-drbg/src/kat.rs` by the script, and fails when reseed is made to do nothing. Also checked against an independent in-test transcription of the SP 800-90A §10.1.2 pseudocode. Published NIST values |
| CTR_DRBG | NIST ACVP `ctrDRBG-1.0`, from the pinned commit (usnistgov/ACVP-Server 975de31eb83d), converted by `scripts/gen_drbg_vectors.py`, which checks each file against a pinned digest: both groups for AES-256 without a derivation function, with and without prediction resistance, 30 cases, run as the HMAC_DRBG cases are. AES-128, AES-192, TDES and the derivation function are not implemented and their groups are not run. Until 2026-10-09 this mechanism had no known answer at all -- its tests and its self-test checked only that output was reproducible and not constant, which a wrong DRBG also satisfies. It was right: all 30 cases passed unchanged. Ignoring the additional input in reseed, skipping it in generate, and encrypting the counter before incrementing it each fail the vectors, and the self-test, now the first NIST case, fails when reseed is made to do nothing. Published NIST values |
| PBKDF2 | reconstructed from the PRF XOR chain (RFC 6070 publishes HMAC-SHA1 only, which this library does not implement). The self-test (`pbkdf2_hmac_sha2_256_self_test`) cannot use RFC 7914 section 11's PBKDF2-HMAC-SHA256 vectors, which run one iteration where `pbkdf2` refuses fewer than SP 800-132's 1000; its value, at 1000 iterations, is Python `hashlib.pbkdf2_hmac`'s (OpenSSL's implementation), and `hashlib` was first required to reproduce the RFC 7914 c=1 vector. Recomputed on 2026-10-06. An independent implementation's output, not a published value. Since 2026-10-09 also Project Wycheproof (C2SP/wycheproof 12fd3aaf33eb), converted by `scripts/gen_wycheproof_vectors.py`, which checks each file against a pinned digest: 118 cases for HMAC-SHA-256 and HMAC-SHA-512, of which 48 reach the arithmetic and match, at 4096 iterations and one at 80000, with outputs of 16, 42 and 65 bytes, so more than one block. The other 70 use fewer than 1000 iterations or a salt under 16 bytes, which `pbkdf2` refuses by its own rule, and are checked to be refused. Encoding the block counter little-endian, and running one iteration too many, each fail the 48. These are the first PBKDF2 values from outside this library and Python's `hashlib` that it has been held to |
| SP 800-108 counter mode, HMAC-SHA256 | the self-test (`sp800_108_counter_hmac_sha2_256_self_test`) value comes from a transcription of SP 800-108r1 section 4.1 in Python's `hmac` -- `HMAC(K, [i]_32 || Label || 0x00 || Context || [L]_32)` per block -- sharing nothing with `ic_kdf`. It asks for 48 bytes, two blocks, so the counter's increment is covered. Recomputed on 2026-10-06. No CAVP KBKDF vector is wired in, since CAVP fixes the counter's position and width per case and this encoding is one of them; an independent transcription, not a published value |
| RSA PKCS#1 v1.5 verification, SHA-256 | NIST ACVP `RSA-SigVer-FIPS186-5`, from the pinned commit (usnistgov/ACVP-Server 975de31eb83d), converted by `scripts/gen_acvp_sig_vectors.py`, which checks each file against a pinned digest: all 108 PKCS#1 v1.5 cases, at 2048, 3072 and 4096 bits, 18 valid and 90 that NIST made invalid by changing the message, the key or the signature, or by moving or altering the encoded digest. Comparing only the digest at the end of the encoded message, and not the whole of it, fails them. They cover SHA-256 only, verification only, and exponents of 32 to 56 bits and not 65537. **Nothing here covers RSA-PSS**: NIST's sample uses SHA-3 and SHAKE for it, which this library's PSS does not. Published NIST values. Also Project Wycheproof (C2SP/wycheproof 12fd3aaf33eb), converted by `scripts/gen_wycheproof_vectors.py`, which checks each file against a pinned digest: 1,293 cases for SHA-256, SHA-384 and SHA-512 at 2048 bits and SHA-256 at 3072 and 4096, of which 1,249 are signatures made wrong in a particular way -- padding shortened or altered, a digest encoding with extra or missing fields, the wrong hash identifier. All are refused, each as a failed signature and no other kind of error; the 39 valid ones are accepted; and the 5 Wycheproof marks acceptable either way, which are signatures whose digest encoding leaves out an optional field, are refused. SHA-384 and SHA-512 at the two larger sizes are four more files of the same malformations and are not bundled |
| RSA PKCS#1 v1.5 | the DigestInfo prefixes are rebuilt from the algorithm OID and checked against the constants in RFC 8017 §9.2; the encoded message is checked against an independent in-test construction; the CAST signatures are implementation-pinned. **Signing is checked against Project Wycheproof** (C2SP/wycheproof 12fd3aaf33eb, `rsa_pkcs1_*_sig_gen_test.json`, in `testvectors/wycheproof-rsa-sign.json`): PKCS#1 v1.5 is deterministic, so a private key and a message have one signature, and 77 are compared byte for byte -- eight messages under each of SHA-256, SHA-384 and SHA-512 at 2048, 3072 and 4096 bits, and five more under keys with a public exponent of 3 that Wycheproof marks acceptable. Truncating the private exponent fails them. Wycheproof gives exponents and no primes, so these reach the private-key operation without the CRT; that the CRT path agrees with it is held by this crate's own tests and by nothing published |
| RSA-PSS | MGF1 against an in-test transcription of RFC 8017 B.2.1; the encoder against the separately written verifier; the CAST signatures are implementation-pinned. **Verification is checked against Project Wycheproof (C2SP/wycheproof 12fd3aaf33eb), converted by `scripts/gen_wycheproof_vectors.py`, which checks each file against a pinned digest**: all six files for PSS as this library has it -- MGF1 over the same hash, salt as long as the hash -- at 2048, 3072 and 4096 bits with SHA-256, SHA-384 and SHA-512, 785 cases. All 511 valid signatures are accepted and all 274 invalid ones refused. Wycheproof is not a standard; it is a set of cases built to catch mistakes, and these are the first signatures from outside this library that its PSS verifier has been held to. Not checking the trailer byte, the spare top bits, the zero padding or the separator each accept a signature Wycheproof marks invalid. **Signing is checked against NIST's CAVP examples**, `SigGenPSS_186-3.txt` from `186-3rsatestvectors.zip` (CAVS 11.4), downloaded from csrc.nist.gov on 2026-10-10 and converted by `scripts/gen_cavp_rsa_pss_vectors.py`, which checks the file against a pinned digest, into `testvectors/cavp-rsa-pss-sign.json`. A PSS signature is randomized, and this is the one file in which NIST publishes the salt and the private exponent, so each signature is determined. The salt reaches the signer as it does in use, through the caller's random source, so the public `sign` is what is tested. **Twenty signatures, and no more**: NIST's salts are as long as the hash only for SHA-256 and SHA-384 at 3072 bits, ten messages each, and those are reproduced byte for byte. Signing with SHA-512, and at 2048 and 4096 bits, has no outside value; what holds those is that the same code path produced the twenty, and that the Wycheproof-checked verifier accepts what it makes. NIST gives no primes, so these reach the private-key operation without the CRT. The other forty cases -- SHA-256, SHA-384 and SHA-512 at 2048 bits with salts of 20, 25 and 30 bytes, and SHA-512 at 3072 with 62 -- are valid signatures of a PSS this library does not have, and the verifier refuses each as a failed signature. pyca/cryptography 50.0.0 verified all sixty under the salt length each case states, as a check on the conversion. Seven zero bytes in M' instead of eight, a little-endian MGF1 counter, not clearing the top bit, the separator a byte early and a wrong trailer byte each change a signature and fail the test; a verifier that takes the salt's length from the signature fails the forty |
| QUIC header protection | RFC 9001 appendix A.2, A.3 and A.5: AES with a four-byte and a two-byte packet number, and the separate ChaCha20 construction. Each transcribed with its derivation checked against the mask the RFC prints. **These vectors do not constrain the mask width**: in all three, bit `0x10` of the mask's first byte is zero, so the long-header rule (`& 0x0f`) and the short-header rule (`& 0x1f`) agree on every published example. Swapping the two leaves all three passing, which was confirmed by doing it, so the rule is checked separately against a sample where that bit is set |
| RSA keys | the identity `(m^e)^d = m (mod n)`, which holds only if `p` and `q` are prime and `d` inverts `e`; Miller-Rabin is checked against Carmichael numbers, which a Fermat test would pass |

Where a row says a vector is missing, supplying one needs no code: drop a file
in `testvectors/` and the matching test starts checking against it. See
`testvectors/README.md` for the format and for how to convert ACVP output.

A published vector constrains only what its own bytes exercise. That sounds
obvious and is easy to forget, because "checked against the RFC" reads like a
completeness claim and is not one: the QUIC row above is a case where three
authoritative vectors all passed against code with an inverted branch, because
the bit that distinguishes the two branches happens to be zero in every
published example. Where behaviour depends on a condition the vectors do not
vary -- a header form, a key length, a padding choice -- the distinction needs
its own test, driven by the rule rather than by a value. Breaking the code and
confirming the test notices is the cheapest way to find out which case you are
in.

RSA-PSS signing was the weak row until it was run against NIST's CAVP
examples, the one place the salt is published, and it is still the thin one:
twenty signatures, at 3072 bits, with SHA-256 and SHA-384. Signing with
SHA-512 and at other sizes rests on the same code having produced those
twenty and on the verifier accepting what it makes. The RSA private-key
operation with the CRT is reached by one outside value, the PKCS#1 v1.5
signatures OpenSSL made with keys that carry their primes; Project
Wycheproof's and NIST's signatures reach it without. The
self-test signatures are values this implementation produced. The DRBG rows
were among the weak ones until they were run against NIST's ACVP vectors, as
were ECDSA P-521 and RSA PKCS#1 v1.5 verification; RSA-PSS verification,
PBKDF2, KMAC256 and ECDH on P-384 and P-521 until they were run against
Project Wycheproof, which is a test suite and not a standard. NIST's sample
files do not reach those: its
PBKDF cases are HMAC-SHA-224 and its RSA-PSS cases SHA-3 and SHAKE, none of
which is implemented here; its KMAC cases are bit-oriented but for three;
its SP 800-108 cases fix the input in a form `kbkdf_counter` does not take;
and its ECDH cases are on curves this library does not have. NIST's ACVP RSA vectors are not reproducible
offline; the pinned signatures there catch regression rather than establishing
correctness, which the rows above them do instead. Wiring in the CAVP `.rsp`
response files is a pre-validation task (below).

### Integrity test

`ic_fips::selftest::integrity_check()` computes an HMAC over the self-test
table. This detects a corrupted or partially linked constant pool — flip a byte
in any embedded vector and it fails.

It is **not** an image integrity test. A conforming one MACs the executable
image against a value patched in after linking, which is a property of the build
system rather than the source. The function's documentation says so explicitly,
so its name cannot imply more than it delivers.

## Compiled-code regression gate

`scripts/check-ct.py` gates 303 probe/target checks over the actual
implementations with fat LTO: 44 fixed-parameter probes on each of five targets
(x86-64, Cortex-M0, Cortex-M4, 32-bit RISC-V and AArch64), 76 more on x86-64
and 7 more on AArch64.
The first run caught secret-dependent branches in ML-DSA's rounding masks and
ML-KEM compression, despite their arithmetic-only source. Input and output
barriers now prevent those transformations in the tested builds. Removing the
input barrier from either fix makes the gate fail; restoring it passes.

The existing exhaustive arithmetic comparisons and published vectors constrain
the numerical results independently. No new vector constants were introduced.
[CONSTANT_TIME.md](CONSTANT_TIME.md) records the precise coverage and limits;
this gate does not prove constant time for complete algorithms or constitute
hardware timing measurements.

The subsequent [host timing reports](timing/2026-09-29-host/README.md) include
positive controls and batched measurements of the two affected kernels. They
are busy-host diagnostics with recorded CPU load, not quiet-hardware evidence
or a proof that other input classes cannot leak.

## What validation would still require

In rough order of effort:

1. **CAVP algorithm certificates.** Every approved algorithm must pass the ACVP
   test harness, including Monte Carlo and large-data tests, not just the sample
   vectors bundled here.
2. **A real image integrity test.** A post-link step that computes an approved
   MAC or signature over the module image and patches it in.
3. **SP 800-90B entropy source validation.** The OS entropy source must be
   characterized and justified, with health tests (repetition count, adaptive
   proportion) on the raw noise source. None of that is here, and none of it
   can be from here: the raw samples are the operating system's. What `Rng`
   does check is the one failure visible in what it is handed -- a seed with
   eight equal bytes in a row, or a second draw that begins as the first did,
   is refused and ends the module. The cutoff is this library's choice, made
   so that a working source trips it about once in `2^50` seeds; it is not a
   90B cutoff, and a weak or replayed source passes it.
4. **Documentation package.** Security policy, finite state model, algorithm
   specification, and the vendor evidence the lab requires.
5. **Laboratory testing and CMVP submission** against a specific binary on
   specific operational environments.
6. **An enforced module boundary.** The error state now reaches every
   operation that can report an error, however it is called. A build with
   `--cfg ic_approved_only` contains no algorithm approved mode refuses, and
   refuses every such operation until the self-tests have passed. Since 0.3.0
   hashes, XOFs and MACs refuse on output too. What is left is the default
   build, where self-tests before first use are still the caller's to ask
   for, and a block cipher's per-block methods, ungated by decision; a lab
   would have to accept the second or see it closed.
7. **Continuous health tests on the DRBGs** and pairwise-consistency tests on
   every generated key pair. ML-KEM, ML-DSA and RSA key generation check their
   pairs, and so does HPKE's `KeyPair::generate` for both KEMs, by computing
   the public key from the private key a second time and comparing -- the
   test for a key-agreement key, which has no second operation to apply in
   turn. That description of the test is from memory of SP 800-56A Rev. 3
   section 5.6.2.1.4 and was not re-read for this change. Three things are
   still untested. The ephemeral key `setup_sender` makes for each message is
   not, by decision: it would add a third scalar multiplication to the two a
   sender performs. SLH-DSA's `keygen_internal`, the interface that takes its
   seeds as arguments, is not; `keygen` is, by a signature made and verified,
   which is most of what it now costs. Measured here in an optimised build,
   two to five runs a set, it takes nine to thirty-six times what generating
   the key alone does: from about 10 ms for SLH-DSA-SHA2-128f to about 2 s
   for the SHAKE small-signature sets. It also holds that signature on the
   stack, 7,856 to 49,856 bytes. And the curve crates have no key generation
   to test -- a caller draws the scalar and asks for its public key. A failed
   test withholds the key, returns `SelfTestFailed` (or `false`, from ML-DSA),
   and puts the module into its error state: the test's input is the module's
   own output, so a failure is the module disagreeing with itself and not
   something a peer can cause. Each test function is shown rejecting a
   mismatched pair, and `ic_core::module::conditional_self_test` is shown
   entering the state on a failure; that each key generator passes its test
   through it is by reading, since making a real key generation fail would
   need a fault injected into it.

ECDSA and ECDH are already implemented and vector-tested over P-256, P-384
and P-521. Algorithm coverage does not replace any of the work above.
These tasks require a defined module boundary, operational environments and
validation process; passing this repository's tests does not complete them.

## Using this under a FIPS requirement today

If you have a genuine FIPS obligation:

- **Validation, not coverage, is the blocker now.** IronCrypto implements
  approved algorithms across the board — AES-GCM, HMAC, CMAC, HKDF, PBKDF2,
  SP 800-108, the DRBGs, ECDSA and ECDH over P-256, P-384 and P-521, ML-KEM and
  ML-DSA — correctly against their published vectors. But *correct* and *validated* are different words, and only
  the second satisfies an auditor. Where a certificate is the actual
  requirement, use a validated module.
- Where you need RSA encryption, this module has nothing to offer, and
  `ic recommend` will say so rather than substituting a smaller curve.
- Use the approved-mode policy engine and the ontology to keep your own code
  honest regardless of which module does the arithmetic. The registry is useful
  even when the implementation behind it is somebody else's.
