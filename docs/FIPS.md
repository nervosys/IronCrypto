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

```
Uninitialized ──initialize()──> SelfTestInProgress ──all pass──> Operational(Unrestricted)
                                        │                               ↕ set_mode()
                                        │                        Operational(Approved)
                                        └──any fail──> Error (latched)
```

No cryptographic service is available before `initialize()`. The error state
**latches**: once entered, `check`, `initialize`, and `set_mode` all fail with
`ModuleErrorState` until the process restarts. There is deliberately no API to
clear it.

The module comes up *unrestricted*. Entering approved mode is an explicit
operator decision, never a default a caller might not have noticed.

### Approved mode of operation

In approved mode, `ic_fips::check(id)` refuses any algorithm the ontology does
not mark as permitted. The policy is data, not a hard-coded list — it reads
`FipsStatus::permitted_in_approved_mode()` straight from the registry, so the
policy and the documentation cannot drift apart.

```rust
ic_fips::set_mode(Mode::Approved)?;
ic_fips::check("aes-256-gcm")?;            // ServiceIndicator::Approved
ic_fips::check("chacha20-poly1305")        // Err(NotApprovedInFipsMode)
```

### Service indicator

FIPS 140-3 requires the module to tell the caller whether the service just used
was an approved one. `check` returns that indicator, and `guarded` pairs it with
the operation:

```rust
let (digest, indicator) = ic_fips::guarded("sha2-256", || Sha256::digest(data))?;
assert_eq!(indicator, ServiceIndicator::Approved);
```

Three values: `Approved`, `ApprovedAsComponent` (a raw block cipher used inside
a mode), `NotApproved`.

### Cryptographic algorithm self-tests

60 known-answer tests, one per implemented algorithm, run by `initialize()` and
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

60 passed, 0 failed; integrity check passed
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
| CMAC | SP 800-38B examples for all three key sizes |
| HMAC | RFC 4231; NIST HMAC-SHA3 samples |
| HKDF | RFC 5869 test cases 1–3 |
| ChaCha20, Poly1305, ChaCha20-Poly1305 | RFC 8439 |
| X25519 | RFC 7748 §5.2 and §6.1 |
| Ed25519 | RFC 8032 §7.1 |
| NIST field and RSA arithmetic on 32-bit words (`narrow` in `ic-ec/src/nist/arith.rs` and `ic-rsa/src/uint.rs`, used on `riscv32`) | compared bit for bit with the 64-bit forms: for the NIST fields, `adc`, `sbb` and Montgomery multiplication on all six moduli, 256 operand pairs each including 0, 1, m - 1 and all ones; for RSA, the three word operations on 31 values, every pair, with edge carries. Every NIST and RSA vector and the rustls suite pass with them selected by `--cfg ic_limb32`. Using the high half of `-m^-1`, ignoring an incoming borrow, dropping the final carry of a Montgomery step, and in RSA dropping any of four inter-column carries each fail both. One mutation of `sbb`, reading bit 62 of the borrow for bit 63, is equivalent -- both are set whenever a 32-bit subtraction wraps -- and is not a gap |
| ML-DSA `power2round`, `decompose`, reduction mod q (`ic-mldsa/src/rounding.rs`); ML-KEM `compress` (`ic-mlkem/src/encode.rs`) | the constant-time forms against FIPS 204 Algorithms 35 and 36 as written, kept in the tests as oracles, on every residue in `[0, q)` for both `gamma2`, plus negative bands; `reduce_q` against `rem_euclid` on every value within `4q` of zero and of both ends of `i32` and on every multiple of `2^16` either side; `compress` against the formula for every `x < q` and `d` from 1 to 12. A wrong folding constant, rounding half up, a dropped fold, a dropped centring, an off-by-one in the mod-5 constant, a missing correction and an overshooting estimate each fail. Two mutations are equivalent and recorded as such: a centring threshold anywhere between `gamma2` and `q - gamma2`, and a compression constant one lower, whose estimate the correction still absorbs |
| GF(2^255 - 19) on 32-bit limbs (`ic-ec/src/field32.rs`, used on `riscv32`) | the RFC 7748 and 8032 vectors, and the whole `ic-ec` and `iron-crypto` suites, pass with it selected on a host by `--cfg ic_limb32`. Under ordinary test it is compared with the five-limb field on 29 operands chosen for their bounds, every pair, for every operation. Its straight-line multiplication, squaring and byte packing were generated by `scripts/gen_fe32.py`, which checks each against integer arithmetic mod p on random operands before printing it. A wrong reduction constant, a missing doubling of odd-limb products in either multiplication, an off-by-one in the final subtraction of p, a dropped last byte, a wrong limb of 2p and an unscaled top carry each fail both the comparison and the suite run under `ic_limb32` |
| ML-KEM-768 | ACVP `ML-KEM-keyGen-FIPS203` and `ML-KEM-encapDecap-FIPS203`, every ML-KEM-768 case in both: 25 key generation and 25 encapsulation. Key generation is deterministic in its seed, so each case pins the sampler, the NTT, the compression and the key encoding together. The NTT is also checked against schoolbook multiplication and the samplers against FIPS 203's pseudocode, which is what localises a failure when one happens. Registered `available` |
| ML-KEM-512, ML-KEM-1024 | The same two ACVP files, every case of each set: 25 key generation and 25 encapsulation apiece, from the same pinned commit (usnistgov/ACVP-Server 975de31eb83d). The scheme is ML-KEM-768's code instantiated with each set's five parameters, so a set is registered only on its own vectors: they are what differs. The extraction was checked by regenerating ML-KEM-768's vendored files from the same download, which matched byte for byte. Setting ML-KEM-512's `eta1` to 2 fails its key generation and encapsulation vectors; setting ML-KEM-1024's `dv` to 4 fails its encapsulation vectors and leaves key generation passing, as it should, since `dv` only shapes ciphertexts. Registered `available` |
| ML-DSA-65 | ACVP `ML-DSA-keyGen-FIPS204` and `ML-DSA-sigGen-FIPS204`, every ML-DSA-65 case in the external pure groups: 25 key generation, 15 deterministic signatures and 15 hedged ones using the randomness each vector specifies. The NTT is also checked against schoolbook multiplication, the packing against a bit-at-a-time reference, and rounding and hints against the equations that define them. Registered `available`; the pure and pre-hash variants are both present and are asserted not to accept each other's signatures |
| ML-DSA-44, ML-DSA-87 | The same two ACVP files, every case of each set: 25 key generation, and 30 signatures from the external pure groups, 15 deterministic and 15 hedged, from the same pinned commit (usnistgov/ACVP-Server 975de31eb83d). The scheme is ML-DSA-65's code instantiated with each set's parameters, registered on its own vectors. The extraction was checked by regenerating ML-DSA-65's vendored files from the same download, which matched byte for byte. Setting ML-DSA-44's `tau` to 49 fails its signature vectors and leaves key generation passing; giving ML-DSA-87 ML-DSA-44's `gamma2` fails both, since key generation runs a sign-and-verify consistency check. The hostile-input suite in `ic-mldsa/tests/robustness.rs` runs unchanged against each set. Registered `available` |
| All six ML-KEM and ML-DSA sets, against OpenSSL | `testvectors/openssl-ml-kem.json` and `openssl-ml-dsa.json`, produced by OpenSSL 3.5.7 on 2026-09-29 with the commands recorded in each file. `iron-crypto/tests/openssl_interop.rs` regenerates OpenSSL's keys from its seeds, requires deterministic ML-DSA signatures to equal OpenSSL's byte for byte, verifies OpenSSL's hedged signatures, and decapsulates OpenSSL's ciphertexts to its secrets. Giving ML-DSA-87 an `omega` of 80 fails it at the first ML-DSA-87 signature while its keys still match. The reverse directions were run once by hand the same day: a small program encapsulated to each OpenSSL ML-KEM key and signed, hedged, under each OpenSSL ML-DSA key, and `openssl pkeyutl -decap` recovered the same secret and `openssl pkeyutl -verify -rawin` accepted every signature, for all six sets. These are interoperability checks, not vectors from a standard |
| X.509 issuance (`ic_pkix::cert`) | `testvectors/openssl-x509.json`: a CA and a leaf that OpenSSL 3.5.7 issued for Ed25519, ML-DSA-65 and ML-DSA-87 with every input fixed and ML-DSA signing deterministically, each chain passing `openssl verify -x509_strict`. `iron-crypto/tests/x509_issuance.rs` issues the same six certificates and requires them byte for byte. A key-usage unused-bit count off by one, extended key usage written before key usage, and `GeneralizedTime` chosen from 2026 rather than 2050 each fail it -- the second only for the leaves, which are the certificates carrying both extensions. ECDSA signatures are random, so P-256 and P-384 chains issued here were checked by `openssl verify -x509_strict` instead, on 2026-09-29, and passed. The OIDs are rebuilt from their dotted arcs, and the time encoding is tested against a day-by-day calendar count from 1970 into 2100 |
| POLYVAL | checked against the GHASH construction of RFC 8452 Appendix A, over a GHASH the published GCM vectors validate |
| AES-GCM-SIV | RFC 8452 appendix C, all 50 published cases across C.1, C.2 and C.3, for both key lengths and in both directions. That includes the counter-wrap tests of C.3, which exist because an implementation can pass every other case and still get the block counter wrong. Registered `available` |
| BLAKE2b | RFC 7693 Appendix A |
| cSHAKE | checked against a Keccak written from FIPS 202 in-test and anchored to the published SHA3-256 answer, plus SP 800-185 section 3.3's identity with SHAKE; no published cSHAKE vector is wired in |
| TupleHash, ParallelHash | rebuilt in-test from SP 800-185 sections 5.1 and 6.2 over cSHAKE, the same way KMAC is |
| KMAC | rebuilt in-test from SP 800-185's own definition over cSHAKE, so the key encoding, padding width and trailing length are each checked against the specification rather than against a value this code produced |
| Argon2id, Argon2i, Argon2d | RFC 9106 §5.1–5.3, all three variants |
| ECDSA P-256 | RFC 6979 A.2.5 (`sample` and `test`), including the published `k` and public key |
| ECDSA P-384 | RFC 6979 A.2.6 (`sample` and `test`), including the published public key |
| ECDH P-256 | NIST CAVP ECC CDH, first published case |
| P-521 domain parameters | the base point satisfies the curve equation and `[n]G` is the identity, both checked in-test; a mistyped digit in `b`, `Gx`, `Gy` or `n` fails one of the two |
| ECDSA P-521 | cross-checked against an independent RFC 6979 implementation written from the specification text, sharing no code with this one; no published vector is wired in |
| HMAC_DRBG | validated against an independent in-test transcription of the SP 800-90A §10.1.2 pseudocode; the CAST vector is an implementation-pinned integrity value |
| CTR_DRBG | determinism and independence properties; no published vector wired in |
| PBKDF2 | reconstructed from the PRF XOR chain (RFC 6070 publishes HMAC-SHA1 only, which this library does not implement) |
| RSA PKCS#1 v1.5 | the DigestInfo prefixes are rebuilt from the algorithm OID and checked against the constants in RFC 8017 §9.2; the encoded message is checked against an independent in-test construction; the CAST signatures are implementation-pinned |
| RSA-PSS | MGF1 against an in-test transcription of RFC 8017 B.2.1; the encoder against the separately written verifier; the CAST signatures are implementation-pinned |
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

The DRBG, PBKDF2, and RSA rows are the weak ones, and are called out as such
rather than being papered over. NIST's ACVP RSA vectors are not reproducible
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

`scripts/check-ct.py` builds thirteen fixed-parameter probes over the actual
implementations with fat LTO on x86-64, Cortex-M0, Cortex-M4 and 32-bit RISC-V.
The first run caught secret-dependent branches in ML-DSA's rounding masks and
ML-KEM compression, despite their arithmetic-only source. Input and output
barriers now prevent those transformations in the tested builds. Removing the
input barrier from either fix makes the gate fail; restoring it passes.

The existing exhaustive arithmetic comparisons and published vectors constrain
the numerical results independently. No new vector constants were introduced.
[CONSTANT_TIME.md](CONSTANT_TIME.md) records the precise coverage and limits;
this gate does not prove constant time for complete algorithms or constitute
hardware timing measurements.

## What validation would still require

In rough order of effort:

1. **CAVP algorithm certificates.** Every approved algorithm must pass the ACVP
   test harness, including Monte Carlo and large-data tests, not just the sample
   vectors bundled here.
2. **A real image integrity test.** A post-link step that computes an approved
   MAC or signature over the module image and patches it in.
3. **SP 800-90B entropy source validation.** The OS entropy source must be
   characterized and justified, with health tests (repetition count, adaptive
   proportion) on the raw noise source.
4. **Documentation package.** Security policy, finite state model, algorithm
   specification, and the vendor evidence the lab requires.
5. **Laboratory testing and CMVP submission** against a specific binary on
   specific operational environments.

ECDSA and ECDH are already implemented and vector-tested over P-256, P-384
and P-521. Algorithm coverage does not replace any of the work above.
These tasks require a defined module boundary, operational environments and
validation process; passing this repository's tests does not complete them.

## Using this under a FIPS requirement today

If you have a genuine FIPS obligation:

- **Validation, not coverage, is the blocker now.** IronCrypto implements
  approved algorithms across the board — AES-GCM, HMAC, CMAC, HKDF, PBKDF2,
  SP 800-108, the DRBGs, and ECDSA and ECDH over P-256 and P-384 — correctly against their
  published vectors. But *correct* and *validated* are different words, and only
  the second satisfies an auditor. Where a certificate is the actual
  requirement, use a validated module.
- Where you need RSA encryption, this module has nothing to offer, and
  `ic recommend` will say so rather than substituting a smaller curve.
- Use the approved-mode policy engine and the ontology to keep your own code
  honest regardless of which module does the arithmetic. The registry is useful
  even when the implementation behind it is somebody else's.
