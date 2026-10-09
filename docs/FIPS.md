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

**The gate is opt-in.** The primitive crates cannot depend on `ic-fips`, which
depends on them, and the facade re-exports them, so a caller who calls a
primitive directly -- `ic_cipher::Aes256Gcm::new`, `ic_hpke::setup_sender` --
reaches it whatever the module's state and mode. The state machine, the
self-tests before first use and the latched error state hold for services
requested through the policy layer, and only for those. A validated module
would have to enforce that boundary; see the list below.

The module comes up *unrestricted*. Entering approved mode is an explicit
operator decision, never a default a caller might not have noticed.

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
    assert_eq!(digest.len(), 32);
    Ok(())
}
```

Three values: `Approved`, `ApprovedAsComponent` (a raw block cipher used inside
a mode), `NotApproved`.

### Cryptographic algorithm self-tests

75 known-answer tests, one per implemented algorithm except six variants whose
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
| CMAC | SP 800-38B examples for all three key sizes |
| HMAC | RFC 4231 (case 6, the hashed long key, for SHA-256, SHA-384 and SHA-512; the SHA-384 and SHA-512 tags also checked against Python's `hmac`); NIST HMAC-SHA3 samples |
| HKDF | RFC 5869 test cases 1–3 |
| ChaCha20, Poly1305, ChaCha20-Poly1305 | RFC 8439 |
| X25519 | RFC 7748 §5.2 and §6.1 |
| Ed25519 | RFC 8032 §7.1 |
| NIST field and RSA arithmetic on 32-bit words (`narrow` in `ic-ec/src/nist/arith.rs` and `ic-rsa/src/uint.rs`, used on `riscv32`) | compared bit for bit with the 64-bit forms: for the NIST fields, `adc`, `sbb` and Montgomery multiplication on all six moduli, 256 operand pairs each including 0, 1, m - 1 and all ones; for RSA, the three word operations on 31 values, every pair, with edge carries. Every NIST and RSA vector and the rustls suite pass with them selected by `--cfg ic_limb32`. Using the high half of `-m^-1`, ignoring an incoming borrow, dropping the final carry of a Montgomery step, and in RSA dropping any of four inter-column carries each fail both. One mutation of `sbb`, reading bit 62 of the borrow for bit 63, is equivalent -- both are set whenever a 32-bit subtraction wraps -- and is not a gap |
| Core `Choice::mask`, byte selection and four-byte conditional copy/swap | truth-table properties over all 256 input flags, including every nonzero value; no asserted external vector. Fixed-size LTO probes on x86-64, Cortex-M0/M4 and RISC-V check compiled control flow. Removing the input barrier before mask negation reproduced secret-dependent branches in all three Cortex-M0 paths; restoring it passed. Scope and limitations are in `docs/CONSTANT_TIME.md` |
| ML-DSA `power2round`, `decompose`, reduction mod q (`ic-mldsa/src/rounding.rs`); ML-KEM `compress` (`ic-mlkem/src/encode.rs`) | the constant-time forms against FIPS 204 Algorithms 35 and 36 as written, kept in the tests as oracles, on every residue in `[0, q)` for both `gamma2`, plus negative bands; `reduce_q` against `rem_euclid` on every value within `4q` of zero and of both ends of `i32` and on every multiple of `2^16` either side; `compress` against the formula for every `x < q` and `d` from 1 to 12. A wrong folding constant, rounding half up, a dropped fold, a dropped centring, an off-by-one in the mod-5 constant, a missing correction and an overshooting estimate each fail. Two mutations are equivalent and recorded as such: a centring threshold anywhere between `gamma2` and `q - gamma2`, and a compression constant one lower, whose estimate the correction still absorbs |
| GF(2^255 - 19) on 32-bit limbs (`ic-ec/src/field32.rs`, used on `riscv32`) | the RFC 7748 and 8032 vectors, and the whole `ic-ec` and `ironcrypto` suites, pass with it selected on a host by `--cfg ic_limb32`. Under ordinary test it is compared with the five-limb field on 29 operands chosen for their bounds, every pair, for every operation. Its straight-line multiplication, squaring and byte packing were generated by `scripts/gen_fe32.py`, which checks each against integer arithmetic mod p on random operands before printing it. A wrong reduction constant, a missing doubling of odd-limb products in either multiplication, an off-by-one in the final subtraction of p, a dropped last byte, a wrong limb of 2p and an unscaled top carry each fail both the comparison and the suite run under `ic_limb32` |
| ML-KEM-768 | ACVP `ML-KEM-keyGen-FIPS203` and `ML-KEM-encapDecap-FIPS203`, every ML-KEM-768 case in both: 25 key generation and 25 encapsulation. Key generation is deterministic in its seed, so each case pins the sampler, the NTT, the compression and the key encoding together. The NTT is also checked against schoolbook multiplication and the samplers against FIPS 203's pseudocode, which is what localises a failure when one happens. Registered `available` |
| ML-KEM-512, ML-KEM-1024 | The same two ACVP files, every case of each set: 25 key generation and 25 encapsulation apiece, from the same pinned commit (usnistgov/ACVP-Server 975de31eb83d). The scheme is ML-KEM-768's code instantiated with each set's five parameters, so a set is registered only on its own vectors: they are what differs. The extraction was checked by regenerating ML-KEM-768's vendored files from the same download, which matched byte for byte. Setting ML-KEM-512's `eta1` to 2 fails its key generation and encapsulation vectors; setting ML-KEM-1024's `dv` to 4 fails its encapsulation vectors and leaves key generation passing, as it should, since `dv` only shapes ciphertexts. Registered `available` |
| ML-DSA-65 | ACVP `ML-DSA-keyGen-FIPS204` and `ML-DSA-sigGen-FIPS204`, every ML-DSA-65 case in the external pure groups: 25 key generation, 15 deterministic signatures and 15 hedged ones using the randomness each vector specifies. The NTT is also checked against schoolbook multiplication, the packing against a bit-at-a-time reference, and rounding and hints against the equations that define them. Registered `available`; the pure and pre-hash variants are both present and are asserted not to accept each other's signatures |
| ML-DSA-44, ML-DSA-87 | The same two ACVP files, every case of each set: 25 key generation, and 30 signatures from the external pure groups, 15 deterministic and 15 hedged, from the same pinned commit (usnistgov/ACVP-Server 975de31eb83d). The scheme is ML-DSA-65's code instantiated with each set's parameters, registered on its own vectors. The extraction was checked by regenerating ML-DSA-65's vendored files from the same download, which matched byte for byte. Setting ML-DSA-44's `tau` to 49 fails its signature vectors and leaves key generation passing; giving ML-DSA-87 ML-DSA-44's `gamma2` fails both, since key generation runs a sign-and-verify consistency check. The hostile-input suite in `ic-mldsa/tests/robustness.rs` runs unchanged against each set. Registered `available` |
| All six ML-KEM and ML-DSA sets, against OpenSSL | `testvectors/openssl-ml-kem.json` and `openssl-ml-dsa.json`, produced by OpenSSL 3.5.7 on 2026-09-29 with the commands recorded in each file. `ironcrypto/tests/openssl_interop.rs` regenerates OpenSSL's keys from its seeds, requires deterministic ML-DSA signatures to equal OpenSSL's byte for byte, verifies OpenSSL's hedged signatures, and decapsulates OpenSSL's ciphertexts to its secrets. Giving ML-DSA-87 an `omega` of 80 fails it at the first ML-DSA-87 signature while its keys still match. The reverse directions were run once by hand the same day: a small program encapsulated to each OpenSSL ML-KEM key and signed, hedged, under each OpenSSL ML-DSA key, and `openssl pkeyutl -decap` recovered the same secret and `openssl pkeyutl -verify -rawin` accepted every signature, for all six sets. These are interoperability checks, not vectors from a standard |
| Shamir secret sharing (`ic_cipher::shamir`) | No standard publishes vectors for it. `testvectors/shamir-gf256.json` comes from `scripts/gen_shamir_vectors.py`, written from Shamir's 1979 construction with its own GF(2^8) arithmetic (a branching multiply, inversion by search) and sharing nothing with `ic_cipher::gf`; it recombines every case from up to twenty subsets before writing it. Under the same fixed coefficient stream, `ironcrypto/tests/shamir.rs` requires every share byte for byte, from 2-of-2 to 255-of-255, and the unit tests recover the secret from every subset of at least the threshold. Dropping Horner's last multiply, a Lagrange denominator missing `x_i`, one set of coefficients for every byte, and accepting index 0 each fail them. An independent-implementation check, not published values |
| HPKE (`ic_hpke`) | RFC 9180 appendix A.1.1 (base mode, AES-128-GCM): the encapsulation, base nonce, exporter secret and first ciphertext, as transcribed for IronSocketLayer. `scripts/gen_hpke_vectors.py`, an RFC 9180 implementation written from the specification on pyca/cryptography's X25519 and AEADs and Python's `hmac`, refuses to run unless it reproduces those four values, so two independent paths agree on them; the self-test checks the first ciphertext. `testvectors/hpke-x25519.json` carries A.1.1's inputs through all three AEADs, six sequence numbers each and three exports, and `ironcrypto/tests/hpke.rs` runs every case from both sides. `DeriveKeyPair` is checked against A.1.1 too: its `ikmE` and `ikmR` must derive the appendix's `skEm`, `pkEm` and `skRm`, and the two `ikm` values were confirmed by an independent derivation reaching those same keys. Only the A.1.1 values are published; the rest are that implementation's outputs |
| HPKE with DHKEM(P-384, HKDF-SHA384) (`ic_hpke::p384`) | No published HPKE vector uses P-384: RFC 9180's appendix and the CFRG's full test-vectors.json cover P-256 and P-521 only. `testvectors/hpke-p384.json` comes from `scripts/gen_hpke_p384_vectors.py`, an implementation of every NIST-curve DHKEM written from RFC 9180 on pyca/cryptography's ECDH and Python's `hmac`, sharing nothing with `ic-hpke`. Before writing it must reproduce all twelve base-mode P-256 and P-521 cases of the CFRG test-vectors.json (fetched 2026-10-06, SHA-256 pinned in the script) -- DeriveKeyPair, enc, the shared secret, the key schedule, every encryption and export -- since P-384 is the same construction with other parameters; must find that OpenSSL accepts each curve order less one as a private key and refuses the order itself; and must exchange a P-384 message each way with pyca/cryptography's own HPKE. The self-test (`HpkeP384::self_test`) pins the AES-256-GCM case: both keys by DeriveKeyPair, then the first encryption. The rejection loop of DeriveKeyPair, which real candidates all but never exercise, is tested against its rule with zero, the order and an all-ones candidate. An independent-implementation and interoperability check, not published values |
| Signature verification by algorithm (`ic_sig::verify`) | It implements no algorithm, so what is checked is the dispatch and the encodings. `testvectors/openssl-sig.json`, from `scripts/gen_sig_vectors.py` with pyca/cryptography 50.0.0 (its bundled OpenSSL reports 4.0.1): ECDSA on P-256, P-384 and P-521, Ed25519, and RSA PKCS#1 v1.5 and PSS with SHA-256, -384 and -512 at 2048 and 3072 bits, three messages each, with keys as SubjectPublicKeyInfo and ECDSA signatures in DER. ML-DSA-65 and -87 and Ed25519 are also checked on the certificates OpenSSL 3.5.7 issued in `testvectors/openssl-x509.json`: each CA's signature on itself and on its leaf. ML-DSA-44 has no OpenSSL-made case and is checked by signing with `ic_mldsa` and verifying here. Against the rule rather than a value: every case is refused with a changed message, a changed or truncated signature, and under every other algorithm -- as a failed signature where the key serves that algorithm, as the caller's error where it does not. Accepting any algorithm for any key, accepting ML-DSA keys with parameters, and dropping the RSA exponent bound each fail a test; the last did not at first, because the test used an even exponent that `ic_rsa` refuses on its own. Interoperability checks against an independent implementation, not values from a standard |
| SLH-DSA, all twelve parameter sets (`ic_slhdsa`) | NIST ACVP `SLH-DSA-keyGen-FIPS205`, `SLH-DSA-sigGen-FIPS205` and `SLH-DSA-sigVer-FIPS205`, from the pinned commit (usnistgov/ACVP-Server 975de31eb83d), converted by `scripts/gen_slh_dsa_vectors.py`, which checks each file against a pinned digest. The implementation was written from the text of FIPS 205, fetched from nvlpubs.nist.gov on 2026-10-08. The originals are about 70 MB, so three subsets are bundled: every key-generation case (120, ten per set); for signing, 96 cases with NIST's signature held as its SHA-256 and length -- for each set and variant (deterministic, hedged), the shortest-message case of the pure and internal interfaces and two pre-hash cases, rotated so that all twelve pre-hash functions are signed under; and for verification, 58 cases -- the pure cases of the six sets with the smallest signatures, both passing and three failing per set, and all fourteen pre-hash cases of each of the two smallest. **The whole of all three interfaces was run once**, on 2026-10-08 in an optimised build with `IC_SLH_DSA_FULL` pointing at the full conversion: 120 key-generation, 624 signature-generation compared byte for byte (288 of them pre-hash), and 504 verification cases (168 pre-hash), all passing; that run is repeatable from the script and is not part of the suite. By default the suite runs all ten key-generation cases of each `f` set and two of each `s` set, the 48 `f`-set signing cases, and all 58 verification cases; `IC_SLOW_SLH_DSA` adds the rest of what is bundled. FIPS 205 prints the object identifiers of four pre-hash functions only -- SHA-256, SHA-512, SHAKE128 and SHAKE256 -- and a unit test holds those four to the printed bytes. The other eight were written from NIST's hash-algorithm arc and are held by the vectors alone: the identifier is part of what is signed, so a wrong one changes the signature, and the `f`-set signing cases, which run by default, cover all twelve. Moving one identifier, swapping two, dropping the identifier, changing the domain byte, dropping the context length, shortening the SHAKE128 digest and substituting SHA-224 for SHA-512/224 were each tried, and each fails the vector test. The verification cases say less than their count suggests: only two of each group's fourteen are valid, so they show a function accepted for few of the twelve, and the signing cases are what constrain the rest. Writing it, the overflow check found a mask that assumed the tree index was under 64 bits, which in the 256f sets it is not. The self-test is an ACVP key-generation case and a sign-verify round trip, not a pinned signature. Published NIST values |
| HSS/LMS verification (`ic_lms`) | All six published cases: RFC 8554 appendix F's two (SHA-256, W=8 and W=4, two levels each) and RFC 9858 appendix A's four (SHA-256/192 at W=8 and at W=4 with H=20, SHAKE256/192, SHAKE256/256). `scripts/gen_lms_vectors.py` reads them out of the RFCs' own text, fetched from rfc-editor.org on 2026-10-08 and checked against pinned digests, so none was typed by hand; the first extraction dropped every value's short last line, which the script's own verifier caught by refusing the result. Those six leave W=1 and W=2 untested for every hash, W=4 for three of the four, and any hierarchy mixing hashes, so the same script holds a verifier and a signer written from the RFCs' pseudocode, sharing nothing with `ic_lms`. Before writing anything it must verify all six published cases and refuse each with a changed message, and its signer must reproduce three of RFC 9858's public keys and signatures byte for byte from their published SEED and I, and the one-time signature of the fourth, whose 2^20-leaf tree is too large to rebuild in Python. It then adds 21 cases: every hash at every Winternitz width, the first and last leaf of a tree, H=10, the empty message, and a three-level hierarchy over three hashes. `testvectors/lms.json` holds all 27, and `ironcrypto/tests/lms.rs` requires each to verify and to be refused with the message changed, lengthened or shortened, a bit changed at about a hundred positions across the signature, the signature truncated or extended, and the key's root or identifier changed. The parameter tables are checked against the RFCs' tables as typed and re-derived by RFC 8554 appendix B's computation of p and ls. Accepting trailing bytes, not checking the level count, and accepting a tree whose LM-OTS and LMS hashes differ each fail a test. Not checking the leaf number failed none at first: no such signature can verify, and what the check prevents is an overflow, which is a panic here; a test for exactly that was added. The self-test is RFC 9858 A.1. Published values for the six; an independent implementation anchored on them for the rest |
| ML-DSA PKCS#8 private keys (`ic_pkix::MlDsaPrivateKey`) | `testvectors/openssl-ml-dsa-pkcs8.json`: two keys per parameter set, each written by OpenSSL 3.5.7 in RFC 9881's three forms (seed, expanded key, both), with OpenSSL's own `-text` account of the seed and expanded key; `scripts/gen_mldsa_pkcs8.py` records the commands. `ironcrypto/tests/openssl_interop.rs` requires the parser to find OpenSSL's seed and expanded key in each form, the writer to reproduce OpenSSL's bytes, and `ic_mldsa` to regenerate OpenSSL's expanded key from the seed. A constructed seed tag, the `both` fields read or written in the wrong order, and an ML-DSA-87 expanded length off by one each fail it. An interoperability check, not a vector from a standard |
| X.509 issuance (`ic_pkix::cert`) | `testvectors/openssl-x509.json`: a CA and a leaf that OpenSSL 3.5.7 issued for Ed25519, ML-DSA-65 and ML-DSA-87 with every input fixed and ML-DSA signing deterministically, each chain passing `openssl verify -x509_strict`. `ironcrypto/tests/x509_issuance.rs` issues the same six certificates and requires them byte for byte. A key-usage unused-bit count off by one, extended key usage written before key usage, and `GeneralizedTime` chosen from 2026 rather than 2050 each fail it -- the second only for the leaves, which are the certificates carrying both extensions. ECDSA signatures are random, so P-256 and P-384 chains issued here were checked by `openssl verify -x509_strict` instead, on 2026-09-29, and passed. The OIDs are rebuilt from their dotted arcs, and the time encoding is tested against a day-by-day calendar count from 1970 into 2100 |
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
| ECDSA `verify_prehash`, every curve with SHA-224, -256, -384 and -512 | `crates/ic-ec/tests/ecdsa_prehash.rs`, generated by `scripts/gen_ecdsa_prehash.py` with pyca/cryptography 50.0.0 (OpenSSL 3.5.7) deterministic ECDSA. The P-256 and P-384 keys are RFC 6979's, and the generator refuses to run unless it reproduces the RFC values for their native hashes that the unit tests above check, so those 16 signatures are RFC 6979 A.2.5 and A.2.6's for each hash; the P-521 key is the generator's own, so its 8 are an interoperability check rather than published values. Beyond the values, the test checks FIPS 186-5's truncation as a rule: bytes of a digest past the order's width change nothing, and bytes within it are bound |
| HMAC_DRBG | validated against an independent in-test transcription of the SP 800-90A §10.1.2 pseudocode; the CAST vector is an implementation-pinned integrity value |
| CTR_DRBG | determinism and independence properties; no published vector wired in |
| PBKDF2 | reconstructed from the PRF XOR chain (RFC 6070 publishes HMAC-SHA1 only, which this library does not implement). The self-test (`pbkdf2_hmac_sha2_256_self_test`) cannot use RFC 7914 section 11's PBKDF2-HMAC-SHA256 vectors, which run one iteration where `pbkdf2` refuses fewer than SP 800-132's 1000; its value, at 1000 iterations, is Python `hashlib.pbkdf2_hmac`'s (OpenSSL's implementation), and `hashlib` was first required to reproduce the RFC 7914 c=1 vector. Recomputed on 2026-10-06. An independent implementation's output, not a published value |
| SP 800-108 counter mode, HMAC-SHA256 | the self-test (`sp800_108_counter_hmac_sha2_256_self_test`) value comes from a transcription of SP 800-108r1 section 4.1 in Python's `hmac` -- `HMAC(K, [i]_32 || Label || 0x00 || Context || [L]_32)` per block -- sharing nothing with `ic_kdf`. It asks for 48 bytes, two blocks, so the counter's increment is covered. Recomputed on 2026-10-06. No CAVP KBKDF vector is wired in, since CAVP fixes the counter's position and width per case and this encoding is one of them; an independent transcription, not a published value |
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
   proportion) on the raw noise source.
4. **Documentation package.** Security policy, finite state model, algorithm
   specification, and the vendor evidence the lab requires.
5. **Laboratory testing and CMVP submission** against a specific binary on
   specific operational environments.
6. **An enforced module boundary.** Today the self-tests, the error state and
   approved mode gate only services requested through `ic_fips::check` or
   `guarded`; a primitive called directly bypasses them. Validation needs every
   service behind one gate.
7. **Continuous health tests on the DRBGs** and pairwise-consistency tests on
   every generated key pair. ML-KEM, ML-DSA and RSA key generation check their
   pairs; HPKE's `KeyPair::generate` and the curve key derivations do not.

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
