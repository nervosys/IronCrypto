# FIPS 140-3 posture

## The headline

**AgenticCrypto is not a FIPS-validated cryptographic module.** It has not been
submitted to the CMVP, holds no certificate number, and appears on no vendor
list. Nothing in this document should be read as a validation claim.

What it *is*: a module that implements the operational discipline FIPS 140-3
requires, so that (a) it behaves correctly for callers who have a FIPS policy
to satisfy, and (b) the distance to an actual validation is a known quantity
rather than a rewrite.

The runtime says this too:

```console
$ acrypto capabilities --json | jq -r '.validationStatement'
AgenticCrypto implements the FIPS 140-3 operational discipline (approved-mode
policy, pre-operational and conditional self-tests, a latching error state, and
service indicators). It has NOT been submitted to or validated by the CMVP, and
holds no certificate number. Do not represent it as FIPS validated.
```

`ac_ontology::runtime::has("fips-validated")` returns `false`.

## What is implemented

### Module boundary and state machine

`ac-fips` defines the boundary. The module moves through:

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

In approved mode, `ac_fips::check(id)` refuses any algorithm the ontology does
not mark as permitted. The policy is data, not a hard-coded list — it reads
`FipsStatus::permitted_in_approved_mode()` straight from the registry, so the
policy and the documentation cannot drift apart.

```rust
ac_fips::set_mode(Mode::Approved)?;
ac_fips::check("aes-256-gcm")?;            // ServiceIndicator::Approved
ac_fips::check("chacha20-poly1305")        // Err(NotApprovedInFipsMode)
```

### Service indicator

FIPS 140-3 requires the module to tell the caller whether the service just used
was an approved one. `check` returns that indicator, and `guarded` pairs it with
the operation:

```rust
let (digest, indicator) = ac_fips::guarded("sha2-256", || Sha256::digest(data))?;
assert_eq!(indicator, ServiceIndicator::Approved);
```

Three values: `Approved`, `ApprovedAsComponent` (a raw block cipher used inside
a mode), `NotApproved`.

### Cryptographic algorithm self-tests

56 known-answer tests, one per implemented algorithm, run by `initialize()` and
individually addressable:

```console
$ acrypto selftest
  PASS sha2-224
  PASS sha2-256
  ...
  PASS ed25519
  PASS ecdh-p256
  PASS ecdsa-p256-sha256
  PASS ecdh-p384
  PASS ecdsa-p384-sha384

56 passed, 0 failed; integrity check passed
```

Each test is the algorithm's own `SelfTest::self_test()` — the same code path
the unit tests exercise, not a reimplementation. The runner never
short-circuits: one failing algorithm must not hide the status of the rest,
because the report is what an operator uses to decide whether the build is
salvageable.

A test suite asserts that every `available` ontology entry has a CAST
registered, so adding an algorithm without a self-test fails CI.

### Vector provenance

| algorithm family | vectors |
|---|---|
| SHA-2, SHA-3, SHAKE | FIPS 180-4 / FIPS 202 published values |
| AES | FIPS 197 Appendix C, SP 800-38A F.1.1 |
| AES-CBC, AES-CTR | SP 800-38A F.2 / F.5 |
| AES-GCM | the McGrew–Viega specification test cases |
| CMAC | SP 800-38B examples for all three key sizes |
| HMAC | RFC 4231; NIST HMAC-SHA3 samples |
| HKDF | RFC 5869 test cases 1–3 |
| ChaCha20, Poly1305, ChaCha20-Poly1305 | RFC 8439 |
| X25519 | RFC 7748 §5.2 and §6.1 |
| Ed25519 | RFC 8032 §7.1 |
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
| RSA keys | the identity `(m^e)^d = m (mod n)`, which holds only if `p` and `q` are prime and `d` inverts `e`; Miller-Rabin is checked against Carmichael numbers, which a Fermat test would pass |

The DRBG, PBKDF2, and RSA rows are the weak ones, and are called out as such
rather than being papered over. NIST's ACVP RSA vectors are not reproducible
offline; the pinned signatures there catch regression rather than establishing
correctness, which the rows above them do instead. Wiring in the CAVP `.rsp`
response files is a pre-validation task (below).

### Integrity test

`ac_fips::selftest::integrity_check()` computes an HMAC over the self-test
table. This detects a corrupted or partially linked constant pool — flip a byte
in any embedded vector and it fails.

It is **not** an image integrity test. A conforming one MACs the executable
image against a value patched in after linking, which is a property of the build
system rather than the source. The function's documentation says so explicitly,
so its name cannot imply more than it delivers.

## What validation would still require

In rough order of effort:

1. **The remaining approved asymmetric algorithms.** ECDSA and ECDH are
   implemented and vector-tested over both P-256 and P-384, which covers
   CNSA-aligned profiles. P-521 is implemented too, for profiles that call
   for it.
2. **CAVP algorithm certificates.** Every approved algorithm must pass the ACVP
   test harness, including Monte Carlo and large-data tests, not just the sample
   vectors bundled here.
3. **A real image integrity test.** A post-link step that computes an approved
   MAC or signature over the module image and patches it in.
4. **SP 800-90B entropy source validation.** The OS entropy source must be
   characterized and justified, with health tests (repetition count, adaptive
   proportion) on the raw noise source.
5. **Documentation package.** Security policy, finite state model, algorithm
   specification, and the vendor evidence the lab requires.
6. **Laboratory testing and CMVP submission** against a specific binary on
   specific operational environments.

Items 1–4 are engineering work in this repository. Items 5–6 are not, and no
amount of code changes them.

## Using this under a FIPS requirement today

If you have a genuine FIPS obligation:

- **Validation, not coverage, is the blocker now.** AgenticCrypto implements
  approved algorithms across the board — AES-GCM, HMAC, CMAC, HKDF, PBKDF2,
  SP 800-108, the DRBGs, and ECDSA and ECDH over P-256 and P-384 — correctly against their
  published vectors. But *correct* and *validated* are different words, and only
  the second satisfies an auditor. Where a certificate is the actual
  requirement, use a validated module.
- Where you need RSA encryption, this module has nothing to offer, and
  `acrypto recommend` will say so rather than substituting a smaller curve.
- Use the approved-mode policy engine and the ontology to keep your own code
  honest regardless of which module does the arithmetic. The registry is useful
  even when the implementation behind it is somebody else's.
