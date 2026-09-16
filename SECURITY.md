# Security

## Status

This code has **not been independently audited**. It is correct against its
published test vectors and its property tests; that is a different and weaker
claim than review by cryptographers. Treat it accordingly.

It is also **not FIPS validated**. See [docs/FIPS.md](docs/FIPS.md).

## Reporting a vulnerability

Report privately via GitHub Security Advisories on the repository, rather than
opening a public issue. Include a description, the affected version, and a
reproduction if you have one.

## Threat model

### In scope

- **Cache-timing and address-bus leakage.** The portable AES computes its S-box
  algebraically and GHASH multiplies bit by bit, so neither indexes memory with
  a secret. The accelerated backend uses `AESENC` and `PCLMULQDQ`, single
  instructions with data-independent latency and no table at all. Curve25519 uses constant-time ladders and complete formulas. Tag
  comparison is constant time.
- **Memory disclosure after use.** Secrets are wrapped in `Zeroizing`, which
  wipes on drop with volatile writes plus a compiler fence. AEAD decryption
  wipes the buffer before returning an authentication failure.
- **Caller misuse.** Parameter bounds are enforced, not merely documented:
  PBKDF2 rejects iteration counts below 1 000 and salts under 128 bits; X25519
  rejects small-order peer keys; Ed25519 rejects non-canonical `S`; DRBGs refuse
  to generate past their reseed interval.
- **Panics as denial of service.** Every fallible path returns `Result`.

### Out of scope

- **Power and electromagnetic analysis.** No countermeasures. Do not use this on
  a smartcard or in an environment with a physically present adversary.
- **Fault injection.** No redundant computation or result verification.
- **Speculative execution.** No speculation barriers beyond what the compiler
  emits.
- **Compiler-introduced leaks.** Constant-time properties are written at the
  source level. LLVM is not obliged to preserve them, and this build is not
  verified with a tool that checks the emitted machine code. This is a real
  limitation shared with most portable constant-time implementations.
- **The operating system entropy source.** `BCryptGenRandom` and
  `/dev/urandom` are trusted to deliver full-entropy bytes. No SP 800-90B
  raw-noise health testing is performed.

## Known weaknesses

| | |
|---|---|
| Limited asymmetric coverage | ECDSA and ECDH are implemented over P-256 and P-384. P-521 and RSA are not. |
| No post-quantum schemes | ML-KEM and ML-DSA are registered as planned. X25519, Ed25519, P-256 and P-384 all fall to Shor. |
| Slow symmetric throughput off x86-64 | The portable backend trades speed for the absence of secret-dependent memory access: single-digit MB/s for AES. x86-64 with AES-NI uses the accelerated path instead. |
| PBKDF2 is not memory-hard | It is the only *approved* password KDF, not the strongest one. Argon2id is implemented and is the default outside FIPS. |
| Two weak vector sources | The CTR_DRBG and PBKDF2 known-answer tests are property-based rather than CAVP-derived. Documented in `docs/FIPS.md`. |

## Cryptographic agility

If a primitive here is broken, the ontology is the mitigation path: set its
`fips` to `Disallowed` and its `status` to `Excluded`, add a `superseded-by`
edge, and every query, recommendation, and policy check updates at once. Callers
that route through `recommend` stop receiving it immediately.
