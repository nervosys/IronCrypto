# IronCrypto and Graviola

[Graviola](https://github.com/ctz/graviola) is the closest library to this one:
pure Rust to build, aimed at rustls, fast on x86-64, with arithmetic proved
correct. This file compares the two, version 0.4.1 of Graviola against the
master branch here, on the properties a person or an agent choosing between
them would ask about. Where Graviola is ahead, it says so.

Neither library is CMVP validated.

## Summary

| | ahead | level | behind |
|---|---|---|---|
| Speed, x86-64 | AES-GCM, X25519, Ed25519, ML-KEM, RSA, ECDSA P-256 verify, ECDSA P-384, SHA-512 | SHA-256, SHA3-256, HMAC-SHA256, ECDSA P-256 sign, P-256 ECDH | P-384 ECDH; ChaCha20-Poly1305 on long messages (see below) |
| Speed, aarch64 | | | everything but AES: not accelerated here, not measured |
| Proved arithmetic | | | Graviola: s2n-bignum's routines are proved to the instruction in HOL Light; here, bounded proofs of the constant-time helpers and ML-DSA's rounding only |
| Side-channel evidence | compiled-code gate on four targets; Valgrind clean on ML-KEM decapsulation | Valgrind, every operation both libraries offer and the harness drives | RSA signing not yet classified here |
| Misuse resistance | nonces drawn and replays refused; self-tests before first use; approved-only build; error state refuses | | |
| Test vectors | every suite Graviola runs, plus ACVP for ML-KEM, ML-DSA, SLH-DSA | | |
| For agents | ontology, `ic recommend`, `ic lint`, MCP server with rules | | Graviola has none |
| Breadth | post-quantum signatures, password hashing, HPKE and more; `no_std`, 32-bit and bare-metal targets | | |

## Speed

Ryzen 9 9900X (Zen 5, AVX-512 and IFMA), `cd bench && cargo run --release --
graviola`, microseconds per operation or MiB/s.

Two kinds of figure. The **controlled** ones come from each piece of work's
own measurement: the build before and after run alternately minutes apart,
with Graviola in the same runs, as AGENTS.md asks; they are in CHANGELOG.md
with their spreads. The **latest** column is one run of the merged master
(5f369cc), on 2026-10-13, while another workload held the CPU at 92 to 100
percent. It moved both libraries: Graviola's X25519 took 21.6 us in it
against 13.2 to 13.6 controlled. Read it to within about fifteen percent,
and a ratio inside that as parity.

| operation | IronCrypto, controlled | Graviola, controlled | latest, IronCrypto / Graviola |
|---|---|---|---|
| AES-256-GCM seal, 4 MiB | 25.4 GB/s | 17.4 GB/s | 13957 / 12650 MiB/s |
| AES-256-GCM seal, 64 B | 1.15 GB/s | 0.82 GB/s | 813 / 679 MiB/s |
| ChaCha20-Poly1305 seal, 4 MiB | -- | -- | 944 / 1382 MiB/s |
| ChaCha20-Poly1305 seal, 64 B | -- | -- | 162 / 104 MiB/s |
| SHA-256, 4 MiB | -- | -- | 2187 / 2275 MiB/s |
| SHA-512, 4 MiB | -- | -- | 669 / 507 MiB/s |
| SHA3-256, 4 MiB | 690 MiB/s | 690-735 MiB/s | 594 / 445 MiB/s |
| HMAC-SHA256, 200 B | 230 ns | parity | 1.18x slower |
| X25519 | 11.7-12.2 | 13.2-13.6 | 13.7 / 21.6 |
| Ed25519 sign | 4.6-4.8 | 5.3-6.0 | 5.2 / 6.7 |
| Ed25519 verify | 17.3-17.6 | 22.4-24.1 | 23.6 / 31.0 |
| P-256 ECDH | 24.8 | 25.7-26.3 | 37.9 / 32.7 |
| ECDSA P-256 sign | 7.5 | 7.8-8.0 | 11.0 / 11.9 |
| ECDSA P-256 verify | 26.8 | 30.0-30.6 | 44.5 / 44.9 |
| P-384 ECDH | 135 | 80 | not in the bench mode |
| ECDSA P-384 sign | 50 | 86-88 | not in the bench mode |
| ECDSA P-384 verify | 145 | 154-171 | not in the bench mode |
| ML-KEM-768 keygen, like for like | 6.4 | 7.5 | 8.5 / 11.0 |
| ML-KEM-768 encapsulate, key prepared | 2.6 | 4.6 | 3.1 / 4.6 |
| ML-KEM-768 decapsulate, key prepared | 4.4 | 5.9 | 5.5 / 9.2 |
| RSA-2048 PKCS#1 v1.5 sign | 255-300 | 345 | 572 / 868 |
| RSA-2048 PKCS#1 v1.5 verify | 7.5-8.5 | 9-10.5 | 12.8 / 22.1 |

Where it is not ahead:

- **P-384 ECDH** is 1.7 times slower. The field arithmetic here is generic in
  the modulus; Graviola's, from s2n-bignum, is specialised to the prime.
  Signing and verification are ahead because they lean on the generator
  table and the scalar arithmetic, where the work here went.
- **ChaCha20-Poly1305** was ahead in an earlier run and is behind on 1 KiB
  and 4 MiB messages in the latest, by 1.25 and 1.46 times; on 64-byte
  messages it is ahead by 1.57. Until a quiet A/B separates load from code,
  treat long-message ChaCha20-Poly1305 as behind.
- **P-256 ECDH** led by under four percent controlled and trailed by sixteen
  in the latest run: parity, not a lead.
- **aarch64** has an AES backend here and nothing else; every other
  algorithm runs the portable code. Graviola carries aarch64 assembly and
  requires the `aes`, `sha2`, `pmull` and `neon` features there. Nothing was
  measured on aarch64.
- **CPUs without AVX-512.** Several of the leads above (X25519, the AES-GCM
  wide kernels, RSA's exponentiation) come from AVX-512 or IFMA paths. On a
  CPU with only AVX2, BMI2 and ADX the MULX/ADX paths run instead; those
  have not been measured against Graviola on such a CPU, and the leads
  should be expected to narrow.

## Proved arithmetic

Graviola is ahead here, and this library does not close the gap.

Graviola's field and group arithmetic for P-256, P-384 and P-521, X25519,
ML-KEM's arithmetic, Keccak-f and its big-integer routines come from
[s2n-bignum](https://github.com/awslabs/s2n-bignum), whose assembly is proved
in HOL Light to compute the mathematical function, instruction by
instruction, for every input.

The proofs here ([PROOFS.md](PROOFS.md)) are Kani bounded model checks at the
level of Rust semantics: the constant-time selection, comparison and swap
helpers for every input (slices to length six), and ML-DSA's `reduce_q`,
`power2round`, `decompose` and the hint lemma for every input. The curve and
RSA arithmetic, including the generated x86-64 assembly, is tested -- against
the portable code over millions of random and edge values, and against
published vectors -- and not proved.

## Side-channel evidence

The same Valgrind harness ([CTGRIND.md](CTGRIND.md)) runs both libraries'
operations with the secrets marked undefined, after two positive controls
that must be reported. Latest run, master 5f369cc:

| operation | IronCrypto | Graviola |
|---|---|---|
| AES-256-GCM seal, ChaCha20-Poly1305 seal, HMAC-SHA256, SHA-256 | 0 | 0 |
| Ed25519 sign | 0 | 0 |
| X25519 | 1 | 1 |
| P-256 ECDH | 3 | 3 |
| ECDSA P-256 sign | 7 | 6 |
| ML-KEM-768 decapsulate | 0 | 45 + 27 address |

Every report on either side, for the operations in this table, is a check
whose outcome the standard makes public (a range check, a zero or identity
check, a refused all-zero secret) or work on a value that is published
(ML-KEM's matrix, sampled from a seed that is in the encapsulation key).
CTGRIND.md classifies each one. Graviola's ML-KEM reports come from the
harness having to mark its decapsulation key through the seed; they are
expected, not a weakness.

Beyond Valgrind, which only sees the build and CPU it runs on:

- `scripts/check-ct.py` disassembles the compiled code of 67 probes on
  x86-64 and 44 on Cortex-M0, Cortex-M4 and 32-bit RISC-V, and fails the
  build on any branch or secret-indexed load in them. It has caught
  compiled code that branched on a secret where the source did not, on
  Cortex-M0 (CONSTANT_TIME.md, "The first regression found").
- `ic timing` measures operations with a fixed against a random secret,
  interleaved at random.

Open: RSA-2048 signing reports 315 branches and 15 addresses, which cannot be
classified until the harness can mark the private key without the public
modulus. Graviola's RSA is not in the harness either, and its README states
that its RSA key generation is not side-channel safe.

## Misuse resistance

Graviola's AEADs take the nonce from the caller (`encrypt(&self, nonce:
&[u8; 12], ...)`), as most libraries do. Here:

- `ic_cipher::Sealer` chooses every nonce itself, and `Opener` refuses
  replays and reordering. AGENTS.md tells a caller to pass a nonce by hand
  only where a protocol dictates it; through MCP, `crypto_seal` refuses a supplied nonce unless
  `protocol_nonce: true` says a protocol dictates it.
- Self-tests run before first use, and a failure puts the module in an error
  state in which every operation that produces output -- hashes, XOFs and
  MACs included, from 0.3.0 -- refuses with `ModuleErrorState`.
- `--cfg ic_approved_only` compiles the non-approved algorithms out, so an
  approved-only deployment cannot call one by accident.
- Tags are compared with `ic_core::ct::verify`; secrets are wiped on drop.

## Test vectors

Every suite Graviola runs also runs here: NIST CAVP's SHA-2, SHA-3, SHAKE and
HMAC response files in full, Monte chains included, and Wycheproof's
ECDSA, ML-KEM (all three parameter sets, where Graviola runs ML-KEM-768)
and AES-GMAC, about 12,000 cases pinned by SHA-256 (`crates/ironcrypto/tests/coverage_vectors.rs`). In
addition: NIST's ACVP vectors for ML-KEM, ML-DSA and SLH-DSA, and the
published vectors of every other algorithm listed in the README. Not yet:
Wycheproof's primality cases, which need a hook into RSA's Miller-Rabin.

## For agents

Graviola is a library for people who already know which primitive they want.
This one also answers the question first, in a form a program can act on:

- `ic recommend <intent> --json` returns the choice, the reasons, the
  rejected alternatives and the constraints, or `unavailable` and
  `impossible` when the honest answer is no.
- `ic ontology show <algorithm> --json` gives byte bounds and constraints
  with severities.
- `ic lint` and MCP's `crypto_lint` check written code against the rules in
  `ic_ontology::RULES`, which the MCP server sends when a client connects.

## Breadth and targets

Graviola covers the algorithms TLS on the web needs, on x86-64 and aarch64
with specific CPU features required. This library covers those and also:
ML-DSA, SLH-DSA, LMS, P-521 signing, HPKE, OPAQUE, OPRFs, Argon2, scrypt,
PBKDF2, the SP 800-185 functions, BLAKE2 and BLAKE3, AES-GCM-SIV, key wrap,
CTR_DRBG, X.509 issuance, and a rustls provider with QUIC. It builds without
`std` and runs on Cortex-M0, Cortex-M4 and 32-bit RISC-V, with portable code
on every CPU.
