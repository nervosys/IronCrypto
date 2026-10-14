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
| Speed, x86-64 | AES-GCM (more variable under load; with AVX-512), ChaCha20-Poly1305, X25519 (with AVX-512), Ed25519 (with AVX-512), ML-KEM encapsulation from key bytes and with the key parsed once, ML-KEM decapsulation with the key parsed once, RSA (with AVX-512), ECDSA P-256 verify, ECDSA P-384, SHA-512 | SHA-256, SHA3-256, HMAC-SHA256, ECDSA P-256 sign, P-256 ECDH, ML-KEM key generation | P-384 ECDH, slightly; without AVX-512, AES-GCM at 1 KiB and 4 MiB, X25519, Ed25519 and RSA-2048 fall behind (see "Without AVX-512") |
| Speed, aarch64 | | | unmeasured. AES, SHA-256, SHA-512 and GHASH have ARMv8 backends behind the off-by-default `aarch64-crypto` feature, run under QEMU only; everything else is portable |
| Proved arithmetic | | | Graviola: s2n-bignum's routines are proved to the instruction in HOL Light; here, bounded proofs of the constant-time helpers, ML-DSA's rounding, and the portable field additions, carries and reductions of P-256 and Curve25519; no multiplication |
| Side-channel evidence | compiled-code gate on four targets; Valgrind clean on ML-KEM decapsulation | Valgrind, every operation both libraries offer and the harness drives | RSA's MULX/ADX path is checked under Valgrind and by the compiled-code gate; its IFMA exponentiation, as a whole at 1024 and 2048 bits, by the gate alone |
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
| ChaCha20-Poly1305 seal, 4 MiB | 2426-3523 MiB/s, loaded | 955-1132 MiB/s, loaded | 2.54-3.68 in the same runs |
| ChaCha20-Poly1305 seal, 1 KiB | 1724-2229 MiB/s, loaded | 662-1055 MiB/s, loaded | 2.07-2.65 in the same runs |
| ChaCha20-Poly1305 seal, 64 B | 147-166 MiB/s, loaded | 113-137 MiB/s, loaded | 1.07-1.47 in the same runs |
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
| P-384 ECDH | 117-141, loaded | 103-138, loaded | 0.94-1.25 in the same runs: parity |
| ECDSA P-384 sign | 46-58, loaded | 125-155, loaded | 0.30-0.42 in the same runs |
| ECDSA P-384 verify | 160-203, loaded | 228-300, loaded | 0.58-0.79 in the same runs |
| ML-KEM-768 keygen, like for like | 6.4 | 7.5 | 8.5 / 11.0 |
| ML-KEM-768 encapsulate, key prepared | 2.6 | 4.6 | 3.1 / 4.6 |
| ML-KEM-768 decapsulate, key prepared | 4.4 | 5.9 | 5.5 / 9.2 |
| RSA-2048 PKCS#1 v1.5 sign | 255-300 | 345 | 572 / 868 |
| RSA-2048 PKCS#1 v1.5 verify | 7.5-8.5 | 9-10.5 | 12.8 / 22.1 |

### The last run, master e9d1261

Taken 2026-10-13 after everything above had merged, three rounds of each
of `graviola`, `graviola-p384` and `graviola-chacha`, both libraries in
every run. The machine was never idle: load read 33 to 100 percent at the
start of the rounds, from other projects' builds. So only the ratio within
a run is read, as IronCrypto's rate over Graviola's (above 1 is faster
here), with the range across rounds:

| operation | ratio | | operation | ratio |
|---|---|---|---|---|
| AES-256-GCM, 4 MiB | 1.20-1.47 in 5 of 7 runs; 0.20 and 0.82 in 2 | | X25519 | 1.14-1.17 |
| AES-256-GCM, 1 KiB | 0.74-1.28 | | Ed25519 sign | 1.04-1.40 |
| AES-256-GCM, 64 B | 1.43-1.46 | | Ed25519 verify | 1.12-1.33 |
| ChaCha20-Poly1305, 4 MiB | 2.64-5.20 | | P-256 ECDH | 0.95-0.99 |
| ChaCha20-Poly1305, 1 KiB | 2.02-2.17 | | ECDSA P-256 sign | 1.00-1.07 |
| ChaCha20-Poly1305, 64 B | 1.19-1.57 | | ECDSA P-256 verify | 1.09-1.13 |
| SHA-256, 4 MiB | 0.98-1.01 | | P-384 ECDH | 0.83-0.98 |
| SHA-512, 4 MiB | 1.27-2.05 | | ECDSA P-384 sign | 2.33-2.79 |
| SHA3-256, 4 MiB | 0.95-0.97 | | ECDSA P-384 verify | 1.41-1.56 |
| HMAC-SHA256, 4 MiB | 0.92-0.99 | | ML-KEM-768 keygen, like for like | 0.98-1.39 |
| HMAC-SHA256, 200 B | 0.93 | | ML-KEM-768 encapsulate, from bytes, both | 1.82-2.08 |
| SHA-256, 64 B | 1.01-1.03 | | ML-KEM-768 encapsulate, parsed once, both | 1.71-2.27 |
| RSA-2048 sign / verify | 1.16-1.30 | | ML-KEM-768 decapsulate, parsed once, both | 1.31-1.38 |

The ML-KEM rows in this table were re-measured for this change, not in the
run above: three rounds, each with the previous bench binary and the new
one run alternately, both libraries in every run, on the branch that adds
them. Decapsulation from key bytes has no Graviola counterpart (below), and
the ML-KEM key generation row is unchanged from the run above.

The AES-GCM outliers are drops in IronCrypto's own rate (2.9 and 13.7
GB/s against 19 to 25 in the other runs) while Graviola's held at 15 to
17: the 512-bit kernel appears more sensitive to a contended machine. It is
the first measurement of each run.

Where it is not ahead:

- **ML-KEM decapsulation from key bytes** has no Graviola row. Graviola
  0.4.1 cannot parse a decapsulation key from bytes: its `DecapKey` comes
  only from `generate`. So Graviola has no from-bytes decapsulation to time,
  and it never runs the hash check that FIPS 203 section 7.3 requires on the
  decapsulation key, which IronCrypto runs on every from-bytes call (7.8 to
  8.7 us here, not compared). Graviola's encapsulation-key parse does check
  the encoding, as IronCrypto's does (FIPS 203 section 7.2), so nothing is
  skipped on that side. The earlier "behind" figures set a from-bytes
  IronCrypto call against Graviola's key already in memory, which was not
  like for like. Graviola's `encaps` consumes its key, so the parsed-once row
  clones it per call; that clone is about 0.1 us, against 4.9 to 6.1 us for
  the encapsulation.
- **P-384 ECDH** is level to slightly behind: 0.83 to 0.98 of Graviola's
  rate in the last run. It was 1.7 times slower while the field arithmetic here was generic in the modulus; specialised to the
  prime, with a squaring of its own and divsteps inversion, it came out at
  0.94 to 1.25 times Graviola's time across five rounds run in the same
  binaries (P-384 rows are `cargo run --release -- graviola-p384` alone).
  Those rounds ran on a machine another workload held near full load, so
  the absolute figures above are high for both libraries; the ratios are
  what to read. The rows are not quite like for like: Graviola's
  `PublicKey` builds its sixteen-point table when it is parsed, outside the
  timed loop, where `EcdhP384::agree` takes SEC1 bytes and decodes,
  validates and builds its window inside every call, about 3.5 us of its
  time.
- **ChaCha20-Poly1305 on 64-byte messages** is level, not ahead: 1.07 to
  1.47 times Graviola's rate across five rounds on a loaded machine, a
  range that includes parity. One block of keystream and four of Poly1305
  are too short for the vector kernels, so this is the portable code. On 1
  KiB and 4 MiB messages it is ahead, by 2.1 to 3.7 times, since ChaCha20
  runs sixteen blocks at a time on AVX-512 and Poly1305 four lanes on AVX2
  (CHANGELOG.md has the A/B). Before that it was 0.8 to 1.5 times
  Graviola's rate under the same load: parity, which an earlier single run
  had read as behind.
- **P-256 ECDH** led by under four percent controlled and trailed by sixteen
  in the latest run: parity, not a lead.
- **aarch64** has ARMv8 backends here for AES, SHA-256 and SHA-512 (the
  `SHA2` and `SHA512` instructions) and GHASH (`PMULL`), all behind the
  off-by-default `aarch64-crypto` feature; every other algorithm, ChaCha20,
  Poly1305 and the curves among them, runs the portable code. Graviola
  carries aarch64 assembly throughout and requires the `aes`, `sha2`, `pmull`
  and `neon` features there. The ARM backends here have been executed only
  under QEMU user-mode emulation, which checks what they compute and says
  nothing about speed: there is no aarch64 hardware on hand, and nothing was
  measured on aarch64. AES-GCM there is the AES backend and the `PMULL`
  GHASH run one after the other, not a fused kernel like x86-64's.
- **CPUs without AVX-512.** Measured on the same Zen 5 machine with
  `--cfg ic_no_avx512`, which turns the AVX-512 and IFMA paths off (table
  below). Without them, AES-GCM at 1 KiB and 4 MiB, X25519 and RSA-2048 fall
  behind Graviola, Ed25519 drops to parity or behind, and ChaCha20-Poly1305
  and ECDSA P-384 keep a lead, the ChaCha20 one smaller. Graviola needs only AVX2 and ADX, so it is the
  fair comparison on such a CPU.

### Without AVX-512

`RUSTFLAGS="--cfg ic_no_avx512" cargo run --release -- graviola` (and
`graviola-p384`, `graviola-chacha`), three rounds each, alternating with the
default build in the same window. Each cell is IronCrypto's rate over
Graviola's within one run, as a range across the three rounds (above 1 is
IronCrypto faster). The machine was loaded by other jobs.

| operation | AVX2 only | default build, same rounds |
|---|---|---|
| AES-256-GCM seal, 4 MiB | 0.44-0.66 | 0.40-1.36 |
| AES-256-GCM seal, 1 KiB | 0.68-0.77 | 1.05-1.34 |
| AES-256-GCM seal, 64 B | 1.24-1.40 | 1.20-1.58 |
| ChaCha20-Poly1305 seal, 4 MiB | 1.65-1.84 | 3.24-3.54 |
| ChaCha20-Poly1305 seal, 1 KiB | 1.41-1.66 | 2.22-2.69 |
| ChaCha20-Poly1305 seal, 64 B | 0.93-1.38 | 1.30-1.31 |
| X25519 | 0.89-0.99 | 1.18-1.64 |
| Ed25519 sign | 0.85-0.94 | 0.95-1.25 |
| Ed25519 verify | 0.88-1.09 | 1.28-1.56 |
| P-256 ECDH | 0.84-0.93 | 0.84-0.99 |
| ECDSA P-256 sign | 0.89-1.05 | 1.04-1.13 |
| ECDSA P-256 verify | 0.98-1.01 | 1.00-1.08 |
| P-384 ECDH | 0.76-0.77 | 0.69-1.26 |
| ECDSA P-384 sign | 2.31-2.59 | 2.26-2.32 |
| ECDSA P-384 verify | 1.08-1.23 | 1.26-1.66 |
| RSA-2048 PKCS#1 v1.5 sign | 0.64-0.68 | 1.16-1.36 |
| RSA-2048 PKCS#1 v1.5 verify | 0.68-0.78 | 1.16-1.25 |
| SHA-512, 4 MiB | 1.47-1.86 | 1.60-2.23 |
| ML-KEM-768 encapsulate, key prepared (control) | 1.74-2.15 | 1.80-2.00 |
| SHA-256, 4 MiB (control) | 0.92-1.20 | 0.95-0.98 |

Read the rows with care. The two controls have no AVX-512 path, so their
spread between the builds is noise, and the P-384 ECDH row moves as much
(0.69 to 1.26 in the default build) though nothing it runs changed. The
AES-GCM 4 MiB default range is wide for the same reason. The AVX2 figures are
tighter, and the drops that separate from the default build (AES-GCM at
1 KiB, X25519, RSA-2048) are the clearest reading. Without AVX-512, P-256 ECDH,
SHA-3, HMAC and ML-KEM with a prepared key stay within the default build's
spread. ML-KEM encapsulation from key bytes was left out of the table: these
rounds used the earlier bench row that set it against a Graviola key parsed
once, which is not like for like (see the last run above for the corrected
rows).

Graviola's own paths are the same in both columns, since it does not use
AVX-512. The AVX2 column is a Zen 5 with AVX-512 switched off, not an older
CPU; frequency and cache are the same as in the default column.

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
`power2round`, `decompose` and the hint lemma for every input; and, in the
portable field code, P-256's addition, subtraction and final conditional
subtraction, and Curve25519's addition, subtraction, carry propagation,
weak reduction and canonical encoding, each over its documented input
domain. Multiplication is not proved: Kani did not finish P-256's
Montgomery step, a 64-bit product by a constant, in 25 minutes. The
products, the Montgomery reduction as a whole, the x86-64 assembly and the
RSA arithmetic are tested -- against the portable code over millions of
random and edge values, and against published vectors -- and not proved.

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

RSA-2048 signing, with only the private key marked (d, the primes and their
Montgomery constants, dP, dQ, qInv), reports one branch: the verdict of the
check after signing that `m^e = c`, which decides only whether the
signature is released. That run exercises the portable exponentiation.
A second case, `ic-rsa-2048-sign-adx`, forces IronCrypto's MULX/ADX Montgomery
product, which Valgrind executes though it hides ADX from CPUID, and reports the
same one branch. Valgrind does not emulate AVX-512, so it cannot reach the
IFMA path; the compiled-code gate reads it instead: the IFMA Montgomery
product (`ct_rsa_ifma_amm_2048`), whose one loop branch is on the row count,
and the whole exponentiation at 1024 and 2048 bits (`ct_rsa_ifma_pow_1024`,
`ct_rsa_ifma_pow_2048`), in which every branch is a loop's own counter
(docs/CONSTANT_TIME.md, "The IFMA exponentiation"). Graviola's RSA is not in the harness,
and its README states that its RSA key generation is not side-channel
safe.

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
published vectors of every other algorithm listed in the README. Wycheproof's
primality cases also run, against RSA key generation's Miller-Rabin test
through a test-only entry point that draws its bases from a seeded RNG, as FIPS
186-5 B.3.1 specifies: 317 cases, 14 signed values skipped and counted, and
every other case agrees with its label. Earlier, 20 composites that fixed bases
accepted were listed as known failures; random bases refuse them.

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
