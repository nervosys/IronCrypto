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
| Speed, x86-64 | **Default build, ahead:** AES-256-GCM at 4 MiB, 1 KiB and 64 B; ChaCha20-Poly1305 at all three sizes; SHA-512; HMAC-SHA256 at 200 B; X25519; Ed25519 sign, verify and verify with the key held; P-256 ECDH (all three rows) and ECDSA P-256 sign and verify; P-384 ECDH (all three rows) and ECDSA P-384 sign and verify; ML-KEM-768 encapsulation (both rows) and decapsulation with the key parsed once; ML-KEM-768 key generation, like for like; RSA-2048, -3072 and -4096 sign and verify. **Without AVX-512, ahead:** ChaCha20-Poly1305 at all three sizes; AES-256-GCM at 64 B; SHA-512; Ed25519 verify with the key held; P-256 ECDH (all three rows) and ECDSA P-256 sign and verify; P-384 ECDH with the key prepared, and ECDSA P-384 sign and verify; ML-KEM-768 encapsulation (both rows) and decapsulation with the key parsed once; RSA-2048 sign and verify; RSA-3072 sign and verify; RSA-4096 verify; AES-256-GCM at 1 KiB in `graviola-gcm` only (level in `graviola`); P-384 ECDH from key bytes in `graviola-p384` only (level in `graviola`); Ed25519 sign in `graviola-25519` only (level in `graviola`). Rule and every row: "Consolidated run, 2026-10-23" under Speed. | **Default build, level:** SHA-256 at 4 MiB and 64 B; SHA3-256; HMAC-SHA256 at 4 MiB. **Without AVX-512, level:** X25519; Ed25519 verify, and sign in `graviola`; SHA-256 at 4 MiB and 64 B; SHA3-256; HMAC-SHA256 at 4 MiB and 200 B; AES-256-GCM at 1 KiB in `graviola`; P-384 ECDH against Graviola's key parsed once (both modes), and from key bytes in `graviola`; RSA-4096 sign; ML-KEM-768 key generation, like for like. | **Default build, behind:** P-384 key preparation (not like for like, see the section); ML-KEM-768 key generation with IronCrypto's pairwise test. **Without AVX-512, behind:** AES-256-GCM at 4 MiB, against Graviola's AVX-512 path (see the section); P-384 key preparation; ML-KEM-768 key generation with the pairwise test. |
| Speed, aarch64 | | | unmeasured. AES, SHA-256, SHA-512 and GHASH have ARMv8 backends behind the off-by-default `aarch64-crypto` feature, run under QEMU only and read by the compiled-code gate, never on hardware; everything else is portable |
| Proved arithmetic | | | Graviola: s2n-bignum's routines are proved to the instruction in HOL Light; here, bounded proofs of the constant-time helpers, ML-DSA's rounding, ML-KEM's scalar reductions, compression and packing, the portable field additions, carries and reductions of P-256 and Curve25519, P-384's portable addition, subtraction and closing subtraction, P-384's portable Montgomery multiplication and squaring in pieces joined by four argued steps, P-256's portable field multiplication and squaring, end to end except for two argued steps, and Curve25519's multiplication column sums; and, by the separate IronProof project, functional proofs of many of the compiled x86-64 kernels (the field arithmetic of P-256, P-384 and Curve25519, the P-256 and P-384 point formulas, the X25519 ladder step, Ed25519's doubling, addition and conversions, the AES-GCM, ChaCha20, Poly1305 and Keccak vector kernels, and RSA-2048's multiplication pieces and Montgomery reduction), solved by SMT solvers over a CPU-tested model of the instructions, not proof-checked as HOL Light is, and not of every kernel |
| Side-channel evidence | compiled-code gate on five targets, aarch64's ARMv8 backends among them; Valgrind clean on ML-KEM decapsulation | Valgrind, every operation both libraries offer and the harness drives | RSA's MULX/ADX path is checked under Valgrind and by the compiled-code gate; its IFMA exponentiation, as a whole at 1024 and 2048 bits, by the gate alone |
| Misuse resistance | nonces drawn and replays refused; self-tests before first use; approved-only build; error state refuses | | |
| Test vectors | every suite Graviola runs, plus ACVP for ML-KEM, ML-DSA, SLH-DSA | | |
| For agents | ontology, `ic recommend`, `ic lint`, MCP server with rules | | Graviola has none |
| Breadth | post-quantum signatures, password hashing, HPKE and more; `no_std`, 32-bit and bare-metal targets | | |

## Speed

### Consolidated run, 2026-10-23, master c04c63f

The run of 2026-10-16, below, repeated the same way on master c04c63f. Every
comparison mode ran five rounds in each of two configurations (`graviola`,
`graviola-p384`, `graviola-chacha`, `graviola-gcm`, `graviola-25519`,
`graviola-rsa`), against Graviola 0.4.1 from crates.io, unpatched. The default
build and `RUSTFLAGS="--cfg ic_no_avx512"` were built from c04c63f with rustc
1.99.1 and copied aside (SHA-256 `bb3fcecb...` and `4a1b778c...`). Round r ran
the six modes with one build, then the six with the other, 30 seconds between
modes; odd rounds started with the default build, even rounds with the other.
The 60 runs took 35 minutes, from 07:30 to 08:05.

The ratios, rule and classification are as for 2026-10-16: IronCrypto's rate
over Graviola's from the bench's own verdict line, minimum, median and maximum
over the five rounds. The host was not quiet: another session's `cargo test`
ran throughout, and the load at the start of each mode read 9 to 100 percent,
median 75. Read the ratios within this run only.

| operation (bench mode) | default, min-median-max | without AVX-512, min-median-max |
|---|---|---|
| aes-256-gcm, 4 MiB (`graviola`) | 1.19-1.54-1.55 ahead | 0.58-0.91-0.92 behind |
| chacha20-poly1305, 4 MiB (`graviola`) | 2.53-2.77-3.22 ahead | 1.40-1.43-1.61 ahead |
| aes-256-gcm, 1 KiB (`graviola`) | 1.38-1.61-1.72 ahead | 0.99-1.19-1.63 level |
| chacha20-poly1305, 1 KiB (`graviola`) | 1.96-2.09-2.18 ahead | 1.29-1.34-1.42 ahead |
| aes-256-gcm, 64 B (`graviola`) | 1.80-2.28-2.88 ahead | 2.83-2.85-3.21 ahead |
| chacha20-poly1305, 64 B (`graviola`) | 2.53-2.57-2.69 ahead | 2.36-2.54-2.57 ahead |
| sha-256 (`graviola`) | 1.00-1.00-1.02 level | 1.00-1.00-1.00 level |
| sha-512 (`graviola`) | 1.12-1.16-1.37 ahead | 1.02-1.18-1.30 ahead |
| sha3-256 (`graviola`) | 0.97-0.98-1.00 level | 0.85-0.97-1.00 level |
| hmac-sha256, 4 MiB (`graviola`) | 0.99-0.99-1.00 level | 0.99-1.00-1.00 level |
| hmac-sha256, 200 B (`graviola`) | 1.12-1.15-1.34 ahead | 0.99-1.12-1.55 level |
| sha-256, 64 B (`graviola`) | 0.97-1.36-1.38 level | 0.92-1.30-1.37 level |
| x25519 agree (`graviola`) | 1.10-1.16-1.42 ahead | 0.87-0.99-1.21 level |
| p-256 ecdh (`graviola`) | 1.16-1.22-1.35 ahead | 1.15-1.19-1.30 ahead |
| p-256 ecdh, from bytes (`graviola`) | 1.23-1.27-1.41 ahead | 1.22-1.26-1.28 ahead |
| p-256 ecdh, key prepared (`graviola`) | 2.61-2.67-3.04 ahead | 2.54-2.67-3.10 ahead |
| ecdsa p-256 sign (`graviola`) | 1.08-1.31-1.38 ahead | 1.07-1.09-1.13 ahead |
| ecdsa p-256 verify (`graviola`) | 1.20-1.42-1.61 ahead | 1.36-1.40-1.42 ahead |
| p-384 ecdh (`graviola`) | 1.23-1.46-1.56 ahead | 0.98-1.04-1.09 level |
| p-384 ecdh, from bytes (`graviola`) | 1.37-1.51-1.67 ahead | 0.96-1.06-1.15 level |
| p-384 ecdh, key prepared (`graviola`) | 2.56-3.12-3.24 ahead | 1.89-2.25-2.36 ahead |
| p-384 key preparation (`graviola`) | 0.04-0.04-0.06 behind | 0.04-0.05-0.06 behind |
| ecdsa p-384 sign (`graviola`) | 2.52-2.88-3.28 ahead | 2.24-2.51-3.20 ahead |
| ecdsa p-384 verify (`graviola`) | 1.80-1.97-2.25 ahead | 1.92-2.04-2.22 ahead |
| ed25519 sign (`graviola`) | 1.00-1.39-1.52 ahead | 0.97-1.07-1.09 level |
| ed25519 verify (`graviola`) | 1.23-1.47-2.01 ahead | 0.99-1.05-1.17 level |
| ed25519 verify, key held (`graviola`) | 1.49-1.68-2.37 ahead | 1.13-1.17-1.21 ahead |
| keygen (ironcrypto with pairwise test) (`graviola`) | 0.52-0.55-0.63 behind | 0.41-0.45-0.49 behind |
| keygen (like for like, no pairwise test) (`graviola`) | 1.16-1.22-1.49 ahead | 0.98-1.01-1.35 level |
| ml-kem-768 encaps, from bytes, both (`graviola`) | 1.68-1.72-1.95 ahead | 1.41-1.47-1.59 ahead |
| ml-kem-768 encaps, parsed once, both (`graviola`) | 2.13-2.25-2.76 ahead | 1.63-1.91-2.28 ahead |
| ml-kem-768 decaps, parsed once, both (`graviola`) | 1.09-1.22-1.31 ahead | 1.13-1.20-1.24 ahead |
| rsa-2048 sign (`graviola`) | 1.28-1.45-1.51 ahead | 1.08-1.13-1.32 ahead |
| rsa-2048 verify (`graviola`) | 1.68-1.77-1.88 ahead | 1.06-1.14-1.29 ahead |
| p-384 ecdh (`graviola-p384`) | 1.25-1.42-1.47 ahead | 1.02-1.04-1.05 level |
| p-384 ecdh, from bytes (`graviola-p384`) | 1.30-1.46-1.55 ahead | 1.06-1.10-1.12 ahead |
| p-384 ecdh, key prepared (`graviola-p384`) | 2.74-3.18-3.24 ahead | 2.10-2.33-2.45 ahead |
| p-384 key preparation (`graviola-p384`) | 0.05-0.05-0.05 behind | 0.05-0.05-0.05 behind |
| ecdsa p-384 sign (`graviola-p384`) | 2.76-3.07-3.20 ahead | 2.38-2.43-2.53 ahead |
| ecdsa p-384 verify (`graviola-p384`) | 1.87-2.01-2.28 ahead | 1.91-2.23-2.31 ahead |
| chacha20-poly1305, 4 MiB (`graviola-chacha`) | 2.74-2.77-3.26 ahead | 1.39-1.41-1.41 ahead |
| chacha20-poly1305, 1 KiB (`graviola-chacha`) | 2.07-2.09-2.25 ahead | 1.34-1.35-1.38 ahead |
| chacha20-poly1305, 64 B (`graviola-chacha`) | 2.51-2.57-2.59 ahead | 2.46-2.55-2.62 ahead |
| aes-256-gcm, 4 MiB (`graviola-gcm`) | 1.22-1.59-1.60 ahead | 0.90-0.90-0.92 behind |
| aes-256-gcm, 1 KiB (`graviola-gcm`) | 1.58-1.72-1.82 ahead | 1.11-1.16-1.19 ahead |
| aes-256-gcm, 64 B (`graviola-gcm`) | 2.35-2.82-2.88 ahead | 2.77-2.86-2.93 ahead |
| x25519 agree (`graviola-25519`) | 1.14-1.15-1.15 ahead | 0.99-0.99-1.05 level |
| ed25519 sign (`graviola-25519`) | 1.21-1.22-1.22 ahead | 1.08-1.09-1.09 ahead |
| ed25519 verify (`graviola-25519`) | 1.14-1.14-1.16 ahead | 0.99-0.99-1.05 level |
| ed25519 verify, key held (`graviola-25519`) | 1.27-1.32-1.35 ahead | 1.12-1.13-1.24 ahead |
| rsa-2048 sign (`graviola-rsa`) | 1.43-1.44-1.49 ahead | 1.08-1.12-1.13 ahead |
| rsa-2048 verify (`graviola-rsa`) | 1.37-1.68-1.75 ahead | 1.13-1.26-1.41 ahead |
| rsa-3072 sign (`graviola-rsa`) | 3.73-3.81-3.97 ahead | 2.48-2.52-2.55 ahead |
| rsa-3072 verify (`graviola-rsa`) | 3.00-3.04-3.39 ahead | 2.96-3.02-3.49 ahead |
| rsa-4096 sign (`graviola-rsa`) | 1.49-1.82-2.20 ahead | 0.98-1.15-1.39 level |
| rsa-4096 verify (`graviola-rsa`) | 2.75-3.01-3.10 ahead | 2.79-3.15-3.48 ahead |

Against 2026-10-16, no row changed between ahead and behind, and the three
rows behind are the same three, for the reasons given there: AES-256-GCM at
4 MiB without AVX-512 against Graviola's own AVX-512 path, P-384 key
preparation, and key generation with the pairwise test (0.55 by median in the
default build here, 0.42 then). Five rows moved between ahead and level. All
five were near the boundary in both runs:

- Without AVX-512, now level: HMAC-SHA256 at 200 B (minimum 0.99, median
  1.12), AES-256-GCM at 1 KiB in `graviola` (minimum 0.99; ahead in
  `graviola-gcm`), and P-384 ECDH against Graviola's key parsed once in
  `graviola-p384` (median 1.04).
- Without AVX-512, now ahead: RSA-2048 verify in `graviola` (1.06-1.14-1.29;
  0.93-1.15-1.41 then).
- Default build, now ahead: ML-KEM-768 key generation like for like
  (1.16-1.22-1.49), which the summary already counted as ahead from
  2026-10-17's "ML-KEM on eight Keccak lanes".

This run cannot say whether any of these is a change in the library. The
code changed between 706bb35 and c04c63f, but each shift is inside the spread
of the earlier run's rows. Telling them apart would take an alternated A/B of
the two commits under the same load, as AGENTS.md describes.

### Consolidated run, 2026-10-16, master 706bb35

This run replaces the piecemeal figures below with one set taken the same
way. Every comparison mode of `bench` ran five rounds in each of two
configurations: `graviola`, `graviola-p384`, `graviola-chacha`,
`graviola-gcm`, `graviola-25519` and `graviola-rsa`, against Graviola 0.4.1
from crates.io, unpatched. The default build and `RUSTFLAGS="--cfg
ic_no_avx512"` were built from 706bb35 and copied aside, so each run used a
fixed binary. Round r ran the six modes with the default build, then the six
with the no-AVX-512 build, about 30 seconds between modes; the two
configurations alternated round by round.

Each ratio is IronCrypto's rate over Graviola's, read from the bench's own
verdict line within the run: a `faster` line gives the ratio, a `SLOWER` line
gives its reciprocal. Each cell is the minimum, median and maximum over the five
rounds. Where two modes report the same operation, both rows are kept, and the
mode is named.

The machine load at the start of each mode read 14 to 100 percent, from other
work on the same host. Read the ratios within a run only; the absolute times
were not compared across runs, and the spread across rounds is shown in each
cell.

Classification, applied to each row in each configuration:

- **behind**: median below 0.95;
- **level**: median from 0.95 to 1.05, or minimum below 1.0 with median at
  least 1.0;
- **ahead**: median at least 1.05 and minimum at least 1.0.

| operation (bench mode) | default, min-median-max | without AVX-512, min-median-max |
|---|---|---|
| aes-256-gcm, 4 MiB (`graviola`) | 1.46-1.57-1.61 ahead | 0.83-0.91-0.92 behind |
| chacha20-poly1305, 4 MiB (`graviola`) | 2.24-2.75-3.25 ahead | 1.44-1.45-1.75 ahead |
| aes-256-gcm, 1 KiB (`graviola`) | 1.39-1.64-1.76 ahead | 1.02-1.17-1.19 ahead |
| chacha20-poly1305, 1 KiB (`graviola`) | 1.86-2.09-2.13 ahead | 1.36-1.44-1.54 ahead |
| aes-256-gcm, 64 B (`graviola`) | 2.32-2.83-2.85 ahead | 1.89-2.64-2.85 ahead |
| chacha20-poly1305, 64 B (`graviola`) | 2.40-2.54-2.70 ahead | 2.46-2.53-2.88 ahead |
| sha-256 (`graviola`) | 0.99-1.00-1.14 level | 0.89-1.01-1.10 level |
| sha-512 (`graviola`) | 1.09-1.15-1.17 ahead | 1.09-1.16-1.72 ahead |
| sha3-256 (`graviola`) | 0.94-0.97-0.98 level | 0.77-0.97-1.00 level |
| hmac-sha256, 4 MiB (`graviola`) | 0.94-1.00-1.01 level | 0.93-1.00-1.00 level |
| hmac-sha256, 200 B (`graviola`) | 1.05-1.12-1.20 ahead | 1.12-1.14-1.21 ahead |
| sha-256, 64 B (`graviola`) | 0.94-1.35-1.37 level | 0.89-1.04-1.44 level |
| x25519 agree (`graviola`) | 1.14-1.16-1.50 ahead | 0.98-0.99-1.02 level |
| p-256 ecdh (`graviola`) | 1.21-1.24-1.31 ahead | 1.01-1.20-1.86 ahead |
| p-256 ecdh, from bytes (`graviola`) | 1.26-1.29-1.58 ahead | 1.13-1.25-1.86 ahead |
| p-256 ecdh, key prepared (`graviola`) | 2.45-2.49-2.57 ahead | 1.85-2.60-4.22 ahead |
| ecdsa p-256 sign (`graviola`) | 1.16-1.16-1.48 ahead | 1.00-1.12-1.54 ahead |
| ecdsa p-256 verify (`graviola`) | 1.33-1.35-1.44 ahead | 1.65-1.94-2.04 ahead |
| p-384 ecdh (`graviola`) | 1.21-1.33-2.01 ahead | 0.91-1.02-1.24 level |
| p-384 ecdh, from bytes (`graviola`) | 1.26-1.39-1.42 ahead | 0.97-1.06-1.19 level |
| p-384 ecdh, key prepared (`graviola`) | 2.70-2.99-5.07 ahead | 2.06-2.36-2.95 ahead |
| p-384 key preparation (`graviola`) | 0.04-0.04-0.05 behind | 0.04-0.05-0.05 behind |
| ecdsa p-384 sign (`graviola`) | 2.80-3.01-3.32 ahead | 2.28-2.36-3.13 ahead |
| ecdsa p-384 verify (`graviola`) | 1.91-1.99-2.15 ahead | 1.75-1.95-2.19 ahead |
| ed25519 sign (`graviola`) | 1.19-1.25-1.56 ahead | 0.99-1.10-1.12 level |
| ed25519 verify (`graviola`) | 1.13-1.15-1.45 ahead | 1.00-1.03-1.27 level |
| ed25519 verify, key held (`graviola`) | 1.31-1.34-1.68 ahead | 1.10-1.13-1.27 ahead |
| keygen (ironcrypto with pairwise test) (`graviola`) | 0.38-0.42-0.45 behind | 0.34-0.36-0.49 behind |
| keygen (like for like, no pairwise test) (`graviola`) | 0.85-1.10-1.18 level | 0.88-1.05-1.17 level |
| ml-kem-768 encaps, from bytes, both (`graviola`) | 1.55-1.65-2.00 ahead | 1.41-1.46-2.02 ahead |
| ml-kem-768 encaps, parsed once, both (`graviola`) | 1.88-2.05-2.32 ahead | 1.90-1.97-2.11 ahead |
| ml-kem-768 decaps, parsed once, both (`graviola`) | 1.32-1.33-1.37 ahead | 1.13-1.16-1.46 ahead |
| rsa-2048 sign (`graviola`) | 1.45-1.61-1.69 ahead | 1.03-1.16-1.23 ahead |
| rsa-2048 verify (`graviola`) | 1.54-1.74-2.02 ahead | 0.93-1.15-1.41 level |
| p-384 ecdh (`graviola-p384`) | 1.33-1.36-1.45 ahead | 1.03-1.06-1.28 ahead |
| p-384 ecdh, from bytes (`graviola-p384`) | 1.40-1.42-1.47 ahead | 1.08-1.09-1.21 ahead |
| p-384 ecdh, key prepared (`graviola-p384`) | 2.94-3.00-3.07 ahead | 2.28-2.50-2.96 ahead |
| p-384 key preparation (`graviola-p384`) | 0.04-0.05-0.05 behind | 0.04-0.04-0.05 behind |
| ecdsa p-384 sign (`graviola-p384`) | 3.01-3.05-3.07 ahead | 2.34-2.42-2.80 ahead |
| ecdsa p-384 verify (`graviola-p384`) | 1.93-1.99-2.07 ahead | 1.84-1.91-2.15 ahead |
| chacha20-poly1305, 4 MiB (`graviola-chacha`) | 2.73-2.79-3.28 ahead | 1.43-1.47-1.74 ahead |
| chacha20-poly1305, 1 KiB (`graviola-chacha`) | 1.42-2.11-2.19 ahead | 1.36-1.38-1.59 ahead |
| chacha20-poly1305, 64 B (`graviola-chacha`) | 2.01-2.55-2.63 ahead | 2.48-2.51-2.59 ahead |
| aes-256-gcm, 4 MiB (`graviola-gcm`) | 1.40-1.54-1.61 ahead | 0.85-0.90-0.95 behind |
| aes-256-gcm, 1 KiB (`graviola-gcm`) | 1.56-1.67-1.71 ahead | 1.07-1.15-1.18 ahead |
| aes-256-gcm, 64 B (`graviola-gcm`) | 2.08-2.82-2.95 ahead | 2.19-2.82-2.89 ahead |
| x25519 agree (`graviola-25519`) | 1.15-1.15-1.45 ahead | 0.98-0.99-1.06 level |
| ed25519 sign (`graviola-25519`) | 1.18-1.22-1.37 ahead | 1.05-1.09-1.10 ahead |
| ed25519 verify (`graviola-25519`) | 1.05-1.14-1.43 ahead | 0.98-0.99-1.02 level |
| ed25519 verify, key held (`graviola-25519`) | 1.32-1.33-1.65 ahead | 1.09-1.13-1.13 ahead |
| rsa-2048 sign (`graviola-rsa`) | 1.36-1.41-1.49 ahead | 1.03-1.11-1.19 ahead |
| rsa-2048 verify (`graviola-rsa`) | 1.72-1.73-1.88 ahead | 1.08-1.10-1.17 ahead |
| rsa-3072 sign (`graviola-rsa`) | 3.55-3.75-3.97 ahead | 2.28-2.51-2.90 ahead |
| rsa-3072 verify (`graviola-rsa`) | 2.24-3.00-3.08 ahead | 2.59-2.97-3.60 ahead |
| rsa-4096 sign (`graviola-rsa`) | 1.70-1.87-1.94 ahead | 0.56-1.06-1.12 level |
| rsa-4096 verify (`graviola-rsa`) | 2.68-2.96-3.03 ahead | 2.99-3.20-3.29 ahead |

Where the rows disagree within this run, both are stated above and the summary
follows the more specific mode. Four things are not like for like, and the
classification is read with them in mind:

- **AES-256-GCM at 4 MiB without AVX-512** is behind in both `graviola-gcm` and
  `graviola`. Unpatched Graviola takes its own AVX-512 path for messages of
  256 bytes and up on this CPU, and IronCrypto runs VAES-256 there, so this is
  the comparison against Graviola's 512-bit kernel, which the section "Without
  AVX-512" already says a CPU without AVX-512 does not run. The patched,
  AES-NI-path comparison of 2026-10-13 is in "AES-GCM without AVX-512"; it was
  not repeated here.
- **P-384 key preparation** sets IronCrypto's prepared key, with sixty-four
  affine multiples, against Graviola's parsing of a key. It is the cost of
  building the key once, not a per-operation rate. Measured again on
  2026-10-17 after batching the field inversions of all four windows into one
  (the table was already normalised per window, not per multiple, so the
  suspected sixty-four inversions were four): `graviola-p384`, eight
  interleaved A/B rounds, preparation 74.0-77.4-85.5 us before and
  68.1-69.0-69.4 us after, against Graviola's 3.5 us parse. That is about
  0.045x before and 0.05x after, which the table's rows above (taken before the
  change) do not reflect. The remaining time is about 300 doublings and 60
  window operations that build the four spacings; only a smaller table, or
  deferring the work to first use, would remove it, and neither was done.
- **Key generation with the pairwise test** runs IronCrypto's pairwise
  consistency check, which Graviola does not; the like-for-like row is the one
  without it.
- **P-384 ECDH against Graviola's key parsed once** without AVX-512 is ahead in
  `graviola-p384` and level in `graviola`. The two modes time the same
  operation in different rounds and layouts; see "P-256 and P-384 without
  AVX-512, 2026-10-14", below.

ML-KEM-768 decapsulation from key bytes has no Graviola row (Graviola 0.4.1
cannot parse a decapsulation key); see "Where it is not ahead", below.

**P-256 ECDH without AVX-512.** The recent change that may have cost about 4
percent is not visible here as a regression. In this run, with Graviola's key
parsed once (`graviola`, P-256 ECDH), IronCrypto's rate over Graviola's was
1.01-1.20-1.86 (minimum, median, maximum over five rounds); from key bytes on
both sides it was 1.13-1.25-1.86. The earlier section "P-256 and P-384 without
AVX-512, 2026-10-14" had, for the same row, 0.97-1.05 before the change and
1.05-1.22 after it in layout A, and 0.94-0.99 before and 1.20-1.23 after in
layout B. From key bytes it had 1.00-1.12 and 1.11-1.29 in layout A, and 0.98-1.00
and 1.27-1.32 in layout B. The consolidated median of 1.20 sits within the
earlier "after" ranges and is not 4 percent below them. But the spread here,
from 1.01 to 1.86, is far wider than 4 percent, so this run cannot confirm or
exclude a 4 percent cost. Resolving it would take an alternated A/B of the two
commits under the same load, as AGENTS.md describes.

The figures below this section were taken on the same Ryzen 9 9900X (Zen 5,
AVX-512 and IFMA), with `cd bench && cargo run --release --
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
| ChaCha20-Poly1305 seal, 64 B | 147-166 MiB/s, loaded | 113-137 MiB/s, loaded | 2.59-2.64 in the same runs (short-message paths, below) |
| SHA-256, 4 MiB | -- | -- | 2187 / 2275 MiB/s |
| SHA-512, 4 MiB | -- | -- | 669 / 507 MiB/s |
| SHA3-256, 4 MiB | 690 MiB/s | 690-735 MiB/s | 594 / 445 MiB/s |
| HMAC-SHA256, 200 B | 230 ns | parity | 1.21-1.25 in the same runs (short-message paths, below) |
| X25519 | 11.7-12.2 | 13.2-13.6 | 13.7 / 21.6 |
| Ed25519 sign | 4.6-4.8 | 5.3-6.0 | 5.2 / 6.7 |
| Ed25519 verify | 17.3-17.6 | 22.4-24.1 | 23.6 / 31.0 |
| P-256 ECDH | 21.8-22.2, loaded (AVX-512) | 25.6-26.7, loaded | 1.16-1.21 in the same runs |
| P-256 ECDH, both parsing the key per call | 21.8-22.2, loaded (AVX-512) | 27.1-28.0, loaded | 1.22-1.28 in the same runs |
| ECDSA P-256 sign | 6.4-6.6, loaded (AVX-512) | 7.8-8.3, loaded | 1.20-1.22 in the same runs |
| ECDSA P-256 verify | 26.8 | 30.0-30.6 | 44.5 / 44.9 |
| P-384 ECDH | 65.0-67.0, loaded (AVX-512) | 76.7-83.1, loaded | 1.17-1.24 in the same runs |
| P-384 ECDH, both parsing the key per call | 65.0-67.0, loaded (AVX-512) | 81.7-94.5, loaded | 1.26-1.42 in the same runs |
| P-384 ECDH, key prepared | 30.2-35.3, loaded (AVX-512) | 76.7-83.1, loaded (parsed once) | 2.26-2.71 in the same runs |
| P-256 ECDH, key prepared | 10.1-10.4, loaded | 25.8-26.3, loaded (parsed once) | 2.50-2.57 in the same runs |
| ECDSA P-384 sign | 32.6-39.3, loaded (AVX-512) | 83.2-109.2, loaded | 0.32-0.43 in the same runs |
| ECDSA P-384 verify | 160-203, loaded | 228-300, loaded | 0.58-0.79 in the same runs |
| ML-KEM-768 keygen, like for like | 6.4 | 7.5 | 8.5 / 11.0 |
| ML-KEM-768 encapsulate, key prepared | 2.6 | 4.6 | 3.1 / 4.6 |
| ML-KEM-768 decapsulate, key prepared | 4.4 | 5.9 | 5.5 / 9.2 |
| RSA-2048 PKCS#1 v1.5 sign | 255-300 | 345 | 572 / 868 |
| RSA-2048 PKCS#1 v1.5 verify | 7.5-8.5 | 9-10.5 | 12.8 / 22.1 |

### ML-KEM on eight Keccak lanes, 2026-10-17

Starting point: master 0aa57cd, where ML-KEM-768 key generation without the
pairwise test was level with Graviola (above) and with it 0.38-0.45 behind,
and SHA3-256 was level. This change runs ML-KEM's Keccak calls (matrix
expansion, noise PRFs, `H`, `J`) eight lanes wide on AVX-512, where that saves
permutations. The AVX-512 build only; a CPU without AVX-512, or
`--cfg ic_no_avx512`, takes the four-lane path unchanged.

**Where key generation's time goes** (6.3 us, the like-for-like row,
measured in one binary before the change): the Keccak schedule for the nine
matrix entries and six noise polynomials 2.6-2.9 us, of which about 1 us is
the scalar work around the permutations (absorbing, copying the squeezed
block out of the interleaved state, rejection sampling, the centred binomial
sample); `H(ek)`, a serial 9-permutation SHA3-256 of the 1184-byte key,
1.7 us; the rest, six NTTs, the matrix-vector product and the encoding,
about 1.8 us. The pairwise test adds an encapsulation (4.9 us from bytes)
and a decapsulation (6.2 us) to that: 19.3 us in all.

**What was done.** `ic-hash` gains `KeccakX8` (hidden, not API): eight states
permuted by one `asm!` block that keeps all 25 lanes in `zmm0`-24 for 24
rounds (`ic-hash/src/sha3/zmm.rs`, generated by `scripts/gen_keccak_x86.py`).
The intrinsics form, four states on `ymm`, has 16 registers and spills; the
same assembly four states wide measured 190 ns against its 181 ns, so the
four-way path was left as it was. Eight states cost 194 ns, so a
permutation of eight is about twice the throughput on this Zen 5 part
(`vector_permutation_widths`, an ignored test: best of 40 batches of 20,000
in one process). `ic-mlkem`'s lane scheduler is generic over the width and
takes eight lanes only when its estimate says that needs fewer permutations:
a schedule bound by one long hash, as encapsulation's `H(ek)` is, takes the
same nine either way and pays more in scalar work around each.

**Measured**, `bench` `graviola`, seven rounds of the binary built from
0aa57cd and the binary built from this change, alternated, both libraries in
every run, ratio of IronCrypto's rate over Graviola's as in the table above
(minimum-median-maximum), load from other work on the host not controlled:

| operation | before | after | class after |
|---|---|---|---|
| keygen (like for like, no pairwise test) | 1.03-1.09-1.13 | 1.11-1.18-1.26 | ahead |
| keygen (ironcrypto with pairwise test) | 0.39-0.40-0.44 | 0.42-0.42-0.46 | behind |
| ml-kem-768 encaps, from bytes, both | 1.60-1.67-1.82 | 1.71-1.73-1.75 | ahead |
| ml-kem-768 encaps, parsed once, both | 1.98-2.08-2.19 | 2.06-2.24-2.33 | ahead |
| ml-kem-768 decaps, parsed once, both | 1.29-1.32-1.35 | 1.15-1.32-1.37 | ahead |
| sha3-256 | 0.96-0.97-0.98 | 0.93-0.97-0.98 | level |

In microseconds, same binary pair, several rounds: key generation without
the pairwise test 6.8-9.2 (typically 7.0) -> 6.27-6.38; with it 18.9-23.6
(typically 19) -> 17.9-18.6; encapsulation from bytes 5.1-6.4 -> 5.0-5.2;
encapsulation with the key parsed 2.2-2.9 -> 2.0-2.4; decapsulation with the
key parsed 4.3-4.7 -> 4.3-4.5 once the width choice cost no more than the
decision itself (an earlier version that ran the estimate twice over the
tasks measured 4.6-5.1; it now makes one pass). Decapsulation from bytes,
which has no Graviola row, 6.3-8.1 -> 5.7.

**What did not pay.** SHA3-256 is a single serial sponge: nothing to run
side by side. Its scalar permutation is about 38 cycles a round (0.18 us; the 19 first
written here was wrong, see the 2026-10-18 section). A single-state AVX-512
permutation was built after this note and did not beat it; SHA3-256 stays
level. The pairwise
test stays 2.4 times behind, and no restructuring that keeps the test whole
brings it near level: encapsulation and decapsulation together cost
more than key generation does (10.7 us from bytes, 6.5 us with the keys
parsed, against 6.3), and Graviola's whole key generation is 7.5 us. What
could be shared is the matrix: encapsulation and decapsulation each expand
`A^T` again, and handing the one expansion to both would save, by an
estimate from the scalar work per block and not built, about 1 us of 18.
It was not done, because it also changes what the test covers: with the
key's own `A` or the test's `A^T` held in common, a fault in the expansion
no longer shows as a disagreement. Eight lanes did not help encapsulation
from bytes (a nine-permutation `H(ek)` bounds it); a measured change there
is inside the spread.

**Where this does not apply.** Measured on one CPU, a Zen 5 part with 512-bit
vector units whose eight-state permutation costs what the four-state one
does. On a CPU that executes 512-bit operations at half rate, eight states
would cost about twice four, and the saving in permutations would not be
a saving in time; this was not measured, and runtime detection here is by
feature, not by microarchitecture. The Intel SDE runs in CI test
correctness, not speed.

### SHA3-256 on one AVX-512 state, tried and not kept, 2026-10-18

SHA3-256 was level (0.93-0.98). The 2026-10-17 note above estimated a
single-state AVX-512 permutation at 16 to 20 cycles a round and did not build
it. Two versions were built and measured; neither beat the scalar one, and
neither is in the tree.

**The target.** Graviola's `sha3_keccak_f1600` on x86-64 is scalar assembly
(Andy Polyakov's OpenSSL kernel, as vendored by s2n-bignum): no `zmm`, no
`ymm`, no `vpternlogq` anywhere in the file. Ours is scalar too, so "level"
is two scalar permutations. The 4 MiB row is permutation-bound: 690 MiB/s is
about 192 ns a 136-byte block against a 181 ns permutation, so absorb
overhead is about 10 ns and there is nothing to win outside the permutation.

**A correction.** The earlier note put the scalar permutation at "about 19
cycles a round". The clock on this part, measured with a dependent `add`
chain, is 4.9 GHz, so 181 ns is 905 cycles, 37.7 cycles a round. (19 is what
the same time gives at 2.5 GHz.)

**Latencies on this part, measured as dependent chains (cycles).** Logic
(`vpternlogq`, `vpxorq`, `vprolq`, `vprolvq`) and in-lane shuffles
(`vpshufd`, `vpalignr`, `vpunpcklqdq`) 1.9; `vpermq`, `vpermt2q` and
`valignq` on `zmm` 4.8, 3.9 on `ymm`; a cross-lane shuffle feeding a logic
operation costs 8.9 together, not 4.8 + 1.9. Throughput: about 2 shuffles
and 3 logic operations a cycle.

**Version 1: five lanes of a plane per `zmm`, 55 operations a round.**
Theta by `vpternlogq` and two `vpermq` for the column rotation, rho by
`vprolvq`, pi by two `vpermt2q`, one `vpermq` and a three-way or per row, chi
by two `vpermq` and `vpternlogq 0xd2`, iota folded into the parity. Correct
against the scalar permutation on 150 chained states. In one process,
alternating, best of 40 batches of 20,000: scalar 181 ns, vector 207 ns
(8.6 ns a round, 43 cycles). Taking out rho, the chi shuffles, the pi
shuffles or theta's shuffles in turn saved 2 to 5 cycles a round each, and
with all four replaced by single-cycle operations it still took 141 ns: the
chain through four shuffle-to-logic crossings is the bound. It is the 16 to
20 cycles the note guessed only if a shuffle plus a logic operation cost 4.8
+ 1.9, which they do not.

**Version 2: spend operations to shorten the chain.** Rows are kept in three
rotations (`A[x-1]`, `A[x]`, `A[x+1]` at lane `x`) so theta's column parities
are plain xor trees with no shuffle, rho and the theta xor are folded into
`rol(S) ^ rol(Cm) ^ rol(Cp)`, and chi is evaluated at three alignments from
the four rotations of each new row. About 110 operations a round, one
shuffle-to-logic crossing fewer. Correct on the same states. Measured in
process against the scalar permutation, on a machine that was loaded by
other builds (the scalar figure moved between 181 and 237 ns across runs, so
only the pair within one run is read): 214.0 against 215.6, 211.9 against
220.2, 214.4 against 237.1. Replacing every chi and pi shuffle by a
single-cycle operation moved it from 214 to 194, so it is now bound by
operation count (about 2.5 operations a cycle), not by the chain. Parity,
within the noise, at best; with the state load and store around it and no
dispatch cost counted, nothing for SHA3-256 to gain.

**Why it stops there.** A single Keccak state is 25 lanes of a serial
chain. The scalar kernel retires about 5 operations a cycle on six integer
ports; the vector kernel either has too few operations to hide its shuffle
latency (version 1) or too many to issue (version 2). The 8-way kernel works
because eight independent states fill the width; one state cannot. A hybrid
that splits one round between the integer and vector units pays a
cross-domain move on every lane it hands over, which is the cost it would
have to save.

**Verdict.** SHA3-256 and the SHAKE sponges stay level with Graviola; no
code changed, nothing added to the build. The four-way and eight-way paths
that ML-KEM and ML-DSA use are unaffected.

### ML-KEM key generation with the pairwise test, 2026-10-18

Starting point: master 4ce0dc7 (0.3.2), where key generation with
IronCrypto's FIPS 140-3 pairwise consistency test (PCT) ran at 0.42 of
Graviola's rate, which has no such test. The test stays whole: it still
encapsulates to the generated key from its bytes, decapsulates with the
generated `dk`, and compares the secrets, on every key and not optionally.
What changed is how its Keccak work is scheduled and one matrix expansion.

**Where the time went.** The PCT added 14 us to a 7 us key generation:
`H(ek)` once more in key generation itself (a serial scalar SHA3-256 of
1184 bytes, 9 permutations, 1.7 us), once in the encapsulation (nine
permutations, with `A^T` beside it), once in the decapsulation's hash
check (nine again), `J(z || c)` in the decapsulation (a 9-block hash again,
bound by it), and `A^T` expanded twice. Each of those hash chains is long
and serial, and the three stages ran one after the other, so the test paid
for three 9-permutation chains where one would do.

**What was done** (`ic-mlkem/src/scheme.rs`, `pairwise_consistency_lanes`;
the AVX2 and AVX-512 paths, which are the ones `parallel()` selects):

1. Every Keccak call in the test that needs only `ek` runs in one schedule:
   `H(ek)` as key generation stores it, `H(ek)` for the encapsulation, `H`
   of the copy of `ek` inside `dk` for the decapsulation's hash check, and
   `A^T`. Three lanes of one schedule instead of three chains in series;
   key generation's own serial `H(ek)` is gone, the stored hash coming out
   of this schedule (`keygen_deterministic`, which has no test, still hashes
   as before).
2. The decapsulation in the test skips `J(z || c)`. Nothing in the
   comparison reads it: the test compares `K` with `K'`, and the rejection
   key is selected only when the re-encryption differs, in which case the
   comparison already fails (the selected key is then zeros, not `J`). `z`
   is drawn by key generation, not computed from the key pair, so there is
   nothing in `J` for the test to check.
3. The encapsulation and the decapsulation share one expansion of `A^T`,
   from `ek`'s seed. This is the item the previous section declined, and it
   needs the argument it asked for, below.

**Why sharing `A^T` between the test's two halves keeps the test meaningful.**
The test must fail if key generation's output is inconsistent. Key
generation's matrix `A_k` (sampled earlier, in a separate Keccak run that the
test never reads) enters only through `t = A_k s + e` in `ek`; the test
expands its own `A'` afresh from the seed stored in `ek`. The decryption in
the decapsulation forms `v - s^T u`, with `v = t^T y + e2 + m` from the
encapsulation and `u = A'^T y + e1`. The terms cancel to leave `m` and small
noise only if `s^T A_k^T y = s^T A'^T y`, which for a fault anywhere in key
generation's sampling, NTT or product (a different `A_k`, `s` or `t`) does not
hold with overwhelming probability, whether `A'` is shared between the two
halves of the test or not. The second, independent expansion in the
unshared form cross-checked the test's own expansion against itself, which
detects a fault in the test and not one in key generation; a fault in the
shared `A'` is still detected, as a failure of the decryption above, since
`t` carries the true matrix. What stays true after the change: no value that
key generation computed is reused by the test (`A_k`, `s`, `e`, `t` and the
seed hash chain are all rebuilt from the bytes of `ek` and `dk`), the
decapsulation decrypts with the `s` stored in `dk` and re-encrypts from the
copy of `ek` stored in `dk`, as the public function does, and the hash lanes
are compared with the stored hash. Pinned by
`the_scheduled_pairwise_test_refuses_each_corruption`: a flipped bit in `s`
(first and last byte), in `t`, in the seed of `ek`, in the copy of `ek` in
`dk` (its `t` and its seed), and in the stored hash, each refused by the
scheduled and the streaming forms, with `ek` corrupted likewise when called
as key generation calls it. Checked by breaking: with the decapsulation's
hash lane left out of the comparison, the copy-of-`ek`-seed case is accepted
and the test fails, on all three parameter sets.

**What is weaker, stated plainly.** The three `H(ek)` lanes are permuted by
the same instruction stream in the same calls, where before they were
three separate calls (and key generation's was the scalar permutation, a
different code path). A fault that hits one lane's data shows as a
disagreement between lanes. A fault common to all lanes of one permutation
call (a corrupted round constant, say) corrupts the three hashes alike and
passes the hash comparison; it would also corrupt the lanes that expand the
test's `A'`, which the decryption above then catches, but a common-mode fault
that left `A'` intact would let a wrong stored `H(ek)` through at generation.
Such a key is refused at its first use (the decapsulation's hash check
recomputes `H`), so it fails closed. A persistent fault in the vector
permutation breaks every known-answer test before it breaks this one.
Nothing in this change removes a check; this one is narrower in what it can
tell apart for a common-mode fault in one call.

**Measured**, `bench` `graviola`, nine rounds of the binary built from
4ce0dc7 and the binary built from this change, alternated, both libraries in
every run, load from other work on the host not controlled (it read heavily
loaded through most of the session, so absolute times are 20 to 30 percent
above the figures in the section above); ratio of IronCrypto's rate over
Graviola's, then IronCrypto's time with the test, minimum-median-maximum:

| build | ratio before | ratio after | us before | us after |
|---|---|---|---|---|
| default (AVX-512 lanes) | 0.40-0.43-0.48 | 0.50-0.59-0.91 | 21.3-23.2-55.4 | 15.9-16.9-19.7 |
| `--cfg ic_no_avx512` | 0.32-0.35-0.38 | 0.38-0.45-0.46 | 26.0-28.3-34.7 | 20.3-21.9-27.3 |

An earlier round of nine on the same pair, under heavier load, read 0.33-0.40-0.46
before and 0.40-0.56-0.74 after. The 0.91 is one round in which Graviola's
own time spiked; the median is the figure. Key generation without the test
did not change (7.3 to 8 us before and after, inside the spread);
encapsulation and decapsulation outside the test were not touched.
Inside the test, on the loaded host, stage by stage (us): the one schedule
about 3.5 to 4.5 (the previous encapsulation's `H(ek)` and `A^T` alone were
about 2.4 to 3.4 under the same load), `G` 0.4, noise 0.7 twice,
encryption 1.8, decryption with `G` 1.4, re-encryption 2.0. Peak stack by
`ic-bench stack mlkem` is unchanged for ML-KEM-768 (keygen 36559 bytes
before and after) and 64 bytes more for ML-KEM-512 and -1024 keygen, against
scrubs of 32 KiB; the scrub sizes in the table above are unchanged.

**The gap is narrowed, not closed, and under this constraint it cannot be.**
With the test whole, key generation does an encapsulation from bytes and
a decapsulation after its own work; those two cost 2.4 and 5.4 us even with
the key parsed once, which alone exceeds Graviola's 7.5 us key generation,
and the test's ciphertext round trip is a dependency chain (encapsulate,
then decrypt, then re-encrypt) that cannot be overlapped with itself. The
remaining time is the NTT-domain arithmetic of two encryptions and a
decryption (18 transforms of about 0.09 us, 27 `basemul_add` of 0.03 us:
about 2.5 us), the scalar glue around the Keccak schedules (about half of
each schedule), and `G` and the noise. Sharing more would mean sharing state
between key generation and the test, which this change does not do.

**What did not pay, or was declined.**

- *Sharing `A_k` (key generation's own matrix) with the test*: declined. It
  would let a fault in key generation's expansion cancel in the test.
- *Dropping the decapsulation's re-encryption and comparing `m` with `m'`*:
  declined. It would stop testing the copy of `ek` inside `dk` and the
  re-encryption check, and it is not the decapsulation the standard names.
- *Two `H(ek)` lanes in place of three*: no measurable difference (the
  schedule is bound by the nine-permutation chain either way and the third
  lane costs a few hundred cycles); three kept, for the comparison.
- *AVX-512 NTT*: not built. A transform is 0.08 to 0.1 us on AVX2; the
  test runs 18, and a 1.5 times faster transform would save about 0.5 us of
  16, against a new kernel to prove constant time and a probe.
- *Faster `H(ek)` on one state*: as the previous section found, a single
  AVX-512 permutation is bound by its dependent shuffles; nothing here
  changed that, and the hash now hides behind the matrix expansion instead.
- *The glue around the lanes* (`xor_lane`, `read_lane`, `reset_lane`: scalar
  strided word accesses, about as long per step as the permutation itself):
  not attempted; it is the next place to look and benefits every ML-KEM
  operation.

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
| ChaCha20-Poly1305, 64 B | 1.19-1.57 (2.59-2.64 since, below) | | ECDSA P-256 verify | 1.09-1.13 |
| SHA-256, 4 MiB | 0.98-1.01 | | P-384 ECDH | 0.83-0.98 |
| SHA-512, 4 MiB | 1.27-2.05 | | ECDSA P-384 sign | 2.33-2.79 |
| SHA3-256, 4 MiB | 0.95-0.97 | | ECDSA P-384 verify | 1.41-1.56 |
| HMAC-SHA256, 4 MiB | 0.92-0.99 | | ML-KEM-768 keygen, like for like | 0.98-1.39 |
| HMAC-SHA256, 200 B | 0.93 (1.21-1.25 since, below) | | ML-KEM-768 encapsulate, from bytes, both | 1.82-2.08 |
| SHA-256, 64 B | 1.01-1.03 (1.35-1.37 since, below) | | ML-KEM-768 encapsulate, parsed once, both | 1.71-2.27 |
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

After that run, prepared ECDH peer keys were added and the rows above for
them measured: nine rounds on P-384 (six of `graviola-p384`, three of the
full run) and three on P-256, the machine at 100 percent load from other
work throughout, so only ratios within a run are read. The other rows are
from the run above and were not changed; an A/B of the unprepared
operations, the build before and after alternated over ten rounds, put
every one of P-256, P-384 and P-521 ECDH, signing and verification at
parity, medians 0.98 to 1.08, so the change did not move them.

Then P-256's and P-384's scalar multiplications moved to AVX-512 IFMA
where the CPU has it (CHANGELOG.md has the design and the tests). The
P-256 and P-384 ECDH, prepared-key and signing rows of the first table are
from that change's A/B: master f3be6ed and the branch alternated, three
rounds of `graviola` and six of `graviola-p384` for each build, load 35
to 96 percent from other work. Before -> after, IronCrypto's rate over
Graviola's in the same run: P-256 ECDH 0.94-1.00 -> 1.16-1.21 (from bytes,
both parsing, 1.03-1.04 -> 1.22-1.28), ECDSA P-256 sign 0.87-1.11 ->
1.20-1.22, P-384 ECDH 0.84-0.90 -> 1.17-1.24 (from bytes 0.88-1.04 ->
1.26-1.42), P-384 prepared 1.87-2.25 -> 2.26-2.71, P-256 prepared
2.25-2.67 -> 2.50-2.57, ECDSA P-384 sign 2.32-2.64 -> 2.34-3.14. The
P-256 and P-384 rows of the last-run table above predate it. Verification
does not use these multiplications and did not move.

Graviola's own times moved between bench binaries that differ only in
IronCrypto's code. Its ECDSA P-256 verify took 46 to 47 us in some builds
and 30 to 31 in others, in the same rounds, and once its P-384 ECDH took
104 to 119 us in one build against 77 to 84 in the rest; timing it before
any IFMA code had run, straight after, and two seconds after, in one
process, did not separate them. This library is no different: a build
that compiled the IFMA paths out under `ic_no_avx512` ran P-256 ECDH on
MULX/ADX at 44 us instead of 25, the source of that path unchanged. So the
figures above are ranges over alternated builds, and a single run of
either library, either way, is not evidence.

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
- **P-384 ECDH without AVX-512 IFMA, against Graviola's key parsed once**,
  is ahead by little in some builds: 1.00 to 1.04 of Graviola's rate in one
  layout of the bench binary and 1.16 to 1.25 in another ("P-256 and P-384
  without AVX-512, 2026-10-14", below), where it was 0.84 to 0.90 and 0.91
  to 1.04 before. From key bytes on both sides it leads in both layouts,
  1.07 to 1.26, and P-256 ECDH and signing lead in both. Graviola's parsed
  key holds its sixteen Jacobian multiples, about 4 us of work that the
  parsed-once row leaves out of Graviola's side and IronCrypto's
  agreement, which builds its window per call, keeps in its own; the two
  libraries' field operations and doubling now run at the same rate, and
  the lead left is what the buffer, the affine window and the inversion
  bring. With the key prepared on both sides IronCrypto leads by 2.3 to 3.3
  times: that lead is bought differently from Graviola's table, and is not
  like for like in memory or set-up: Graviola's parsed key holds sixteen
  Jacobian multiples and costs about 4 us to build; the prepared key here
  holds sixty-four affine multiples, at four spacings across the scalar, so
  that an agreement needs a quarter of the doublings, and costs about one
  agreement to build. It pays from the second agreement with the same key.
  P-384 ECDH was 1.7 times slower while the field arithmetic here was
  generic in the modulus. All of these rounds ran with the machine loaded
  by other work; read the ratios, not the absolute figures.
- **aarch64** has ARMv8 backends here for AES, SHA-256 and SHA-512 (the
  `SHA2` and `SHA512` instructions) and GHASH (`PMULL`), all behind the
  off-by-default `aarch64-crypto` feature; every other algorithm, ChaCha20,
  Poly1305 and the curves among them, runs the portable code. Graviola
  carries aarch64 assembly throughout and requires the `aes`, `sha2`, `pmull`
  and `neon` features there. The ARM backends here have been executed only
  under QEMU user-mode emulation, which checks what they compute and says
  nothing about speed: there is no aarch64 hardware on hand, and nothing was
  measured on aarch64. Their compiled code is gated: `scripts/check-ct.py`
  reads seven aarch64 probes of them (CONSTANT_TIME.md, "The ARMv8
  backends"). AES-GCM there is the AES backend and the `PMULL`
  GHASH run one after the other, not a fused kernel like x86-64's.
- **CPUs without AVX-512.** Measured on the same Zen 5 machine with
  `--cfg ic_no_avx512`, which turns the AVX-512 and IFMA paths off (table
  below). Without them, X25519 is level with Graviola, Ed25519 signs at
  1.07 to 1.10 times Graviola's rate since the radix-32 table and 64-bit
  scalar arithmetic ("Ed25519 signing without AVX-512, 2026-10-14", below;
  0.84 to 0.93 before) and verifies ahead with the key held, and ChaCha20-Poly1305 and ECDSA P-384 keep a lead, the ChaCha20 one
  smaller. AES-GCM leads at every size, by 1.9 to 2.3 times on a CPU with
  VAES and, at 1 KiB and 4 MiB, by 1.04 to 1.22 on AES-NI alone ("AES-GCM
  without AVX-512", below); the earlier reading of it as behind set
  IronCrypto without AVX-512 against Graviola's own AVX-512 path. RSA,
  behind before the MULX/ADX backend was rewritten, now leads at every
  size, narrowly at 4096-bit signing (1.08-1.09; the RSA tables below).
  P-256 ECDH and signing and P-384 ECDH from key bytes keep a smaller
  lead than with IFMA, and P-384 ECDH against Graviola's key parsed once a
  lead of 0 to 25 percent, depending on the build (bullet above, and "P-256
  and P-384 without AVX-512, 2026-10-14").
  Graviola needs only AVX2 and ADX, so it is the
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
| ECDSA P-256 verify | 0.98-1.01 (1.36-1.49 since the joint chain, below) | 1.00-1.08 (1.24-1.56 since) |
| P-384 ECDH | 0.76-0.77 | 0.69-1.26 |
| ECDSA P-384 sign | 2.31-2.59 | 2.26-2.32 |
| ECDSA P-384 verify | 1.08-1.23 (1.46-2.53 since the joint chain, below) | 1.26-1.66 (1.94-2.32 since) |
| RSA-2048 PKCS#1 v1.5 sign | 0.64-0.68, before the rewrite below | 1.16-1.36 |
| RSA-2048 PKCS#1 v1.5 verify | 0.68-0.78, before the rewrite below | 1.16-1.25 |
| SHA-512, 4 MiB | 1.47-1.86 | 1.60-2.23 |
| ML-KEM-768 encapsulate, key prepared (control) | 1.74-2.15 | 1.80-2.00 |
| SHA-256, 4 MiB (control) | 0.92-1.20 | 0.95-0.98 |

#### Curve25519 on MULX/ADX, after the changes of 2026-10-13

The X25519 and Ed25519 rows above are from before the MULX/ADX field's
changes listed in CHANGELOG.md (Unreleased, Performance). Measured since
with `cargo run --release -- graviola-25519`, which alternates the two
libraries in batches of 200 calls, forty times, and takes each side's
fastest batch, so that load reaching one reaches the other. Three rounds,
the build before the changes and after alternating, both configurations,
on a machine other jobs held near fully loaded (Graviola's X25519 took 16.5
to 17.4 us in these runs, against 12.8 when quieter). IronCrypto's rate over
Graviola's, the range across rounds:

| operation | AVX2 only, before | AVX2 only, after | default, before | default, after |
|---|---|---|---|---|
| X25519 | 0.95-0.97 | 0.97-1.02 | 1.42-1.47 | 1.46-1.50 |
| Ed25519 sign | 0.74-0.78 | 0.84-0.93 | 1.21-1.24 | 1.23-1.32 |
| Ed25519 verify, one-shot | 1.00-1.03 | 1.02-1.05 | 1.34-1.38 | 1.39-1.43 |
| Ed25519 verify, key held on both sides | 1.07-1.18 | 1.12-1.19 | 1.49-1.57 | 1.66-1.71 |

The last row is the like-for-like one: Graviola's verifying key holds its
point decoded, and the one-shot row decodes IronCrypto's on every call.

Not ahead, then, without AVX-512: X25519 is level and signing behind. The
diagnosis is that both libraries run the same instructions where it counts.
A field multiplication here and in s2n-bignum is the same sixteen `MULX`
products on `ADCX`/`ADOX` and the same fold by 38 -- about 80 instructions,
4.8 ns each when eight independent ones run back to back on this core, 7 ns
in a dependent chain -- and the ladder step, the mixed addition and the
doubling make the same number of them. Rewriting the carry chains with
`ADC` alone did not change that throughput, and reordering the ladder step
made it slower. What was left to take was outside the field operations:
the table read, the inversion, the steps the clamped scalar makes
unnecessary, R's decompression in verification. A 64-window signing table,
which drops four doublings, measured slower under this load, its 48 KiB
competing for the L1, and was not kept.

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

#### P-256 and P-384 without AVX-512, 2026-10-14

The P-256 and P-384 rows of the table above, and the last run's, predate
this. What changed is in CHANGELOG.md (Unreleased, Performance): the field
corrections by `cmov`, the doubling's fused operations on P-256 too, the
formulas' operations reordered, the multiplications on one buffer with the
doublings in place, P-384's window affine, and the inversions' divsteps in
packed rounds of assembly.

Profiled first, with `--cfg ic_no_avx512`. A P-384 ECDH here was 385
doublings, about 65 percent of it, 77 additions, 25, then the window, the
inversion and the reads. Graviola's own kernels, called directly from a
copy of 0.4.1 patched to export them (outside the repository, for
measurement only), against these in one process, the two alternated in
batches: the field multiplication and squaring level (0.92 to 1.03 of
Graviola's rate), the doubling 0.91 and the addition 0.86. The same
instructions, near enough -- 36 `MULX` and the same two-`MULX` reduction per
word in each multiplication, about 2,400 instructions in a doubling here
against 2,320 -- and two doublings interleaved operation by operation ran
no faster than one after the other: the core was at its throughput, not
waiting on a chain. Graviola's corrections end in `cmov`, here in a second
carry chain, and its doubling interleaves independent operations where this
one ran them in `point.rs`'s order. After the change the doubling in place
measured 1.03 to 1.05 of Graviola's, the addition 0.96, the field inversion
1.55 us against 2.2 (Graviola's is 1.05). The inversion's packing was tried
first in Rust, its decisions still masks: no faster; the time per step was
the chain from `g`'s parity through its mask, and `cmov` shortens it. Two
things tried and not kept: the field multiplication and squaring as
subroutines called from the formulas, to shrink the formulas' code (the
addition is about 4,700 instructions) -- no faster; and P-384's window
built affine on P-256 too, estimated even from the measured costs and not
tried.

Measured with `cargo run --release -- graviola-p384` (four rounds) and
`graviola` (three rounds), the build before (master 329477b) and after
alternated within each round, each in two layouts: as built, and with
`-C llvm-args=-align-all-functions=6`, which moves every function and
nothing else. Both libraries' times moved with the layout -- Graviola's
P-256 ECDH from 26 to 42 us between two binaries in an earlier probe that
differed only in IronCrypto's code -- so a change is read only where it
holds in both. The machine was loaded by other work throughout (P-384 ECDH
from 74 to 250 us); each cell is IronCrypto's rate over Graviola's within
one run, the range across rounds:

| `--cfg ic_no_avx512` | layout A, before | layout A, after | layout B, before | layout B, after |
|---|---|---|---|---|
| P-384 ECDH, Graviola's key parsed once (`graviola-p384`) | 0.84-0.90 | 1.00-1.04 | 0.91-1.04 | 1.16-1.25 |
| P-384 ECDH, Graviola's key parsed once (`graviola`) | 0.79-1.30 | 1.08-1.18 | 0.81-0.90 | 1.16-1.31 |
| P-384 ECDH, both from key bytes (`graviola-p384`) | 0.93-1.05 | 1.07-1.09 | 0.96-1.09 | 1.20-1.21 |
| P-384 ECDH, both from key bytes (`graviola`) | 0.85-1.49 | 1.14-1.26 | 0.90-0.93 | 1.20-1.24 |
| P-384 ECDH, key prepared | 2.08-2.28 | 2.30-2.43 | 2.35-2.63 | 2.60-2.86 |
| ECDSA P-384 sign | 1.77-2.37 | 2.34-2.36 | 2.33-2.65 | 2.70-3.71 |
| P-256 ECDH, Graviola's key parsed once | 0.97-1.05 | 1.05-1.22 | 0.94-0.99 | 1.20-1.23 |
| P-256 ECDH, both from key bytes | 1.00-1.12 | 1.11-1.29 | 0.98-1.00 | 1.27-1.32 |
| P-256 ECDH, key prepared | 2.46-2.58 | 2.39-2.74 | 2.37-2.60 | 2.46-2.63 |
| ECDSA P-256 sign | 0.98-1.08 | 1.11-1.13 | 0.96-1.04 | 1.10-1.15 |
| ECDSA P-256 verify | 1.14-1.49 | 1.03-1.19 | 1.00-1.13 | 1.05-1.19 |

| default build (IFMA) | layout A, before | layout A, after | layout B, before | layout B, after |
|---|---|---|---|---|
| P-384 ECDH, key parsed once (`graviola`) | 1.42-1.44 | 1.47-1.49 | 1.26-1.31 | 1.25-1.28 |
| P-384 ECDH, both from key bytes (`graviola`) | 1.48-1.49 | 1.53-1.58 | 1.32-1.39 | 1.29-1.33 |
| P-256 ECDH, key parsed once | 1.20-1.23 | 1.21-1.34 | 1.18-1.19 | 1.22-1.28 |
| ECDSA P-256 sign | 1.22-1.25 | 1.28-1.34 | 1.16-1.27 | 1.24-1.26 |
| ECDSA P-256 verify | 1.51-1.53 | 1.17-1.19 | 1.12-1.31 | 1.18-1.19 |

Read them with care. P-384 ECDH against Graviola's key parsed once is
ahead in both layouts after, and by little in layout A: 1.00 to 1.04 in
`graviola-p384`'s rounds, which time the two libraries one after the
other, 1.08 to 1.18 in `graviola`'s. Its gain is not the layout: IronCrypto's
own time fell from 85.4-125.7 us to 73.6-106.1 in layout A and from
85.9-124.5 to 73.9-106.7 in layout B, Graviola's being the same binaries'
in both. The default build's rows are the IFMA path, which this does not
change; its P-256 verification row before, in layout A, is Graviola's
slow layout (its verify took 39 to 42 us there, against 29 to 30 in every
other build) and IronCrypto's own time did not move (25.9-27.8 us to
24.6-33.5). P-521, which none of this touches, signed and verified in the
same times before and after (`stack ec`, three rounds: 199-216 and
559-591 us either way).

#### ECDSA verification, the joint chain, 2026-10-14

Profiled first under `--cfg ic_no_avx512` (`where_verification_spends_its_time`
in `crates/ic-ec/src/nist/ecdsa.rs`, loaded Zen 5). A P-256 verification was
26.5 us: `u2*Q` 21.3 of it (256 doublings at about 57 ns, 43 Jacobian
additions at about 105, and `Q`'s eight-entry window), `u1*G` 3.4 (43 mixed
additions from the signing table), `s^-1` 0.8, and the digest, the key's
decoding and the final comparison under 0.2 together; the comparison was
already `X = r Z^2` without an inversion. P-384 was 111.6 us, 13.0 of it
`s^-1`, by Fermat in the generic scalar ring. Graviola 0.4.1's verification
is the same shape as this one was: `u1*G` from a width-7 table of 37 mixed
additions, `u2*Q` by a fixed width-5 window with 51 Jacobian additions over a
window built when the key is parsed (outside the timed loop in `bench`),
one addition joining them, and three field inversions and a generic modular
inverse.

The two halves now share one chain of doublings. `u2` is recoded to a
width-5 non-adjacent form against `Q, 3Q, .., 15Q` made affine with one
inversion; `u1` to a width-8 form against `G, 3G, .., 127G`, affine, built
once into a `static` (4 KiB on P-256). On P-256 that is 256 doublings and
about 72 mixed additions, against 256 doublings, 43 Jacobian and 43 mixed
additions before. On MULX/ADX the chain runs on the generated formulas over
one buffer with the doubling in place (`nist::verify_x86`). The recoding
had cost 1.1 us for the two forms and now costs 0.12, and P-384 inverts `s`
by divsteps, 1.7 us. After: P-256 21.5-23.4 us, P-384 79.7-81.1, in the
same profile. All of it is variable time and reachable only from
verification; CHANGELOG.md has the tests and the four mutations they catch.

Measured with the bench binaries of master dc22f6b and this change
alternated, `graviola` and `graviola-p384`, four rounds each (ten for
P-384 under `ic_no_avx512`), in layout A (as built) and layout B
(`-C llvm-args=-align-all-functions=6`), the machine loaded by other work.
IronCrypto's rate over Graviola's within each run, the range across rounds:

| | layout A, before | layout A, after | layout B, before | layout B, after |
|---|---|---|---|---|
| P-256 verify, `ic_no_avx512` | 1.08-1.19 | 1.36-1.41 | 1.18-1.24 | 1.39-1.49 |
| P-256 verify, default | 1.19-1.71 | 1.24-1.56 | 1.10-1.35 | 1.25-1.43 |
| P-384 verify, `ic_no_avx512` (`graviola-p384`) | 1.45-1.54 | 1.46-2.30 | 1.35-1.52 | 1.90-2.53 |
| P-384 verify, default (`graviola-p384`) | 1.44-1.61 | 2.12-2.32 | 1.37-1.57 | 1.94-2.00 |

So P-256 verification without AVX-512, level before (0.98 to 1.08 in the
earlier rounds above), is now ahead in both layouts. The default build's
P-256 spread is Graviola's, whose verification took 31 to 47 us across
these binaries while IronCrypto's took 25.2-28.8 before and 21.7-25.3
after. The low end of P-384 under layout A, 1.46, is one round of ten;
the other nine read 1.65 to 2.30. Signing and ECDH, which the
change does not touch, stayed level by their ratios in both layouts;
IronCrypto's own P-384 signing time read 3 to 5 percent higher in the new
binaries, with its ratio unchanged, which these runs do not separate from
layout.

#### Ed25519 signing without AVX-512, 2026-10-14

Profiled first with `--cfg ic_no_avx512` (`where_signing_spends_its_time`
in `ic-ec/src/ed25519/fast.rs`, loaded Zen 5): a signature was 4.6 us, of
which the basepoint multiplication 3.2 (64 additions 2.4, the 64
eight-entry table reads 0.53, the four doublings and final addition about
0.27), the compression's inversion 0.7, two SHA-512 hashes with their
reductions 0.54 (the reductions 0.08 each), and `S = k a + r` 0.10.
Graviola's `edwards25519_scalarmulbase` takes 63 additions and no doublings
against a 48 KiB table, at about the same cost per addition and read as
here; the gap was the doublings and the scalar arithmetic, and the read and
the addition summing exactly when timed apart: the read of the next window
was outside the out-of-order window, behind a 1400-instruction addition.

Two changes (CHANGELOG.md, Unreleased). The read of the next window moved
inside the addition's assembly block, in `ymm` registers on AVX2, which hid
most of it; that made sixteen-entry windows affordable, so the digits are
now signed radix 32: 26 steps of two additions instead of 32, against 39 KiB
of tables. A variant with separate windows for the odd digits (no
doublings, twice the reads, 48 KiB at radix 16) measured 1-2% faster than
radix 16 with doublings, and radix 32 1.20 times faster, so radix 32 with
five doublings was kept. And the scalar arithmetic modulo L runs on 64-bit
limbs by Barrett's method on x86-64: 80 to 13 ns per reduction, 100 to 21
ns for `S`.

`graviola-25519`, base (master) and new binaries alternated, three rounds (five for the default build's Ed25519 rows),
on a machine other jobs held at full load; IronCrypto's rate over
Graviola's within each run, range across rounds:

| operation | AVX2 only, before | AVX2 only, after | default, before | default, after |
|---|---|---|---|---|
| Ed25519 sign | 0.90-0.91 | 1.07-1.10 | 1.22-1.33 | 1.31-1.41 |
| X25519 | 0.99-1.05 | 0.95-1.04 | 1.46-1.48 | 1.47-1.50 |
| Ed25519 verify, one-shot | 1.03-1.05 | 1.01-1.06 | 1.38-1.42 | 1.40-1.43 |
| Ed25519 verify, key held | 1.15-1.18 | 1.15-1.19 | 1.57-1.68 | 1.44-1.69 |

Ahead without AVX-512 now, by less than a tenth: "clearly" applies only in
that every round of the new build was ahead and every round of the old one
behind. The default build signs on IFMA, unchanged, and gains the scalar
arithmetic. X25519 and verification did not change; their spread is the
load (the key-held verification's 1.44 is one round, its others 1.60-1.69).
The full `graviola` run, two rounds per build and configuration, was too
noisy to add to this (its controls moved by more than these effects: P-256
ECDH with a prepared key read 2.3 and 12.2 in consecutive rounds); its
Ed25519 signing rows read 0.88-0.89 before and 0.96-1.04 after with the
cfg, and 1.15-1.29 before and 1.18-1.31 after without.

What remains in a signature without AVX-512 is the 51 additions (2.3 us),
the inversion (0.7), the two hashes (0.35) and the five doublings (0.25).

#### X25519 without AVX-512, 2026-10-14

Profiled first (`where_x25519_spends_its_time`, `--cfg ic_no_avx512`):
251 ladder steps took 12.4 us, 49 ns a step, the inversion 0.7. Graviola's
whole X25519 took 12.9 us in the same minutes, so its step is near 46.5 ns.
Counted, Graviola's loop body executes more instructions than this one's
(about 910 against 870), on the same multiplication; what differed was
around it. s2n-bignum's ladder is one loop inside one function, and its two
cross products `dm * sn` and `sm * dn` are left at five limbs and reduced
once, in their sum and difference. Here each step was a call, which on
Windows pushed and popped six registers and ran four alignment NOPs, and
both products were fully reduced and then folded again by the addition.

Each idea A/B'd alone against the build without it, alternating binaries,
`graviola-25519`, 11 to 21 rounds per comparison, both layouts (as built,
and `-C llvm-args=-align-all-functions=6`); IronCrypto's rate over
Graviola's, median and interquartile range:

| change | as built | aligned | kept |
|---|---|---|---|
| step inlined into the loop | 0.985 to 1.002 | 0.983 to 1.005 | yes |
| products at five limbs, one fold in their sum and difference | 0.983 (0.981-0.984) to 0.993 (0.990-0.993) | 0.982 (0.980-0.985) to 0.993 (0.993-0.995) | yes |
| squaring: three cross products without additions | 0.998 to 1.002 | 0.998 to 1.003 | no |
| one-fold additions' carry by `CMOV` | 0.998 to 1.002 | 0.998 to 1.003 | no |
| `121666 e + dd`: one `SHLD` fold, or the second fold by `CMOV` | 1.004 to 1.002-1.006 | 1.002 to 1.004-1.010 | no |

The last three moved less than the rounds' spread (min to max) in one layout
or both, and were dropped. The pointer select for the swap was not tried: it
makes the address the squarings read from depend on the secret bit, which
the constant-time rules here do not allow.

The kept pair, the build before and after alternated, eleven rounds:

| configuration | before | after |
|---|---|---|
| AVX2 only, as built | 0.964-0.966 | 0.992-0.994 |
| AVX2 only, aligned | 0.963-0.966 | 0.989-0.994 |
| default (IFMA), as built | 1.142-1.148 | 1.145-1.149 |
| default (IFMA), aligned | 1.143-1.147 | 1.144-1.147 |

Level with Graviola without AVX-512, as before, now within 1 percent of it
rather than 3 to 4. The default build runs X25519 on IFMA and did not
change.

#### RSA, after the MULX/ADX rewrite

`RUSTFLAGS="--cfg ic_no_avx512" cargo run --release -- graviola-rsa`, which
runs PKCS#1 v1.5 with SHA-256 at 2048, 3072 and 4096 bits on one key loaded
into both libraries. Master's binary and the rewritten backend's alternated,
three rounds, on a Zen 5 that other jobs held near full load; each cell is
IronCrypto's rate over Graviola's within a run, as the range across rounds
(CHANGELOG.md has the design and the instruction counts):

| operation | master | MULX/ADX rewritten |
|---|---|---|
| RSA-2048 sign | 0.56-0.69 | 1.08-1.28 |
| RSA-2048 verify | 0.67-0.69 | 1.04-1.42 |
| RSA-3072 sign | 1.61-1.84 | 2.45-3.03 |
| RSA-3072 verify | 1.70-1.92 | 2.79-3.49 |
| RSA-4096 sign | 0.65-0.71 | 1.02-1.11 |
| RSA-4096 verify | 1.68-2.00 | 2.59-3.45 |

RSA-4096 signing is level, not ahead: earlier rounds on the branch read
0.95 to 1.07. Its primes are 32 words, where Graviola squares with one
level of Karatsuba (`bignum_ksqr_32_64`, 408 `mulx` against 528 here). At
16 words, RSA-2048's primes, both libraries square with 136 `mulx` and
reduce the same way; the lead there comes from fewer instructions around
them. At 3072 bits Graviola has no kernel specialised to 24-word primes.
Verification at 2048 bits leads by less than signing, 1.04 at the low
end, and is the row closest to parity after 4096-bit signing. The next
section is what changed that.

#### RSA, with Karatsuba at 32 words and a five-bit window

Four changes (CHANGELOG.md, Unreleased, has each): Karatsuba for the
32-word product and square, as Graviola has; a five-bit window from 16
words up (on x86-64 with `std`); the exponentiation's table read on AVX2, entry by entry; and
every assembly block of the backend aligned to 64 bytes, after two builds
of the same source ran the 1024-bit product at 138 and 343 ns.
`RUSTFLAGS="--cfg ic_no_avx512" cargo run --release -- graviola-rsa`, the
build before and this one alternated, three rounds, each run pinned to one
core at high priority on the same Zen 5, with other jobs running; each
cell is IronCrypto's rate over Graviola's within a run, the range across
rounds:

| operation | before | after |
|---|---|---|
| RSA-2048 sign | 1.11-1.12 | 1.12-1.14 |
| RSA-2048 verify | 1.11 | 1.14 |
| RSA-3072 sign | 2.38-2.41 | 2.49-2.51 |
| RSA-3072 verify | 2.99-3.00 | 2.99-3.02 |
| RSA-4096 sign | 1.01 | 1.08-1.09 |
| RSA-4096 verify | 2.90-3.19 | 3.16-3.19 |

The "before" column is higher at 2048 bits and narrower everywhere than
the table above: pinning the runs took out most of the spread. RSA-4096
signing now leads, by 8 to 9%: IronCrypto's own time went from 2118-2132
us to 1973-1992 us. Karatsuba alone gave about 3% of that. At 32 words a
square takes about 1600 TSC ticks, of which the reduction, unchanged and the
same shape as Graviola's (`bignum_emontredc_8n`), takes about 1040; the
steps here run about one `mulx` a tick, bound by their carry chains, and
Karatsuba's additions and its three diagonals take back much of what its
120 fewer `mulx` save. The five-bit window and the AVX2 read gave the rest.
Graviola uses a four-bit window and reads its table with
`bignum_copy_row_from_table`.

The default build, with AVX-512 IFMA, runs RSA-4096's primes as a whole
IFMA exponentiation and is unchanged: 1.77-1.78 in both columns, and its
2048- and 3072-bit rows as before.

Graviola's own paths are the same in both columns -- except AES-GCM's.
Graviola 0.4.1 has an AES-GCM path on VAES and AVX-512 that it takes for
messages of 256 bytes and more when the CPU has AVX-512F, BW and VL, so in
the two AES-GCM rows above at 1 KiB and 4 MiB it ran that path in both
columns: the AVX2 column set IronCrypto without AVX-512 against Graviola
with it, which is not what a CPU without AVX-512 runs. The next section
corrects those rows. The AVX2 column is a Zen 5 with AVX-512 switched off,
not an older CPU; frequency and cache are the same as in the default column.

### AES-GCM without AVX-512

Two changes, and a corrected comparison. The 128- and 256-bit AES-GCM
kernels were rewritten as assembly with a cheaper GHASH reduction, and the
512-bit kernel took the same reduction (CHANGELOG.md, Unreleased). And
`--cfg ic_no_vaes` was added, which switches off VAES as well, so that the
eight-block AES-NI kernel -- what Skylake or Zen 2 runs -- can be measured
on this machine as the default.

On Graviola's side, its switch for the AVX-512 path,
`GRAVIOLA_CPU_DISABLE_avx512f`, is read only in its debug builds, and there
on every call, which swamps the short rows. So the like-for-like rows use a
local copy of Graviola 0.4.1 in which `HaveAvx512ForAesGcm::check` returns
`None`, patched in for those builds only:

```text
cd bench
RUSTFLAGS="--cfg ic_no_avx512" cargo run --release \
  --config "patch.crates-io.graviola.path='<copy>'" -- graviola-gcm
RUSTFLAGS="--cfg ic_no_avx512 --cfg ic_no_vaes" cargo run --release \
  --config "patch.crates-io.graviola.path='<copy>'" -- graviola-gcm
```

`graviola-gcm` runs the three AES-256-GCM sealing rows alone, best of 15.
Four rounds on 2026-10-13, the build before this change (`base`) and after
it run alternately in each configuration, Graviola in every run; the
machine was loaded by other jobs throughout. IronCrypto's rate over
Graviola's within each run, range across rounds:

| configuration | Graviola runs | 4 MiB | 1 KiB | 64 B |
|---|---|---|---|---|
| default (512-bit kernel), before | its AVX-512 path | 1.28-1.38 | 1.08-1.10 | 1.29-1.36 |
| default, after | its AVX-512 path | 1.42-1.53 | 1.45-1.59 | 2.12-2.29 |
| VAES-256 (`ic_no_avx512`), before | its AES-NI path | 1.55-1.97 | 1.24-1.40 | 1.17-1.22 |
| VAES-256, after | its AES-NI path | 1.99-2.28 | 1.91-2.08 | 1.98-2.02 |
| AES-NI (`ic_no_avx512 ic_no_vaes`), before | its AES-NI path | 0.80-0.84 | 0.74-0.84 | 1.09-1.24 |
| AES-NI, after | its AES-NI path | 1.04-1.09 | 1.09-1.22 | 1.87-2.10 |
| VAES-256, before | its AVX-512 path (not like for like) | 0.68-0.74 | 0.74-0.77 | 1.36-1.44 |
| VAES-256, after | its AVX-512 path (not like for like) | 0.80-0.87 | 0.93-1.14 | 2.15-2.22 |

IronCrypto's own rate, the same rounds: the 512-bit kernel at 4 MiB went
from 17621-20953 MiB/s to 21345-23627; VAES-256 from 9270-11887 to 11494-12650; the
AES-NI kernel from 4827-5118 to 6085-6453.

Read the AES-NI row at 4 MiB as a lead, but a narrow one. A second harness,
the minimum over thousands of short alternating trials rather than the best
of fifteen long ones, which filters out moments when another process holds
the core's other thread, put it at 1.24 at 4 MiB and 1.21 at 1 KiB. The
eight-block loop is within about a quarter of what the AES unit alone
allows on this CPU -- eight blocks of AES-256 take sixty cycles at two
`AESENC` a cycle, and the loop takes some 75 to 80 -- so there is little
left to take on the kernel's side; Graviola's eight-block loop is not
stitched, and takes about a hundred.

The VAES-256 kernel against Graviola's AVX-512 path (the last two rows) is
behind at 4 MiB and level at 1 KiB: two blocks per instruction against
four, on a CPU whose 512-bit units are full width. That is the comparison
on Zen 4 and on Intel CPUs with AVX-512 -- but there IronCrypto runs its own
512-bit kernel, the default rows. A CPU without AVX-512 runs neither
library's 512-bit path.

The P-256 and P-384 rows of the AVX2 table predate their IFMA path, so the
default column there is the MULX/ADX path too; the IFMA change's own
figures, with and without `ic_no_avx512`, are above.

### Short messages, 2026-10-14

ChaCha20-Poly1305 at 64 bytes, HMAC-SHA256 at 200 and SHA-256 at 64 were
level with Graviola: 1.07-1.47, 0.93 and 1.01-1.03 above. Each was
measured first for what it pays per message (CHANGELOG.md, Unreleased, has
the breakdown): at 64 bytes ChaCha20-Poly1305 ran the portable block
function twice -- the Poly1305 key's block and the message's -- and the
26-bit Poly1305; SHA-256 and HMAC paid for the state's shuffle into and out
of SHA-NI's layout once per call rather than once per message, and for
buffers copied and wiped; and the public `Mac::mac` and `Digest::digest`
never reached the one-pass paths the implementations have. Now a two-block
AVX2 kernel gives the AEAD its Poly1305 key and keystream in one call, the
tag is computed in radix 2^64 for short inputs, SHA-256 pads into its own
buffer and compresses in one call, and HMAC-SHA256 on SHA-NI is three
calls, the outer block built from the inner digest in registers.

`graviola` and `graviola-chacha`, master's binary and this change's
alternated, five and six rounds, the machine loaded by other work;
IronCrypto's rate over Graviola's within a run, the range across rounds. The
HMAC rows rekey per call on both sides, like for like:

| operation | default, before | default, after | `ic_no_avx512`, before | after |
|---|---|---|---|---|
| ChaCha20-Poly1305 seal, 64 B | 1.48-1.51 | 2.59-2.64 | 1.34-1.51 | 2.57-2.65 |
| HMAC-SHA256, 200 B | 0.92-0.93 | 1.21-1.25 | 0.92-0.94 | 1.17-1.24 |
| SHA-256, 64 B | 0.92-1.03 | 1.35-1.37 | 1.01-1.04 | 1.36-1.37 |
| ChaCha20-Poly1305 seal, 1 KiB | 2.11-2.14 | 2.05-2.09 | 1.40-1.42 | 1.40-1.41 |
| ChaCha20-Poly1305 seal, 4 MiB | 2.80-2.84 | 2.68-2.75 | 1.32-1.66 | 1.46 |
| SHA-256, HMAC-SHA256, 4 MiB | 0.99-1.00 | 0.99-1.01 | 0.99-1.01 | 0.99-1.01 |

The long ChaCha20-Poly1305 rows of the default build read a few percent
lower after, though their code is unchanged; P-256 ECDH, which this change
does not touch, read 1.19-1.21 before and 1.44-1.50 after in the same
binaries. An rdtsc harness that runs the code in a binary of its own puts
1 KiB and 16 KiB level. Read those rows as unchanged, and the short rows as
ahead. SHA-256 and HMAC-SHA256 on long inputs stay level: both libraries
run the same SHA-NI instructions over the same blocks.

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
`power2round`, `decompose` and the hint lemma for every input; ML-KEM's
Montgomery and Barrett reductions, `fqmul`, the conditional subtraction of
`q`, `Compress_d` and `Decompress_d` for every `d` it uses (against FIPS 203's
definition, with the decryption error bound), the byte packing of a group of
eight coefficients at every width, the NTT butterfly's value and bound for one
layer, and the 32-byte selection behind implicit rejection; P-384's field and
scalar-ring addition and subtraction, the closing subtraction of its
Montgomery multiplication and the quotient-digit lemma of its loop, for every
input below the modulus; and, in the
portable field code, P-256's addition, subtraction and Montgomery reduction,
and Curve25519's addition, subtraction, carry propagation, weak reduction,
canonical encoding and the column sums its multiplication and squaring hand
to the carry pass, each over its documented input domain. The reduction and
the column sums are proved as function contracts, each piece over the proved
contracts of the pieces it calls.

Multiplication is proved in part. P-256's portable `mul` and `square` are
proved to return `a b 2^-256 mod p`, canonical, for every `a`, `b` below `p`.
The schoolbook is split: Kani proves the carries and accumulation with every
64-by-64 product replaced by an arbitrary value no larger than `(2^64 - 1)^2`,
Z3 and cvc5 prove the polynomial identities `sum a_i b_j 2^(64 (i + j)) = a b`
and its squaring form over the integers, and `reduce` is proved as before.
Two steps are argued, not machine-checked: that the linear proof, which holds
for every product in the bound, holds for the true ones (the bound itself, that
a real word product is at most `(2^64 - 1)^2`, is now a Kani harness), and the
final substitution of the product into `reduce`'s contract. P-384's portable
Montgomery multiplication, which its field and scalar ring run off x86-64, is
proved the same way, one phase of one loop iteration at a time: Kani for the
carries of each phase over arbitrary products, for the quotient digit's
low-word lemma and for the closing subtraction, Z3 and cvc5 for the
seventy-two-product identity, the telescoping of the six rows and the bound
`T < 2m`; four steps that join the pieces are argued (PROOFS.md lists them). Curve25519's columns
are proved equal to the schoolbook as the code writes it, `a_i (19 b_j)`; that
this is `a b` mod `p` rests on integer associativity, argued and not
machine-checked. The x86-64 assembly and the RSA arithmetic are tested
against the portable code over millions of random and edge values, and
against published vectors. Many of the x86-64 kernels are now also proved,
by the separate project below.

### The x86-64 assembly, through IronProof

[IronProof](https://github.com/nervosys/IronProof) proves properties of the
machine code that rustc emits for this library's `asm!` kernels. It works
on the compiled probe functions of `scripts/ct-audit` (rustc 1.99.1,
release profile, `x86_64-unknown-linux-gnu`), not on the Rust source. Each
proof is symbolic execution of the instructions, then queries to Bitwuzla
(bit vectors) and Z3 (integers). A long kernel is split into stages, and an
integer composition joins them. Its `docs/RESULTS.md` records every result
below, with its times, mutants and assumptions. The functional proofs, for
every input inside the kernel's documented contract:

- Curve25519 (`fe64`): addition, subtraction, multiplication, squaring and
  the multiplication by 121666, as their `asm!` blocks and as the whole
  probe functions; the X25519 ladder doubling block, the RFC 7748
  doubling formula with every intermediate reduced modulo p; and the whole
  ladder step block, the differential addition and the doubling of the
  point the secret swap bit selects, modulo p; and Ed25519's doubling,
  addition of a Niels point and the two conversions from the completed
  point (the `fe64::edwards` blocks `dbl`, `nadd`, `to_ext` and
  `to_proj`), each its chain of field operations modulo p.
- P-256 and P-384: Montgomery multiplication and squaring on MULX/ADX
  (`2^k out == a b mod p`, canonical), the P-384 scalar-field
  multiplication, and the Jacobian doubling, in-place doubling, addition
  and mixed addition of both curves. The point results are the formulas'
  chains of field operations, each congruent modulo p. The group law's
  exceptional cases are the caller's.
- AES-GCM at AES-256: the counter-mode and GHASH kernels at 128, 256 and
  512 bits, and the stitched seal and open, for the group counts the probes
  pass. Counter mode is checked against FIPS 197 `Cipher()`, GHASH against
  SP 800-38D multiplication.
- ChaCha20: the AVX2 two- and four-block kernels and the AVX-512
  sixteen-block group, against the RFC 8439 block function.
- Poly1305: the AVX2 `step` and `finish`.
- Keccak-f[1600]: the AVX-512 permutation of eight states.
- RSA-2048 (MULX/ADX): the 16-word schoolbook multiplication and squaring,
  the Karatsuba middle terms, the 16-word absolute difference, the final
  conditional subtraction, and the 2048-bit Montgomery reduction (one
  32-word block, and `redc_8n` over four of them, `T + O N = out 2^2048`).
- The masked table selects of RSA's exponentiation and Ed25519's signing.

The same tool also proves constant time, register hygiene and memory
safety for these kernels. That is a separate claim from the arithmetic and
belongs under "Side-channel evidence".

Where this stops, and where Graviola remains ahead:

- **Trust.** An `unsat` answer is the solver's. No proof object is checked.
  IronProof's instruction semantics, its term simplifier and its SMT emitter
  are trusted. Every rule these kernels use is compared with the CPU by a
  differential test; the rules are not derived from a formal ISA model. s2n-bignum's
  proofs are checked by HOL Light's kernel, against a formal model of the
  instructions.
- **Argued steps.** A product abstracted in a stage holds for every value
  in its range, and the real product is one of them. Unrolled loops are
  proved for the counts the probes pass, with the induction over other
  counts argued. The AES key schedule and the algebra that joins GHASH's
  aggregated sum to the one-block recurrence are outside the kernels.
- **Coverage.** Not proved: the X25519 ladder loop and field inversion,
  Ed25519's `madd`, `msub` and `nsub` blocks, the IFMA kernels (P-256,
  P-384, X25519 and RSA), RSA at 3072 and 4096 bits and the whole
  exponentiation, the
  scalar-multiplication loops, ML-KEM's and ML-DSA's AVX2 code, and every
  aarch64 path. Graviola's s2n-bignum covers the arithmetic of P-256,
  P-384, P-521, X25519 and ML-KEM to the instruction.
- **Build.** A proof is of the instructions one compiler emitted from one
  revision. Another compiler or revision gives other text and needs the
  proof run again.

What remains behind Graviola, stated plainly: the proofs here are of the
portable Rust, bounded to the stated domains, checked at the level of Rust
semantics and not of the instructions that run; P-384's multiplication is
proved only in the pieces above, with argued joins (its x86-64 Montgomery
multiplication and squaring are proved by the tool above); ML-KEM's whole NTT and inverse NTT, basemul, sampling and the AVX2 code
are tested and not proved (layer-by-layer contracts were tried and did not reach
a verdict here); and the induction over the NTT's seven layers is argued from a
proved single step. The x86-64 assembly is proved only in part, by the
separate tool above, with the trust and coverage limits it states.
Graviola's s2n-bignum covers the arithmetic of P-256, P-384, P-521, X25519
and ML-KEM to the instruction, for every input.

## Side-channel evidence

The same Valgrind harness ([CTGRIND.md](CTGRIND.md)) runs both libraries'
operations with the secrets marked undefined, after two positive controls
that must be reported. Latest run, master 5f369cc (IronCrypto's counts were rerun unchanged at 168d3ed, CTGRIND.md):

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

- `scripts/check-ct.py` disassembles the compiled code of 130 probes on
  x86-64, 51 on aarch64 (the ARMv8 AES, `PMULL` GHASH, SHA-256 and SHA-512
  backends among them) and 44 on Cortex-M0, Cortex-M4 and 32-bit RISC-V, and fails the
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
same one branch, and so does a third, `ic-rsa-4096-sign-adx`, on the 32-word
Karatsuba kernels. Valgrind does not emulate AVX-512, so it cannot reach the
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
