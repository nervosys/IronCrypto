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
| Speed, x86-64 | AES-GCM (at every size, also without AVX-512, narrowly at 4 MiB on AES-NI alone), ChaCha20-Poly1305 (at 1 KiB and 4 MiB, not at 64 bytes), X25519 (with AVX-512), Ed25519 (with AVX-512; without it, signing narrowly, 1.07-1.10), ML-KEM encapsulation from key bytes and with the key parsed once, ML-KEM decapsulation with the key parsed once, P-256 and P-384 ECDH with a prepared key, P-256 and P-384 ECDH from key bytes (with AVX-512), ECDSA P-256 sign (with AVX-512), RSA (also without AVX-512 at 2048 and 3072 bits; level at 4096-bit signing), ECDSA P-256 verify, ECDSA P-384, SHA-512 | SHA-256, SHA3-256, HMAC-SHA256, ML-KEM key generation | without AVX-512, P-384 ECDH against Graviola's key parsed once trails, and X25519, P-256 ECDH, P-256 signing and P-256 verify are level (see "Without AVX-512") |
| Speed, aarch64 | | | unmeasured. AES, SHA-256, SHA-512 and GHASH have ARMv8 backends behind the off-by-default `aarch64-crypto` feature, run under QEMU only and read by the compiled-code gate, never on hardware; everything else is portable |
| Proved arithmetic | | | Graviola: s2n-bignum's routines are proved to the instruction in HOL Light; here, bounded proofs of the constant-time helpers, ML-DSA's rounding, the portable field additions, carries and reductions of P-256 and Curve25519, P-256's portable field multiplication and squaring, end to end except for two argued steps, and Curve25519's multiplication column sums; the x86-64 assembly is not proved |
| Side-channel evidence | compiled-code gate on five targets, aarch64's ARMv8 backends among them; Valgrind clean on ML-KEM decapsulation | Valgrind, every operation both libraries offer and the harness drives | RSA's MULX/ADX path is checked under Valgrind and by the compiled-code gate; its IFMA exponentiation, as a whole at 1024 and 2048 bits, by the gate alone |
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
- **P-384 and P-256 ECDH from key bytes without AVX-512 IFMA** are level
  or behind. Under `--cfg ic_no_avx512`, in the IFMA change's A/B, P-384
  ran at 0.92 to 1.11 of Graviola's rate with both parsing the key per
  call and 0.85 to 0.92 against Graviola's key parsed once; P-256 at 1.09
  to 1.11 and 1.00 to 1.05. With IFMA both lead (above). With the key
  prepared on both sides they lead either way: 1.68 to 2.20 times on P-384
  and 2.43 to 2.56 on P-256 without IFMA. That lead is bought differently
  from Graviola's table, and is not like for like in memory or set-up:
  Graviola's parsed key holds sixteen Jacobian multiples and costs about 4
  us to build; the prepared key here holds sixty-four affine multiples, at
  four spacings across the scalar, so that an agreement needs a quarter of
  the doublings, and costs about one agreement (100 to 121 us) to build. It
  pays from the second agreement with the same key. Where the key is used
  once, the from-bytes row is the one to read, and without IFMA there the
  two are level: most of either's time is the same 385 doublings and 77
  additions, and doublings alone measured about 70 percent of this
  library's. IFMA leads by running four of a doubling's multiplications at
  once. An affine window with mixed additions inside the unprepared
  agreement was tried and measured: level on P-256 and P-384, slower on
  P-521, where the inversion costs more than the additions save, so it was
  not kept. P-384 ECDH was 1.7 times slower
  while the field arithmetic here was generic in the modulus. All of these
  rounds ran with the machine loaded by other work; read the ratios, not
  the absolute figures.
- **ChaCha20-Poly1305 on 64-byte messages** is level, not ahead: 1.07 to
  1.47 times Graviola's rate across five rounds on a loaded machine, a
  range that includes parity. One block of keystream and four of Poly1305
  are too short for the vector kernels, so this is the portable code. On 1
  KiB and 4 MiB messages it is ahead, by 2.1 to 3.7 times, since ChaCha20
  runs sixteen blocks at a time on AVX-512 and Poly1305 four lanes on AVX2
  (CHANGELOG.md has the A/B). Before that it was 0.8 to 1.5 times
  Graviola's rate under the same load: parity, which an earlier single run
  had read as behind.
- **ECDSA P-256 signing without AVX-512 IFMA** is level: 1.02 to 1.07
  of Graviola's rate under `ic_no_avx512`, against 1.20 to 1.22 with IFMA.
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
  behind before the MULX/ADX backend was rewritten, now leads at 2048 and
  3072 bits and is level at 4096-bit signing (the RSA table below).
  P-256 and P-384 ECDH from key bytes and P-256 signing lose the lead
  IFMA gives them (bullets above).
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
| ECDSA P-256 verify | 0.98-1.01 | 1.00-1.08 |
| P-384 ECDH | 0.76-0.77 | 0.69-1.26 |
| ECDSA P-384 sign | 2.31-2.59 | 2.26-2.32 |
| ECDSA P-384 verify | 1.08-1.23 | 1.26-1.66 |
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
end, and is the row closest to parity after 4096-bit signing.

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
for every product in the bound, holds for the true ones, and the final
substitution of the product into `reduce`'s contract. Curve25519's columns
are proved equal to the schoolbook as the code writes it, `a_i (19 b_j)`; that
this is `a b` mod `p` rests on integer associativity, argued and not
machine-checked. The x86-64 assembly, which is what P-256 runs on x86-64,
and the RSA arithmetic are tested -- against the portable code over millions
of random and edge values, and against published vectors -- and not proved.

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

- `scripts/check-ct.py` disassembles the compiled code of 114 probes on
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
