# Host timing diagnostics, 2026-09-29

These runs used an AMD Ryzen 9 9900X on Windows, rustc 1.98.1, and the
workspace release profile: fat LTO, one codegen unit, overflow checks enabled.
All runs used `ic timing --iterations 100000 --json`, with randomly interleaved
input classes and the existing deliberately variable-time comparison as a
positive control. The detector reports the largest absolute Welch statistic
across the untrimmed data and its three trimming thresholds.

This was a busy developer machine, not quiet reference hardware. CPU-load
readings at the beginning and end of the runs ranged from 79% to 100%.
No Cortex-M or RISC-V board was measured. The USB serial device on COM3 was
confirmed by the maintainer not to be a development board.

## Source and artifacts

`run-1.json` is the existing nine-target suite from clean commit `397f9f2`.
`run-2.json` and `run-3.json` add only two timing targets to that base; the
cryptographic implementation is the same. Each context file records the
compiler, timestamps, source revision and load readings. The extended runs
also record SHA-256 hashes of the timing source and executable. Their timing
source hash is `B414AB7D94863A77DAC5D2A0C05B69731569720CBC9F2F465BBECD7CCE0883C3`.
This is a measured file hash, not a cryptographic test vector.

The files retain the CLI's aggregate JSON reports. They do not contain
per-sample durations, which this CLI does not export.

## Results

| Target | Samples per run | Run 1 t | Run 2 t | Run 3 t |
|---|---:|---:|---:|---:|
| Positive control, naive comparison | 100000 | 1228.16 | 1640.10 | 1565.21 |
| Constant-time comparison | 100000 | -1.32 | 2.76 | 4.57 |
| AEAD open | 100000 | -5.07 | -3.83 | -3.94 |
| P-256 scalar multiplication | 100000 | -0.92 | 1.23 | -0.44 |
| X25519 | 100000 | -1.03 | 2.29 | 0.62 |
| ML-KEM decapsulation | 20000 | 1.63 | -1.16 | 1.95 |
| AES encryption | 100000 | -0.35 | -0.99 | -0.48 |
| ECDSA signing | 20000 | 0.95 | 3.12 | 2.22 |
| RSA signing | 2000 | -1.99 | -1.02 | -1.77 |
| ML-DSA rounding batch | 100000 | not measured | 1.05 | -0.76 |
| ML-KEM compression batch | 100000 | not measured | -1.23 | 2.41 |

The existing detector uses `|t| >= 5` as suspicious and `|t| >= 10` as leaking.
Every positive control exceeded the leakage threshold. Apart from AEAD open
in run 1, every other target stayed below the suspicious threshold. The AEAD
difference is documented in `Target::known_difference`: authentication failure
zeroizes the output while success does not; the branch is on the already-public
authentication verdict. Runs 2 and 3 did not distinguish that difference.

The new targets compare 256 zero coefficients with 256 random synthetic
coefficients in `[0, q)`. Input preparation is outside the timed region.
ML-DSA retains both outputs of power2round and decompose at each gamma2;
ML-KEM retains compression results at widths 1, 4, 5, 10 and 11. The entire
output array passes through `black_box` before the timer stops. A sample is
one full batch, not an independent observation of every coefficient.

## Interpretation and remaining work

These particular input classes showed no evidence of leakage in these host
runs. The positive control demonstrates that the setup detected its deliberately
large difference, not that it would detect every smaller channel. CPU load,
timer resolution, input-class choice and iteration ceilings limit the result.
The RSA and ECDSA/ML-KEM ceilings are deliberately smaller than 100000.

Quiet reference hardware, embedded M0/M4 and RISC-V timing, and wider input
classes remain unverified. The branch/division probes in
[CONSTANT_TIME.md](../../CONSTANT_TIME.md) are complementary compiled-code
evidence. Neither set of checks proves constant time for entire algorithms.
