# P-256 ECDH host diagnostics

Two runs of the same release executable, 30 seconds apart, on an AMD Ryzen 9
9900X with rustc 1.98.1. The source base is `58f97b8`, plus the focused
benchmark added in this change. The context JSON files record the exact
benchmark-source and executable hashes, timestamps and CPU-load readings.
The saved executable preceded a subsequent lint-only change to the full
suite's AES chunk iterator; the focused ECDH source is unchanged.

Each run warms both implementations and records twenty alternating pairs of
200 agreements. Inputs and outputs are retained with `black_box`; setup
checks that the implementations agree on the shared secret. The CSV rows
preserve batch means, not individual operation durations.

| Run | IronCrypto min / median / max, us/op | p256 min / median / max, us/op | CPU before / after |
|---|---|---|---|
| 1 | 68.076 / 71.117 / 91.666 | 64.742 / 67.496 / 73.400 | 99% / 93% |
| 2 | 72.743 / 82.663 / 102.077 | 70.291 / 79.739 / 109.957 | 97% / 99% |

The observed ranges overlap and the host is heavily loaded. Treat these
results as parity within the observed noise; they do not support a speedup
or regression claim. The APIs also include different work: IronCrypto
validates the SEC1 peer per call, whereas p256 receives a pre-parsed peer.
Neither run compares a source change against itself, measures constant-time
behavior, or closes the quiet-hardware verification gap.

The [benchmark instructions](../../../bench/README.md) describe reproduction
and how to arrange a separate before/after comparison. Quiet-host repetition
and Cortex-M/RISC-V hardware measurements remain outstanding.
