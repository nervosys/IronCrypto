# Compiled-code regression checks

Run `python scripts/check-ct.py` from any directory. Install the four targets
with `rustup target add x86_64-unknown-linux-gnu thumbv6m-none-eabi
thumbv7em-none-eabihf riscv32imac-unknown-none-elf` first. A missing target is an
error. `--target <target>` checks one target. Python uses only its standard
library; the isolated harness depends only on this repository's crates.

The full local gate (`scripts/check.sh`) and the `constant-time` CI job run
the same checker. `--quick` skips these cross-target builds. Compiler upgrades
are checked against these rules rather than a snapshot of instruction counts.
The latest assembly remains in `target/ct-audit/probes/<target>.s` for review.
Each run requests a fresh explicit compiler output, so old dependency-version
artifacts cannot be mistaken for the current build or require a manual clean.
Regression tests place multiple stale passing artifacts beside a current
branching output, and require the branch to be detected. They also reject a
missing current output despite a previous passing result, and propagate
compiler failure. Deliberately replacing the fresh output name with the
previous result's name failed two tests; restoring it passed all eight.

## What it checks

Thirteen exported probes call the actual implementations. Their public sizes
and algorithm parameters are fixed; secret inputs remain runtime arguments.
Release optimization with fat LTO exposes the called implementation inside
each probe. Integer overflow checks are off, as in an ordinary consumer's
release profile; this is not the workspace binary's overflow-checked profile.

- ML-DSA reduction modulo q, power2round, and decompose for both gamma2 values.
- ML-KEM compression at all five widths used by its parameter sets: 1, 4, 5,
  10 and 11 bits.
- Core 32- and 64-bit selection, one-byte hex encoding and three-byte Base64
  encoding.

Every expected symbol must have a complete, nonempty ELF assembly body.
Branches, integer division/remainder instructions, and calls or tail calls
are rejected. Rejecting calls prevents an uninlined function from passing by
hiding its instructions outside the probe. Unsupported targets, missing
symbols and missing requested assembly output fail rather than silently reducing
coverage. If a compiler merges symbols, review the output and adapt the parser;
do not remove a probe merely to make it pass.

## What it does not establish

This is a regression check on these compiled probes, not a proof of constant
time for entire algorithms. Other optimization profiles, callers, compiler
versions and CPUs can generate different code. ARM predicated instructions are
not branches and are permitted. The checker does not establish their timing,
track secret-dependent memory addresses, or measure instruction latency.
Encoding probes do not automatically detect a return to lookup tables.

Decoding, KWP authentication, coefficient sampling, signing rejection loops,
curve/RSA arithmetic and other functions are outside this gate. Some of their
branches are permitted because the inputs are public or because the standard
allows the rejection to be observable. Extending coverage needs explicit rules
for each such case rather than a blanket branch-count allowance.

Assembly review and statistical timing measurements remain necessary. No M0,
M4 or RISC-V hardware timing measurements were performed for this change.

Subsequent [host diagnostics](timing/2026-09-29-host/README.md) exercised the
existing timing suite and added batched ML-DSA rounding and ML-KEM compression
targets. Their positive controls worked and the kernel targets stayed below
the suspicious threshold in two runs. CPU load was 79–100%, so these results
do not close the quiet-hardware or embedded-timing gaps.

## The first regression found

On 2026-09-29, rustc 1.98.1 with LTO emitted seventeen conditional branches
across the Cortex-M0 probes for ML-KEM compression and ML-DSA reduction and
decomposition. Their source masks were turned back into conditional choices.
The gate rejected that output before the fixes were made.

The affected operations now hide the operand's range before sign extraction
and the mask's range afterwards with `core::hint::black_box`. An output-only
barrier was tried and still branched while constructing the mask. The final
thirteen probes have no forbidden instructions on any of the four targets.
Numerical correctness is checked independently by the existing exhaustive
comparisons and published vectors. This is evidence for the tested build,
not a guarantee about future compilers or all call contexts.

Both fixes were deliberately broken by removing the input barrier while
keeping the output barrier. The gate failed on the ML-DSA decomposition probes
and the ML-KEM compression probes, respectively. Both files were restored and
all four targets passed again. Parser tests independently check conditional
branches, division, calls, missing symbols and incomplete function bodies.
