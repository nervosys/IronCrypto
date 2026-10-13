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

Thirty-five exported probes call the actual implementations on every target,
and five more on x86-64 (below). Their public sizes
and algorithm parameters are fixed; secret inputs remain runtime arguments.
Release optimization with fat LTO exposes the called implementation inside
each probe. Integer overflow checks are off, as in an ordinary consumer's
release profile; this is not the workspace binary's overflow-checked profile.

- ML-DSA reduction modulo q, power2round, and decompose for both gamma2 values.
- ML-KEM compression at all five widths used by its parameter sets: 1, 4, 5,
  10 and 11 bits.
- Core 8-, 32- and 64-bit selection; four-byte equality, zero checking,
  big-endian ordering, conditional copy and swap; one-byte hex encoding and
  three-byte Base64 encoding.
- P-256 field and scalar operations: reduction from bytes, addition,
  subtraction, multiplication, negation, conditional move, equality and
  parity, each from and back to bytes. Hashing to the curve, the OPRF,
  ECDH and ECDSA are built from these. All four targets gate; on the
  32-bit ones a few findings are excused by rule, as described below.
- On x86-64 only: P-256's field multiplication and squaring on
  MULX/ADCX/ADOX, and the doubling, addition and mixed addition that are
  each one block of that assembly (`ct_p256_fp_mul_adx`,
  `ct_p256_fp_square_adx`, `ct_p256_point_double_adx`,
  `ct_p256_point_add_adx`, `ct_p256_point_add_affine_adx`). The common
  P-256 probes are built without `std`, so there is no run-time detection
  and they compile to the baseline `mul`/`adc` assembly; these name the
  other sequences directly. `TARGET_SYMBOLS` in the checker requires them
  on that target.

Every expected symbol must have a complete, nonempty ELF assembly body.
Branches and integer division/remainder instructions are rejected. A call or
tail call into a function whose body is in the same assembly is followed,
and that body is held to the same rules, recursively; a finding there is
reported against the probe. A call to anything else -- a runtime-library
routine, a register -- is rejected, so an uninlined function cannot pass by
hiding its instructions outside what the checker reads. Unsupported targets, missing
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
The four-byte helper probes do not cover all buffer lengths or loop forms.

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
original thirteen probes have no forbidden instructions on any of the four targets.
Numerical correctness is checked independently by the existing exhaustive
comparisons and published vectors. This is evidence for the tested build,
not a guarantee about future compilers or all call contexts.

Both fixes were deliberately broken by removing the input barrier while
keeping the output barrier. The gate failed on the ML-DSA decomposition probes
and the ML-KEM compression probes, respectively. Both files were restored and
all four targets passed again. Parser tests independently check conditional
branches, division, calls, missing symbols and incomplete function bodies.

## Core mask regression

On 2026-09-30 six additional probes exercised core helpers. The Cortex-M0
build branched on the flag while constructing `Choice::mask` in byte
selection, four-byte conditional copy and four-byte conditional swap. The
existing barrier followed negation, so it could not prevent the optimizer
from branching before the barrier. An input barrier before negation fixes
these tested paths; the output barrier remains.

Removing the input barrier deliberately reproduced all three forbidden
branches. Restoring it passed all nineteen probes on all four targets.
The functional test checks masks, byte selection and four-byte copy/swap for
all 256 flag inputs, including noncanonical nonzero values. This adds
compiler regression coverage, not hardware timing evidence or a guarantee
for all buffer sizes and callers.

## P-256 field and scalar, 2026-10-12

Sixteen probes were added for the P-256 field and scalar operations, which
hashing to the curve (RFC 9380) and the OPRF (RFC 9497) apply to values
derived from a password or a server key. The checker learned to follow calls
into bodies in the same file, since LLVM left `from_bytes_reduced` and
`from_mont` uninlined and the old rule rejected every call outright.

On x86-64 the one remaining finding was a branch in `from_be_bytes`: a byte
loop, its count fixed at 32. It was rewritten to read whole 8-byte words, as
`to_be_bytes` now writes them, and every P-256 probe has no forbidden
instruction on x86-64, where they gate. The byte form of `to_be_bytes` also
shifted a u64 by a variable amount, which 32-bit RISC-V compiles to a branch
on whether it reaches 32: an index, not a secret, but now gone.

On the three 32-bit targets the P-256 probes leave findings the checker
would reject. Each was read on 2026-10-12, with rustc 1.99.0:

- Cortex-M4: one `bne.w` per function, after `subs r1, #1` on a counter
  spilled to the stack: the Montgomery multiplication's word loop.
- RISC-V: one `bne` per function, comparing a pointer with a fixed stack
  address, the same loop; and a `memset` of a constant 40 bytes.
- Cortex-M0: `beq`/`b` after `cmp r1, #32` on a counter stepping by 8, the
  same loop; and `__aeabi_lmul`, the runtime library's 64-bit multiply,
  which M0 needs for every 32x32 product.

None branches on a field element.

### How they gate, 2026-10-12

They were first left ungated, because a text check cannot tell a loop
counter from a secret and allowing a branch count would be the blanket
allowance this gate exists to refuse. They gate now, on all three targets,
without one:

- **`__aeabi_lmul` is read, not trusted.** The checker disassembles it from
  the toolchain's own `compiler_builtins` for Cortex-M0, with `llvm-objdump`
  from `rustup component add llvm-tools`, and holds that body to the same
  rules as a probe. In rustc 1.99.0 it is straight-line `muls`, `adds` and
  `adcs`. A routine is followed this way only where `VERIFIED_EXTERNAL`
  names it for that target, and without the tools the check fails rather
  than skips. Its timing is then the multiplier's, which on Cortex-M0 is fixed
  per implementation, not per operand; that last step is a statement about
  the core, not something the gate checked.
- **The rest is excused by rule, not by text.** Each rule is about the
  instructions around the finding: a conditional branch whose flags come from
  `subs rN, #imm`, or from `cmp rN, #imm` directly after `adds rN, #imm` on
  the same register (a counter stepped by a constant); an unconditional jump
  to a local label; on RISC-V, a branch against a bound computed as `sp` plus
  a constant, and a `memset` whose length is loaded as a constant into a
  destination on the stack. `cmp r0, #0; bne`, `subs r0, r0, r1; bne`, a
  branch between two registers, or a `memset` of a computed length matches
  none of them. Rules apply only to the P-256 probes, only on the target
  each was reviewed for.
- **Each rule has a ceiling**, the number of findings it excused when they
  were read (`EXCUSE_CEILINGS`, counted per probe, so a loop in a shared
  `from_mont` counts once for each probe that reaches it). A rule that excuses
  more fails the gate: a new loop that resembles the old ones is read before
  it is accepted, not after.

Turning `select_ct` into a branch on its mask failed every target: 32
findings on x86-64, 303 on Cortex-M0, which also exceeded its jump ceiling,
48 on Cortex-M4 and 52 on RISC-V. It was restored and all four pass.

A counter rule is a pattern, not a proof that the register is a counter:
`subs rN, #1; bne` on a secret-derived `rN` would match it. What closes that
is the ceiling, which means any such branch has to arrive as part of a change
that someone then reads, and the review recorded above.

Not probed: BLAKE2s and BLAKE3, whose round loops stay rolled on some
targets. Both are additions, rotations and XORs with no table and no
secret-dependent branch, by construction. Not probed because they are not
constant time by design: bcrypt, scrypt and yescrypt read memory at
password-derived indices, as the ontology records.

The `ic timing` targets `hash-to-curve` (a fixed versus a random password),
`oprf-evaluate` (two server keys), `blake2s-keyed` and `blake3-keyed` (a
fixed versus a random key) were added and run on 2026-10-12 on a development
machine that was not quiet: |t| was 1.79, 0.91, 3.11 and 3.19, against 1686
for the positive control in the same session. That is no evidence of
leakage on that machine, not a proof of its absence.

## P-256 on x86-64 in assembly, 2026-10-13

P-256's coordinate field now runs on x86-64 in inline assembly
(`crates/ic-ec/src/nist/p256_x86.rs`): `mul`/`adc`/`cmovc` on every CPU, and
`mulx`/`adcx`/`adox` where the CPU has BMI2 and ADX, chosen once per process.
Doubling, addition and mixed addition are each one `asm!` block of those
operations, generated by `scripts/gen_p256_x86_point.py` into
`p256_x86_point.rs`. `ic-ec` therefore denies `unsafe` rather than forbidding
it, and allows it in those two modules only.

What the gate reads: the common `ct_p256_fp_*` probes compile, on x86-64
without `std`, to the baseline sequences; the five x86-64-only probes name the
MULX/ADX field operations and the three point formulas. All forty pass with
no finding, rustc 1.99.0. In assembly the final reduction is a `cmovc` on the
borrow, which the compiler emits as written and cannot turn into a branch, so
the barrier `select_ct` needs in Rust has no counterpart to lose there.

What it does not read, and why: everything with a loop, since the gate
rejects every branch and these loops' counts are public constants.

- Table scans: the generator table (32 affine entries per window on P-256)
  and the variable-base window (16 Jacobian entries) are read in full every
  time, OR-ing each entry under a mask that is all ones for the wanted entry
  and zero otherwise. The masks are computed for the whole scan and put
  behind one `black_box`; on x86-64 the P-256 scans are SSE2, and AVX2 for
  the generator table where the CPU has it.
- Inversion: on 64-bit targets P-256's two residue rings invert by
  Bernstein-Yang divsteps (`nist/safegcd.rs`, libsecp256k1's `modinv64`
  transcribed): 590 divsteps for every input, each branch-free, its two
  decisions as masks behind `black_box`, as libsecp256k1 puts them behind
  `volatile`. Elsewhere, and for P-384 and P-521, inversion and square roots
  are a fixed four-bit-window exponentiation whose table is read by masked
  scan: no branch on the exponent at all, where square-and-multiply branched
  on each of its bits, which Valgrind reported in the nonce inversion (see
  `docs/CTGRIND.md`).

Those are covered dynamically instead: `scripts/ctgrind.sh` on P-256 ECDH,
P-256 and P-384 signing reports 3, 7 and 7, against 3, 8 and 7 before, and
every report left is one of the allowed declassifications: the private key's
and the RFC 6979 candidate's range and zero checks, the identity check on
`kG` and on the shared point, and `r = 0` and `s = 0`. Valgrind does not
report ADX in CPUID, so under it the baseline field sequence runs; the
MULX/ADX sequences are the ones the probes above read.

Two additions in the scalar multiplications are no longer complete, by
argument rather than by formula: in the variable-base loop every addition but
the last, and in the generator table every addition below the top of the
order. The arguments are in `Point::mul_scalar` and `gentable::mul`; the
tests run the scalars at both edges of the range, `1..40` and `n-40..n-1`,
where the last, complete addition is the one that matters.
