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

Forty-four exported probes call the actual implementations on every target, and twenty-eight more on x86-64. Their public sizes
and algorithm parameters are fixed; secret inputs remain runtime arguments.
Release optimization with fat LTO exposes the called implementation inside
each probe. Integer overflow checks are off, as in an ordinary consumer's
release profile; this is not the workspace binary's overflow-checked profile.

- ML-DSA reduction modulo q, power2round, and decompose for both gamma2 values.
- ML-KEM compression at all five widths used by its parameter sets: 1, 4, 5,
  10 and 11 bits.
- ML-KEM's other scalar helpers that see secrets: centered binomial
  sampling a word at a time for eta 2 and 3, the twelve-bit field
  reduction modulo q, packing and unpacking eight twelve-bit fields, and
  Barrett and Montgomery reduction.
- Core 8-, 32- and 64-bit selection; four-byte equality, zero checking,
  big-endian ordering, conditional copy and swap; one-byte hex encoding and
  three-byte Base64 encoding.
- P-256 field and scalar operations: reduction from bytes, addition,
  subtraction, multiplication, negation, conditional move, equality and
  parity, each from and back to bytes. Hashing to the curve, the OPRF,
  ECDH and ECDSA are built from these. All four targets gate; on the
  32-bit ones a few findings are excused by rule, as described below.
- Ed25519 scalar arithmetic modulo L: the reduction of a 512-bit value, which
  makes the secret nonce from a hash and finishes `S`, and `a * b + c`, which
  is `S`. Straight-line on all four targets; see "Ed25519 scalar reduction"
  below.
- On x86-64 only, the Curve25519 backends that exist only there: the
  MULX/ADX field's multiplication, squaring, addition, subtraction,
  multiplication by 121666 and divstep inversion, each from and back to
  bytes; X25519's ladder step on it; signing's group operations on it; and
  the AVX-512 IFMA four-lane ladder step, table selection, mixed addition and
  doubling. See "Curve25519 on x86-64" below.
- On x86-64 only: P-256's field multiplication and squaring on
  MULX/ADCX/ADOX, and the doubling, addition and mixed addition that are
  each one block of that assembly (`ct_p256_fp_mul_adx`,
  `ct_p256_fp_square_adx`, `ct_p256_point_double_adx`,
  `ct_p256_point_add_adx`, `ct_p256_point_add_affine_adx`). The common
  P-256 probes are built without `std`, so there is no run-time detection
  and they compile to the baseline `mul`/`adc` assembly; these name the
  other sequences directly. Likewise P-384's: the field's multiplication
  and squaring specialised to its prime, the scalar ring's multiplication,
  and the same three point formulas (`ct_p384_fp_mul_adx`,
  `ct_p384_fp_sqr_adx`, `ct_p384_fn_mul_adx`, `ct_p384_point_double_adx`,
  `ct_p384_point_add_adx`, `ct_p384_point_add_affine_adx`).
- On x86-64 only, the divsteps inversions, on the integer as the field or
  ring gives it to them: P-384's field (`ct_p384_fp_invert`) and P-256's
  field and scalar ring (`ct_p256_fp_invert`, `ct_p256_fn_invert`, the
  last the ECDSA nonce's). They exist on 64-bit targets only, and x86-64 is
  the 64-bit target the gate reads. See "P-384 specialised to its prime"
  below.
  `X86_ONLY` in the checker requires all of these on that target and no other.

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
curve arithmetic and other functions are outside this gate, and so are RSA's
Montgomery products and exponentiation (see the end of this file). Some of their
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

## ML-KEM decode regression

On 2026-10-13 seven probes were added for the ML-KEM helpers the AVX2 work
rewrote or newly relied on. The first run failed on Cortex-M0: the twelve-bit
reduction `reduce_12`, which a decapsulation key's secret vector passes
through, compiled its sign mask into a comparison and `blo`. It replaced a
`% q` that had no probe at all. The same input and output barriers as
`compress` fixed it, and all twenty-six probes then passed on all four
targets.

The AVX2 forms of these routines (`ic-mlkem/src/avx2.rs`) are outside this
gate: they exist only in `std` x86-64 builds behind runtime detection, and
their loops branch on loop counters. They are vector instructions with no
data-dependent branch or index; each is compared exactly against the scalar
form on every input the tests reach.
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

## Ed25519 scalar reduction, 2026-10-13

Valgrind (docs/CTGRIND.md) found that `scalar::conditional_subtract_l`, in
source a borrow turned into a mask, compiled under LTO on x86-64 to `js` on
the sign of the top limb's difference: a jump on whether the secret nonce or
S was at least L, nine of them per signature. No probe covered it.

`ct_ed25519_reduce_wide` and `ct_ed25519_mul_add` do now. On the unchanged
source the first run failed x86-64 with those `js` and with the loops LLVM had
left rolled -- public counts, but a rolled loop is a jump this checker cannot
tell from a secret one. The fix has two parts:

- **Barriers.** The borrow passes through `black_box` before it becomes a
  mask, and the mask through another after, as `Choice::mask` does. Removing
  just those two, with everything else below kept, fails every target: 10
  findings on x86-64, 14 on each Cortex-M, 10 on RISC-V.
- **Straight-line code.** The fold rounds, the folding positions, the carry
  passes and the unpacking are written out with literal indices; `c` enters
  `mul_add` as the product's initial value instead of through a byte-wise
  carry loop; and the result is packed into words directly instead of
  through a zeroed buffer, which on the 32-bit targets was a `memset` call.

What remains is one shape on Cortex-M0: an unconditional `b` over a literal
pool -- Thumb-1 loads 32-bit constants from memory beside the code, and the
compiler parks a pool mid-function and jumps over it to the next instruction.
The rule `literal-pool jump` excuses exactly that: a `b` to a local label
reached from the jump through nothing but `.LCPI` labels, alignment and data
directives. It applies to these two probes only, on Cortex-M0, with a ceiling
of 12, the count read on 2026-10-13 with rustc 1.99.0. `test-check-ct.py`
holds it to excusing that shape and not a jump over code, a conditional jump
over a pool, a jump to another label, or the same jump in another probe.

Valgrind on Ed25519 signing reports 9 secret-dependent branches before and 0
after. It sees the portable field only: Valgrind does not report ADX in
CPUID, so the x86-64 MULX/ADX field is not selected under it.

## Curve25519 on x86-64, 2026-10-13

X25519 and Ed25519 now run, where the CPU has the instructions, on a field
of four 64-bit limbs whose multiplication is `MULX`/`ADCX`/`ADOX` assembly
(`ic-ec/src/fe64.rs`), and where it also has AVX-512 IFMA on four field
elements at once (`ic-ec/src/f51x4.rs`). Thirteen probes cover them, on
x86-64 only because that is the only target they compile for;
`check-ct.py` requires them there (`X86_ONLY`) and nowhere else, and its
tests check both halves of that.

They are constant time by construction rather than by barrier: the field
operations and X25519's ladder step are assembly with no branch in them, the
carry folds are `sbb`/`and` masks inside it, the ladder's selection is
`CMOV`, the divstep inversion's 590 steps are one `.rept` block of masks and
`CMOV` in ten calls written out, and the IFMA code is vector instructions
selected by blends under masks. Where Rust computes a mask from a secret
bit, it goes through `fe64::mask`, a one-instruction `neg` in an assembly
block the optimiser cannot see into -- `nomem`, unlike `black_box`, whose
memory clobber cost the ladder a spill of every live value.

All thirteen pass. Replacing the masked final subtraction in the four-limb
field's reduction to bytes with an `if` on the same comparison fails every
probe that reaches it with `js` on x86-64; restored, they pass. The probes
read compiled code; whether the CPU's `MULX`, `ADCX`, `ADOX`, `CMOV` and
`VPMADD52` take the same time for all operands is a statement about the
hardware, not something the gate checked.

Not probed: the full scalar multiplications, whose loops over public counts
stay rolled; `Window::select` on the MULX/ADX field, which needs the `std`
tables the probe build does not have (its masks go through the same
`fe64::mask`); and verification, which is variable time by design on public
data. Valgrind (docs/CTGRIND.md) cannot see these backends either: it does
not report ADX or AVX-512 in CPUID, so under it the portable field runs.

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
`p256_x86_point.rs`. P-384 has the same on MULX/ADX only, with field
operations generic in the modulus (`scripts/gen_mont_x86.py` into
`mont_x86.rs`, `scripts/gen_p384_x86_point.py` into `p384_x86_point.rs`,
dispatched from `p384_x86.rs`). `ic-ec` therefore denies `unsafe` rather than
forbidding it, and allows it in those modules only.

What the gate reads: the common `ct_p256_fp_*` probes compile, on x86-64
without `std`, to the baseline sequences; the ten x86-64-only probes name the
MULX/ADX field operations and the point formulas of both curves. All
forty-five pass with no finding, rustc 1.99.0. In assembly the final reduction is a `cmovc` on the
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
  `volatile`. (Since then P-384's field inverts by divsteps too, and these
  inversions are probed; see "P-384 specialised to its prime" below.)
  Elsewhere, and for P-384 and P-521, inversion and square roots
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

## P-384 specialised to its prime, 2026-10-13

P-384's field operations on x86-64 with BMI2 and ADX are now specialised to
p = 2^384 - 2^128 - 2^96 + 2^32 - 1 (`scripts/gen_p384_x86_point.py`):
Montgomery reduction by two `mulx` per word by constants, a squaring of its
own, final corrections by masked addition in registers, and three fused
`c*a - d*b` operations in the doubling. Each is branch-free by construction:
every correction is a mask from a carry or borrow, never a `cmov` choice of
address and never a jump. `ct_p384_fp_mul_adx` now names the specialised
multiplication, and `ct_p384_fp_sqr_adx` the squaring; the point formula
probes read the regenerated blocks.

P-384's field now inverts by divsteps on 64-bit targets
(`nist/safegcd.rs`): Bernstein and Yang's own divstep, 62 to a batch,
eighteen batches, for the 1111 their Theorem 11.2 requires at 384 bits.
32-bit targets keep an addition chain of squarings and multiplications, a
fixed sequence. The steps are written out and the batches are calls rather
than loops, so the compiled inversion has no branch for the gate to excuse;
P-256's inversion was restructured the same way, and is now probed too.

The first run of `ct_p384_fp_invert` failed, and the finding was real, in
the new code: in the final normalisation, generic over the limb count, LLVM
compiled `x += m & mask` -- `m` the constant modulus, `mask` the sign of the
secret result -- into a `js`/`jns` around the addition. The masks now pass
through `black_box`, as the divsteps' own decisions already did; with the
barriers removed again, all three inversion probes fail on exactly those
branches. P-256's inversion as shipped before this change was compiled into
a scratch probe to see whether it had the same branch: it did not (its two
loop branches were the only ones), so this is not a fix to a released leak.
Making each modulus a type (`safegcd::Modulus`) gives each its own copy of
the inversion with its limbs as constants, so no limb test survives as a
branch either.

Probe count: twenty-seven on x86-64 alone, where there were twenty-three.
All seventy-one pass on x86-64, and the forty-four on each 32-bit target
are unchanged.

RSA, 2026-10-13: one probe was added for RSA's windowed-exponentiation table
read at 2048 bits, `ct_rsa_select_2048` (`ic-rsa/src/uint.rs`, `select`, called
through `ic_rsa::ct_probes::select_2048`). The masked scan is unrolled on
x86-64, so the gate reads it there, and it is listed in `X86_ONLY`. On the
32-bit targets and RISC-V LLVM keeps the entry loop rolled, a loop over a
public count, so the probe is not required there, and no rule excuses it.
Probe count: twenty-eight on x86-64 alone, where there were twenty-seven. All
seventy-two pass on x86-64, and the forty-four on each 32-bit target are
unchanged.

Three RSA probes were tried and dropped from the gate. Each contains loops
over the public width, which the gate rejects on every target, and the rule
for this gate is not to reshape library code to pass it:

- `ct_rsa_adx_mont_mul_2048`: the MULX/ADCX/ADOX product. Its row and pass
  loops end on `jrcxz`, `jmp` and `jne` on the width.
- `ct_rsa_ifma_amm_2048`: the IFMA product. Its row loop is `jnz` on the
  word count, and `Ctx::amm`'s carry loop adds `je`, `jne` and `ja`.
- `ct_rsa_cios_2048`: the portable CIOS product. Its i and j loops end on
  `b`, `bne` and `beq` on every target.

The MULX/ADX path is covered by `ic-rsa-2048-sign-adx` in ctgrind instead,
which forces that backend under Valgrind (docs/CTGRIND.md). The IFMA path is
covered by neither tool.
