# Compiled-code regression checks

Run `python scripts/check-ct.py` from any directory. Install the five targets
with `rustup target add x86_64-unknown-linux-gnu thumbv6m-none-eabi
thumbv7em-none-eabihf riscv32imac-unknown-none-elf aarch64-unknown-linux-gnu`
first. A missing target is an
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

Forty-four exported probes call the actual implementations on every target,
seventy more on x86-64, and seven more on aarch64. Their public sizes
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
  ECDH and ECDSA are built from these. All five targets gate; on the
  32-bit ones a few findings are excused by rule, as described below.
- Ed25519 scalar arithmetic modulo L: the reduction of a 512-bit value, which
  makes the secret nonce from a hash and finishes `S`, and `a * b + c`, which
  is `S`. Straight-line on all five targets; see "Ed25519 scalar reduction"
  below. On x86-64 these are the 64-bit Barrett form, elsewhere the portable
  21-bit fold; see "Ed25519 signing on AVX2".
- On x86-64 only, the Curve25519 backends that exist only there: the
  MULX/ADX field's multiplication, squaring, addition, subtraction,
  multiplication by 121666 and divstep inversion, each from and back to
  bytes; X25519's ladder step and its doubling alone on it; signing's
  table read and group operations on it; and
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
- On x86-64 only, ChaCha20's sixteen-block AVX-512 keystream group
  (`ct_chacha20_zmm_group`), and Poly1305's four-lane AVX2 step and the
  lanes' final multiplication and folding (`ct_poly1305_avx2_step`,
  `ct_poly1305_avx2_finish`). See "ChaCha20 and Poly1305 on x86-64" below.
- On x86-64 only, RSA at 2048 bits: the windowed exponentiation's table
  read (`ct_rsa_select_2048`), and the three Montgomery products -- on
  MULX/ADCX/ADOX (`ct_rsa_adx_mont_mul_2048`, and its square
  `ct_rsa_adx_mont_sqr_2048`), on AVX-512 IFMA (`ct_rsa_ifma_amm_2048`) and
  the portable CIOS (`ct_rsa_cios_2048`); and at 1024 bits the straight-line
  MULX/ADCX/ADOX product and square (`ct_rsa_adx_mont_mul_1024`,
  `ct_rsa_adx_mont_sqr_1024`). The loops over the width are excused by the
  x86-64 counter-loop rule, per probe, up to a ceiling. See "Loops on
  x86-64" and "RSA on MULX/ADX in eight-word blocks" below.
- On x86-64 only, RSA's whole exponentiation on AVX-512 IFMA, from the
  modulus, base and secret exponent to the reduced result, at 1024 bits
  (`ct_rsa_ifma_pow_1024`, each of RSA-2048's two CRT exponentiations) and
  2048 bits (`ct_rsa_ifma_pow_2048`, its modulus): under the same rule, with
  no branch but a loop's own counter. See "The IFMA exponentiation" below.

- On x86-64 only, the window read of a prepared P-384 public key in ECDH
  (`ct_p384_comb_select`): a secret digit's masked read of sixteen affine
  entries and the conditional negation. See "Prepared ECDH public keys"
  below.

- On x86-64 only, AES-GCM's eight-block (AES-NI, `PCLMULQDQ`) and
  sixteen-block (VAES, `VPCLMULQDQ` on `ymm`) loops at AES-256: sealing and
  opening a fixed three groups (`ct_gcm_clmul8_seal`, `ct_gcm_clmul8_open`,
  `ct_gcm_vaes256_seal`, `ct_gcm_vaes256_open`), a one-group message
  (`ct_gcm_clmul8_group`, `ct_gcm_vaes256_group`), and the twist of a power
  of `H` at key setup (`ct_gcm_twist`). See "AES-GCM on x86-64" below.

- On x86-64 only, P-256's and P-384's point formulas on AVX-512 IFMA, each
  one generated block of assembly -- doubling, addition, mixed addition,
  the four-lane mixed addition, and the conversions into and out of the
  lane form (`ct_p256_ifma_double` .. `ct_p256_ifma_to_fp4`, and the same
  seven for P-384) -- the secret digit's read of a window of lane vectors
  (`ct_p256_ifma_select`, `ct_p384_ifma_select`), and the reduction of a
  converted coordinate below p (`ct_p256_ifma_from_limbs`,
  `ct_p384_ifma_from_limbs`). See "P-256 and P-384 on AVX-512 IFMA" below.
  `X86_ONLY` in the checker requires all of these on that target and no other.

- On aarch64 only, the ARMv8 backends behind `aarch64-crypto`: AES-256 one
  block each way and a batch of four, each after the key load
  (`ct_aes256_armv8_encrypt`, `ct_aes256_armv8_decrypt`,
  `ct_aes256_armv8_encrypt4`), the `PMULL` GHASH multiply and its
  eight-block absorb (`ct_ghash_pmull_mul`, `ct_ghash_pmull_absorb8`), and
  SHA-256 and SHA-512 compression (`ct_sha256_armv8_compress`,
  `ct_sha512_armv8_compress`). Their loops over blocks are excused by the
  AArch64 counter-loop rule, per probe, up to a ceiling. `AARCH64_ONLY`
  requires them on that target and no other. See "The ARMv8 backends"
  below.

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
curve arithmetic and other functions are outside this gate, and so is RSA's
exponentiation as a whole; its products and its table read are probed (see
"Loops on x86-64"). Some of their
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
`CMOV`, the divstep inversion's steps are `.rept` blocks of masks and
`CMOV` in ten calls written out (590 then; 600 in packed batches since, see
"Curve25519 without AVX-512"), and the IFMA code is vector instructions
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
stay rolled; and verification, which is variable time by design on public
data. (Signing's table read on the MULX/ADX field was not probed either,
being Rust over the `std` tables; it is now an assembly block, probed below.) Valgrind (docs/CTGRIND.md) cannot see these backends either: it does
not report ADX or AVX-512 in CPUID, so under it the portable field runs.

The `ic timing` targets `hash-to-curve` (a fixed versus a random password),
`oprf-evaluate` (two server keys), `blake2s-keyed` and `blake3-keyed` (a
fixed versus a random key) were added and run on 2026-10-12 on a development
machine that was not quiet: |t| was 1.79, 0.91, 3.11 and 3.19, against 1686
for the positive control in the same session. That is no evidence of
leakage on that machine, not a proof of its absence.

## Curve25519 without AVX-512, 2026-10-13

The MULX/ADX field's signing table read, X25519's doubling step and the
field inversion changed (CHANGELOG.md, Unreleased). Two probes are new:

- `ct_ed25519_fe64_select`: `fe64::edwards::select`, the scan of a window's
  eight entries by the secret digit. Every entry is read, the one wanted kept
  by `CMOV` on a comparison of the magnitude with its index, and the sign
  applied by `CMOV` too. It replaces `Window::select` in Rust on this field,
  which the gate could not read.
- `ct_x25519_fe64_double`: `fe64::ladder_double`, the ladder's doubling
  alone, which the clamped ladder runs at bit 254 and at bits 2 to 0.

`ct_fe64_invert` reads the new inversion: 600 divsteps in thirty `.rept`
blocks of twenty, on words packing `f` or `g` with their row of the
transition matrix, every choice a `CMOV`; the unpacking and the products
of the three batches' matrices are arithmetic.

Breaking them: a `test rcx, rcx; jz 2f; nop; 2:` inserted at the top of the
select's assembly fails `ct_ed25519_fe64_select` with `je`; the same in the
doubling's fails `ct_x25519_fe64_double`; in the divsteps' `.rept` body it
fails `ct_fe64_invert`. Restored, all pass.

Probe count: thirty-six on x86-64 alone, where there were thirty-four. All
eighty pass on x86-64, and the forty-four on each 32-bit target are
unchanged: 80 + 3 x 44 = 212 gating probe/target checks. Valgrind
(docs/CTGRIND.md) runs none of this: it reports no ADX, so the portable
field runs under it.

## Ed25519 signing on AVX2, 2026-10-14

Signing without AVX-512 IFMA changed twice (CHANGELOG.md, Unreleased): the
basepoint multiplication on the MULX/ADX field now takes signed radix-32
digits against sixteen-entry windows, read in vector registers inside the
additions, where the CPU has AVX2; and on x86-64 the scalar arithmetic
modulo L runs on four 64-bit limbs, by Barrett's method. Three probes are
new, on x86-64 only:

- `ct_ed25519_fe64_scan`: `fe64::edwards::scan`, the read of two secret
  digits' entries from one window. Every entry is loaded, each half's kept by
  `VPBLENDVB` under a mask from comparing its magnitude with the entry's
  index; a negative digit swaps two elements by masked `XOR`s and negates the
  third by subtraction and `CMOV`.
- `ct_ed25519_fe64_madd_ext2_scan`: `fe64::edwards::madd_ext2_scan`, the
  same read placed inside the two interleaved mixed additions of a step.
- `ct_ed25519_digits32`: the secret scalar's radix-32 recoding. As loops,
  the field extraction and the carries stayed rolled and failed this probe
  with `jne`/`je`/`jmp` on the loop counters; they are written out with
  literal indices, as the portable reduction's steps are, and pass.

`ct_ed25519_reduce_wide` and `ct_ed25519_mul_add` keep their names and read
the 64-bit code on x86-64 and the portable code on the other four targets.
The 64-bit form's final choice is a mask through `fe64::mask`; replacing it
with an early `return` on the borrow fails both probes with `jb`/`jmp`. A
`test rax, rax; jz 2f; 2:` inserted into the table read's setup fails
`ct_ed25519_fe64_scan` and `ct_ed25519_fe64_madd_ext2_scan`. Restored, all
pass.

Valgrind (docs/CTGRIND.md) runs the 64-bit scalar arithmetic, which is Rust
on baseline x86-64 instructions, but not the table read: it reports no ADX,
so signing takes the portable field under it. Rerun on this change
(`scripts/ctgrind.sh`, WSL Debian), `ic-ed25519-sign` reports 0 branches and
0 addresses depending on the seed, with both positive controls caught.

Probe count: seventy on x86-64 alone, where there were sixty-seven: 114 on
x86-64, and 297 gating probe/target checks with the other four targets
unchanged.

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
over the public width, which the gate rejected on every target, and the rule
for this gate is not to reshape library code to pass it. They are back on
x86-64, under the counter-loop rule; see "Loops on x86-64" below.

- `ct_rsa_adx_mont_mul_2048`: the MULX/ADCX/ADOX product. Its row and pass
  loops end on `jrcxz`, `jmp` and `jne` on the width.
- `ct_rsa_ifma_amm_2048`: the IFMA product. Its row loop is `jnz` on the
  word count, and `Ctx::amm`'s carry loop adds `je`, `jne` and `ja`.
- `ct_rsa_cios_2048`: the portable CIOS product. Its i and j loops end on
  `b`, `bne` and `beq` on every target.

The MULX/ADX path is also covered by `ic-rsa-2048-sign-adx` in ctgrind,
which forces that backend under Valgrind (docs/CTGRIND.md). The IFMA product
is now covered by this gate alone; Valgrind cannot run AVX-512.

## ChaCha20 and Poly1305 on x86-64, 2026-10-13

Two kernels handle the key, the keystream and Poly1305's `r` on x86-64, and
both are probed.

`ct_chacha20_zmm_group` is one sixteen-block group of the AVX-512 keystream
(`ic-cipher/src/chacha/zmm.rs`): a single `asm!` block with the twenty rounds
written out, so the compiled body is the text as written -- 320 `vprold`,
the two transposes, the xor into the data, `vzeroall`, and the wipe of its
scratch buffer -- with no branch. The probe calls the kernel through the
real constructor of its starting state; the state's wipe on drop, a loop
over a fixed sixteen words, is left out of the probe by `ManuallyDrop`.

`ct_poly1305_avx2_step` is one step of the four-lane Poly1305
(`ic-cipher/src/chacha/poly_avx2.rs`): load and split four blocks, 25
`vpmuludq`, and the two interleaved carry chains, which are shifts, masks
and adds with no comparison. `ct_poly1305_avx2_finish` is the last
multiplication, by a different power of `r` in each lane, and the sum of the
lanes. The loop over groups between them runs once per 64 bytes of message,
which is public, and is not probed.

All three pass. Inserting a `test`/`jz` on a byte of the starting state
into the keystream's assembly fails `ct_chacha20_zmm_group` on that `je`, reported
through the call into the kernel's body; restoring it passes.

The AVX2 eight-block keystream that predates these is not probed: its round
loop is not unrolled in the source.

Probe count: thirty-one on x86-64 alone, with the RSA probe above, where
there were twenty-seven. All seventy-five pass on x86-64, and the forty-four on each 32-bit target are
unchanged.

## Loops on x86-64, 2026-10-13

RSA's three Montgomery products were dropped from the gate (above) because
each loops over the public width, and on x86-64 the gate excused nothing. A
rule now excuses loop control on x86-64, in the probes it names and no
others, each up to a ceiling; it brought the three back. Valgrind cannot run
AVX-512, so for the IFMA product this gate is the only tool that reads it.

### The rule

`X86Body` in `check-ct.py` builds each function body's control-flow graph,
finds its natural loops by dominators (a back edge `u -> h` where `h`
dominates `u`; the loop is `h` and every block that reaches `u` without
passing through `h`, so every instruction executed between two visits to
the header is in it), and excuses three shapes:

- **counter loop**: a conditional branch that is a back edge to a loop's
  header or an exit from the loop, and whose condition is that loop's
  counter. Either `jrcxz`/`jecxz`, on rcx; or a `jcc` whose flags come from
  an instruction in the branch's own basic block, reached backwards over
  only instructions that write no flags (moves, `lea`, `mulx`, `setcc`,
  `cmov`, vector operations other than comparisons), that is one of: `inc`,
  `dec`, `add $imm` or `sub $imm` of a register; `cmp $imm` or `test $imm`
  of a register; `test r, r`; or `cmp r1, r2`. The register is a counter of
  the loop if every instruction in the loop that writes it, under any of its
  names (`%ecx` is `%rcx`), is `inc`, `dec`, `add $imm`, `sub $imm` or
  `lea imm(r), r` on it, and at least one does. For `cmp r1, r2` one must
  be a counter and the other written nowhere in the loop. A loop that
  contains a call, a string instruction, or an instruction without operands
  that the checker does not know, excuses nothing: it cannot list what those
  write.
- **unconditional jump**: `jmp` to a label in the same function. It has no
  condition; the branches that decide whether it is reached are checked.
- **constant memset**: a call to `memset` whose length was loaded into rdx
  as an immediate, whose value is rsi zeroed by `xor`, and whose destination
  is rdi set by `lea imm(%rsp)`, all in the call's basic block: the zeroing
  of a fixed-size buffer on the stack. Its timing depends on the length and
  the address, both fixed.

It refuses, and the tests in `test-check-ct.py` hold it to refusing: a
branch whose flags come from a load, from `adc` or `sbb`, or from anything
else between the counter and the branch; a counter also written from data
in the loop (an `add` of a loaded value, a `cmov`, the high half of a
`mul`); `cmp` against a register written in the loop or against memory; a
register the loop never steps; a counter branch inside the loop that is
neither an exit nor the back edge; a counter branch outside any loop;
`jrcxz` with rcx loaded in the loop; an indirect jump; a `memset` of a
computed length or to a pointer that is not the stack; a loop in a probe not
listed; any loop at all in a body that switches to Intel syntax; and one
excused finding more than a probe's ceiling, or any finding under a rule
the probe was not reviewed for. Breaking the checker nine ways -- accepting
any write to the counter, dropping the step requirement, ignoring the fixed
operand of `cmp`, excusing any branch in a loop, reading flags past an `adc`,
allowing calls in a loop, excusing unlisted probes, dropping the ceiling,
accepting any `memset` length -- fails the tests each time.

What it does not establish: where a counter starts. The rule proves the
branch is decided by the number of iterations, given the counter's value on
entry; that the value on entry is public -- the width, a constant -- is what
the reading below established for each probe, and why each probe is named
with a ceiling rather than the rule applying everywhere. A counter loaded
from a secret before the loop would pass the rule. The ceiling means such a
loop has to arrive as a change that someone then reads.

### The ceilings, read on 2026-10-13, rustc 1.99.0

`X86_EXCUSE_CEILINGS`, per probe, counted following calls:

| Probe | counter loop | unconditional jump | constant memset |
| --- | --- | --- | --- |
| `ct_rsa_adx_mont_mul_2048` | 4 | 2 | 1 |
| `ct_rsa_ifma_amm_2048` | 1 | 0 | 0 |
| `ct_rsa_cios_2048` | 4 | 2 | 1 |
| `ct_p384_comb_select` | 1 | 0 | 0 |

Each excused finding, read in `target/ct-audit/probes/x86_64-unknown-linux-gnu.s`:

- `ct_rsa_adx_mont_mul_2048` (`ic-rsa/src/uint/x86.rs`, `mont_mul_adx` at
  `L = 32`, then `finish`): in the kernel, `jrcxz` ending each of the two
  passes over the 32 words, rcx running from -32 to 0 by `lea 4(%rcx)`,
  each pass closed by a `jmp` back to its top; `decq %r14; jne` ending the
  row loop, r14 set to 32 before the kernel and written nowhere else; in
  `finish`, `addq $2, %rcx; cmpq $32, %rcx; jne` over the words of the
  masked subtraction; and `memset` of 528 bytes at `8(%rsp)`, the zeroed
  66-word accumulator.
- `ct_rsa_ifma_amm_2048` (`ic-rsa/src/uint/ifma.rs`, `Ctx<40>::mul_inline`,
  the `amm5` kernel inlined as the exponentiation's window loop has it):
  `decq %r9; jne` ending the row loop, r9 set to 40, the number of 52-bit
  words, by `movl $40` before the kernel. Everything else in the product,
  the carry of the columns into limbs included, is straight-line. Re-read
  after "The IFMA exponentiation" below changed the code: the same one
  branch.
- `ct_rsa_cios_2048` (`ic-rsa/src/uint.rs`, `cios` at 32 words): the outer
  loop's exit, `incq %rbp; cmpq $32, %rbp; je`; the multiply pass,
  `addq $2, %rsi; cmpq $33, %rsi; jne`; the reduction pass's exit,
  `cmpq $32, %r8; je`, r8 stepped by `addq $2`, and its back edge `jmp`;
  the `jmp` into the outer loop from the prologue; `finish`'s word loop,
  `addq $2, %rcx; cmpq $33, %rcx; jne`; and `memset` of 272 bytes at
  `16(%rsp)`, the 34-word accumulator.

None of the three has a bounds check, an indirect call or a branch on a
value. When these were read, the IFMA probe set the context's geometry to
2048 bits before the product (`Ctx::set_width_for_probe`), so the kernel
was selected at compile time; the context is now built for one width, a
const parameter, and the probe takes a `Ctx<40>`. Then, `Ctx::amm` now reads the width once, before the kernel, which is
handed a pointer into the context and so forced every later read of the
field to be a reload, and with it a bounds check on `out[words..]` that
could not be folded. That change is a refactor: the same value, read
earlier. The ADX and IFMA kernels and their probe hooks compile without
`std` under `ct-probes`, where nothing selects them, for the probe build to
read.

### Mutations

Each was applied to the library, the gate run as `check.sh` runs it
(`python scripts/check-ct.py --target x86_64-unknown-linux-gnu`), and
restored:

- `if a[0] & 1 != 0 { black_box(a[1]) }` in `Ctx::amm`: fails
  `ct_rsa_ifma_amm_2048: jne .LBB69_2` and
  `ct_rsa_ifma_amm_2048: jmp .LBB69_3` (a jump this probe was not reviewed
  for).
- `test {x3}, 1; jz 7f; nop; 7:` inside the IFMA kernel's row loop, on a
  column sum: fails `ct_rsa_ifma_amm_2048 -> ...ifma4amm5: je .Ltmp1`.
- `if b[i] & 1 != 0 { black_box(a[0]) }` at the top of CIOS's row: fails
  `ct_rsa_cios_2048: je .LBB68_3`.
- `test rax, 1; jz 7f; nop; 7:` inside pass A of the MULX/ADX kernel: fails
  `ct_rsa_adx_mont_mul_2048 -> ...x8612mont_mul_adx: je .Ltmp3`.
- A second loop over the output words in `Ctx::amm`: fails
  `ct_rsa_ifma_amm_2048: 2 findings excused as counter loop, more than the 1
  reviewed`.
- The reduction pass run twice in each CIOS row: fails
  `ct_rsa_cios_2048: 5 findings excused as counter loop, more than the 4
  reviewed`. (A second pass over the fixed 34-word accumulator did not:
  LLVM unrolled it, so it added no loop.)

Restored, all 78 pass. These ran against `Ctx::amm` as it then was; the
next section's mutations ran against the code that replaced it.

### Not covered

- **The IFMA exponentiation as a whole** was not covered when this was
  written; "The IFMA exponentiation" below covers it.
- **The MULX/ADX product's entry checks** (`x86::mont_mul`: the CPU
  feature, the slice lengths) are not in the probe, which calls the kernel
  at a fixed width. They are on public lengths, and Valgrind runs that path
  (`ic-rsa-2048-sign-adx`, docs/CTGRIND.md).
- **CIOS on the 32-bit targets.** It clears its accumulator through
  `__aeabi_memclr8` on Cortex-M, a runtime routine the gate does not read,
  and its loop tests (`cmp r1, #32` after an `adc`, `cmp.w r2, #256`) do not
  fit the 32-bit counter shapes, which apply to the P-256 probes only. It
  is required on x86-64 only (`X86_ONLY`), and no 32-bit rule was widened.
- **The squaring** (`uint::sqr`), the other product the 64-bit
  exponentiation uses, is not probed.

Probe count: thirty-four on x86-64 alone, where there were thirty-one. All
seventy-eight pass on x86-64, and the forty-four on each 32-bit target are
unchanged: 78 + 3 x 44 = 210 gating probe/target checks.

## The ARMv8 backends, 2026-10-14

AES (`ic-cipher::aes::aarch64`), GHASH on `PMULL` (`ic-cipher::pmull`),
SHA-256 and SHA-512 (`ic-hash::sha2::aarch64`), the AArch64 backends behind
the off-by-default `aarch64-crypto` feature, are in the gate:
`aarch64-unknown-linux-gnu` is its fifth target. The harness is a static
library, so the target needs no linker and no C toolchain, only
`rustup target add aarch64-unknown-linux-gnu`; like every other target, a
missing one is an error.

`scripts/ct-audit` turns on `aarch64-crypto` and `ct-probes` for `ic-cipher`
and `ic-hash`. Under `ct-probes` the backends compile without `std`, so
without the run-time detection that selects them in the library (which
stays under `std`); on every other target the two features select nothing.
The wrappers are in `ic_cipher::ct_probes` and `ic_hash::ct_probes`,
hidden, not API, and compiled only with the feature.

This gates the compiled code. It does not establish anything about the
instructions' timing on a core, which is the next point's subject, and none
of this has run on ARM hardware.

### What fails on AArch64

Every control transfer but a bare `ret`: `b.<cond>`, `cbz`/`cbnz`,
`tbz`/`tbnz`, `b` to a label, `bl`, `br`, `blr`, their
pointer-authenticated forms (`braa`, `blraa`, `retaa`, ...), `ret` to a
named register, `svc`/`hvc`/`smc`/`eret`; and `sdiv`/`udiv`. A `b` or `bl`
to a function whose body is in the same assembly is followed, and that
body is held to the same rules, as on every target; a `bl` to anything
else (`memcpy`) fails.

### The rule

One rule, "counter loop", in `A64Body`, the x86-64 rule's shape and no
wider, applied only in the probes `AARCH64_EXCUSE_CEILINGS` names:

- The branch is the last instruction of its basic block, targets a label
  in the same function, and is the back edge or an exit of a natural loop,
  found from the control-flow graph by dominators.
- Its condition is a counter's: `cbz`/`cbnz` on a register, or a
  `b.<cond>` whose flags come, within its own basic block, from
  `subs`/`adds Xn, Xn, #imm`, `cmp`/`cmn Xn, #imm`, or `cmp Xn, Xm` of two
  distinct registers. Every instruction between that one and the branch
  must be one the checker knows does not set the flags.
- The register is a counter of that loop: every instruction in the loop
  that writes it is `add`, `sub`, `adds` or `subs` of an immediate to
  itself, and at least one is. For `cmp Xn, Xm` the other register is
  written nowhere in the loop.
- Every instruction in the loop is one whose register writes the checker
  can list (`A64_KNOWN`: integer and SIMD data processing, the crypto
  instructions, loads and stores with their writeback). A call, an
  indirect branch or any instruction not in the list voids the excuse for
  that loop.

Never excused: `tbz`/`tbnz` (a branch on one bit, data or counter),
`ccmp`/`ccmn` chains, `tst`, `ands`, flags from carries (`adcs`, `sbcs`),
flags from a register a load or data arithmetic wrote, `cmp` against a
register written in the loop, a counter stepped by a load's writeback or
selected by `csel`, and `b` to a label: there is no unconditional-jump
rule on AArch64, because none of these probes needed one.

### Probes

Seven, in `AARCH64_ONLY`, required on aarch64 and nowhere else:

- `ct_aes256_armv8_encrypt`, `ct_aes256_armv8_decrypt`: one block each way
  at AES-256, after `Keys::load` from a fourteen-round schedule
  (`Schedule::from_aes256_round_keys`, behind `ct-probes`). The round count
  is a field the library branches on by key length; the probes fix it, so
  the code read is AES-256's. The decryption probe reads the key load's
  derivation of the inverse cipher's keys through `AESIMC`, which touches
  every round key.
- `ct_aes256_armv8_encrypt4`: one batch of four blocks through
  `encrypt_blocks`, the path counter mode takes.
- `ct_ghash_pmull_mul`: one GHASH multiplication on `PMULL`.
- `ct_ghash_pmull_absorb8`: three groups of eight blocks absorbed against
  eight powers of `H`.
- `ct_sha256_armv8_compress`: SHA-256 compression over four blocks.
- `ct_sha512_armv8_compress`: SHA-512 compression over two blocks.

A separate probe of the key load alone was written and dropped: returning
the loaded keys copied them out with `bl memcpy`, which fails, correctly.
The encryption and decryption probes read the load inlined instead.

aarch64 also runs the forty-four probes every target runs. All pass with
nothing excused: the P-256 probes follow `bl` into `from_bytes_reduced` and
`from_mont`, straight-line, and nothing else branches. The x86-64-only
probes are not required there; `ct_rsa_cios_2048` compiles for aarch64 and
has four loop branches there that nobody has read, so it stays out.

### The ceilings, read on 2026-10-14, rustc 1.99.0

`AARCH64_EXCUSE_CEILINGS`, per probe, counted following calls; every other
probe excuses nothing.

| Probe | counter loop |
| --- | --- |
| `ct_ghash_pmull_absorb8` | 1 |
| `ct_sha256_armv8_compress` | 1 |
| `ct_sha512_armv8_compress` | 2 |

Each excused branch, read in `<CARGO_TARGET_DIR or target>/ct-audit/probes/aarch64-unknown-linux-gnu.s`:

- `ct_ghash_pmull_absorb8`: `subs x11, x11, #128` at the top of the group
  loop, `b.ne` at its end, x11 set to 384 by `mov w11, #384` before it.
  Between them only loads (one post-indexed on the block pointer x10),
  `rbit`, `pmull`/`pmull2`, `ext`, `eor` and `dup`.
- `ct_sha256_armv8_compress`: `add x8, x8, #64; cmp x8, #256; b.ne`, x8 the
  block offset, from `mov x8, xzr`. The sixteen four-round groups are
  unrolled inside it.
- `ct_sha512_armv8_compress`: the block loop, `subs x8, x8, #128` and
  `b.ne` after `add x1, x1, #128`, x8 from `mov w8, #256`; and inside it
  the loop over four of the five eight-round groups (the first, which has
  no schedule update, is peeled), `subs x11, x11, #1; b.ne`, x11 set to 4
  at the top of each block.

The rest is straight-line. The AES encryption probe is fourteen `aese` and
thirteen `aesmc`, unrolled; decryption is fourteen `aesd` and twenty-six
`aesimc`, thirteen of them the key load's; the batch is fifty-six `aese`.
The `PMULL` multiply is thirty instructions with no branch. Neither AES
probe has a bounds check: the fixed round count folds them.

### Mutations

Each applied to the library, the gate run as `python scripts/check-ct.py
--target aarch64-unknown-linux-gnu`, and restored:

- `if state[0] & 1 != 0 { black_box(state[1]) }` at the top of
  `compress256`: fails `ct_sha256_armv8_compress -> ...sha256_armv8_compress:
  tbz w8, #0, .LBB63_2`.
- `if h[0] & 1 != 0 { black_box(x[1]) }` at the top of `pmull::mul`: fails
  `ct_ghash_pmull_mul -> ...ghash_pmull_mul: tbz w8, #0, .LBB53_2`.
- `if block[0] == 0x80 { black_box(block[1]) }` inside the SHA-256 block
  loop (`armv8_sha256_blocks`): fails `b.ne .LBB63_1`, whose flags are
  `cmp w11, #128` on the loaded byte, and the two `b` the branch brought
  with it; the loop's own exit, now `b.eq` on the counter, is still the one
  excused.
- The SHA-512 round-group loop written out twice in `armv8_sha512_blocks`:
  fails `ct_sha512_armv8_compress: 3 findings excused as counter loop, more
  than the 2 reviewed`.

Two attempts to add a loop that did not: the absorb run twice in the probe
(LLVM merged the two loops), and `compress512` called twice (one
out-of-line copy, and a body is counted once per probe). Neither changed
what is read; the duplicated round-group loop above is the over-ceiling
check.

`scripts/test-check-ct.py` has the rule's own cases: the shapes the
compiler emitted pass (`subs`/`b.ne`, `add`/`cmp #imm`/`b.ne`, a `cbnz`
countdown, `cmp` against a fixed end pointer, SHA-512's nesting), and
nineteen that only resemble them fail (`b.eq` on a loaded value, `subs` of a
loaded register, `tbz` on a
data bit, `tbnz` on the counter, a counter also written from data, loaded,
stepped by writeback or selected by `csel`, `cmp` against a register
written in the loop, a `ccmp` chain, `tst`, flags from `adcs`, a register
never stepped, a branch outside any loop, a call in the loop, an unknown
instruction in the loop or between the flags and the branch, `br`, `blr`),
as do one loop over a ceiling and the same loops in an unlisted probe.
Making `_counter` accept every register, and the flag search skip unknown
instructions, failed nine of those.

### Not covered

- **The key expansion.** `Schedule::expand` is portable code shared by
  every backend, and is a probe on no target. The ARM-specific half of key
  setup, the load and the `AESIMC` derivation, is read.
- **AES-128 and AES-192.** The round count is public; their code is the
  same loop at ten and twelve rounds, not read.
- **The composition.** Run-time detection, the dispatch in `aes.rs`,
  `encrypt_blocks`'s remainder path, and AES-GCM on ARM (`gcm.rs`, which
  runs the AES backend and the `PMULL` GHASH one after the other) need
  `std` or a message length, and are not probed. Their branches are on
  lengths and on the CPU's features.
- **Execution.** The probes are compiled to be read. `scripts/test-aarch64.sh`
  runs the kernels' differential tests under QEMU; it was not run for this
  change, which had no QEMU to hand, and none of it has run on ARM
  hardware.
- **The instructions' timing.** `AESE`/`AESD`/`AESMC`/`AESIMC`,
  `PMULL`/`PMULL2`, `SHA256H`/`SHA256H2`/`SHA256SU0`/`SHA256SU1`,
  `SHA512H`/`SHA512H2`/`SHA512SU0`/`SHA512SU1`, `RBIT`, `REV32`/`REV64` and
  `EXT` are vector operations with no data-dependent behaviour in the
  architecture; Arm lists the crypto instructions among those covered by
  FEAT_DIT (data-independent timing). This library does not set
  `PSTATE.DIT`, and the gate does not look at timing.

Probe count: seven on aarch64 alone, and the forty-four shared, fifty-one
there, all passing. With 114 on x86-64 and 44 on each 32-bit target:
114 + 3 x 44 + 51 = 297 gating probe/target checks.

## The IFMA exponentiation, 2026-10-13

RSA's exponentiation on AVX-512 IFMA (`ic-rsa/src/uint/ifma.rs`) is in the
gate as a whole: `ct_rsa_ifma_pow_1024` and `ct_rsa_ifma_pow_2048` call
`ifma::pow_fixed` with the modulus, base, secret exponent and exponent
length as arguments, and read everything from the conversion into radix
2^52 to the reduced result. No rule was added or widened; both pass under
the counter-loop rule above, with ceilings.

### What changed

A trial probe of the old code showed every product re-reading the
context's register count and width after the kernel call and dispatching
on them (`cmpq $3, %rax; je` to `amm3`), bounds checks on the width
(`cmpq $84, %rsi; ja` to `slice_index_fail`), an indirect `callq *%rbp`
`memset`, and a `memset` of `512 - 8 * words` bytes. Now:

- **One copy per width.** `ifma::pow` matches the modulus's width once,
  16, 24 or 32 words, to `pow_fixed::<24>`, `<32>` or `<40>`, and inside
  that every bound, offset and kernel choice is a constant; values are
  `[u64; N]`. The match and the CPU check (`available`) are outside the
  probe, as are the copy of the result into a `Uint`.
- **No call but to code the gate reads.** A call to anything outside the
  assembly fails; a call inside a loop voids that loop's excuse. So the
  window loop's squaring and multiplication are the kernel inlined
  (`Ctx::square_inline`, `mul_assign_inline`), and every other product
  calls one out-of-line copy per width (`Ctx::mul_raw`). Nothing is copied
  between arrays, which would be `memcpy`: one is made in the table and
  again in the accumulator by two products, and the base is converted
  straight into its table entry. The scratch is one `repr(C)` work area,
  zeroed by one `memset` of a constant length on the stack and wiped as one
  run of words.
- **`R'^2` by two products** rather than 32 to 64 modular doublings, whose
  loop held sixteen to thirty-two words and spilled its counter: with
  `A = R^2 mod m` and `P = 2^(208W - 256L)` (64, 96 or 128 bits),
  `A * (A * P / R') / R' = 2^(104W) = R'^2`.
- **The top window like the others.** The window loop is entered
  unconditionally, `max(1, ceil(exp_bits / 4))` times; the bits above
  `exp_bits` are cleared in a masked copy of the exponent first, so the
  loop has no test but its counter's. The first four squarings square one.
- **The loop counters keep their registers.** The kernel holds twelve
  general registers. Each of these was a finding of the gate, a counter
  reloaded from the stack inside its loop, which the rule refuses, and is
  answered by giving the compiler less to hold across the kernel: `MASK`
  is read from the context rather than held in a register; the kernel
  writes `a[0..3] << 12` itself, so no word of the accumulator is cached
  across it; the table read's sixteen masks are made two at a time in
  SSE2 registers, where the compiler had made all sixteen in ten general
  registers at once; `take` no longer stores zeros above `W`, which every
  value already has; and the work area's barrier names a field other than
  its first, so the `memset` destination is a `lea` from the stack rather
  than a register kept for later. The conversions into radix 2^52 are split
  where a limb stops taking bits from the word above, rather than masking a
  loaded word, which the compiler had turned into `cmpq $20; jae` around
  the load.

### The ceilings, read on 2026-10-13, rustc 1.99.0

| Probe | counter loop | constant memset |
| --- | --- | --- |
| `ct_rsa_ifma_pow_1024` | 9 | 1 |
| `ct_rsa_ifma_pow_2048` | 12 | 1 |

`ct_rsa_ifma_pow_1024` (`pow_fixed::<24>`, 20 limbs of 52 bits, 16
64-bit words), each read in the assembly with where its counter starts:

- the kernel's row loop three times, `decq; jne` with the counter set by
  `movl $20` just before the kernel: inlined for the squaring and the
  multiplication in the window loop, and in `Ctx<24>::mul_raw`;
- the four squarings, `decl %ecx; jne`, `movl $4, %ecx`;
- the table read's word loop, `addq $2, %rcx; cmpq $20, %rcx; jne`, from
  `xorl %ecx, %ecx`;
- the window loop, `testq %rax, %rax; jne`, rax stepped only by `dec`,
  and set before the loop from the `exp_bits` argument by `cmpq $4096;
  cmovb` (the clamp), `addq $3; shrq $2` and `cmpq $1; adcq $0` (the
  floor of one window): public, and no branch in computing it;
- the masking of the exponent, `addq $2, %r15; cmpq $64, %r15; jne`, from
  `xorl %r15d, %r15d` before the work area's `memset`, r15 being preserved
  across the calls between;
- the conversion out of radix 2^52 in `leave::<24>`,
  `addq $64, %rsi; cmpq $1024, %rsi; jne`, from `xorl %esi, %esi`;
- the wipe of the work area, eight volatile stores a pass,
  `addq $64, %rax; cmpq $4600, %rax; jne`, from `movl $56, %eax`: 71
  passes, 4544 bytes;
- and `memset` of 4544 bytes at `904(%rsp)`, the work area.

`Ctx<24>::rr` and `to_radix52::<64, 24>` are straight-line.

`ct_rsa_ifma_pow_2048` (`pow_fixed::<40>`, 40 limbs, 32 words): the same
nine, with 40 rows, a 40-word table read, the conversion out to 2048 bits
and a wipe of 7232 bytes from 56 to 7288; and three loops the 1024-bit copy
unrolls: the conversion of the modulus into the context and
`to_radix52::<64, 40>`, each `addq $52; cmpq $2028; jne` from zero (39
limbs taking bits from the word above; the fortieth is straight-line), and
the masked subtraction in `leave::<40>`, `addq $2, %rax; cmpq $33, %rax;
jne` from `movl $1, %eax`. And `memset` of 7232 bytes on the stack.

The exponent length is an argument to both probes, as it is to
`Modulus::pow`; the window loop's count is computed from it, without a
branch, and the rule's limit -- it does not establish where a counter
starts -- is answered for it by the reading above.

### Mutations

Each applied to `pow_fixed`, the gate run as `check.sh` runs it, and
restored:

- `if digit & 1 != 0 { black_box(digit) }` on the window's digit before the
  table read: fails `ct_rsa_ifma_pow_1024: jae .LBB70_7` and
  `ct_rsa_ifma_pow_2048: jae .LBB71_9` (the test is a `bt`).
- The work area wiped twice: fails `ct_rsa_ifma_pow_1024: 10 findings
  excused as counter loop, more than the 9 reviewed` and the same for
  `ct_rsa_ifma_pow_2048`, 13 against 12.
- The table read run twice in the window loop: fails both probes on the
  window loop's own branch (`jne .LBB70_3`, `jne .LBB71_5`). The extra
  masks took the counter's register, and its reload from the stack is not
  a counter. Not the ceiling mutation it was meant to be, but it shows the
  rule refusing a spilled counter in this code.

`R'^2` computed with one bit too many fails `one_ifma_product_is_right`
and `the_exponentiation_backends_agree`, so the tests reach the IFMA path
on this CPU.

### Not covered

- **The entry.** `ifma::pow` asks the CPU (`available`, a cached atomic)
  and matches the width; both are public. The result is then copied into a
  `Uint`. These are outside the probes.
- **`pow_public`.** The public-exponent path branches on the exponent's
  bits by design; it shares the conversions, `R'^2` and the out-of-line
  product, which the probes read.
- **1536 bits.** `pow_fixed::<32>`, RSA-3072's primes, is the same generic
  code and is not probed.
- **The rule's own limit**, above: a counter is shown to be stepped only by
  constants, not to start from a public value; the starts above were read.

### Cost

Measured on Zen 5 under load, release builds.

- **Code size.** `ic-rsa`'s `.text`, built for x86-64 Linux with LTO off so
  the library's own code can be counted: 79,365 bytes before, 97,666
  after (+18,301, 23 percent). Three widths each carry the kernel inlined
  twice in the window loop and once out of line. Inlining every product
  instead, the first version of this, was +77 KB; most of the difference
  was the kernel's copies outside the window loop and unrolled wipes.
- **Speed.** RSA-2048 PKCS#1 v1.5 against Graviola 0.4.1 in the same
  process, fifteen rounds alternating which runs first, the ratio
  IronCrypto/Graviola per round; the old and new builds alternated five
  times each, minutes apart. Signing: median ratio 0.71 to 0.83 per run
  before, 0.61 to 0.70 after. Verification: 0.68 to 0.81 before, 0.47 to
  0.60 after. Faster in every pair; the cause was not isolated. Removed
  from each exponentiation: the 32 to 64 modular doublings for `R'^2`,
  and the copies of operands between arrays. Added: the four squarings of
  one in the top window, and two products where a copy was.

Probe count: thirty-six on x86-64 alone, where there were thirty-four. All
eighty pass on x86-64, and the forty-four on each 32-bit target are
unchanged: 80 + 3 x 44 = 212 gating probe/target checks.

## Prepared ECDH public keys, 2026-10-13

`p256::PreparedPublicKey`, `p384::PreparedPublicKey` and
`p521::PreparedPublicKey` hold sixteen affine multiples of the peer's point
at each of four spacings (`nist::gentable::Comb`), and an agreement through
one is `Comb::mul`: the private scalar recoded into signed five-bit digits as
for `Point::mul_scalar`, then, for each position, five doublings and one
mixed addition per window. Every loop in it runs over a count fixed by the
curve, and the one test on the position (`i < n`, past the top digit) is on
the loop index. What sees the secret is each digit's read of its window and
the addition that follows.

`ct_p384_comb_select` is that read, on x86-64: `AffineWindow::select` on a
prepared P-384 window, the digit a runtime argument. It reads all sixteen
entries under masks made from the digit's magnitude, through the SSE2 scan
P-384 already uses for its generator table, and negates `y` by a
conditional move for a negative digit. One finding, excused as a counter
loop (ceiling 1): `incq %rax; cmpq $16, %rax; jne`, the scan's loop over the
sixteen entries, rax set to zero before it and written nowhere else in it.
The masks are read from the stack at that counter; nothing is indexed by the
digit.

Two mutations, each restored afterwards:

- `if magnitude & 1 != 0 { black_box(&masks) }` in `select`: fails
  `ct_p384_comb_select: je .LBB54_2`.
- A second masked pass over the entries in `select`: fails
  `ct_p384_comb_select: 2 findings excused as counter loop, more than the 1
  reviewed`. (A pass that only touched each entry was unrolled and added no
  loop.)

### Not covered

- **The multiplication as a whole, and the addition after the read.** A
  probe of one step -- the read and `AffineWindow::add_to`'s mixed
  addition -- was built and read, and is not in the gate. The probe build
  has no `std` and no BMI2/ADX target feature, so it selects P-384's generic
  field, whose multiplication and squaring keep their six-row word loop
  rolled; the row counter is spilled to the stack and the register reused
  inside the loop, then reloaded before `cmpq $6`, and the rule rightly
  cannot prove a counter it does not see stepped. Those loops are on a
  constant count. On a CPU with BMI2 and ADX, which is where P-384 runs in
  practice, the additions and doublings are the assembly blocks probed as
  `ct_p384_point_add_affine_adx`, `ct_p384_point_add_adx` and
  `ct_p384_point_double_adx`, and the complete addition at the last position
  is made of those. The scalar's recoding (`signed_digits_w`), shared with
  `Point::mul_scalar` and the generator table, is not probed either.
- **P-256 and P-521's prepared keys** are the same generic code over other
  fields, and are not probed separately.

Probe count: thirty-five on x86-64 alone, where there were thirty-four. All
seventy-nine pass on x86-64, and the forty-four on each 32-bit target are
unchanged: 79 + 3 x 44 = 211 gating probe/target checks.

## AES-GCM on x86-64, 2026-10-13

The 128- and 256-bit fused AES-GCM kernels became assembly
(`ic-cipher/src/gcm_x86_asm.rs`), and with that a body the gate can read as
written. Seven probes, in `ic_cipher::ct_probes`, all at AES-256 (the round
count is a const parameter; `.if` assembles the extra rounds in or out, so
there is no branch on the key size either):

- `ct_gcm_clmul8_seal`, `ct_gcm_clmul8_open`: the eight-block loop over three
  groups, sealing (the first group encrypted alone, two stitched iterations,
  the last group hashed alone) and opening (three stitched iterations).
- `ct_gcm_vaes256_seal`, `ct_gcm_vaes256_open`: the same on the sixteen-block
  `ymm` loop.
- `ct_gcm_clmul8_group`, `ct_gcm_vaes256_group`: a one-group message,
  counter mode then GHASH, two straight-line blocks.
- `ct_gcm_twist`: a power of `H` multiplied by `x^-1` at key setup, which
  reads `H`'s top bit as a mask (`psrad`), not a branch.

The loops' only branch is their back edge. Each excused finding, read in
`target/ct-audit/probes/x86_64-unknown-linux-gnu.s` (rustc 1.99.0):

| Probe | counter loop | where |
| --- | --- | --- |
| `ct_gcm_clmul8_seal` | 1 | `movl $2, %r9d` before the loop; `decq %r9; jne` closes it; nothing else in the loop writes r9 |
| `ct_gcm_clmul8_open` | 1 | the same with `movl $3, %r9d` |
| `ct_gcm_vaes256_seal` | 1 | `movl $2, %r9d`; `decq %r9; jne` |
| `ct_gcm_vaes256_open` | 1 | `movl $3, %r9d`; `decq %r9; jne` |

The counter is the group count, a length. The data pointer is stepped by
`addq $256, %rdi` (or 128) beside it. `X86_EXCUSE_CEILINGS` holds each at 1.

Mutation: `ptest xmm10, xmm10; jz 7f; nop; 7:` inserted into the eight-block
reduction, on the unreduced GHASH sum, fails `ct_gcm_clmul8_seal` (twice:
in the loop and in the last group's hash), `ct_gcm_clmul8_open` and
`ct_gcm_clmul8_group`, each on the `je`; restored, all pass. The branch
inside the loop is not excused: it is in the loop but is neither its exit
nor its back edge.

Not covered: the 512-bit kernel's loops (`zmm_groups`, `zmm32_groups` in
`gcm_x86.rs`), which branch on the round count inside the assembly
(`cmp {rounds}, 10; je`) -- public, but not a loop counter, so the rule
does not excuse it; the AAD, tail, length-block and tag code (`Pending`,
`finish`), intrinsics that branch on lengths; and the choice of kernel,
which branches on the CPU's features. Valgrind (docs/CTGRIND.md) runs the
AES-GCM path the CPU it runs on selects.

Probe count: forty-one on x86-64 alone, where there were thirty-four. All
eighty-five pass on x86-64, and the forty-four on each 32-bit target are
unchanged: 85 + 3 x 44 = 217 gating probe/target checks.

## RSA on MULX/ADX in eight-word blocks, 2026-10-13

The MULX/ADCX/ADOX backend (`ic-rsa/src/uint/x86.rs`) was rewritten for
speed: a straight-line product and square at 16 words, the width of an
RSA-2048 prime; product, square and reduction in eight-word register blocks
at the other multiples of eight; the final conditional subtraction in
assembly, by mask; and the exponentiation's table read (`select`) as an SSE2
masked scan. The older interleaved kernel remains for widths that are a
multiple of four but not of eight, which no RSA key has. Squaring, which was
not probed (above, "Not covered"), now has its own kernels and probes.

Probes: `ct_rsa_adx_mont_mul_2048` now reads the block kernels;
`ct_rsa_adx_mont_sqr_2048` is new, for the block square; and
`ct_rsa_adx_mont_mul_1024` and `ct_rsa_adx_mont_sqr_1024` are new, for the
straight-line kernels that RSA-2048 signing spends its time in. Each runs the
kernel and the final subtraction on an uninitialised scratch buffer, as the
library now does: the kernels write every word of it before reading it, so
the 66-word `memset` the old probe had is gone, and with it that ceiling.
`ct_rsa_select_2048` reads the SSE2 scan, which is a loop.

### The ceilings, read on 2026-10-13, rustc 1.99.0

| Probe | counter loop | unconditional jump | constant memset |
| --- | --- | --- | --- |
| `ct_rsa_adx_mont_mul_2048` | 10 | 10 | 0 |
| `ct_rsa_adx_mont_sqr_2048` | 11 | 11 | 0 |
| `ct_rsa_adx_mont_mul_1024` | 2 | 2 | 0 |
| `ct_rsa_adx_mont_sqr_1024` | 2 | 2 | 0 |
| `ct_rsa_select_2048` | 1 | 1 | 0 |

Each excused finding, read in `target/ct-audit/probes/x86_64-unknown-linux-gnu.s`:

- The 16-word kernels have no branch at all. Both 1024-bit probes' four
  findings are the final subtraction (`x86::finish`): two loops, each
  `jrcxz` leaving and `jmp` closing it, rcx set to `-4` (16 words, four a
  turn) before each and stepped only by `lea 1(%rcx)`, which leaves the
  borrow chain alone.
- `ct_rsa_adx_mont_mul_2048`: four product blocks and four reduction blocks,
  each a loop over its groups of eight steps -- `testq %rbp, %rbp; je` at
  the top, `decq %rbp`, `jmp` back -- with rbp loaded from rcx or rax, set
  to `$4` (product) and `$3` (reduction) before each block; and the final
  subtraction's two loops, rcx `$-8`.
- `ct_rsa_adx_mont_sqr_2048`: four blocks of cross products, the same loop
  shape with the group count `$3`, `$2`, `$1` and `0`; the diagonal's loop,
  `jrcxz`/`jmp` with rcx `$-8`; four reduction blocks, `$3` each; and the
  final subtraction.
- `ct_rsa_select_2048`: the scan's loop over pairs of words, `jrcxz`/`jmp`,
  rcx `$-16`. Inside it, sixteen `movdqu`/`pand`/`por` at fixed offsets from
  the table, one per entry; the masks are computed in Rust as before.

Every count starts at a constant derived from the width. Nothing in any of
the kernels indexes memory by a value.

### Mutations

Applied one at a time to the library, the check run, and restored:

- `test rax, 1; jz 7f; nop; 7:` in every step of the 16-word kernels: fails
  `ct_rsa_adx_mont_mul_1024 -> ...x8611mont_mul_16: je .Ltmp19`.
- The same in every step of the block kernels: fails
  `ct_rsa_adx_mont_mul_2048 -> ...x8611mont_mul_8n: je .Ltmp21`.
- A branch on the selected words in the SSE2 table read: fails
  `ct_rsa_select_2048: je .Ltmp17`.
- The final subtraction run twice in the 1024-bit square: fails
  `ct_rsa_adx_mont_sqr_1024: 4 findings excused as counter loop, more than
  the 2 reviewed`.

Restored, all pass. Probe count, after merging the IFMA exponentiation and
P-384 window probes from master: forty on x86-64 alone, three of them these.
All eighty-four pass on x86-64, and the forty-four on each 32-bit target are
unchanged: 84 + 3 x 44 = 216 gating probe/target checks. The IFMA
exponentiation probes read their own table scan, not this one, and their
counts are as master left them.

After this merged with the AES-GCM probes above: forty-nine on x86-64
alone, ninety-three there, 93 + 3 x 44 = 225 gating probe/target checks.

## P-256 and P-384 on AVX-512 IFMA, 2026-10-13

`nist::ifma` runs P-256's and P-384's three scalar multiplications --
`Point::mul_scalar` (ECDH from key bytes), a prepared key's `Comb::mul` and
the generator table's `gentable::mul` (signing's `k * G`) -- on point
formulas that are each one block of assembly, generated by
`scripts/gen_nist_ifma.py` (`nist::ifma_kernels`). The generator emits no
branch and no address but a base register plus a constant: a selection
between results is `VPBLENDVB` under a mask the caller makes from the digit
without a comparison. Eighteen probes, all x86-64 only, read the compiled
code:

- The fourteen kernels, P-256's and P-384's `double`, `add`, `madd`,
  `madd4`, `from_fp`, `to_fp` and `to_fp4`, each called through the probe
  with buffers as large as any of them uses. Every one is straight-line: no
  finding, nothing excused.
- `ct_p256_ifma_select` and `ct_p384_ifma_select`: `nist::ifma::select`, the
  read each digit of `mul_scalar` makes -- masks from the digit's magnitude
  (`arith::masks_for`, behind its barrier), every one of the sixteen entries
  read and masked in AVX2 (`scan_avx2`), and the digit's sign and zero masks
  computed arithmetically. One finding each, excused as a counter loop
  (ceiling 1): `incq %rax; cmpq $16, %rax; jne`, the scan's loop over the
  entries, rax zeroed before it and written nowhere else in it, the masks
  read at rax and the entries through rdi, which steps one entry (160 or 256
  bytes) a pass. The digit decides only the masks. The first build of these
  probes also failed on a `memcpy` that returned the entry by value; the
  scan now writes into the caller's vector.
- `ct_p256_ifma_from_limbs` and `ct_p384_ifma_from_limbs`: a `to_fp`
  output, a secret-derived coordinate, packed into words and brought below
  p by masked subtractions -- one on P-256, four on P-384, as many as the
  generator's bounds say the value needs. Straight-line. The first version
  packed through a loop over a slice whose positions were runtime values;
  P-384's failed with 33 branches on those positions, and both now pack
  through fixed shifts.

Two mutations, each restored afterwards:

- `if magnitude == 0 { *out = V::zero() } else { scan }` in `select`:
  fails both `select` probes, `je` and `jmp` on the new branch.
- A second masked pass over the entries, with other masks: LLVM fused it
  into the scan's own loop, so there is still one counter loop and both
  probes pass, correctly. That the ceiling holds was checked by lowering
  `ct_p256_ifma_select`'s to zero instead: "1 findings excused as counter
  loop, more than the 0 reviewed", and a failure.

### Not covered

- **The multiplications as a whole.** `table_mul` needs `std`, and the
  probe build has none. `mul_scalar` and `comb_mul` compile without it, but
  besides the probed pieces they hold loops over counts fixed by the curve,
  the digit recoding shared with the `Fp` multiplications
  (`signed_digits_w`, not probed there either, whose test for a window
  straddling two words is on a public bit position, not a loop counter),
  and the complete addition at the end, which without `std` runs P-384's
  generic field, whose loops the rule cannot read as counters ("Prepared
  ECDH public keys" has the same finding). The accumulator's identity is an
  AND of the digits' zero masks, `acc_inf &= zero`; nothing tests it.
- **Valgrind.** Valgrind's CPUID reports no AVX-512, so `scripts/ctgrind.sh`
  runs P-256 ECDH and ECDSA signing on the MULX/ADX path, and this path is
  read by the compiled-code gate alone (docs/CTGRIND.md).

Probe count: fifty-five on x86-64 alone, where there were thirty-seven. All
ninety-nine pass on x86-64, and the forty-four on each 32-bit target are
unchanged: 99 + 3 x 44 = 231 gating probe/target checks.
