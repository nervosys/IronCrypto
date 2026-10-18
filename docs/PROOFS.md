# Bounded proofs

Some of this library's arithmetic is proved, not only tested, with the
[Kani](https://github.com/model-checking/kani) model checker: for every input
in the stated domain, the function computes what its specification says.

```console
$ scripts/kani.sh              # every proof; Linux, with cargo-kani installed
$ scripts/kani.sh -p ic-mldsa  # one crate
```

Kani is not a dependency. The proofs are modules under `#[cfg(kani)]`, which
no ordinary build compiles. Several `ic-ec` proofs use function contracts and
verified stubbing, which Kani 0.68 keeps behind `-Z function-contracts` and
`-Z stubbing`; `scripts/kani.sh` passes both, and `--no-assert-contracts`, so
that a plain harness does not also check the contracts of what it calls (each
contract has its own harness; P-256's schoolbook harnesses replace the
multiplication inside `mac` and need `mac`'s contract left unchecked there).
The polynomial identities under `crates/ic-ec/proofs/smt/` need Z3 or cvc5 and
run with `crates/ic-ec/proofs/smt/run.sh`. Those marked Bitwuzla below need
the [Bitwuzla](https://bitwuzla.github.io) binary on `PATH` (0.9.1 was used,
the static Linux release, installed under `$HOME/.local`).

## What is proved

| crate | function | property | domain |
|---|---|---|---|
| `ic-core` | `ct::Choice` | every constructor yields 0 or 1; `from_u8` means non-zero; `mask`, `not`, `and`, `or`, `unwrap_u8` and the `bool` conversion agree with boolean logic | every value |
| `ic-core` | `ct::select_u8`, `select_u32`, `select_u64` | return `a` when the choice is true and `b` otherwise | every choice and every pair of operands, 2^129 cases for `u64` |
| `ic-core` | `ct::eq`, `ct::verify` | are slice equality, lengths included | every length up to 6 and every content |
| `ic-core` | `ct::lt_be` | is numeric less-than on big-endian strings | every length up to 6 and every content |
| `ic-core` | `ct::is_zero`, `cswap`, `cmov` | mean what they say | every length up to 6 and every content |
| `ic-mldsa` | `rounding::reduce_q` | equals `r mod q` in `[0, q)` | every `i32` |
| `ic-mldsa` | `rounding::power2round` | is FIPS 204 algorithm 35's unique split: the parts sum to `r mod q`, `r0` in `(-2^12, 2^12]`, `r1` in ten bits | every `i32` |
| `ic-mldsa` | `rounding::decompose` | equals FIPS 204 algorithm 36 as written, with its division and its fold, for both `gamma2` | every `i32` |
| `ic-mldsa` | `make_hint`, `use_hint` | satisfy `UseHint(MakeHint(z, r), r + z) = HighBits(r)`, the lemma ML-DSA's correctness rests on | every `r` in `[0, q)` and every `z` with `|z| <= gamma2`, both `gamma2` |
| `ic-ec` | `nist::p256_field::add` | returns `a + b mod p`, in `[0, p)` | every `a`, `b` in `[0, p)` |
| `ic-ec` | `nist::p256_field::sub` | returns `a - b mod p`, in `[0, p)`: adding `b` back gives `a` or `a + p` | every `a`, `b` in `[0, p)` |
| `ic-ec` | `field::Fe::add` | adds limb by limb, with the value of the sum exactly the sum of the values | every limb below `2^63` |
| `ic-ec` | `field::Fe::weak_reduce` | one carry pass preserves the value up to `c4 * p`, and leaves every limb below `2^51 + 64` | every limb below `2^53` |
| `ic-ec` | `field::Fe::sub` | returns `a - b mod p`, with limbs below `2^51 + 96` | `a` limbs below `2^53`, `b` limbs below `2^52 - 38` |
| `ic-ec` | `field::Fe::to_bytes` | returns the unique representative `v` below `p`, with `value = v + k p` for `k` in `0..=4` | every limb below `2^53` |
| `ic-ec` | `p384::Fp::add_raw`, `Fn::add_raw` | returns `a + b mod m`, in `[0, m)`, for `m` the field prime and the group order | every `a`, `b` in `[0, m)` |
| `ic-ec` | `p384::Fp::sub_raw`, `Fn::sub_raw` | returns `a - b mod m`, in `[0, m)`: adding `b` back gives `a` or `a + m` | every `a`, `b` in `[0, m)` |
| `ic-ec` | `p384::canonical` | the closing step of a Montgomery multiplication: returns `v` or `v - m`, below `m`, for `v = t + top 2^384` | every `t`, every `top` in `{0, 1}`, `v < 2m`, both moduli |
| `ic-ec` | `p384::P`, `N` | `P` is `2^384 - 2^128 - 2^96 + 2^32 - 1` computed from the powers of two, and `P`, `N` equal the constants the specifications spell out | no inputs |
| `ic-mlkem` | `poly::montgomery_reduce` | returns `r` with `r 2^16 = a mod q`, in `(-q, q)` | every `a` with `abs(a) < 2^15 q` |
| `ic-mlkem` | `poly::barrett_reduce` | returns `r = a mod q` with `abs(r) <= 1665` | every `i16` |
| `ic-mlkem` | `poly::fqmul` | returns `r` with `r 2^16 = a b mod q`, in `(-q, q)` | every `i16` `a`, `b` in `(-q, q)` |
| `ic-mlkem` | `poly::normalize_coefficient` (the conditional subtraction of `q`) | returns `a mod q` in `[0, q)` | every `i16` |
| `ic-mlkem` | `poly::ZETAS` | every entry is in `[0, q)` | the 128 entries |
| `ic-mlkem` | `poly::ntt_butterfly` | outputs are `a + t` and `a - t` with `t 2^16 = zeta b mod q`, as congruences; no `i16` operation overflows; outputs are within `(k + 1) q` | `abs(zeta) < q`, `a`, `b` within `k q`, `k` in `1..=7` |
| `ic-mlkem` | `encode::compress` | is FIPS 203 equation 4.7, `floor((2^(d+1) x + q) / 2q) mod 2^d` | every `x` in `[0, q)`, every `d` in `1..=12` |
| `ic-mlkem` | `encode::decompress` | is equation 4.8: the integer `r` with `r <= q y / 2^d + 1/2 < r + 1`, in `[0, q)` | every `y` below `2^d`, every `d` in `1..=12` |
| `ic-mlkem` | `Decompress_d(Compress_d(x))` | is within `ceil(q / 2^(d+1))` of `x` modulo `q` (section 4.2.1) | every `x` in `[0, q)`, every `d` in `1..=11` |
| `ic-mlkem` | `encode::reduce_12` | is `(x & 0xfff) mod q`, in `[0, q)`, and the identity below `q` | every `u16` |
| `ic-mlkem` | `encode::pack8`, `unpack8` | for each width the code packs at (1, 4, 5, 10, 11, 12): unpack after pack returns the fields, the bytes above the first `D` are zero, bits above `D` in an input are ignored, and pack after unpack returns the bytes | eight symbolic fields, sixteen symbolic bytes |
| `ic-mlkem` | `scheme::select_key` | writes `K` when the comparison matched and the rejection key otherwise, all 32 bytes | every `K`, rejection key and choice |
| `ic-mlkem` | `ct::eq` at 768 bytes | is slice equality | every pair of 768-byte strings |

### ML-KEM

All of these are plain harnesses in `crates/ic-mlkem/src/{poly,encode,scheme}/proofs.rs`,
run by `scripts/kani.sh -p ic-mlkem` (18 harnesses, 4 minutes on a 24-thread
machine with other work running; the multipliers cost the most: `fqmul`
34 s, `montgomery_reduce` 31 s, the butterfly 62 s, the 768-byte comparison
51 s, everything else under 6 s). Specifications are congruences and ranges
over `i64`, or FIPS 203's rounding written as its defining inequalities; none
reads a constant from the code under test.

Findings while writing them:

- `barrett_reduce`'s doc comment said `[-q/2, q/2]`. The first version of the
  harness asserted `[-1664, 1664]` and Kani refused it: `a = 11652` returns 1665
  and `a = -31626` returns -1665, because `20158 = floor(2^26 / q)` is one short
  of the true quotient at the extremes. The proved bound is `[-1665, 1665]`;
  nothing depended on the narrower one, and the comment now says so.
- `compress`'s comment said `40318 = floor(2^27 / q)`. It is the ceiling (the
  floor is 40317). The proof holds for either constant, so the arithmetic was
  never wrong; the comment is corrected.

Three small refactors made the units provable, with no change to behaviour:
`normalize_coefficient` (the loop body of `normalize_portable`), `ntt_butterfly`
(the body of the NTT inner loop, `inline(always)`), and `select_key` (the byte
loop of `select_shared_secret`). Both constant-time gates were rerun after them on
2026-10-17: `scripts/check-ct.py` passed on all five targets (131 probes on
x86-64, at e8c593e), and `ctgrind.sh` reported the counts of
[CTGRIND.md](CTGRIND.md) unchanged, ML-KEM's included (at dc690fc). The full
Kani run at dc690fc verified all 63 harnesses.

Not proved here, and what covers it:

- The seven-layer bound of the NTT is the single-step bound applied seven times
  (inputs below `q` in magnitude, outputs below `8 q = 26632` after the last
  layer); the induction is argued, the step is proved. `inv_ntt`, `basemul`
  and the AVX2 code are tested against the portable code and against the
  schoolbook product, not proved.
- `ct::eq` is proved at 768 bytes and, in `ic-core`, up to length 6. The other
  ciphertext lengths (1088 and 1568) are the same loop and are not separately
  proved. `ct::eq` and `select_u8` are `ic-core`'s proofs; decapsulation's
  re-encryption and the comparison's inputs are not.
- Whole-polynomial `byte_encode`/`byte_decode` (the chunking of 256
  coefficients into groups of eight) is tested, not proved; the group
  pack/unpack is.
- `black_box` is an identity to Kani. The barriers that keep the compiled code
  branch-free are checked by `scripts/check-ct.py`, not here.

### P-384

`crates/ic-ec/src/p384/proofs.rs`, 7 harnesses, 94 s in all (`Fn` subtraction
39 s, `Fp` subtraction 25 s, the rest under 4 s). They mirror P-256's `add` and
`sub` and the `finish` step, over the macro-generated six-word code that both
P-384 rings use on every target, and `canonical`, the closing subtraction of
the x86-64 multiplication (the generic `mont_mul_raw` ends in the same
expression, inline).

Not proved: the Montgomery multiplication itself (`arith::wide::mont_mul`, a
6-by-6 word CIOS loop nest) and so P-384 `mul` and `square`. P-256's reduction
needed a decomposition into function contracts and a half hour of Bitwuzla for
four words; the same method on six words and the multiplication was not
attempted in this pass. P-384 multiplication is tested against big-integer
arithmetic and published vectors, and the x86-64 assembly against the portable
code.

### Multiplication and reduction

These are function contracts. Each has a `proof_for_contract` harness that
checks the function's body against its contract over the whole domain; a
harness marked "over" a contract replaces that callee with its contract
(`stub_verified`) instead of running its code. Such a proof rests on the
callee's own proof: it says nothing unless that one passes too, and
`scripts/kani.sh` runs them all. Times are Kani's verification time for the
harness, measured with other proofs running on the same 24-thread machine,
so they are an upper bound on a quiet one.

| function | property | domain | over | solver | time |
|---|---|---|---|---|---|
| `p256_field::mac` | `lo + 2^64 hi = a + b c + carry`, no overflow | every input | | Bitwuzla | 31 s |
| `p256_field::mont_step` | `2^64 out = w + w0 p`, with `w0 p` written as `w0 (2^256 - 2^224 + 2^192 + 2^96 - 1)`, no multiplication | every `w` | | Bitwuzla | 331 s |
| `p256_field::montgomery_low` | `2^256 out = lo + U p` for the textbook digits (`u_i` is word `i` of `lo + sum_{j<i} u_j p 2^(64 j)`, since `-p^-1 = 1 mod 2^64`), and `out <= p` | every `lo` | `mont_step` | Bitwuzla | 1563 s |
| `p256_field::finish` | `out < p`, and `hi + w` is `out` or `out + p` | `hi < p`, `w <= p` | | CaDiCaL | 21 s |
| `p256_field::reduce` | `out < p` and `2^256 out = t + U p - e 2^256 p`, `e` in `{0, 1}`: `out = t 2^-256 mod p` | every `t` with upper half below `p` | `montgomery_low`, `finish` | Bitwuzla | 1066 s |
| (specification) | the integer `a b`, and `a^2`, has upper half below `p`: a product of residues is in `reduce`'s domain | every `a`, `b` below `p` | | Bitwuzla | 87 s |
| `p256_field::mul`'s schoolbook (`schoolbook!`, as `product`), linear part | with each 64-by-64 product replaced by an arbitrary `p_k <= (2^64 - 1)^2`: exactly sixteen products are asked for, the `k`-th of `a_i` and `b_j` in row-major order, and the eight words returned are `sum_k p_k 2^(64 (i_k + j_k))`, which is below `2^512` | every `a`, `b`, and every sixteen `p_k` | | CaDiCaL | 73 s |
| `p256_field::square`'s schoolbook (`schoolbook_square!`, as `square_product`), linear part | likewise: ten products asked for, `a_0 a_1`, `a_0 a_2`, `a_0 a_3`, `a_1 a_2`, `a_1 a_3`, `a_2 a_3`, then `a_i a_i`, and the eight words are `sum_{i<j} 2 p_ij 2^(64 (i + j)) + sum_i p_ii 2^(128 i)`; the code's doubling by shifts is checked against adding twice | every `a`, and every ten `p` | | Bitwuzla | 446 s (Kissat 509 s, CaDiCaL 1018 s) |
| (polynomial identity) | `sum_{i,j<4} a_i b_j 2^(64 (i + j)) = (sum a_i 2^(64 i)) (sum b_j 2^(64 j))` | every integer `a_i`, `b_j` | | Z3, cvc5 | 0.10 s, 0.03 s |
| (polynomial identity) | `sum_{i<j} 2 a_i a_j 2^(64 (i + j)) + sum a_i^2 2^(128 i) = (sum a_i 2^(64 i))^2` | every integer `a_i` | | Z3, cvc5 | 0.13 s, 0.03 s |
| `field::carry_reduce` | the result is congruent to the five columns mod `p` (exact identity with witness `k`), limb 0 below `2^51 + 2^14`, the rest below `2^51` | every column below `95 * 2^104` | | CaDiCaL | 1490 s |
| `field::mul_columns` | the columns equal `sum_{i+j=k} a_i b_j + sum_{i+j=k+5} a_i (19 b_j)`, exactly, with no overflow | every limb below `2^52` | | Bitwuzla | 481 s |
| `field::square_columns` | the columns equal `sum_{i<=j, i+j=k mod 5} (c_ij a_i) a_j`, `c_ij` = 2 for `i != j` times 19 for `i + j >= 5`, exactly | every limb below `2^52` | | Bitwuzla | 222 s |
| `field::Fe::mul` | `mul_columns` is called in its domain and its promised columns are in `carry_reduce`'s | every limb below `2^52` | `mul_columns`, `carry_reduce` | CaDiCaL | 53 s |
| `field::Fe::square` | the same for `square_columns` | every limb below `2^52` | `square_columns`, `carry_reduce` | CaDiCaL | 60 s |

Put together: P-256's `reduce` is proved to be Montgomery reduction, canonical,
for every input its callers can give it, and a product of two residues is
proved to be such an input. P-256's portable `mul` and `square` are proved to
compute `a b 2^-256 mod p` and `a^2 2^-256 mod p`, canonical, for every `a`,
`b` below `p`, with two steps argued rather than machine-checked: that the
schoolbook's linear proof, which holds for every value of its sixteen (ten)
products, holds for the true ones, and the final substitution of the product
into `reduce`'s proved contract (next section). Curve25519's `mul` and
`square` are proved to hand `carry_reduce` columns in its domain, equal to the schoolbook columns as the
code writes them, and `carry_reduce` is proved to reduce any such columns
correctly. That `mul` returns what `carry_reduce` promises for those columns
is substitution through two proved contracts, not a separate Kani run: a
harness asserting it, which evaluates `carry_reduce`'s postcondition twice,
gave no verdict in 25 minutes.

### The products: a linear and a nonlinear part

Every earlier attempt at P-256's schoolbook asked a solver to relate sixteen
symbolic 64-by-64 multiplications, regrouped by carry chains, to the integer
product, and none answered (below). Even with `mac` replaced by its contract
the multiplications stay, because the contract says `b c`. The proof now
separates what is about carries from what is about multiplication.

1. **`mac`** (proved, Bitwuzla): `lo + 2^64 hi = a + b c + carry`.
2. **Linear part** (Kani, no multiplication in the formula). The harnesses
   replace the one multiplication in `mac`, `u128::wrapping_mul`, with
   `product_abstract`: it returns an arbitrary `p <= (2^64 - 1)^2`, the only
   property every true product of two words has, and appends its operands and
   `p` to a ghost log (`static mut` arrays, `cfg(kani)` only). Everything else
   -- `mac`'s two additions, checked for overflow, the split into words, every
   carry of the schoolbook, the doubling shifts of the square -- runs as
   written. With `a` and `b` unconstrained, the harness asserts that the log
   has exactly sixteen entries (ten for the square), that entry `k` multiplied
   `a_i` by `b_j` for the `k`-th pair of the schedule (row-major; for the
   square the six cross pairs, then the four diagonal), and that the eight
   words returned equal `sum_k p_k 2^(64 (i_k + j_k))` (for the square,
   `sum_{i<j} 2 p_ij 2^(64 (i + j)) + sum_i p_ii 2^(128 i)`, the doubling as
   two additions), computed in nine words with plain carries by the proof's
   own loops, with the ninth word asserted zero. The dumped SMT2 formula of
   the square's harness contains no `bvmul` at all; the product's runs on
   CaDiCaL.
3. **Nonlinear part** (SMT over the integers, `crates/ic-ec/proofs/smt/`,
   `run.sh`). `sum_{i,j} a_i b_j 2^(64 (i + j)) = a b` and
   `sum_{i<j} 2 a_i a_j 2^(64 (i + j)) + sum_i a_i^2 2^(128 i) = a^2`, with
   `a = sum a_i 2^(64 i)`, stated in QF_NIA with the negation asserted, for
   every integer `a_i`, `b_j` (no word bounds needed). Z3 5.1.0 and cvc5 1.4.2
   both answer `unsat` in under 0.2 s. These are facts about polynomials, not
   about the code. Two negative controls, a term at the wrong weight and a
   cross product not doubled, must answer `sat`, and do.
4. **Composition, argued**. The step from 2 to the code as it runs is an
   instantiation: the linear harness holds for every value the sixteen
   products can take within the bound, and the real `wrapping_mul` of two
   words returns their product `b c <= (2^64 - 1)^2` (which is also what
   `mac`'s proved contract says), so the real schoolbook returns
   `sum a_i b_j 2^(64 (i + j))` exactly: `product_spec(a, b)`, the same
   function the proofs use for the integer product, evaluated on the true
   word products. Kani proves one formula with free `p_k`; the substitution
   `p_k := a_i b_j` is done by hand. By 3, `product_spec(a, b)` is the integer
   `a b` (it is below `2^512`, so its eight words hold it exactly). By the
   domain lemma above, it is in `reduce`'s domain for `a`, `b` below `p`, and
   `reduce`'s proved contract then gives `out < p` and `2^256 out = a b mod
   p`; `mul` is `reduce` applied to the schoolbook, so that is what `mul`
   returns. The same for `square`, with `square_spec` and the squaring
   identity. This last substitution was written as a harness --
   `proof_for_contract(mul)` with the product replaced by "any eight words
   equal to `product_spec(a, b)`" and `reduce` by its verified contract, and
   the same for `square` -- and neither gave a verdict in 30 minutes on
   Bitwuzla (each run twice), as the comparable harness over the old product
   contract did not before. So it is argued too, and the harnesses are not
   kept.

`mul` and `square` keep their compiled code. The schoolbooks are macros,
`schoolbook!` and `schoolbook_square!`, expanded in `mul` and `square` in an
ordinary build and in the Kani-only functions `product` and `square_product`,
which the harnesses call: the same tokens in both. Factoring the schoolbook
out as an `#[inline(always)]` function instead changed the release code: the computation of `mul` itself was the same
instructions, but the compiler then inlined `mul` into its callers (on
aarch64, `Fp::mul` and the rest: 61 out-of-line calls became inlined copies,
`umulh` count 1415 to 1795) and scheduled the reduction's carries differently
there. With the macros, the release assembly of `ic-ec` is byte-identical to
before on `x86_64-pc-windows-msvc` and `aarch64-unknown-linux-gnu`, checked
with two exported probe functions calling `mul` and `square`, so no timing
comparison was needed.

With these harnesses and `--no-assert-contracts`, `scripts/kani.sh -p ic-ec`
verified all 20 `ic-ec` harnesses (958 s wall clock with `--jobs 8
--output-format=terse`).

### Solvers

Kani's default solver, CaDiCaL, bit-blasts every multiplication. The earlier
attempt at `mont_step` ran 25 minutes without a verdict on it.
[Bitwuzla](https://bitwuzla.github.io), an SMT solver that abstracts
multiplications and refines them lazily, closes `mont_step` in minutes once
its specification has no multiplication in it.

CBMC 6.11, as bundled with Kani 0.68, encodes a *checked* multiplication
wrongly in the SMT-LIB encoding it writes when datatypes are off, the one Kani
uses for Bitwuzla: it
builds the 65-bit result-and-flag tuple as `concat(product[63:0], overflow)`
and reads it back as `concat(overflow, product)`, so the value is the product
shifted left one bit and the flag is its bit 63. A four-line C program
reproduces it: `__builtin_mul_overflow(x, 19, &r)` with `x < 2^59` fails under
`cbmc --bitwuzla` and verifies under the default SAT back end, `--smt2` (Z3
through text, with datatypes), and CBMC's native `--z3` and `--cvc5` back
ends, which encode the tuple as a struct. The dumped flattened formula, from
`--bitwuzla` or from `--smt2 --outfile`, is satisfiable under Bitwuzla, Z3 and
cvc5 alike, so the fault is CBMC's encoding, not the solver's. Reported as
[diffblue/cbmc#9215](https://github.com/diffblue/cbmc/issues/9215). Found here as a
false overflow report on `19 * c4`. A checked multiplication through that back
end is therefore wrong in both directions, not only noisy. Every proof run
through Bitwuzla here has none:

- the code multiplies with `wrapping_mul` where a product is taken: `mac`'s
  64-by-64 product, `field::m`, and the 19, 38 and 2 scalings in
  `mul_columns` and `square_columns`. None of these can wrap for the inputs
  they are given, and the compiled code is the same instruction. Behaviour
  outside the domain changes in a debug build only: an out-of-range limb that
  used to panic in the scaling now wraps, as it always did in release.
- the specifications multiply with `wrapping_mul` and stay below the width;
- the SMT2 formula of every Bitwuzla harness was dumped
  (`--cbmc-args --outfile`) and contains no checked-multiplication encoding.
  Index arithmetic such as `64 * k` is constant once loops unroll and is folded
  before the formula is written. For the schoolbook harnesses: the square's
  linear harness has no `bvmul` at all.

`carry_reduce`'s postcondition multiplies `19 * k` checked, so it and the
harnesses that assume it run on CaDiCaL.

### How the specifications are written

The specifications compute with plain word loops, independently of the code:
`p` is written out again rather than read from the code, `u p` from the shape
of `p` with shifts, products as sums of word products at their weights. Three
choices keep them fast without weakening them:

- they compute modulo `2^(64 N)`, without asserting that nothing carries out,
  at a width `N` where every true value compared is below `2^(64 N)`, so
  equality of the computed values is equality of the integers;
- they have no branches: `lt` is the borrow of a subtraction, `eq` a
  conjunction of word equalities, `&&` and `||` are `&` and `|`. Two calls of a
  branching helper on equal inputs carry different path conditions and stop
  looking alike to the solver, and `==` on arrays becomes a byte-wise
  `memcmp`;
- they contain no assertions, because a stubbed call assumes its contract's
  postcondition and an assertion inside it would be an obligation at every
  call.

### What was tried and did not finish

Each ran 25 minutes without a verdict unless noted.

- P-256's schoolbook, `mul`'s sixteen multiply-adds against the integer
  product: as a whole on Bitwuzla and Z3 (Kissat and CaDiCaL stopped after 16
  and 10 minutes); with each multiply-add replaced by `mac`'s contract on
  Bitwuzla and CaDiCaL (Kissat stopped after 16); split into four rows,
  `r + x b` of four multiply-adds each, where a single row did not finish on
  Bitwuzla or Z3, with or without `mac`'s contract, and the product over the
  rows' contract did not finish on Bitwuzla, CaDiCaL or Z3. The word
  products are the same terms in code and specification; what the solvers do
  not close is the carry chains regrouped. `square`'s ten-multiplication
  schoolbook: Bitwuzla. These are what the linear/nonlinear split above
  replaces.
- The composition of the split with `reduce` (`mul` and `square` against
  `out < p`, `2^256 out = a b mod p`, over "eight words equal to
  `product_spec`" and `reduce`'s contract): Bitwuzla, 30 minutes, twice each.
  Their dumped formulas contain only the specification's unchecked
  `wrapping_mul`s (32 and 20 `bvmul`), so the CBMC fault above is not the
  cause.
- Curve25519's columns against `19 a_i b_j` rather than `a_i (19 b_j)`: the
  lemma `x (19 y) = 19 (x y)` for 52-bit `x`, `y` alone, on CaDiCaL and Kissat,
  and on Bitwuzla with the multiplications wrapping.
- A harness asserting `mul`'s final postcondition through both stubbed
  contracts, for both fields, instead of the call checks above.
- `mont_step` on CaDiCaL, with the product shared between code and
  specification (about 20 minutes, stopped).

## Checked against broken code

Each proof was checked against a broken function: masking one bit out of
`select_u64`, and adding `q - 2` instead of `q` in `reduce_q`, each makes its
proof fail. The `ic-ec` proofs were checked the same way, each against one
mutation of the function it proves, and each failed:

| function | mutation | failed in |
|---|---|---|
| `p256_field::finish` | top-word overflow dropped (`need = 1 - b`) | 29 s; as a contract, 3 s |
| `p256_field::add` | top-word overflow dropped (`need = 1 - b0`) | 40 s |
| `p256_field::sub` | carry into the second word of the add-back dropped | 22 s |
| `p256_field::mac` | incoming carry dropped | 0.4 s |
| `p256_field::mont_step` | carry from the first word's addition into the second dropped | 3 s |
| `p256_field::mont_step` | `P[3]` replaced by `P[3] - 2` | 4 s |
| `p256_field::montgomery_low` | three steps instead of four | 1381 s |
| `p256_field::reduce` | two words of the upper half swapped | 1254 s, in its postcondition and in `finish`'s precondition at the call |
| (product domain) | `a` no longer assumed below `p` | 66 s |
| `field::Fe::weak_reduce` | `19 * c4` changed to `18 * c4` | 20 s |
| `field::carry_reduce` | `c[4] * 19` changed to `c[4] * 18` | 30 s; as a contract, 1882 s |
| `field::mul_columns` | `b[4] * 19` changed to `b[4] * 18` | 498 s |
| `field::mul_columns` | `a_4 (19 b_1)` in column 1 where `a_4 (19 b_2)` belongs | 965 s |
| `field::square_columns` | `38 a_1` changed to `37 a_1` | 155 s |
| `field::Fe::to_bytes` | `19 * q` changed to `18 * q` | 77 s |
| `field::Fe::add` | `+` changed to `^` | 22 s |
| `field::Fe::sub` | one limb of `2p` changed by one | 36 s |
| `Fe::mul` call check | domain widened to limbs below `2^53` | 73 s, in `mul_columns`' precondition at the call |
| `p256_field` schoolbook | two products' columns swapped (`a_0 b_2` computed where `a_0 b_1` belongs, and the reverse) | 123 s, in the schedule assertion |
| `p256_field` schoolbook | carry into `a_1 b_1`'s multiply-add dropped | 28 s |
| `p256_field` square schoolbook | low word of the diagonal `a_1^2` doubled | 13 s (CaDiCaL: 22 s) |
| `p256_field` square schoolbook | low word of the cross products not doubled (`r1 << 1` dropped) | 12 s (CaDiCaL: 20 s) |
| (polynomial identity) | `a_1 b_2` at weight `2^(64 * 4)` instead of `2^(64 * 3)` | `sat`, Z3 0.13 s, cvc5 0.06 s (kept as a negative control) |
| (polynomial identity) | `a_0 a_1` not doubled | `sat`, Z3 0.12 s, cvc5 0.04 s (kept as a negative control) |
| `poly::montgomery_reduce` | `Q_INV` -3327 changed to -3328 | congruence |
| `poly::barrett_reduce` | rounding constant `1 << 25` changed to `1 << 24`; separately `V` reduced by 40 | range |
| `poly::normalize_coefficient` | added `q - 1` instead of `q` | congruence |
| `poly::fqmul` | product plus one | congruence |
| `poly::ntt_butterfly` | second output `a + t` where `a - t` belongs | congruence |
| `encode::compress` | multiplier 40318 changed to 40300; separately the final correction removed | equation 4.7 |
| `encode::decompress` | rounding term `1 << (d - 1)` changed to `1 << d` | equation 4.8 |
| `encode::compress` | rounding term `q / 2` changed to `q / 4` | error bound |
| `encode::reduce_12` | added `q - 1` instead of `q` | the reduction |
| `encode::pack8` | field 7 shifted one bit too far at width 11 | round trip, both directions |
| `encode::unpack8` | mask halved at width 12 | round trip, both directions |
| `scheme::select_key` | `K` and the rejection key swapped | selection |
| `ct::eq` | loop starts at 1 | equality at 768 bytes |
| `arith::add_raw` | final carry dropped (`need = carry`) | P-384 `Fp` add; with `need = 1 - borrow`, `Fn` add |
| `arith::sub_raw` | modulus mask halved; separately mask forced to zero | P-384 `Fp` and `Fn` subtraction |
| `p384::canonical` | the top word dropped from the selector; separately `borrow` for `1 - borrow` | both moduli |

Two mutants of the ML-KEM proofs were not caught and are not failures of the
proofs. Raising `barrett_reduce`'s `V` to 20159 (the value an old AVX2 comment
named) still returns a representative within the proved range, so the harness
passes: it is a different valid reduction, not a wrong one. Changing
`compress`'s multiplier to 40317 (the floor) still computes `Compress_d`
exactly, as the harness says. Neither is an error the specification could see,
which is the point of writing it from the definition. The ML-KEM and P-384
mutations were applied to the working tree, one at a time, the harness run
against it (at its own name, with `--harness`), and the tree restored; each is
a one-line `sed` edit, and each of the rows above failed. Restoring a file from
a copy gives it an older modification time than the mutant build, and the next
run then reused the mutant (the first full run after the mutations failed
`ct::eq` at 768 bytes for that reason); `touch` restored files, then rerun.

The mutations were applied to the working tree, the proof run, and the code
restored, one at a time, each on the solver its proof uses (the schoolbook
ones to a copy of the tree, so that the unmutated proofs could run beside
them). The constant check that `p` has the shape the specifications use has no
symbolic input and was not mutated.

## What a proof here is not

- **Not a proof of constant time.** These establish what a function computes.
  Whether its compiled code branches on a secret is answered by
  `scripts/check-ct.py` and `scripts/ctgrind.sh`.
- **Not a proof of the whole algorithm.** ML-DSA's rounding is proved; its
  sampling, NTT and encoding are tested against NIST's vectors, not proved.
  ML-KEM's scalar reductions, compression, group packing and the butterfly's
  bound are proved; its NTT as a whole, sampling, matrix products and the
  AVX2 code are tested, not proved.
- **Not a proof at the level of the compiled code.** Graviola's s2n-bignum
  routines are proved to the instruction in HOL Light. These are bounded
  checks of Rust semantics, on the portable code; the x86-64 assembly and
  the AVX2 paths that run in practice are tested against it, not proved.
- **Field multiplication is proved in part.** On P-256 the portable `mul`
  and `square` are proved end to end, `a b 2^-256 mod p` canonical for every
  `a`, `b` below `p`, except for two argued steps: that the schoolbook's
  linear proof, over arbitrary products, applies to the true ones, and the
  substitution of the product into `reduce`'s contract ("The products"
  above). The polynomial identities are checked by Z3 and cvc5 over the
  integers, outside Kani. On
  Curve25519 the column sums of `mul` and `square` are proved equal to the
  schoolbook written as the code multiplies, `a_i (19 b_j)` and `(c a_i) a_j`,
  and in `carry_reduce`'s domain, and `carry_reduce` is proved for any columns
  in that domain. That those columns are `a b` mod `p` rests on `2^255 = 19 mod
  p` and on `a_i (19 b_j) = 19 a_i b_j`, integer arithmetic no solver here
  closed for 52-bit limbs; it is argued, not machine-checked. The final step
  of each composition, substituting one proved contract into the next, is
  argued too. `mul121666` is not proved.
- **Contract proofs are only as good as the contracts they stand on.** A
  proof over a stubbed callee holds if the callee's own proof does. All of
  them are run together.
- **Not Graviola's kind of proof.** Graviola carries s2n-bignum's routines,
  proved in HOL Light down to the machine instructions. These are proved at
  the level of Rust semantics by bounded model checking, and the slice proofs
  are bounded in length. The x86-64 assembly the P-256 field runs on x86-64 is
  tested against the portable code, not proved.
- **The solvers are trusted.** A proof here is a solver's "unsatisfiable".
  One of them was found to be fed a wrong formula for checked
  multiplication (above); the mutations above are the check that each proof
  can fail at all.
- Kani runs on Linux only; the proofs were run under WSL.
