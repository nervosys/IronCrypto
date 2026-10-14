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
`-Z stubbing`; `scripts/kani.sh` passes both. Those marked Bitwuzla below need
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
| (specification) | the integer `a b`, and `a^2`, has upper half below `p`: a product of residues is in `reduce`'s domain | every `a`, `b` below `p` | | Bitwuzla | 427 s |
| `field::carry_reduce` | the result is congruent to the five columns mod `p` (exact identity with witness `k`), limb 0 below `2^51 + 2^14`, the rest below `2^51` | every column below `95 * 2^104` | | CaDiCaL | 1490 s |
| `field::mul_columns` | the columns equal `sum_{i+j=k} a_i b_j + sum_{i+j=k+5} a_i (19 b_j)`, exactly, with no overflow | every limb below `2^52` | | Bitwuzla | 481 s |
| `field::square_columns` | the columns equal `sum_{i<=j, i+j=k mod 5} (c_ij a_i) a_j`, `c_ij` = 2 for `i != j` times 19 for `i + j >= 5`, exactly | every limb below `2^52` | | Bitwuzla | 222 s |
| `field::Fe::mul` | `mul_columns` is called in its domain and its promised columns are in `carry_reduce`'s | every limb below `2^52` | `mul_columns`, `carry_reduce` | CaDiCaL | 53 s |
| `field::Fe::square` | the same for `square_columns` | every limb below `2^52` | `square_columns`, `carry_reduce` | CaDiCaL | 60 s |

Put together: P-256's `reduce` is proved to be Montgomery reduction, canonical,
for every input its callers can give it, and a product of two residues is
proved to be such an input. Curve25519's `mul` and `square` are proved to hand
`carry_reduce` columns in its domain, equal to the schoolbook columns as the
code writes them, and `carry_reduce` is proved to reduce any such columns
correctly. That `mul` returns what `carry_reduce` promises for those columns
is substitution through two proved contracts, not a separate Kani run: a
harness asserting it, which evaluates `carry_reduce`'s postcondition twice,
gave no verdict in 25 minutes.

### Solvers

Kani's default solver, CaDiCaL, bit-blasts every multiplication. The earlier
attempt at `mont_step` ran 25 minutes without a verdict on it.
[Bitwuzla](https://bitwuzla.github.io), an SMT solver that abstracts
multiplications and refines them lazily, closes `mont_step` in minutes once
its specification has no multiplication in it.

Kani reaches Bitwuzla, Z3 and cvc5 through CBMC's SMT2 output, and CBMC 6.11
encodes a *checked* multiplication there wrongly: it builds the result and the
overflow flag into one bit-vector in one order and reads them back in the
other, so the value is the product shifted left one bit and the flag is its
top bit. The SAT path (CaDiCaL, Kissat) is not affected. Found here as a false
overflow report: `19 * c4` for `c4 < 2^59.6` failed under Bitwuzla and passed
under Z3 and CaDiCaL, and the dumped formula shows the swap. A checked
multiplication through the SMT path is therefore wrong in both directions,
not only noisy. Every proof run through Bitwuzla here has none:

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
  before the formula is written.

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
  schoolbook: Bitwuzla. Neither is proved, and the code keeps its original
  shape.
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

The mutations were applied to the working tree, the proof run, and the code
restored, one at a time, each on the solver its proof uses. The
constant check that `p` has the shape the specifications use has no
symbolic input and was not mutated.

## What a proof here is not

- **Not a proof of constant time.** These establish what a function computes.
  Whether its compiled code branches on a secret is answered by
  `scripts/check-ct.py` and `scripts/ctgrind.sh`.
- **Not a proof of the whole algorithm.** ML-DSA's rounding is proved; its
  sampling, NTT and encoding are tested against NIST's vectors, not proved.
- **Field multiplication is proved in part.** On P-256 the Montgomery
  reduction is proved, and that a product of residues is in its domain; the
  schoolbook products that compute that product, in `mul` and `square`, are
  tested and not proved, so `mul` and `square` as a whole are not. On
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
