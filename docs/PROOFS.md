# Bounded proofs

Some of this library's arithmetic is proved, not only tested, with the
[Kani](https://github.com/model-checking/kani) model checker: for every input
in the stated domain, the function computes what its specification says.

```console
$ scripts/kani.sh              # every proof; Linux, with cargo-kani installed
$ scripts/kani.sh -p ic-mldsa  # one crate
```

Kani is not a dependency. The proofs are modules under `#[cfg(kani)]`, which
no ordinary build compiles.

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
| `ic-ec` | `nist::p256_field::finish` | returns `hi + w mod p`, in `[0, p)` | every `hi` in `[0, p)` and `w` at most `p` |
| `ic-ec` | `field::Fe::add` | adds limb by limb, with the value of the sum exactly the sum of the values | every limb below `2^63` |
| `ic-ec` | `field::Fe::weak_reduce` | one carry pass preserves the value up to `c4 * p`, and leaves every limb below `2^51 + 64` | every limb below `2^53` |
| `ic-ec` | `field::Fe::sub` | returns `a - b mod p`, with limbs below `2^51 + 96` | `a` limbs below `2^53`, `b` limbs below `2^52 - 38` |
| `ic-ec` | `field::carry_reduce` | returns the five column sums reduced mod `p`, with limb 0 below `2^51 + 2^14` and the rest below `2^51` | every column below `95 * 2^104` (five products of 52-bit limbs, weighted by 19 at most) |
| `ic-ec` | `field::Fe::to_bytes` | returns the unique representative `v` below `p`, with `value = v + k p` for `k` in `0..=4` | every limb below `2^53` |

Each proof was checked against a broken function: masking one bit out of
`select_u64`, and adding `q - 2` instead of `q` in `reduce_q`, each makes its
proof fail. The `ic-ec` proofs were checked the same way, each against one
mutation of the function it proves, and each failed:

| function | mutation | failed in |
|---|---|---|
| `p256_field::finish` | top-word overflow dropped (`need = 1 - b`) | 29 s |
| `p256_field::add` | top-word overflow dropped (`need = 1 - b0`) | 40 s |
| `p256_field::sub` | carry into the second word of the add-back dropped | 22 s |
| `field::Fe::weak_reduce` | `19 * c4` changed to `18 * c4` | 20 s |
| `field::carry_reduce` | `c[4] * 19` changed to `c[4] * 18` | 30 s |
| `field::Fe::to_bytes` | `19 * q` changed to `18 * q` | 77 s |
| `field::Fe::add` | `+` changed to `^` | 22 s |
| `field::Fe::sub` | one limb of `2p` changed by one | 36 s |

The mutations were applied to the working tree, the proof run, and the code
restored, one at a time.

## What a proof here is not

- **Not a proof of constant time.** These establish what a function computes.
  Whether its compiled code branches on a secret is answered by
  `scripts/check-ct.py` and `scripts/ctgrind.sh`.
- **Not a proof of the whole algorithm.** ML-DSA's rounding is proved; its
  sampling, NTT and encoding are tested against NIST's vectors, not proved.
- **Field multiplication is not proved.** The additions, subtractions,
  carry passes and canonical reductions above are proved; the multiplications
  they serve are tested. On P-256, the Montgomery reduction (`reduce`) is not
  proved: its step (`mont_step`, one 64-bit product by the constant `P[3]`) and
  the four-step `montgomery_low` each ran for 25 minutes in Kani's solver
  without a verdict, both as a product and as shifts and adds, so they are
  left out rather than proved in part. Its final conditional subtraction
  (`finish`) is proved. On Curve25519, `mul` and `square` are not proved;
  `carry_reduce` is proved for any column sums in its domain, not for the
  products that feed it.
- **Not Graviola's kind of proof.** Graviola carries s2n-bignum's routines,
  proved in HOL Light down to the machine instructions. These are proved at
  the level of Rust semantics by bounded model checking, and the slice proofs
  are bounded in length.
- Kani runs on Linux only; the proofs were run under WSL.
