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

Each proof was checked against a broken function: masking one bit out of
`select_u64`, and adding `q - 2` instead of `q` in `reduce_q`, each makes its
proof fail.

## What a proof here is not

- **Not a proof of constant time.** These establish what a function computes.
  Whether its compiled code branches on a secret is answered by
  `scripts/check-ct.py` and `scripts/ctgrind.sh`.
- **Not a proof of the whole algorithm.** ML-DSA's rounding is proved; its
  sampling, NTT and encoding are tested against NIST's vectors, not proved.
- **Not Graviola's kind of proof.** Graviola carries s2n-bignum's routines,
  proved in HOL Light down to the machine instructions. These are proved at
  the level of Rust semantics by bounded model checking, and the slice proofs
  are bounded in length. Field and scalar multiplication of 256-bit values
  are beyond what this approach finishes, and are tested, not proved.
- Kani runs on Linux only; the proofs were run under WSL.
