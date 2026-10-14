//! Bounded proofs of the portable Curve25519 field's addition, subtraction,
//! multiplication's column sums, carry propagation and canonical encoding, for
//! Kani.
//!
//! ```text
//! scripts/kani.sh -p ic-ec
//! ```
//!
//! Field elements are five 51-bit limbs, and the value of a limb vector is the
//! integer `sum l_i * 2^(51 i)`. Every specification here is written in those
//! integers, not in the limb arithmetic the code uses. A value is held as
//! coefficients of `2^(51 j)` and reduced to canonical base-2^51 digits by a
//! plain carry loop (`canon`). Two values are equal exactly when their digits
//! are. `p = 2^255 - 19` is written out again below rather than read from the
//! code, and the proofs use the identity `2^255 = p + 19` only where it is the
//! statement being checked.
//!
//! What is proved is value preservation modulo `p`, stated as an exact integer
//! identity with an explicit witness `k` (the multiple of `p` the reduction
//! removed), together with bounds on the limbs produced.
//!
//! Multiplication and squaring are `carry_reduce` applied to five column sums.
//! Each half is a function contract with its own proof: the columns equal
//! [`mul_columns_spec`] (or [`square_columns_spec`]) exactly, for limbs below
//! `2^52`; `carry_reduce` maps any columns in its domain to a congruent,
//! bounded element. A third proof checks that `mul` and `square` call both
//! within their domains, over the two contracts. What the solver does not show
//! is that the columns are the product mod `p`: the specification multiplies
//! as the code does, `a_i (19 b_j)`, and `a_i (19 b_j) = 19 a_i b_j` is the
//! associativity of integer multiplication, which no solver tried closed in 25
//! minutes for 52-bit limbs.

use super::*;

/// Digits in base 2^51 for every value the proofs reach: up to 357 bits, which
/// covers a carry column of the largest product input here.
const N: usize = 7;

const M51: u128 = (1 << 51) - 1;

/// `p = 2^255 - 19` in base 2^51: the digit `2^51 - 19`, then four of `2^51 - 1`.
const P51: [u128; N] = [(1 << 51) - 19, M51, M51, M51, M51, 0, 0];

/// `2p` in base 2^51: `2*(2^51 - 19)`, then four of `2*(2^51 - 1)`.
const TWO_P51: [u128; N] = [
    (1 << 52) - 38,
    (1 << 52) - 2,
    (1 << 52) - 2,
    (1 << 52) - 2,
    (1 << 52) - 2,
    0,
    0,
];

/// The integer `sum c_j * 2^(51 j)`, in canonical base-2^51 digits: every digit
/// below `2^51`, carries propagated one digit at a time. The sum must fit `N`
/// digits, which the assertion checks.
fn canon(c: [u128; N]) -> [u64; N] {
    let mut out = [0u64; N];
    let mut acc: u128 = 0;
    for j in 0..N {
        acc += c[j];
        out[j] = (acc & M51) as u64;
        acc >>= 51;
    }
    assert_eq!(acc, 0);
    out
}

/// `canon` without the assertion: the digits of the value modulo
/// `2^(51 N)`. For the contract postcondition below, which a stubbed call
/// assumes, so an assertion inside it would be an obligation at every call.
/// Every value it is applied to there is below `2^320`, well inside
/// `2^(51 N) = 2^357`, so equal digits still mean equal integers.
fn canon_mod(c: [u128; N]) -> [u64; N] {
    let mut out = [0u64; N];
    let mut acc: u128 = 0;
    for j in 0..N {
        acc += c[j];
        out[j] = (acc & M51) as u64;
        acc >>= 51;
    }
    out
}

/// `a < b` for canonical digit arrays, by scanning from the most significant.
fn lt_digits(a: &[u64; N], b: &[u64; N]) -> bool {
    for i in (0..N).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// Five limbs as coefficients.
fn value(l: [u64; 5]) -> [u128; N] {
    let mut c = [0u128; N];
    for i in 0..5 {
        c[i] = l[i] as u128;
    }
    c
}

/// Coefficient-wise sum.
fn plus(a: [u128; N], b: [u128; N]) -> [u128; N] {
    let mut r = [0u128; N];
    for j in 0..N {
        r[j] = a[j] + b[j];
    }
    r
}

/// `k * p` as coefficients.
fn times_p(k: u128) -> [u128; N] {
    let mut r = [0u128; N];
    for j in 0..N {
        r[j] = P51[j] * k;
    }
    r
}

/// `Fe::add` is limbwise addition: for limbs below `2^63` no limb overflows,
/// and the value of the result is the sum of the values, exactly.
#[kani::proof]
fn add_is_the_sum_of_the_values() {
    let a: [u64; 5] = kani::any();
    let b: [u64; 5] = kani::any();
    for limb in a {
        kani::assume(limb < 1 << 63);
    }
    for limb in b {
        kani::assume(limb < 1 << 63);
    }
    let out = Fe(a).add(&Fe(b));
    assert_eq!(canon(value(out.0)), canon(plus(value(a), value(b))));
}

/// `weak_reduce` is one carry pass, for limbs below `2^53`, which is the bound
/// `sub` establishes before calling it.
///
/// The value is preserved modulo `p` by the exact identity
/// `value(in) = value(out) + c4 * p`, where `c4` is the carry taken off the
/// top limb: that carry is `c4 * 2^255 = c4 * (p + 19)`, and the `19 * c4`
/// returns to limb 0. Every output limb is below `2^51 + 64`.
#[kani::proof]
fn weak_reduce_keeps_the_value_mod_p_and_bounds_the_limbs() {
    let r: [u64; 5] = kani::any();
    for limb in r {
        kani::assume(limb < 1 << 53);
    }
    let out = Fe(r).weak_reduce();
    let c4 = (r[4] >> 51) as u128;
    assert_eq!(canon(value(r)), canon(plus(value(out.0), times_p(c4))));
    for limb in out.0 {
        assert!(limb < (1 << 51) + 64);
    }
}

/// `sub` is `a - b mod p` for limbs `a` below `2^53` and `b` below `2^52 - 38`
/// (the least of `2p`'s limbs, so no limb of `2p - b` goes negative).
///
/// With `raw = a + 2p - b` limbwise and `c4` the carry off its top limb,
/// `value(a) + 2p = value(out) + value(b) + c4 * p`, so `out` is `a - b` mod
/// `p`. The raw limbs reach `2^53 + 2^52`, not `2^53`, because `2p`'s limbs
/// are near `2^52`: the top carry is then at most 5, so limb 0 is bounded by
/// `2^51 + 95` and the others by `2^51 + 6`. Every limb is below `2^51 + 96`.
#[kani::proof]
fn sub_is_a_minus_b_mod_p_with_bounded_limbs() {
    let a: [u64; 5] = kani::any();
    let b: [u64; 5] = kani::any();
    for limb in a {
        kani::assume(limb < 1 << 53);
    }
    for limb in b {
        kani::assume(limb < (1 << 52) - 38);
    }
    let out = Fe(a).sub(&Fe(b));
    let raw: [u128; 5] = core::array::from_fn(|i| a[i] as u128 + TWO_P51[i] - b[i] as u128);
    let c4 = raw[4] >> 51;
    assert_eq!(
        canon(plus(value(a), TWO_P51)),
        canon(plus(plus(value(out.0), value(b)), times_p(c4)))
    );
    for limb in out.0 {
        assert!(limb < (1 << 51) + 96);
    }
}

/// The domain of `carry_reduce`: every column below `95 * 2^104`, five
/// products of 52-bit limbs, each doubled or multiplied by 19 at most.
pub(super) fn carry_reduce_pre(r: [u128; 5]) -> bool {
    let mut ok = true;
    for i in 0..5 {
        ok &= r[i] < 95 << 104;
    }
    ok
}

/// What `carry_reduce` promises: the result is congruent to the columns mod
/// `p`, and its limbs are below `2^51` except limb 0, which is below
/// `2^51 + 2^14`.
///
/// The parallel step splits each column into 51 bits and a carry, and folds the
/// top carry back as `19 * c4`. The serial pass then carries once more. Taking
/// `top = floor(y / 2^255)` for the value `y` after the parallel step, the
/// identity is `value(r) = value(out) + (c4 + top) * p`, which is exact.
pub(super) fn carry_reduce_post(r: [u128; 5], out: &Fe) -> bool {
    // The parallel step on the specification's own carries.
    let mut c = [0u128; 5];
    for i in 0..5 {
        c[i] = r[i] >> 51;
    }
    let mut y = [0u128; N];
    y[0] = (r[0] & M51) + 19 * c[4];
    for i in 1..5 {
        y[i] = (r[i] & M51) + c[i - 1];
    }
    let d = canon_mod(y);
    let top = d[5] as u128 + ((d[6] as u128) << 51);
    let k = c[4] + top;

    // `value(r) = value(out) + k * p` is `value(r) + 19 k = value(out) + k * 2^255`,
    // since `p = 2^255 - 19`. Written that way it has no multiplication by a
    // symbolic value: `19 k` is a constant multiple, and `k * 2^255` sits in
    // base-2^51 digit 5. That keeps the solver off the multiplier.
    let mut value_r = [0u128; N];
    for i in 0..5 {
        value_r[i] = r[i];
    }
    let mut nineteen_k = [0u128; N];
    nineteen_k[0] = 19 * k;
    let mut k_at_255 = [0u128; N];
    k_at_255[5] = k;
    let (x, y) = (
        canon_mod(plus(value_r, nineteen_k)),
        canon_mod(plus(value(out.0), k_at_255)),
    );
    let mut same = true;
    for j in 0..N {
        same &= x[j] == y[j];
    }
    same & (out.0[0] < (1 << 51) + (1 << 14))
        & (out.0[1] < 1 << 51)
        & (out.0[2] < 1 << 51)
        & (out.0[3] < 1 << 51)
        & (out.0[4] < 1 << 51)
}

/// `carry_reduce` meets its contract for every five columns in its domain.
#[kani::proof_for_contract(carry_reduce)]
fn carry_reduce_meets_its_contract() {
    carry_reduce(
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
        kani::any(),
    );
}

/// `to_bytes` is the unique representative: the 32 bytes, read as an integer
/// `v`, satisfy `v < p`, and `value(in) = v + k * p` for some `k` in `0..=4`.
/// The domain is limbs below `2^53`; such a value is below `5p`, so the
/// quotient `k` is in that range, and the proof checks every `k` in it.
#[kani::proof]
fn to_bytes_is_the_canonical_representative_below_p() {
    let r: [u64; 5] = kani::any();
    for limb in r {
        kani::assume(limb < 1 << 53);
    }
    let bytes = Fe(r).to_bytes();

    // The bytes as an integer, read bit by bit into base-2^51 digits.
    let mut v = [0u128; N];
    for bit in 0..256 {
        let b = ((bytes[bit / 8] >> (bit % 8)) & 1) as u128;
        v[bit / 51] += b << (bit % 51);
    }
    let vd = canon(v);
    assert!(lt_digits(&vd, &canon(P51)));

    let inp = canon(value(r));
    assert!((0..5u128).any(|k| canon(plus(v, times_p(k))) == inp));
}

// ---------------------------------------------------------------------------
// The products.
// ---------------------------------------------------------------------------

impl kani::Arbitrary for Fe {
    fn any() -> Fe {
        Fe(kani::any())
    }
}

/// Every limb below `2^52`: the domain of `mul` and `square`.
pub(super) fn limbs52(a: &[u64; 5]) -> bool {
    let mut ok = true;
    for i in 0..5 {
        ok &= a[i] < 1 << 52;
    }
    ok
}

/// Five limbs, each below `2^52`.
fn any_limbs52() -> [u64; 5] {
    let a: [u64; 5] = kani::any();
    kani::assume(limbs52(&a));
    a
}

/// `a = b`, as a conjunction of equalities rather than `==`, which on arrays
/// is a byte-wise `memcmp`; see the P-256 proofs.
pub(super) fn eq128(a: &[u128; 5], b: &[u128; 5]) -> bool {
    let mut same = true;
    for i in 0..5 {
        same &= a[i] == b[i];
    }
    same
}

/// `x * y` for two limbs, as a `u128`. `wrapping_mul` only to keep the model
/// checker off a 256-bit overflow test: a product of two 64-bit values is
/// below `2^128` and never wraps.
fn limb_product(x: u64, y: u64) -> u128 {
    (x as u128).wrapping_mul(y as u128)
}

/// `c * x` for a limb `x` below `2^52` and `c` at most 38: below `2^58`, so the
/// 64-bit product is exact. `wrapping_mul` only because a checked one is
/// mis-encoded on the SMT path (see the P-256 proofs); it never wraps here.
fn scaled(x: u64, c: u64) -> u64 {
    x.wrapping_mul(c)
}

/// The column sums of `a b` folded by `2^255 = 19 mod p`: column `k` is
/// `sum_{i+j=k} a_i b_j + sum_{i+j=k+5} a_i (19 b_j)`. A product of weight
/// `2^(51 (i+j))` with `i + j >= 5` is `2^255 2^(51 (i+j-5))`, and `2^255 =
/// 19 mod p`, so it moves down five limbs with a factor of 19. The 19 is
/// carried on the limb, `a_i (19 b_j)`, which is how the code multiplies.
pub(super) fn mul_columns_spec(a: [u64; 5], b: [u64; 5]) -> [u128; 5] {
    let mut cols = [0u128; 5];
    for i in 0..5 {
        for j in 0..5 {
            if i + j < 5 {
                cols[i + j] += limb_product(a[i], b[j]);
            } else {
                cols[i + j - 5] += limb_product(a[i], scaled(b[j], 19));
            }
        }
    }
    cols
}

/// The column sums of `a^2` folded the same way, over unordered pairs: for
/// `i <= j`, `a_i a_j` with coefficient `c_ij`, 2 when `i != j` (the pair
/// appears twice in `a a`) times 19 when `i + j >= 5`, the coefficient carried
/// on the lower-index limb, `(c_ij a_i) a_j`, which is how the code multiplies.
pub(super) fn square_columns_spec(a: [u64; 5]) -> [u128; 5] {
    let mut cols = [0u128; 5];
    for i in 0..5 {
        for j in i..5 {
            let c = if i == j { 1 } else { 2 } * if i + j >= 5 { 19 } else { 1 };
            cols[(i + j) % 5] += limb_product(scaled(a[i], c), a[j]);
        }
    }
    cols
}

/// `mul_columns` computes [`mul_columns_spec`] for every pair of limb vectors
/// below `2^52`, without overflow.
#[kani::proof_for_contract(mul_columns)]
#[kani::solver(bitwuzla)]
fn mul_columns_meets_its_contract() {
    let (a, b): ([u64; 5], [u64; 5]) = (kani::any(), kani::any());
    mul_columns(&a, &b);
}

/// `square_columns` computes [`square_columns_spec`] for every limb vector
/// below `2^52`, without overflow.
#[kani::proof_for_contract(square_columns)]
#[kani::solver(bitwuzla)]
fn square_columns_meets_its_contract() {
    let a: [u64; 5] = kani::any();
    square_columns(&a);
}

/// `Fe::mul` is `carry_reduce(mul_columns(a, b))`. For limbs below `2^52` this
/// checks both calls against the contracts proved above: `mul_columns`' domain
/// holds, and the columns it promises, [`mul_columns_spec`], lie in
/// `carry_reduce`'s domain, every column below `95 * 2^104`. With the two
/// postconditions that makes `mul`'s result congruent mod `p` to the columns
/// of [`mul_columns_spec`], with limbs below `2^51` but limb 0, below
/// `2^51 + 2^14`. That last step is substitution, and is not a Kani run: the
/// harness asserting it, which evaluates `carry_reduce`'s postcondition twice,
/// ran 25 minutes without a verdict.
#[kani::proof]
#[kani::stub_verified(mul_columns)]
#[kani::stub_verified(carry_reduce)]
fn mul_calls_stay_in_their_contracts() {
    let (a, b) = (any_limbs52(), any_limbs52());
    Fe(a).mul(&Fe(b));
}

/// `Fe::square` is `carry_reduce(square_columns(a))`, checked the same way.
#[kani::proof]
#[kani::stub_verified(square_columns)]
#[kani::stub_verified(carry_reduce)]
fn square_calls_stay_in_their_contracts() {
    let a = any_limbs52();
    Fe(a).square();
}
