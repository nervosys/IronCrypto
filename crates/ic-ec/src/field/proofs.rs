//! Bounded proofs of the portable Curve25519 field's addition, subtraction,
//! carry propagation and canonical encoding, for Kani.
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
//! removed), together with bounds on the limbs produced. Multiplication is not
//! covered: these are the reductions that follow it.

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

/// `carry_reduce` takes five 128-bit column sums and returns a field element.
/// For columns below `95 * 2^104` (five products of 52-bit limbs, each doubled
/// or multiplied by 19 at most), the result is congruent to the input mod `p`,
/// and its limbs are below `2^51` except limb 0, which is below `2^51 + 2^14`.
///
/// The parallel step splits each column into 51 bits and a carry, and folds the
/// top carry back as `19 * c4`. The serial pass then carries once more. Taking
/// `top = floor(y / 2^255)` for the value `y` after the parallel step, the
/// identity is `value(r) = value(out) + (c4 + top) * p`, which is exact.
#[kani::proof]
fn carry_reduce_keeps_the_value_mod_p_and_bounds_the_limbs() {
    let bound: u128 = 95 << 104;
    let r0: u128 = kani::any();
    let r1: u128 = kani::any();
    let r2: u128 = kani::any();
    let r3: u128 = kani::any();
    let r4: u128 = kani::any();
    for col in [r0, r1, r2, r3, r4] {
        kani::assume(col < bound);
    }
    let r = [r0, r1, r2, r3, r4];
    let out = carry_reduce(r0, r1, r2, r3, r4);

    // The parallel step on the specification's own carries.
    let c: [u128; 5] = core::array::from_fn(|i| r[i] >> 51);
    let mut y = [0u128; N];
    y[0] = (r[0] & M51) + 19 * c[4];
    for i in 1..5 {
        y[i] = (r[i] & M51) + c[i - 1];
    }
    let d = canon(y);
    let top = d[5] as u128 + ((d[6] as u128) << 51);
    let k = c[4] + top;

    // `value(r) = value(out) + k * p` is `value(r) + 19 k = value(out) + k * 2^255`,
    // since `p = 2^255 - 19`. Written that way it has no multiplication by a
    // symbolic value: `19 k` is a constant multiple, and `k * 2^255` sits in
    // base-2^51 digit 5. That keeps the solver off the multiplier.
    let mut value_r = [0u128; N];
    value_r[..5].copy_from_slice(&r);
    let mut nineteen_k = [0u128; N];
    nineteen_k[0] = 19 * k;
    let mut k_at_255 = [0u128; N];
    k_at_255[5] = k;
    assert_eq!(
        canon(plus(value_r, nineteen_k)),
        canon(plus(value(out.0), k_at_255))
    );
    assert!(out.0[0] < (1 << 51) + (1 << 14));
    for limb in &out.0[1..] {
        assert!(*limb < 1 << 51);
    }
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
