//! P-384's arithmetic on MULX/ADX, where the CPU has it.
//!
//! The arithmetic is generated: the field operations and point formulas,
//! specialised to the prime, into `p384_x86_point`, and the scalar ring's
//! multiplication, generic in the modulus, into `mont_x86`. This is the
//! dispatch, the one place they are called from. `None` where the CPU lacks
//! BMI2 or ADX, and the caller then uses the generic arithmetic, which
//! computes the same function.

use super::p256_x86::{has_adx, Ladder, Secret};
use core::mem::MaybeUninit;

/// `a * b * 2^-384` modulo P-384's prime, canonical; `None` without BMI2
/// and ADX.
#[inline(always)]
pub(crate) fn mul_p(a: &[u64; 6], b: &[u64; 6]) -> Option<[u64; 6]> {
    if !has_adx() {
        return None;
    }
    let mut buf = slots::<24>(&[a, b]);
    // SAFETY: the CPU has BMI2 and ADX; every field element is below the
    // prime. The block writes `out`, slot 2.
    unsafe {
        super::p384_x86_point::fmul_adx(&mut buf);
        let [r] = read(&buf, super::p384_x86_point::FMUL_OUT);
        Some(r)
    }
}

/// `a^2 * 2^-384` modulo P-384's prime, canonical; `None` without BMI2 and
/// ADX.
#[inline(always)]
pub(crate) fn sqr_p(a: &[u64; 6]) -> Option<[u64; 6]> {
    if !has_adx() {
        return None;
    }
    let mut buf = slots::<18>(&[a]);
    // SAFETY: as for `mul_p`; the block writes `out`, slot 1.
    unsafe {
        super::p384_x86_point::fsqr_adx(&mut buf);
        let [r] = read(&buf, super::p384_x86_point::FSQR_OUT);
        Some(r)
    }
}

/// `a + b` modulo P-384's prime, through the assembly the point formulas
/// use; for the tests, which hold it to the generic addition.
#[cfg(test)]
pub(crate) fn add_p(a: &[u64; 6], b: &[u64; 6]) -> Option<[u64; 6]> {
    if !has_adx() {
        return None;
    }
    let mut buf = slots::<24>(&[a, b]);
    // SAFETY: as for `mul_p`.
    unsafe {
        super::p384_x86_point::fadd_adx(&mut buf);
        let [r] = read(&buf, super::p384_x86_point::FADD_OUT);
        Some(r)
    }
}

/// `cm * a - dm * b` modulo P-384's prime, through the fused operation the
/// doubling uses, for each `(cm, dm)` it uses; for the tests.
#[cfg(test)]
pub(crate) fn cms_p(cm: u64, dm: u64, a: &[u64; 6], b: &[u64; 6]) -> Option<[u64; 6]> {
    if !has_adx() {
        return None;
    }
    let mut buf = slots::<24>(&[a, b]);
    // SAFETY: as for `mul_p`.
    unsafe {
        use super::p384_x86_point as f;
        let out = match (cm, dm) {
            (3, 8) => {
                f::fcms_3_8_adx(&mut buf);
                f::FCMS_3_8_OUT
            }
            (4, 1) => {
                f::fcms_4_1_adx(&mut buf);
                f::FCMS_4_1_OUT
            }
            (12, 9) => {
                f::fcms_12_9_adx(&mut buf);
                f::FCMS_12_9_OUT
            }
            _ => return None,
        };
        let [r] = read(&buf, out);
        Some(r)
    }
}

/// `a - b` modulo P-384's prime, the same way.
#[cfg(test)]
pub(crate) fn sub_p(a: &[u64; 6], b: &[u64; 6]) -> Option<[u64; 6]> {
    if !has_adx() {
        return None;
    }
    let mut buf = slots::<24>(&[a, b]);
    // SAFETY: as for `mul_p`.
    unsafe {
        super::p384_x86_point::fsub_adx(&mut buf);
        let [r] = read(&buf, super::p384_x86_point::FSUB_OUT);
        Some(r)
    }
}

/// The table scan of `p256_x86::scan`, in SSE2, over affine P-384 points as
/// their twelve words: `OR` over the entries of each masked by its mask, every
/// entry read, so the selected one is never an address.
#[inline]
pub(crate) fn scan_affine(
    entries: &[crate::nist::point::AffinePoint<crate::p384::P384>],
    masks: &[u64],
) -> crate::nist::point::AffinePoint<crate::p384::P384> {
    use crate::nist::point::AffinePoint;
    use crate::p384::Fp;
    const _: () = assert!(core::mem::size_of::<AffinePoint<crate::p384::P384>>() == 96);
    // SAFETY: `AffinePoint` is `repr(C)` over two `Fp`, each a
    // `repr(transparent)` `[u64; 6]`, so a slice of them is a slice of
    // `[u64; 12]` of the same length, alignment and lifetime; the assertion
    // above holds the size to that.
    let words: &[[u64; 12]] =
        // SAFETY: `entries` is a live slice of `AffinePoint`, whose layout the comment
        // above covers; the pointer and element count are the slice's own.
        unsafe { core::slice::from_raw_parts(entries.as_ptr().cast(), entries.len()) };
    let w = super::p256_x86::scan(words, masks);
    AffinePoint {
        x: Fp([w[0], w[1], w[2], w[3], w[4], w[5]]),
        y: Fp([w[6], w[7], w[8], w[9], w[10], w[11]]),
    }
}

/// The same over Jacobian P-384 points, as their eighteen words.
#[inline]
pub(crate) fn scan_point(
    entries: &[crate::nist::point::Point<crate::p384::P384>],
    masks: &[u64],
) -> [[u64; 6]; 3] {
    use crate::nist::point::Point;
    const _: () = assert!(core::mem::size_of::<Point<crate::p384::P384>>() == 144);
    // SAFETY: `Point` is `repr(C)` over three `Fp`, each a
    // `repr(transparent)` `[u64; 6]`; as for `scan_affine`.
    let words: &[[u64; 18]] =
        unsafe { core::slice::from_raw_parts(entries.as_ptr().cast(), entries.len()) };
    let w = super::p256_x86::scan(words, masks);
    [
        [w[0], w[1], w[2], w[3], w[4], w[5]],
        [w[6], w[7], w[8], w[9], w[10], w[11]],
        [w[12], w[13], w[14], w[15], w[16], w[17]],
    ]
}

/// A formula's slots with `values` in the first ones, the rest left
/// uninitialised: the formula writes every slot it reads but these.
#[inline(always)]
fn slots<const L: usize>(values: &[&[u64; 6]]) -> [MaybeUninit<u64>; L] {
    let mut buf = [const { MaybeUninit::uninit() }; L];
    for (i, v) in values.iter().enumerate() {
        for (j, w) in v.iter().enumerate() {
            buf[6 * i + j].write(*w);
        }
    }
    buf
}

/// Field elements from the slots `first..first + K`.
///
/// # Safety
///
/// The formula must have written those slots.
#[inline(always)]
unsafe fn read<const L: usize, const K: usize>(
    buf: &[MaybeUninit<u64>; L],
    first: usize,
) -> [[u64; 6]; K] {
    let mut out = [[0u64; 6]; K];
    for (k, value) in out.iter_mut().enumerate() {
        for (j, w) in value.iter_mut().enumerate() {
            // SAFETY: the caller guarantees the slot was written.
            *w = unsafe { buf[6 * (first + k) + j].assume_init() };
        }
    }
    out
}

// `read` takes the outputs as contiguous slots: X3, Y3, Z3, and then H and R.
const _: () = {
    use super::p384_x86_point as f;
    assert!(f::DOUBLE_Y3 == f::DOUBLE_X3 + 1 && f::DOUBLE_Z3 == f::DOUBLE_X3 + 2);
    assert!(
        f::DOUBLE_IN_PLACE_Y == f::DOUBLE_IN_PLACE_X + 1
            && f::DOUBLE_IN_PLACE_Z == f::DOUBLE_IN_PLACE_X + 2
    );
    assert!(f::ADD_Y3 == f::ADD_X3 + 1 && f::ADD_Z3 == f::ADD_X3 + 2);
    assert!(f::ADD_H == f::ADD_X3 + 3 && f::ADD_R == f::ADD_H + 1);
    assert!(f::ADD_AFFINE_Y3 == f::ADD_AFFINE_X3 + 1 && f::ADD_AFFINE_Z3 == f::ADD_AFFINE_X3 + 2);
    assert!(f::ADD_AFFINE_H == f::ADD_AFFINE_X3 + 3 && f::ADD_AFFINE_R == f::ADD_AFFINE_H + 1);
};

/// Jacobian doubling as one block of assembly; `None` without BMI2 and ADX.
#[inline(always)]
pub(crate) fn point_double(p: [&[u64; 6]; 3]) -> Option<[[u64; 6]; 3]> {
    if !has_adx() {
        return None;
    }
    let mut buf = slots::<96>(&p);
    // SAFETY: the CPU has BMI2 and ADX; the formula writes X3, Y3, Z3, slots
    // 3 to 5.
    unsafe {
        super::p384_x86_point::double_adx(&mut buf);
        Some(read(&buf, super::p384_x86_point::DOUBLE_X3))
    }
}

/// The Jacobian addition formula as one block of assembly, with `h` and `r`;
/// `None` without BMI2 and ADX.
#[inline(always)]
#[allow(clippy::type_complexity)]
pub(crate) fn point_add(
    p: [&[u64; 6]; 3],
    q: [&[u64; 6]; 3],
) -> Option<([[u64; 6]; 3], [u64; 6], [u64; 6])> {
    if !has_adx() {
        return None;
    }
    let mut buf = slots::<150>(&[p[0], p[1], p[2], q[0], q[1], q[2]]);
    // SAFETY: the CPU has BMI2 and ADX; the formula writes X3, Y3, Z3, H, R,
    // slots 6 to 10.
    unsafe {
        super::p384_x86_point::add_adx(&mut buf);
        let [h, r] = read(&buf, super::p384_x86_point::ADD_H);
        Some((read(&buf, super::p384_x86_point::ADD_X3), h, r))
    }
}

/// The mixed addition formula as one block of assembly, with `h` and `r`;
/// `None` without BMI2 and ADX.
#[inline(always)]
#[allow(clippy::type_complexity)]
pub(crate) fn point_add_affine(
    p: [&[u64; 6]; 3],
    q: [&[u64; 6]; 2],
) -> Option<([[u64; 6]; 3], [u64; 6], [u64; 6])> {
    if !has_adx() {
        return None;
    }
    let mut buf = slots::<126>(&[p[0], p[1], p[2], q[0], q[1]]);
    // SAFETY: the CPU has BMI2 and ADX; the formula writes X3, Y3, Z3, H, R,
    // slots 5 to 9.
    unsafe {
        super::p384_x86_point::add_affine_adx(&mut buf);
        let [h, r] = read(&buf, super::p384_x86_point::ADD_AFFINE_H);
        Some((read(&buf, super::p384_x86_point::ADD_AFFINE_X3), h, r))
    }
}

/// Words of the buffer [`mul_scalar`] keeps: the mixed addition's slots,
/// the most of any formula it runs. The doubling in place uses a prefix.
pub(crate) const LADDER: usize = 126;

/// `scalar * p`, as `Point::mul_scalar` -- the same digits, doublings and
/// additions -- with the window affine, on one buffer kept for the whole
/// multiplication; `None` without BMI2 and ADX.
///
/// The window is `gentable::AffineWindow`'s: the sixteen multiples of `p`,
/// normalised with one inversion for all of them. That costs an inversion
/// and about a hundred multiplications more than the Jacobian window to
/// build, and makes each of the 76 additions after it a mixed one, seven
/// multiplications and four squarings where the Jacobian addition takes
/// eleven and five: measured, 3.5 percent of a multiplication less. (On
/// P-256 the same sum, from the measured costs, comes out even -- 51
/// additions 26 ns cheaper against about 1.8 us more to build -- so
/// `p256_x86::mul_scalar` keeps the Jacobian window; that was estimated,
/// not measured.)
///
/// The accumulator lives in the buffer's first three slots, where both
/// `double_in_place_adx` and `add_affine_adx` read it, so the five
/// doublings of a digit run back to back on it in place, and nothing is
/// copied in or out but each digit's entry and the addition's result.
///
/// The additions are `Point::mul_scalar`'s, and the argument there for why
/// they may be incomplete holds unchanged: the same accumulator meets the
/// same multiples. The identity cases are `Point::add_affine_unequal_or_keep`'s
/// selections -- the accumulator at infinity takes the entry, a zero digit
/// keeps the accumulator -- on the same masks behind the same barrier. The
/// top digit starts the accumulator, or the identity for a zero digit; the
/// last addition is the complete one, `AffineWindow::add_to`'s. A `p` at
/// infinity has no affine multiples: its window is zeros, which the loop
/// runs through, and the result is the identity, selected at the end.
pub(crate) fn mul_scalar(
    p: &crate::nist::point::Point<crate::p384::P384>,
    scalar: &<crate::p384::P384 as crate::nist::point::Curve>::Scalar,
) -> Option<crate::nist::point::Point<crate::p384::P384>> {
    use super::gentable::{digit_count, signed_digits_w, AffineWindow, ENTRIES, WIDTH};
    use crate::nist::arith::{select, Field};
    use crate::nist::point::Point;
    use crate::p384::{Fp, P384};
    use ic_core::ct::Choice;
    if !has_adx() {
        return None;
    }
    let secret_bytes = Secret::new(scalar.to_bytes());
    let bytes = secret_bytes.as_ref();
    let digits = Secret::new(signed_digits_w(bytes, WIDTH));
    let n = digit_count(bytes.len(), WIDTH);
    let window = AffineWindow::<P384, ENTRIES>::new(p);
    // The selected entry's coordinates, one guarded slot for every digit.
    let mut xy = Secret::new((Fp::ZERO, Fp::ZERO));

    let mut buf = Ladder::<LADDER>::new();
    let put = |buf: &mut [MaybeUninit<u64>; LADDER], slot: usize, w: &[u64; 6]| {
        for (j, x) in w.iter().enumerate() {
            buf[6 * slot + j].write(*x);
        }
    };
    let identity = Point::<P384>::identity();
    *xy = window.select(digits[n - 1]);
    let top: &(Fp, Fp) = &xy;
    let top_zero = core::hint::black_box(zero_digit(digits[n - 1]));
    put(
        &mut buf,
        super::p384_x86_point::DOUBLE_IN_PLACE_X,
        &select(top_zero, identity.x().0, top.0 .0),
    );
    put(&mut buf, 1, &select(top_zero, identity.y().0, top.1 .0));
    put(&mut buf, 2, &select(top_zero, identity.z().0, Fp::ONE.0));
    let doublings = |buf: &mut [MaybeUninit<u64>; LADDER]| {
        let ip: &mut [MaybeUninit<u64>; 78] = (&mut buf[..78])
            .try_into()
            .expect("the doubling's slots are a prefix of the buffer");
        for _ in 0..WIDTH {
            // SAFETY: the CPU has BMI2 and ADX; X, Y and Z, slots 0 to 2,
            // hold the accumulator, every coordinate below p.
            unsafe { super::p384_x86_point::double_in_place_adx(ip) };
        }
    };
    for i in (1..n - 1).rev() {
        // The scan first: it does not depend on the accumulator.
        *xy = window.select(digits[i]);
        doublings(&mut buf);
        // SAFETY: the CPU has BMI2 and ADX, and slots 0 to 2 hold the
        // accumulator.
        let cur: &(Fp, Fp) = &xy;
        unsafe { ladder_add(&mut buf, &cur.0 .0, &cur.1 .0, digits[i]) };
    }
    doublings(&mut buf);
    // SAFETY: slots 0 to 2 are written.
    let [x, y, z] = unsafe { read::<LADDER, 3>(&buf, super::p384_x86_point::DOUBLE_IN_PLACE_X) };
    let acc = Point::from_coordinates(Fp(x), Fp(y), Fp(z));
    let mut out = window.add_to(&acc, digits[0], true);
    let base_inf = core::hint::black_box(p.z().zero_mask());
    Point::cmov(&mut out, &identity, Choice::from_u8((base_inf & 1) as u8));
    Some(out)
}

/// All ones for a zero digit, which adds the identity: as in
/// `AffineWindow::add_to`.
#[inline(always)]
fn zero_digit(d: i8) -> u64 {
    ((d as u8 as u64).wrapping_sub(1) >> 63).wrapping_neg()
}

/// One digit's addition in [`mul_scalar`], after its doublings: `(x, y)`,
/// the window's entry for `digit`, added to the accumulator in slots 0 to 2
/// by the mixed addition, and the identity cases selected as
/// `Point::add_affine_unequal_or_keep` selects them -- the accumulator at
/// infinity takes the entry, a zero digit keeps the accumulator -- both
/// tests behind one barrier. The `ct_p384_ladder_add` probe is this and the
/// entry's read.
///
/// # Safety
///
/// The CPU must support BMI2 and ADX, and slots 0 to 2 must hold a point,
/// every coordinate below p.
#[inline(always)]
pub(crate) unsafe fn ladder_add(
    buf: &mut [MaybeUninit<u64>; LADDER],
    x: &[u64; 6],
    y: &[u64; 6],
    digit: i8,
) {
    use crate::nist::arith::{select, Field};
    use crate::p384::Fp;
    let put = |buf: &mut [MaybeUninit<u64>; LADDER], slot: usize, w: &[u64; 6]| {
        for (j, v) in w.iter().enumerate() {
            buf[6 * slot + j].write(*v);
        }
    };
    put(buf, 3, x);
    put(buf, 4, y);
    // SAFETY: the caller guarantees the instructions and slots 0 to 2;
    // slots 3 and 4 are written above, below p. The formula writes X3, Y3,
    // Z3, slots 5 to 7.
    unsafe { super::p384_x86_point::add_affine_adx(buf) };
    // SAFETY: slots 0 to 7 are written.
    let [ax, ay, az, _, _, sx, sy, sz] = unsafe { read::<LADDER, 8>(buf, 0) };
    let [acc_inf, keep] = core::hint::black_box([Fp(az).zero_mask(), zero_digit(digit)]);
    let lifted = [*x, *y, Fp::ONE.0];
    for (k, (a, (l, s))) in [ax, ay, az]
        .iter()
        .zip(lifted.iter().zip([sx, sy, sz].iter()))
        .enumerate()
    {
        let r = select(acc_inf, *l, *s);
        put(buf, k, &select(keep, *a, r));
    }
}

/// The same modulo P-384's group order.
#[inline(always)]
pub(crate) fn mul_n(a: &[u64; 6], b: &[u64; 6]) -> Option<([u64; 6], u64)> {
    if !has_adx() {
        return None;
    }
    // SAFETY: as for `mul_p`; every scalar is below the order.
    Some(unsafe { super::mont_x86::mul_p384_n(a, b) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nist::arith::{compute_neg_inv, wide};
    use crate::nist::point::Curve;
    use crate::p384::P384;

    /// SplitMix64.
    fn next(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Below `m`: uniform, or built from whole words of zeros and ones.
    fn operand(state: &mut u64, m: &[u64; 6], structured: bool) -> [u64; 6] {
        loop {
            let r = next(state);
            let mut x = [0u64; 6];
            for (i, w) in x.iter_mut().enumerate() {
                *w = if structured {
                    match (r >> (2 * i)) & 3 {
                        0 => 0,
                        1 => u64::MAX,
                        2 => next(state),
                        _ => 1 << (next(state) % 64),
                    }
                } else {
                    next(state)
                };
            }
            if wide::sbb(x, *m).1 == 1 {
                return x;
            }
        }
    }

    /// Values below `m` that sit on the reductions' edges: zero, one and
    /// two; `m` less one, two and three; the halves of `m`; `2^384 - m`
    /// (which is `R mod m`, the Montgomery one) and its neighbours; powers
    /// of two at and around the words and at the places p has its terms
    /// (32, 96, 128), and `m` less each of them; and words of all ones and
    /// zeros below the top.
    fn edges(m: &[u64; 6]) -> std::vec::Vec<[u64; 6]> {
        let one = [1u64, 0, 0, 0, 0, 0];
        let small = |v: u64| [v, 0, 0, 0, 0, 0];
        let half = {
            // (m - 1) / 2: m is odd.
            let mut h = *m;
            for i in 0..6 {
                h[i] = (h[i] >> 1) | if i < 5 { h[i + 1] << 63 } else { 0 };
            }
            h
        };
        let c = wide::sbb([0; 6], *m).0;
        let mut out = std::vec![
            [0u64; 6],
            one,
            small(2),
            wide::sbb(*m, one).0,
            wide::sbb(*m, small(2)).0,
            wide::sbb(*m, small(3)).0,
            half,
            wide::adc(half, one).0,
            c,
            wide::sbb(c, one).0,
            wide::adc(c, one).0,
            [u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, m[5] - 1],
            [u64::MAX, 0, u64::MAX, 0, u64::MAX, m[5] >> 1],
            [0, u64::MAX, 0, u64::MAX, 0, m[5] >> 1],
        ];
        for k in [
            1, 31, 32, 33, 63, 64, 65, 95, 96, 97, 127, 128, 129, 191, 192, 255, 256, 320, 382, 383,
        ] {
            let mut x = [0u64; 6];
            x[k / 64] = 1 << (k % 64);
            if wide::sbb(x, *m).1 == 1 {
                out.push(x);
                out.push(wide::sbb(*m, x).0);
                out.push(wide::sbb(x, one).0);
            }
        }
        out
    }

    /// `a * b mod 2^384`.
    fn mul_lo(a: &[u64; 6], b: &[u64; 6]) -> [u64; 6] {
        let mut r = [0u64; 6];
        for i in 0..6 {
            let mut carry = 0u128;
            for j in 0..6 - i {
                let t = r[i + j] as u128 + a[i] as u128 * b[j] as u128 + carry;
                r[i + j] = t as u64;
                carry = t >> 64;
            }
        }
        r
    }

    /// A square root of `t` modulo 2^384, for `t = 1 mod 8`: Newton's
    /// iteration for the inverse square root, `y <- y (3 - t y^2) / 2`,
    /// which doubles the bits that are right, less one; then `x = t y`,
    /// right modulo 2^383, and corrected in its bit 382 if need be.
    fn sqrt_2adic(t: &[u64; 6]) -> [u64; 6] {
        assert_eq!(t[0] & 7, 1);
        let mut y = [1u64, 0, 0, 0, 0, 0];
        for _ in 0..10 {
            let ty2 = mul_lo(t, &mul_lo(&y, &y));
            let (three_less, _) = wide::sbb([3, 0, 0, 0, 0, 0], ty2);
            let mut half = mul_lo(&y, &three_less);
            for i in 0..6 {
                half[i] = (half[i] >> 1) | if i < 5 { half[i + 1] << 63 } else { 0 };
            }
            y = half;
        }
        let mut x = mul_lo(t, &y);
        if mul_lo(&x, &x) != *t {
            x[5] ^= 1 << 62;
        }
        assert_eq!(mul_lo(&x, &x), *t, "no square root found");
        x
    }

    /// The reduction's rare carry, on purpose. Each word of reduction
    /// subtracts `w * (2^384 - p)`, and the top word of that, `q3`, is 1 only
    /// where `w` is within about 2^32 of 2^64: once in four billion words of
    /// random operands, which a random test does not reach. The `w` of each
    /// word are the words of `M = -a b p^-1 mod 2^384`, so operands are built
    /// from `M` instead: `a b = -M p mod 2^384`, every word of `M` chosen near
    /// 2^64. For the multiplication `b` is one and `a` that; for the squaring,
    /// `a` is a square root of it modulo 2^384. Then every word of the
    /// reduction carries, in both, and the result must still be the generic
    /// loop's.
    #[test]
    fn the_reductions_rare_carry_is_right() {
        if !has_adx() {
            return;
        }
        let m = crate::p384::Fp::MODULUS;
        let ninv = compute_neg_inv(m[0]);
        let mont = |a: [u64; 6], b: [u64; 6]| {
            let (reduced, lo, need) = wide::mont_mul(a, b, m, ninv);
            if need == 1 {
                reduced
            } else {
                lo
            }
        };
        let mut state = 0x9_u64;
        let mut squares = 0;
        for round in 0..2000 {
            let mut big_m = [0u64; 6];
            for w in big_m.iter_mut() {
                // Within 2^31 of 2^64; the lowest word 1 mod 8 so that the
                // square root exists.
                *w = u64::MAX - (next(&mut state) >> 33);
            }
            big_m[0] = (big_m[0] & !7) | 1;
            let target = wide::sbb([0; 6], mul_lo(&big_m, &m)).0;
            let one = [1u64, 0, 0, 0, 0, 0];
            if wide::sbb(target, m).1 == 1 {
                assert_eq!(mul_p(&target, &one).unwrap(), mont(target, one), "{round}");
                assert_eq!(mul_p(&one, &target).unwrap(), mont(one, target), "{round}");
            }
            // target = -M p = M mod 8 = 1 mod 8: four square roots, at least
            // one of them below p.
            let x = sqrt_2adic(&target);
            for root in [x, wide::sbb([0; 6], x).0] {
                if wide::sbb(root, m).1 == 1 {
                    assert_eq!(sqr_p(&root).unwrap(), mont(root, root), "{round}");
                    assert_eq!(mul_p(&root, &root).unwrap(), mont(root, root), "{round}");
                    squares += 1;
                }
            }
        }
        assert!(squares > 1000, "only {squares} squares built");
    }

    /// The doubling in place against `Point::double_formula`, word for
    /// word, on points with `Z` far from one and on arbitrary coordinates,
    /// which no curve point has but which the formula must still compute
    /// the same function on; and run twice over, as the loop runs it.
    #[test]
    fn the_doubling_in_place_is_the_formula() {
        use crate::nist::point::Point;
        use crate::p384::Fp;
        if !has_adx() {
            return;
        }
        let m = Fp::MODULUS;
        let mut state = 0x2d_u64;
        let mut p = Point::<P384>::generator().double().double();
        for i in 0..2000 {
            let q = if i % 2 == 0 {
                p = p.add(&Point::generator());
                p
            } else {
                let mut c = [[0u64; 6]; 3];
                for w in c.iter_mut() {
                    *w = operand(&mut state, &m, i % 4 == 1);
                }
                Point::from_coordinates(Fp(c[0]), Fp(c[1]), Fp(c[2]))
            };
            let mut buf = [const { MaybeUninit::uninit() }; 78];
            for (k, c) in [q.x(), q.y(), q.z()].iter().enumerate() {
                for (j, w) in c.0.iter().enumerate() {
                    buf[6 * k + j].write(*w);
                }
            }
            for _ in 0..2 {
                // SAFETY: the CPU has BMI2 and ADX; slots 0 to 2 hold the
                // point, below p.
                unsafe { super::super::p384_x86_point::double_in_place_adx(&mut buf) };
            }
            // SAFETY: slots 0 to 2 are written.
            let got: [[u64; 6]; 3] =
                unsafe { read(&buf, crate::nist::p384_x86_point::DOUBLE_IN_PLACE_X) };
            let want = q.double_formula().double_formula();
            assert_eq!(got, [want.x().0, want.y().0, want.z().0], "{i}");
        }
    }

    /// The MULX/ADX scalar multiplication, called directly so that a CPU
    /// with IFMA runs it too, against the generic one: the same point, not
    /// the same words, since its window is affine. On the generator,
    /// another point and the identity, at zero, `1 .. 40` and `n - 1 .. n -
    /// 40`, where the last, complete addition is needed and where an
    /// incomplete one would fail if the argument for it did not hold, and
    /// at a thousand random scalars.
    #[test]
    fn the_buffer_multiplication_agrees_with_the_generic_one() {
        use crate::nist::arith::Field;
        use crate::nist::point::Point;
        type S = <P384 as Curve>::Scalar;
        if !has_adx() {
            return;
        }
        let mut ks = std::vec![S::ZERO];
        let (mut small, mut minus) = (S::ZERO, S::ZERO);
        for _ in 0..40 {
            small = small.add(&S::ONE);
            minus = minus.sub(&S::ONE);
            ks.push(small);
            ks.push(minus);
        }
        let mut state = 0x384a_u64;
        for _ in 0..1000 {
            let mut bytes = S::zero_bytes();
            for chunk in bytes.as_mut().chunks_mut(8) {
                chunk.copy_from_slice(&next(&mut state).to_le_bytes()[..chunk.len()]);
            }
            ks.push(S::from_bytes_reduced(&bytes));
        }
        let g = Point::<P384>::generator();
        for p in [g, g.mul_scalar_generic(&ks[100]), Point::identity()] {
            for k in &ks {
                let got = mul_scalar(&p, k).expect("BMI2 and ADX");
                assert!(bool::from(got.ct_eq(&p.mul_scalar_generic(k))), "{k:?}");
                // Affine where the generic one is, at infinity where it is.
                let want = p.mul_scalar_generic(k).to_affine().map(|a| (a.x.0, a.y.0));
                assert_eq!(got.to_affine().map(|a| (a.x.0, a.y.0)), want);
            }
        }
    }

    /// The multiplication wipes its buffer when it returns: one `Ladder`
    /// drop, the buffer clear at it. Fails with the wipe deleted from
    /// `Ladder`'s `Drop`.
    #[test]
    fn the_buffer_multiplication_wipes_its_buffer() {
        use crate::nist::arith::Field;
        use crate::nist::p256_x86::{ladder_probe as probe, secret_probe};
        use crate::nist::point::Point;
        type S = <P384 as Curve>::Scalar;
        if !has_adx() {
            std::println!("no BMI2 and ADX; the buffer multiplication was not run");
            return;
        }
        let k = S::ONE.add(&S::ONE).add(&S::ONE);
        probe::reset();
        secret_probe::reset();
        mul_scalar(&Point::<P384>::generator(), &k).expect("BMI2 and ADX");
        assert_eq!(probe::snapshot(), (1, 0));
        // The scalar's bytes, the digits and the selected entry's coordinates.
        assert_eq!(secret_probe::snapshot(), (3, 0));
    }

    /// The fused operations on inputs built to take each side of their
    /// fold (`fold_edges`): where the sum with `(t + 1)(2^384 - p)` carries
    /// out of the top word, which random inputs never reach, and where it
    /// just fails to. Against repeated generic additions.
    #[test]
    fn the_fused_operations_take_both_sides_of_their_fold() {
        use crate::nist::arith::Field;
        use crate::p384::Fp;
        if !has_adx() {
            return;
        }
        let mut sides = [0usize; 2];
        for (cm, dm) in [(3u64, 8u64), (4, 1), (12, 9)] {
            for (a, b, carries) in crate::nist::fold_edges::cases(&Fp::MODULUS, cm, dm) {
                let a: [u64; 6] = a.try_into().unwrap();
                let b: [u64; 6] = b.try_into().unwrap();
                let mut want = Fp::ZERO;
                for _ in 0..cm {
                    want = want.add(&Fp(a));
                }
                for _ in 0..dm {
                    want = want.sub(&Fp(b));
                }
                assert_eq!(
                    cms_p(cm, dm, &a, &b).unwrap(),
                    want.0,
                    "{cm} {a:x?} - {dm} {b:x?}"
                );
                sides[usize::from(carries)] += 1;
            }
        }
        assert!(sides[0] > 20 && sides[1] > 20, "{sides:?}");
    }

    /// The table scans select exactly the masked entry, every word of it, at
    /// every position of a sixteen-entry window, and nothing for no mask.
    #[test]
    fn the_scans_select_the_masked_entry() {
        use crate::nist::point::{AffinePoint, Point};
        use crate::p384::Fp;
        let mut state = 0x5ca9_u64;
        let mut fe = || {
            let mut w = [0u64; 6];
            for x in w.iter_mut() {
                *x = next(&mut state);
            }
            Fp(w)
        };
        let points: std::vec::Vec<Point<P384>> = (0..16)
            .map(|_| Point::from_coordinates(fe(), fe(), fe()))
            .collect();
        let affine: std::vec::Vec<AffinePoint<P384>> =
            (0..16).map(|_| AffinePoint { x: fe(), y: fe() }).collect();
        for pick in 0..=16usize {
            let masks: std::vec::Vec<u64> = (0..16)
                .map(|i| if i == pick { u64::MAX } else { 0 })
                .collect();
            let [x, y, z] = scan_point(&points, &masks);
            let a = scan_affine(&affine, &masks);
            if pick == 16 {
                assert_eq!([x, y, z], [[0u64; 6]; 3]);
                assert_eq!((a.x.0, a.y.0), ([0u64; 6], [0u64; 6]));
            } else {
                let p = &points[pick];
                assert_eq!([x, y, z], [p.x().0, p.y().0, p.z().0], "{pick}");
                assert_eq!((a.x, a.y), (affine[pick].x, affine[pick].y), "{pick}");
            }
        }
    }

    /// The scalar ring's multiplication, before the last subtraction,
    /// against the generic word loop's: both the value below `2n` and its
    /// top word, on the edges and a million random pairs.
    #[test]
    fn the_scalar_assembly_agrees_with_the_generic_loop() {
        let adx = std::is_x86_feature_detected!("bmi2") && std::is_x86_feature_detected!("adx");
        assert_eq!(has_adx(), adx);
        std::println!(
            "P-384 mulx/adx: {}",
            if adx { "selected" } else { "unavailable" }
        );
        if !adx {
            assert!(mul_n(&[0; 6], &[0; 6]).is_none());
            return;
        }
        let m = <P384 as Curve>::Scalar::MODULUS;
        let ninv = compute_neg_inv(m[0]);
        let check = |a: [u64; 6], b: [u64; 6]| {
            let (reduced, lo, need) = wide::mont_mul(a, b, m, ninv);
            let want = if need == 1 { reduced } else { lo };
            let (t, top) = mul_n(&a, &b).unwrap();
            let (r, borrow) = wide::sbb(t, m);
            let got = if top == 1 || borrow == 0 { r } else { t };
            assert_eq!(got, want, "{a:x?} * {b:x?}");
            // And the unreduced value is the generic loop's unreduced one.
            assert_eq!(t, lo, "{a:x?} * {b:x?}");
        };
        let edges = edges(&m);
        for a in &edges {
            for b in &edges {
                check(*a, *b);
            }
        }
        let mut state = m[0];
        for i in 0..1 << 20 {
            let s = i % 2 == 1;
            let (a, b) = (operand(&mut state, &m, s), operand(&mut state, &m, s));
            check(a, b);
        }
    }

    /// The field operations specialised to the prime -- the ones every point
    /// formula is made of -- against the generic arithmetic: Montgomery
    /// multiplication and squaring against the generic word loop, addition
    /// and subtraction against the field's own, which is the generic
    /// carry-chain code. On every pair of edges, on sums and differences
    /// that land exactly on `0`, `p - 1` and `p`, and on a million random
    /// pairs, half of them built from whole words of zeros and ones.
    #[test]
    fn the_field_assembly_agrees_with_the_generic_arithmetic() {
        use crate::nist::arith::Field;
        use crate::p384::Fp;
        if !has_adx() {
            assert!(mul_p(&[0; 6], &[0; 6]).is_none());
            assert!(sqr_p(&[0; 6]).is_none());
            return;
        }
        let m = Fp::MODULUS;
        let ninv = compute_neg_inv(m[0]);
        let mont = |a: [u64; 6], b: [u64; 6]| {
            let (reduced, lo, need) = wide::mont_mul(a, b, m, ninv);
            if need == 1 {
                reduced
            } else {
                lo
            }
        };
        let mut checked = 0usize;
        let mut check = |a: [u64; 6], b: [u64; 6]| {
            assert_eq!(mul_p(&a, &b).unwrap(), mont(a, b), "{a:x?} * {b:x?}");
            assert_eq!(sqr_p(&a).unwrap(), mont(a, a), "{a:x?}^2");
            assert_eq!(
                add_p(&a, &b).unwrap(),
                Fp(a).add(&Fp(b)).0,
                "{a:x?} + {b:x?}"
            );
            assert_eq!(
                sub_p(&a, &b).unwrap(),
                Fp(a).sub(&Fp(b)).0,
                "{a:x?} - {b:x?}"
            );
            // The fused operations, against repeated generic addition.
            let times = |x: [u64; 6], k: u64| {
                let mut s = Fp::ZERO;
                for _ in 0..k {
                    s = s.add(&Fp(x));
                }
                s
            };
            for (cm, dm) in [(3, 8), (4, 1), (12, 9)] {
                assert_eq!(
                    cms_p(cm, dm, &a, &b).unwrap(),
                    times(a, cm).sub(&times(b, dm)).0,
                    "{cm} {a:x?} - {dm} {b:x?}"
                );
            }
            checked += 1;
        };
        let one = [1u64, 0, 0, 0, 0, 0];
        let edges = edges(&m);
        for a in &edges {
            for b in &edges {
                check(*a, *b);
            }
            // a + b = p - 1, p and (but for a = 0) p + 1; a - b = 0 and -1.
            let neg = wide::sbb(m, *a).0;
            let neg_minus_one = wide::sbb(neg, one).0;
            if wide::sbb(neg_minus_one, m).1 == 1 {
                check(*a, neg_minus_one);
            }
            if wide::sbb(neg, m).1 == 1 {
                check(*a, neg);
                let neg_plus_one = wide::adc(neg, one).0;
                if wide::sbb(neg_plus_one, m).1 == 1 {
                    check(*a, neg_plus_one);
                }
            }
            check(*a, *a);
            let next = wide::adc(*a, one).0;
            if wide::sbb(next, m).1 == 1 {
                check(*a, next);
            }
        }
        let mut state = m[1];
        for i in 0..1 << 20 {
            let s = i % 2 == 1;
            let (a, b) = (operand(&mut state, &m, s), operand(&mut state, &m, s));
            check(a, b);
            if i % 64 == 0 && a != [0; 6] {
                // A sum on p exactly, from a random a.
                check(a, wide::sbb(m, a).0);
            }
        }
        assert!(checked > (1 << 20) + 50 * 50, "only {checked} checked");
    }
}
