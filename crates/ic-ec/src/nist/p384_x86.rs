//! P-384's arithmetic on MULX/ADX, where the CPU has it.
//!
//! The arithmetic is generated: the field operations and point formulas,
//! specialised to the prime, into `p384_x86_point`, and the scalar ring's
//! multiplication, generic in the modulus, into `mont_x86`. This is the
//! dispatch, the one place they are called from. `None` where the CPU lacks
//! BMI2 or ADX, and the caller then uses the generic arithmetic, which
//! computes the same function.

use super::p256_x86::has_adx;
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
        let [r] = read(&buf, 2);
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
        let [r] = read(&buf, 1);
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
        let [r] = read(&buf, 2);
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
        match (cm, dm) {
            (3, 8) => f::fcms_3_8_adx(&mut buf),
            (4, 1) => f::fcms_4_1_adx(&mut buf),
            (12, 9) => f::fcms_12_9_adx(&mut buf),
            _ => return None,
        }
        let [r] = read(&buf, 2);
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
        let [r] = read(&buf, 2);
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

/// Jacobian doubling as one block of assembly; `None` without BMI2 and ADX.
#[inline(always)]
pub(crate) fn point_double(p: [&[u64; 6]; 3]) -> Option<[[u64; 6]; 3]> {
    if !has_adx() {
        return None;
    }
    let mut buf = slots::<90>(&p);
    // SAFETY: the CPU has BMI2 and ADX; the formula writes X3, Y3, Z3, slots
    // 3 to 5.
    unsafe {
        super::p384_x86_point::double_adx(&mut buf);
        Some(read(&buf, 3))
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
    let mut buf = slots::<132>(&[p[0], p[1], p[2], q[0], q[1], q[2]]);
    // SAFETY: the CPU has BMI2 and ADX; the formula writes X3, Y3, Z3, H, R,
    // slots 6 to 10.
    unsafe {
        super::p384_x86_point::add_adx(&mut buf);
        let [h, r] = read(&buf, 9);
        Some((read(&buf, 6), h, r))
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
    let mut buf = slots::<114>(&[p[0], p[1], p[2], q[0], q[1]]);
    // SAFETY: the CPU has BMI2 and ADX; the formula writes X3, Y3, Z3, H, R,
    // slots 5 to 9.
    unsafe {
        super::p384_x86_point::add_affine_adx(&mut buf);
        let [h, r] = read(&buf, 8);
        Some((read(&buf, 5), h, r))
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
