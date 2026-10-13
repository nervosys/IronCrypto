//! P-384's Montgomery multiplications on MULX/ADX, where the CPU has them.
//!
//! The arithmetic is generated into `mont_x86`; this is the dispatch, the one
//! place it is called from. `None` where the CPU lacks BMI2 or ADX, and the
//! caller then uses the generic word loop, which computes the same function.

use super::p256_x86::has_adx;
use core::mem::MaybeUninit;

/// `a * b * 2^-384` modulo P-384's prime, below twice the prime, and its top
/// word; `None` without BMI2 and ADX.
#[inline(always)]
pub(crate) fn mul_p(a: &[u64; 6], b: &[u64; 6]) -> Option<([u64; 6], u64)> {
    if !has_adx() {
        return None;
    }
    // SAFETY: the CPU has BMI2 and ADX; every field element is below the
    // prime.
    Some(unsafe { super::mont_x86::mul_p384_p(a, b) })
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

    /// The assembly's result, before the last subtraction, against the
    /// generic word loop's: both the value below `2m` and its top word, on
    /// the edges and two million random pairs per modulus.
    #[test]
    fn the_assembly_agrees_with_the_generic_loop() {
        let adx = std::is_x86_feature_detected!("bmi2") && std::is_x86_feature_detected!("adx");
        assert_eq!(has_adx(), adx);
        std::println!(
            "P-384 mulx/adx: {}",
            if adx { "selected" } else { "unavailable" }
        );
        if !adx {
            assert!(mul_p(&[0; 6], &[0; 6]).is_none());
            return;
        }
        let p = <P384 as Curve>::Field::MODULUS;
        let n = <P384 as Curve>::Scalar::MODULUS;
        for (m, f) in [
            (
                p,
                mul_p as fn(&[u64; 6], &[u64; 6]) -> Option<([u64; 6], u64)>,
            ),
            (n, mul_n),
        ] {
            let ninv = compute_neg_inv(m[0]);
            let one = [1u64, 0, 0, 0, 0, 0];
            let mut edges = std::vec![
                [0u64; 6],
                one,
                wide::sbb(m, one).0,
                wide::sbb(m, [2, 0, 0, 0, 0, 0]).0,
                wide::sbb([0; 6], m).0,
                [u64::MAX, u64::MAX, u64::MAX, u64::MAX, u64::MAX, m[5] - 1],
                [0, 0, 0, 0, 0, 1 << 63],
            ];
            edges.push([u64::MAX, 0, u64::MAX, 0, u64::MAX, m[5] >> 1]);
            let check = |a: [u64; 6], b: [u64; 6]| {
                let (reduced, lo, need) = wide::mont_mul(a, b, m, ninv);
                let want = if need == 1 { reduced } else { lo };
                let (t, top) = f(&a, &b).unwrap();
                let (r, borrow) = wide::sbb(t, m);
                let got = if top == 1 || borrow == 0 { r } else { t };
                assert_eq!(got, want, "{a:x?} * {b:x?}");
                // And the unreduced value is the generic loop's unreduced one.
                assert_eq!(t, lo, "{a:x?} * {b:x?}");
            };
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
    }
}
