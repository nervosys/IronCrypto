//! Verification's joint chain on one buffer, for P-256 and P-384 on
//! x86-64 with BMI2 and ADX: **variable time, public inputs only**.
//!
//! The same chain as `nist::verify::joint_vartime` -- the same digits,
//! entries, doublings and additions, so the same point -- run on the
//! generated formulas (`p256_x86_point`, `p384_x86_point`, called, not
//! changed) the way `p256_x86::mul_scalar` runs the ladder: the accumulator
//! lives in the buffer's first three slots, where both the in-place doubling
//! and the mixed addition read it, so a run of doublings moves nothing, and
//! an addition moves only its entry in and its result back. The generic
//! chain moves every point through a fresh buffer per formula.
//!
//! Unlike everything else built on these formulas, nothing here is constant
//! time, by design: the digits are read as they come, the tables by index,
//! and the additions' exceptional cases -- the accumulator at infinity,
//! equal to the entry, or its negation -- are branches on `H` and `R`, which
//! the mixed addition leaves in its slots. Signing and ECDH never reach this
//! file: its only caller is `Curve::mul_double_vartime_fast`, whose only
//! caller is `nist::verify::mul_double_vartime`.

use core::mem::MaybeUninit;

use super::arith::Field;
use super::p256_x86::has_adx;
use super::point::{AffinePoint, Point};

/// The joint chain over one curve's formulas, as a function.
///
/// `$limbs`: words per field element. `$buf`: the mixed addition's slots,
/// in words, the most of the two formulas. `$dbl`: the in-place doubling's,
/// a prefix. The mixed addition's slots are `X1, Y1, Z1, x2, y2, X3, Y3,
/// Z3, H, R, ..`; the doubling's begin `X, Y, Z`.
macro_rules! joint {
    ($name:ident, $curve:ty, $fp:path, $limbs:literal, $buf:literal, $dbl:literal,
     $double:path, $add:path) => {
        /// `nist::verify::joint_vartime` for this curve on BMI2 and ADX, or
        /// `None` without them. **Variable time**: public inputs only.
        pub(crate) fn $name(
            g: &[AffinePoint<$curve>],
            q: &[AffinePoint<$curve>],
            g_naf: &[i8],
            q_naf: &[i8],
        ) -> Option<Point<$curve>> {
            if !has_adx() {
                return None;
            }
            debug_assert_eq!(g_naf.len(), q_naf.len());
            let mut buf = [const { MaybeUninit::<u64>::uninit() }; $buf];
            let put = |buf: &mut [MaybeUninit<u64>; $buf], slot: usize, w: &[u64; $limbs]| {
                for (j, v) in w.iter().enumerate() {
                    buf[$limbs * slot + j].write(*v);
                }
            };
            // Only for slots already written: by `put`, or by the formula
            // named beside the use.
            let get = |buf: &[MaybeUninit<u64>; $buf], slot: usize| -> [u64; $limbs] {
                let mut w = [0u64; $limbs];
                for (j, v) in w.iter_mut().enumerate() {
                    // SAFETY: every read below is of a written slot.
                    *v = unsafe { buf[$limbs * slot + j].assume_init() };
                }
                w
            };
            let double = |buf: &mut [MaybeUninit<u64>; $buf]| {
                let ip: &mut [MaybeUninit<u64>; $dbl] = (&mut buf[..$dbl])
                    .try_into()
                    .expect("the doubling's slots are a prefix of the buffer");
                // SAFETY: the CPU has BMI2 and ADX; slots 0 to 2 hold the
                // accumulator, every coordinate below p.
                unsafe { $double(ip) };
            };

            // Whether the accumulator is the identity, which has no slots'
            // worth of meaning here: it is tracked rather than stored.
            let mut at_infinity = true;
            for i in (0..g_naf.len()).rev() {
                if !at_infinity {
                    double(&mut buf);
                }
                for (naf, table) in [(g_naf, g), (q_naf, q)] {
                    let digit = naf[i];
                    if digit == 0 {
                        continue;
                    }
                    let entry = &table[(digit.unsigned_abs() >> 1) as usize];
                    let y = if digit > 0 { entry.y } else { entry.y.neg() };
                    if at_infinity {
                        put(&mut buf, 0, &entry.x.0);
                        put(&mut buf, 1, &y.0);
                        put(&mut buf, 2, &<$fp>::ONE.0);
                        at_infinity = false;
                        continue;
                    }
                    put(&mut buf, 3, &entry.x.0);
                    put(&mut buf, 4, &y.0);
                    // SAFETY: the CPU has BMI2 and ADX; slots 0 to 4 are
                    // written, every coordinate below p. The formula writes
                    // X3, Y3, Z3, H and R, slots 5 to 9.
                    unsafe { $add(&mut buf) };
                    if get(&buf, 8) != [0; $limbs] {
                        for k in 0..3 {
                            let c = get(&buf, 5 + k);
                            put(&mut buf, k, &c);
                        }
                    } else if get(&buf, 9) == [0; $limbs] {
                        // The accumulator is the entry: the sum is its double.
                        double(&mut buf);
                    } else {
                        // The accumulator is the entry's negation.
                        at_infinity = true;
                    }
                }
            }
            if at_infinity {
                return Some(Point::identity());
            }
            let [x, y, z] = [get(&buf, 0), get(&buf, 1), get(&buf, 2)];
            Some(Point::from_coordinates($fp(x), $fp(y), $fp(z)))
        }
    };
}

joint!(
    p256,
    crate::p256::P256,
    crate::p256::Fp,
    4,
    80,
    48,
    super::p256_x86_point::double_in_place_adx,
    super::p256_x86_point::add_affine_adx
);

joint!(
    p384,
    crate::p384::P384,
    crate::p384::Fp,
    6,
    126,
    78,
    super::p384_x86_point::double_in_place_adx,
    super::p384_x86_point::add_affine_adx
);
