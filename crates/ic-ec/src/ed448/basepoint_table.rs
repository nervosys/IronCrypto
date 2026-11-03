//! A precomputed table for multiplying the Ed448 basepoint.
//!
//! The same shape as Ed25519's (`ed25519/basepoint_table.rs`), which explains
//! it at more length. The scalar becomes 114 signed digits in `[-8, 8]`,
//! radix 16. There are 57 windows, window `j` holding `1..=8` times
//! `16^(2j) B`. The even-numbered digits read the windows directly. The odd
//! ones read the same windows and are scaled once, at the end, by four
//! doublings. That is 114 additions and 4 doublings, where
//! [`Point::mul_scalar`] does 456 doublings and 128 additions.
//!
//! Each entry is affine, `(x, y)` with `z = 1`, so adding one skips a
//! multiplication ([`Point::add_affine`]). A lookup reads all eight entries
//! of its window and selects with conditional moves, and a negative digit
//! negates `x` the same way. No address depends on the scalar.
//!
//! The windows are 57 KiB. They live in statics behind `std`, one `OnceLock`
//! per window, built on first use or by [`crate::prepare`]. Without `std`
//! the basepoint goes through [`Point::mul_scalar`] like any other point.

use std::sync::OnceLock;

use super::{Fe, Point, LEN};
use ic_core::ct::Choice;

/// Digits per scalar, radix 16 over 456 bits.
const DIGITS: usize = 2 * LEN;

/// Entries per window: the multiples `1..=8`.
const ENTRIES: usize = 8;

/// One window per pair of digits.
const WINDOWS: usize = DIGITS / 2;

/// A point with `z = 1`.
#[derive(Clone, Copy)]
pub(super) struct Affine {
    pub(super) x: Fe,
    pub(super) y: Fe,
}

impl Affine {
    const IDENTITY: Affine = Affine {
        x: Fe::ZERO,
        y: Fe::ONE,
    };
}

/// `1..=8` times some fixed multiple of the basepoint.
struct Window([Affine; ENTRIES]);

impl Window {
    /// The multiples of `base`, made affine with one inversion between them.
    ///
    /// The inversions, one per window, are not most of what building the
    /// table costs: sharing one between four windows measured the same.
    fn new(base: &Point) -> Self {
        let mut multiples = [*base; ENTRIES];
        for i in 1..ENTRIES {
            multiples[i] = multiples[i - 1].add(base);
        }
        // Montgomery's trick: prefix[i] is z_0 ... z_i, and one inversion of
        // the whole product gives each 1 / z_i by walking back down.
        let mut prefix = [Fe::ONE; ENTRIES];
        let mut product = Fe::ONE;
        for (p, m) in prefix.iter_mut().zip(multiples.iter()) {
            product = product.mul(&m.z);
            *p = product;
        }
        let mut inverse = product.invert();
        let mut entries = [Affine::IDENTITY; ENTRIES];
        for i in (0..ENTRIES).rev() {
            let zinv = if i == 0 {
                inverse
            } else {
                inverse.mul(&prefix[i - 1])
            };
            inverse = inverse.mul(&multiples[i].z);
            entries[i] = Affine {
                x: multiples[i].x.mul(&zinv),
                y: multiples[i].y.mul(&zinv),
            };
        }
        Self(entries)
    }

    /// `digit` times the window's base, for `digit` in `[-8, 8]`, without
    /// indexing by it.
    fn select(&self, digit: i8) -> Affine {
        let negative = Choice::from_u8((digit as u8) >> 7);
        let magnitude = ((digit as i16 ^ (digit as i16 >> 7)) - (digit as i16 >> 7)) as u64;

        let mut out = Affine::IDENTITY;
        for (i, entry) in self.0.iter().enumerate() {
            // `magnitude == i + 1`, by arithmetic: the difference is zero
            // exactly then, and only zero minus one sets the top bit.
            let hit = Choice::from_u8(((magnitude ^ (i as u64 + 1)).wrapping_sub(1) >> 63) as u8);
            out.x = out.x.select(&entry.x, hit);
            out.y = out.y.select(&entry.y, hit);
        }
        out.x = out.x.select(&out.x.neg(), negative);
        out
    }
}

/// The windows, filled by [`prepare`] or one at a time by [`window`].
static TABLE: [OnceLock<Window>; WINDOWS] = [const { OnceLock::new() }; WINDOWS];

/// Whether [`prepare`] has run.
static BUILT: OnceLock<()> = OnceLock::new();

/// Fill every window, in order, sharing the doublings between them: eight
/// per window, seven additions and one inversion each, once. A second caller
/// waits for the first.
pub(crate) fn prepare() {
    BUILT.get_or_init(|| {
        let mut base = Point::basepoint();
        for (i, slot) in TABLE.iter().enumerate() {
            if i > 0 {
                // Times 16^2.
                for _ in 0..8 {
                    base = base.double();
                }
            }
            slot.get_or_init(|| Window::new(&base));
        }
    });
}

/// Window `i`. Filled by [`prepare`]; were it somehow not, it is built here on
/// its own, more slowly and with the same result, rather than panicking.
fn window(i: usize) -> &'static Window {
    TABLE[i].get_or_init(|| {
        let mut base = Point::basepoint();
        for _ in 0..8 * i {
            base = base.double();
        }
        Window::new(&base)
    })
}

/// A little-endian scalar below 2^455 as 114 signed radix-16 digits, the
/// first 113 in `[-8, 8)` and the last in `[0, 8]`, `sum d_i 16^i`.
///
/// Each digit of 8 or more is traded for one more in the next, arithmetic
/// only, the same for every scalar. The last digit is not recoded: it takes
/// the final carry, which below 2^455 leaves it at most 8. Every scalar here
/// is below 2^448: a clamped secret has its last byte zero, and `r` is reduced
/// modulo the group order.
pub(super) fn signed_digits(k: &[u8; LEN]) -> [i8; DIGITS] {
    debug_assert!(k[LEN - 1] < 0x80, "the scalar must be below 2^455");
    let mut d = [0i8; DIGITS];
    for (i, byte) in k.iter().enumerate() {
        d[2 * i] = (byte & 0x0f) as i8;
        d[2 * i + 1] = (byte >> 4) as i8;
    }
    for i in 0..DIGITS - 1 {
        let carry = (d[i] + 8) >> 4;
        d[i] -= carry << 4;
        d[i + 1] += carry;
    }
    d
}

/// `[k]B`, for `k` below 2^455, in constant time.
pub(super) fn mul(k: &[u8; LEN]) -> Point {
    prepare();
    let digits = signed_digits(k);

    // Odd digits first, then four doublings to scale them by 16, then the
    // even ones. Both halves read the same windows.
    let mut acc = Point::IDENTITY;
    for i in (1..DIGITS).step_by(2) {
        acc = acc.add_affine(&window(i / 2).select(digits[i]));
    }
    for _ in 0..4 {
        acc = acc.double();
    }
    for i in (0..DIGITS).step_by(2) {
        acc = acc.add_affine(&window(i / 2).select(digits[i]));
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed448::L_BYTES;

    fn point(a: &Affine) -> Point {
        Point {
            x: a.x,
            y: a.y,
            z: Fe::ONE,
        }
    }

    /// Scalars that exercise the recoding: zero, one, every nibble 8 (where
    /// a digit turns negative), every nibble 9 (a carry at every position),
    /// the largest below 2^455, L - 1, a clamped secret, and random ones.
    fn scalars() -> Vec<[u8; LEN]> {
        let mut out = vec![[0u8; LEN]];
        let mut one = [0u8; LEN];
        one[0] = 1;
        out.push(one);
        let mut eights = [0x88u8; LEN];
        eights[LEN - 1] = 0x08;
        out.push(eights);
        let mut nines = [0x99u8; LEN];
        nines[LEN - 1] = 0x09;
        out.push(nines);
        let mut top = [0xffu8; LEN];
        top[LEN - 1] = 0x7f;
        out.push(top);
        let mut l_minus_1 = L_BYTES;
        l_minus_1[0] -= 1;
        out.push(l_minus_1);
        let mut clamped = [0xa5u8; LEN];
        clamped[0] &= 0xfc;
        clamped[55] |= 0x80;
        clamped[LEN - 1] = 0;
        out.push(clamped);
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..8 {
            let mut k = [0u8; LEN];
            for b in k.iter_mut() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *b = state as u8;
            }
            k[LEN - 1] &= 0x7f;
            out.push(k);
        }
        out
    }

    /// The table has no vectors of its own: it is right if it agrees with
    /// [`Point::mul_scalar`], which RFC 8032's vectors check.
    #[test]
    fn the_table_agrees_with_the_windowed_multiplication() {
        let mut checked = 0;
        for k in &scalars() {
            let base = Point::basepoint();
            assert!(mul(k).eq(&base.mul_scalar(k)), "{k:02x?}");
            checked += 1;
        }
        assert_eq!(checked, 15, "the comparison did not run");
    }

    /// Each window [`prepare`] fills is the one [`window`]'s fallback would
    /// build on its own, every entry `m 16^(2j) B`.
    #[test]
    fn every_window_holds_its_multiples() {
        prepare();
        let mut base = Point::basepoint();
        for j in 0..WINDOWS {
            let w = window(j);
            let mut m = base;
            for (i, entry) in w.0.iter().enumerate() {
                assert!(point(entry).eq(&m), "window {j}, entry {i}");
                m = m.add(&base);
            }
            for _ in 0..8 {
                base = base.double();
            }
        }
    }

    /// The selection gives `d` times the base for every digit, negative ones
    /// included, and the identity for zero.
    #[test]
    fn select_gives_every_signed_multiple() {
        let w = window(3);
        let base = point(&w.0[0]);
        for d in -8i8..=8 {
            let mut want = Point::IDENTITY;
            for _ in 0..d.unsigned_abs() {
                want = want.add(&base);
            }
            if d < 0 {
                want = want.negate();
            }
            assert!(point(&w.select(d)).eq(&want), "digit {d}");
        }
    }

    /// The digits stay in range and evaluate back to the scalar, here modulo
    /// a prime unrelated to the curve.
    #[test]
    fn the_signed_digits_represent_the_scalar() {
        const M: u64 = 1_000_000_007;
        for k in &scalars() {
            let digits = signed_digits(k);
            for (i, d) in digits.iter().enumerate() {
                let range = if i == DIGITS - 1 { 0..=8 } else { -8..=7 };
                assert!(range.contains(d), "digit {i} is {d}");
            }
            let (mut from_digits, mut power) = (0u64, 1u64);
            for d in digits {
                from_digits = (from_digits + (d as i64).rem_euclid(M as i64) as u64 * power) % M;
                power = power * 16 % M;
            }
            let (mut from_bytes, mut power) = (0u64, 1u64);
            for b in k {
                from_bytes = (from_bytes + u64::from(*b) * power) % M;
                power = power * 256 % M;
            }
            assert_eq!(from_digits, from_bytes, "{k:02x?}");
        }
    }
}
