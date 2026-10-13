//! A precomputed table for multiplying a NIST curve's generator.
//!
//! # Why
//!
//! [`Point::mul_scalar`][super::point::Point::mul_scalar] handles an arbitrary
//! point: it builds `1..=8` times the point per call and walks the scalar four
//! bits at a time, which is what ECDH needs. Every digit still costs four
//! doublings, and for an arbitrary point nothing can remove them.
//!
//! ECDSA signing does not need it. `R = k*G` multiplies the generator, which is
//! the same point in every signature, so its multiples can be computed once.
//! Measured on P-256 before this existed: one scalar multiplication cost 146.8
//! microseconds and a whole signature 159.5, so the ladder was essentially the
//! entire operation and everything else -- RFC 6979, the inversion -- was
//! thirteen microseconds of it.
//!
//! # The shape
//!
//! The scalar is recoded into signed digits of `W` bits, each in
//! `[-2^(W-1), 2^(W-1))`, and window `i` stores `1..=2^(W-1)` times
//! `2^(W*i) * G`, affine. Then `k*G` is one addition per digit and no
//! doublings at all: the digit's multiple, negated in `y` when the digit is
//! negative, added to the accumulator. The lookup reads every entry of the
//! window and selects with conditional moves rather than indexing -- a table
//! indexed by a secret is a cache-timing channel.
//!
//! `W` is per curve, trading storage for additions: 6 for P-256 (43
//! additions, 88 KiB), 5 for P-384 (77, 118 KiB), 4 for P-521 (133, 150 KiB).
//! This replaced a radix-16 comb with two passes and four doublings between
//! them, 65 additions on P-256 in a complete projective formula; the
//! additions here are Jacobian with an affine operand, seven multiplications
//! and four squarings, and all but the last may be incomplete -- see
//! [`mul`] for why.
//!
//! # Where it lives
//!
//! Behind `std`, in a `static` per curve: one `OnceLock` per window, filled in
//! order on first use, or earlier through [`crate::prepare`]. `no_std`
//! multiplies the generator with [`Point::mul_scalar`], which uses this
//! module's [`Window`] and [`signed_digits`] against the point it is given, one
//! window built per call: four bits per addition, without the storage.
//!
//! The storage is static, not heap. It used to be a `Vec`, and a caller that
//! forbids allocation after start-up -- a TLS engine running in caller-owned
//! memory -- met that allocation in the middle of its first handshake. A
//! single `OnceLock` holding every window would avoid the heap, but its value
//! is built on the stack and then moved in, which is the whole table's worth
//! of stack; that overflowed once, and is why the `Vec` was there. A lock per
//! window needs neither: each window is built where it is stored, and at most
//! one window's worth of stack is in use at a time. `tests/cold_tables.rs`
//! checks that a first use allocates nothing.

use ic_core::ct::Choice;

use super::arith::mask_of;
#[cfg(feature = "std")]
use super::arith::Field;
#[cfg(feature = "std")]
use super::point::AffinePoint;
use super::point::Curve;
use super::point::Point;

/// Digits for the widest curve here: P-521 has a 66-byte scalar, so 132
/// nibbles, plus one for the carry out of the top. See `signed_digits`.
const MAX_DIGITS: usize = 133;

/// Entries per window of [`Point::mul_scalar`]: the multiples `1..=8`.
const ENTRIES: usize = 8;

/// `1..=8` times some fixed point, for [`Point::mul_scalar`].
pub(super) struct Window<C: Curve>([Point<C>; ENTRIES]);

impl<C: Curve> Window<C> {
    /// Even multiples by doubling, odd ones by adding `base` to the even one
    /// below: `2k * base` and `base` are never the same point when `base` has
    /// prime order above 8, so [`Point::add_unequal`] is enough, and it also
    /// handles a `base` at infinity.
    pub(super) fn new(base: &Point<C>) -> Self {
        Self(multiples(base))
    }

    /// `digit * base` for `digit` in `[-8, 8]`, without indexing by it.
    pub(super) fn select(&self, digit: i8) -> Point<C> {
        let negative = Choice::from_u8((digit as u8) >> 7);
        let magnitude = ((digit as i16 ^ (digit as i16 >> 7)) - (digit as i16 >> 7)) as u8;

        let mut out = Point::identity();
        for (i, entry) in self.0.iter().enumerate() {
            Point::cmov_mask(&mut out, entry, mask_of(magnitude as u32, i as u32 + 1));
        }
        out.conditional_negate(negative);
        out
    }
}

/// `1..=E` times `base`, Jacobian: even multiples by doubling, odd ones by
/// one incomplete addition; see [`Window::new`].
fn multiples<C: Curve, const E: usize>(base: &Point<C>) -> [Point<C>; E] {
    let mut entries = [Point::identity(); E];
    entries[0] = *base;
    for i in 1..E {
        // entries[i] = (i + 1) * base
        entries[i] = if i % 2 == 1 {
            entries[i / 2].double()
        } else {
            entries[i - 1].add_unequal(base)
        };
    }
    entries
}

/// `a == b`, as a [`Choice`], without a comparison the compiler could turn
/// into a branch: the xor is zero exactly when they are equal, and zero minus
/// one is the only value here with the top bit set.
#[inline]
#[cfg(feature = "std")]
fn equal(a: u8, b: u8) -> Choice {
    Choice::from_u8((((a ^ b) as u32).wrapping_sub(1) >> 31) as u8)
}

/// `1..=E` times one power of the generator, affine, for [`mul`]: an affine
/// entry makes the accumulator's addition three multiplications cheaper.
#[cfg(feature = "std")]
pub struct AffineWindow<C: Curve, const E: usize>([AffinePoint<C>; E]);

#[cfg(feature = "std")]
impl<C: Curve, const E: usize> AffineWindow<C, E> {
    /// The window for `base`, a nonzero multiple of the generator, so none of
    /// its multiples `1..=E` is the identity. Normalised with one inversion
    /// for the whole window (Montgomery's trick): the product of every `Z`,
    /// inverted once, then unwound.
    fn new(base: &Point<C>) -> Self {
        let points: [Point<C>; E] = multiples(base);
        let mut prefix = [C::Field::ONE; E];
        let mut acc = C::Field::ONE;
        for (p, point) in prefix.iter_mut().zip(points.iter()) {
            *p = acc;
            acc = acc.mul(&point.z());
        }
        // acc = z_0 * .. * z_{E-1}; walk back, peeling one z at a time.
        let mut inv = acc.invert();
        let mut entries = [AffinePoint {
            x: C::Field::ZERO,
            y: C::Field::ZERO,
        }; E];
        for i in (0..E).rev() {
            let z_inv = inv.mul(&prefix[i]);
            inv = inv.mul(&points[i].z());
            let z_inv2 = z_inv.square();
            entries[i] = AffinePoint {
                x: points[i].x().mul(&z_inv2),
                y: points[i].y().mul(&z_inv2.mul(&z_inv)),
            };
        }
        Self(entries)
    }

    /// `|digit| * base`'s coordinates, negated in `y` for a negative digit,
    /// without indexing by the digit. A zero digit selects the first entry,
    /// which the caller discards.
    fn select(&self, digit: i8) -> (C::Field, C::Field) {
        let negative = Choice::from_u8((digit as u8) >> 7);
        let magnitude = ((digit as i16 ^ (digit as i16 >> 7)) - (digit as i16 >> 7)) as u8;
        let mut x = self.0[0].x;
        let mut y = self.0[0].y;
        for (i, entry) in self.0.iter().enumerate() {
            let hit = mask_of(magnitude as u32, i as u32 + 1);
            C::Field::cmov_mask(&mut x, &entry.x, hit);
            C::Field::cmov_mask(&mut y, &entry.y, hit);
        }
        let ny = y.neg();
        C::Field::cmov(&mut y, &ny, negative);
        (x, y)
    }

    /// `acc + digit * base`, in constant time. With `complete` false, `acc`
    /// must not equal `digit * base`; see [`mul`].
    fn add_to(&self, acc: &Point<C>, digit: i8, complete: bool) -> Point<C> {
        let (x, y) = self.select(digit);
        let mut out = if complete {
            acc.add(&Point::from_affine(&AffinePoint { x, y }))
        } else {
            acc.add_affine_unequal(&x, &y)
        };
        // A zero digit adds the identity, which has no affine form: the
        // addition above was of an arbitrary entry, and is discarded.
        Point::cmov(&mut out, acc, equal(digit as u8, 0));
        out
    }

    /// `acc + digit * base` for a public digit, as in verification.
    fn add_to_vartime(&self, acc: &Point<C>, digit: i8) -> Point<C> {
        if digit == 0 {
            return *acc;
        }
        let entry = &self.0[digit.unsigned_abs() as usize - 1];
        if digit > 0 {
            acc.add_affine_vartime(&entry.x, &entry.y)
        } else {
            acc.add_affine_vartime(&entry.x, &entry.y.neg())
        }
    }
}

/// One curve's windows: `2^(W*i) * G` and its multiples `1..=E`, for each
/// `i`, where `E = 2^(W-1)`.
#[cfg(feature = "std")]
pub type Windows<C, const E: usize> = [std::sync::OnceLock<AffineWindow<C, E>>];

/// The window width that goes with `E` entries.
#[cfg(feature = "std")]
const fn width<const E: usize>() -> usize {
    E.trailing_zeros() as usize + 1
}

/// Fill every window, in order, sharing the doublings between them.
///
/// Costs about one variable-base scalar multiplication plus one inversion per
/// window, once. `built` makes it run once: a second caller waits for the
/// first rather than repeating the work.
#[cfg(feature = "std")]
pub fn prepare<C: Curve, const E: usize>(windows: &Windows<C, E>, built: &std::sync::OnceLock<()>) {
    built.get_or_init(|| {
        let mut base = Point::<C>::generator();
        for (i, slot) in windows.iter().enumerate() {
            if i > 0 {
                for _ in 0..width::<E>() {
                    base = base.double();
                }
            }
            slot.get_or_init(|| AffineWindow::new(&base));
        }
    });
}

/// Window `i`, built by itself if [`prepare`] somehow had not: slower, and
/// the same answer rather than a panic.
#[cfg(feature = "std")]
fn window<C: Curve, const E: usize>(windows: &Windows<C, E>, i: usize) -> &AffineWindow<C, E> {
    windows[i].get_or_init(|| {
        let mut base = Point::<C>::generator();
        for _ in 0..width::<E>() * i {
            base = base.double();
        }
        AffineWindow::new(&base)
    })
}

/// `scalar * G`, constant time in the scalar.
///
/// # Which additions can be incomplete
///
/// The digits are added least significant first, so before digit `i` the
/// accumulator is `L * G` with `L` the integer the digits below `i` spell,
/// `|L| < 2^(W*i) / 1.8`, and the entry is `d * 2^(W*i) * G`. They are equal
/// only if `L = d * 2^(W*i) mod n`. For `d != 0` the right side is at least
/// `2^(W*i)` in magnitude, more than `|L|`, so the two differ as integers; and
/// their difference is below `0.6 * 2^(W*(i+1))`, which is below `n`
/// whenever `W*(i+1) < ORDER_BITS`, since `n > 2^(ORDER_BITS-1)`. So up to
/// there the points differ, and [`Point::add_affine_unequal`] is exact; it
/// also handles an accumulator at infinity, and `d = 0` is discarded by the
/// caller. The windows above that bound -- one on P-256 and P-384, three on
/// P-521 -- use the complete addition.
#[cfg(feature = "std")]
pub fn mul<C: Curve, const E: usize>(
    windows: &Windows<C, E>,
    built: &std::sync::OnceLock<()>,
    scalar: &C::Scalar,
) -> Point<C> {
    prepare(windows, built);
    let w = width::<E>();
    let bytes = scalar.to_bytes();
    let digits = signed_digits_w(bytes.as_ref(), w);
    let n = digit_count(bytes.as_ref().len(), w);
    debug_assert!(n <= windows.len());

    let mut acc = Point::identity();
    for (i, digit) in digits.iter().take(n).enumerate() {
        let complete = w * (i + 1) >= C::ORDER_BITS;
        acc = window(windows, i).add_to(&acc, *digit, complete);
    }
    acc
}

/// `scalar * G` for a public scalar, as in verification: the entry is read by
/// index and zero digits are skipped.
#[cfg(feature = "std")]
pub fn mul_vartime<C: Curve, const E: usize>(
    windows: &Windows<C, E>,
    built: &std::sync::OnceLock<()>,
    scalar: &C::Scalar,
) -> Point<C> {
    prepare(windows, built);
    let w = width::<E>();
    let bytes = scalar.to_bytes();
    let digits = signed_digits_w(bytes.as_ref(), w);
    let n = digit_count(bytes.as_ref().len(), w);
    let mut acc = Point::identity();
    for (i, digit) in digits.iter().take(n).enumerate() {
        acc = window(windows, i).add_to_vartime(&acc, *digit);
    }
    acc
}

/// Digits of `W` bits in a `len`-byte scalar, plus one for the carry out of
/// the top.
#[cfg(feature = "std")]
pub(crate) const fn digit_count(len: usize, w: usize) -> usize {
    8 * len / w + 1
}

/// The widest digit expansion [`signed_digits_w`] produces: P-521's 66 bytes
/// at four bits.
#[cfg(feature = "std")]
const MAX_DIGITS_W: usize = 8 * 66 / 4 + 1;

/// The scalar as signed digits of `w` bits, each in `[-2^(w-1), 2^(w-1))`
/// but the top one, in `[0, 2^(w-1)]`, least significant first; `bytes` is
/// big-endian.
///
/// Branch-free in the scalar: each window's bits are read at a public
/// position, the carry is `(v + 2^(w-1)) >> w`, and the digit is `v` less the
/// carry shifted back. The top window absorbs the last carry.
#[cfg(feature = "std")]
pub(crate) fn signed_digits_w(bytes: &[u8], w: usize) -> [i8; MAX_DIGITS_W] {
    // Little-endian words, with room above the top for windows that run past
    // it.
    let mut limbs = [0u64; 10];
    for (i, byte) in bytes.iter().rev().enumerate() {
        limbs[i / 8] |= (*byte as u64) << (8 * (i % 8));
    }
    let n = digit_count(bytes.len(), w);
    let mask = (1u64 << w) - 1;
    let half = 1i16 << (w - 1);
    let mut digits = [0i8; MAX_DIGITS_W];
    let mut carry = 0i16;
    for (i, digit) in digits.iter_mut().take(n).enumerate() {
        let bit = w * i;
        let (word, shift) = (bit / 64, bit % 64);
        // The window's bits, which may straddle two words. `shift` is public.
        let lo = limbs[word] >> shift;
        let hi = if shift + w > 64 {
            limbs[word + 1] << (64 - shift)
        } else {
            0
        };
        let v = ((lo | hi) & mask) as i16 + carry;
        if i + 1 == n {
            // The top window holds at most w - 1 of the scalar's bits, so
            // with the carry it is at most 2^(w-1): a magnitude the table
            // has, kept rather than recoded, because there is no digit above
            // to take a carry.
            *digit = v as i8;
        } else {
            carry = (v + half) >> w;
            *digit = (v - (carry << w)) as i8;
        }
    }
    digits
}

/// The scalar as signed radix-16 digits, each in `[-8, 8]`.
///
/// `bytes` is big-endian, as `Field::to_bytes` produces; the digits are
/// little-endian, least significant first, because that is the order the
/// accumulation wants.
///
/// Every nibble is recoded and the carry out of the top gets a digit of its
/// own, which is where this differs from the Ed25519 version.
///
/// There, scalars are below `2^255`, so the most significant nibble is at most
/// 7, one carry takes it to 8, and 8 is a legal digit -- the last nibble can
/// absorb the carry and no extra digit is needed. Here the group orders are
/// close to `2^(8*SCALAR_BYTES)`, so the top nibble can be 15; a carry would
/// make it 16, which is outside `[-8, 8]`, and `select` would match no entry
/// and silently return the identity. Hence the extra digit, which is 0 or 1.
///
/// That is exactly how this failed first: the Ed25519 recoding was reused
/// unchanged and every RFC 6979 vector rejected it.
pub(super) fn signed_digits(bytes: &[u8]) -> [i8; MAX_DIGITS] {
    let mut nibbles = [0i8; MAX_DIGITS];
    let n = bytes.len() * 2;
    for (i, byte) in bytes.iter().rev().enumerate() {
        nibbles[i * 2] = (byte & 0x0f) as i8;
        nibbles[i * 2 + 1] = (byte >> 4) as i8;
    }

    for i in 0..n {
        let carry = (nibbles[i] + 8) >> 4;
        nibbles[i] -= carry << 4;
        nibbles[i + 1] += carry;
    }
    debug_assert!(nibbles[n] == 0 || nibbles[n] == 1);
    nibbles
}

/// A curve that knows how to multiply its own generator.
///
/// The trait exists on every target; only the implementation differs. Under
/// `std` it is the table; under `no_std` it is [`Point::mul_scalar`] on the
/// generator, four bits at a time with no stored window, so callers need no
/// conditional bound and the generic code has one shape.
///
/// It is separate from [`Curve`] because the table's storage is a `static`,
/// which has to live in a concrete function body: a `static` inside a generic
/// function is shared across every instantiation, which would hand P-384 the
/// P-256 table.
pub trait HasGeneratorTable: Curve + Sized + 'static {
    /// `scalar * G`, constant time in the scalar.
    fn mul_generator(scalar: &Self::Scalar) -> super::point::Point<Self>;

    /// `scalar * G` for a public scalar: variable time.
    fn mul_generator_vartime(scalar: &Self::Scalar) -> super::point::Point<Self>;

    /// Build the table now rather than on first use. Nothing under `no_std`.
    fn prepare_generator_table();
}

/// Implement [`HasGeneratorTable`] for a curve, with its own storage, in
/// windows of `$entries = 2^(W-1)` multiples.
macro_rules! generator_table_for {
    ($curve:ty, $entries:literal) => {
        /// This curve's generator table, and whether it has been filled.
        #[cfg(feature = "std")]
        fn generator_table() -> (
            &'static $crate::nist::gentable::Windows<$curve, $entries>,
            &'static std::sync::OnceLock<()>,
        ) {
            const USED: usize = $crate::nist::gentable::digit_count(
                <$curve as $crate::nist::point::Curve>::SCALAR_BYTES,
                ($entries as usize).trailing_zeros() as usize + 1,
            );
            #[allow(clippy::declare_interior_mutable_const)]
            const EMPTY: std::sync::OnceLock<
                $crate::nist::gentable::AffineWindow<$curve, $entries>,
            > = std::sync::OnceLock::new();
            static WINDOWS: [std::sync::OnceLock<
                $crate::nist::gentable::AffineWindow<$curve, $entries>,
            >; USED] = [EMPTY; USED];
            static BUILT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
            (&WINDOWS, &BUILT)
        }

        impl $crate::nist::gentable::HasGeneratorTable for $curve {
            #[cfg(feature = "std")]
            fn mul_generator(
                scalar: &<Self as $crate::nist::point::Curve>::Scalar,
            ) -> $crate::nist::point::Point<Self> {
                let (windows, built) = generator_table();
                $crate::nist::gentable::mul(windows, built, scalar)
            }

            #[cfg(not(feature = "std"))]
            fn mul_generator(
                scalar: &<Self as $crate::nist::point::Curve>::Scalar,
            ) -> $crate::nist::point::Point<Self> {
                $crate::nist::point::Point::<Self>::generator().mul_scalar(scalar)
            }

            #[cfg(feature = "std")]
            fn mul_generator_vartime(
                scalar: &<Self as $crate::nist::point::Curve>::Scalar,
            ) -> $crate::nist::point::Point<Self> {
                let (windows, built) = generator_table();
                $crate::nist::gentable::mul_vartime(windows, built, scalar)
            }

            #[cfg(not(feature = "std"))]
            fn mul_generator_vartime(
                scalar: &<Self as $crate::nist::point::Curve>::Scalar,
            ) -> $crate::nist::point::Point<Self> {
                $crate::nist::point::Point::<Self>::generator().mul_scalar_vartime(scalar)
            }

            fn prepare_generator_table() {
                #[cfg(feature = "std")]
                {
                    let (windows, built) = generator_table();
                    $crate::nist::gentable::prepare(windows, built);
                }
            }
        }
    };
}

pub(crate) use generator_table_for;

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    /// The recoding, read back: every width, scalars at the edges and a
    /// spread between, each digit in range and the digits summing to the
    /// scalar. Arithmetic in i128 over 15-byte scalars, independently of the
    /// curve code; 120 bits leaves every width's top window partly full.
    #[test]
    fn signed_digits_sum_to_the_scalar() {
        let mut cases: std::vec::Vec<[u8; 15]> = std::vec![[0; 15], [0xff; 15], [0x80; 15]];
        let mut x = [0u8; 15];
        for i in 0..200u32 {
            for (j, b) in x.iter_mut().enumerate() {
                *b = (i.wrapping_mul(2654435761) >> (j % 24)) as u8 ^ (j as u8).wrapping_mul(37);
            }
            cases.push(x);
        }
        for w in 4..=6 {
            for bytes in &cases {
                let digits = signed_digits_w(bytes, w);
                let n = digit_count(bytes.len(), w);
                let half = 1i128 << (w - 1);
                let mut sum = 0i128;
                for (i, d) in digits.iter().take(n).enumerate() {
                    let d = *d as i128;
                    if i + 1 == n {
                        assert!(0 <= d && d <= half, "top digit {d} at width {w}");
                    } else {
                        assert!(-half <= d && d < half, "digit {d} at width {w}");
                    }
                    sum += d << (w * i);
                }
                assert!(digits[n..].iter().all(|d| *d == 0));
                let want = bytes.iter().fold(0i128, |acc, b| (acc << 8) | *b as i128);
                assert_eq!(sum, want, "width {w}");
            }
        }
    }
}
