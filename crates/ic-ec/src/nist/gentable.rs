//! A precomputed table for multiplying a NIST curve's generator.
//!
//! # Why
//!
//! [`Point::mul_scalar`][super::point::Point::mul_scalar] is a
//! double-and-add-always ladder: every bit doubles and adds, and a conditional
//! move decides whether the addition counts. That is the right algorithm for an
//! arbitrary point and it is what ECDH needs.
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
//! The same construction [`crate::ed25519`] uses, and the reasoning is there in
//! full: signed radix-16 digits so only positive multiples are stored, one
//! table per *pair* of digits with the odd ones scaled by four doublings
//! applied once, and a lookup that reads every entry and selects with
//! conditional moves rather than indexing -- a table indexed by a secret is a
//! cache-timing channel.
//!
//! The differences are that a Weierstrass point negates in `y` rather than `x`
//! and `t`, and that the scalar width varies by curve, so the digit count is
//! computed from `C::SCALAR_BYTES` and the arrays are sized for the widest
//! curve this crate has.
//!
//! # Where it lives
//!
//! Behind `std`, built once into a `OnceLock`. P-256's table is about 25 KiB
//! and P-521's about 114 KiB, which is a reasonable trade on a host and a bad
//! one on a microcontroller; `no_std` keeps the ladder, which needs no storage.

#[cfg(feature = "std")]
use ic_core::ct::Choice;

#[cfg(feature = "std")]
use super::arith::Field;
use super::point::Curve;
#[cfg(feature = "std")]
use super::point::Point;

#[cfg(feature = "std")]
/// Digits for the widest curve here: P-521 has a 66-byte scalar, so 132
/// nibbles, plus one for the carry out of the top. See `signed_digits`.
const MAX_DIGITS: usize = 133;

#[cfg(feature = "std")]
/// Entries per table: the multiples `1..=8`.
const ENTRIES: usize = 8;

#[cfg(feature = "std")]
/// `1..=8` times some fixed multiple of the generator.
struct Window<C: Curve>([Point<C>; ENTRIES]);

#[cfg(feature = "std")]
impl<C: Curve> Window<C> {
    fn new(base: &Point<C>) -> Self {
        let mut entries = [Point::identity(); ENTRIES];
        entries[0] = *base;
        for i in 1..ENTRIES {
            entries[i] = entries[i - 1].add(base);
        }
        Self(entries)
    }

    /// `digit * base` for `digit` in `[-8, 8]`, without indexing by it.
    fn select(&self, digit: i8) -> Point<C> {
        let negative = Choice::from_u8((digit as u8) >> 7);
        let magnitude = ((digit as i16 ^ (digit as i16 >> 7)) - (digit as i16 >> 7)) as u8;

        let mut out = Point::identity();
        for (i, entry) in self.0.iter().enumerate() {
            let hit = Choice::from_u8(u8::from(magnitude == (i as u8 + 1)));
            Point::cmov(&mut out, entry, hit);
        }
        out.conditional_negate(negative);
        out
    }
}

/// Every multiple of the generator this algorithm needs.
///
/// The windows live on the heap and are pushed one at a time. An array sized
/// for the widest curve would be about 116 KiB for P-521, and building it as a
/// stack temporary before moving it into the `OnceLock` overflowed the stack --
/// which is how this first failed, in the FIPS self-test doctests. A `Vec` also
/// sizes each curve to what it actually uses rather than to P-521.
#[cfg(feature = "std")]
pub struct Table<C: Curve> {
    windows: std::vec::Vec<Window<C>>,
}

#[cfg(feature = "std")]
impl<C: Curve> Table<C> {
    /// Build it. Costs a little over one scalar multiplication, once.
    pub fn build() -> Self {
        // One window per pair of digits, and there are `2*SCALAR_BYTES + 1`
        // digits once the carry digit is counted.
        let used = C::SCALAR_BYTES + 1;
        let mut windows = std::vec::Vec::with_capacity(used);
        let mut base = Point::<C>::generator();
        for i in 0..used {
            if i > 0 {
                // times 16^2 = eight doublings.
                for _ in 0..8 {
                    base = base.double();
                }
            }
            windows.push(Window::new(&base));
        }
        Self { windows }
    }

    /// `scalar * G`.
    pub fn mul(&self, scalar: &C::Scalar) -> Point<C> {
        let bytes = scalar.to_bytes();
        let digits = signed_digits(bytes.as_ref());
        // Every nibble, plus the carry digit above them.
        let n = bytes.as_ref().len() * 2 + 1;
        debug_assert!(n.div_ceil(2) <= self.windows.len());

        let mut acc = Point::identity();
        for i in (1..n).step_by(2) {
            acc = acc.add(&self.windows[i / 2].select(digits[i]));
        }
        for _ in 0..4 {
            acc = acc.double();
        }
        for i in (0..n).step_by(2) {
            acc = acc.add(&self.windows[i / 2].select(digits[i]));
        }
        acc
    }
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
#[cfg(feature = "std")]
fn signed_digits(bytes: &[u8]) -> [i8; MAX_DIGITS] {
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
/// `std` it is the table; under `no_std` it is the ladder, so callers need no
/// conditional bound and the generic code has one shape.
///
/// It is separate from [`Curve`] because the table's storage is a `static`,
/// which has to live in a concrete function body: a `static` inside a generic
/// function is shared across every instantiation, which would hand P-384 the
/// P-256 table.
pub trait HasGeneratorTable: Curve + Sized + 'static {
    /// `scalar * G`.
    fn mul_generator(scalar: &Self::Scalar) -> super::point::Point<Self>;
}

/// Implement [`HasGeneratorTable`] for a curve, with its own storage.
#[macro_export]
macro_rules! generator_table_for {
    ($curve:ty) => {
        impl $crate::nist::gentable::HasGeneratorTable for $curve {
            #[cfg(feature = "std")]
            fn mul_generator(
                scalar: &<Self as $crate::nist::point::Curve>::Scalar,
            ) -> $crate::nist::point::Point<Self> {
                static TABLE: std::sync::OnceLock<$crate::nist::gentable::Table<$curve>> =
                    std::sync::OnceLock::new();
                TABLE
                    .get_or_init($crate::nist::gentable::Table::build)
                    .mul(scalar)
            }

            #[cfg(not(feature = "std"))]
            fn mul_generator(
                scalar: &<Self as $crate::nist::point::Curve>::Scalar,
            ) -> $crate::nist::point::Point<Self> {
                use $crate::nist::point::Curve as _;
                $crate::nist::point::Point::<Self>::generator().mul_scalar(scalar)
            }
        }
    };
}
