//! A precomputed table for multiplying a NIST curve's generator.
//!
//! # Why
//!
//! [`Point::mul_scalar`][super::point::Point::mul_scalar] handles an arbitrary
//! point: it builds `1..=8` times the point per call and walks the scalar four
//! bits at a time, which is what ECDH needs. Every digit still costs four
//! doublings, and for an arbitrary point nothing can remove them.
//!
//! The measurements below date from when `mul_scalar` was a
//! double-and-add-always ladder, one addition per bit.
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
//! Behind `std`, in a `static` per curve: one `OnceLock` per window, filled in
//! order on first use, or earlier through [`crate::prepare`]. P-256's table is
//! about 25 KiB and P-521's about 114 KiB, which is a reasonable trade on a
//! host and a bad one on a microcontroller. `no_std` multiplies the generator
//! with [`Point::mul_scalar`], which uses this module's [`Window`] and
//! [`signed_digits`] against the point it is given, one window built per call:
//! the same four bits per addition, without the storage.
//!
//! The storage is static, not heap. It used to be a `Vec`, and a caller that
//! forbids allocation after start-up -- a TLS engine running in caller-owned
//! memory -- met that allocation in the middle of its first handshake. A
//! single `OnceLock` holding every window would avoid the heap, but its value
//! is built on the stack and then moved in, which is 114 KiB of stack for
//! P-521; that overflowed once, and is why the `Vec` was there. A lock per
//! window needs neither: each window is built where it is stored, and at most
//! one window's worth of stack is in use at a time. `tests/cold_tables.rs`
//! checks that a first use allocates nothing.

use ic_core::ct::Choice;

#[cfg(feature = "std")]
use super::arith::Field;
use super::point::Curve;
use super::point::Point;
#[cfg(feature = "std")]
use super::point::{AffinePoint, Projective};

/// Digits for the widest curve here: P-521 has a 66-byte scalar, so 132
/// nibbles, plus one for the carry out of the top. See `signed_digits`.
const MAX_DIGITS: usize = 133;

/// Entries per table: the multiples `1..=8`.
const ENTRIES: usize = 8;

/// `1..=8` times some fixed point: a multiple of the generator in the table,
/// or the point being multiplied in [`Point::mul_scalar`].
pub(super) struct Window<C: Curve>([Point<C>; ENTRIES]);

impl<C: Curve> Window<C> {
    pub(super) fn new(base: &Point<C>) -> Self {
        let mut entries = [Point::identity(); ENTRIES];
        entries[0] = *base;
        for i in 1..ENTRIES {
            entries[i] = entries[i - 1].add(base);
        }
        Self(entries)
    }

    /// `digit * base` for `digit` in `[-8, 8]`, without indexing by it.
    pub(super) fn select(&self, digit: i8) -> Point<C> {
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

/// `1..=8` times one power of the generator, normalized to affine, for
/// [`Table`]: an affine entry makes the accumulator's addition one
/// multiplication cheaper. Normalizing costs an inversion per entry, once,
/// when the table is built.
#[cfg(feature = "std")]
pub struct AffineWindow<C: Curve>([AffinePoint<C>; ENTRIES]);

#[cfg(feature = "std")]
impl<C: Curve> AffineWindow<C> {
    /// `None` only if a multiple of `base` is the identity, which `1..=8`
    /// times a power of a generator of prime order above 8 never is.
    fn new(base: &Point<C>) -> Option<Self> {
        let window = Window::new(base);
        let mut entries = [AffinePoint {
            x: C::Field::ZERO,
            y: C::Field::ZERO,
        }; ENTRIES];
        for (out, entry) in entries.iter_mut().zip(window.0.iter()) {
            *out = entry.to_affine()?;
        }
        Some(Self(entries))
    }

    /// `acc + digit * base` for `digit` in `[-8, 8]`, without indexing by it.
    ///
    /// A zero digit selects the identity, which has no affine form, so the
    /// addition is made anyway -- on an arbitrary entry -- and its result
    /// discarded by a conditional move. The work is the same for every digit.
    fn add_to(&self, acc: &Projective<C>, digit: i8) -> Projective<C> {
        let negative = Choice::from_u8((digit as u8) >> 7);
        let magnitude = ((digit as i16 ^ (digit as i16 >> 7)) - (digit as i16 >> 7)) as u8;

        let mut x = self.0[0].x;
        let mut y = self.0[0].y;
        for (i, entry) in self.0.iter().enumerate() {
            let hit = Choice::from_u8(u8::from(magnitude == (i as u8 + 1)));
            C::Field::cmov(&mut x, &entry.x, hit);
            C::Field::cmov(&mut y, &entry.y, hit);
        }
        let ny = y.neg();
        C::Field::cmov(&mut y, &ny, negative);

        let mut out = acc.add_affine(&x, &y);
        Projective::cmov(&mut out, acc, Choice::from_u8(u8::from(magnitude == 0)));
        out
    }
}

/// One curve's windows: `16^(2i) * G` and its multiples `1..=8`, for each `i`.
#[cfg(feature = "std")]
pub type Windows<C> = [std::sync::OnceLock<AffineWindow<C>>];

/// The window for `base`, which is always a nonzero multiple of the generator.
#[cfg(feature = "std")]
fn window_for<C: Curve>(base: &Point<C>) -> AffineWindow<C> {
    match AffineWindow::new(base) {
        Some(window) => window,
        None => unreachable!("a multiple of the generator below its order is the identity"),
    }
}

/// Fill every window, in order, sharing the doublings between them.
///
/// Costs a little over one scalar multiplication, once. `built` makes it run
/// once: a second caller waits for the first rather than repeating the work.
#[cfg(feature = "std")]
pub fn prepare<C: Curve>(windows: &Windows<C>, built: &std::sync::OnceLock<()>) {
    built.get_or_init(|| {
        let mut base = Point::<C>::generator();
        for (i, slot) in windows.iter().enumerate() {
            if i > 0 {
                // times 16^2 = eight doublings.
                for _ in 0..8 {
                    base = base.double();
                }
            }
            slot.get_or_init(|| window_for(&base));
        }
    });
}

/// `scalar * G`.
#[cfg(feature = "std")]
pub fn mul<C: Curve>(
    windows: &Windows<C>,
    built: &std::sync::OnceLock<()>,
    scalar: &C::Scalar,
) -> Point<C> {
    prepare(windows, built);
    // Every window is filled by now. Each read still goes through
    // `get_or_init`, building that one window by itself if it somehow were
    // not, which is slower and gives the same answer rather than a panic.
    let window = |i: usize| {
        windows[i].get_or_init(|| {
            let mut base = Point::<C>::generator();
            for _ in 0..8 * i {
                base = base.double();
            }
            window_for(&base)
        })
    };

    let bytes = scalar.to_bytes();
    let digits = signed_digits(bytes.as_ref());
    // Every nibble, plus the carry digit above them.
    let n = bytes.as_ref().len() * 2 + 1;
    debug_assert!(n.div_ceil(2) <= windows.len());

    // Accumulated projectively; see `Projective` for why.
    let mut acc = Projective::identity();
    for i in (1..n).step_by(2) {
        acc = window(i / 2).add_to(&acc, digits[i]);
    }
    for _ in 0..4 {
        acc = acc.double();
    }
    for i in (0..n).step_by(2) {
        acc = window(i / 2).add_to(&acc, digits[i]);
    }
    acc.to_jacobian()
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
    /// `scalar * G`.
    fn mul_generator(scalar: &Self::Scalar) -> super::point::Point<Self>;

    /// Build the table now rather than on first use. Nothing under `no_std`.
    fn prepare_generator_table();
}

/// Implement [`HasGeneratorTable`] for a curve, with its own storage.
macro_rules! generator_table_for {
    ($curve:ty) => {
        /// This curve's generator table, and whether it has been filled.
        #[cfg(feature = "std")]
        fn generator_table() -> (
            &'static $crate::nist::gentable::Windows<$curve>,
            &'static std::sync::OnceLock<()>,
        ) {
            const USED: usize = <$curve as $crate::nist::point::Curve>::SCALAR_BYTES + 1;
            #[allow(clippy::declare_interior_mutable_const)]
            const EMPTY: std::sync::OnceLock<$crate::nist::gentable::AffineWindow<$curve>> =
                std::sync::OnceLock::new();
            static WINDOWS: [std::sync::OnceLock<$crate::nist::gentable::AffineWindow<$curve>>;
                USED] = [EMPTY; USED];
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
