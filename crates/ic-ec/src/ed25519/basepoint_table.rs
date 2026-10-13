//! A precomputed table for multiplying the Ed25519 basepoint.
//!
//! # Why this exists
//!
//! [`Point::mul_scalar`][super::Point::mul_scalar] walks the scalar one bit at
//! a time, doubling and adding at every position and selecting between the two
//! with a conditional move so the trace does not depend on the scalar. That is
//! 256 doublings and 256 additions, and it is the right algorithm for an
//! arbitrary point.
//!
//! The basepoint is not arbitrary. It is the same point in every signature ever
//! made, so its multiples can be computed once and looked up, and the doublings
//! disappear almost entirely: this performs 64 additions and 4 doublings.
//!
//! # The shape
//!
//! The scalar becomes 64 signed digits in `[-8, 8]`, radix 16. Signed digits
//! halve the table -- only the positive multiples are stored and a negative
//! digit negates on the way out, which on a twisted Edwards curve is two field
//! negations and nothing else.
//!
//! Thirty-two tables rather than sixty-four, each holding `1..=8` times
//! `16^(2j) * B`. The even-numbered digits read them directly; the odd ones
//! read the same tables and are then scaled by four doublings applied once to
//! the running sum. That halves the memory for one doubling per two digits.
//!
//! # Constant time
//!
//! A table indexed by a secret is a cache-timing side channel, which is the
//! whole reason the AES S-box in this workspace is computed rather than looked
//! up. So the lookup here is not an index: it reads all eight entries and
//! selects with conditional moves, and the sign is applied the same way. The
//! cost is why the digit is only four bits wide.
//!
//! # Where it lives
//!
//! Behind `std`, because it is built once on first use, or earlier through
//! [`crate::prepare`], rather than written into the binary. It is held in
//! statics, a `OnceLock` per window and per odd multiple, so building it
//! allocates nothing and needs about one window of stack, where a single
//! `OnceLock` around the whole table would build its 30 KiB on the caller's
//! stack before moving it in. Forty kilobytes of tables is a reasonable
//! trade on a server and a bad one on a microcontroller, and this library
//! targets both. `no_std` uses the same signed radix-16 digits against a
//! single window of `1..=8` times the basepoint, built on the stack per call
//! and discarded -- `mul_scalar_windowed` in the parent module. That keeps the
//! 64 additions and gives back the doublings, 252 of them, which is what forty
//! kilobytes buys. It is still about twice as fast as the bit-at-a-time ladder
//! it replaced there, and needs no storage that outlives the call.

use std::sync::OnceLock;

use super::{basepoint, signed_digits, AffineNiels, EdField, Ext};

/// Digits per scalar, radix 16 over 256 bits.
const DIGITS: usize = 64;

/// Entries per table: the multiples `1..=8`.
const ENTRIES: usize = 8;

/// One table per *pair* of digits; see the module note.
const TABLES: usize = DIGITS / 2;

/// `1..=8` times some fixed multiple of the basepoint, in affine Niels form.
///
/// Affine because an entry is only ever added to something: storing
/// `(y+x, y-x, 2d·x·y)` makes that addition three multiplications instead of
/// nine, and stores three field elements instead of four, which is a quarter
/// less for the conditional-move scan below to walk.
pub(crate) struct Window<F>([AffineNiels<F>; ENTRIES]);

impl<F: EdField> Window<F> {
    /// The multiples `1..=8`, for building the four-lane copy.
    #[cfg(all(target_arch = "x86_64", not(any(ic_limb32, ic_ec_portable))))]
    pub(super) fn entries(&self) -> &[AffineNiels<F>; ENTRIES] {
        &self.0
    }

    /// Build the multiples of `base`.
    fn new(base: &Ext<F>) -> Self {
        let mut multiples = [*base; ENTRIES];
        for i in 1..ENTRIES {
            multiples[i] = multiples[i - 1].add(base);
        }
        Self(core::array::from_fn(|i| multiples[i].to_affine_niels()))
    }

    /// `digit * base`, for `digit` in `[-8, 8]`, without indexing by it.
    ///
    /// Reads every entry and selects with conditional moves. Indexing would be
    /// a secret-dependent memory access, which is exactly what this workspace
    /// avoids elsewhere at considerably greater cost.
    pub(super) fn select(&self, digit: i8) -> AffineNiels<F> {
        // The sign and |digit|, computed without a branch.
        let negative = u64::from((digit as u8) >> 7);
        let magnitude = ((digit as i16 ^ (digit as i16 >> 7)) - (digit as i16 >> 7)) as u64;

        let mut out = AffineNiels::IDENTITY;
        for (i, entry) in self.0.iter().enumerate() {
            // `magnitude == i + 1` as 0 or 1, by arithmetic rather than a
            // comparison: the difference is zero exactly then, and subtracting
            // one from zero is the only way to set the top bit here.
            let hit = (magnitude ^ (i as u64 + 1)).wrapping_sub(1) >> 63;
            out.cmov(entry, hit);
        }
        out.conditional_negate(negative);
        out
    }
}

/// A field with its own copy of the tables.
///
/// The tables are statics, and a static cannot be generic, so each field
/// that runs the curve code names its own here. Only the field the CPU
/// selects is ever filled; the other's `OnceLock`s stay empty and cost their
/// own size in `.bss` and nothing else.
pub(crate) trait TableField: EdField {
    /// `1..=8` times `16^(2j) * B`, for each `j`.
    fn windows() -> &'static [OnceLock<Window<Self>>; TABLES];
    /// `1B, 3B, 5B .. 127B`; see [`odd_multiple`].
    fn odd() -> &'static [OnceLock<AffineNiels<Self>>; 64];
    /// Whether both tables have been filled.
    fn built() -> &'static OnceLock<()>;

    /// `scalar * B`, constant time: [`mul_generic`] unless the field has a
    /// faster form of the same algorithm.
    fn mul_base(scalar: &[u8; 32]) -> Ext<Self> {
        mul_generic::<Self>(scalar)
    }

    /// `[k]A + [s]B`, variable time:
    /// [`double_scalar_mul_vartime_generic`][super::double_scalar_mul_vartime_generic]
    /// unless the field has a faster form of the same algorithm.
    fn double_mul(a: &Ext<Self>, k: &[u8; 32], s: &[u8; 32]) -> Ext<Self> {
        super::double_scalar_mul_vartime_generic(a, k, s)
    }
}

macro_rules! tables {
    ($f:ty $(, $fast:item)*) => {
        impl TableField for $f {
            $($fast)*
            fn windows() -> &'static [OnceLock<Window<Self>>; TABLES] {
                #[allow(clippy::declare_interior_mutable_const)]
                const NO_WINDOW: OnceLock<Window<$f>> = OnceLock::new();
                static WINDOWS: [OnceLock<Window<$f>>; TABLES] = [NO_WINDOW; TABLES];
                &WINDOWS
            }
            fn odd() -> &'static [OnceLock<AffineNiels<Self>>; 64] {
                #[allow(clippy::declare_interior_mutable_const)]
                const NO_POINT: OnceLock<AffineNiels<$f>> = OnceLock::new();
                static ODD: [OnceLock<AffineNiels<$f>>; 64] = [NO_POINT; 64];
                &ODD
            }
            fn built() -> &'static OnceLock<()> {
                static BUILT: OnceLock<()> = OnceLock::new();
                &BUILT
            }
        }
    };
}

tables!(crate::field::Fe);
#[cfg(all(target_arch = "x86_64", not(any(ic_limb32, ic_ec_portable))))]
tables!(
    crate::fe64::Fe64,
    // Four lanes at once where the CPU has IFMA; one group operation per
    // assembly block where it has only BMI2 and ADX.
    fn mul_base(scalar: &[u8; 32]) -> Ext<Self> {
        match crate::f51x4::Ifma::get() {
            Some(t) => super::vector::mul_base(t, scalar),
            None => super::fast::mul_base(scalar),
        }
    },
    fn double_mul(a: &Ext<Self>, k: &[u8; 32], s: &[u8; 32]) -> Ext<Self> {
        match crate::f51x4::Ifma::get() {
            Some(t) => super::vector::double_mul(t, a, k, s),
            None => super::fast::double_mul(a, k, s),
        }
    }
);

/// Fill both tables for `F`, in order, sharing the doublings between entries.
///
/// Costs about one and a half scalar multiplications for the signing table and
/// sixty-four additions for the other, once. A second caller waits for the
/// first rather than repeating the work.
pub fn prepare<F: TableField>() {
    F::built().get_or_init(|| {
        // Start at B, and step by 16^2 between windows.
        let mut base = basepoint::<F>();
        for (i, slot) in F::windows().iter().enumerate() {
            if i > 0 {
                // times 16^2 = eight doublings.
                for _ in 0..8 {
                    base = base.double();
                }
            }
            slot.get_or_init(|| Window::new(&base));
        }

        let b = basepoint::<F>();
        let twice = b.double();
        let mut multiple = b;
        for (i, slot) in F::odd().iter().enumerate() {
            if i > 0 {
                multiple = multiple.add(&twice);
            }
            // Affine Niels, since every one of them exists only to be added:
            // three multiplications each instead of nine.
            slot.get_or_init(|| multiple.to_affine_niels());
        }
    });
}

/// Window `i`. Filled by [`prepare`]; were it somehow not, it is built here on
/// its own, more slowly and with the same result, rather than panicking.
pub(super) fn window<F: TableField>(i: usize) -> &'static Window<F> {
    F::windows()[i].get_or_init(|| {
        let mut base = basepoint::<F>();
        for _ in 0..8 * i {
            base = base.double();
        }
        Window::new(&base)
    })
}

/// `scalar * B`, with the scalar in little-endian canonical form.
pub fn mul<F: TableField>(scalar: &[u8; 32]) -> Ext<F> {
    F::mul_base(scalar)
}

/// [`mul`] in the field's own arithmetic, one method call per operation.
pub fn mul_generic<F: TableField>(scalar: &[u8; 32]) -> Ext<F> {
    prepare::<F>();
    let digits = signed_digits(scalar);

    // Odd digits first, then four doublings to scale them by 16, then the
    // even ones. Both halves read the same tables; see the module note.
    let mut acc = Ext::IDENTITY;
    for i in (1..DIGITS).step_by(2) {
        acc = acc
            .add_affine_niels(&window::<F>(i / 2).select(digits[i]))
            .to_extended();
    }
    for _ in 0..4 {
        acc = acc.double();
    }
    for i in (0..DIGITS).step_by(2) {
        acc = acc
            .add_affine_niels(&window::<F>(i / 2).select(digits[i]))
            .to_extended();
    }
    acc
}

/// `(2i + 1) * B`, for `i` in `0..64`.
///
/// The variable-time companion to [`mul`]. Verification may index a table
/// directly -- it holds nothing secret -- so this one is a plain array read
/// rather than a conditional-move scan, and the window is width 8 instead of
/// the signed radix 16 above. Sixty-four points, about ten kilobytes, filled
/// by [`prepare`], which the caller runs first.
///
/// Signing must not call this. See
/// [`double_scalar_mul_vartime`][super::double_scalar_mul_vartime].
pub(super) fn odd_multiple<F: TableField>(i: usize) -> &'static AffineNiels<F> {
    F::odd()[i].get_or_init(|| {
        let b = basepoint::<F>();
        let twice = b.double();
        let mut multiple = b;
        for _ in 0..i {
            multiple = multiple.add(&twice);
        }
        multiple.to_affine_niels()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::traits::SignatureScheme as _;

    /// The table path must agree with the bit-at-a-time path.
    ///
    /// This is the whole correctness argument. `mul_scalar` is validated by RFC
    /// 8032's vectors; nothing validates the table except that it produces the
    /// same answers, so it is compared over scalars chosen to exercise the
    /// digit recoding -- zero, one, values that carry at every nibble, and the
    /// top of the range.
    #[cfg(feature = "std")]
    #[test]
    fn the_table_agrees_with_bitwise_multiplication() {
        // Every one has its top byte at most 127, which is the precondition
        // `signed_digits` documents and every caller satisfies.
        let mut scalars: std::vec::Vec<[u8; 32]> = std::vec![
            [0u8; 32],
            [1u8; 32],
            // Every nibble 8, the boundary the recoding turns negative.
            {
                let mut s = [0x88u8; 32];
                s[31] = 0x08;
                s
            },
            // Every nibble 9, which carries at every position.
            {
                let mut s = [0x99u8; 32];
                s[31] = 0x09;
                s
            },
            // The largest the precondition allows, carrying all the way up.
            {
                let mut s = [0xffu8; 32];
                s[31] = 127;
                s
            },
        ];
        let mut one = [0u8; 32];
        one[0] = 1;
        scalars.push(one);
        // A canonical-looking scalar with the high bits Ed25519 clamping sets.
        let mut clamped = [0x5au8; 32];
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;
        scalars.push(clamped);

        let mut checked = 0;
        for s in &scalars {
            let fast = mul::<crate::field::Fe>(s);
            let slow = basepoint::<crate::field::Fe>().mul_scalar(s);
            assert_eq!(
                fast.compress(),
                slow.compress(),
                "table and bitwise multiplication differ for {s:02x?}"
            );
            checked += 1;
        }
        assert_eq!(checked, 7, "the comparison did not run");
    }

    /// The recoding must represent the scalar it was given.
    ///
    /// Checked by evaluating the digits back to an integer modulo a small
    /// prime, which catches a sign or carry error that the curve comparison
    /// above would also catch but less legibly.
    #[test]
    fn the_signed_digits_represent_the_scalar() {
        let mut top = [0xffu8; 32];
        top[31] = 127;
        let mut eights = [0x88u8; 32];
        eights[31] = 0x08;
        let mut nines = [0x99u8; 32];
        nines[31] = 0x09;
        for raw in [[0u8; 32], [1u8; 32], eights, nines, top] {
            let digits = signed_digits(&raw);
            for d in digits {
                assert!((-8..=8).contains(&d), "digit {d} out of range");
            }
            // Evaluate sum(d_i * 16^i) mod m, and the scalar mod m, for a
            // modulus small enough to do in u64 and unrelated to the curve.
            const M: u64 = 1_000_000_007;
            let mut from_digits = 0u64;
            let mut power = 1u64;
            for d in digits {
                let term = ((d as i64).rem_euclid(M as i64)) as u64;
                from_digits = (from_digits + term * power) % M;
                power = power * 16 % M;
            }
            let mut from_bytes = 0u64;
            let mut p = 1u64;
            for byte in raw {
                from_bytes = (from_bytes + (byte as u64) * p) % M;
                p = p * 256 % M;
            }
            assert_eq!(from_digits, from_bytes, "recoding changed the value");
        }
    }

    /// Signing must still match the published vectors through the new path.
    #[cfg(feature = "std")]
    #[test]
    fn rfc8032_still_passes_through_the_table() {
        // RFC 8032 section 7.1, the first test vector.
        let seed = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let mut pk = [0u8; 32];
        super::super::Ed25519::public_key(&seed, &mut pk).unwrap();
        assert_eq!(
            ic_core::codec::hex(&pk),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        );
    }
}
