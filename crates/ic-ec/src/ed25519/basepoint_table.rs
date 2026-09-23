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
//! Behind `std`, because it is built once into a `OnceLock` on first use rather
//! than written into the binary. Forty kilobytes of tables is a reasonable
//! trade on a server and a bad one on a microcontroller, and this library
//! targets both; `no_std` keeps the bit-at-a-time path, which is correct and
//! needs no storage at all.

use ic_core::ct::Choice;

use super::{basepoint, Point};

/// Digits per scalar, radix 16 over 256 bits.
const DIGITS: usize = 64;

/// Entries per table: the multiples `1..=8`.
const ENTRIES: usize = 8;

/// One table per *pair* of digits; see the module note.
const TABLES: usize = DIGITS / 2;

/// `1..=8` times some fixed multiple of the basepoint.
struct Window([Point; ENTRIES]);

impl Window {
    /// Build the multiples of `base`.
    fn new(base: &Point) -> Self {
        let mut entries = [Point::IDENTITY; ENTRIES];
        entries[0] = *base;
        for i in 1..ENTRIES {
            entries[i] = entries[i - 1].add(base);
        }
        Self(entries)
    }

    /// `digit * base`, for `digit` in `[-8, 8]`, without indexing by it.
    ///
    /// Reads every entry and selects with conditional moves. Indexing would be
    /// a secret-dependent memory access, which is exactly what this workspace
    /// avoids elsewhere at considerably greater cost.
    fn select(&self, digit: i8) -> Point {
        let negative = Choice::from_u8((digit as u8) >> 7);
        // |digit|, computed without a branch.
        let magnitude = ((digit as i16 ^ (digit as i16 >> 7)) - (digit as i16 >> 7)) as u8;

        let mut out = Point::IDENTITY;
        for (i, entry) in self.0.iter().enumerate() {
            // `magnitude == i + 1`, as a Choice.
            let hit = Choice::from_u8(u8::from(magnitude == (i as u8 + 1)));
            out.cmov(entry, hit);
        }
        out.conditional_negate(negative);
        out
    }
}

/// Every multiple of the basepoint this algorithm needs.
pub struct Table {
    windows: [Window; TABLES],
}

impl Table {
    /// Build it. Costs about one and a half scalar multiplications, once.
    fn build() -> Self {
        let b = basepoint();
        // Start at B, and step by 16^2 between windows.
        let mut base = b;
        let windows = core::array::from_fn(|i| {
            if i > 0 {
                // times 16^2 = eight doublings.
                for _ in 0..8 {
                    base = base.double();
                }
            }
            Window::new(&base)
        });
        Self { windows }
    }

    /// `scalar * B`, with the scalar in little-endian canonical form.
    pub fn mul(&self, scalar: &[u8; 32]) -> Point {
        let digits = signed_digits(scalar);

        // Odd digits first, then four doublings to scale them by 16, then the
        // even ones. Both halves read the same tables; see the module note.
        let mut acc = Point::IDENTITY;
        for i in (1..DIGITS).step_by(2) {
            acc = acc.add(&self.windows[i / 2].select(digits[i]));
        }
        for _ in 0..4 {
            acc = acc.double();
        }
        for i in (0..DIGITS).step_by(2) {
            acc = acc.add(&self.windows[i / 2].select(digits[i]));
        }
        acc
    }
}

/// The scalar as 64 signed radix-16 digits, each in `[-8, 8]`.
///
/// A nibble above 8 becomes `nibble - 16` with a carry into the next digit,
/// which is what keeps the table to the positive multiples.
///
/// Only the first 63 digits are recoded. The last one is left to absorb the
/// final carry, because a carry *out* of the top would be a factor of `16^64`
/// with nowhere to go -- silently dropping it would give the wrong point. That
/// works because every scalar reaching here has its top byte at most 127: the
/// clamped secret has bit 255 cleared by construction, and `r` and `s` are
/// reduced modulo the group order and so are far smaller. The top nibble is
/// then at most 7, one carry takes it to 8, and 8 is in range.
///
/// The first version of this recoded all 64 and dropped that carry. The
/// agreement test below caught it.
fn signed_digits(scalar: &[u8; 32]) -> [i8; DIGITS] {
    debug_assert!(
        scalar[31] <= 127,
        "the top digit can only absorb the final carry for scalars below 2^255"
    );

    let mut nibbles = [0i8; DIGITS];
    for (i, byte) in scalar.iter().enumerate() {
        nibbles[i * 2] = (byte & 0x0f) as i8;
        nibbles[i * 2 + 1] = (byte >> 4) as i8;
    }

    for i in 0..DIGITS - 1 {
        let carry = (nibbles[i] + 8) >> 4;
        nibbles[i] -= carry << 4;
        nibbles[i + 1] += carry;
    }
    nibbles
}

/// The table, built once.
#[cfg(feature = "std")]
pub fn table() -> &'static Table {
    use std::sync::OnceLock;
    static TABLE: OnceLock<Table> = OnceLock::new();
    TABLE.get_or_init(Table::build)
}

/// Odd multiples of the basepoint, `1B, 3B, 5B .. 127B`.
///
/// The variable-time companion to [`table`]. Verification may index a table
/// directly -- it holds nothing secret -- so this one is a plain array read
/// rather than a conditional-move scan, and the window is width 8 instead of
/// the signed radix 16 above. Sixty-four points, about ten kilobytes, built
/// once on first use.
///
/// Signing must not call this. See
/// [`double_scalar_mul_vartime`][super::double_scalar_mul_vartime].
#[cfg(feature = "std")]
pub(super) fn odd_multiples() -> &'static [Point; 64] {
    use std::sync::OnceLock;
    static ODD: OnceLock<[Point; 64]> = OnceLock::new();
    ODD.get_or_init(|| {
        let b = basepoint();
        let twice = b.double();
        let mut out = [b; 64];
        for i in 1..64 {
            out[i] = out[i - 1].add(&twice);
        }
        out
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
            let fast = table().mul(s);
            let slow = basepoint().mul_scalar(s);
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
