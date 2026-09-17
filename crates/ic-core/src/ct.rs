//! Constant-time primitives.
//!
//! Every routine here executes in time independent of the *values* of its
//! secret inputs (lengths are considered public). The implementations avoid
//! branches and table lookups on secret data, and pass results through
//! [`core::hint::black_box`] to stop the optimizer from re-introducing a branch
//! when it proves a value is boolean.

use core::hint::black_box;

/// A branch-free boolean whose value is never observable through control flow.
///
/// Stored as `0` or `1` so it can be expanded to a full-width bitmask by
/// [`Choice::mask`] and consumed by the `select_*` helpers.
#[must_use = "a Choice carries the outcome of a constant-time comparison"]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Choice(u8);

impl Choice {
    /// The false value.
    pub const FALSE: Choice = Choice(0);
    /// The true value.
    pub const TRUE: Choice = Choice(1);

    /// Build a `Choice` that is true whenever `v` is non-zero.
    #[inline]
    pub fn from_u8(v: u8) -> Self {
        Choice(((v | v.wrapping_neg()) >> 7) & 1)
    }

    /// Reveal the boolean as `0` or `1`.
    ///
    /// This is the one place a secret becomes branchable; call it once, at the
    /// API boundary.
    #[inline]
    pub fn unwrap_u8(self) -> u8 {
        black_box(self.0)
    }

    /// Full-width mask: `0x00` when false, `0xFF` when true.
    #[inline]
    pub fn mask(self) -> u8 {
        black_box(self.0.wrapping_neg())
    }

    /// Logical negation, branch-free.
    ///
    /// Deliberately an inherent method rather than `core::ops::Not`: callers
    /// use it in constant-time chains where the operator form would invite an
    /// accidental `!` on a `bool` instead.
    #[allow(clippy::should_implement_trait)]
    #[inline]
    pub fn not(self) -> Self {
        Choice(self.0 ^ 1)
    }

    /// Logical AND, branch-free.
    #[inline]
    pub fn and(self, other: Self) -> Self {
        Choice(self.0 & other.0)
    }

    /// Logical OR, branch-free.
    #[inline]
    pub fn or(self, other: Self) -> Self {
        Choice(self.0 | other.0)
    }
}

impl From<Choice> for bool {
    #[inline]
    fn from(c: Choice) -> bool {
        c.unwrap_u8() == 1
    }
}

/// Constant-time equality over two byte slices.
///
/// Returns [`Choice::FALSE`] immediately on a length mismatch. Lengths are
/// public in every IronCrypto API, so this leaks nothing secret.
#[inline]
pub fn eq(a: &[u8], b: &[u8]) -> Choice {
    if a.len() != b.len() {
        return Choice::FALSE;
    }
    let mut acc: u8 = 0;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    Choice::from_u8(acc).not()
}

/// Constant-time byte-slice comparison returning a plain `bool`.
///
/// Use this for MAC and AEAD tag verification instead of `==`.
#[inline]
#[must_use = "this is the result of a cryptographic verification; discarding it accepts everything"]
pub fn verify(expected: &[u8], actual: &[u8]) -> bool {
    eq(expected, actual).into()
}

/// Branch-free select: returns `a` when `c` is true, otherwise `b`.
#[inline]
pub fn select_u8(c: Choice, a: u8, b: u8) -> u8 {
    let m = c.mask();
    b ^ (m & (a ^ b))
}

/// Branch-free select over `u32`.
#[inline]
pub fn select_u32(c: Choice, a: u32, b: u32) -> u32 {
    let m = (c.unwrap_u8() as u32).wrapping_neg();
    b ^ (m & (a ^ b))
}

/// Branch-free select over `u64`.
#[inline]
pub fn select_u64(c: Choice, a: u64, b: u64) -> u64 {
    let m = (c.unwrap_u8() as u64).wrapping_neg();
    b ^ (m & (a ^ b))
}

/// Conditionally swap two equal-length buffers in constant time.
///
/// Used by Montgomery ladders to hide which scalar bit is being processed.
#[inline]
pub fn cswap(c: Choice, a: &mut [u8], b: &mut [u8]) {
    debug_assert_eq!(a.len(), b.len());
    let m = c.mask();
    let n = core::cmp::min(a.len(), b.len());
    for i in 0..n {
        let t = m & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

/// Copy `src` over `dst` only when `c` is true, in constant time.
#[inline]
pub fn cmov(c: Choice, dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());
    let m = c.mask();
    let n = core::cmp::min(dst.len(), src.len());
    for i in 0..n {
        dst[i] ^= m & (dst[i] ^ src[i]);
    }
}

/// Constant-time `a < b` over big-endian byte strings of equal length.
pub fn lt_be(a: &[u8], b: &[u8]) -> Choice {
    debug_assert_eq!(a.len(), b.len());
    let mut borrow: u16 = 0;
    for i in (0..a.len()).rev() {
        let d = (a[i] as u16).wrapping_sub(b[i] as u16).wrapping_sub(borrow);
        borrow = (d >> 8) & 1;
    }
    Choice::from_u8(borrow as u8)
}

/// Constant-time check that every byte of `x` is zero.
#[inline]
pub fn is_zero(x: &[u8]) -> Choice {
    let mut acc = 0u8;
    for &b in x {
        acc |= b;
    }
    Choice::from_u8(acc).not()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eq_matches_semantics() {
        assert!(bool::from(eq(b"abc", b"abc")));
        assert!(!bool::from(eq(b"abc", b"abd")));
        assert!(!bool::from(eq(b"abc", b"ab")));
        assert!(bool::from(eq(b"", b"")));
    }

    #[test]
    fn select_picks_correct_branch() {
        assert_eq!(select_u8(Choice::TRUE, 0xAA, 0x55), 0xAA);
        assert_eq!(select_u8(Choice::FALSE, 0xAA, 0x55), 0x55);
        assert_eq!(select_u32(Choice::TRUE, 1, 2), 1);
        assert_eq!(select_u64(Choice::FALSE, 1, 2), 2);
    }

    #[test]
    fn cswap_is_conditional() {
        let (mut a, mut b) = ([1u8, 2, 3], [4u8, 5, 6]);
        cswap(Choice::FALSE, &mut a, &mut b);
        assert_eq!((a, b), ([1, 2, 3], [4, 5, 6]));
        cswap(Choice::TRUE, &mut a, &mut b);
        assert_eq!((a, b), ([4, 5, 6], [1, 2, 3]));
    }

    #[test]
    fn cmov_is_conditional() {
        let mut dst = [0u8; 4];
        cmov(Choice::FALSE, &mut dst, &[9, 9, 9, 9]);
        assert_eq!(dst, [0, 0, 0, 0]);
        cmov(Choice::TRUE, &mut dst, &[9, 9, 9, 9]);
        assert_eq!(dst, [9, 9, 9, 9]);
    }

    #[test]
    fn lt_be_orders_correctly() {
        assert!(bool::from(lt_be(&[0, 1], &[0, 2])));
        assert!(!bool::from(lt_be(&[0, 2], &[0, 1])));
        assert!(!bool::from(lt_be(&[0, 2], &[0, 2])));
        assert!(bool::from(lt_be(&[0x00, 0xFF], &[0x01, 0x00])));
    }

    #[test]
    fn is_zero_detects_all_zero() {
        assert!(bool::from(is_zero(&[0, 0, 0])));
        assert!(!bool::from(is_zero(&[0, 1, 0])));
    }
}
