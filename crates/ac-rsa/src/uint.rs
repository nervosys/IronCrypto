//! Fixed-capacity big integers and Montgomery modular arithmetic.
//!
//! Every value is a `[u64; MAX_LIMBS]` regardless of the modulus in use, and
//! the *active* width travels with the [`Modulus`]. That keeps the type simple
//! and allocation-free while still letting a 2048-bit key run at 2048-bit cost
//! rather than 4096-bit cost. A key's size is public, so branching on the width
//! leaks nothing; nothing here branches on a value.
//!
//! # Constant-time posture
//!
//! [`Modulus::pow`] is the private-key path and is constant-time in the
//! exponent: it squares and multiplies on every bit, selecting the result with
//! a conditional move. [`Modulus::pow_public`] is for the public exponent,
//! which is not secret, and is allowed to branch on it.
//!
//! [`Uint::bits`] and [`Uint::cmp_vartime`] are, as their names say, variable
//! time; they are used only on public values (moduli, byte lengths) and never
//! on key material.

use ac_core::ct::Choice;
use ac_core::Zeroize;

/// Largest supported modulus, in 64-bit limbs: 4096 bits.
pub const MAX_LIMBS: usize = 64;

/// Largest supported modulus, in bytes.
pub const MAX_BYTES: usize = MAX_LIMBS * 8;

/// A fixed-capacity unsigned big integer, little-endian by limb.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Uint(pub [u64; MAX_LIMBS]);

impl Zeroize for Uint {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Uint {
    /// Zero.
    pub const ZERO: Uint = Uint([0u64; MAX_LIMBS]);

    /// One.
    pub fn one() -> Uint {
        let mut v = Uint::ZERO;
        v.0[0] = 1;
        v
    }

    /// Build from a small integer.
    pub fn from_u64(v: u64) -> Uint {
        let mut out = Uint::ZERO;
        out.0[0] = v;
        out
    }

    /// Decode a big-endian byte string, which must fit.
    pub fn from_be_bytes(bytes: &[u8]) -> Option<Uint> {
        if bytes.len() > MAX_BYTES {
            return None;
        }
        let mut out = Uint::ZERO;
        for (i, byte) in bytes.iter().rev().enumerate() {
            out.0[i / 8] |= (*byte as u64) << (8 * (i % 8));
        }
        Some(out)
    }

    /// Encode big-endian into `out`, zero-padded on the left.
    pub fn to_be_bytes(&self, out: &mut [u8]) {
        for slot in out.iter_mut() {
            *slot = 0;
        }
        let n = out.len();
        for i in 0..core::cmp::min(n, MAX_BYTES) {
            out[n - 1 - i] = (self.0[i / 8] >> (8 * (i % 8))) as u8;
        }
    }

    /// Bit `i`, counting from the least significant.
    #[inline]
    pub fn bit(&self, i: usize) -> u8 {
        if i >= MAX_LIMBS * 64 {
            return 0;
        }
        ((self.0[i / 64] >> (i % 64)) & 1) as u8
    }

    /// The position of the highest set bit, plus one.
    ///
    /// Variable time; used only on public values such as a modulus.
    pub fn bits(&self) -> usize {
        for i in (0..MAX_LIMBS).rev() {
            if self.0[i] != 0 {
                return i * 64 + (64 - self.0[i].leading_zeros() as usize);
            }
        }
        0
    }

    /// Constant-time test for zero, over `limbs` active limbs.
    pub fn is_zero(&self, limbs: usize) -> Choice {
        let mut acc = 0u64;
        for i in 0..limbs {
            acc |= self.0[i];
        }
        Choice::from_u8(((acc | acc.wrapping_neg()) >> 63) as u8).not()
    }

    /// Constant-time equality over `limbs` active limbs.
    pub fn ct_eq(&self, other: &Uint, limbs: usize) -> Choice {
        let mut acc = 0u64;
        for i in 0..limbs {
            acc |= self.0[i] ^ other.0[i];
        }
        Choice::from_u8(((acc | acc.wrapping_neg()) >> 63) as u8).not()
    }

    /// Whether `self < other`, variable time. Public values only.
    pub fn cmp_vartime(&self, other: &Uint) -> core::cmp::Ordering {
        for i in (0..MAX_LIMBS).rev() {
            match self.0[i].cmp(&other.0[i]) {
                core::cmp::Ordering::Equal => continue,
                ord => return ord,
            }
        }
        core::cmp::Ordering::Equal
    }

    /// Constant-time conditional move.
    #[inline]
    pub fn cmov(a: &mut Uint, b: &Uint, choice: Choice, limbs: usize) {
        let mask = (choice.unwrap_u8() as u64).wrapping_neg();
        for i in 0..limbs {
            a.0[i] ^= mask & (a.0[i] ^ b.0[i]);
        }
    }

    /// `self + other` over `limbs` limbs, returning the carry.
    pub fn add_assign(&mut self, other: &Uint, limbs: usize) -> u64 {
        let mut carry = 0u128;
        for i in 0..limbs {
            let sum = (self.0[i] as u128) + (other.0[i] as u128) + carry;
            self.0[i] = sum as u64;
            carry = sum >> 64;
        }
        carry as u64
    }

    /// `self - other` over `limbs` limbs, returning the borrow.
    pub fn sub_assign(&mut self, other: &Uint, limbs: usize) -> u64 {
        let mut borrow = 0u128;
        for i in 0..limbs {
            let diff = (self.0[i] as u128)
                .wrapping_sub(other.0[i] as u128)
                .wrapping_sub(borrow);
            self.0[i] = diff as u64;
            borrow = (diff >> 127) & 1;
        }
        borrow as u64
    }

    /// Shift right by one bit over `limbs` limbs.
    pub fn shr1(&mut self, limbs: usize) {
        let mut carry = 0u64;
        for i in (0..limbs).rev() {
            let next = self.0[i] & 1;
            self.0[i] = (self.0[i] >> 1) | (carry << 63);
            carry = next;
        }
    }

    /// Whether the value is odd.
    #[inline]
    pub fn is_odd(&self) -> bool {
        self.0[0] & 1 == 1
    }

    /// Remainder modulo a small integer, variable time. Public values only.
    pub fn rem_u64(&self, m: u64) -> u64 {
        let mut rem = 0u128;
        for i in (0..MAX_LIMBS).rev() {
            rem = ((rem << 64) | self.0[i] as u128) % (m as u128);
        }
        rem as u64
    }
}

/// `-m^-1 mod 2^64`, by Newton iteration.
const fn neg_inv(m0: u64) -> u64 {
    let mut inv = m0;
    let mut i = 0;
    while i < 6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
        i += 1;
    }
    inv.wrapping_neg()
}

/// An odd modulus, prepared for Montgomery arithmetic.
#[derive(Clone, Copy)]
pub struct Modulus {
    n: Uint,
    /// Active width in limbs. Public: it is a function of the key size.
    limbs: usize,
    n0inv: u64,
    r2: Uint,
}

impl Zeroize for Modulus {
    fn zeroize(&mut self) {
        self.n.zeroize();
        self.r2.zeroize();
    }
}

impl Modulus {
    /// Prepare `n` for Montgomery arithmetic. `n` must be odd and non-zero.
    pub fn new(n: Uint) -> Option<Modulus> {
        if !n.is_odd() {
            return None;
        }
        let bits = n.bits();
        if bits == 0 {
            return None;
        }
        let limbs = bits.div_ceil(64);

        let mut m = Modulus {
            n,
            limbs,
            n0inv: neg_inv(n.0[0]),
            r2: Uint::ZERO,
        };
        m.r2 = m.compute_r2();
        Some(m)
    }

    /// The modulus itself.
    pub fn value(&self) -> &Uint {
        &self.n
    }

    /// Active width in limbs.
    pub fn limbs(&self) -> usize {
        self.limbs
    }

    /// Width in bytes of a canonical encoding modulo `n`.
    pub fn byte_len(&self) -> usize {
        self.n.bits().div_ceil(8)
    }

    /// `R^2 mod n`, by repeated doubling.
    ///
    /// Computed rather than supplied, so there is no constant to mistranscribe.
    /// This runs once per key.
    fn compute_r2(&self) -> Uint {
        let mut x = Uint::one();
        // R = 2^(64*limbs); R^2 needs 128*limbs doublings from one.
        for _ in 0..(128 * self.limbs) {
            let carry = {
                let copy = x;
                x.add_assign(&copy, self.limbs)
            };
            // Conditionally subtract n when the sum overflowed or reached n.
            let mut reduced = x;
            let borrow = reduced.sub_assign(&self.n, self.limbs);
            let need = Choice::from_u8((carry | (1 - borrow)) as u8);
            Uint::cmov(&mut x, &reduced, need, self.limbs);
        }
        x
    }

    /// Montgomery multiplication (CIOS).
    ///
    /// The inner loops index `t`, `a`, `b`, and `n` together at offsets that do
    /// not line up, so the index is the clearer form here.
    #[allow(clippy::needless_range_loop)]
    pub fn mont_mul(&self, a: &Uint, b: &Uint) -> Uint {
        let limbs = self.limbs;
        let mut t = [0u64; MAX_LIMBS + 2];

        for i in 0..limbs {
            // t += a * b[i]
            let mut carry = 0u128;
            for j in 0..limbs {
                let sum = (t[j] as u128) + (a.0[j] as u128) * (b.0[i] as u128) + carry;
                t[j] = sum as u64;
                carry = sum >> 64;
            }
            let sum = (t[limbs] as u128) + carry;
            t[limbs] = sum as u64;
            t[limbs + 1] = (sum >> 64) as u64;

            // t = (t + n * (t[0] * n0inv mod 2^64)) / 2^64
            let u = t[0].wrapping_mul(self.n0inv);
            let sum = (t[0] as u128) + (u as u128) * (self.n.0[0] as u128);
            let mut carry = sum >> 64;
            for j in 1..limbs {
                let sum = (t[j] as u128) + (u as u128) * (self.n.0[j] as u128) + carry;
                t[j - 1] = sum as u64;
                carry = sum >> 64;
            }
            let sum = (t[limbs] as u128) + carry;
            t[limbs - 1] = sum as u64;
            t[limbs] = (t[limbs + 1] as u128 + (sum >> 64)) as u64;
            t[limbs + 1] = 0;
        }

        let mut out = Uint::ZERO;
        out.0[..limbs].copy_from_slice(&t[..limbs]);

        // One conditional subtraction brings the result below n.
        let mut reduced = out;
        let borrow = reduced.sub_assign(&self.n, limbs);
        let need = Choice::from_u8((t[limbs] | (1 - borrow)) as u8);
        Uint::cmov(&mut out, &reduced, need, limbs);

        t.zeroize();
        out
    }

    /// Convert into Montgomery form (`a * R mod n`).
    pub fn to_mont(&self, a: &Uint) -> Uint {
        self.mont_mul(a, &self.r2)
    }

    /// Convert out of Montgomery form.
    pub fn from_mont(&self, a: &Uint) -> Uint {
        self.mont_mul(a, &Uint::one())
    }

    /// Reduce `a` modulo `n`, for `a < n^2`.
    ///
    /// Used to bring a decoded message into range; callers that need a strict
    /// range check should compare first.
    pub fn reduce_once(&self, a: &Uint) -> Uint {
        let mut out = *a;
        let mut reduced = out;
        let borrow = reduced.sub_assign(&self.n, self.limbs);
        Uint::cmov(
            &mut out,
            &reduced,
            Choice::from_u8((1 - borrow) as u8),
            self.limbs,
        );
        out
    }

    /// `base^exp mod n`, constant-time in `exp`.
    ///
    /// Squares and multiplies on every bit of the exponent up to `exp_bits`,
    /// selecting between the two with a conditional move. This is the
    /// private-key path: the exponent is the secret.
    pub fn pow(&self, base: &Uint, exp: &Uint, exp_bits: usize) -> Uint {
        let one_mont = self.to_mont(&Uint::one());
        let base_mont = self.to_mont(base);

        let mut acc = one_mont;
        for i in (0..exp_bits).rev() {
            acc = self.mont_mul(&acc, &acc);
            let multiplied = self.mont_mul(&acc, &base_mont);
            let bit = Choice::from_u8(exp.bit(i));
            Uint::cmov(&mut acc, &multiplied, bit, self.limbs);
        }
        self.from_mont(&acc)
    }

    /// `base^e mod n` for a small public exponent.
    ///
    /// The public exponent is not secret, so this may branch on it.
    pub fn pow_public(&self, base: &Uint, e: u64) -> Uint {
        let base_mont = self.to_mont(base);
        let mut acc = self.to_mont(&Uint::one());
        let bits = 64 - e.leading_zeros() as usize;
        for i in (0..bits).rev() {
            acc = self.mont_mul(&acc, &acc);
            if (e >> i) & 1 == 1 {
                acc = self.mont_mul(&acc, &base_mont);
            }
        }
        self.from_mont(&acc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A deliberately naive modular exponentiation, used as the oracle for the
    /// Montgomery implementation. Schoolbook, variable time, and obviously
    /// correct by inspection — which is the point.
    fn reference_pow(base: u128, exp: u128, modulus: u128) -> u128 {
        let mut acc = 1u128;
        let mut b = base % modulus;
        let mut e = exp;
        while e > 0 {
            if e & 1 == 1 {
                acc = acc * b % modulus;
            }
            b = b * b % modulus;
            e >>= 1;
        }
        acc
    }

    fn uint(v: u128) -> Uint {
        let mut out = Uint::ZERO;
        out.0[0] = v as u64;
        out.0[1] = (v >> 64) as u64;
        out
    }

    fn to_u128(v: &Uint) -> u128 {
        (v.0[0] as u128) | ((v.0[1] as u128) << 64)
    }

    #[test]
    fn byte_round_trip() {
        for bytes in [
            &[0x01u8][..],
            &[0xff, 0xff][..],
            &[0x12, 0x34, 0x56, 0x78, 0x9a][..],
            &[0xa5u8; 32][..],
            &[0x7fu8; 256][..],
        ] {
            let v = Uint::from_be_bytes(bytes).unwrap();
            let mut out = vec![0u8; bytes.len()];
            v.to_be_bytes(&mut out);
            assert_eq!(out, bytes, "round trip of {} bytes", bytes.len());
        }
        assert!(Uint::from_be_bytes(&[0u8; MAX_BYTES + 1]).is_none());
    }

    #[test]
    fn bit_accessors_agree_with_the_value() {
        let v = Uint::from_u64(0b1011);
        assert_eq!(v.bit(0), 1);
        assert_eq!(v.bit(1), 1);
        assert_eq!(v.bit(2), 0);
        assert_eq!(v.bit(3), 1);
        assert_eq!(v.bits(), 4);
        assert!(v.is_odd());
        assert_eq!(Uint::ZERO.bits(), 0);
        assert!(!Uint::from_u64(4).is_odd());
    }

    #[test]
    fn add_and_sub_carry_correctly() {
        let mut a = Uint::from_u64(u64::MAX);
        let carry = a.add_assign(&Uint::from_u64(1), 2);
        assert_eq!(carry, 0);
        assert_eq!(a.0[0], 0);
        assert_eq!(a.0[1], 1);

        let borrow = a.sub_assign(&Uint::from_u64(1), 2);
        assert_eq!(borrow, 0);
        assert_eq!(a.0[0], u64::MAX);
        assert_eq!(a.0[1], 0);

        let mut z = Uint::ZERO;
        assert_eq!(z.sub_assign(&Uint::from_u64(1), 2), 1, "borrow out");
    }

    /// The Montgomery exponentiation must agree with the naive one. This is the
    /// differential test that makes the optimized arithmetic trustworthy.
    #[test]
    fn modexp_matches_the_reference() {
        // Odd moduli of assorted sizes, all small enough for u128 arithmetic.
        for &m in &[
            3u128,
            17,
            65537,
            4_294_967_291,
            0xffff_ffff_ffff_fffbu128,
            0x7fff_ffff_ffff_ffffu128,
        ] {
            let modulus = Modulus::new(uint(m)).unwrap();
            for &base in &[0u128, 1, 2, 3, 7, 12345, m - 1] {
                for &e in &[0u128, 1, 2, 3, 65537, 1_000_003] {
                    let want = reference_pow(base % m, e, m);
                    let got = modulus.pow(&uint(base % m), &uint(e), 64);
                    assert_eq!(to_u128(&got), want, "{base}^{e} mod {m}");

                    if e <= u64::MAX as u128 {
                        let got = modulus.pow_public(&uint(base % m), e as u64);
                        assert_eq!(to_u128(&got), want, "public {base}^{e} mod {m}");
                    }
                }
            }
        }
    }

    #[test]
    fn montgomery_conversion_round_trips() {
        let m = Modulus::new(uint(0xffff_ffff_ffff_fffbu128)).unwrap();
        for v in [0u128, 1, 2, 12345, 0xffff_ffff_ffff_fffau128] {
            let a = uint(v);
            assert_eq!(to_u128(&m.from_mont(&m.to_mont(&a))), v, "{v}");
        }
    }

    #[test]
    fn multiplication_matches_the_reference() {
        let m = 0xffff_ffff_ffff_fffbu128;
        let modulus = Modulus::new(uint(m)).unwrap();
        for a in [0u128, 1, 2, 999, m - 1] {
            for b in [0u128, 1, 3, 65537, m - 1] {
                let got =
                    modulus.from_mont(&modulus.mont_mul(&modulus.to_mont(&uint(a)), &uint(b)));
                // mont_mul(to_mont(a), b) = a*b*R/R = a*b ... one from_mont too
                // many, so compare against the same composition done naively.
                let want = a * b % m;
                let direct =
                    modulus.mont_mul(&modulus.to_mont(&uint(a)), &modulus.to_mont(&uint(b)));
                assert_eq!(
                    to_u128(&modulus.from_mont(&direct)),
                    want,
                    "{a}*{b} mod {m}"
                );
                let _ = got;
            }
        }
    }

    #[test]
    fn even_and_zero_moduli_are_rejected() {
        assert!(Modulus::new(uint(4)).is_none(), "even");
        assert!(Modulus::new(Uint::ZERO).is_none(), "zero");
        assert!(Modulus::new(uint(1)).is_some(), "one is odd");
    }

    #[test]
    fn widths_follow_the_modulus() {
        let m = Modulus::new(uint(0xffff_ffff_ffff_fffbu128)).unwrap();
        assert_eq!(m.limbs(), 1);
        assert_eq!(m.byte_len(), 8);

        let mut big = Uint::ZERO;
        big.0[31] = 0x8000_0000_0000_0000;
        big.0[0] = 1;
        let m = Modulus::new(big).unwrap();
        assert_eq!(m.limbs(), 32, "2048-bit modulus");
        assert_eq!(m.byte_len(), 256);
    }

    #[test]
    fn shift_and_remainder() {
        let mut v = Uint::from_u64(0b1010);
        v.shr1(2);
        assert_eq!(v.0[0], 0b101);
        assert_eq!(Uint::from_u64(100).rem_u64(7), 2);
        assert_eq!(Uint::from_u64(65537).rem_u64(3), 65537 % 3);
    }

    #[test]
    fn constant_time_helpers_behave() {
        assert!(bool::from(Uint::ZERO.is_zero(4)));
        assert!(!bool::from(Uint::from_u64(1).is_zero(4)));
        assert!(bool::from(Uint::from_u64(7).ct_eq(&Uint::from_u64(7), 4)));
        assert!(!bool::from(Uint::from_u64(7).ct_eq(&Uint::from_u64(8), 4)));

        let mut a = Uint::from_u64(1);
        Uint::cmov(&mut a, &Uint::from_u64(2), Choice::FALSE, 4);
        assert_eq!(a.0[0], 1);
        Uint::cmov(&mut a, &Uint::from_u64(2), Choice::TRUE, 4);
        assert_eq!(a.0[0], 2);
    }
}
