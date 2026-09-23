//! Arithmetic in GF(2^255 - 19).
//!
//! Field elements are five 51-bit limbs in a `u64`, the representation used by
//! every high-quality Curve25519 implementation: products fit a `u128` without
//! overflow, and carries propagate in a fixed pattern with no data-dependent
//! branches. Nothing here inspects a limb value to decide control flow, so the
//! whole module is constant-time with respect to secrets.

//! Indexed loops over fixed-size limb and word arrays are used throughout; they
//! mirror the index algebra in the specifications these routines implement, so
//! `needless_range_loop` is allowed rather than obscuring the correspondence.
#![allow(clippy::needless_range_loop)]

use ic_core::ct::Choice;

/// A field element modulo 2^255 - 19.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fe(pub [u64; 5]);

const MASK: u64 = (1 << 51) - 1;

/// `2 * p`, used so subtraction never goes negative.
// Limb 0 is 2*(2^51 - 19) = 2^52 - 38; the rest are 2*(2^51 - 1) = 2^52 - 2.
// The digits are grouped to show all thirteen nibbles of each 52-bit limb
// rather than in fours, which would obscure the limb boundary.
#[allow(clippy::unusual_byte_groupings)]
const TWO_P: [u64; 5] = [
    0xFFFFFFFFFFFDA,
    0xFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFE,
];

impl Fe {
    /// The additive identity.
    pub const ZERO: Fe = Fe([0, 0, 0, 0, 0]);
    /// The multiplicative identity.
    pub const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// A small integer as a field element.
    pub const fn from_u64(v: u64) -> Fe {
        Fe([v & MASK, v >> 51, 0, 0, 0])
    }

    /// Field addition.
    #[inline]
    pub fn add(&self, other: &Fe) -> Fe {
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = self.0[i] + other.0[i];
        }
        Fe(r)
    }

    /// Field subtraction, via `self + 2p - other` so limbs stay non-negative.
    #[inline]
    pub fn sub(&self, other: &Fe) -> Fe {
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = self.0[i] + TWO_P[i] - other.0[i];
        }
        Fe(r).weak_reduce()
    }

    /// Field negation.
    #[inline]
    pub fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    /// One pass of carry propagation, leaving every limb below 2^51.
    #[inline]
    fn weak_reduce(self) -> Fe {
        let mut r = self.0;
        let mut carry = r[0] >> 51;
        r[0] &= MASK;
        for i in 1..5 {
            r[i] += carry;
            carry = r[i] >> 51;
            r[i] &= MASK;
        }
        r[0] += carry.wrapping_mul(19);
        Fe(r)
    }

    /// Field multiplication.
    // What has already been tried on the field multiply, so it is not tried
    // again. Curve25519 is doublings almost entirely and a doubling is four
    // multiplications and four squarings, so this function is most of Ed25519
    // and X25519.
    //
    // - **`#[inline(always)]` on `mul`, `square`, `add`, `sub` and
    //   `carry_reduce`.** The per-crate assembly shows `Point::double` calling
    //   them rather than inlining, with a 480-byte frame, which looks like the
    //   problem. Measured: Ed25519 verify went from 1.59x behind dalek to
    //   1.96x, reproducibly. The bodies are large enough that forcing them
    //   inline costs more in spills than the calls cost. Under the benchmark's
    //   profile LLVM already inlines them; the out-of-line copies are for other
    //   callers.
    // - **Removing `weak_reduce` from `sub`.** Also looks like waste: a
    //   doubling does five of them, each a serial carry chain. Measured with
    //   the diagnostic in `ed25519.rs`: `sub` is 2.14ns against `add` at
    //   0.92ns, so all five are about 6ns of a 96ns doubling. Not where the
    //   time is.
    //
    // - **A four-wide AVX2 field multiply.** This one was built and measured
    //   rather than argued about, because the primitive really is faster:
    //   24.35ns for four multiplications against 43.83ns for four scalar ones,
    //   1.80x, verified lane for lane against `mul`. AVX2 has no 64x64
    //   multiply, so it needs ten limbs alternating 26 and 25 bits instead of
    //   five of 51 -- ten of those come to exactly 255, which keeps the
    //   reduction constant at 19 -- and the products were generated from that
    //   layout and checked against integer arithmetic mod p before any of it
    //   was written.
    //
    //   It was not kept, because the primitive is not the point layer. 77% of
    //   a doubling is its four multiplications and four squarings; the rest is
    //   additions and subtractions across coordinates, and in a four-lane
    //   layout those do not disappear, they become lane shuffles. Two `mul4`
    //   calls are 48.7ns against the 73.8ns of field work they replace, so
    //   even a shuffle cost of 20ns -- optimistic -- leaves a doubling at
    //   68.7ns against 96ns, and verification at about 24us against dalek's
    //   19.8. It narrows the gap and does not close it, and it would cost this
    //   crate its `forbid(unsafe_code)`, which no other crate here has.
    //
    //   What dalek gets from its own AVX2 backend is 19.8 -> 16.6us, so the
    //   target moves too. Closing this properly means their whole point layer,
    //   not a faster multiply.
    //
    // Where the time is: 160 `mul` instructions in a doubling against 775
    // `mov`. Five `u128` accumulators and two five-limb operands do not fit in
    // sixteen registers, so the schoolbook spills, and that is a property of
    // the shape rather than of the instruction selection. `-C
    // target-cpu=native` turns the `mul`s into `mulx` and drops the moves to
    // 475 -- 18% fewer instructions -- and buys 2% end to end. dalek gains 16%
    // from the same flag, because it has an AVX2 field backend that engages
    // there and this does not. That backend, not scheduling, is the remaining
    // gap on Ed25519.
    #[inline]
    pub fn mul(&self, other: &Fe) -> Fe {
        let a = &self.0;
        let b = &other.0;

        // The 19s are computed in 64 bits, and every product below is
        // `u64 * u64 -> u128`.
        //
        // They used to be `(b[i] as u128) * 19`, which makes the scaled value a
        // 128-bit quantity with no bound the compiler can see under 2^64 -- so
        // each product became a full 128x128 multiply, three instructions and
        // some adds where one `mul` would do. A limb is below 2^52 and 19 times
        // it is below 2^57, so the scaling belongs in 64 bits and the compiler
        // can then see that both operands of every product fit.
        let b1_19 = b[1] * 19;
        let b2_19 = b[2] * 19;
        let b3_19 = b[3] * 19;
        let b4_19 = b[4] * 19;

        let r0 = m(a[0], b[0]) + m(a[1], b4_19) + m(a[2], b3_19) + m(a[3], b2_19) + m(a[4], b1_19);
        let r1 = m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b4_19) + m(a[3], b3_19) + m(a[4], b2_19);
        let r2 = m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b4_19) + m(a[4], b3_19);
        let r3 = m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b4_19);
        let r4 = m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]);

        carry_reduce([r0, r1, r2, r3, r4])
    }

    /// Field squaring.
    #[inline]
    pub fn square(&self) -> Fe {
        // Twenty-five limb products become fifteen.
        //
        // In `a * b` every pair `(i, j)` is distinct, so all twenty-five
        // appear. Squaring pairs `i` with `j` and `j` with `i` to the same
        // product, so each off-diagonal term is computed once and doubled --
        // which is a shift, not a multiplication. The 19s are the same
        // reduction the general multiply uses, folding `2^255 = 19` back into
        // the low limbs, pre-multiplied into the doubled coefficients where
        // both apply.
        //
        // This is on the hot path everywhere: four squarings per Edwards
        // doubling, four per Montgomery ladder step, and a few hundred in a
        // field inversion.
        // Scalings in 64 bits, products as `u64 * u64 -> u128`; see `mul`.
        // A limb is below 2^52, so 38 times it is below 2^58.
        let a = &self.0;
        let a0_2 = a[0] * 2;
        let a1_2 = a[1] * 2;
        let a1_38 = a[1] * 38;
        let a2_38 = a[2] * 38;
        let a3_38 = a[3] * 38;
        let a3_19 = a[3] * 19;
        let a4_19 = a[4] * 19;

        // r_k = sum_{i+j=k} a_i a_j + 19 * sum_{i+j=k+5} a_i a_j
        let r0 = m(a[0], a[0]) + m(a1_38, a[4]) + m(a2_38, a[3]);
        let r1 = m(a0_2, a[1]) + m(a2_38, a[4]) + m(a3_19, a[3]);
        let r2 = m(a0_2, a[2]) + m(a[1], a[1]) + m(a3_38, a[4]);
        let r3 = m(a0_2, a[3]) + m(a1_2, a[2]) + m(a4_19, a[4]);
        let r4 = m(a0_2, a[4]) + m(a1_2, a[3]) + m(a[2], a[2]);

        carry_reduce([r0, r1, r2, r3, r4])
    }

    /// Repeated squaring, `self^(2^n)`.
    #[inline]
    pub fn square_n(&self, n: usize) -> Fe {
        let mut r = *self;
        for _ in 0..n {
            r = r.square();
        }
        r
    }

    /// Multiplication by the Montgomery ladder constant `a24 = 121666`.
    #[inline]
    pub fn mul121666(&self) -> Fe {
        let mut r = [0u128; 5];
        for i in 0..5 {
            r[i] = (self.0[i] as u128) * 121_666;
        }
        carry_reduce(r)
    }

    /// Multiplicative inverse, `self^(p-2)`, with `inverse(0) == 0`.
    ///
    /// Uses the standard addition chain: 254 squarings and 11 multiplications.
    pub fn invert(&self) -> Fe {
        let z2 = self.square();
        let z9 = z2.square_n(2).mul(self);
        let z11 = z9.mul(&z2);
        let z2_5_0 = z11.square().mul(&z9);
        let z2_10_0 = z2_5_0.square_n(5).mul(&z2_5_0);
        let z2_20_0 = z2_10_0.square_n(10).mul(&z2_10_0);
        let z2_40_0 = z2_20_0.square_n(20).mul(&z2_20_0);
        let z2_50_0 = z2_40_0.square_n(10).mul(&z2_10_0);
        let z2_100_0 = z2_50_0.square_n(50).mul(&z2_50_0);
        let z2_200_0 = z2_100_0.square_n(100).mul(&z2_100_0);
        let z2_250_0 = z2_200_0.square_n(50).mul(&z2_50_0);
        z2_250_0.square_n(5).mul(&z11)
    }

    /// `self^((p-5)/8)`, the exponent used to take square roots.
    pub fn pow22523(&self) -> Fe {
        let z2 = self.square();
        let z9 = z2.square_n(2).mul(self);
        let z11 = z9.mul(&z2);
        let z2_5_0 = z11.square().mul(&z9);
        let z2_10_0 = z2_5_0.square_n(5).mul(&z2_5_0);
        let z2_20_0 = z2_10_0.square_n(10).mul(&z2_10_0);
        let z2_40_0 = z2_20_0.square_n(20).mul(&z2_20_0);
        let z2_50_0 = z2_40_0.square_n(10).mul(&z2_10_0);
        let z2_100_0 = z2_50_0.square_n(50).mul(&z2_50_0);
        let z2_200_0 = z2_100_0.square_n(100).mul(&z2_100_0);
        let z2_250_0 = z2_200_0.square_n(50).mul(&z2_50_0);
        z2_250_0.square_n(2).mul(self)
    }

    /// Decode 32 little-endian bytes, ignoring the top bit as RFC 7748 requires.
    pub fn from_bytes(bytes: &[u8; 32]) -> Fe {
        let load = |i: usize| -> u64 {
            let mut v = [0u8; 8];
            v.copy_from_slice(&bytes[i..i + 8]);
            u64::from_le_bytes(v)
        };
        let l0 = load(0) & MASK;
        let l1 = (load(6) >> 3) & MASK;
        let l2 = (load(12) >> 6) & MASK;
        let l3 = (load(19) >> 1) & MASK;
        let l4 = (load(24) >> 12) & MASK;
        Fe([l0, l1, l2, l3, l4])
    }

    /// Encode as 32 little-endian bytes, fully reduced modulo p.
    pub fn to_bytes(&self) -> [u8; 32] {
        // Three passes leave every limb strictly below 2^51: each pass can
        // push at most a 19 back into limb 0, so the residue shrinks each time.
        let mut t = self.weak_reduce().weak_reduce().weak_reduce().0;

        // Conditionally subtract p, in constant time.
        // q is 1 exactly when t >= p.
        let mut q = (t[0] + 19) >> 51;
        for i in 1..5 {
            q = (t[i] + q) >> 51;
        }
        t[0] += 19 * q;
        let mut carry = t[0] >> 51;
        t[0] &= MASK;
        for i in 1..5 {
            t[i] += carry;
            carry = t[i] >> 51;
            t[i] &= MASK;
        }
        // Drop the bit that overflowed past 2^255.
        t[4] &= (1 << 51) - 1;

        let mut out = [0u8; 32];
        let mut acc: u128 = 0;
        let mut acc_bits = 0usize;
        let mut idx = 0usize;
        for limb in t.iter() {
            acc |= (*limb as u128) << acc_bits;
            acc_bits += 51;
            while acc_bits >= 8 && idx < 32 {
                out[idx] = acc as u8;
                acc >>= 8;
                acc_bits -= 8;
                idx += 1;
            }
        }
        while idx < 32 {
            out[idx] = acc as u8;
            acc >>= 8;
            idx += 1;
        }
        out
    }

    /// Constant-time conditional swap.
    #[inline]
    pub fn cswap(a: &mut Fe, b: &mut Fe, choice: Choice) {
        let mask = (choice.unwrap_u8() as u64).wrapping_neg();
        for i in 0..5 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }

    /// Constant-time conditional move: `a = b` when `choice` is true.
    #[inline]
    pub fn cmov(a: &mut Fe, b: &Fe, choice: Choice) {
        let mask = (choice.unwrap_u8() as u64).wrapping_neg();
        for i in 0..5 {
            a.0[i] ^= mask & (a.0[i] ^ b.0[i]);
        }
    }

    /// Constant-time test for zero.
    pub fn is_zero(&self) -> Choice {
        ic_core::ct::is_zero(&self.to_bytes())
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &Fe) -> Choice {
        ic_core::ct::eq(&self.to_bytes(), &other.to_bytes())
    }

    /// The least significant bit of the canonical encoding — the "sign" used by
    /// Edwards point compression.
    pub fn is_negative(&self) -> Choice {
        Choice::from_u8(self.to_bytes()[0] & 1)
    }
}

/// One 64x64 multiplication, widened.
///
/// Written out so both operands are visibly `u64`: that is what lets the
/// compiler emit a single widening multiply instead of a 128-bit one.
#[inline(always)]
fn m(x: u64, y: u64) -> u128 {
    (x as u128) * (y as u128)
}

/// Fold five 128-bit products back into 51-bit limbs.
#[inline]
fn carry_reduce(r: [u128; 5]) -> Fe {
    // The five carries are extracted independently, not chained.
    //
    // This used to walk the limbs in order, each iteration adding the previous
    // carry before computing its own -- five 128-bit shift-and-mask steps on a
    // single dependency chain, on the hot path of every multiplication and
    // squaring. Nothing about the reduction requires that order: each `r[i]`
    // already holds its full product sum, so every carry can be taken at once
    // and delivered to its neighbour afterwards, which is five independent
    // shifts the scheduler can overlap instead of five it cannot.
    //
    // The bound that makes it safe: both operands of a product have limbs
    // below 2^52, so `r[i] < 5 * 19 * 2^104 < 2^110.3` and `c[i] < 2^59.3`.
    // The largest quantity below is `c[4] * 19 < 2^63.6`, which is why the
    // scaled carry still fits in a u64. `limbs_at_their_maximum_do_not_carry_
    // out_of_a_u64` drives that worst case, and an arithmetic overflow there
    // is a panic in a debug build rather than a wrong answer in a release one.
    let c: [u64; 5] = [
        (r[0] >> 51) as u64,
        (r[1] >> 51) as u64,
        (r[2] >> 51) as u64,
        (r[3] >> 51) as u64,
        (r[4] >> 51) as u64,
    ];
    let mut out: [u64; 5] = [
        (r[0] as u64 & MASK) + c[4] * 19,
        (r[1] as u64 & MASK) + c[0],
        (r[2] as u64 & MASK) + c[1],
        (r[3] as u64 & MASK) + c[2],
        (r[4] as u64 & MASK) + c[3],
    ];

    // One short 64-bit pass to settle what those additions carried. Serial,
    // but over small numbers and only once.
    let mut carry = out[0] >> 51;
    out[0] &= MASK;
    for slot in out.iter_mut().skip(1) {
        *slot += carry;
        carry = *slot >> 51;
        *slot &= MASK;
    }
    out[0] += carry * 19;
    Fe(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Squaring must agree with multiplying a value by itself.
    ///
    /// The dedicated formula reaches the same answer by a different route --
    /// fifteen products where the general one has twenty-five, with the
    /// off-diagonal terms doubled rather than recomputed -- so agreement is
    /// the whole correctness argument. `mul` is what the RFC 7748 and RFC 8032
    /// vectors validate, which makes it the oracle.
    ///
    /// The values include zero, one, the largest limbs the representation
    /// holds unreduced, and values that carry out of every limb, because the
    /// doubling is where this formula can overflow if the bounds are wrong.
    #[test]
    fn squaring_agrees_with_multiplication() {
        let mut cases = std::vec![
            Fe::ZERO,
            Fe::ONE,
            Fe([1, 1, 1, 1, 1]),
            Fe([(1u64 << 51) - 1; 5]),
            Fe([(1u64 << 51) - 1, 0, (1u64 << 51) - 1, 0, (1u64 << 51) - 1]),
            Fe([0, (1u64 << 51) - 1, 0, (1u64 << 51) - 1, 0]),
        ];
        // And a spread of pseudo-random field elements.
        let mut x = Fe([0x51a2, 0x9e37, 0x79b9, 0x7f4a, 0x7c15]);
        for _ in 0..16 {
            x = x.mul(&Fe([3, 5, 7, 11, 13])).add(&Fe::ONE);
            cases.push(x);
        }

        let mut checked = 0;
        for f in &cases {
            assert_eq!(
                f.square().to_bytes(),
                f.mul(f).to_bytes(),
                "square and mul-by-self differ"
            );
            checked += 1;
        }
        assert_eq!(checked, 22, "the comparison did not run");
    }

    fn fe(v: u64) -> Fe {
        Fe::from_u64(v)
    }

    #[test]
    fn encode_decode_roundtrip() {
        for v in [0u64, 1, 2, 19, 1 << 51, u64::MAX] {
            let a = fe(v);
            assert_eq!(Fe::from_bytes(&a.to_bytes()).to_bytes(), a.to_bytes());
        }
    }

    #[test]
    fn small_arithmetic() {
        assert_eq!(fe(2).add(&fe(3)).to_bytes(), fe(5).to_bytes());
        assert_eq!(fe(5).sub(&fe(3)).to_bytes(), fe(2).to_bytes());
        assert_eq!(fe(6).mul(&fe(7)).to_bytes(), fe(42).to_bytes());
        assert_eq!(fe(9).square().to_bytes(), fe(81).to_bytes());
    }

    #[test]
    fn subtraction_wraps_into_the_field() {
        // 0 - 1 == p - 1, whose encoding is ec ff .. 7f.
        let r = Fe::ZERO.sub(&Fe::ONE).to_bytes();
        assert_eq!(r[0], 0xec);
        assert_eq!(r[31], 0x7f);
        for b in &r[1..31] {
            assert_eq!(*b, 0xff);
        }
    }

    #[test]
    fn p_encodes_as_zero() {
        // p itself must reduce to 0.
        let mut p_bytes = [0xffu8; 32];
        p_bytes[0] = 0xed;
        p_bytes[31] = 0x7f;
        assert_eq!(Fe::from_bytes(&p_bytes).to_bytes(), [0u8; 32]);
    }

    #[test]
    fn inversion_is_correct() {
        for v in [1u64, 2, 3, 19, 12345, u32::MAX as u64] {
            let a = fe(v);
            assert_eq!(a.mul(&a.invert()).to_bytes(), Fe::ONE.to_bytes(), "1/{v}");
        }
        assert_eq!(Fe::ZERO.invert().to_bytes(), [0u8; 32]);
    }

    #[test]
    fn multiplication_is_associative_and_distributive() {
        let a = Fe::from_bytes(&[0x11; 32]);
        let b = Fe::from_bytes(&[0x7a; 32]);
        let c = Fe::from_bytes(&[0xc3; 32]);
        assert_eq!(a.mul(&b).mul(&c).to_bytes(), a.mul(&b.mul(&c)).to_bytes());
        assert_eq!(
            a.mul(&b.add(&c)).to_bytes(),
            a.mul(&b).add(&a.mul(&c)).to_bytes()
        );
    }

    #[test]
    fn pow22523_gives_a_square_root() {
        // For a square x, x^((p-5)/8) * x is a square root up to a factor of i.
        let x = fe(4);
        let r = x.pow22523().mul(&x);
        let sq = r.square();
        // r^2 is either x or -x.
        assert!(
            bool::from(sq.ct_eq(&x)) || bool::from(sq.ct_eq(&x.neg())),
            "square root property"
        );
    }

    #[test]
    fn cswap_and_cmov_are_conditional() {
        let mut a = fe(1);
        let mut b = fe(2);
        Fe::cswap(&mut a, &mut b, Choice::FALSE);
        assert_eq!(a.to_bytes(), fe(1).to_bytes());
        Fe::cswap(&mut a, &mut b, Choice::TRUE);
        assert_eq!(a.to_bytes(), fe(2).to_bytes());

        let mut c = fe(5);
        Fe::cmov(&mut c, &fe(9), Choice::FALSE);
        assert_eq!(c.to_bytes(), fe(5).to_bytes());
        Fe::cmov(&mut c, &fe(9), Choice::TRUE);
        assert_eq!(c.to_bytes(), fe(9).to_bytes());
    }

    #[test]
    fn high_bit_of_input_is_ignored() {
        let mut a = [0x42u8; 32];
        let mut b = a;
        a[31] &= 0x7f;
        b[31] |= 0x80;
        assert_eq!(Fe::from_bytes(&a).to_bytes(), Fe::from_bytes(&b).to_bytes());
    }

    /// The serial carry chain `carry_reduce` replaced, kept as an oracle.
    ///
    /// It is the implementation the RFC 7748 and 8032 vectors were passing
    /// against before the parallel form went in, so agreeing with it on
    /// arbitrary limb patterns is the evidence that the rewrite changed the
    /// schedule and not the arithmetic.
    fn carry_reduce_serial(r: [u128; 5]) -> Fe {
        let mut out = [0u64; 5];
        let mut carry: u128 = 0;
        for (slot, limb) in out.iter_mut().zip(r) {
            let v = limb + carry;
            carry = v >> 51;
            *slot = (v & MASK as u128) as u64;
        }
        out[0] += (carry as u64) * 19;
        let mut c = out[0] >> 51;
        out[0] &= MASK;
        for slot in out.iter_mut().skip(1) {
            *slot += c;
            c = *slot >> 51;
            *slot &= MASK;
        }
        out[0] += c * 19;
        Fe(out)
    }

    /// Build the limb products the way `mul` does, without reducing.
    fn raw_products(a: &[u64; 5], b: &[u64; 5]) -> [u128; 5] {
        let m = |x: u64, y: u64| (x as u128) * (y as u128);
        let (b1, b2, b3, b4) = (b[1] * 19, b[2] * 19, b[3] * 19, b[4] * 19);
        [
            m(a[0], b[0]) + m(a[1], b4) + m(a[2], b3) + m(a[3], b2) + m(a[4], b1),
            m(a[0], b[1]) + m(a[1], b[0]) + m(a[2], b4) + m(a[3], b3) + m(a[4], b2),
            m(a[0], b[2]) + m(a[1], b[1]) + m(a[2], b[0]) + m(a[3], b4) + m(a[4], b3),
            m(a[0], b[3]) + m(a[1], b[2]) + m(a[2], b[1]) + m(a[3], b[0]) + m(a[4], b4),
            m(a[0], b[4]) + m(a[1], b[3]) + m(a[2], b[2]) + m(a[3], b[1]) + m(a[4], b[0]),
        ]
    }

    /// The worst case the safety argument rests on.
    ///
    /// `add` does not reduce, so a limb reaching `mul` can be as large as
    /// `2^52 - 2`. Every limb is put there at once, which maximises every
    /// product sum simultaneously -- a state the curve itself may never reach,
    /// which is the point of testing it rather than arguing about it. In a
    /// debug build the scaled carry overflowing a u64 panics here.
    #[test]
    fn limbs_at_their_maximum_do_not_carry_out_of_a_u64() {
        let max = [(1u64 << 52) - 2; 5];
        let r = raw_products(&max, &max);
        assert_eq!(
            carry_reduce(r).to_bytes(),
            carry_reduce_serial(r).to_bytes(),
            "parallel and serial carry disagree at the limb maximum"
        );
    }

    /// The two carry forms agree on arbitrary limb patterns.
    #[test]
    fn parallel_carry_agrees_with_the_serial_one() {
        let mut state = 0x243f_6a88_85a3_08d3u64;
        let mut next = || {
            // xorshift64*, enough to walk the limb space without a dependency.
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545_f491_4f6c_dd1d)
        };
        for _ in 0..20_000 {
            let mut a = [0u64; 5];
            let mut b = [0u64; 5];
            for i in 0..5 {
                // The full range `mul` promises to accept, endpoints included.
                a[i] = next() % (1 << 52);
                b[i] = next() % (1 << 52);
            }
            let r = raw_products(&a, &b);
            assert_eq!(
                carry_reduce(r).to_bytes(),
                carry_reduce_serial(r).to_bytes(),
                "disagreement on a={a:?} b={b:?}"
            );
        }
    }
}
