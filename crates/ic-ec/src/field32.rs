//! Arithmetic in GF(2^255 - 19) on 32-bit limbs, for 32-bit RISC-V.
//!
//! # Why a second implementation
//!
//! The five-limb field in `field.rs` multiplies `u64` by `u64` into `u128`.
//! A 64-bit CPU does that in one or two instructions. 32-bit RISC-V has no
//! conditional move, and rustc builds the 128-bit carries there from 32-bit
//! comparisons joined by *branches*: twenty per multiplication, a hundred per
//! Edwards doubling, every one of them on secret data. That was found by
//! reading the compiled code, and `SECURITY.md` records it.
//!
//! This is the representation 32-bit Curve25519 implementations have used
//! since ref10: ten limbs alternating 26 and 25 bits, so limb `i` holds bits
//! `ceil(25.5 i)` upward and ten of them come to exactly 255 bits, which keeps
//! the reduction constant at 19. Every product is `u32 * u32 -> u64` -- `mul`
//! and `mulhu`, no carries at all -- and every sum is a `u64` add, which is
//! `add`, `sltu`, `add`: a comparison producing a value, not a branch. The
//! compiled code for 32-bit RISC-V is checked for branches, as `SECURITY.md`
//! describes.
//!
//! It is selected on `riscv32`, and on any target with `--cfg ic_fe32`, which
//! is how the RFC 7748 and 8032 vectors are run against it on a host. Under
//! test it is also compiled beside the five-limb field and compared with it
//! directly.
//!
//! # Bounds
//!
//! Every operation returns limbs below `2^26` for even `i` and `2^25` for odd
//! `i`, except that limb 1 may exceed `2^25` by a carry below `2^18`. That is
//! the only input shape any operation here is given, so every function below
//! can take it as its precondition. `mul` is written for it with room to
//! spare: a product of two such limbs, doubled and times 19, is below `2^58`,
//! and ten of them are below `2^62`.
#![allow(clippy::needless_range_loop)]

use ic_core::ct::Choice;

/// A field element modulo 2^255 - 19.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fe([u32; 10]);

/// Width of limb `i`: 26 bits when `i` is even, 25 when it is odd.
const fn width(i: usize) -> u32 {
    26 - (i as u32 & 1)
}

/// `2 * p` in this radix: limb 0 is `2 * (2^26 - 19)`, the other even limbs
/// `2 * (2^26 - 1)` and the odd ones `2 * (2^25 - 1)`.
const TWO_P: [u32; 10] = [
    0x7FF_FFDA, 0x3FF_FFFE, 0x7FF_FFFE, 0x3FF_FFFE, 0x7FF_FFFE, 0x3FF_FFFE, 0x7FF_FFFE, 0x3FF_FFFE,
    0x7FF_FFFE, 0x3FF_FFFE,
];

impl Fe {
    /// The additive identity.
    pub const ZERO: Fe = Fe([0; 10]);
    /// The multiplicative identity.
    pub const ONE: Fe = Fe([1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    /// A constant written as five 51-bit limbs, the form `ed25519.rs` gives
    /// its constants in, so that one source serves both representations.
    ///
    /// Evaluated at compile time; the limbs are public constants.
    pub const fn from_limbs51(l: [u64; 5]) -> Fe {
        let mut bytes = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            // Byte `i` is bits 8i..8i+8, drawn from the one or two limbs that
            // hold them.
            let bit = 8 * i;
            let limb = bit / 51;
            let off = bit % 51;
            let mut v = l[limb] >> off;
            if off > 43 && limb < 4 {
                v |= l[limb + 1] << (51 - off);
            }
            bytes[i] = v as u8;
            i += 1;
        }
        Fe::from_bytes_const(&bytes)
    }

    /// A small integer as a field element.
    #[cfg(test)]
    pub const fn from_u64(v: u64) -> Fe {
        let mut bytes = [0u8; 32];
        let le = v.to_le_bytes();
        let mut i = 0;
        while i < 8 {
            bytes[i] = le[i];
            i += 1;
        }
        Fe::from_bytes_const(&bytes)
    }

    /// Field addition.
    #[inline]
    pub fn add(&self, other: &Fe) -> Fe {
        // Unlike the five-limb field, which has thirteen spare bits a limb,
        // these have six at most, so a sum is carried at once rather than left
        // for a later multiplication to absorb.
        let mut r = [0u32; 10];
        for i in 0..10 {
            r[i] = self.0[i] + other.0[i];
        }
        Fe(r).weak_reduce()
    }

    /// Field subtraction, via `self + 2p - other` so limbs stay non-negative.
    ///
    /// `2p`'s limbs are each above the largest limb an operand can have --
    /// limb 1, at `2^25 + 2^18`, against `2^26 - 2` -- so nothing underflows.
    #[inline]
    pub fn sub(&self, other: &Fe) -> Fe {
        let mut r = [0u32; 10];
        for i in 0..10 {
            r[i] = self.0[i] + TWO_P[i] - other.0[i];
        }
        Fe(r).weak_reduce()
    }

    /// Field negation.
    #[inline]
    pub fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    /// One pass of carry propagation over limbs below `2^28`, which is what
    /// `add` and `sub` produce. The carry off the top is at most 8, and 19
    /// times it re-enters limb 0, whose own carry then settles into limb 1.
    #[inline]
    fn weak_reduce(self) -> Fe {
        let mut r = self.0;
        let mut carry = 0u32;
        for i in 0..10 {
            r[i] += carry;
            carry = r[i] >> width(i);
            r[i] &= (1 << width(i)) - 1;
        }
        r[0] += 19 * carry;
        let c = r[0] >> 26;
        r[0] &= (1 << 26) - 1;
        r[1] += c;
        Fe(r)
    }

    /// Field multiplication.
    ///
    /// `z_k` collects every `a_i b_j` with `i + j = k`, and nineteen times
    /// every one with `i + j = k + 10`, since `2^255 = 19`. Limb `i` sits at
    /// bit `ceil(25.5 i)`, so a product of two odd limbs lands one bit above
    /// the limb it is added to and is doubled; every other product lands
    /// exactly.
    #[inline]
    pub fn mul(&self, other: &Fe) -> Fe {
        let a = &self.0;
        let b = &other.0;
        // Nineteen times a limb below 2^26 + 2^18 is below 2^31: still a u32,
        // so each product below stays one widening multiply.
        let mut b19 = [0u32; 10];
        for j in 0..10 {
            b19[j] = 19 * b[j];
        }
        // Odd limbs of `a`, doubled for their products with odd limbs of `b`.
        let mut a2 = [0u32; 10];
        for i in 0..10 {
            a2[i] = a[i] << (i & 1);
        }

        // Written out rather than looped. As a loop over `i` and `j` it was
        // correct, but LLVM kept it rolled for RISC-V and tested `i + j < 10`
        // at run time: a branch on an index, not a secret, but a listing with
        // no branches at all is one that can be checked by counting. The terms
        // were generated, and checked against integer arithmetic mod p, by
        // `scripts/gen_fe32.py`.
        let z0 = m(a[0], b[0])
            + m(a2[1], b19[9])
            + m(a[2], b19[8])
            + m(a2[3], b19[7])
            + m(a[4], b19[6])
            + m(a2[5], b19[5])
            + m(a[6], b19[4])
            + m(a2[7], b19[3])
            + m(a[8], b19[2])
            + m(a2[9], b19[1]);
        let z1 = m(a[0], b[1])
            + m(a[1], b[0])
            + m(a[2], b19[9])
            + m(a[3], b19[8])
            + m(a[4], b19[7])
            + m(a[5], b19[6])
            + m(a[6], b19[5])
            + m(a[7], b19[4])
            + m(a[8], b19[3])
            + m(a[9], b19[2]);
        let z2 = m(a[0], b[2])
            + m(a2[1], b[1])
            + m(a[2], b[0])
            + m(a2[3], b19[9])
            + m(a[4], b19[8])
            + m(a2[5], b19[7])
            + m(a[6], b19[6])
            + m(a2[7], b19[5])
            + m(a[8], b19[4])
            + m(a2[9], b19[3]);
        let z3 = m(a[0], b[3])
            + m(a[1], b[2])
            + m(a[2], b[1])
            + m(a[3], b[0])
            + m(a[4], b19[9])
            + m(a[5], b19[8])
            + m(a[6], b19[7])
            + m(a[7], b19[6])
            + m(a[8], b19[5])
            + m(a[9], b19[4]);
        let z4 = m(a[0], b[4])
            + m(a2[1], b[3])
            + m(a[2], b[2])
            + m(a2[3], b[1])
            + m(a[4], b[0])
            + m(a2[5], b19[9])
            + m(a[6], b19[8])
            + m(a2[7], b19[7])
            + m(a[8], b19[6])
            + m(a2[9], b19[5]);
        let z5 = m(a[0], b[5])
            + m(a[1], b[4])
            + m(a[2], b[3])
            + m(a[3], b[2])
            + m(a[4], b[1])
            + m(a[5], b[0])
            + m(a[6], b19[9])
            + m(a[7], b19[8])
            + m(a[8], b19[7])
            + m(a[9], b19[6]);
        let z6 = m(a[0], b[6])
            + m(a2[1], b[5])
            + m(a[2], b[4])
            + m(a2[3], b[3])
            + m(a[4], b[2])
            + m(a2[5], b[1])
            + m(a[6], b[0])
            + m(a2[7], b19[9])
            + m(a[8], b19[8])
            + m(a2[9], b19[7]);
        let z7 = m(a[0], b[7])
            + m(a[1], b[6])
            + m(a[2], b[5])
            + m(a[3], b[4])
            + m(a[4], b[3])
            + m(a[5], b[2])
            + m(a[6], b[1])
            + m(a[7], b[0])
            + m(a[8], b19[9])
            + m(a[9], b19[8]);
        let z8 = m(a[0], b[8])
            + m(a2[1], b[7])
            + m(a[2], b[6])
            + m(a2[3], b[5])
            + m(a[4], b[4])
            + m(a2[5], b[3])
            + m(a[6], b[2])
            + m(a2[7], b[1])
            + m(a[8], b[0])
            + m(a2[9], b19[9]);
        let z9 = m(a[0], b[9])
            + m(a[1], b[8])
            + m(a[2], b[7])
            + m(a[3], b[6])
            + m(a[4], b[5])
            + m(a[5], b[4])
            + m(a[6], b[3])
            + m(a[7], b[2])
            + m(a[8], b[1])
            + m(a[9], b[0]);
        carry_reduce([z0, z1, z2, z3, z4, z5, z6, z7, z8, z9])
    }

    /// Field squaring: the fifty-five distinct products of `mul`'s hundred,
    /// the off-diagonal ones doubled.
    #[inline]
    pub fn square(&self) -> Fe {
        let a = &self.0;
        let mut a19 = [0u32; 10];
        for j in 0..10 {
            a19[j] = 19 * a[j];
        }
        // Each product doubled once if off the diagonal and once more if both
        // limbs are odd, by scaling the left operand: `d` is twice a limb and
        // `q` four times, below 2^28, so every product stays one widening
        // multiply and below 2^58.3. Written out for the reason `mul` is.
        let mut d = [0u32; 10];
        let mut q = [0u32; 10];
        for i in 0..10 {
            d[i] = a[i] << 1;
            q[i] = a[i] << 2;
        }
        let z0 = m(a[0], a[0])
            + m(q[1], a19[9])
            + m(d[2], a19[8])
            + m(q[3], a19[7])
            + m(d[4], a19[6])
            + m(d[5], a19[5]);
        let z1 =
            m(d[0], a[1]) + m(d[2], a19[9]) + m(d[3], a19[8]) + m(d[4], a19[7]) + m(d[5], a19[6]);
        let z2 = m(d[0], a[2])
            + m(d[1], a[1])
            + m(q[3], a19[9])
            + m(d[4], a19[8])
            + m(q[5], a19[7])
            + m(a[6], a19[6]);
        let z3 =
            m(d[0], a[3]) + m(d[1], a[2]) + m(d[4], a19[9]) + m(d[5], a19[8]) + m(d[6], a19[7]);
        let z4 = m(d[0], a[4])
            + m(q[1], a[3])
            + m(a[2], a[2])
            + m(q[5], a19[9])
            + m(d[6], a19[8])
            + m(d[7], a19[7]);
        let z5 = m(d[0], a[5]) + m(d[1], a[4]) + m(d[2], a[3]) + m(d[6], a19[9]) + m(d[7], a19[8]);
        let z6 = m(d[0], a[6])
            + m(q[1], a[5])
            + m(d[2], a[4])
            + m(d[3], a[3])
            + m(q[7], a19[9])
            + m(a[8], a19[8]);
        let z7 = m(d[0], a[7]) + m(d[1], a[6]) + m(d[2], a[5]) + m(d[3], a[4]) + m(d[8], a19[9]);
        let z8 = m(d[0], a[8])
            + m(q[1], a[7])
            + m(d[2], a[6])
            + m(q[3], a[5])
            + m(a[4], a[4])
            + m(d[9], a19[9]);
        let z9 = m(d[0], a[9]) + m(d[1], a[8]) + m(d[2], a[7]) + m(d[3], a[6]) + m(d[4], a[5]);
        carry_reduce([z0, z1, z2, z3, z4, z5, z6, z7, z8, z9])
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
        let mut z = [0u64; 10];
        for i in 0..10 {
            z[i] = m(self.0[i], 121_666);
        }
        carry_reduce(z)
    }

    /// Multiplicative inverse, `self^(p-2)`, with `inverse(0) == 0`.
    ///
    /// The same addition chain as the five-limb field: 254 squarings and 11
    /// multiplications.
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
        Fe::from_bytes_const(bytes)
    }

    /// [`Self::from_bytes`], as a `const fn` for [`Self::from_limbs51`].
    const fn from_bytes_const(bytes: &[u8; 32]) -> Fe {
        let mut r = [0u32; 10];
        let mut i = 0;
        let mut bit = 0usize;
        while i < 10 {
            // Four bytes from the one holding `bit` cover a 26-bit limb at any
            // offset below 8; past the end reads as zero.
            let mut v = 0u64;
            let mut k = 0;
            while k < 5 {
                let at = bit / 8 + k;
                if at < 32 {
                    v |= (bytes[at] as u64) << (8 * k);
                }
                k += 1;
            }
            r[i] = ((v >> (bit % 8)) as u32) & ((1 << width(i)) - 1);
            bit += width(i) as usize;
            i += 1;
        }
        Fe(r)
    }

    /// Encode as 32 little-endian bytes, fully reduced modulo p.
    pub fn to_bytes(self) -> [u8; 32] {
        // Limbs within their widths but for limb 1's small excess: the value
        // is below 2p, so at most one p comes off.
        let mut t = self.weak_reduce().0;

        // q is 1 exactly when t + 19 reaches 2^255, which is when t >= p.
        // Carrying through every limb computes that floor exactly.
        let mut q = (t[0] + 19) >> 26;
        for i in 1..10 {
            q = (t[i] + q) >> width(i);
        }
        // t - q*p = t + 19q - q*2^255: add 19q, carry, drop bit 255.
        t[0] += 19 * q;
        // The carry out of limb 9 is bit 255, and is dropped.
        let mut carry = 0u32;
        for i in 0..10 {
            t[i] += carry;
            carry = t[i] >> width(i);
            t[i] &= (1 << width(i)) - 1;
        }

        // Eight 32-bit words, each the limbs that overlap it at fixed shifts.
        // A packing loop with a running bit count compiled to branches on that
        // count -- public, but not what this module should need explaining.
        let words: [u32; 8] = [
            t[0] | t[1] << 26,
            t[1] >> 6 | t[2] << 19,
            t[2] >> 13 | t[3] << 13,
            t[3] >> 19 | t[4] << 6,
            t[5] | t[6] << 25,
            t[6] >> 7 | t[7] << 19,
            t[7] >> 13 | t[8] << 12,
            t[8] >> 20 | t[9] << 6,
        ];
        let mut out = [0u8; 32];
        for (chunk, w) in out.chunks_exact_mut(4).zip(words.iter()) {
            chunk.copy_from_slice(&w.to_le_bytes());
        }
        out
    }

    /// Constant-time conditional swap.
    #[inline]
    pub fn cswap(a: &mut Fe, b: &mut Fe, choice: Choice) {
        let mask = (choice.unwrap_u8() as u32).wrapping_neg();
        for i in 0..10 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }

    /// Constant-time conditional move: `a = b` when `choice` is true.
    #[inline]
    pub fn cmov(a: &mut Fe, b: &Fe, choice: Choice) {
        let mask = (choice.unwrap_u8() as u32).wrapping_neg();
        for i in 0..10 {
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

/// One 32x32 multiplication, widened: `mul` and `mulhu` on RISC-V.
#[inline(always)]
fn m(x: u32, y: u32) -> u64 {
    (x as u64) * (y as u64)
}

/// Fold ten 64-bit column sums back into 26- and 25-bit limbs.
///
/// Serial: each column takes the carry of the one below. Columns are below
/// `2^62`, so a carry is below `2^37` and a column plus a carry still fits.
/// The carry off limb 9 is below `2^38`; nineteen times it is below `2^43`,
/// and after it re-enters limb 0 the carry into limb 1 is below `2^18`, which
/// is the one excess the module's bound allows.
#[inline]
fn carry_reduce(mut z: [u64; 10]) -> Fe {
    let mut carry = 0u64;
    for i in 0..10 {
        z[i] += carry;
        carry = z[i] >> width(i);
        z[i] &= (1 << width(i)) - 1;
    }
    z[0] += 19 * carry;
    let c = z[0] >> 26;
    z[0] &= (1 << 26) - 1;
    z[1] += c;
    let mut r = [0u32; 10];
    for i in 0..10 {
        r[i] = z[i] as u32;
    }
    Fe(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// p as ten limbs: the largest value of each limb, less 18 in limb 0.
    const P: [u32; 10] = [
        0x3FF_FFED, 0x1FF_FFFF, 0x3FF_FFFF, 0x1FF_FFFF, 0x3FF_FFFF, 0x1FF_FFFF, 0x3FF_FFFF,
        0x1FF_FFFF, 0x3FF_FFFF, 0x1FF_FFFF,
    ];

    /// Bytes from a counter, through SHA-256: deterministic and unstructured.
    fn bytes(seed: u32) -> [u8; 32] {
        use ic_core::traits::Digest;
        ic_hash::Sha256::digest(&seed.to_le_bytes())
    }

    /// Operands that exercise the bounds: random values, zero, one, p - 1,
    /// every limb at its largest, and limb 1 carrying its permitted excess.
    fn operands() -> std::vec::Vec<Fe> {
        let mut v: std::vec::Vec<Fe> = (0..24).map(|s| Fe::from_bytes(&bytes(s))).collect();
        v.push(Fe::ZERO);
        v.push(Fe::ONE);
        v.push(Fe::ZERO.sub(&Fe::ONE));
        let mut max = [0u32; 10];
        for i in 0..10 {
            max[i] = (1 << width(i)) - 1;
        }
        v.push(Fe(max));
        max[1] += (1 << 18) - 1;
        v.push(Fe(max));
        v
    }

    /// Against the five-limb field, which the RFC 7748 and 8032 vectors pass
    /// against on every 64-bit build. Only when the two are different code:
    /// under `--cfg ic_fe32` `crate::field` is this module.
    #[cfg(not(any(target_arch = "riscv32", ic_fe32)))]
    #[test]
    fn agrees_with_the_five_limb_field() {
        use crate::field::Fe as Fe51;
        let conv = |x: &Fe| Fe51::from_bytes(&x.to_bytes());
        let ops = operands();
        let mut checked = 0;
        for x in &ops {
            let (x51, xb) = (conv(x), x.to_bytes());
            assert_eq!(x51.to_bytes(), xb, "encoding");
            assert_eq!(x.square().to_bytes(), x51.square().to_bytes(), "square");
            assert_eq!(x.neg().to_bytes(), x51.neg().to_bytes(), "neg");
            assert_eq!(x.mul121666().to_bytes(), x51.mul121666().to_bytes(), "a24");
            assert_eq!(x.is_negative().unwrap_u8(), x51.is_negative().unwrap_u8());
            assert_eq!(x.is_zero().unwrap_u8(), x51.is_zero().unwrap_u8());
            for y in &ops {
                let y51 = conv(y);
                assert_eq!(x.mul(y).to_bytes(), x51.mul(&y51).to_bytes(), "mul");
                assert_eq!(x.add(y).to_bytes(), x51.add(&y51).to_bytes(), "add");
                assert_eq!(x.sub(y).to_bytes(), x51.sub(&y51).to_bytes(), "sub");
                checked += 1;
            }
        }
        for x in ops.iter().take(6) {
            assert_eq!(x.invert().to_bytes(), conv(x).invert().to_bytes());
            assert_eq!(x.pow22523().to_bytes(), conv(x).pow22523().to_bytes());
        }
        assert_eq!(checked, 29 * 29);
    }

    /// The same checks as the five-limb field's own tests, so they hold of this
    /// one under `--cfg ic_fe32`, where the comparison above is not compiled.
    #[test]
    fn p_encodes_as_zero_and_p_minus_one_does_not() {
        assert_eq!(Fe(P).to_bytes(), [0u8; 32]);
        let mut pm1 = P;
        pm1[0] -= 1;
        let mut want = [0xFFu8; 32];
        want[0] = 0xEC;
        want[31] = 0x7F;
        assert_eq!(Fe(pm1).to_bytes(), want);
        assert_eq!(Fe::ZERO.sub(&Fe::ONE).to_bytes(), want);
    }

    #[test]
    fn encoding_round_trips_and_ignores_the_top_bit() {
        for s in 0..64 {
            let mut b = bytes(s);
            b[31] &= 0x7F;
            // Values at or above p encode reduced, so compare only below it.
            if b[31] == 0x7F && b[1..31].iter().all(|&x| x == 0xFF) && b[0] >= 0xED {
                continue;
            }
            assert_eq!(Fe::from_bytes(&b).to_bytes(), b);
            let mut hi = b;
            hi[31] |= 0x80;
            assert_eq!(Fe::from_bytes(&hi), Fe::from_bytes(&b));
        }
    }

    #[test]
    fn field_axioms_hold() {
        let ops = operands();
        for x in &ops {
            // x * x^-1 = 1, except for zero, whose inverse is zero.
            let inv = x.invert();
            let want = if bool::from(x.is_zero()) {
                Fe::ZERO
            } else {
                Fe::ONE
            };
            assert!(bool::from(x.mul(&inv).ct_eq(&want)), "inverse");
            assert!(bool::from(x.square().ct_eq(&x.mul(x))), "square");
            assert!(bool::from(x.add(&x.neg()).is_zero()), "x + -x");
            assert!(
                bool::from(x.mul121666().ct_eq(&x.mul(&Fe::from_u64(121_666)))),
                "a24"
            );
            for y in &ops {
                assert!(bool::from(x.mul(y).ct_eq(&y.mul(x))), "commutative");
                assert!(bool::from(x.sub(y).add(y).ct_eq(x)), "x - y + y");
                let z = x.add(y);
                assert!(
                    bool::from(z.mul(x).ct_eq(&x.square().add(&y.mul(x)))),
                    "distributive"
                );
            }
        }
    }

    /// The limb-9 carry must fold back as 19, and a doubled odd-odd product
    /// must land in the right place: `2^255 = 19` and `2^26 * 2^25 = 2^51`,
    /// which are the two facts the product layout rests on.
    #[test]
    fn the_radix_is_what_the_layout_assumes() {
        let two_to = |k: u32| {
            let mut b = [0u8; 32];
            b[(k / 8) as usize] = 1 << (k % 8);
            Fe::from_bytes(&b)
        };
        // 2^128 * 2^127 = 2^255 = 19.
        assert!(bool::from(
            two_to(128).mul(&two_to(127)).ct_eq(&Fe::from_u64(19))
        ));
        // Limbs 1 and 3 (bits 26 and 77) multiply to 2^103, in limb 4 at 102.
        assert!(bool::from(two_to(26).mul(&two_to(77)).ct_eq(&two_to(103))));
        // Limbs 9 and 9 (bit 230 twice) give 2^460 = 19 * 2^205.
        assert!(bool::from(
            two_to(230)
                .square()
                .ct_eq(&two_to(205).mul(&Fe::from_u64(19)))
        ));
    }

    #[test]
    fn cswap_and_cmov_are_conditional() {
        let (x, y) = (Fe::from_bytes(&bytes(1)), Fe::from_bytes(&bytes(2)));
        let (mut a, mut b) = (x, y);
        Fe::cswap(&mut a, &mut b, Choice::from_u8(0));
        assert_eq!((a, b), (x, y));
        Fe::cswap(&mut a, &mut b, Choice::from_u8(1));
        assert_eq!((a, b), (y, x));
        let mut c = x;
        Fe::cmov(&mut c, &y, Choice::from_u8(0));
        assert_eq!(c, x);
        Fe::cmov(&mut c, &y, Choice::from_u8(1));
        assert_eq!(c, y);
    }

    #[test]
    fn from_limbs51_matches_decoding() {
        // 2^51 - 1 in limb 0 and 1 in limb 1 is 2^52 - 1.
        let x = Fe::from_limbs51([(1 << 51) - 1, 1, 0, 0, 0]);
        assert!(bool::from(x.ct_eq(&Fe::from_u64((1 << 52) - 1))));
        for s in 0..16 {
            let b = Fe::from_bytes(&bytes(s)).to_bytes();
            let mut l = [0u64; 5];
            for (k, limb) in l.iter_mut().enumerate() {
                for bit in 0..51 {
                    let at = 51 * k + bit;
                    if at < 256 && (b[at / 8] >> (at % 8)) & 1 == 1 {
                        *limb |= 1 << bit;
                    }
                }
            }
            assert_eq!(Fe::from_limbs51(l).to_bytes(), b);
        }
    }
}
