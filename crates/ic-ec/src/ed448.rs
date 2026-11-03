//! RFC 8032 Ed448 signatures.
//!
//! The field is GF(p), p = 2^448 - 2^224 - 1, in eight limbs of 56 bits. A
//! product's high half folds back with 2^448 = 2^224 + 1, which is why the
//! limbs are 56 bits: 224 is four of them, and the fold lands on a limb
//! boundary.
//!
//! Points use projective coordinates `(X : Y : Z)` on the untwisted Edwards
//! curve x^2 + y^2 = 1 + d x^2 y^2 with d = -39081. Because d is a non-square,
//! RFC 8032's addition formula is *complete*: correct for every pair of
//! points, the identity and doubling among them. Scalar multiplication is
//! therefore one branch-free loop over fixed four-bit windows, each entry of
//! the table read by a constant-time select.
//!
//! Under `std`, multiples of the basepoint come from a precomputed table
//! (`basepoint_table`), read by constant-time selects. Verification computes
//! `[S]B + [k](-A)` in one variable-time pass over both scalars, as every
//! input to it is public.
//!
//! Verification is strict, as [`crate::Ed25519`]'s is: a non-canonical
//! encoding of a key or of R, a key or an R of small order, and an S that is
//! not reduced are all refused, and the equation is checked without the
//! cofactor, `[S]B + [k](-A) == R`, which RFC 8032 section 5.2.7 permits.

use ic_core::ct::Choice;
use ic_core::traits::internal::Xof;
use ic_core::traits::{Algorithm, SelfTest, SignatureScheme};
use ic_core::{ensure, Result, Zeroize};
use ic_hash::Shake256;

#[cfg(any(feature = "std", feature = "ct-probes"))]
mod basepoint_table;
#[cfg(test)]
mod rfc8032_vectors;

/// Bytes in a public key, a seed and each half of a signature.
const LEN: usize = 57;

const MASK: u64 = (1 << 56) - 1;

// The constants below were read from RFC 8032 Table 2 by script, which also
// checked that the basepoint is on the curve and that d is a non-square.

/// p = 2^448 - 2^224 - 1, in limbs.
const P: [u64; 8] = [MASK, MASK, MASK, MASK, MASK - 1, MASK, MASK, MASK];

/// 2p, which every limb of a reduced element is below; added before a
/// subtraction so that no limb goes negative.
const TWO_P: [u64; 8] = [
    2 * MASK,
    2 * MASK,
    2 * MASK,
    2 * MASK,
    2 * MASK - 2,
    2 * MASK,
    2 * MASK,
    2 * MASK,
];

/// d = -39081 mod p.
const D: [u64; 8] = [
    0xffffffffff6756,
    0xffffffffffffff,
    0xffffffffffffff,
    0xffffffffffffff,
    0xfffffffffffffe,
    0xffffffffffffff,
    0xffffffffffffff,
    0xffffffffffffff,
];

/// The basepoint's x coordinate.
const BASE_X: [u64; 8] = [
    0x26a82bc70cc05e,
    0x80e18b00938e26,
    0xf72ab66511433b,
    0xa3d3a46412ae1a,
    0x0f1767ea6de324,
    0x36da9e14657047,
    0xed221d15a622bf,
    0x4f1970c66bed0d,
];

/// The basepoint's y coordinate.
const BASE_Y: [u64; 8] = [
    0x08795bf230fa14,
    0x132c4ed7c8ad98,
    0x1ce67c39c4fdbd,
    0x05a0c2d73ad3ff,
    0xa3984087789c1e,
    0xc7624bea73736c,
    0x248876203756c9,
    0x693f46716eb6bc,
];

/// The group order L = 2^446 - 13818066809895115352007386748515426880336692474882178609894547503885,
/// little-endian.
const L_BYTES: [u8; LEN] = [
    0xf3, 0x44, 0x58, 0xab, 0x92, 0xc2, 0x78, 0x23, 0x55, 0x8f, 0xc5, 0x8d, 0x72, 0xc2, 0x6c, 0x21,
    0x90, 0x36, 0xd6, 0xae, 0x49, 0xdb, 0x4e, 0xc4, 0xe9, 0x23, 0xca, 0x7c, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f, 0x00,
];

/// An all-ones mask when `c` is set, zero otherwise.
fn mask64(c: Choice) -> u64 {
    u64::from(c.unwrap_u8()).wrapping_neg()
}

/// An element of GF(p). Every limb is below 2^57 between operations.
#[derive(Clone, Copy)]
struct Fe([u64; 8]);

impl Fe {
    const ZERO: Fe = Fe([0; 8]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0, 0, 0, 0]);

    /// Carry limbs below 2^63 down to 56 bits, folding the carry out of the
    /// top back in at 2^0 and 2^224. Limbs 0 and 4 can be left up to 2^7 over.
    fn carry(mut l: [u64; 8]) -> Fe {
        for i in 0..7 {
            l[i + 1] += l[i] >> 56;
            l[i] &= MASK;
        }
        let top = l[7] >> 56;
        l[7] &= MASK;
        l[0] += top;
        l[4] += top;
        Fe(l)
    }

    fn add(&self, b: &Fe) -> Fe {
        let mut l = [0u64; 8];
        for (i, x) in l.iter_mut().enumerate() {
            *x = self.0[i] + b.0[i];
        }
        Fe::carry(l)
    }

    fn sub(&self, b: &Fe) -> Fe {
        let mut l = [0u64; 8];
        for (i, x) in l.iter_mut().enumerate() {
            *x = self.0[i] + TWO_P[i] - b.0[i];
        }
        Fe::carry(l)
    }

    fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    fn mul(&self, b: &Fe) -> Fe {
        let (a, b) = (&self.0, &b.0);
        let mut c = [0u128; 15];
        for i in 0..8 {
            for j in 0..8 {
                c[i + j] += u128::from(a[i]) * u128::from(b[j]);
            }
        }
        Fe::reduce_wide(c)
    }

    /// `self * self`, with each cross product computed once and doubled:
    /// 36 limb products where `mul` takes 64. Each column holds what `mul`'s
    /// would, so the bounds `reduce_wide` relies on are the same.
    fn square(&self) -> Fe {
        let a = &self.0;
        let mut c = [0u128; 15];
        for i in 0..8 {
            c[2 * i] += u128::from(a[i]) * u128::from(a[i]);
            // Below 2^58: the doubling happens before the product, in 64 bits.
            let twice = a[i] << 1;
            for j in i + 1..8 {
                c[i + j] += u128::from(twice) * u128::from(a[j]);
            }
        }
        Fe::reduce_wide(c)
    }

    /// The 15 columns of a product, each below 2^117, reduced to limbs.
    fn reduce_wide(mut c: [u128; 15]) -> Fe {
        // 2^448 = 2^224 + 1: limb k >= 8 goes to limbs k - 4 and k - 8. From
        // the top down, so that what lands on limbs 8 to 10 is folded again.
        for k in (8..15).rev() {
            let t = c[k];
            c[k - 4] += t;
            c[k - 8] += t;
        }
        // Each limb is now below 2^121. Carry twice: the first pass leaves a
        // carry out of the top of up to 2^66, the second one of at most 1.
        let mut r = [0u128; 8];
        r.copy_from_slice(&c[..8]);
        for _ in 0..2 {
            for i in 0..7 {
                r[i + 1] += r[i] >> 56;
                r[i] &= u128::from(MASK);
            }
            let top = r[7] >> 56;
            r[7] &= u128::from(MASK);
            r[0] += top;
            r[4] += top;
        }
        let mut l = [0u64; 8];
        for (x, y) in l.iter_mut().zip(r.iter()) {
            *x = *y as u64;
        }
        Fe::carry(l)
    }

    /// `self` squared `n` times.
    fn square_n(&self, n: u32) -> Fe {
        let mut x = *self;
        for _ in 0..n {
            x = x.square();
        }
        x
    }

    /// `self^((p - 3) / 4)`, where (p - 3) / 4 = 2^446 - 2^222 - 1.
    ///
    /// `x_n` below is `self^(2^n - 1)`. The exponent is
    /// `(2^223 - 1) * 2^223 + (2^222 - 1)`.
    fn pow_p34(&self) -> Fe {
        let x1 = *self;
        let x2 = x1.square().mul(&x1);
        let x3 = x2.square().mul(&x1);
        let x6 = x3.square_n(3).mul(&x3);
        let x12 = x6.square_n(6).mul(&x6);
        let x24 = x12.square_n(12).mul(&x12);
        let x30 = x24.square_n(6).mul(&x6);
        let x48 = x24.square_n(24).mul(&x24);
        let x96 = x48.square_n(48).mul(&x48);
        let x192 = x96.square_n(96).mul(&x96);
        let x222 = x192.square_n(30).mul(&x30);
        let x223 = x222.square().mul(&x1);
        x223.square_n(223).mul(&x222)
    }

    /// `self^(p - 2)`: the inverse, and zero for zero.
    /// p - 2 = 4 * ((p - 3) / 4) + 1.
    fn invert(&self) -> Fe {
        self.pow_p34().square_n(2).mul(self)
    }

    /// The canonical encoding: 56 bytes, little-endian, below p.
    fn to_bytes(self) -> [u8; 56] {
        let l = Fe::carry(self.0).0;
        // The value is below 2p, so subtracting p once, and adding it back if
        // that borrowed, reduces it. The borrow out of the top is -1 or 0.
        let mut r = [0u64; 8];
        let mut borrow = 0i64;
        for i in 0..8 {
            let v = l[i] as i64 - P[i] as i64 + borrow;
            r[i] = (v as u64) & MASK;
            borrow = v >> 56;
        }
        let back = core::hint::black_box(borrow as u64);
        let mut carry = 0u64;
        for i in 0..8 {
            let v = r[i] + (P[i] & back) + carry;
            r[i] = v & MASK;
            carry = v >> 56;
        }
        let mut out = [0u8; 56];
        for (i, limb) in r.iter().enumerate() {
            out[7 * i..7 * i + 7].copy_from_slice(&limb.to_le_bytes()[..7]);
        }
        out
    }

    /// Decode 56 little-endian bytes, `None` unless the value is below p.
    fn from_bytes(b: &[u8; 56]) -> Option<Fe> {
        let mut l = [0u64; 8];
        for (i, limb) in l.iter_mut().enumerate() {
            let mut w = [0u8; 8];
            w[..7].copy_from_slice(&b[7 * i..7 * i + 7]);
            *limb = u64::from_le_bytes(w);
        }
        let x = Fe(l);
        // Decoding is of public values only, so this may branch.
        if x.to_bytes() == *b {
            Some(x)
        } else {
            None
        }
    }

    fn is_zero(&self) -> Choice {
        ic_core::ct::is_zero(&self.to_bytes())
    }

    /// The low bit of the canonical value.
    fn is_odd(&self) -> u8 {
        self.to_bytes()[0] & 1
    }

    fn ct_eq(&self, other: &Fe) -> Choice {
        ic_core::ct::eq(&self.to_bytes(), &other.to_bytes())
    }

    /// `other` if `c` is set, `self` otherwise.
    fn select(&self, other: &Fe, c: Choice) -> Fe {
        let m = mask64(c);
        let mut l = self.0;
        for (x, y) in l.iter_mut().zip(other.0.iter()) {
            *x ^= m & (*x ^ y);
        }
        Fe(l)
    }
}

/// A point in projective coordinates, x = X/Z and y = Y/Z.
#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
}

impl Point {
    const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
    };

    fn basepoint() -> Point {
        Point {
            x: Fe(BASE_X),
            y: Fe(BASE_Y),
            z: Fe::ONE,
        }
    }

    // The formulas update a point in place, a coordinate at a time. A whole
    // point is 192 bytes, and `p = p.double()` builds it in a temporary and
    // copies it back, which on x86-64 is a call to `memcpy`: one the
    // compiled-code gate cannot read, inside the loops it has to excuse.
    // A coordinate, 64 bytes, is copied inline.

    /// RFC 8032 section 5.2.4: complete for every pair of points.
    fn add(&self, o: &Point) -> Point {
        let mut p = *self;
        p.add_assign(o);
        p
    }

    /// `self = self + o`, as [`Point::add`].
    fn add_assign(&mut self, o: &Point) {
        let a = self.z.mul(&o.z);
        let b = a.square();
        let c = self.x.mul(&o.x);
        let d = self.y.mul(&o.y);
        let e = Fe(D).mul(&c).mul(&d);
        let f = b.sub(&e);
        let g = b.add(&e);
        let h = self.x.add(&self.y).mul(&o.x.add(&o.y));
        self.x = a.mul(&f).mul(&h.sub(&c).sub(&d));
        self.y = a.mul(&g).mul(&d.sub(&c));
        self.z = f.mul(&g);
    }

    /// `self = self + o` with `o.z = 1`, which saves the first
    /// multiplication of [`Point::add`].
    #[cfg(any(feature = "std", feature = "ct-probes"))]
    fn add_affine_assign(&mut self, o: &basepoint_table::Affine) {
        let a = self.z;
        let b = a.square();
        let c = self.x.mul(&o.x);
        let d = self.y.mul(&o.y);
        let e = Fe(D).mul(&c).mul(&d);
        let f = b.sub(&e);
        let g = b.add(&e);
        let h = self.x.add(&self.y).mul(&o.x.add(&o.y));
        self.x = a.mul(&f).mul(&h.sub(&c).sub(&d));
        self.y = a.mul(&g).mul(&d.sub(&c));
        self.z = f.mul(&g);
    }

    /// RFC 8032 section 5.2.4's doubling.
    fn double(&self) -> Point {
        let mut p = *self;
        p.double_assign();
        p
    }

    /// `self = 2 self`, as [`Point::double`].
    fn double_assign(&mut self) {
        let b = self.x.add(&self.y).square();
        let c = self.x.square();
        let d = self.y.square();
        let e = c.add(&d);
        let h = self.z.square();
        let j = e.sub(&h.add(&h));
        self.x = b.sub(&e).mul(&j);
        self.y = e.mul(&c.sub(&d));
        self.z = e.mul(&j);
    }

    fn negate(&self) -> Point {
        Point {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
        }
    }

    /// `[k]self`, for a little-endian `k` below 2^456, in constant time:
    /// the same doublings and additions for every `k`, and every table entry
    /// read on every window.
    #[cfg_attr(all(feature = "std", not(test)), allow(dead_code))]
    fn mul_scalar(&self, k: &[u8; LEN]) -> Point {
        // `0..=15` times `self`, a coordinate to an array, and every point
        // here built a coordinate at a time: see `add_assign`. Copying
        // `self` whole is such a copy too, so the multiples are summed from
        // the identity, (0, 1, 1), one addition more than they need.
        let mut xs = [Fe::ONE; 16];
        let mut ys = [Fe::ONE; 16];
        let mut zs = [Fe::ONE; 16];
        xs[0] = Fe::ZERO;
        let mut p = Point {
            x: Fe::ZERO,
            y: Fe::ONE,
            z: Fe::ONE,
        };
        for i in 1..16 {
            p.add_assign(self);
            xs[i] = p.x;
            ys[i] = p.y;
            zs[i] = p.z;
        }
        let mut acc = Point {
            x: Fe::ZERO,
            y: Fe::ONE,
            z: Fe::ONE,
        };
        for i in (0..2 * LEN).rev() {
            let nibble = u32::from((k[i / 2] >> ((i & 1) * 4)) & 15);
            Point::window(&mut acc, [&xs, &ys, &zs], nibble);
        }
        acc
    }

    /// One window of [`Point::mul_scalar`]: four doublings of `acc`, then the
    /// addition of `nibble` times the point, read from every entry of its
    /// multiples.
    ///
    /// Out of line so that the loop over the windows keeps its counter in a
    /// register, as `reduce_step` is for the same reason.
    #[inline(never)]
    fn window(acc: &mut Point, [xs, ys, zs]: [&[Fe; 16]; 3], nibble: u32) {
        for _ in 0..4 {
            acc.double_assign();
        }
        let mut t = Point {
            x: Fe::ZERO,
            y: Fe::ONE,
            z: Fe::ONE,
        };
        for j in 0..16 {
            // `j == nibble`, without a comparison the compiler could
            // branch on.
            let diff = j as u32 ^ nibble;
            let hit = Choice::from_u8((diff.wrapping_sub(1) >> 31) as u8);
            t.x = t.x.select(&xs[j], hit);
            t.y = t.y.select(&ys[j], hit);
            t.z = t.z.select(&zs[j], hit);
        }
        acc.add_assign(&t);
    }

    /// RFC 8032 section 5.2.2: y in 56 bytes, then a byte holding x's low bit
    /// in its top bit.
    fn compress(&self) -> [u8; LEN] {
        let zinv = self.z.invert();
        let x = self.x.mul(&zinv);
        let y = self.y.mul(&zinv);
        let mut out = [0u8; LEN];
        out[..56].copy_from_slice(&y.to_bytes());
        out[56] = x.is_odd() << 7;
        out
    }

    /// RFC 8032 section 5.2.3. Refuses a y at or above p, a final byte with
    /// any of its low seven bits set, a y with no x on the curve, and the
    /// sign bit set on x = 0. Decoding is of public values only.
    fn decompress(bytes: &[u8; LEN]) -> Option<Point> {
        if bytes[56] & 0x7f != 0 {
            return None;
        }
        let sign = bytes[56] >> 7;
        let mut yb = [0u8; 56];
        yb.copy_from_slice(&bytes[..56]);
        let y = Fe::from_bytes(&yb)?;

        // x^2 = (y^2 - 1) / (d y^2 - 1) = u / v, and the candidate root is
        // u^3 v (u^5 v^3)^((p - 3) / 4).
        let yy = y.square();
        let u = yy.sub(&Fe::ONE);
        let v = Fe(D).mul(&yy).sub(&Fe::ONE);
        let u2 = u.square();
        let u3 = u2.mul(&u);
        let v3 = v.square().mul(&v);
        let mut x = u3.mul(&v).mul(&u3.mul(&u2).mul(&v3).pow_p34());
        if !bool::from(v.mul(&x.square()).ct_eq(&u)) {
            return None;
        }
        if bool::from(x.is_zero()) && sign == 1 {
            return None;
        }
        if x.is_odd() != sign {
            x = x.neg();
        }
        Some(Point { x, y, z: Fe::ONE })
    }

    /// Whether the two represent the same point.
    fn eq(&self, o: &Point) -> bool {
        bool::from(
            self.x
                .mul(&o.z)
                .ct_eq(&o.x.mul(&self.z))
                .and(self.y.mul(&o.z).ct_eq(&o.y.mul(&self.z))),
        )
    }

    /// Whether the point's order divides 4, the cofactor. The only points
    /// with x = 0 are the identity and (0, -1), of order 2, and `[4]P` is one
    /// of them exactly when it is.
    fn has_small_order(&self) -> bool {
        bool::from(self.double().double().x.is_zero())
    }
}

/// `[k]B`, for `k` below 2^455, in constant time: through the table under
/// `std`, by [`Point::mul_scalar`] without it.
///
/// Every multiplication of the basepoint goes through here, as Ed25519's do
/// through its `mul_basepoint`, so the two paths cannot drift apart.
fn mul_basepoint(k: &[u8; LEN]) -> Point {
    #[cfg(feature = "std")]
    {
        basepoint_table::mul(k)
    }
    #[cfg(not(feature = "std"))]
    {
        let base = Point::basepoint();
        base.mul_scalar(k)
    }
}

/// Fill the basepoint table now; see [`crate::prepare`].
#[cfg(feature = "std")]
pub(crate) fn prepare_table() {
    basepoint_table::prepare();
}

/// The width-5 NAF of a little-endian scalar below 2^456: odd digits in
/// -15..=15, least significant first, with at least four zeros after each
/// non-zero one. Variable time, and so for public scalars only.
///
/// A negative digit adds to the remainder, which can then reach 2^456 but
/// not pass it, so 457 digits always suffice; the eight limbs hold 512 bits.
fn wnaf5(k: &[u8; LEN]) -> [i8; 8 * LEN + 1] {
    let mut x = [0u64; 8];
    for (i, b) in k.iter().enumerate() {
        x[i / 8] |= u64::from(*b) << (8 * (i % 8));
    }
    let mut naf = [0i8; 8 * LEN + 1];
    let mut i = 0;
    while x.iter().any(|w| *w != 0) {
        if x[0] & 1 == 1 {
            let mut d = (x[0] & 31) as i64;
            if d >= 16 {
                d -= 32;
            }
            naf[i] = d as i8;
            // x -= d, which leaves the low five bits zero.
            let (v, mut carry) = if d > 0 {
                (d as u64, false)
            } else {
                (d.unsigned_abs(), true)
            };
            if carry {
                let (r, mut c) = x[0].overflowing_add(v);
                x[0] = r;
                for w in x.iter_mut().skip(1) {
                    let (r, c2) = w.overflowing_add(u64::from(c));
                    *w = r;
                    c = c2;
                }
                carry = c;
            } else {
                let (r, mut b) = x[0].overflowing_sub(v);
                x[0] = r;
                for w in x.iter_mut().skip(1) {
                    let (r, b2) = w.overflowing_sub(u64::from(b));
                    *w = r;
                    b = b2;
                }
                carry = b;
            }
            debug_assert!(!carry, "the scalar left the eight limbs");
        }
        for j in 0..7 {
            x[j] = (x[j] >> 1) | (x[j + 1] << 63);
        }
        x[7] >>= 1;
        i += 1;
    }
    naf
}

/// `[1]P, [3]P .. [15]P`.
fn odd_multiples(p: &Point) -> [Point; 8] {
    let twice = p.double();
    let mut t = [*p; 8];
    for i in 1..8 {
        t[i] = t[i - 1].add(&twice);
    }
    t
}

/// `[s]B + [k]P`, with one chain of doublings for both. Variable time: for
/// verification, where all of `s`, `k` and `P` are public.
fn double_mul_vartime(p: &Point, k: &[u8; LEN], s: &[u8; LEN]) -> Point {
    let (odd_p, odd_b) = (odd_multiples(p), odd_multiples(&Point::basepoint()));
    let (naf_k, naf_s) = (wnaf5(k), wnaf5(s));
    let add = |acc: &Point, table: &[Point; 8], digit: i8| {
        let t = &table[usize::from(digit.unsigned_abs() / 2)];
        if digit > 0 {
            acc.add(t)
        } else {
            acc.add(&t.negate())
        }
    };
    // From the highest digit either has: doubling the identity is wasted.
    let top = (0..naf_k.len())
        .rev()
        .find(|i| naf_k[*i] != 0 || naf_s[*i] != 0)
        .unwrap_or(0);
    let mut acc = Point::IDENTITY;
    for i in (0..=top).rev() {
        acc = acc.double();
        if naf_k[i] != 0 {
            acc = add(&acc, &odd_p, naf_k[i]);
        }
        if naf_s[i] != 0 {
            acc = add(&acc, &odd_b, naf_s[i]);
        }
    }
    acc
}

/// `x mod L`, for a little-endian `x` of any fixed length, in constant time.
///
/// Bit by bit from the top: double, add the bit, subtract L if that reached
/// it. The accumulator stays below L, so one subtraction is always enough.
/// Slower than folding at 2^446, and much simpler to check; it runs three
/// times a signature, each a few tens of microseconds at most.
fn reduce<const N: usize>(x: &[u8; N]) -> [u8; LEN] {
    let l = l_words();
    let mut acc = [0u32; 15];
    let mut t = [0u32; 15];
    for n in (0..8 * N).rev() {
        reduce_step(&mut acc, &mut t, &l, u32::from((x[n / 8] >> (n % 8)) & 1));
    }
    // Below L, so the 60 bytes of `acc` end in three zeros.
    let mut bytes = [0u8; 60];
    for (chunk, w) in bytes.chunks_exact_mut(4).zip(acc.iter()) {
        chunk.copy_from_slice(&w.to_le_bytes());
    }
    let mut out = [0u8; LEN];
    out.copy_from_slice(&bytes[..LEN]);
    acc.zeroize();
    t.zeroize();
    bytes.zeroize();
    out
}

/// One bit of [`reduce`]: `acc = 2 acc + bit`, less L if that reached it.
///
/// Out of line so that the loop over the bits, with the step's words held
/// here, keeps its counter in a register: the compiled-code gate excuses a
/// loop by its counter, and one the compiler spilled to the stack it cannot
/// follow.
#[inline(never)]
fn reduce_step(acc: &mut [u32; 15], t: &mut [u32; 15], l: &[u32; 15], bit: u32) {
    let mut carry = bit;
    for w in acc.iter_mut() {
        let v = (u64::from(*w) << 1) | u64::from(carry);
        *w = v as u32;
        carry = (v >> 32) as u32;
    }
    let mut borrow = 0i64;
    for i in 0..15 {
        let v = i64::from(acc[i]) - i64::from(l[i]) + borrow;
        t[i] = v as u32;
        borrow = v >> 32;
    }
    // All ones if acc < L: keep acc, otherwise take acc - L.
    let keep = core::hint::black_box(borrow as u32);
    for i in 0..15 {
        acc[i] = (acc[i] & keep) | (t[i] & !keep);
    }
}

/// L in fifteen 32-bit words.
fn l_words() -> [u32; 15] {
    let mut l = [0u32; 15];
    for (i, b) in L_BYTES.iter().enumerate() {
        l[i / 4] |= u32::from(*b) << (8 * (i % 4));
    }
    l
}

/// Fifteen 32-bit words of a 57-byte little-endian value.
fn words(x: &[u8; LEN]) -> [u32; 15] {
    let mut w = [0u32; 15];
    for (i, b) in x.iter().enumerate() {
        w[i / 4] |= u32::from(*b) << (8 * (i % 4));
    }
    w
}

/// `(k * s + r) mod L`, in constant time, for `k` and `r` below L and `s`
/// below 2^448.
fn mul_add(k: &[u8; LEN], s: &[u8; LEN], r: &[u8; LEN]) -> [u8; LEN] {
    let (a, b, c) = (words(k), words(s), words(r));
    // Below 2^446 * 2^448 + 2^446, inside the 960 bits of `w`.
    let mut w = [0u32; 30];
    for i in 0..15 {
        let mut carry = 0u64;
        for j in 0..15 {
            let v = u64::from(w[i + j]) + u64::from(a[i]) * u64::from(b[j]) + carry;
            w[i + j] = v as u32;
            carry = v >> 32;
        }
        w[i + 15] = carry as u32;
    }
    let mut carry = 0u64;
    for (x, y) in w[..15].iter_mut().zip(c.iter()) {
        let v = u64::from(*x) + u64::from(*y) + carry;
        *x = v as u32;
        carry = v >> 32;
    }
    for x in w[15..].iter_mut() {
        let v = u64::from(*x) + carry;
        *x = v as u32;
        carry = v >> 32;
    }
    let mut bytes = [0u8; 120];
    for (i, x) in w.iter().enumerate() {
        bytes[4 * i..4 * i + 4].copy_from_slice(&x.to_le_bytes());
    }
    let out = reduce(&bytes);
    w.zeroize();
    bytes.zeroize();
    out
}

/// Whether a signature's S is below L, as RFC 8032 section 5.2.7 requires.
fn is_canonical(s: &[u8; LEN]) -> bool {
    reduce(s) == *s
}

/// `SHAKE256(dom4(0, context) || parts..., 114)`, reduced mod L.
fn hash_to_scalar(context: &[u8], parts: &[&[u8]]) -> [u8; LEN] {
    let mut h = Shake256::default();
    h.update(b"SigEd448");
    // phflag 0, pure Ed448; then the context's length. Callers have checked
    // it is at most 255.
    h.update(&[0, context.len() as u8]);
    h.update(context);
    for p in parts {
        h.update(p);
    }
    let mut digest = [0u8; 2 * LEN];
    h.finalize_xof(&mut digest);
    let out = reduce(&digest);
    digest.zeroize();
    out
}

/// Expand a 57-byte seed into the pruned scalar and the nonce prefix, as
/// RFC 8032 section 5.2.5 does.
fn expand_seed(seed: &[u8]) -> ([u8; LEN], [u8; LEN]) {
    let mut h = [0u8; 2 * LEN];
    let mut x = Shake256::default();
    x.update(seed);
    x.finalize_xof(&mut h);
    let mut s = [0u8; LEN];
    let mut prefix = [0u8; LEN];
    s.copy_from_slice(&h[..LEN]);
    prefix.copy_from_slice(&h[LEN..]);
    s[0] &= 0xfc;
    s[55] |= 0x80;
    s[56] = 0;
    h.zeroize();
    (s, prefix)
}

/// RFC 8032 Ed448 (PureEdDSA over edwards448 with SHAKE256).
///
/// [`SignatureScheme`] signs and verifies with the empty context;
/// [`Ed448Key::sign_with_context`] and [`Ed448VerifyKey::verify_with_context`]
/// take one.
pub struct Ed448;

impl Algorithm for Ed448 {
    const ID: &'static str = "ed448";
    const NAME: &'static str = "Ed448";
}

/// A signing key with its public key already derived, so that a key used
/// more than once pays for that scalar multiplication once.
pub struct Ed448Key {
    /// The pruned scalar from the seed's hash.
    scalar: [u8; LEN],
    /// The second half of that hash, which seeds the deterministic nonce.
    prefix: [u8; LEN],
    /// `scalar * B`, compressed.
    public: [u8; LEN],
}

impl Drop for Ed448Key {
    fn drop(&mut self) {
        self.scalar.zeroize();
        self.prefix.zeroize();
    }
}

impl Ed448Key {
    /// Expand a 57-byte seed and derive its public key.
    pub fn from_seed(seed: &[u8]) -> Result<Self> {
        ic_core::module::operational()?;
        ensure!(seed.len() == LEN, InvalidLength, "ed448 seed");
        let (scalar, prefix) = expand_seed(seed);
        let public = mul_basepoint(&scalar).compress();
        Ok(Self {
            scalar,
            prefix,
            public,
        })
    }

    /// The public key.
    pub fn public_key(&self) -> &[u8; LEN] {
        &self.public
    }

    /// Sign `message` with the empty context.
    pub fn sign(&self, message: &[u8], signature: &mut [u8]) -> Result<()> {
        self.sign_with_context(b"", message, signature)
    }

    /// Sign `message` under `context`, at most 255 bytes, which the verifier
    /// must give byte for byte.
    pub fn sign_with_context(
        &self,
        context: &[u8],
        message: &[u8],
        signature: &mut [u8],
    ) -> Result<()> {
        ic_core::module::operational()?;
        ensure!(
            signature.len() == 2 * LEN,
            InvalidLength,
            "ed448 signature buffer"
        );
        ensure!(context.len() <= 255, InvalidParameter, "ed448 context");

        let mut r = hash_to_scalar(context, &[&self.prefix, message]);
        let big_r = mul_basepoint(&r).compress();
        let k = hash_to_scalar(context, &[&big_r, &self.public, message]);
        let s = mul_add(&k, &self.scalar, &r);

        signature[..LEN].copy_from_slice(&big_r);
        signature[LEN..].copy_from_slice(&s);
        r.zeroize();
        Ok(())
    }
}

impl SignatureScheme for Ed448 {
    const PRIVATE_KEY_LEN: usize = LEN;
    const PUBLIC_KEY_LEN: usize = LEN;
    const SIGNATURE_LEN: usize = 2 * LEN;

    fn public_key(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ic_core::module::operational()?;
        ensure!(out.len() == LEN, InvalidLength, "ed448 public key buffer");
        out.copy_from_slice(Ed448Key::from_seed(private_key)?.public_key());
        Ok(())
    }

    fn sign(private_key: &[u8], message: &[u8], signature: &mut [u8]) -> Result<()> {
        ic_core::module::operational()?;
        Ed448Key::from_seed(private_key)?.sign(message, signature)
    }

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        ic_core::module::operational()?;
        Ed448VerifyKey::from_bytes(public_key)?.verify(message, signature)
    }
}

/// A public key with its point already recovered and negated, the form the
/// verification equation `[S]B + [k](-A) == R` wants.
pub struct Ed448VerifyKey {
    /// The encoding as given, which the challenge hash needs verbatim.
    compressed: [u8; LEN],
    /// `-A`.
    neg_a: Point,
}

impl Ed448VerifyKey {
    /// Decode `public_key`, refusing anything not on the curve, not
    /// canonically encoded, or of order dividing 4. A key of small order has
    /// no secret behind it; see [`crate::Ed25519VerifyKey::from_bytes`].
    pub fn from_bytes(public_key: &[u8]) -> Result<Self> {
        ensure!(public_key.len() == LEN, InvalidLength, "ed448 public key");
        let mut compressed = [0u8; LEN];
        compressed.copy_from_slice(public_key);
        let a = Point::decompress(&compressed).ok_or(ic_core::err!(
            MalformedEncoding,
            "ed448 public key is not on the curve or not canonical"
        ))?;
        ensure!(
            !a.has_small_order(),
            InvalidParameter,
            "ed448 public key has small order"
        );
        Ok(Self {
            compressed,
            neg_a: a.negate(),
        })
    }

    /// The key as it was given.
    pub fn as_bytes(&self) -> &[u8; LEN] {
        &self.compressed
    }

    /// Verify `signature` over `message` with the empty context.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        self.verify_with_context(b"", message, signature)
    }

    /// Verify `signature` over `message` under `context`.
    pub fn verify_with_context(
        &self,
        context: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        ic_core::module::operational()?;
        ensure!(signature.len() == 2 * LEN, InvalidLength, "ed448 signature");
        ensure!(context.len() <= 255, InvalidParameter, "ed448 context");

        let mut big_r = [0u8; LEN];
        big_r.copy_from_slice(&signature[..LEN]);
        let mut s = [0u8; LEN];
        s.copy_from_slice(&signature[LEN..]);

        // RFC 8032 section 5.2.7: S must be below L, or the signature is
        // malleable.
        ensure!(
            is_canonical(&s),
            MalformedEncoding,
            "ed448 signature S is not reduced"
        );
        let r = Point::decompress(&big_r).ok_or(ic_core::err!(
            MalformedEncoding,
            "ed448 signature R is not on the curve or not canonical"
        ))?;
        ensure!(
            !r.has_small_order(),
            MalformedEncoding,
            "ed448 signature R has small order"
        );

        let k = hash_to_scalar(context, &[&big_r, &self.compressed, message]);
        let lhs = double_mul_vartime(&self.neg_a, &k, &s);
        ensure!(lhs.eq(&r), AuthenticationFailed, "ed448");
        Ok(())
    }
}

impl SelfTest for Ed448 {
    fn self_test() -> Result<()> {
        // RFC 8032 section 7.4, "1 octet": a one-byte message, the empty
        // context.
        let mut seed = [0u8; LEN];
        ic_core::codec::hex_decode(
            b"c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e",
            &mut seed,
        )?;
        let mut want_pk = [0u8; LEN];
        ic_core::codec::hex_decode(
            b"43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480",
            &mut want_pk,
        )?;
        let mut want_sig = [0u8; 2 * LEN];
        ic_core::codec::hex_decode(
            b"26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00",
            &mut want_sig,
        )?;
        let message = [0x03u8];

        let mut pk = [0u8; LEN];
        <Self as SignatureScheme>::public_key(&seed, &mut pk)?;
        ensure!(ic_core::ct::verify(&want_pk, &pk), SelfTestFailed, "ed448");

        let mut sig = [0u8; 2 * LEN];
        <Self as SignatureScheme>::sign(&seed, &message, &mut sig)?;
        ensure!(
            ic_core::ct::verify(&want_sig, &sig),
            SelfTestFailed,
            "ed448"
        );

        <Self as SignatureScheme>::verify(&pk, &message, &sig)?;

        // A corrupted signature must be rejected.
        sig[0] ^= 1;
        ensure!(
            <Self as SignatureScheme>::verify(&pk, &message, &sig).is_err(),
            SelfTestFailed,
            "ed448"
        );
        Ok(())
    }
}

/// What signing does with secrets, for the compiled-code gate
/// (`scripts/check-ct.py`), through [`crate::ct_probes`]. Field elements are
/// eight limbs, points their coordinates' limbs in order.
#[cfg(feature = "ct-probes")]
#[doc(hidden)]
pub mod probes {
    use super::basepoint_table::{signed_digits, Affine, Window};
    use super::{mul_add, reduce, Fe, Point, LEN};

    fn point(l: &[u64; 24]) -> Point {
        let mut c = [[0u64; 8]; 3];
        for (i, limb) in l.iter().enumerate() {
            c[i / 8][i % 8] = *limb;
        }
        Point {
            x: Fe(c[0]),
            y: Fe(c[1]),
            z: Fe(c[2]),
        }
    }

    /// Written in place: a 192-byte point returned by value is copied out
    /// with `memcpy`, which the gate cannot read.
    fn limbs(p: &Point, out: &mut [u64; 24]) {
        out[..8].copy_from_slice(&p.x.0);
        out[8..16].copy_from_slice(&p.y.0);
        out[16..].copy_from_slice(&p.z.0);
    }

    fn affine(l: &[u64; 16]) -> Affine {
        let (mut x, mut y) = ([0u64; 8], [0u64; 8]);
        x.copy_from_slice(&l[..8]);
        y.copy_from_slice(&l[8..]);
        Affine { x: Fe(x), y: Fe(y) }
    }

    /// The field multiplication.
    pub fn fe_mul(a: &[u64; 8], b: &[u64; 8]) -> [u64; 8] {
        Fe(*a).mul(&Fe(*b)).0
    }

    /// The field squaring.
    pub fn fe_square(a: &[u64; 8]) -> [u64; 8] {
        Fe(*a).square().0
    }

    /// The inversion, by a fixed exponent: what compresses R and the key.
    pub fn fe_invert(a: &[u64; 8]) -> [u64; 8] {
        Fe(*a).invert().0
    }

    /// The canonical encoding, with its conditional subtraction of p.
    pub fn fe_to_bytes(a: &[u64; 8]) -> [u8; 56] {
        Fe(*a).to_bytes()
    }

    /// The table read: a window's entry by the secret digit.
    pub fn select(window: &[[u64; 16]; 8], digit: i8) -> [u64; 16] {
        let w = Window(core::array::from_fn(|i| affine(&window[i])));
        let a = w.select(digit);
        let mut out = [0u64; 16];
        out[..8].copy_from_slice(&a.x.0);
        out[8..].copy_from_slice(&a.y.0);
        out
    }

    /// The secret scalar's signed radix-16 digits.
    pub fn signed_digits_of(k: &[u8; LEN]) -> [i8; 2 * LEN] {
        signed_digits(k)
    }

    /// The addition of a table entry.
    pub fn add_affine(out: &mut [u64; 24], p: &[u64; 24], q: &[u64; 16]) {
        let mut p = point(p);
        p.add_affine_assign(&affine(q));
        limbs(&p, out)
    }

    /// The doubling.
    pub fn double(out: &mut [u64; 24], p: &[u64; 24]) {
        let mut p = point(p);
        p.double_assign();
        limbs(&p, out)
    }

    /// The windowed multiplication, the basepoint's without `std`.
    pub fn mul_scalar(out: &mut [u64; 24], p: &[u64; 24], k: &[u8; LEN]) {
        limbs(&point(p).mul_scalar(k), out)
    }

    /// `x mod L` for a 114-byte hash: what makes the nonce r.
    pub fn reduce_hash(x: &[u8; 2 * LEN]) -> [u8; LEN] {
        reduce(x)
    }

    /// `(k s + r) mod L`: S, from the secret scalar and nonce.
    pub fn mul_add_of(k: &[u8; LEN], s: &[u8; LEN], r: &[u8; LEN]) -> [u8; LEN] {
        mul_add(k, s, r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::ErrorKind;

    fn hex(s: &str) -> Vec<u8> {
        let mut v = vec![0u8; s.len() / 2];
        ic_core::codec::hex_decode(s.as_bytes(), &mut v).unwrap();
        v
    }

    fn l_minus(k: u8) -> [u8; LEN] {
        let mut x = L_BYTES;
        x[0] -= k;
        x
    }

    /// A deterministic stream of field elements, for the algebraic checks.
    fn elements(n: usize) -> Vec<Fe> {
        let mut x = Shake256::default();
        x.update(b"ic-ec ed448 test elements");
        let mut bytes = vec![0u8; 56 * n];
        x.finalize_xof(&mut bytes);
        bytes
            .chunks(56)
            .map(|c| {
                let mut b = [0u8; 56];
                b.copy_from_slice(c);
                // Clear the top bit so the value is below p.
                b[55] &= 0x7f;
                Fe::from_bytes(&b).unwrap()
            })
            .collect()
    }

    #[test]
    fn rfc8032_vectors() {
        for &(name, sk, pk, ctx, msg, sig) in rfc8032_vectors::VECTORS {
            let (sk, pk, ctx, msg, sig) = (hex(sk), hex(pk), hex(ctx), hex(msg), hex(sig));
            let key = Ed448Key::from_seed(&sk).unwrap();
            assert_eq!(&key.public_key()[..], &pk[..], "{name}: public key");
            let mut out = [0u8; 2 * LEN];
            key.sign_with_context(&ctx, &msg, &mut out).unwrap();
            assert_eq!(&out[..], &sig[..], "{name}: signature");
            let vk = Ed448VerifyKey::from_bytes(&pk).unwrap();
            vk.verify_with_context(&ctx, &msg, &sig).unwrap();
            if ctx.is_empty() {
                Ed448::verify(&pk, &msg, &sig).unwrap();
            } else {
                // The context is bound: without it the signature fails.
                assert!(Ed448::verify(&pk, &msg, &sig).is_err(), "{name}");
            }
        }
    }

    #[test]
    fn self_test_passes() {
        Ed448::self_test().unwrap();
    }

    #[test]
    fn field_inverse_and_square_root() {
        for x in elements(16) {
            if bool::from(x.is_zero()) {
                continue;
            }
            assert!(bool::from(x.mul(&x.invert()).ct_eq(&Fe::ONE)));
            // p = 3 mod 4, so x^((p+1)/4) is a root of x^2 when one exists,
            // and x^2 always has one.
            let sq = x.square();
            let root = sq.pow_p34().mul(&sq);
            assert!(bool::from(root.square().ct_eq(&sq)));
        }
        assert!(bool::from(Fe::ZERO.invert().is_zero()));
    }

    #[test]
    fn field_matches_reference_arithmetic() {
        // Against schoolbook arithmetic on bytes, independent of the limbs:
        // (a + b), (a - b) and a * b mod p, through to_bytes.
        let xs = elements(8);
        for a in &xs {
            for b in &xs {
                let want_add = big_mod(&big_add(&be(a), &be(b)));
                assert_eq!(le_to_be(&a.add(b).to_bytes()), want_add);
                let want_mul = big_mod(&big_mul(&be(a), &be(b)));
                assert_eq!(le_to_be(&a.mul(b).to_bytes()), want_mul);
                // a * a both ways, and the square against the reference.
                assert_eq!(
                    le_to_be(&a.square().to_bytes()),
                    big_mod(&big_mul(&be(a), &be(a)))
                );
                // a - b = c exactly when c + b = a.
                assert!(bool::from(a.sub(b).add(b).ct_eq(a)));
            }
        }
    }

    /// The joint multiplication verification uses, against the constant-time
    /// pair it replaced, at the extremes of the scalar range and at random
    /// scalars; and each recoding obeys the NAF rules.
    #[test]
    fn double_mul_vartime_matches_the_constant_time_pair() {
        let mut state = 0x0bad_cafe_dead_beefu64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut scalars: Vec<[u8; LEN]> = vec![[0; LEN], [0xff; LEN]];
        let mut one = [0u8; LEN];
        one[0] = 1;
        scalars.push(one);
        let mut l_minus_1 = [0u8; LEN];
        l_minus_1.copy_from_slice(&L_BYTES);
        l_minus_1[0] -= 1;
        scalars.push(l_minus_1);
        // Runs of ones, where the recoding carries furthest.
        let mut runs = [0u8; LEN];
        runs[..56].fill(0xff);
        scalars.push(runs);
        for _ in 0..12 {
            let mut k = [0u8; LEN];
            for b in k.iter_mut() {
                *b = next() as u8;
            }
            scalars.push(k);
        }
        for k in &scalars {
            let naf = wnaf5(k);
            let mut last = None;
            for (i, d) in naf.iter().enumerate() {
                if *d != 0 {
                    assert!(d % 2 != 0 && d.unsigned_abs() <= 15, "digit {d}");
                    if let Some(j) = last {
                        assert!(i - j >= 5, "digits at {j} and {i}");
                    }
                    last = Some(i);
                }
            }
        }
        // Some scalars here are above 2^455, the table's bound, so `[s]B`
        // is the windowed multiplication's.
        let base = Point::basepoint();
        let p = mul_basepoint(&scalars[6]);
        for k in &scalars {
            for s in scalars.iter().step_by(3) {
                let want = base.mul_scalar(s).add(&p.mul_scalar(k));
                assert!(double_mul_vartime(&p, k, s).eq(&want));
            }
        }
    }

    /// `square` against `mul` at the widest limbs the representation allows,
    /// where the doubled cross products are largest, and at random limbs of
    /// every width up to it.
    #[test]
    fn square_agrees_with_mul_at_the_limb_bound() {
        let top = (1u64 << 57) - 1;
        let mut cases = vec![Fe([top; 8]), Fe([MASK; 8])];
        let mut state = 0x1234_5678_9abc_def0u64;
        for _ in 0..2000 {
            let mut l = [0u64; 8];
            for x in l.iter_mut() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *x = state & top;
            }
            cases.push(Fe(l));
        }
        for x in &cases {
            assert_eq!(x.square().to_bytes(), x.mul(x).to_bytes());
            // And the result is again within the bound.
            assert!(x.square().0.iter().all(|l| *l <= top));
        }
    }

    // Minimal big-endian bignum helpers for the reference check above.
    fn be(x: &Fe) -> Vec<u8> {
        le_to_be(&x.to_bytes())
    }
    fn le_to_be(x: &[u8]) -> Vec<u8> {
        let mut v = x.to_vec();
        v.reverse();
        v
    }
    fn big_add(a: &[u8], b: &[u8]) -> Vec<u8> {
        let n = a.len().max(b.len()) + 1;
        let mut out = vec![0u8; n];
        let mut carry = 0u16;
        for i in 0..n {
            let x = if i < a.len() { a[a.len() - 1 - i] } else { 0 } as u16;
            let y = if i < b.len() { b[b.len() - 1 - i] } else { 0 } as u16;
            let s = x + y + carry;
            out[n - 1 - i] = s as u8;
            carry = s >> 8;
        }
        out
    }
    fn big_mul(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut out = vec![0u32; a.len() + b.len()];
        for (i, x) in a.iter().rev().enumerate() {
            for (j, y) in b.iter().rev().enumerate() {
                out[i + j] += u32::from(*x) * u32::from(*y);
            }
        }
        let mut bytes = vec![0u8; out.len()];
        let mut carry = 0u64;
        for (i, w) in out.iter().enumerate() {
            let v = u64::from(*w) + carry;
            bytes[out.len() - 1 - i] = v as u8;
            carry = v >> 8;
        }
        bytes
    }
    /// Reduce mod p by repeated subtraction of shifted p: slow and obvious.
    fn big_mod(x: &[u8]) -> Vec<u8> {
        let p = {
            let mut v = vec![0xffu8; 56];
            v[27] = 0xfe; // 2^224's bit, counted from the big end
            v
        };
        let bits = x.len() * 8;
        let get = |v: &[u8], i: usize| (v[v.len() - 1 - i / 8] >> (i % 8)) & 1;
        let mut r = vec![0u8; 57];
        for i in (0..bits).rev() {
            // r = 2r + bit
            let mut carry = get(x, i);
            for k in (0..57).rev() {
                let v = (u16::from(r[k]) << 1) | u16::from(carry);
                r[k] = v as u8;
                carry = (v >> 8) as u8;
            }
            // if r >= p, r -= p
            let mut pp = vec![0u8; 1];
            pp.extend_from_slice(&p);
            if r >= pp {
                let mut borrow = 0i16;
                for k in (0..57).rev() {
                    let v = i16::from(r[k]) - i16::from(pp[k]) - borrow;
                    r[k] = v as u8;
                    borrow = i16::from(v < 0);
                }
            }
        }
        r[1..].to_vec()
    }

    #[test]
    fn reference_p_is_p() {
        // The 2^224 bit is in byte 27 from the big end of 56 bytes.
        let mut p = [0u8; 56];
        for (i, l) in P.iter().enumerate() {
            p[7 * i..7 * i + 7].copy_from_slice(&l.to_le_bytes()[..7]);
        }
        let mut want = vec![0xffu8; 56];
        want[27] = 0xfe;
        assert_eq!(le_to_be(&p), want);
    }

    #[test]
    fn basepoint_has_order_l() {
        let b = Point::basepoint();
        assert!(Point::decompress(&b.compress()).unwrap().eq(&b));
        assert!(b.mul_scalar(&L_BYTES).eq(&Point::IDENTITY));
        assert!(!b.mul_scalar(&l_minus(1)).eq(&Point::IDENTITY));
        assert!(!b.has_small_order());
    }

    #[test]
    fn doubling_agrees_with_adding() {
        let mut p = Point::basepoint();
        for _ in 0..8 {
            assert!(p.double().eq(&p.add(&p)));
            p = p.add(&Point::basepoint()).double();
        }
        assert!(Point::IDENTITY.double().eq(&Point::IDENTITY));
    }

    #[test]
    fn scalar_multiplication_is_linear() {
        // [a]B + [b]B == [a + b]B, with a + b formed by `mul_add` (k = 1).
        let mut one = [0u8; LEN];
        one[0] = 1;
        let a = reduce(&[0x5au8; 80]);
        let b = reduce(&[0xa5u8; 80]);
        let sum = mul_add(&one, &a, &b);
        let base = Point::basepoint();
        assert!(base
            .mul_scalar(&a)
            .add(&base.mul_scalar(&b))
            .eq(&base.mul_scalar(&sum)));
    }

    #[test]
    fn reduce_agrees_with_reference() {
        fn check<const N: usize>() {
            let l_be = le_to_be(&L_BYTES);
            let mut x = Shake256::default();
            x.update(&[N as u8]);
            let mut bytes = [0u8; N];
            x.finalize_xof(&mut bytes);
            let got = reduce(&bytes);
            // got < L, and got = bytes mod L: bytes - got is a multiple of
            // L. Checked as: big_mod_l(bytes) == got.
            assert_eq!(
                le_to_be(&got),
                big_mod_by(&le_to_be(&bytes), &l_be),
                "{N} bytes"
            );
        }
        check::<1>();
        check::<56>();
        check::<57>();
        check::<58>();
        check::<114>();
        check::<120>();
        assert_eq!(reduce(&L_BYTES), [0u8; LEN]);
        assert_eq!(reduce(&l_minus(1)), l_minus(1));
    }

    fn big_mod_by(x: &[u8], m: &[u8]) -> Vec<u8> {
        let n = m.len() + 1;
        let mut mm = vec![0u8; 1];
        mm.extend_from_slice(m);
        let mut r = vec![0u8; n];
        for i in (0..x.len() * 8).rev() {
            let mut carry = (x[x.len() - 1 - i / 8] >> (i % 8)) & 1;
            for k in (0..n).rev() {
                let v = (u16::from(r[k]) << 1) | u16::from(carry);
                r[k] = v as u8;
                carry = (v >> 8) as u8;
            }
            if r >= mm {
                let mut borrow = 0i16;
                for k in (0..n).rev() {
                    let v = i16::from(r[k]) - i16::from(mm[k]) - borrow;
                    r[k] = v as u8;
                    borrow = i16::from(v < 0);
                }
            }
        }
        r[1..].to_vec()
    }

    #[test]
    fn mul_add_agrees_with_reference() {
        let l_be = le_to_be(&L_BYTES);
        let k = reduce(&[0x77u8; 114]);
        let (s, _) = expand_seed(&[9u8; LEN]);
        let r = reduce(&[0x13u8; 114]);
        let got = mul_add(&k, &s, &r);
        let want = big_mod_by(
            &big_add(&big_mul(&le_to_be(&k), &le_to_be(&s)), &le_to_be(&r)),
            &l_be,
        );
        assert_eq!(le_to_be(&got), want);
    }

    /// Adding r to the low 480 bits of k s carries into word 15 only when
    /// they are within r of 2^480, which random scalars almost never are.
    /// k = r = L - 1 and s = 2^34 put them there: (L - 1) 2^34 is below
    /// 2^480 by 2^34 (2^446 - L + 1), about 2^258, far less than r.
    #[test]
    fn mul_add_carries_out_of_the_low_words() {
        let l_be = le_to_be(&L_BYTES);
        let (k, r) = (l_minus(1), l_minus(1));
        let mut s = [0u8; LEN];
        s[4] = 4;
        // The carry is there: the low 480 bits of k s, plus r, reach 2^480.
        let prod = big_mul(&le_to_be(&k), &le_to_be(&s));
        let low = &prod[prod.len() - 60..];
        let sum = big_add(low, &le_to_be(&r));
        assert!(sum.len() > 60 && sum[..sum.len() - 60].iter().any(|b| *b != 0));
        let got = mul_add(&k, &s, &r);
        let want = big_mod_by(&big_add(&prod, &le_to_be(&r)), &l_be);
        assert_eq!(le_to_be(&got), want);
    }

    #[test]
    fn rejects_non_canonical_s() {
        let (_, sk, pk, _, msg, sig) = rfc8032_vectors::VECTORS[1];
        let (_sk, pk, msg, mut sig) = (hex(sk), hex(pk), hex(msg), hex(sig));
        Ed448::verify(&pk, &msg, &sig).unwrap();
        // S + L is the same scalar and a different encoding.
        let s: [u8; LEN] = sig[LEN..].try_into().unwrap();
        let mut sum = [0u8; LEN];
        let mut carry = 0u16;
        for i in 0..LEN {
            let v = u16::from(s[i]) + u16::from(L_BYTES[i]) + carry;
            sum[i] = v as u8;
            carry = v >> 8;
        }
        sig[LEN..].copy_from_slice(&sum);
        let e = Ed448::verify(&pk, &msg, &sig).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::MalformedEncoding);
    }

    #[test]
    fn rejects_tampering() {
        let (_, _, pk, _, msg, sig) = rfc8032_vectors::VECTORS[3];
        let (pk, msg, sig) = (hex(pk), hex(msg), hex(sig));
        for i in [0, LEN - 2, LEN, 2 * LEN - 2] {
            let mut bad = sig.clone();
            bad[i] ^= 0x10;
            assert!(Ed448::verify(&pk, &msg, &bad).is_err(), "byte {i}");
        }
        let mut m = msg.clone();
        m[0] ^= 1;
        assert_eq!(
            Ed448::verify(&pk, &m, &sig).unwrap_err().kind(),
            ErrorKind::AuthenticationFailed
        );
        assert!(Ed448::verify(&pk, &msg, &sig[..2 * LEN - 1]).is_err());
        let mut long = [0u8; 256];
        long[..2 * LEN].copy_from_slice(&sig);
        let key = Ed448Key::from_seed(&[1u8; LEN]).unwrap();
        let mut out = [0u8; 2 * LEN];
        assert!(key.sign_with_context(&long, b"m", &mut out).is_err());
    }

    #[test]
    fn small_order_keys_and_r_are_refused() {
        // The identity, (0, 1), and the point of order 2, (0, -1).
        let mut identity = [0u8; LEN];
        identity[0] = 1;
        let minus_one = {
            let mut b = [0u8; LEN];
            b[..56].copy_from_slice(&Fe::ONE.neg().to_bytes());
            b
        };
        for enc in [identity, minus_one] {
            assert_eq!(
                Ed448VerifyKey::from_bytes(&enc).err().unwrap().kind(),
                ErrorKind::InvalidParameter
            );
        }
        // A signature with R the identity and S = 0 would verify under the
        // identity key; under a real key, R of small order is refused first.
        let (_, _, pk, _, _, _) = rfc8032_vectors::VECTORS[0];
        let mut sig = [0u8; 2 * LEN];
        sig[..LEN].copy_from_slice(&identity);
        assert_eq!(
            Ed448::verify(&hex(pk), b"", &sig).unwrap_err().kind(),
            ErrorKind::MalformedEncoding
        );
    }

    #[test]
    fn non_canonical_encodings_do_not_decode() {
        // y = p, and y = p + 1 (which would otherwise be 1).
        let mut y = [0u8; LEN];
        for (i, l) in P.iter().enumerate() {
            y[7 * i..7 * i + 7].copy_from_slice(&l.to_le_bytes()[..7]);
        }
        assert!(Point::decompress(&y).is_none());
        // p + 1 = 2^448 - 2^224: bytes 0 to 27 zero, 28 to 55 all ones.
        y[..28].fill(0);
        y[28] = 0xff;
        assert!(Point::decompress(&y).is_none());
        // ...which reduced is 1, and 1 does decode.
        let mut one = [0u8; LEN];
        one[0] = 1;
        assert!(Point::decompress(&one).is_some());
        // Low bits of the last byte set.
        let mut b = Point::basepoint().compress();
        b[56] |= 1;
        assert!(Point::decompress(&b).is_none());
        // x = 0 with the sign bit set.
        one[56] = 0x80;
        assert!(Point::decompress(&one).is_none());
    }

    #[test]
    fn both_square_roots_decode_by_the_sign_bit() {
        let b = Point::basepoint();
        let mut enc = b.compress();
        enc[56] ^= 0x80;
        assert!(Point::decompress(&enc).unwrap().eq(&b.negate()));
    }
}
