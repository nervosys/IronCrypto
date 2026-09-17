//! Polynomial arithmetic in `Z_q[X]/(X^256 + 1)`, with `q = 3329`.
//!
//! Everything ML-KEM does happens in this ring. A polynomial is 256
//! coefficients modulo 3329, and the operation that dominates the cost is
//! multiplication, which the NTT turns from quadratic into linearithmic.
//!
//! # Why the NTT is the part worth testing hardest
//!
//! The number-theoretic transform is a discrete Fourier transform over a finite
//! field. `q = 3329` is chosen so that 256th roots of unity exist, which makes
//! multiplication in the ring into pointwise multiplication in the transform
//! domain. It is also a wall of index arithmetic and precomputed roots, and a
//! single transposed index gives a transform that is self-consistent — forward
//! and inverse still round-trip — while computing the wrong product.
//!
//! So a round-trip test proves nothing here. What proves something is
//! [`tests::ntt_multiplication_matches_schoolbook`]: multiply two polynomials
//! the slow quadratic way, multiply them through the NTT, and require the same
//! answer. Schoolbook multiplication in a 256-element ring is four lines and
//! obviously correct by inspection, which is exactly what an oracle needs to
//! be.
//!
//! # Constant time
//!
//! Every reduction here is arithmetic, never a branch on a coefficient.
//! Barrett and Montgomery reduction are used rather than `%`, both because they
//! are faster and because a hardware divide's timing can depend on its
//! operands.

use ic_core::Zeroize;

/// The modulus. Prime, and `q - 1 = 2^8 * 13`, which is what gives the ring its
/// 256th roots of unity.
pub const Q: i16 = 3329;

/// Coefficients per polynomial.
pub const N: usize = 256;

/// `-q^-1 mod 2^16`, for Montgomery reduction.
const Q_INV: i32 = -3327;

/// Zeta powers in bit-reversed order, in Montgomery form.
///
/// Derived at compile time from the primitive root rather than transcribed:
/// `ZETAS[i] = 17^(bitrev7(i)) * 2^16 mod q`. A pasted table is 128 numbers
/// nobody can check by eye, and one wrong entry produces a transform that
/// round-trips and multiplies incorrectly.
pub const ZETAS: [i16; 128] = compute_zetas();

const fn compute_zetas() -> [i16; 128] {
    let mut out = [0i16; 128];
    let mut i = 0;
    while i < 128 {
        // bitrev7: reverse the low seven bits of i.
        let mut rev = 0usize;
        let mut b = 0;
        while b < 7 {
            rev |= ((i >> b) & 1) << (6 - b);
            b += 1;
        }
        // 17^rev mod q, then into Montgomery form.
        let mut acc: u32 = 1;
        let mut e = 0;
        while e < rev {
            acc = (acc * 17) % (Q as u32);
            e += 1;
        }
        // acc * 2^16 mod q
        let mont = ((acc as u64 * 65536) % (Q as u64)) as i16;
        out[i] = mont;
        i += 1;
    }
    out
}

/// Montgomery reduction: given `a`, return `a * 2^-16 mod q` in `(-q, q)`.
#[inline]
pub fn montgomery_reduce(a: i32) -> i16 {
    let t = ((a as i16) as i32).wrapping_mul(Q_INV) as i16;
    ((a - (t as i32) * (Q as i32)) >> 16) as i16
}

/// Barrett reduction: return a representative of `a mod q` in `[-q/2, q/2]`.
///
/// The final subtraction is done in `i32`. In `i16` it overflows: for `a` near
/// `i16::MAX` the quotient reaches 10, and `10 * 3329 = 33290` does not fit.
/// The reference implementations get away with a narrow subtraction because
/// their callers keep coefficients small; making the arithmetic safe for the
/// whole input range costs nothing and removes a precondition nobody can see.
#[inline]
pub fn barrett_reduce(a: i16) -> i16 {
    // 20159 = round(2^26 / q), so this is a multiply-shift division.
    const V: i32 = (1i32 << 26) / (Q as i32);
    let t = (V * (a as i32) + (1 << 25)) >> 26;
    (a as i32 - t * (Q as i32)) as i16
}

/// `a * b * 2^-16 mod q`.
#[inline]
fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce((a as i32) * (b as i32))
}

/// A ring element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poly {
    /// Coefficients, index `i` being the coefficient of `X^i` — or, after
    /// [`Poly::ntt`], a transform-domain value.
    pub c: [i16; N],
}

impl Default for Poly {
    fn default() -> Self {
        Self::ZERO
    }
}

impl Zeroize for Poly {
    fn zeroize(&mut self) {
        // `ic_core::Zeroize` covers the unsigned array widths; coefficients are
        // signed, so overwrite them directly through a volatile-ish loop that
        // the compiler cannot elide, matching what the trait does elsewhere.
        for c in self.c.iter_mut() {
            *c = 0;
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Poly {
    /// The zero polynomial.
    pub const ZERO: Poly = Poly { c: [0i16; N] };

    /// Coefficient-wise addition.
    pub fn add(&self, other: &Poly) -> Poly {
        let mut out = Poly::ZERO;
        for i in 0..N {
            out.c[i] = self.c[i] + other.c[i];
        }
        out
    }

    /// Coefficient-wise subtraction.
    pub fn sub(&self, other: &Poly) -> Poly {
        let mut out = Poly::ZERO;
        for i in 0..N {
            out.c[i] = self.c[i] - other.c[i];
        }
        out
    }

    /// Reduce every coefficient into `[-q/2, q/2]`.
    pub fn reduce(&mut self) {
        for c in self.c.iter_mut() {
            *c = barrett_reduce(*c);
        }
    }

    /// Bring every coefficient into `[0, q)`.
    pub fn normalize(&mut self) {
        for c in self.c.iter_mut() {
            let v = barrett_reduce(*c);
            *c = v + ((v >> 15) & Q);
        }
    }

    /// Forward NTT, in place.
    ///
    /// Seven layers of Cooley-Tukey butterflies. The result is *not* a
    /// polynomial any more: it is 128 pairs of values, each pair a degree-one
    /// polynomial modulo `X^2 - zeta`, which is why multiplication afterwards
    /// is [`Poly::basemul`] rather than a plain product.
    pub fn ntt(&mut self) {
        let mut k = 1usize;
        let mut len = 128usize;
        while len >= 2 {
            let mut start = 0;
            while start < N {
                let zeta = ZETAS[k];
                k += 1;
                for j in start..start + len {
                    let t = fqmul(zeta, self.c[j + len]);
                    self.c[j + len] = self.c[j] - t;
                    self.c[j] += t;
                }
                start += 2 * len;
            }
            len >>= 1;
        }
        self.reduce();
    }

    /// Inverse NTT, in place, including the `1/128` scaling.
    pub fn inv_ntt(&mut self) {
        // 1441 = 2^16 * 2^-7 mod q, the Montgomery-form scaling factor.
        const F: i16 = 1441;

        let mut k = 127usize;
        let mut len = 2usize;
        while len <= 128 {
            let mut start = 0;
            while start < N {
                let zeta = ZETAS[k];
                k = k.wrapping_sub(1);
                for j in start..start + len {
                    let t = self.c[j];
                    self.c[j] = barrett_reduce(t + self.c[j + len]);
                    self.c[j + len] -= t;
                    self.c[j + len] = fqmul(zeta, self.c[j + len]);
                }
                start += 2 * len;
            }
            len <<= 1;
        }
        for c in self.c.iter_mut() {
            *c = fqmul(*c, F);
        }
    }

    /// Multiply two transform-domain polynomials.
    ///
    /// Each of the 128 pairs is multiplied modulo `X^2 - zeta`, with the zeta
    /// alternating sign between even and odd pairs.
    pub fn basemul(&self, other: &Poly) -> Poly {
        let mut out = Poly::ZERO;
        for i in 0..N / 4 {
            let zeta = ZETAS[64 + i];
            basemul_pair(
                &mut out.c[4 * i..4 * i + 2],
                &self.c[4 * i..4 * i + 2],
                &other.c[4 * i..4 * i + 2],
                zeta,
            );
            basemul_pair(
                &mut out.c[4 * i + 2..4 * i + 4],
                &self.c[4 * i + 2..4 * i + 4],
                &other.c[4 * i + 2..4 * i + 4],
                -zeta,
            );
        }
        out
    }

    /// Divide every coefficient by `R`, undoing one Montgomery factor.
    ///
    /// [`Poly::ntt`] followed by [`Poly::inv_ntt`] returns `a * R`, because the
    /// inverse transform's scaling constant carries the factor that
    /// [`Poly::basemul`] would otherwise need cancelled. Multiplication through
    /// the transform therefore needs no correction at all, while a bare round
    /// trip needs this one.
    pub fn from_mont(&mut self) {
        for c in self.c.iter_mut() {
            *c = fqmul(*c, 1);
        }
    }

    /// Convert every coefficient into Montgomery form.
    pub fn to_mont(&mut self) {
        // 1353 = 2^32 mod q, so multiplying by it and reducing gives a * 2^16.
        const R2: i16 = 1353;
        for c in self.c.iter_mut() {
            *c = fqmul(*c, R2);
        }
    }
}

/// `(a0 + a1 X) * (b0 + b1 X) mod (X^2 - zeta)`.
fn basemul_pair(out: &mut [i16], a: &[i16], b: &[i16], zeta: i16) {
    out[0] = fqmul(fqmul(a[1], b[1]), zeta) + fqmul(a[0], b[0]);
    out[1] = fqmul(a[0], b[1]) + fqmul(a[1], b[0]);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(x: i64) -> i16 {
        x.rem_euclid(Q as i64) as i16
    }

    /// Schoolbook multiplication in `Z_q[X]/(X^256 + 1)`.
    ///
    /// Quadratic, obvious, and slow. `X^256 = -1`, so a product term of degree
    /// `>= 256` wraps around with a sign flip. This is the oracle.
    fn schoolbook(a: &Poly, b: &Poly) -> Poly {
        // i64, not i32: 256 terms of up to 3328^2 each would overflow 32 bits
        // if the signs happened to line up.
        let mut acc = [0i64; N];
        for i in 0..N {
            for j in 0..N {
                let prod = (a.c[i] as i64) * (b.c[j] as i64);
                let k = i + j;
                if k < N {
                    acc[k] += prod;
                } else {
                    acc[k - N] -= prod;
                }
            }
        }
        let mut out = Poly::ZERO;
        for (o, a) in out.c.iter_mut().zip(acc.iter()) {
            *o = m(*a);
        }
        out
    }

    /// A small reproducible generator; a fuzzer wants determinism, not entropy.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn poly(&mut self) -> Poly {
            let mut p = Poly::ZERO;
            for c in p.c.iter_mut() {
                *c = (self.next() % (Q as u64)) as i16;
            }
            p
        }
    }

    #[test]
    fn the_zeta_table_is_consistent_with_its_definition() {
        // Recompute independently: 17^bitrev7(i) * 2^16 mod q.
        for (i, z) in ZETAS.iter().enumerate() {
            let mut rev = 0usize;
            for b in 0..7 {
                rev |= ((i >> b) & 1) << (6 - b);
            }
            let mut acc: u64 = 1;
            for _ in 0..rev {
                acc = acc * 17 % (Q as u64);
            }
            let want = (acc * 65536 % (Q as u64)) as i16;
            assert_eq!(*z, want, "ZETAS[{i}]");
        }
        // 17 must actually be a 256th root of unity modulo q.
        let mut acc: u64 = 1;
        for _ in 0..256 {
            acc = acc * 17 % (Q as u64);
        }
        assert_eq!(acc, 1, "17^256 != 1 mod q");
        let mut acc: u64 = 1;
        for _ in 0..128 {
            acc = acc * 17 % (Q as u64);
        }
        assert_ne!(acc, 1, "17 has order dividing 128, so it is not primitive");
    }

    #[test]
    fn reductions_agree_with_the_modulus() {
        for a in [-32768i32, -3329, -1, 0, 1, 1664, 3328, 3329, 32767] {
            let b = barrett_reduce(a as i16);
            assert_eq!(
                (b as i32).rem_euclid(Q as i32),
                (a).rem_euclid(Q as i32),
                "barrett_reduce({a})"
            );
            assert!(b.abs() <= Q, "barrett_reduce({a}) = {b} out of range");
        }
        for a in [0i32, 1, 3329, 65536, -65536, 1 << 20] {
            let r = montgomery_reduce(a);
            // r == a * 2^-16 mod q
            let inv = {
                // 2^-16 mod q by Fermat: 2^(q-2) style, done simply.
                let mut acc: i64 = 1;
                let base: i64 = 65536 % Q as i64;
                let mut e = Q as i64 - 2;
                let mut b = base;
                while e > 0 {
                    if e & 1 == 1 {
                        acc = acc * b % Q as i64;
                    }
                    b = b * b % Q as i64;
                    e >>= 1;
                }
                acc
            };
            let want = ((a as i64).rem_euclid(Q as i64) * inv).rem_euclid(Q as i64);
            assert_eq!((r as i64).rem_euclid(Q as i64), want, "montgomery({a})");
        }
    }

    /// The test that matters. A transposed index in the NTT still round-trips;
    /// it does not still multiply correctly.
    #[test]
    fn ntt_multiplication_matches_schoolbook() {
        let mut rng = Rng(0x0123_4567_89ab_cdef);
        for round in 0..24 {
            let a = rng.poly();
            let b = rng.poly();

            let mut want = schoolbook(&a, &b);
            want.normalize();

            let mut fa = a;
            let mut fb = b;
            fa.ntt();
            fb.ntt();
            let mut got = fa.basemul(&fb);
            got.inv_ntt();
            // No Montgomery correction: basemul contributes R^-1 and the
            // inverse transform's scaling contributes R, so they cancel.
            got.normalize();

            assert_eq!(got, want, "round {round}");
        }
    }

    #[test]
    fn the_transform_round_trips() {
        let mut rng = Rng(0xfeed_face_dead_beef);
        for _ in 0..8 {
            let original = rng.poly();
            let mut p = original;
            p.ntt();
            p.inv_ntt();
            // A bare round trip *does* pick up a factor of R, unlike a
            // multiplication, so undo it.
            p.from_mont();
            p.normalize();
            let mut want = original;
            want.normalize();
            assert_eq!(p, want);
        }
    }

    #[test]
    fn addition_and_subtraction_are_inverse() {
        let mut rng = Rng(7);
        let a = rng.poly();
        let b = rng.poly();
        let mut round = a.add(&b).sub(&b);
        round.normalize();
        let mut want = a;
        want.normalize();
        assert_eq!(round, want);
    }

    /// Multiplying by one must be the identity, which catches a scaling error
    /// that the schoolbook comparison could in principle share.
    #[test]
    fn multiplying_by_one_is_the_identity() {
        let mut rng = Rng(99);
        let a = rng.poly();
        let mut one = Poly::ZERO;
        one.c[0] = 1;

        let mut want = schoolbook(&a, &one);
        want.normalize();
        let mut norm_a = a;
        norm_a.normalize();
        assert_eq!(want, norm_a, "the oracle itself must respect the identity");

        let mut fa = a;
        let mut fo = one;
        fa.ntt();
        fo.ntt();
        let mut got = fa.basemul(&fo);
        got.inv_ntt();
        got.normalize();
        assert_eq!(got, norm_a);
    }
}
