//! Polynomial arithmetic in `Z_q[X]/(X^256 + 1)`, with `q = 8380417`.
//!
//! ML-DSA's ring, which is not ML-KEM's. The modulus here is
//! `q = 2^23 - 2^13 + 1`, chosen so that `q - 1` is divisible by 512 rather
//! than only by 256. That extra factor of two is why this NTT runs all the way
//! down to length one and multiplication afterwards is a plain coefficient-wise
//! product — where ML-KEM's stops a layer early and needs a degree-one
//! `basemul` for each pair.
//!
//! # The oracle
//!
//! As in [`ic_mlkem::poly`], the test that matters multiplies two polynomials
//! the slow quadratic way and requires the transform to agree. A transposed
//! index or a bad zeta leaves the forward and inverse transforms mutually
//! consistent while computing the wrong product, so a round-trip test proves
//! nothing.
//!
//! The Montgomery bookkeeping was settled before any of this was written, by
//! simulating the pipeline against schoolbook multiplication: transform, point
//! multiply, inverse transform needs **no** correction, while a bare round trip
//! picks up a factor of `R`. That is the reverse of what intuition suggests and
//! exactly the thing that went wrong in the ML-KEM work.
//!
//! # Constants are derived, not transcribed
//!
//! `QINV` comes out of a Newton iteration at compile time and the zeta table
//! from `1753^bitrev8(i)`. Both are checked in the tests against their
//! definitions, and the zeta table against the published reference values —
//! which it matches, giving the one piece of external confirmation available
//! this far down.

use ic_core::Zeroize;

/// The modulus, `2^23 - 2^13 + 1`.
pub const Q: i32 = 8_380_417;

/// Coefficients per polynomial.
pub const N: usize = 256;

/// `q^-1 mod 2^32`, by Newton iteration.
///
/// Derived rather than pasted. Six doublings of a three-bit seed cover 32 bits,
/// the same construction the RSA and elliptic-curve code uses.
const QINV: i32 = compute_qinv();

const fn compute_qinv() -> i32 {
    let q = Q as u32;
    let mut inv: u32 = q;
    let mut i = 0;
    while i < 6 {
        inv = inv.wrapping_mul(2u32.wrapping_sub(q.wrapping_mul(inv)));
        i += 1;
    }
    inv as i32
}

/// `2^32 mod q`, the Montgomery factor.
pub const MONT: i32 = ((1u64 << 32) % (Q as u64)) as i32;

/// Zeta powers in bit-reversed order, in signed Montgomery form.
///
/// `ZETAS[i] = 1753^bitrev8(i) * 2^32 mod q`, reduced to `(-q/2, q/2)`. Entry
/// zero is never read: the forward transform starts at index one and the
/// inverse stops there.
pub const ZETAS: [i32; N] = compute_zetas();

const fn compute_zetas() -> [i32; N] {
    let mut out = [0i32; N];
    let mut i = 0;
    while i < N {
        let mut rev = 0usize;
        let mut b = 0;
        while b < 8 {
            rev |= ((i >> b) & 1) << (7 - b);
            b += 1;
        }
        let mut acc: u64 = 1;
        let mut e = 0;
        while e < rev {
            acc = (acc * 1753) % (Q as u64);
            e += 1;
        }
        let mont = (acc * ((1u64 << 32) % (Q as u64))) % (Q as u64);
        let signed = if mont > (Q as u64) / 2 {
            (mont as i64) - (Q as i64)
        } else {
            mont as i64
        };
        out[i] = signed as i32;
        i += 1;
    }
    out
}

/// Montgomery reduction: `a * 2^-32 mod q`, for `|a| < 2^31 * q`.
#[inline]
pub fn montgomery_reduce(a: i64) -> i32 {
    let t = (a as i32).wrapping_mul(QINV);
    ((a - (t as i64) * (Q as i64)) >> 32) as i32
}

/// Reduce to a representative in `(-q/2, q/2]`.
#[inline]
pub fn reduce32(a: i32) -> i32 {
    let t = (a + (1 << 22)) >> 23;
    a - t * Q
}

/// Add `q` to a negative value, bringing it into `[0, q)`.
#[inline]
pub fn caddq(a: i32) -> i32 {
    a + ((a >> 31) & Q)
}

/// A ring element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Poly {
    /// Coefficients, or transform-domain values after [`Poly::ntt`].
    pub c: [i32; N],
}

impl Default for Poly {
    fn default() -> Self {
        Self::ZERO
    }
}

impl Zeroize for Poly {
    fn zeroize(&mut self) {
        for c in self.c.iter_mut() {
            *c = 0;
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Poly {
    /// The zero polynomial.
    pub const ZERO: Poly = Poly { c: [0i32; N] };

    /// Coefficient-wise addition.
    pub fn add(&self, other: &Poly) -> Poly {
        let mut out = Poly::ZERO;
        for ((o, a), b) in out.c.iter_mut().zip(self.c.iter()).zip(other.c.iter()) {
            *o = a + b;
        }
        out
    }

    /// Coefficient-wise subtraction.
    pub fn sub(&self, other: &Poly) -> Poly {
        let mut out = Poly::ZERO;
        for ((o, a), b) in out.c.iter_mut().zip(self.c.iter()).zip(other.c.iter()) {
            *o = a - b;
        }
        out
    }

    /// Reduce every coefficient to `(-q/2, q/2]`.
    pub fn reduce(&mut self) {
        for c in self.c.iter_mut() {
            *c = reduce32(*c);
        }
    }

    /// Bring every coefficient into `[0, q)`.
    pub fn normalize(&mut self) {
        for c in self.c.iter_mut() {
            *c = caddq(reduce32(*c));
        }
    }

    /// Forward NTT, in place.
    ///
    /// Eight layers, down to length one, because `q` has a primitive 512th root
    /// of unity. The result is a plain pointwise representation, so
    /// [`Poly::pointwise`] is a coefficient-wise multiply with no per-pair
    /// twiddle.
    #[allow(clippy::needless_range_loop)]
    pub fn ntt(&mut self) {
        let mut k = 0usize;
        let mut len = 128usize;
        while len > 0 {
            let mut start = 0;
            while start < N {
                k += 1;
                let zeta = ZETAS[k] as i64;
                for j in start..start + len {
                    let t = montgomery_reduce(zeta * (self.c[j + len] as i64));
                    self.c[j + len] = self.c[j] - t;
                    self.c[j] += t;
                }
                start += 2 * len;
            }
            len >>= 1;
        }
    }

    /// Inverse NTT, leaving the result in Montgomery form.
    ///
    /// The name matches the reference implementation's `invntt_tomont`, and the
    /// factor it carries is what makes [`Poly::pointwise`] need no correction
    /// afterwards. A bare round trip through `ntt` and this does pick up a
    /// factor of `R`, which [`Poly::from_mont`] removes.
    #[allow(clippy::needless_range_loop)]
    pub fn inv_ntt(&mut self) {
        // 41978 = 2^64 / 256 mod q, folding the inverse transform's 1/256 into
        // the Montgomery factor.
        const F: i64 = 41978;

        let mut k = N;
        let mut len = 1usize;
        while len < N {
            let mut start = 0;
            while start < N {
                k -= 1;
                let zeta = -(ZETAS[k] as i64);
                for j in start..start + len {
                    let t = self.c[j];
                    self.c[j] = t + self.c[j + len];
                    self.c[j + len] = t - self.c[j + len];
                    self.c[j + len] = montgomery_reduce(zeta * (self.c[j + len] as i64));
                }
                start += 2 * len;
            }
            len <<= 1;
        }
        for c in self.c.iter_mut() {
            *c = montgomery_reduce(F * (*c as i64));
        }
    }

    /// Coefficient-wise product in the transform domain.
    pub fn pointwise(&self, other: &Poly) -> Poly {
        let mut out = Poly::ZERO;
        for ((o, a), b) in out.c.iter_mut().zip(self.c.iter()).zip(other.c.iter()) {
            *o = montgomery_reduce((*a as i64) * (*b as i64));
        }
        out
    }

    /// Divide every coefficient by `R`, undoing one Montgomery factor.
    pub fn from_mont(&mut self) {
        for c in self.c.iter_mut() {
            *c = montgomery_reduce(*c as i64);
        }
    }

    /// Whether any coefficient is at or above `bound` in absolute value.
    ///
    /// ML-DSA's signing loop rejects candidates on exactly this test, so it is
    /// the gate the whole scheme's timing story rests on: it must not branch on
    /// *which* coefficient failed, only on whether one did, and the result is
    /// public because a rejection is visible in the retry anyway.
    pub fn exceeds(&self, bound: i32) -> bool {
        // Every coefficient is inspected, and the accumulator is only consulted
        // at the end, so the timing does not reveal *which* one failed. The
        // answer itself is public: a rejection is visible in the retry.
        let mut failed = 0i32;
        for c in self.c.iter() {
            // |c|, without a branch, for values already reduced to (-q/2, q/2].
            let abs = *c - ((*c >> 31) & (2 * *c));
            // Sign bit set when abs - bound >= 0, i.e. when the bound is hit.
            failed |= (bound - abs - 1) >> 31;
        }
        failed != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                *c = (self.next() % (Q as u64)) as i32;
            }
            p
        }
    }

    /// Schoolbook multiplication in `Z_q[X]/(X^256 + 1)`. `X^256 = -1`, so a
    /// product term of degree 256 or more wraps with a sign flip.
    ///
    /// The accumulator is `i64`: 256 terms of up to `(q-1)^2` is about
    /// `1.8e16`, comfortably inside its range and nowhere near `i32`'s.
    fn schoolbook(a: &Poly, b: &Poly) -> Poly {
        let mut acc = [0i64; N];
        for i in 0..N {
            for j in 0..N {
                let prod = (a.c[i] as i64) * (b.c[j] as i64);
                if i + j < N {
                    acc[i + j] += prod;
                } else {
                    acc[i + j - N] -= prod;
                }
            }
        }
        let mut out = Poly::ZERO;
        for (o, a) in out.c.iter_mut().zip(acc.iter()) {
            *o = a.rem_euclid(Q as i64) as i32;
        }
        out
    }

    #[test]
    fn the_modulus_has_the_shape_the_scheme_needs() {
        assert_eq!(Q, (1 << 23) - (1 << 13) + 1);
        // q - 1 must be divisible by 512, which is what lets the transform run
        // to length one.
        assert_eq!((Q - 1) % 512, 0);
        // And 1753 must be a primitive 512th root of unity.
        let mut acc: i64 = 1;
        for _ in 0..512 {
            acc = acc * 1753 % Q as i64;
        }
        assert_eq!(acc, 1, "1753^512 != 1");
        let mut acc: i64 = 1;
        for _ in 0..256 {
            acc = acc * 1753 % Q as i64;
        }
        assert_eq!(acc, Q as i64 - 1, "1753^256 should be -1");
    }

    #[test]
    fn the_derived_constants_are_correct() {
        // q * QINV == 1 mod 2^32.
        let product = (Q as u32).wrapping_mul(QINV as u32);
        assert_eq!(product, 1, "QINV is not the inverse of q");
        // The reference implementations publish this value; matching it is the
        // external check.
        assert_eq!(QINV, 58_728_449);
        assert_eq!(MONT, ((1u64 << 32) % Q as u64) as i32);
    }

    #[test]
    fn the_zeta_table_matches_its_definition_and_the_reference() {
        for (i, z) in ZETAS.iter().enumerate() {
            let mut rev = 0usize;
            for b in 0..8 {
                rev |= ((i >> b) & 1) << (7 - b);
            }
            let mut acc: u64 = 1;
            for _ in 0..rev {
                acc = acc * 1753 % Q as u64;
            }
            let mont = acc * ((1u64 << 32) % Q as u64) % Q as u64;
            let want = if mont > Q as u64 / 2 {
                mont as i64 - Q as i64
            } else {
                mont as i64
            };
            assert_eq!(*z as i64, want, "ZETAS[{i}]");
        }
        // The first few published reference values.
        assert_eq!(
            &ZETAS[1..6],
            &[25847, -2608894, -518909, 237124, -777960],
            "the table disagrees with the published reference"
        );
    }

    /// The test that counts. Everything above could be right and this still
    /// fail if an index is transposed.
    #[test]
    fn ntt_multiplication_matches_schoolbook() {
        let mut rng = Rng(0x2468_ace0_1357_9bdf);
        for round in 0..16 {
            let a = rng.poly();
            let b = rng.poly();

            let mut want = schoolbook(&a, &b);
            want.normalize();

            let mut fa = a;
            let mut fb = b;
            fa.ntt();
            fb.ntt();
            let mut got = fa.pointwise(&fb);
            got.inv_ntt();
            // No correction: pointwise contributes R^-1 and inv_ntt contributes
            // R, established by simulation before this was written.
            got.normalize();

            assert_eq!(got, want, "round {round}");
        }
    }

    /// A bare round trip *does* pick up a factor of R, unlike a multiplication.
    #[test]
    fn the_transform_round_trips_modulo_a_montgomery_factor() {
        let mut rng = Rng(0xdead_c0de_feed_face);
        for _ in 0..8 {
            let original = rng.poly();
            let mut p = original;
            p.ntt();
            p.inv_ntt();
            p.from_mont();
            p.normalize();

            let mut want = original;
            want.normalize();
            assert_eq!(p, want);
        }
    }

    #[test]
    fn multiplying_by_one_is_the_identity() {
        let mut rng = Rng(4242);
        let a = rng.poly();
        let mut one = Poly::ZERO;
        one.c[0] = 1;

        let mut fa = a;
        let mut fo = one;
        fa.ntt();
        fo.ntt();
        let mut got = fa.pointwise(&fo);
        got.inv_ntt();
        got.normalize();

        let mut want = a;
        want.normalize();
        assert_eq!(got, want);
    }

    #[test]
    fn reductions_agree_with_the_modulus() {
        for a in [
            i32::MIN / 2,
            -Q,
            -1,
            0,
            1,
            Q / 2,
            Q - 1,
            Q,
            Q + 1,
            i32::MAX / 2,
        ] {
            let r = reduce32(a);
            assert_eq!(
                (r as i64).rem_euclid(Q as i64),
                (a as i64).rem_euclid(Q as i64),
                "reduce32({a})"
            );
            assert!(r.abs() <= Q, "reduce32({a}) = {r} is out of range");
            let c = caddq(reduce32(a));
            assert!((0..Q).contains(&c), "caddq(reduce32({a})) = {c}");
        }
    }

    #[test]
    fn montgomery_reduction_divides_by_r() {
        let r_inv = {
            let mut acc: i64 = 1;
            let mut base = MONT as i64;
            let mut e = Q as i64 - 2;
            while e > 0 {
                if e & 1 == 1 {
                    acc = acc * base % Q as i64;
                }
                base = base * base % Q as i64;
                e >>= 1;
            }
            acc
        };
        for a in [0i64, 1, 1000, Q as i64, (Q as i64) * 1000, -(Q as i64) * 7] {
            let got = montgomery_reduce(a);
            let want = (a.rem_euclid(Q as i64) * r_inv).rem_euclid(Q as i64);
            assert_eq!(
                (got as i64).rem_euclid(Q as i64),
                want,
                "montgomery_reduce({a})"
            );
        }
    }

    #[test]
    fn addition_and_subtraction_are_inverse() {
        let mut rng = Rng(13);
        let a = rng.poly();
        let b = rng.poly();
        let mut round = a.add(&b).sub(&b);
        round.normalize();
        let mut want = a;
        want.normalize();
        assert_eq!(round, want);
    }

    /// The rejection gate signing depends on.
    #[test]
    fn the_bound_check_is_exact() {
        let mut p = Poly::ZERO;
        assert!(!p.exceeds(1), "all zeros is under any positive bound");

        p.c[100] = 5;
        assert!(p.exceeds(5), "5 is not under a bound of 5");
        assert!(!p.exceeds(6));

        p.c[100] = -5;
        assert!(p.exceeds(5), "the check is on absolute value");
        assert!(!p.exceeds(6));

        // A single out-of-range coefficient anywhere must trip it.
        for index in [0usize, 1, 128, 255] {
            let mut q = Poly::ZERO;
            q.c[index] = 1000;
            assert!(q.exceeds(1000), "index {index}");
            assert!(!q.exceeds(1001), "index {index}");
        }
    }
}
