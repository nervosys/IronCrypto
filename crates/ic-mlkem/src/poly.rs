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
//! `ntt_multiplication_matches_schoolbook`: multiply two polynomials
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
    // 20158 = floor(2^26 / q), so this is a multiply-shift division. (This
    // said round, which is 20159; the AVX2 copy took the comment at its word
    // and disagreed with this function at one input in 3329.)
    const V: i32 = (1i32 << 26) / (Q as i32);
    let t = (V * (a as i32) + (1 << 25)) >> 26;
    (a as i32 - t * (Q as i32)) as i16
}

/// `a * b * 2^-16 mod q`.
#[inline]
fn fqmul(a: i16, b: i16) -> i16 {
    montgomery_reduce((a as i32) * (b as i32))
}

/// Whether this CPU has AVX2, asked once.
///
/// Only under `std`, because the detection needs it: a `no_std` build has no
/// way to ask, and guessing wrong is an illegal instruction rather than a
/// wrong answer.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
pub(crate) fn avx2() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering};
    // 0 not yet asked, 1 yes, 2 no.
    static CACHED: AtomicU8 = AtomicU8::new(0);
    match CACHED.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let have = std::is_x86_feature_detected!("avx2");
            CACHED.store(u8::from(!have) + 1, Ordering::Relaxed);
            have
        }
    }
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

    /// Forward NTT, in place.
    ///
    /// Seven layers of Cooley-Tukey butterflies. The result is *not* a
    /// polynomial any more: it is 128 pairs of values, each pair a degree-one
    /// polynomial modulo `X^2 - zeta`, which is why multiplication afterwards
    /// is [`Poly::basemul`] rather than a plain product.
    ///
    /// With AVX2 it runs sixteen coefficients at a time and produces the same
    /// integers, coefficient for coefficient; see `crate::avx2`.
    #[allow(unsafe_code)]
    pub fn ntt(&mut self) {
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        if avx2() {
            // SAFETY: `avx2()` is the feature test `avx2::ntt` requires.
            unsafe { crate::avx2::ntt(&mut self.c) };
            return;
        }
        self.ntt_portable();
    }

    /// Inverse NTT, in place, including the `1/128` scaling.
    #[allow(unsafe_code)]
    pub fn inv_ntt(&mut self) {
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        if avx2() {
            // SAFETY: `avx2()` is the feature test `avx2::inv_ntt` requires.
            unsafe { crate::avx2::inv_ntt(&mut self.c) };
            return;
        }
        self.inv_ntt_portable();
    }

    /// `self += a o b`: [`Poly::basemul`] accumulated in place.
    ///
    /// The sums are the ones `acc.add(&a.basemul(b))` forms, coefficient for
    /// coefficient, without the two polynomials that expression holds for the
    /// product and the sum. A matrix-vector row is `k` of these.
    #[allow(unsafe_code)]
    pub(crate) fn basemul_add(&mut self, a: &Poly, b: &Poly) {
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        if avx2() {
            // SAFETY: `avx2()` is the feature test `avx2::basemul_add` requires.
            unsafe { crate::avx2::basemul_add(&mut self.c, &a.c, &b.c) };
            return;
        }
        self.basemul_add_portable(a, b);
    }

    /// Reduce every coefficient into `[-q/2, q/2]`.
    #[allow(unsafe_code)]
    pub fn reduce(&mut self) {
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        if avx2() {
            // SAFETY: `avx2()` is the feature test `avx2::reduce` requires.
            unsafe { crate::avx2::reduce(&mut self.c) };
            return;
        }
        self.reduce_portable();
    }

    /// Coefficient-wise addition, in place: [`Poly::add`] without a second
    /// 512-byte polynomial for the result.
    #[allow(unsafe_code)]
    pub(crate) fn add_assign(&mut self, other: &Poly) {
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        if avx2() {
            // SAFETY: `avx2()` is the feature test `avx2::add_assign` requires.
            unsafe { crate::avx2::add_assign(&mut self.c, &other.c) };
            return;
        }
        self.add_assign_portable(other);
    }

    /// Bring every coefficient into `[0, q)`.
    #[allow(unsafe_code)]
    pub fn normalize(&mut self) {
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        if avx2() {
            // SAFETY: `avx2()` is the feature test `avx2::normalize` requires.
            unsafe { crate::avx2::normalize(&mut self.c) };
            return;
        }
        self.normalize_portable();
    }

    /// Convert every coefficient into Montgomery form.
    #[allow(unsafe_code)]
    pub fn to_mont(&mut self) {
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        if avx2() {
            // SAFETY: `avx2()` is the feature test `avx2::to_mont` requires.
            unsafe { crate::avx2::to_mont(&mut self.c) };
            return;
        }
        self.montgomery_form_portable();
    }

    /// [`Poly::add_assign`], one coefficient at a time.
    pub(crate) fn add_assign_portable(&mut self, other: &Poly) {
        for i in 0..N {
            self.c[i] += other.c[i];
        }
    }

    /// `self += a o b`: [`Poly::basemul`] accumulated in place.
    ///
    /// The sums are the ones `acc.add(&a.basemul(b))` forms, coefficient for
    /// coefficient, without the two polynomials that expression holds for the
    /// product and the sum. A matrix-vector row is `k` of these.
    pub(crate) fn basemul_add_portable(&mut self, a: &Poly, b: &Poly) {
        let mut pair = [0i16; 2];
        for i in 0..N / 4 {
            let zeta = ZETAS[64 + i];
            for (offset, z) in [(0, zeta), (2, -zeta)] {
                let at = 4 * i + offset;
                basemul_pair(&mut pair, &a.c[at..at + 2], &b.c[at..at + 2], z);
                self.c[at] += pair[0];
                self.c[at + 1] += pair[1];
            }
        }
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
    pub(crate) fn reduce_portable(&mut self) {
        for c in self.c.iter_mut() {
            *c = barrett_reduce(*c);
        }
    }

    /// Bring every coefficient into `[0, q)`.
    pub(crate) fn normalize_portable(&mut self) {
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
    pub(crate) fn ntt_portable(&mut self) {
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
        self.reduce_portable();
    }

    /// Inverse NTT, in place, including the `1/128` scaling.
    pub(crate) fn inv_ntt_portable(&mut self) {
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
    pub(crate) fn montgomery_form_portable(&mut self) {
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

    /// Inputs for the differential tests: random coefficients in `[-q, q]`,
    /// then the extremes of that range in patterns a lane or shuffle error
    /// would disturb -- constant, alternating, a single spike at each end,
    /// and a ramp.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    fn awkward_polys(rng: &mut Rng, random: usize) -> Vec<Poly> {
        let mut out = Vec::new();
        for _ in 0..random {
            let mut p = Poly::ZERO;
            for c in p.c.iter_mut() {
                *c = (rng.next() % (2 * Q as u64 + 1)) as i16 - Q;
            }
            out.push(p);
        }
        for v in [Q, -Q, Q - 1, -(Q - 1), 1, -1, 0] {
            out.push(Poly { c: [v; N] });
            let mut alt = Poly::ZERO;
            for (i, c) in alt.c.iter_mut().enumerate() {
                *c = if i % 2 == 0 { v } else { -v };
            }
            out.push(alt);
        }
        for at in [0, 1, 15, 16, 127, 128, 254, 255] {
            let mut spike = Poly::ZERO;
            spike.c[at] = Q;
            out.push(spike);
        }
        let mut ramp = Poly::ZERO;
        for (i, c) in ramp.c.iter_mut().enumerate() {
            *c = (i as i16 * 26) - Q;
        }
        out.push(ramp);
        out
    }

    /// The AVX2 transform, inverse transform, base multiplication and
    /// reduction produce the same integers as the portable ones -- not the
    /// same values modulo `q`, the same coefficients -- on every input here.
    ///
    /// The NTT tests below pass whichever path runs, so on their own they
    /// cannot see the two disagree. This runs both explicitly, and says so
    /// when the CPU cannot run the vector path rather than passing silently.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[test]
    fn the_avx2_arithmetic_matches_the_portable_arithmetic_exactly() {
        if !avx2() {
            println!("no AVX2 on this CPU; the vector arithmetic was not exercised");
            return;
        }
        let mut rng = Rng(0x0a5f_2c3e_9b71_d804);
        let inputs = awkward_polys(&mut rng, 400);
        let mut checked = 0;
        for (n, p) in inputs.iter().enumerate() {
            let mut want = *p;
            want.ntt_portable();
            let mut got = *p;
            // SAFETY: guarded by the `avx2()` check above, as is every call
            // into `crate::avx2` in this test.
            #[allow(unsafe_code)]
            unsafe {
                crate::avx2::ntt(&mut got.c)
            };
            assert_eq!(got, want, "ntt, input {n}");

            let mut want = *p;
            want.inv_ntt_portable();
            let mut got = *p;
            #[allow(unsafe_code)]
            unsafe {
                crate::avx2::inv_ntt(&mut got.c)
            };
            assert_eq!(got, want, "inv_ntt, input {n}");

            // Accumulate four products, as a rank-4 matrix row does, onto a
            // starting value that is itself not zero.
            let other = &inputs[(n * 7 + 3) % inputs.len()];
            let mut want = inputs[(n + 1) % inputs.len()];
            let mut got = want;
            for _ in 0..4 {
                want.basemul_add_portable(p, other);
                #[allow(unsafe_code)]
                unsafe {
                    crate::avx2::basemul_add(&mut got.c, &p.c, &other.c)
                };
            }
            assert_eq!(got, want, "basemul_add, input {n}");
            checked += 1;
        }
        assert_eq!(checked, inputs.len(), "the comparison did not run");

        // Barrett reduction, normalisation and conversion to Montgomery form
        // over every sixteen-bit value.
        for chunk in 0..256 {
            let mut p = Poly::ZERO;
            for (i, c) in p.c.iter_mut().enumerate() {
                *c = (chunk * 256 + i) as u16 as i16;
            }
            let mut want = p;
            want.reduce_portable();
            let mut got = p;
            #[allow(unsafe_code)]
            unsafe {
                crate::avx2::reduce(&mut got.c)
            };
            assert_eq!(got, want, "reduce, chunk {chunk}");

            let mut want = p;
            want.normalize_portable();
            let mut got = p;
            #[allow(unsafe_code)]
            unsafe {
                crate::avx2::normalize(&mut got.c)
            };
            assert_eq!(got, want, "normalize, chunk {chunk}");

            let mut want = p;
            want.montgomery_form_portable();
            let mut got = p;
            #[allow(unsafe_code)]
            unsafe {
                crate::avx2::to_mont(&mut got.c)
            };
            assert_eq!(got, want, "to_mont, chunk {chunk}");
        }

        // Addition, on sums that stay inside sixteen bits as the scheme's do.
        for (n, p) in inputs.iter().enumerate() {
            let other = &inputs[(n * 5 + 1) % inputs.len()];
            let mut want = *p;
            want.add_assign_portable(other);
            let mut got = *p;
            #[allow(unsafe_code)]
            unsafe {
                crate::avx2::add_assign(&mut got.c, &other.c)
            };
            assert_eq!(got, want, "add_assign, input {n}");
        }
    }

    /// The portable arithmetic multiplies correctly on its own, whatever
    /// this CPU selects for [`Poly::ntt`]: the schoolbook comparison, run
    /// against the portable functions by name.
    #[test]
    fn the_portable_transform_multiplies_correctly() {
        let mut rng = Rng(0x7777_1234_5678_9abc);
        for round in 0..8 {
            let a = rng.poly();
            let b = rng.poly();
            let mut want = schoolbook(&a, &b);
            want.normalize();
            let mut fa = a;
            let mut fb = b;
            fa.ntt_portable();
            fb.ntt_portable();
            let mut got = Poly::ZERO;
            got.basemul_add_portable(&fa, &fb);
            got.inv_ntt_portable();
            got.normalize();
            assert_eq!(got, want, "round {round}");
        }
    }

    /// Which path [`Poly::ntt`] takes on this CPU.
    #[test]
    fn the_active_arithmetic_path_is_reported() {
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        let vector = avx2();
        #[cfg(not(all(target_arch = "x86_64", feature = "std")))]
        let vector = false;
        println!(
            "ml-kem arithmetic: {}",
            if vector { "AVX2" } else { "portable" }
        );
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
