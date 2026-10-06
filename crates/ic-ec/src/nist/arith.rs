//! Constant-time arithmetic modulo a prime, in Montgomery form.
//!
//! Each NIST curve needs two residue rings: the coordinate field GF(p) and the
//! scalar ring Z/nZ. They differ only in their modulus and their width, so
//! the `mont_field!` macro generates all of them — four for P-256 and P-384 —
//! from one implementation.
//!
//! # Deriving the constants
//!
//! Montgomery arithmetic needs `R^2 mod m` and `-m^-1 mod 2^64`. Both are
//! computed at compile time from the modulus rather than pasted in as magic
//! numbers: `R^2` by `2 * 64 * LIMBS` constant-time doublings, and the inverse
//! by Newton iteration. A transcription error in a hand-copied constant would
//! produce a library that computes confidently wrong answers. The only
//! constants left to get wrong are the modulus, the curve coefficient, and the
//! base point — and the tests check those against the curve equation and the
//! group order.

use ic_core::ct::Choice;

/// The widest curve supported here, in 64-bit limbs.
///
/// Nine, for P-521: 521 bits needs nine 64-bit words, and the top one carries
/// only nine significant bits. Nothing here requires the modulus to fill its
/// top limb — see `from_be_bytes` and `to_be_bytes`, which is where that
/// assumption used to live.
pub const MAX_LIMBS: usize = 9;

// # Two word sizes
//
// Values are always `[u64; N]`, and so are the constants. What differs by
// target is the word the carry chains and the Montgomery multiplication run
// on inside `adc`, `sbb` and `mont_mul`.
//
// On a 64-bit CPU, a `u64 * u64 -> u128` product is one or two instructions,
// and [`wide`] uses it. On 32-bit RISC-V the same code is a constant-time
// disaster: that CPU has no conditional move, and rustc builds a 128-bit carry
// from 32-bit comparisons joined by *branches* -- 100 of them in a P-256 point
// addition, 248 on P-521, on secret data. [`narrow`] runs the identical
// algorithms on 32-bit words with `u64` accumulators, so every carry is a
// shift of a value that cannot overflow, and nothing is compared.
//
// Both compute the same function: Montgomery form with `R = 2^(64 N)` is
// Montgomery form with `R = 2^(32 * 2N)`, and `-m^-1 mod 2^32` is the low half
// of `-m^-1 mod 2^64`. So the representation, every constant and every result
// is bit for bit the same, and the tests below compare the two directly.
// `narrow` is selected on `riscv32`, and anywhere under `--cfg ic_limb32`, the
// flag that also selects the 32-bit Curve25519 field.

#[cfg(not(any(target_arch = "riscv32", ic_limb32)))]
pub(crate) use wide::{adc, mont_mul, sbb};

#[cfg(any(target_arch = "riscv32", ic_limb32))]
pub(crate) use narrow::{adc, mont_mul, sbb};

/// 64-bit words, `u128` products: for CPUs with a 64-bit multiplier.
#[cfg(any(test, not(any(target_arch = "riscv32", ic_limb32))))]
pub(crate) mod wide {
    use super::MAX_LIMBS;

    /// Add two multi-limb values, returning the sum and the carry out.
    #[inline]
    pub(crate) const fn adc<const N: usize>(a: [u64; N], b: [u64; N]) -> ([u64; N], u64) {
        let mut out = [0u64; N];
        let mut carry = 0u128;
        let mut i = 0;
        while i < N {
            let sum = (a[i] as u128) + (b[i] as u128) + carry;
            out[i] = sum as u64;
            carry = sum >> 64;
            i += 1;
        }
        (out, carry as u64)
    }

    /// Subtract two multi-limb values, returning the difference and the borrow out.
    #[inline]
    pub(crate) const fn sbb<const N: usize>(a: [u64; N], b: [u64; N]) -> ([u64; N], u64) {
        let mut out = [0u64; N];
        let mut borrow = 0u128;
        let mut i = 0;
        while i < N {
            let diff = (a[i] as u128)
                .wrapping_sub(b[i] as u128)
                .wrapping_sub(borrow);
            out[i] = diff as u64;
            borrow = (diff >> 127) & 1;
            i += 1;
        }
        (out, borrow as u64)
    }

    /// Montgomery multiplication (CIOS), up to its last step: returns `t - m`,
    /// `t`, and whether the first is the answer. The caller makes that choice,
    /// with a barrier at run time and without one in a `const`.
    ///
    /// `inline(always)`: as a plain `#[inline]` function, called through
    /// the macro, it stopped being inlined into the point formulas, and P-256
    /// point addition went from 424 to 500-650 ns while a field
    /// multiplication timed alone did not move.
    #[inline(always)]
    pub(crate) const fn mont_mul<const N: usize>(
        a: [u64; N],
        b: [u64; N],
        m: [u64; N],
        neg_inv: u64,
    ) -> ([u64; N], [u64; N], u64) {
        // Scratch is sized for the widest supported curve rather than
        // `N + 2`, which Rust cannot yet express generically.
        let mut t = [0u64; MAX_LIMBS + 2];
        let mut i = 0;
        while i < N {
            // t += a * b[i]
            let mut carry = 0u128;
            let mut j = 0;
            while j < N {
                let sum = (t[j] as u128) + (a[j] as u128) * (b[i] as u128) + carry;
                t[j] = sum as u64;
                carry = sum >> 64;
                j += 1;
            }
            let sum = (t[N] as u128) + carry;
            t[N] = sum as u64;
            t[N + 1] = (sum >> 64) as u64;

            // t = (t + m * (t[0] * neg_inv mod 2^64)) / 2^64
            let u = t[0].wrapping_mul(neg_inv);
            let sum = (t[0] as u128) + (u as u128) * (m[0] as u128);
            let mut carry = sum >> 64;
            let mut j = 1;
            while j < N {
                let sum = (t[j] as u128) + (u as u128) * (m[j] as u128) + carry;
                t[j - 1] = sum as u64;
                carry = sum >> 64;
                j += 1;
            }
            let sum = (t[N] as u128) + carry;
            t[N - 1] = sum as u64;
            t[N] = (t[N + 1] as u128 + (sum >> 64)) as u64;
            t[N + 1] = 0;
            i += 1;
        }

        // A single conditional subtraction brings the result below m.
        let mut lo = [0u64; N];
        let mut k = 0;
        while k < N {
            lo[k] = t[k];
            k += 1;
        }
        let (reduced, borrow) = sbb(lo, m);
        (reduced, lo, t[N] | (1 - borrow))
    }
}

/// 32-bit words, `u64` accumulators: for 32-bit RISC-V. The same algorithms as
/// [`wide`], a word at a time where it takes a limb at a time. No sum below
/// can overflow its `u64` -- `(2^32 - 1)^2 + 2 (2^32 - 1) = 2^64 - 1` -- so each
/// carry is a shift and no comparison is ever made.
#[cfg(any(test, target_arch = "riscv32", ic_limb32))]
pub(crate) mod narrow {
    use super::MAX_LIMBS;

    /// `x` as 32-bit words, least significant first.
    ///
    /// Every shift here is by a constant. Indexing a word as `x[k / 2] >>
    /// (32 * (k % 2))` shifts a `u64` by a variable amount, which 32-bit
    /// RISC-V does with a branch on whether it reaches 32 -- a branch on an
    /// index, not a secret, but one the compiled code need not have.
    #[inline(always)]
    const fn words<const N: usize>(x: &[u64; N]) -> [u32; 2 * MAX_LIMBS] {
        let mut w = [0u32; 2 * MAX_LIMBS];
        let mut i = 0;
        while i < N {
            w[2 * i] = x[i] as u32;
            w[2 * i + 1] = (x[i] >> 32) as u32;
            i += 1;
        }
        w
    }

    /// Add two multi-limb values, returning the sum and the carry out.
    #[inline]
    pub(crate) const fn adc<const N: usize>(a: [u64; N], b: [u64; N]) -> ([u64; N], u64) {
        let mut out = [0u64; N];
        let mut carry = 0u64;
        let mut i = 0;
        while i < N {
            let lo = (a[i] as u32 as u64) + (b[i] as u32 as u64) + carry;
            let hi = (a[i] >> 32) + (b[i] >> 32) + (lo >> 32);
            out[i] = (lo as u32 as u64) | (hi << 32);
            carry = hi >> 32;
            i += 1;
        }
        (out, carry)
    }

    /// Subtract two multi-limb values, returning the difference and the
    /// borrow out.
    #[inline]
    pub(crate) const fn sbb<const N: usize>(a: [u64; N], b: [u64; N]) -> ([u64; N], u64) {
        let mut out = [0u64; N];
        let mut borrow = 0u64;
        let mut i = 0;
        while i < N {
            let lo = (a[i] as u32 as u64)
                .wrapping_sub(b[i] as u32 as u64)
                .wrapping_sub(borrow);
            let hi = (a[i] >> 32).wrapping_sub(b[i] >> 32).wrapping_sub(lo >> 63);
            out[i] = (lo as u32 as u64) | (hi << 32);
            borrow = hi >> 63;
            i += 1;
        }
        (out, borrow)
    }

    /// Montgomery multiplication (CIOS) on 32-bit words; see
    /// [`super::wide::mont_mul`] for the contract, which is the same.
    #[inline]
    pub(crate) const fn mont_mul<const N: usize>(
        a: [u64; N],
        b: [u64; N],
        m: [u64; N],
        neg_inv: u64,
    ) -> ([u64; N], [u64; N], u64) {
        let m_limbs = m;
        // -m^-1 mod 2^32 is -m^-1 mod 2^64, reduced.
        let neg_inv = neg_inv as u32;
        let n = 2 * N;
        let (a, m) = (words(&a), words(&m));
        let b = words(&b);
        let mut t = [0u32; 2 * MAX_LIMBS + 2];
        let mut i = 0;
        while i < n {
            // t += a * b_i
            let bi = b[i] as u64;
            let mut carry = 0u64;
            let mut j = 0;
            while j < n {
                let sum = (t[j] as u64) + (a[j] as u64) * bi + carry;
                t[j] = sum as u32;
                carry = sum >> 32;
                j += 1;
            }
            let sum = (t[n] as u64) + carry;
            t[n] = sum as u32;
            t[n + 1] = (sum >> 32) as u32;

            // t = (t + m * (t_0 * neg_inv mod 2^32)) / 2^32
            let u = t[0].wrapping_mul(neg_inv) as u64;
            let sum = (t[0] as u64) + u * (m[0] as u64);
            let mut carry = sum >> 32;
            let mut j = 1;
            while j < n {
                let sum = (t[j] as u64) + u * (m[j] as u64) + carry;
                t[j - 1] = sum as u32;
                carry = sum >> 32;
                j += 1;
            }
            let sum = (t[n] as u64) + carry;
            t[n - 1] = sum as u32;
            t[n] = t[n + 1] + (sum >> 32) as u32;
            t[n + 1] = 0;
            i += 1;
        }

        let mut lo = [0u64; N];
        let mut k = 0;
        while k < N {
            lo[k] = (t[2 * k] as u64) | ((t[2 * k + 1] as u64) << 32);
            k += 1;
        }
        let (reduced, borrow) = sbb(lo, m_limbs);
        (reduced, lo, t[n] as u64 | (1 - borrow))
    }
}

/// Branch-free select: `a` when `mask` is all ones, `b` when it is zero.
#[inline]
pub(crate) const fn select<const N: usize>(mask: u64, a: [u64; N], b: [u64; N]) -> [u64; N] {
    let mut out = [0u64; N];
    let mut i = 0;
    while i < N {
        out[i] = b[i] ^ (mask & (a[i] ^ b[i]));
        i += 1;
    }
    out
}

/// [`select`] behind an optimisation barrier, for every runtime use.
///
/// `select` is branch-free as written, but its mask is almost always
/// `flag.wrapping_neg()` for a flag the compiler can see is 0 or 1 -- a carry, a
/// borrow. A compiler that knows that may recognise `b ^ (mask & (a ^ b))` as
/// "choose `a` or `b`", and on a CPU with no conditional move, such as
/// Cortex-M0, emit a branch on a secret. `black_box` hides the mask's range,
/// the same barrier `ic_core::ct::Choice` puts on every value it releases.
///
/// Defence in depth rather than a fix, and worth being exact about: with rustc
/// 1.98 no branch comes back on Cortex-M0 or RISC-V when the barrier is
/// removed. The branches that were there came from field subtraction adding
/// the modulus as a constant; see `sub`. It costs up to five percent on
/// x86-64 and is kept because relying on the optimiser's current choices is
/// what this workspace's constant-time policy exists to avoid.
///
/// `select` itself stays `const`, and barrier-free, for the curve constants
/// computed at compile time, where nothing is secret and `black_box` is not
/// allowed.
#[inline]
pub(crate) fn select_ct<const N: usize>(mask: u64, a: [u64; N], b: [u64; N]) -> [u64; N] {
    select(core::hint::black_box(mask), a, b)
}

/// Double `x` modulo `m`, in constant time.
#[inline]
const fn double_mod<const N: usize>(x: [u64; N], m: [u64; N]) -> [u64; N] {
    let (sum, carry) = adc(x, x);
    let (reduced, borrow) = sbb(sum, m);
    // Reduce when the sum overflowed the limb width, or is already >= m.
    let need = carry | (1 - borrow);
    select(need.wrapping_neg(), reduced, sum)
}

/// `R^2 mod m`, where `R = 2^(64*N)`.
///
/// Computed by doubling one `2 * 64 * N` times, so no constant is transcribed
/// by hand.
pub(crate) const fn compute_r2<const N: usize>(m: [u64; N]) -> [u64; N] {
    let mut x = [0u64; N];
    x[0] = 1;
    let mut i = 0;
    while i < 128 * N {
        x = double_mod(x, m);
        i += 1;
    }
    x
}

/// Decode big-endian bytes into little-endian limbs.
///
/// The byte width need not be `8 * N`: P-521's field elements are 66 bytes in
/// nine limbs, so the top limb takes only two of them. Indexing from the least
/// significant end rather than slicing fixed eight-byte windows is what makes
/// that work, and it is why this is a helper rather than four lines inlined in
/// the macro.
#[inline]
pub(crate) fn from_be_bytes<const N: usize>(bytes: &[u8]) -> [u64; N] {
    let mut limbs = [0u64; N];
    for (i, byte) in bytes.iter().rev().enumerate() {
        limbs[i / 8] |= (*byte as u64) << (8 * (i % 8));
    }
    limbs
}

/// Encode little-endian limbs as big-endian bytes, zero-padded on the left.
#[inline]
pub(crate) fn to_be_bytes<const N: usize>(limbs: &[u64; N], out: &mut [u8]) {
    let n = out.len();
    for (i, slot) in out.iter_mut().rev().enumerate() {
        *slot = (limbs[i / 8] >> (8 * (i % 8))) as u8;
    }
    let _ = n;
}

/// `-m^-1 mod 2^64`, by Newton iteration.
///
/// `x_{k+1} = x_k * (2 - m * x_k)` doubles the number of correct bits each
/// step; starting from `m` (correct to 3 bits for odd `m`), six steps cover 64.
pub(crate) const fn compute_neg_inv(m0: u64) -> u64 {
    let mut inv = m0;
    let mut i = 0;
    while i < 6 {
        inv = inv.wrapping_mul(2u64.wrapping_sub(m0.wrapping_mul(inv)));
        i += 1;
    }
    inv.wrapping_neg()
}

/// The operations the group law and the signature schemes need from a residue
/// ring.
///
/// Implemented by every type the `mont_field!` macro generates, so the point
/// arithmetic can be written once and instantiated per curve.
pub trait Field: Copy + Clone + core::fmt::Debug + PartialEq + Eq + Sized {
    /// The canonical big-endian byte encoding.
    type Bytes: AsRef<[u8]> + AsMut<[u8]> + Copy;

    /// The additive identity.
    const ZERO: Self;
    /// The multiplicative identity.
    const ONE: Self;
    /// Width of [`Self::Bytes`].
    const BYTE_LEN: usize;

    /// Ring addition.
    fn add(&self, rhs: &Self) -> Self;
    /// Ring subtraction.
    fn sub(&self, rhs: &Self) -> Self;
    /// Ring multiplication.
    fn mul(&self, rhs: &Self) -> Self;
    /// Squaring.
    fn square(&self) -> Self;
    /// Doubling, cheaper than a general addition.
    fn double(&self) -> Self;
    /// Tripling, used by the `a = -3` doubling formula.
    fn triple(&self) -> Self;
    /// Negation.
    fn neg(&self) -> Self;
    /// Multiplicative inverse, with `inverse(0) == 0`.
    fn invert(&self) -> Self;

    /// Decode a canonical encoding, rejecting values at or above the modulus.
    fn from_bytes(bytes: &Self::Bytes) -> Option<Self>;
    /// Decode, reducing rather than rejecting.
    fn from_bytes_reduced(bytes: &Self::Bytes) -> Self;
    /// Encode canonically.
    fn to_bytes(&self) -> Self::Bytes;
    /// Build a zeroed byte buffer of the right width. Only the tests need one.
    #[cfg(test)]
    fn zero_bytes() -> Self::Bytes;

    /// Constant-time test for zero.
    fn is_zero(&self) -> Choice;
    /// Constant-time equality.
    fn ct_eq(&self, other: &Self) -> Choice;
    /// Constant-time conditional move.
    fn cmov(a: &mut Self, b: &Self, choice: Choice);
    /// Whether the canonical integer is odd — the SEC1 compression sign bit.
    fn is_odd(&self) -> Choice;
}

/// Generate a constant-time Montgomery residue ring.
///
/// `$limbs` is the width in 64-bit words and `$bytes` is the width of the
/// canonical encoding. They are passed separately because they are not always
/// related by a factor of eight: P-521 is 66 bytes in nine limbs. Both are
/// explicit because Rust cannot yet compute one from the other in a type
/// position.
#[macro_export]
#[doc(hidden)]
macro_rules! mont_field {
    ($name:ident, $limbs:literal, $bytes:literal, $modulus:expr, $doc:literal) => {
        #[doc = $doc]
        ///
        /// Values are held in Montgomery form (`a * R mod m`). Arithmetic is
        /// branch-free and carries no data-dependent memory access.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub struct $name(pub [u64; $limbs]);

        impl $name {
            /// The modulus, as little-endian 64-bit limbs.
            pub const MODULUS: [u64; $limbs] = $modulus;
            /// `R^2 mod m`, for conversion into Montgomery form.
            const R2: [u64; $limbs] = $crate::nist::arith::compute_r2($modulus);
            /// `-m^-1 mod 2^64`.
            const NEG_INV: u64 = $crate::nist::arith::compute_neg_inv($modulus[0]);

            /// Montgomery multiplication up to its last step: `t - m`, `t`,
            /// and whether the first is the answer. [`Self::mont_mul_raw`] and
            /// [`Self::mont_mul_const`] make that choice, one with a barrier
            /// and one without, so the arithmetic exists once -- per word size;
            /// see `mont_mul`.
            #[inline(always)]
            const fn mont_mul_parts(
                a: [u64; $limbs],
                b: [u64; $limbs],
            ) -> ([u64; $limbs], [u64; $limbs], u64) {
                $crate::nist::arith::mont_mul(a, b, Self::MODULUS, Self::NEG_INV)
            }

            /// Montgomery multiplication, constant time: the final subtraction
            /// is chosen through [`select_ct`]($crate::nist::arith::select_ct).
            #[inline]
            fn mont_mul_raw(a: [u64; $limbs], b: [u64; $limbs]) -> [u64; $limbs] {
                let (reduced, lo, need) = Self::mont_mul_parts(a, b);
                $crate::nist::arith::select_ct(need.wrapping_neg(), reduced, lo)
            }

            /// Montgomery multiplication for compile-time constants only.
            ///
            /// `const`, so it cannot use the barrier [`Self::mont_mul_raw`] does,
            /// and must not be used on a secret. Anything that is not a
            /// constant cannot call it by accident in a `const` item, and
            /// anything at runtime has no reason to.
            const fn mont_mul_const(a: [u64; $limbs], b: [u64; $limbs]) -> [u64; $limbs] {
                let (reduced, lo, need) = Self::mont_mul_parts(a, b);
                $crate::nist::arith::select(need.wrapping_neg(), reduced, lo)
            }

            /// Convert a plain integer into Montgomery form, in constant time.
            pub fn to_mont(limbs: [u64; $limbs]) -> Self {
                Self(Self::mont_mul_raw(limbs, Self::R2))
            }

            /// [`Self::to_mont`] for a curve constant, evaluated at compile
            /// time. Not for secrets: it skips the barrier `to_mont` has.
            pub const fn to_mont_const(limbs: [u64; $limbs]) -> Self {
                Self(Self::mont_mul_const(limbs, Self::R2))
            }

            /// Convert out of Montgomery form, in constant time.
            pub fn from_mont(&self) -> [u64; $limbs] {
                let mut one = [0u64; $limbs];
                one[0] = 1;
                Self::mont_mul_raw(self.0, one)
            }

            /// Repeated squaring, `self^(2^n)`.
            pub fn square_n(&self, n: usize) -> Self {
                let mut r = *self;
                for _ in 0..n {
                    r = <Self as $crate::nist::arith::Field>::square(&r);
                }
                r
            }

            /// Exponentiation by a public exponent, square-and-multiply.
            ///
            /// The exponent is always a fixed constant here (`m - 2` for
            /// inversion, `(p + 1) / 4` for square roots), so branching on its
            /// bits leaks nothing; the base stays secret throughout.
            pub fn pow(&self, exponent: &[u64; $limbs]) -> Self {
                let mut result = <Self as $crate::nist::arith::Field>::ONE;
                for i in (0..$limbs).rev() {
                    for bit in (0..64).rev() {
                        result = <Self as $crate::nist::arith::Field>::square(&result);
                        if (exponent[i] >> bit) & 1 == 1 {
                            result = <Self as $crate::nist::arith::Field>::mul(&result, self);
                        }
                    }
                }
                result
            }
        }

        impl $crate::nist::arith::Field for $name {
            type Bytes = [u8; $bytes];

            const ZERO: Self = Self([0u64; $limbs]);
            const ONE: Self = Self(Self::mont_mul_const(
                {
                    let mut one = [0u64; $limbs];
                    one[0] = 1;
                    one
                },
                Self::R2,
            ));
            const BYTE_LEN: usize = $bytes;

            #[inline]
            fn add(&self, other: &Self) -> Self {
                let (sum, carry) = $crate::nist::arith::adc(self.0, other.0);
                let (reduced, borrow) = $crate::nist::arith::sbb(sum, Self::MODULUS);
                let need = carry | (1 - borrow);
                Self($crate::nist::arith::select_ct(
                    need.wrapping_neg(),
                    reduced,
                    sum,
                ))
            }

            #[inline]
            fn sub(&self, other: &Self) -> Self {
                let (diff, borrow) = $crate::nist::arith::sbb(self.0, other.0);
                // On borrow, add the modulus back: add `m & mask`, which is `m`
                // or zero. Adding the modulus as a constant and then selecting
                // let the compiler specialise the carry chain around its limbs
                // -- P-256's are 0 and 2^32 - 1 -- into selects, which
                // Cortex-M0 compiles to branches on the borrow. Masking behind
                // the barrier leaves it nothing to specialise, and is one
                // addition where that was an addition and a selection.
                let mask = core::hint::black_box(borrow.wrapping_neg());
                let mut m = Self::MODULUS;
                for limb in m.iter_mut() {
                    *limb &= mask;
                }
                let (fixed, _) = $crate::nist::arith::adc(diff, m);
                Self(fixed)
            }

            #[inline]
            fn mul(&self, other: &Self) -> Self {
                Self(Self::mont_mul_raw(self.0, other.0))
            }

            #[inline]
            fn square(&self) -> Self {
                Self(Self::mont_mul_raw(self.0, self.0))
            }

            #[inline]
            fn double(&self) -> Self {
                <Self as $crate::nist::arith::Field>::add(self, self)
            }

            #[inline]
            fn triple(&self) -> Self {
                let d = <Self as $crate::nist::arith::Field>::double(self);
                <Self as $crate::nist::arith::Field>::add(&d, self)
            }

            #[inline]
            fn neg(&self) -> Self {
                <Self as $crate::nist::arith::Field>::sub(
                    &<Self as $crate::nist::arith::Field>::ZERO,
                    self,
                )
            }

            fn invert(&self) -> Self {
                // m - 2
                let mut two = [0u64; $limbs];
                two[0] = 2;
                let (exp, _) = $crate::nist::arith::sbb(Self::MODULUS, two);
                self.pow(&exp)
            }

            fn from_bytes(bytes: &Self::Bytes) -> Option<Self> {
                let limbs: [u64; $limbs] = $crate::nist::arith::from_be_bytes(bytes.as_ref());
                let (_, borrow) = $crate::nist::arith::sbb(limbs, Self::MODULUS);
                if borrow == 0 {
                    return None;
                }
                Some(Self::to_mont(limbs))
            }

            fn from_bytes_reduced(bytes: &Self::Bytes) -> Self {
                let limbs: [u64; $limbs] = $crate::nist::arith::from_be_bytes(bytes.as_ref());
                let (reduced, borrow) = $crate::nist::arith::sbb(limbs, Self::MODULUS);
                let limbs = $crate::nist::arith::select_ct(borrow.wrapping_neg(), limbs, reduced);
                Self::to_mont(limbs)
            }

            fn to_bytes(&self) -> Self::Bytes {
                let limbs = self.from_mont();
                let mut out = [0u8; $bytes];
                $crate::nist::arith::to_be_bytes(&limbs, &mut out);
                out
            }

            #[cfg(test)]
            fn zero_bytes() -> Self::Bytes {
                [0u8; $bytes]
            }

            #[inline]
            fn is_zero(&self) -> ic_core::ct::Choice {
                let mut acc = 0u64;
                for limb in self.0.iter() {
                    acc |= *limb;
                }
                ic_core::ct::Choice::from_u8(((acc | acc.wrapping_neg()) >> 63) as u8).not()
            }

            #[inline]
            fn ct_eq(&self, other: &Self) -> ic_core::ct::Choice {
                let d = <Self as $crate::nist::arith::Field>::sub(self, other);
                <Self as $crate::nist::arith::Field>::is_zero(&d)
            }

            #[inline]
            fn cmov(a: &mut Self, b: &Self, choice: ic_core::ct::Choice) {
                let mask = (choice.unwrap_u8() as u64).wrapping_neg();
                a.0 = $crate::nist::arith::select_ct(mask, b.0, a.0);
            }

            #[inline]
            fn is_odd(&self) -> ic_core::ct::Choice {
                ic_core::ct::Choice::from_u8((self.from_mont()[0] & 1) as u8)
            }
        }
    };
}

/// Square root by `a^((p+1)/4)`, valid only when `p = 3 mod 4`.
///
/// Both P-256 and P-384 satisfy that, which is why neither needs the general
/// Tonelli-Shanks algorithm. The caller must square the result to confirm the
/// input was a quadratic residue; this returns a candidate either way.
pub fn sqrt_p3mod4<F: Field, const N: usize>(
    x: &F,
    modulus: [u64; N],
    pow: impl Fn(&F, &[u64; N]) -> F,
) -> F {
    let mut one = [0u64; N];
    one[0] = 1;
    let (sum, _) = adc(modulus, one);
    // (p + 1) / 4
    let mut exp = [0u64; N];
    let mut i = 0;
    while i < N {
        let lo = sum[i] >> 2;
        let hi = if i + 1 < N { sum[i + 1] << 62 } else { 0 };
        exp[i] = lo | hi;
        i += 1;
    }
    pow(x, &exp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newton_inverse_satisfies_its_defining_equation() {
        for m0 in [
            0xffff_ffff_ffff_ffffu64,
            0xf3b9_cac2_fc63_2551,
            0x0000_0000_ffff_ffff,
            0xecec_196a_ccc5_2973,
        ] {
            // m * (-m^-1) == -1 mod 2^64
            assert_eq!(m0.wrapping_mul(compute_neg_inv(m0)), u64::MAX, "{m0:#x}");
        }
    }

    #[test]
    fn carry_and_borrow_propagate() {
        let (sum, carry) = adc([u64::MAX, 0], [1u64, 0]);
        assert_eq!(sum, [0, 1]);
        assert_eq!(carry, 0);

        let (sum, carry) = adc([u64::MAX, u64::MAX], [1u64, 0]);
        assert_eq!(sum, [0, 0]);
        assert_eq!(carry, 1);

        let (diff, borrow) = sbb([0u64, 1], [1u64, 0]);
        assert_eq!(diff, [u64::MAX, 0]);
        assert_eq!(borrow, 0);

        let (diff, borrow) = sbb([0u64, 0], [1u64, 0]);
        assert_eq!(diff, [u64::MAX, u64::MAX]);
        assert_eq!(borrow, 1);
    }

    /// The 32-bit-word arithmetic against the 64-bit, on every modulus this
    /// crate uses. They must agree bit for bit, since both are Montgomery
    /// multiplication with the same `R`; `ic_limb32` then runs every NIST vector
    /// through the narrow one.
    #[test]
    fn narrow_words_agree_with_wide() {
        use crate::nist::point::Curve;
        fn case<const N: usize>(m: [u64; N], seed: u64) -> usize {
            let neg_inv = compute_neg_inv(m[0]);
            // Operands below m from a counter through SplitMix64, plus the
            // edges: 0, 1, m - 1, and all ones where the width allows it.
            let mut state = seed;
            let mut next = || {
                state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
                let mut z = state;
                z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
                z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
                z ^ (z >> 31)
            };
            let mut ops = std::vec::Vec::new();
            let mut one = [0u64; N];
            one[0] = 1;
            ops.push([0u64; N]);
            ops.push(one);
            ops.push(wide::sbb(m, one).0);
            ops.push([u64::MAX; N]);
            for _ in 0..12 {
                let mut x = [0u64; N];
                for limb in x.iter_mut() {
                    *limb = next();
                }
                // Below m, by taking the top limb below m's.
                x[N - 1] %= m[N - 1].max(1);
                ops.push(x);
            }
            let mut checked = 0;
            for a in &ops {
                for b in &ops {
                    assert_eq!(wide::adc(*a, *b), narrow::adc(*a, *b), "adc");
                    assert_eq!(wide::sbb(*a, *b), narrow::sbb(*a, *b), "sbb");
                    assert_eq!(
                        wide::mont_mul(*a, *b, m, neg_inv),
                        narrow::mont_mul(*a, *b, m, neg_inv),
                        "mont_mul"
                    );
                    checked += 1;
                }
            }
            checked
        }
        let checked = case(<crate::p256::P256 as Curve>::Field::MODULUS, 1)
            + case(<crate::p256::P256 as Curve>::Scalar::MODULUS, 2)
            + case(<crate::p384::P384 as Curve>::Field::MODULUS, 3)
            + case(<crate::p384::P384 as Curve>::Scalar::MODULUS, 4)
            + case(<crate::p521::P521 as Curve>::Field::MODULUS, 5)
            + case(<crate::p521::P521 as Curve>::Scalar::MODULUS, 6);
        assert_eq!(checked, 6 * 16 * 16);
    }

    #[test]
    fn select_is_branch_free_and_correct() {
        assert_eq!(select(u64::MAX, [1u64, 2], [3u64, 4]), [1, 2]);
        assert_eq!(select(0, [1u64, 2], [3u64, 4]), [3, 4]);
    }
}
