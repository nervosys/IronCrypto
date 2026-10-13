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
//! exponent: a fixed four-bit window, four squarings and one multiplication
//! per window whatever its value, the multiplier read from a table of sixteen
//! by a masked scan of every entry. [`Modulus::pow_public`] is for the public
//! exponent, which is not secret, and is allowed to branch on it.
//!
//! # Backends
//!
//! The portable Montgomery multiplication is the reference and runs
//! everywhere. On x86-64 with `std`, two others are chosen at run time, by
//! CPU feature and modulus width -- both public -- and [`backend_for`] says
//! which: `MULX`/`ADCX`/`ADOX` assembly for single products (`x86`), and
//! AVX-512 IFMA in radix `2^52` for whole exponentiations at the widths RSA
//! uses (`ifma`). Each module's docs say why it is assembly, what it
//! computes, and why it is constant time; each is tested against the
//! portable path on edge and random operands, and `--cfg ic_limb32` turns both
//! off. Neither changes what is computed: the 64-bit and radix-`2^52`
//! Montgomery domains meet only at the ends of an exponentiation, where a
//! value goes in as an ordinary residue and comes out as one.
//!
//! [`Uint::bits`] and [`Uint::cmp_vartime`] are, as their names say, variable
//! time; they are used only on public values (moduli, byte lengths) and never
//! on key material.

use ic_core::ct::Choice;
use ic_core::Zeroize;

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
        let mut carry = 0u64;
        for i in 0..limbs {
            (self.0[i], carry) = adc(self.0[i], other.0[i], carry);
        }
        carry
    }

    /// `self - other` over `limbs` limbs, returning the borrow.
    pub fn sub_assign(&mut self, other: &Uint, limbs: usize) -> u64 {
        let mut borrow = 0u64;
        for i in 0..limbs {
            (self.0[i], borrow) = sbb(self.0[i], other.0[i], borrow);
        }
        borrow
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
    #[must_use]
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

/// Word arithmetic: the three operations every loop in this crate that touches
/// a secret is built from.
///
/// On a 64-bit CPU they are `u128` sums, as they always were. On 32-bit RISC-V
/// that is not constant time: the CPU has no conditional move, and rustc
/// builds a 128-bit carry from 32-bit comparisons joined by branches -- six in
/// a Montgomery multiplication's inner loop, on the private key. There,
/// [`narrow`] computes the same results from 32-bit halves with `u64` sums
/// that cannot overflow, so each carry is a shift and nothing is compared.
/// `--cfg ic_limb32` selects it anywhere, and the tests compare the two.
#[cfg(not(any(target_arch = "riscv32", ic_limb32)))]
pub(crate) use wide::{adc, mac, sbb};

#[cfg(any(target_arch = "riscv32", ic_limb32))]
pub(crate) use narrow::{adc, mac, sbb};

/// `u128` sums, for CPUs with a 64-bit multiplier.
#[cfg(any(test, not(any(target_arch = "riscv32", ic_limb32))))]
pub(crate) mod wide {
    /// `acc + a * b + carry`, as (low word, high word). Cannot overflow:
    /// `(2^64 - 1)^2 + 2 (2^64 - 1) = 2^128 - 1`.
    #[inline(always)]
    pub(crate) fn mac(acc: u64, a: u64, b: u64, carry: u64) -> (u64, u64) {
        let s = (acc as u128) + (a as u128) * (b as u128) + (carry as u128);
        (s as u64, (s >> 64) as u64)
    }

    /// `a + b + carry`, as (sum, carry out).
    #[inline(always)]
    pub(crate) fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
        let s = (a as u128) + (b as u128) + (carry as u128);
        (s as u64, (s >> 64) as u64)
    }

    /// `a - b - borrow`, as (difference, borrow out).
    #[inline(always)]
    pub(crate) fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
        let d = (a as u128)
            .wrapping_sub(b as u128)
            .wrapping_sub(borrow as u128);
        (d as u64, ((d >> 127) & 1) as u64)
    }
}

/// 32-bit halves and `u64` sums, for 32-bit RISC-V. Every product is `u32 *
/// u32 -> u64`, which is `mul` and `mulhu`; every sum below is under `2^35`,
/// so no `u64` addition here can carry out of its word.
#[cfg(any(test, target_arch = "riscv32", ic_limb32))]
pub(crate) mod narrow {
    const M: u64 = 0xFFFF_FFFF;

    /// `acc + a * b + carry`, as (low word, high word), column by column.
    #[inline(always)]
    pub(crate) fn mac(acc: u64, a: u64, b: u64, carry: u64) -> (u64, u64) {
        let (a0, a1, b0, b1) = (a & M, a >> 32, b & M, b >> 32);
        let (p00, p01, p10, p11) = (a0 * b0, a0 * b1, a1 * b0, a1 * b1);
        let c0 = (p00 & M) + (acc & M) + (carry & M);
        let c1 = (p00 >> 32) + (p01 & M) + (p10 & M) + (acc >> 32) + (carry >> 32) + (c0 >> 32);
        let c2 = (p01 >> 32) + (p10 >> 32) + (p11 & M) + (c1 >> 32);
        let c3 = (p11 >> 32) + (c2 >> 32);
        ((c0 & M) | (c1 << 32), (c2 & M) | (c3 << 32))
    }

    /// `a + b + carry`, as (sum, carry out).
    #[inline(always)]
    pub(crate) fn adc(a: u64, b: u64, carry: u64) -> (u64, u64) {
        let lo = (a & M) + (b & M) + carry;
        let hi = (a >> 32) + (b >> 32) + (lo >> 32);
        ((lo & M) | (hi << 32), hi >> 32)
    }

    /// `a - b - borrow`, as (difference, borrow out).
    #[inline(always)]
    pub(crate) fn sbb(a: u64, b: u64, borrow: u64) -> (u64, u64) {
        let lo = (a & M).wrapping_sub(b & M).wrapping_sub(borrow);
        let hi = (a >> 32).wrapping_sub(b >> 32).wrapping_sub(lo >> 63);
        ((lo & M) | (hi << 32), hi >> 63)
    }
}

// MULX/ADCX/ADOX, where the CPU has them. Only under `std`, because the
// detection needs it, and not under `ic_limb32`, whose point is to put every
// multiplication through the 32-bit word operations above.
#[cfg(all(target_arch = "x86_64", feature = "std", not(ic_limb32)))]
#[allow(unsafe_code)]
mod x86;

// AVX-512 IFMA, for exponentiation. Same conditions as `x86`.
#[cfg(all(target_arch = "x86_64", feature = "std", not(ic_limb32)))]
#[allow(unsafe_code)]
mod ifma;

/// Which implementation of Montgomery arithmetic this process uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Backend {
    /// Word operations in Rust: the reference, and the path on every CPU
    /// without the next two.
    Portable,
    /// x86-64 `MULX`, `ADCX` and `ADOX`, for moduli whose width is a multiple
    /// of 256 bits -- every RSA size this crate accepts, and their primes.
    Adx,
    /// x86-64 AVX-512 IFMA in radix `2^52`, for exponentiation modulo 1024,
    /// 1536 and 2048-bit moduli: the primes of every RSA size this crate
    /// accepts, and an RSA-2048 modulus. Single multiplications
    /// ([`Modulus::mont_mul`]) still use [`Backend::Adx`].
    Ifma,
}

/// The backend [`Modulus::pow`] and [`Modulus::pow_public`] use for a modulus
/// of `limbs` 64-bit words.
///
/// Depends only on the CPU and the width, never on a value.
#[must_use]
pub fn backend_for(limbs: usize) -> Backend {
    #[cfg(all(target_arch = "x86_64", feature = "std", not(ic_limb32)))]
    {
        if !force_portable() && ifma::handles(limbs) {
            return Backend::Ifma;
        }
        if !force_portable() && x86::handles(limbs) {
            return Backend::Adx;
        }
    }
    let _ = limbs;
    Backend::Portable
}

/// A value's words, at full capacity, as the exponentiation passes them.
type Limbs = [u64; MAX_LIMBS];

/// One Montgomery domain's multiplication, as [`pow_windowed`] needs it.
trait Engine {
    /// Words that carry a value; the rest are zero.
    fn width(&self) -> usize;
    /// `a * b`, in the domain.
    fn mul(&mut self, a: &Limbs, b: &Limbs, out: &mut Limbs);
    /// `a * a`, in the domain.
    fn sqr(&mut self, a: &Limbs, out: &mut Limbs);
}

/// The 64-bit Montgomery form of [`Modulus`], on whichever of the portable and
/// ADX multiplications applies.
struct Mont64<'a> {
    m: &'a Modulus,
    scratch: Scratch,
}

impl Engine for Mont64<'_> {
    fn width(&self) -> usize {
        self.m.limbs
    }
    fn mul(&mut self, a: &Limbs, b: &Limbs, out: &mut Limbs) {
        self.m.mul_into(a, b, out, &mut self.scratch);
    }
    fn sqr(&mut self, a: &Limbs, out: &mut Limbs) {
        self.m.sqr_into(a, out, &mut self.scratch);
    }
}

#[cfg(all(target_arch = "x86_64", feature = "std", not(ic_limb32)))]
impl Engine for ifma::Ctx {
    fn width(&self) -> usize {
        self.words()
    }
    fn mul(&mut self, a: &Limbs, b: &Limbs, out: &mut Limbs) {
        self.amm(a, b, out);
    }
    fn sqr(&mut self, a: &Limbs, out: &mut Limbs) {
        self.amm(a, a, out);
    }
}

/// `base^exp` in the engine's domain, constant-time in `exp`, over its low
/// `exp_bits` bits; `one` and `base` are already in the domain.
///
/// A fixed four-bit window: a table of `base^0 .. base^15`, then for each
/// window of the exponent from the top, four squarings and one multiplication
/// by the table entry the window selects. The sequence of operations depends
/// only on `exp_bits`; the window's value reaches only [`select`], which reads
/// every entry and keeps one by masking. A zero window multiplies by one
/// rather than skipping.
fn pow_windowed<E: Engine>(
    e: &mut E,
    one: &Limbs,
    base: &Limbs,
    exp: &Uint,
    exp_bits: usize,
    acc: &mut Limbs,
) {
    let w = e.width();
    let mut table = [[0u64; MAX_LIMBS]; 16];
    table[0] = *one;
    table[1] = *base;
    for k in 2..16 {
        let (done, rest) = table.split_at_mut(k);
        if k % 2 == 0 {
            e.sqr(&done[k / 2], &mut rest[0]);
        } else {
            e.mul(&done[k - 1], base, &mut rest[0]);
        }
    }

    *acc = *one;
    let mut tmp = [0u64; MAX_LIMBS];
    let mut sel = [0u64; MAX_LIMBS];
    // Each product goes into the other buffer and the two swap roles, rather
    // than copying back. Whether the result ends in `acc` or `tmp` depends on
    // the number of windows, which is public.
    let mut x: &mut Limbs = acc;
    let mut y: &mut Limbs = &mut tmp;
    let mut swapped = false;
    let windows = exp_bits.div_ceil(4);
    for i in (0..windows).rev() {
        let mut digit = window(exp, i);
        if i == windows - 1 {
            // The top window may run past exp_bits; those bits are not part of
            // the exponent. Which ones they are is public.
            let used = exp_bits - 4 * i;
            digit &= (1u64 << used) - 1;
            select(&table, w, digit, x);
            continue;
        }
        for _ in 0..4 {
            e.sqr(x, y);
            core::mem::swap(&mut x, &mut y);
        }
        select(&table, w, digit, &mut sel);
        e.mul(x, &sel, y);
        core::mem::swap(&mut x, &mut y);
        swapped = !swapped;
    }
    if swapped {
        // `x` is `tmp` and `y` is `acc`.
        y[..w].copy_from_slice(&x[..w]);
    }

    for entry in table.iter_mut() {
        entry.zeroize();
    }
    tmp.zeroize();
    sel.zeroize();
}

// Tests run the whole RSA stack through the portable path as well, by setting
// this on their own thread.
#[cfg(test)]
std::thread_local! {
    static FORCE_PORTABLE: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

#[cfg(test)]
#[allow(dead_code)] // Unused where there is no other backend to force off.
fn force_portable() -> bool {
    FORCE_PORTABLE.with(|f| f.get())
}

#[cfg(all(not(test), target_arch = "x86_64", feature = "std", not(ic_limb32)))]
#[inline(always)]
fn force_portable() -> bool {
    false
}

/// Run `f` with the portable backend forced on this thread.
#[cfg(test)]
pub(crate) fn with_portable<T>(f: impl FnOnce() -> T) -> T {
    FORCE_PORTABLE.with(|c| c.set(true));
    let out = f();
    FORCE_PORTABLE.with(|c| c.set(false));
    out
}

/// Scratch for one Montgomery product: the accumulator, at the size the
/// widest backend needs.
struct Scratch([u64; 2 * MAX_LIMBS + 2]);

impl Scratch {
    fn new() -> Scratch {
        Scratch([0u64; 2 * MAX_LIMBS + 2])
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// `out = t - n` if `top` is set or `t >= n`, else `t`; `t` below `2n`.
///
/// The one conditional subtraction that ends every Montgomery product, on a
/// mask rather than a branch.
#[inline(always)]
fn finish(out: &mut [u64], t: &[u64], top: u64, n: &[u64]) {
    let mut borrow = 0u64;
    for ((o, &w), &m) in out.iter_mut().zip(t).zip(n) {
        (*o, borrow) = sbb(w, m, borrow);
    }
    // Keep `t` when nothing overflowed and the subtraction borrowed.
    let keep = core::hint::black_box((1 ^ top) & borrow).wrapping_neg();
    for (o, &w) in out.iter_mut().zip(t) {
        *o = (w & keep) | (*o & !keep);
    }
}

/// Portable CIOS product of `a` and `b`, `n.len()` words, into `out`.
///
/// `#[inline(always)]` so that the width dispatch in [`Modulus::mul_into`]
/// gets a copy per common width with the loop bounds constant.
#[inline(always)]
#[allow(clippy::needless_range_loop)]
fn cios(t: &mut [u64], a: &[u64], b: &[u64], n: &[u64], n0inv: u64, out: &mut [u64]) {
    let limbs = n.len();
    let (a, b, out) = (&a[..limbs], &b[..limbs], &mut out[..limbs]);
    let t = &mut t[..limbs + 2];
    t.fill(0);
    for i in 0..limbs {
        // t += a * b[i]
        let mut carry = 0u64;
        for j in 0..limbs {
            (t[j], carry) = mac(t[j], a[j], b[i], carry);
        }
        (t[limbs], t[limbs + 1]) = adc(t[limbs], carry, 0);

        // t = (t + n * (t[0] * n0inv mod 2^64)) / 2^64
        let u = t[0].wrapping_mul(n0inv);
        let (_, mut carry) = mac(t[0], u, n[0], 0);
        for j in 1..limbs {
            (t[j - 1], carry) = mac(t[j], u, n[j], carry);
        }
        let (sum, c) = adc(t[limbs], carry, 0);
        t[limbs - 1] = sum;
        t[limbs] = t[limbs + 1] + c;
        t[limbs + 1] = 0;
    }
    let top = t[limbs];
    finish(out, &t[..limbs], top, n);
}

/// Portable Montgomery square of `a`, `n.len()` words, into `out`.
///
/// The full square first, computing each cross product `a[i] * a[j]` once and
/// doubling the sum, then a separate reduction: `L(L-1)/2 + L` products and
/// `L^2` for the reduction, against `2L^2` for [`cios`].
#[inline(always)]
#[allow(clippy::needless_range_loop)]
fn sqr(t: &mut [u64], a: &[u64], n: &[u64], n0inv: u64, out: &mut [u64]) {
    let limbs = n.len();
    let (a, out) = (&a[..limbs], &mut out[..limbs]);
    let t = &mut t[..2 * limbs];
    t.fill(0);

    // Cross products, i < j.
    for i in 0..limbs {
        let mut carry = 0u64;
        for j in (i + 1)..limbs {
            (t[i + j], carry) = mac(t[i + j], a[i], a[j], carry);
        }
        // Nothing has reached t[i + limbs] yet: row i - 1 stopped below it.
        t[i + limbs] = carry;
    }
    // Double them. The sum of cross products is below 2^(128L - 1), so the bit
    // shifted out of the top is zero.
    let mut top = 0u64;
    for w in t.iter_mut() {
        let next = *w >> 63;
        *w = (*w << 1) | top;
        top = next;
    }
    // Add the squares on the diagonal. a^2 < 2^(128L), so no carry leaves.
    let mut carry = 0u64;
    for i in 0..limbs {
        let (lo, hi) = mac(0, a[i], a[i], 0);
        let c;
        (t[2 * i], c) = adc(t[2 * i], lo, carry);
        (t[2 * i + 1], carry) = adc(t[2 * i + 1], hi, c);
    }

    // Montgomery reduction: zero the low L words one at a time. `top` carries
    // the overflow of the word above each row into the next.
    let mut top = 0u64;
    for i in 0..limbs {
        let u = t[i].wrapping_mul(n0inv);
        let mut carry = 0u64;
        for j in 0..limbs {
            (t[i + j], carry) = mac(t[i + j], u, n[j], carry);
        }
        (t[i + limbs], top) = adc(t[i + limbs], carry, top);
    }
    let (_, hi) = t.split_at(limbs);
    finish(out, hi, top, n);
}

/// Bits `4w..4w + 4` of `exp`, as one window of the exponentiation.
#[inline(always)]
fn window(exp: &Uint, w: usize) -> u64 {
    let bit = 4 * w;
    match exp.0.get(bit / 64) {
        Some(word) => (word >> (bit % 64)) & 0xF,
        None => 0,
    }
}

/// Constant-time read of entry `digit` of a 16-entry table, over the low
/// `limbs` words of each entry.
///
/// Every entry is read and masked; which one survives is arithmetic on
/// `digit`, which is secret, and the addresses are not.
fn select(table: &[Limbs; 16], limbs: usize, digit: u64, out: &mut Limbs) {
    let digit = core::hint::black_box(digit);
    let mut masks = [0u64; 16];
    for (k, mask) in masks.iter_mut().enumerate() {
        let x = (k as u64) ^ digit;
        // All ones when x == 0, zero otherwise.
        *mask = ((x | x.wrapping_neg()) >> 63).wrapping_sub(1);
    }
    // One barrier for all sixteen, so the compiler cannot see that exactly
    // one mask is set and turn the scan into an indexed load.
    let masks = core::hint::black_box(masks);
    let out = &mut out[..limbs];
    out.fill(0);
    for (entry, &mask) in table.iter().zip(&masks) {
        for (o, &e) in out.iter_mut().zip(entry) {
            *o |= e & mask;
        }
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

    /// `x = 2x mod n`, for `x < n`, with a masked subtraction.
    fn double_mod(&self, x: &mut Uint) {
        let l = self.limbs;
        let mut doubled = [0u64; MAX_LIMBS];
        let mut top = 0u64;
        for (d, &w) in doubled.iter_mut().zip(&x.0[..l]) {
            *d = (w << 1) | top;
            top = w >> 63;
        }
        // Subtract n when the doubling overflowed or reached n.
        finish(&mut x.0[..l], &doubled[..l], top, &self.n.0[..l]);
    }

    /// `R^2 mod n`.
    ///
    /// Computed rather than supplied, so there is no constant to mistranscribe.
    /// Doubling `2^(bits - 1)` with a conditional subtraction each time reaches
    /// `R * 2^k mod n` after `64L + k - bits + 1` steps; then `s` Montgomery
    /// squarings, each taking `R * 2^j` to `R * 2^(2j)`, reach `R * 2^(64L)`,
    /// which is `R^2`, when `k * 2^s = 64L`. Taking `2^s` as the largest power
    /// of two dividing `64L` makes `k` the odd part of `L`: a few dozen
    /// doublings and about ten squarings, where doubling all the way from one
    /// took `128L` steps -- most of the cost of parsing a public key.
    fn compute_r2(&self) -> Uint {
        let limbs = self.limbs;
        let bits = self.n.bits();
        let total = 64 * limbs;
        let s = total.trailing_zeros() as usize;
        let k = total >> s;

        let mut x = Uint::ZERO;
        x.0[(bits - 1) / 64] = 1u64 << ((bits - 1) % 64);
        // Only n = 1 equals its top bit; reduce that to zero.
        let mut x = self.reduce_once(&x);
        for _ in 0..(total + k + 1 - bits) {
            self.double_mod(&mut x);
        }
        let mut scratch = Scratch::new();
        let mut y = Uint::ZERO;
        for _ in 0..s {
            self.sqr_into(&x.0[..limbs], &mut y.0[..limbs], &mut scratch);
            x = y;
        }
        x
    }

    /// `a * b / R mod n` into `out`, all `limbs` words.
    ///
    /// The width is public, so dispatching on it is too: the common RSA widths
    /// and their primes each get a copy of the portable loop with constant
    /// bounds, and the x86-64 backend takes any multiple of four words.
    fn mul_into(&self, a: &[u64], b: &[u64], out: &mut [u64], scratch: &mut Scratch) {
        let l = self.limbs;
        let (a, b, n, out) = (&a[..l], &b[..l], &self.n.0[..l], &mut out[..l]);
        let t = &mut scratch.0[..];

        #[cfg(all(target_arch = "x86_64", feature = "std", not(ic_limb32)))]
        if !force_portable() && x86::mont_mul(t, a, b, n, self.n0inv) {
            let (lo, hi) = t.split_at(2 * l);
            finish(out, &lo[l..], hi[0], n);
            return;
        }

        match l {
            16 => cios(t, &a[..16], &b[..16], &n[..16], self.n0inv, &mut out[..16]),
            24 => cios(t, &a[..24], &b[..24], &n[..24], self.n0inv, &mut out[..24]),
            32 => cios(t, &a[..32], &b[..32], &n[..32], self.n0inv, &mut out[..32]),
            _ => cios(t, a, b, n, self.n0inv, out),
        }
    }

    /// `a^2 / R mod n` into `out`, all `limbs` words.
    fn sqr_into(&self, a: &[u64], out: &mut [u64], scratch: &mut Scratch) {
        let l = self.limbs;
        let (a, n, out) = (&a[..l], &self.n.0[..l], &mut out[..l]);
        let t = &mut scratch.0[..];

        #[cfg(all(target_arch = "x86_64", feature = "std", not(ic_limb32)))]
        if !force_portable() && x86::mont_mul(t, a, a, n, self.n0inv) {
            let (lo, hi) = t.split_at(2 * l);
            finish(out, &lo[l..], hi[0], n);
            return;
        }

        match l {
            16 => sqr(t, &a[..16], &n[..16], self.n0inv, &mut out[..16]),
            24 => sqr(t, &a[..24], &n[..24], self.n0inv, &mut out[..24]),
            32 => sqr(t, &a[..32], &n[..32], self.n0inv, &mut out[..32]),
            _ => sqr(t, a, n, self.n0inv, out),
        }
    }

    /// Montgomery multiplication: `a * b / R mod n`, for `a * b < R * n`.
    pub fn mont_mul(&self, a: &Uint, b: &Uint) -> Uint {
        let mut out = Uint::ZERO;
        self.mul_into(&a.0, &b.0, &mut out.0, &mut Scratch::new());
        out
    }

    /// Montgomery squaring: `a^2 / R mod n`, the same value as
    /// `mont_mul(a, a)`, for `a < n`.
    pub fn mont_sqr(&self, a: &Uint) -> Uint {
        let mut out = Uint::ZERO;
        self.sqr_into(&a.0, &mut out.0, &mut Scratch::new());
        out
    }

    /// The portable multiplication, whatever the CPU: the reference the
    /// assembly is tested against.
    #[cfg(test)]
    fn mont_mul_portable(&self, a: &Uint, b: &Uint) -> Uint {
        with_portable(|| self.mont_mul(a, b))
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

    /// `base^exp mod n`, constant-time in `exp`, over the low `exp_bits` bits
    /// of `exp`. `base` may be any value of the modulus's width, below
    /// `2^(64 * limbs)`; it is reduced on the way into Montgomery form.
    ///
    /// A fixed four-bit window ([`pow_windowed`]): four squarings and one
    /// multiplication by a table entry per four bits, the entry read by a
    /// masked scan of the whole table. This is the private-key path: the
    /// exponent is the secret, and the sequence of operations depends only on
    /// `exp_bits`. Against a square and a multiplication on every bit, it is a
    /// quarter of the multiplications.
    ///
    /// Runs on AVX-512 IFMA where [`backend_for`] says so, and on the 64-bit
    /// Montgomery multiplication otherwise.
    pub fn pow(&self, base: &Uint, exp: &Uint, exp_bits: usize) -> Uint {
        #[cfg(all(target_arch = "x86_64", feature = "std", not(ic_limb32)))]
        if !force_portable() {
            if let Some(mut ctx) = ifma::Ctx::new(&self.n, self.limbs, self.n0inv) {
                return self.pow_ifma(&mut ctx, base, |ctx, one, base, acc| {
                    pow_windowed(ctx, one, base, exp, exp_bits, acc);
                });
            }
        }

        let mut engine = Mont64 {
            m: self,
            scratch: Scratch::new(),
        };
        let mut one = self.to_mont(&Uint::one());
        let mut base_mont = self.to_mont(base);
        let mut acc = Uint::ZERO;
        pow_windowed(&mut engine, &one.0, &base_mont.0, exp, exp_bits, &mut acc.0);
        let out = self.from_mont(&acc);
        one.zeroize();
        base_mont.zeroize();
        acc.zeroize();
        out
    }

    /// Run an exponentiation `body` in the IFMA domain, `R' = 2^(52W)`, and
    /// bring the result back to an ordinary residue.
    ///
    /// `body` gets the context, `R' mod n` and `base * R' mod n` (both
    /// almost-reduced, below `2n`), and writes the result in the domain.
    #[cfg(all(target_arch = "x86_64", feature = "std", not(ic_limb32)))]
    fn pow_ifma(
        &self,
        ctx: &mut ifma::Ctx,
        base: &Uint,
        body: impl FnOnce(&mut ifma::Ctx, &Limbs, &Limbs, &mut Limbs),
    ) -> Uint {
        let mut rr52 = self.ifma_rr(ctx);
        let mut base52 = [0u64; MAX_LIMBS];
        let mut unit = [0u64; MAX_LIMBS];
        unit[0] = 1;
        ctx.import(base, &mut base52);

        let mut one = [0u64; MAX_LIMBS];
        let mut base_mont = [0u64; MAX_LIMBS];
        ctx.amm(&rr52, &unit, &mut one);
        ctx.amm(&base52, &rr52, &mut base_mont);

        let mut acc = [0u64; MAX_LIMBS];
        body(ctx, &one, &base_mont, &mut acc);

        // Multiplying by one leaves a value at most n; one masked subtraction
        // takes n itself to zero.
        let mut res52 = [0u64; MAX_LIMBS];
        ctx.amm(&acc, &unit, &mut res52);
        let mut out = Uint::ZERO;
        ctx.export(&res52, &mut out);
        let out = self.reduce_once(&out);

        rr52.zeroize();
        base52.zeroize();
        base_mont.zeroize();
        acc.zeroize();
        res52.zeroize();
        out
    }

    /// `R'^2 mod n` in radix `2^52`, for converting into the IFMA domain.
    ///
    /// `R^2 * 2^(104W - 128L)`: 32, 48 or 64 doublings of the `R^2` this
    /// modulus already has.
    #[cfg(all(target_arch = "x86_64", feature = "std", not(ic_limb32)))]
    fn ifma_rr(&self, ctx: &ifma::Ctx) -> Limbs {
        let mut rr = self.r2;
        for _ in 0..(104 * ctx.words() - 128 * self.limbs) {
            self.double_mod(&mut rr);
        }
        let mut rr52 = [0u64; MAX_LIMBS];
        ctx.import(&rr, &mut rr52);
        rr.zeroize();
        rr52
    }

    /// Reduce a double-width value modulo `n`, without general division.
    ///
    /// The CRT path needs `c mod p` where `c` is as wide as the modulus of the
    /// whole key and `p` is half that. There is no division here, so the
    /// reduction is done by splitting:
    ///
    /// ```text
    /// c = c_hi * 2^(64*limbs) + c_lo  =  c_hi * R + c_lo   (mod p)
    /// ```
    ///
    /// and `c_hi * R mod p` is exactly what a Montgomery multiplication by
    /// `R^2` computes. Both halves start below `2 * p` — `p` has its top two
    /// bits set, so `2^(64*limbs) < 2p` — which one conditional subtraction
    /// fixes.
    ///
    /// `wide` must be less than `n^2`, and `n` must occupy the full `limbs`
    /// words, which is what [`Modulus::is_full_width`] checks.
    pub fn reduce_wide(&self, wide: &Uint) -> Uint {
        let limbs = self.limbs;

        let mut lo = Uint::ZERO;
        lo.0[..limbs].copy_from_slice(&wide.0[..limbs]);
        let mut hi = Uint::ZERO;
        for i in 0..limbs {
            hi.0[i] = wide.0.get(limbs + i).copied().unwrap_or(0);
        }

        let lo = self.reduce_once(&lo);
        let hi = self.reduce_once(&hi);

        // hi * R mod n, then add the low half.
        let mut acc = self.mont_mul(&hi, &self.r2);
        let carry = acc.add_assign(&lo, limbs);
        let mut reduced = acc;
        let borrow = reduced.sub_assign(&self.n, limbs);
        let need = Choice::from_u8((carry | (1 - borrow)) as u8);
        Uint::cmov(&mut acc, &reduced, need, limbs);
        acc
    }

    /// Whether the modulus fills its top limb, which [`Modulus::reduce_wide`]
    /// relies on.
    ///
    /// A prime from [`crate::key::generate`] always does, because the candidate
    /// search forces the top two bits. A prime from somewhere else might not,
    /// and then the CRT path is declined rather than silently given a value it
    /// cannot reduce.
    #[must_use]
    pub fn is_full_width(&self) -> bool {
        self.n.bits() == self.limbs * 64
    }

    /// `a - b mod n`, for `a, b < n`.
    pub fn sub_mod(&self, a: &Uint, b: &Uint) -> Uint {
        let mut out = *a;
        let borrow = out.sub_assign(b, self.limbs);
        // On underflow, add the modulus back. Both branches run; the choice is
        // a conditional move.
        let mut wrapped = out;
        wrapped.add_assign(&self.n, self.limbs);
        Uint::cmov(
            &mut out,
            &wrapped,
            Choice::from_u8(borrow as u8),
            self.limbs,
        );
        out
    }

    /// `a * b mod n`, for `a, b < n`.
    pub fn mul_mod(&self, a: &Uint, b: &Uint) -> Uint {
        // Two Montgomery multiplications: the R factors cancel.
        let a_mont = self.to_mont(a);
        self.mont_mul(&a_mont, b)
    }
}

impl Modulus {
    /// Modular inverse of `a` modulo this odd modulus, by the binary extended
    /// GCD. Variable time.
    ///
    /// Used once per key, to derive `qInv` during generation. Never on a
    /// message. Returns `None` when `a` and the modulus are not coprime.
    pub fn invert_vartime(&self, a: &Uint) -> Option<Uint> {
        let limbs = self.limbs;
        let m = &self.n;

        // The accumulators need one word more than the modulus. Halving a value
        // modulo an odd `m` goes through `x + m`, and when `m` fills its top
        // limb — which every prime from `generate` does — that sum carries out
        // of the modulus width. The extra word returns to zero after the shift,
        // since `(x + m) / 2 < m`.
        let wide = limbs + 1;
        if wide > MAX_LIMBS {
            return None;
        }

        // Halving modulo an odd modulus: if x is odd, adding m makes it even
        // without changing its residue.
        fn half_mod(x: &mut Uint, m: &Uint, limbs: usize) {
            if x.is_odd() {
                x.add_assign(m, limbs);
            }
            x.shr1(limbs);
        }
        fn sub_mod_vartime(x: &mut Uint, y: &Uint, m: &Uint, limbs: usize) {
            if x.sub_assign(y, limbs) == 1 {
                x.add_assign(m, limbs);
            }
        }

        let mut u = self.reduce_once(a);
        let mut v = *m;
        let mut x1 = Uint::one();
        let mut x2 = Uint::ZERO;
        let one = Uint::one();

        // Bounded so a non-coprime input terminates rather than spinning.
        for _ in 0..(limbs * 64 * 4) {
            if u.cmp_vartime(&one) == core::cmp::Ordering::Equal {
                return Some(x1);
            }
            if v.cmp_vartime(&one) == core::cmp::Ordering::Equal {
                return Some(x2);
            }
            if u.cmp_vartime(&Uint::ZERO) == core::cmp::Ordering::Equal {
                return None;
            }

            while !u.is_odd() {
                u.shr1(limbs);
                half_mod(&mut x1, m, wide);
            }
            while !v.is_odd() {
                v.shr1(limbs);
                half_mod(&mut x2, m, wide);
            }

            if u.cmp_vartime(&v) != core::cmp::Ordering::Less {
                u.sub_assign(&v, limbs);
                sub_mod_vartime(&mut x1, &x2, m, wide);
            } else {
                v.sub_assign(&u, limbs);
                sub_mod_vartime(&mut x2, &x1, m, wide);
            }
        }
        None
    }

    /// `base^e mod n` for a small public exponent.
    ///
    /// The public exponent is not secret, so this may branch on it.
    pub fn pow_public(&self, base: &Uint, e: u64) -> Uint {
        if e == 0 {
            return self.from_mont(&self.to_mont(&Uint::one()));
        }

        #[cfg(all(target_arch = "x86_64", feature = "std", not(ic_limb32)))]
        if !force_portable() {
            if let Some(mut ctx) = ifma::Ctx::new(&self.n, self.limbs, self.n0inv) {
                return self.pow_ifma(&mut ctx, base, |ctx, _, base, acc| {
                    pow_public_in(ctx, base, e, acc);
                });
            }
        }

        let mut engine = Mont64 {
            m: self,
            scratch: Scratch::new(),
        };
        let base_mont = self.to_mont(base);
        let mut acc = Uint::ZERO;
        pow_public_in(&mut engine, &base_mont.0, e, &mut acc.0);
        self.from_mont(&acc)
    }
}

/// `base^e` in the engine's domain, for a non-zero public `e`: left to right,
/// branching on its bits.
fn pow_public_in<E: Engine>(engine: &mut E, base: &Limbs, e: u64, acc: &mut Limbs) {
    let w = engine.width();
    // The top bit is set, so start from the base rather than squaring one.
    *acc = *base;
    let mut tmp = [0u64; MAX_LIMBS];
    let bits = 64 - e.leading_zeros() as usize;
    for i in (0..bits.saturating_sub(1)).rev() {
        engine.sqr(acc, &mut tmp);
        if (e >> i) & 1 == 1 {
            engine.mul(&tmp, base, acc);
        } else {
            acc[..w].copy_from_slice(&tmp[..w]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 32-bit-half word operations against the `u128` ones, on edges and
    /// on a counter's worth of mixed values. `--cfg ic_limb32` then runs every
    /// RSA test through the narrow ones.
    #[test]
    fn narrow_words_agree_with_wide() {
        let mut vals = std::vec![
            0u64,
            1,
            2,
            0xFFFF_FFFF,
            0x1_0000_0000,
            u64::MAX,
            u64::MAX - 1
        ];
        let mut x = 0x0123_4567_89AB_CDEFu64;
        for _ in 0..24 {
            x = x.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17) ^ 0xD1B5_4A32_D192_ED03;
            vals.push(x);
        }
        let mut checked = 0;
        for &a in &vals {
            for &b in &vals {
                for c in [0u64, 1] {
                    assert_eq!(wide::adc(a, b, c), narrow::adc(a, b, c), "adc");
                    assert_eq!(wide::sbb(a, b, c), narrow::sbb(a, b, c), "sbb");
                }
                for &acc in &[0u64, u64::MAX, a ^ b] {
                    for &carry in &[0u64, u64::MAX, b] {
                        assert_eq!(
                            wide::mac(acc, a, b, carry),
                            narrow::mac(acc, a, b, carry),
                            "mac"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 31 * 31 * 9);
    }

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

    /// `reduce_wide` has to agree with an ordinary remainder. Checked against
    /// u128 arithmetic on moduli small enough for the reference to be obvious.
    #[test]
    fn wide_reduction_matches_the_reference() {
        for &m in &[
            0x8000_0000_0000_0001u128,
            0xffff_ffff_ffff_fffbu128,
            0xc000_0000_0000_0007u128,
        ] {
            let modulus = Modulus::new(uint(m)).unwrap();
            assert!(modulus.is_full_width(), "the top bit is set");
            for &c in &[
                0u128,
                1,
                m - 1,
                m,
                m + 1,
                m * 2,
                0xffff_ffff_ffff_ffff_ffff_ffff_ffff_fffeu128,
                (m - 1) * (m - 1) % u128::MAX,
            ] {
                let got = modulus.reduce_wide(&uint(c));
                assert_eq!(to_u128(&got), c % m, "{c} mod {m}");
            }
        }
    }

    /// A modulus whose top limb is not full cannot use the split reduction, and
    /// says so rather than returning a wrong answer.
    #[test]
    fn a_short_modulus_declines_wide_reduction() {
        let m = Modulus::new(uint(0x0000_0000_ffff_fffbu128)).unwrap();
        assert!(!m.is_full_width());
        let full = Modulus::new(uint(0xffff_ffff_ffff_fffbu128)).unwrap();
        assert!(full.is_full_width());
    }

    #[test]
    fn modular_subtraction_and_multiplication_match_the_reference() {
        let m = 0xffff_ffff_ffff_fffbu128;
        let modulus = Modulus::new(uint(m)).unwrap();
        for a in [0u128, 1, 2, 999, m / 2, m - 1] {
            for b in [0u128, 1, 3, 65537, m / 2, m - 1] {
                assert_eq!(
                    to_u128(&modulus.sub_mod(&uint(a), &uint(b))),
                    (a + m - b) % m,
                    "{a} - {b} mod {m}"
                );
                assert_eq!(
                    to_u128(&modulus.mul_mod(&uint(a), &uint(b))),
                    a * b % m,
                    "{a} * {b} mod {m}"
                );
            }
        }
    }

    #[test]
    fn modular_inversion_round_trips() {
        for &m in &[
            65537u128,
            0xffff_ffff_ffff_fffbu128,
            0x7fff_ffff_ffff_ffffu128,
        ] {
            let modulus = Modulus::new(uint(m)).unwrap();
            for a in [1u128, 2, 3, 65536, m - 1] {
                let inv = modulus.invert_vartime(&uint(a)).expect("coprime");
                assert_eq!(
                    to_u128(&modulus.mul_mod(&uint(a), &inv)),
                    1,
                    "{a} * {a}^-1 mod {m}"
                );
            }
        }

        // Not coprime: 2 has no inverse modulo an even number, and 0 has none
        // modulo anything.
        let m = Modulus::new(uint(15)).unwrap();
        assert!(m.invert_vartime(&uint(3)).is_none(), "gcd(3, 15) = 3");
        assert!(m.invert_vartime(&Uint::ZERO).is_none());
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

    /// SplitMix64: deterministic test values, so a failure reproduces.
    struct Gen(u64);

    impl Gen {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        /// A random value below `n`, which fills `limbs` words.
        fn below(&mut self, n: &Uint, limbs: usize) -> Uint {
            let mut x = Uint::ZERO;
            for w in x.0[..limbs].iter_mut() {
                *w = self.next();
            }
            // Below n's top word, so below n.
            x.0[limbs - 1] %= n.0[limbs - 1];
            x
        }
    }

    /// Odd moduli of `limbs` words in the shapes that stress carries: random
    /// with the top bit set (every RSA modulus and prime), all ones, a lone
    /// top bit plus one, and a top word of one (far from full width).
    fn moduli(g: &mut Gen, limbs: usize) -> std::vec::Vec<Uint> {
        let mut out = std::vec::Vec::new();
        for _ in 0..3 {
            let mut n = Uint::ZERO;
            for w in n.0[..limbs].iter_mut() {
                *w = g.next();
            }
            n.0[0] |= 1;
            n.0[limbs - 1] |= 1 << 63;
            out.push(n);
        }
        let mut ones = Uint::ZERO;
        ones.0[..limbs].fill(u64::MAX);
        out.push(ones);
        let mut lone = Uint::ZERO;
        lone.0[0] = 1;
        lone.0[limbs - 1] |= 1 << 63;
        out.push(lone);
        let mut short = Uint::ZERO;
        for w in short.0[..limbs].iter_mut() {
            *w = g.next();
        }
        short.0[0] |= 1;
        short.0[limbs - 1] = 1;
        out.push(short);
        out
    }

    /// Operands for a modulus: the edges, then random values.
    fn operands(g: &mut Gen, n: &Uint, limbs: usize) -> std::vec::Vec<Uint> {
        let mut v = std::vec![Uint::ZERO];
        for k in 1..=2u64 {
            let mut minus = *n;
            minus.sub_assign(&Uint::from_u64(k), limbs);
            for x in [Uint::from_u64(k), minus] {
                if x.cmp_vartime(n) == core::cmp::Ordering::Less {
                    v.push(x);
                }
            }
        }
        for _ in 0..12 {
            v.push(g.below(n, limbs));
        }
        v
    }

    /// The backend in use is the one this CPU should get, and forcing the
    /// portable path really does force it. Without this, every differential
    /// test below could be comparing the portable path with itself.
    #[test]
    fn the_fast_backends_are_selected_where_the_cpu_has_them() {
        #[cfg(all(target_arch = "x86_64", not(ic_limb32)))]
        {
            let adx = std::is_x86_feature_detected!("bmi2") && std::is_x86_feature_detected!("adx");
            let ifma = std::is_x86_feature_detected!("avx512f")
                && std::is_x86_feature_detected!("avx512ifma")
                && std::is_x86_feature_detected!("bmi2");
            std::eprintln!("this CPU: adx {adx}, ifma {ifma}");
            for limbs in [16, 24, 32] {
                let want = match (ifma, adx) {
                    (true, _) => Backend::Ifma,
                    (false, true) => Backend::Adx,
                    _ => Backend::Portable,
                };
                assert_eq!(backend_for(limbs), want, "{limbs} limbs");
            }
            for limbs in [4, 8, 48, 64] {
                let want = if adx { Backend::Adx } else { Backend::Portable };
                assert_eq!(backend_for(limbs), want, "{limbs} limbs");
            }
        }
        for limbs in [1, 2, 3, 5, 17, 31] {
            assert_eq!(backend_for(limbs), Backend::Portable, "{limbs} limbs");
        }
        with_portable(|| {
            for limbs in [4, 16, 24, 32, 64] {
                assert_eq!(backend_for(limbs), Backend::Portable, "{limbs} limbs");
            }
        });
    }

    /// The default multiplication and squaring -- ADX where the CPU has it --
    /// against the portable ones, at every width a multiple of four words up
    /// to the maximum, on edge and random operands.
    #[test]
    fn the_multiplication_backends_agree() {
        let mut g = Gen(1);
        for limbs in [4usize, 8, 12, 16, 20, 24, 32, 40, 48, 56, 64] {
            for n in moduli(&mut g, limbs) {
                let m = Modulus::new(n).unwrap();
                assert_eq!(m.limbs(), limbs);
                let ops = operands(&mut g, &n, limbs);
                for a in &ops {
                    let want = with_portable(|| m.mont_sqr(a));
                    assert_eq!(m.mont_sqr(a), want, "{limbs} limbs: sqr");
                    assert_eq!(m.mont_mul(a, a), want, "{limbs} limbs: sqr as mul");
                    for b in ops.iter().step_by(3) {
                        let want = m.mont_mul_portable(a, b);
                        assert_eq!(m.mont_mul(a, b), want, "{limbs} limbs: mul");
                    }
                }
            }
        }
    }

    /// The portable squaring against the portable multiplication, at widths
    /// with and without a fixed-width copy.
    #[test]
    fn portable_squaring_matches_multiplication() {
        let mut g = Gen(2);
        for limbs in [1usize, 2, 3, 5, 16, 24, 32, 33, 64] {
            for n in moduli(&mut g, limbs) {
                let m = Modulus::new(n).unwrap();
                for a in operands(&mut g, &n, limbs) {
                    with_portable(|| assert_eq!(m.mont_sqr(&a), m.mont_mul(&a, &a), "{limbs}"));
                }
            }
        }
    }

    /// Exponentiation on the default backend -- IFMA where the CPU has it --
    /// against the portable one, at the widths IFMA takes and either side of
    /// them, for exponent lengths that do and do not fill their top window.
    #[test]
    fn the_exponentiation_backends_agree() {
        let mut g = Gen(3);
        for limbs in [8usize, 16, 24, 32] {
            for n in moduli(&mut g, limbs).into_iter().take(4) {
                let m = Modulus::new(n).unwrap();
                let mut bases = operands(&mut g, &n, limbs);
                // A base of the full width, not below n: `pow` takes those, and
                // must give what it gives for the base reduced.
                let mut wide = Uint::ZERO;
                wide.0[..limbs].fill(u64::MAX);
                let reduced = with_portable(|| m.from_mont(&m.to_mont(&wide)));
                let e = g.below(&n, limbs);
                let want = with_portable(|| m.pow(&reduced, &e, 64 * limbs));
                assert_eq!(
                    m.pow(&wide, &e, 64 * limbs),
                    want,
                    "{limbs} limbs, wide base"
                );
                assert_eq!(with_portable(|| m.pow(&wide, &e, 64 * limbs)), want);
                bases.insert(1, wide);
                for (i, base) in bases.iter().enumerate().take(8) {
                    for bits in [1usize, 3, 4, 5, 64, 64 * limbs - 1, 64 * limbs] {
                        let mut exp = g.below(&n, limbs);
                        if i == 1 {
                            // All ones: every window selects the last entry.
                            exp.0[..limbs].fill(u64::MAX);
                        }
                        let want = with_portable(|| m.pow(base, &exp, bits));
                        assert_eq!(m.pow(base, &exp, bits), want, "{limbs} limbs, {bits} bits");
                    }
                    for e in [1u64, 2, 3, 17, 65537, u64::MAX] {
                        let want = with_portable(|| m.pow_public(base, e));
                        assert_eq!(m.pow_public(base, e), want, "{limbs} limbs, e = {e}");
                    }
                }
            }
        }
    }

    /// One IFMA product, checked on its own rather than through an
    /// exponentiation: two of them, by the operands and then by `R'^2`, give
    /// `a * b mod n`; and every output is normalised and below `2^(B+1)`.
    #[test]
    #[cfg(all(target_arch = "x86_64", not(ic_limb32)))]
    fn one_ifma_product_is_right() {
        let mut g = Gen(4);
        for limbs in [16usize, 24, 32] {
            for n in moduli(&mut g, limbs) {
                let m = Modulus::new(n).unwrap();
                let Some(mut ctx) = ifma::Ctx::new(&n, limbs, m.n0inv) else {
                    return; // No IFMA on this CPU; the selection test covers it.
                };
                let rr = m.ifma_rr(&ctx);
                let w = ctx.words();
                let ops = operands(&mut g, &n, limbs);
                for a in &ops {
                    for b in ops.iter().step_by(2) {
                        let (mut a52, mut b52) = ([0u64; MAX_LIMBS], [0u64; MAX_LIMBS]);
                        ctx.import(a, &mut a52);
                        ctx.import(b, &mut b52);
                        let (mut t, mut r) = ([0u64; MAX_LIMBS], [0u64; MAX_LIMBS]);
                        ctx.amm(&a52, &b52, &mut t);
                        assert!(t.iter().all(|&l| l < 1 << 52), "normalised");
                        assert!(t[w..].iter().all(|&l| l == 0), "zero above W");
                        let mut wide = Uint::ZERO;
                        ctx.export(&t, &mut wide);
                        assert!(wide.bits() <= n.bits() + 1, "below 2^(B+1)");
                        ctx.amm(&t, &rr, &mut r);
                        let mut got = Uint::ZERO;
                        ctx.export(&r, &mut got);
                        let got = m.reduce_once(&got);
                        let want = with_portable(|| m.mul_mod(a, b));
                        assert_eq!(got, want, "{limbs} limbs");
                    }
                }
            }
        }
    }

    /// Per-operation cost of each backend's multiplication and squaring, at
    /// the widths RSA uses.
    #[test]
    #[ignore = "timing; run manually with --release"]
    fn report_montgomery_timings() {
        for limbs in [16usize, 32] {
            let mut n = Uint::ZERO;
            let mut x = 0x0123_4567_89AB_CDEFu64;
            for w in n.0[..limbs].iter_mut() {
                x = x.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17) ^ 0xD1B5_4A32_D192_ED03;
                *w = x;
            }
            n.0[0] |= 1;
            n.0[limbs - 1] |= 1 << 63;
            let m = Modulus::new(n).unwrap();
            let mut a = m.reduce_once(&Uint::from_u64(12345));
            a.0[3] = 77;
            let mut e = n;
            e.0[0] ^= 6;
            for (label, portable) in [("default", false), ("portable", true)] {
                let run = |reps: u32, f: &dyn Fn()| {
                    let mut best = f64::MAX;
                    for _ in 0..5 {
                        let t = std::time::Instant::now();
                        for _ in 0..reps {
                            f();
                        }
                        best = best.min(t.elapsed().as_nanos() as f64 / reps as f64);
                    }
                    best
                };
                let go = || {
                    let mul = run(200_000, &|| {
                        std::hint::black_box(m.mont_mul(std::hint::black_box(&a), &a));
                    });
                    let sq = run(200_000, &|| {
                        std::hint::black_box(m.mont_sqr(std::hint::black_box(&a)));
                    });
                    let pow = run(200, &|| {
                        std::hint::black_box(m.pow(std::hint::black_box(&a), &e, limbs * 64));
                    });
                    let public = run(20_000, &|| {
                        std::hint::black_box(m.pow_public(std::hint::black_box(&a), 65537));
                    });
                    (mul, sq, pow, public)
                };
                #[cfg(all(target_arch = "x86_64", feature = "std", not(ic_limb32)))]
                if !portable {
                    if let Some(ctx) = ifma::Ctx::new(&m.n, m.limbs, m.n0inv) {
                        let ctx = core::cell::RefCell::new(ctx);
                        let mut x = [0u64; MAX_LIMBS];
                        ctx.borrow().import(&a, &mut x);
                        let amm = run(200_000, &|| {
                            let mut o = [0u64; MAX_LIMBS];
                            ctx.borrow_mut().amm(std::hint::black_box(&x), &x, &mut o);
                            std::hint::black_box(&o);
                        });
                        // Each product feeding the next, as in an
                        // exponentiation: latency rather than throughput.
                        let chained = run(1_000, &|| {
                            let mut c = ctx.borrow_mut();
                            let mut p = x;
                            let mut q = [0u64; MAX_LIMBS];
                            for _ in 0..100 {
                                c.amm(&p, &p, &mut q);
                                c.amm(&q, &q, &mut p);
                            }
                            std::hint::black_box(&p);
                        }) / 200.0;
                        let fixed = run(2_000, &|| {
                            std::hint::black_box(m.pow(std::hint::black_box(&a), &e, 4));
                        });
                        std::println!(
                            "{limbs} limbs ifma: chained amm {chained:.1} ns, \
                             pow with one window {:.2} us",
                            fixed / 1000.0
                        );
                        let dbl = run(200_000, &|| {
                            let mut r = std::hint::black_box(m.r2);
                            m.double_mod(&mut r);
                            std::hint::black_box(&r);
                        });
                        std::println!("{limbs} limbs ifma: amm {amm:.1} ns, double {dbl:.1} ns");
                    }
                }
                let (mul, sq, pow, public) = if portable { with_portable(go) } else { go() };
                std::println!(
                    "{limbs} limbs {label}: mul {mul:.1} ns, sqr {sq:.1} ns, \
                     pow {:.1} us, pow 65537 {:.2} us",
                    pow / 1000.0,
                    public / 1000.0
                );
            }
        }
    }
}
