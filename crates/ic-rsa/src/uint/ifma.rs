//! Montgomery multiplication on AVX-512 IFMA, in radix `2^52`.
//!
//! # Why this exists
//!
//! On x86-64 the scalar multiply-accumulate is bounded by the integer ports:
//! [`super::x86`] runs at about 1.4 cycles a word-product on Zen 5, however the
//! carry chains are arranged, which leaves RSA-2048 signing at parity with the
//! fastest assembly around and no further. `VPMADD52LUQ` and `VPMADD52HUQ`
//! multiply eight pairs of 52-bit lanes and add the low or high 52 bits of each
//! product into 64-bit accumulators, two instructions a cycle. Twelve spare
//! bits in each lane mean a column can absorb hundreds of products before
//! anything has to carry, so the vector work has no carry chain at all.
//!
//! # The algorithm
//!
//! Almost-Montgomery multiplication, word-serial over `b`, with `W` limbs of 52
//! bits and `R' = 2^(52W)`, where `52W` exceeds the modulus width by 16 bits or
//! more:
//!
//! ```text
//! for i in 0..W:
//!     acc += a * b[i]                       (low halves at lane j, high at j+1)
//!     u    = acc[0] * k0 mod 2^52           (k0 = -m^-1 mod 2^52)
//!     acc += m * u                          (acc[0] becomes 0 mod 2^52)
//!     acc  = acc / 2^52                     (drop lane 0, carry into lane 1)
//! ```
//!
//! Lanes are never normalised inside the loop: every lane stays below `2^61`.
//! The accumulator is split across register sets -- low and high halves, and
//! for the 1024-bit kernel also `a * b[i]` and `m * u` -- because each set is a
//! dependency chain of its multiply-adds plus a lane shift, and a multiply-add
//! takes four cycles and the shift five.
//!
//! The serial dependency is `u`, which needs lane 0 exactly, carries and all.
//! Reading it back from the vector unit each row would put a broadcast, two
//! multiply-adds, a shift and an extraction on that path. Instead the scalar
//! registers track the next two columns: column `i + 1` is what the vector
//! held for it before row `i`, plus the four products of row `i` that land
//! there, plus the carry out of column `i`, which is `(x0 + 2^52 - 1) >> 52`
//! because `x0 + (m0 u mod 2^52)` is a multiple of `2^52`; column `i + 2`
//! likewise, without the carry. Only the vector's part of column `i + 2` is
//! read back, a row and a half before it is needed. The products use `a[j]`
//! and `m[j]` shifted left by twelve, so one `MULX` gives the high 52 bits in
//! its high word and the low 52 bits, shifted, in its low word. About eleven
//! cycles a row remain on the critical path.
//!
//! Inputs below `2^(B+1)`, for a `B`-bit modulus, give an output below
//! `2^(B+1)`, because `R'` is at least `2^(B+16)`; so outputs chain into
//! inputs without the conditional subtraction the 64-bit form needs, and
//! nothing here compares or branches on a value. The exponentiation converts
//! out at the end with one more multiplication by one, which lands at or below
//! `m`, and one masked subtraction.
//!
//! # Constant time
//!
//! The width is matched once, in [`pow`] and [`pow_public`], and each arm is
//! a copy of the whole exponentiation compiled for that width
//! ([`pow_fixed`]), so inside it every bound, offset and kernel choice is a
//! constant. What branches there are the loops: the kernel's rows, the table,
//! the windows, the conversions. `scripts/check-ct.py` reads the compiled
//! exponentiation at 1024 and 2048 bits (`ct_rsa_ifma_pow_1024`,
//! `ct_rsa_ifma_pow_2048`) and accepts no branch but a loop's own counter.
//! That took more than the arithmetic: no value is copied or zeroed by a call,
//! and nothing the compiler would hold in a register across the kernel, which
//! takes twelve, is left for it to hold, so that the loop counters keep
//! theirs rather than going to the stack. The comments where that was done
//! say why.
//!
//! Every address is a base pointer plus a constant, the row pointer into `b`,
//! which advances one word per row whatever the values, or a public loop
//! index. IFMA, `MULX`, `IMUL` and the lane moves have data-independent
//! latency.
//!
//! # Safety
//!
//! [`Ctx::product`] is the only way into the assembly. It takes fixed-size
//! arrays, of a width with a kernel or the code does not compile, and a
//! context that [`Ctx::init`], which is `unsafe`, prepared on a CPU with the
//! instructions. The comment on the assembly says which words each address
//! reaches.

use core::arch::asm;
use core::mem::MaybeUninit;

use super::{finish, Modulus, Uint, MAX_LIMBS};
use ic_core::Zeroize;

/// The low 52 bits.
const MASK: u64 = (1 << 52) - 1;

/// The widest vector this module handles, in words: five registers of eight.
const MAX_WORDS: usize = 40;

/// Where the kernel writes its output columns in the context buffer: past the
/// widest modulus and the four words after it, `k0` and `a[0..3]`, each
/// shifted left by twelve.
const LANES: usize = MAX_WORDS + 4;

/// Where the context buffer holds `MASK`, past the output columns, for the
/// kernel to add from memory: one fewer register for it to hold, which leaves
/// the exponentiation's loop counters room to stay in registers.
const MASK_AT: usize = LANES + MAX_WORDS;

/// Words in the context buffer.
const CTX_WORDS: usize = MASK_AT + 1;

/// Whether this CPU has AVX-512F, IFMA and BMI2, asked once.
pub(crate) fn available() -> bool {
    if super::adx_forced() {
        return false;
    }
    #[cfg(feature = "std")]
    {
        use core::sync::atomic::{AtomicU8, Ordering};
        // 0 not yet asked, 1 yes, 2 no.
        static CACHED: AtomicU8 = AtomicU8::new(0);
        match CACHED.load(Ordering::Relaxed) {
            1 => true,
            2 => false,
            _ => {
                // `--cfg ic_no_avx512` reports this false, for measuring the AVX2 paths.
                let have = !cfg!(ic_no_avx512)
                    && std::is_x86_feature_detected!("avx512f")
                    && std::is_x86_feature_detected!("avx512ifma")
                    && std::is_x86_feature_detected!("bmi2");
                CACHED.store(u8::from(!have) + 1, Ordering::Relaxed);
                have
            }
        }
    }
    // Without `std` there is no detection; this module is compiled only for
    // `scripts/ct-audit` to read, and nothing selects it.
    #[cfg(not(feature = "std"))]
    false
}

/// 52-bit limbs `W` for a vector of `n = 8K` words, where there is a kernel
/// for it: 1024, 1536 and 2048-bit moduli, `L = n - 8` 64-bit words each --
/// the primes of RSA-2048, -3072 and -4096, and the modulus of RSA-2048. Each
/// has at least 16 bits of headroom in `52W`. Any other `n` is a compile-time
/// error where it is used.
const fn words_for(n: usize) -> usize {
    match n {
        24 => 20,
        32 => 30,
        40 => 40,
        _ => panic!("no IFMA kernel for this width"),
    }
}

/// Whether [`pow`] and [`pow_public`] will take a modulus of `limbs` words on
/// this CPU.
pub(crate) fn handles(limbs: usize) -> bool {
    matches!(limbs, 16 | 24 | 32) && available()
}

/// `base^exp mod m` over the low `exp_bits` bits of `exp`, as
/// [`Modulus::pow`] defines it; `None` where [`handles`] says no.
///
/// The width is matched here, once, and each arm is a copy of the whole
/// exponentiation compiled for that width: every loop bound, offset and
/// kernel inside it is a constant.
pub(crate) fn pow(m: &Modulus, base: &Uint, exp: &Uint, exp_bits: usize) -> Option<Uint> {
    if !handles(m.limbs) {
        return None;
    }
    let mut out = Uint::ZERO;
    // SAFETY: `handles` asked the CPU for AVX-512F, IFMA and BMI2, and
    // matched the width each arm is compiled for.
    unsafe {
        match m.limbs {
            16 => pow_fixed::<24>(m, base, exp, exp_bits, prefix(&mut out)),
            24 => pow_fixed::<32>(m, base, exp, exp_bits, prefix(&mut out)),
            _ => pow_fixed::<40>(m, base, exp, exp_bits, prefix(&mut out)),
        }
    }
    Some(out)
}

/// `base^e mod m` for a non-zero public `e`, as [`Modulus::pow_public`]
/// defines it; `None` where [`handles`] says no.
pub(crate) fn pow_public(m: &Modulus, base: &Uint, e: u64) -> Option<Uint> {
    if !handles(m.limbs) {
        return None;
    }
    let mut out = Uint::ZERO;
    // SAFETY: as in `pow`.
    unsafe {
        match m.limbs {
            16 => pow_public_fixed::<24>(m, base, e, prefix(&mut out)),
            24 => pow_public_fixed::<32>(m, base, e, prefix(&mut out)),
            _ => pow_public_fixed::<40>(m, base, e, prefix(&mut out)),
        }
    }
    Some(out)
}

/// The first `N` words of `x`.
fn prefix<const N: usize>(x: &mut Uint) -> &mut [u64; N] {
    const { assert!(N <= MAX_LIMBS) };
    match x.0.first_chunk_mut::<N>() {
        Some(p) => p,
        None => unreachable!(),
    }
}

/// Everything one exponentiation holds besides the context, in one place so
/// that it is zeroed once on the way in and wiped once on the way out. In
/// this order, so that `exp` is not at its start.
#[repr(C)]
struct Work<const N: usize> {
    /// `base^0 .. base^15` in the domain.
    table: [[u64; N]; 16],
    acc: [u64; N],
    sel: [u64; N],
    /// One, as a value: the multiplier that converts out of the domain.
    unit: [u64; N],
    /// `R^2` in radix `2^52`, then the result in 64-bit words.
    wide: [u64; N],
    /// `R'^2` in radix `2^52`.
    spare: [u64; N],
    /// The exponent's low `exp_bits` bits, and zero above.
    exp: [u64; MAX_LIMBS],
}

impl<const N: usize> Work<N> {
    /// Every word to zero, through volatile stores, as one run of words:
    /// field by field, the compiler unrolled each wipe, which was most of the
    /// exponentiation's code.
    #[inline(always)]
    fn wipe(&mut self) {
        let words = core::mem::size_of::<Self>() / 8;
        // SAFETY: `Work` is `repr(C)` and made of `u64` arrays only, so it is
        // `words` initialised `u64`s with no padding, and `self` is borrowed
        // uniquely for the slice's life.
        let all =
            unsafe { core::slice::from_raw_parts_mut((self as *mut Self).cast::<u64>(), words) };
        all.zeroize();
    }
}

/// `base^exp mod m`, the fixed four-bit window of [`super::pow_windowed`] in
/// the IFMA domain at one width, into `out`: the first `L = N - 8` words, and
/// zero above. `m` must be `L` words wide.
///
/// Constant-time in `exp`. The sequence of products depends only on
/// `exp_bits`, and each window's value reaches only [`select`]. Every loop
/// runs a constant number of times except the window loop, which runs
/// `max(1, ceil(exp_bits / 4))` times, entered unconditionally and counted
/// down to zero; nothing else here branches. Nothing is copied or zeroed by
/// a call either, but the work area once: every value is computed where it
/// is kept.
///
/// The top window is handled like the others rather than by a branch on the
/// window index, so the first four squarings square one: four products in the
/// thirteen hundred of a 1024-bit exponent. The values in the domain may be
/// different almost-reduced representatives from the ones a separate first
/// window would give; the conversion out reduces fully, so the result is the
/// same residue.
///
/// # Safety
///
/// The CPU must have AVX-512F, IFMA and BMI2.
pub(crate) unsafe fn pow_fixed<const N: usize>(
    m: &Modulus,
    base: &Uint,
    exp: &Uint,
    exp_bits: usize,
    out: &mut [u64; N],
) {
    let mut ctx = Ctx::<N> {
        k: [const { MaybeUninit::uninit() }; CTX_WORDS],
    };
    // SAFETY: as the caller guarantees.
    unsafe { ctx.init(m) };
    let mut w = Work::<N> {
        table: [[0u64; N]; 16],
        acc: [0u64; N],
        sel: [0u64; N],
        unit: [0u64; N],
        wide: [0u64; N],
        spare: [0u64; N],
        exp: [0u64; MAX_LIMBS],
    };
    // All of it zeroed here, in one `memset` of a constant length on the
    // stack. The barrier keeps the compiler from trimming the stores that
    // follow out of it, which split it into several calls through a register;
    // it names a field other than the first so that the call's destination is
    // not a register kept for after it.
    core::hint::black_box(&mut w.exp);
    w.unit[0] = 1;

    // Into the domain: one, in the table and in the accumulator, and the
    // base. Each is made where it is kept, rather than copied there, which
    // would be a call to `memcpy`.
    ctx.rr(m, &mut w.spare, &mut w.wide);
    for x in [&mut w.table[0], &mut w.acc] {
        x[0] = 1;
        ctx.mul_assign(x, &w.spare);
    }
    to_radix52::<MAX_LIMBS, N>(&base.0, &mut w.table[1]);
    ctx.mul_assign(&mut w.table[1], &w.spare);

    // Entry 2k is entry k squared, and 2k + 1 is that times the base. Written
    // out rather than a loop: the products here are calls, and the gate
    // excuses no loop with a call in it.
    let mut entries = |k: usize| {
        let (lo, hi) = w.table.split_at_mut(2 * k);
        let (even, odd) = hi.split_at_mut(1);
        ctx.mul(&lo[k], &lo[k], &mut even[0]);
        ctx.mul(&even[0], &lo[1], &mut odd[0]);
    };
    entries(1);
    entries(2);
    entries(3);
    entries(4);
    entries(5);
    entries(6);
    entries(7);

    // The top window may run past `exp_bits`; those bits are not part of the
    // exponent, and are cleared here, in a copy, rather than in the loop. How
    // many there are is public. An exponent wider than `Uint` has no bits up
    // there to read.
    let exp_bits = exp_bits.min(64 * MAX_LIMBS);
    for (t, (e, &x)) in w.exp.iter_mut().zip(&exp.0).enumerate() {
        let r = exp_bits.saturating_sub(64 * t).min(64);
        // 2^r - 1, with r = 64 as two shifts rather than one too wide.
        *e = x & ((1u64 << (r / 2)) << (r - r / 2)).wrapping_sub(1);
    }
    // At least one window, so that the loop is entered unconditionally and
    // its only test is its counter's. Inside it, only the counter is live
    // across the kernel, which leaves it a register.
    let mut i = core::cmp::max(exp_bits.div_ceil(4), 1);
    loop {
        i -= 1;
        // The products in the loop are the kernel itself, inlined: a call
        // would end the gate's excuse for the loop.
        for _ in 0..4 {
            ctx.square_inline(&mut w.acc);
        }
        select(&w.table, window(&w.exp, i), &mut w.sel);
        ctx.mul_assign_inline(&mut w.acc, &w.sel);
        if i == 0 {
            break;
        }
    }

    leave(&mut ctx, m, &mut w.acc, &w.unit, &mut w.wide, out);
    w.wipe();
}

/// `base^e mod m` for a non-zero public `e`, left to right, branching on its
/// bits, into `out` as [`pow_fixed`] writes it.
///
/// # Safety
///
/// As [`pow_fixed`].
unsafe fn pow_public_fixed<const N: usize>(m: &Modulus, base: &Uint, e: u64, out: &mut [u64; N]) {
    let mut ctx = Ctx::<N> {
        k: [const { MaybeUninit::uninit() }; CTX_WORDS],
    };
    // SAFETY: as the caller guarantees.
    unsafe { ctx.init(m) };
    let (mut wide, mut rr52, mut base_mont) = ([0u64; N], [0u64; N], [0u64; N]);
    let mut unit = [0u64; N];
    unit[0] = 1;
    ctx.rr(m, &mut rr52, &mut wide);
    to_radix52::<MAX_LIMBS, N>(&base.0, &mut base_mont);
    ctx.mul_assign(&mut base_mont, &rr52);
    // The top bit is set, so start from the base rather than squaring one.
    let mut acc = base_mont;
    let bits = 64 - e.leading_zeros() as usize;
    for i in (0..bits.saturating_sub(1)).rev() {
        ctx.square(&mut acc);
        if (e >> i) & 1 == 1 {
            ctx.mul_assign(&mut acc, &base_mont);
        }
    }
    leave(&mut ctx, m, &mut acc, &unit, &mut wide, out);
    for x in [&mut wide, &mut rr52, &mut base_mont, &mut acc] {
        x.zeroize();
    }
}

/// Out of the domain: `acc / R' mod m`, fully reduced, into the first `L`
/// words of `out` and zero above, by way of `wide`. Multiplying by one leaves
/// a value at most `m`; one masked subtraction takes `m` itself to zero.
#[inline(never)]
fn leave<const N: usize>(
    ctx: &mut Ctx<N>,
    m: &Modulus,
    acc: &mut [u64; N],
    unit: &[u64; N],
    wide: &mut [u64; N],
    out: &mut [u64; N],
) {
    let l = N - 8;
    ctx.mul_assign(acc, unit);
    from_radix52::<N>(acc, wide);
    finish(&mut out[..l], &wide[..l], 0, &m.n.0[..l]);
    for o in &mut out[l..] {
        *o = 0;
    }
}

/// Bits `4i .. 4i + 4` of `exp`, for `4i < 64 * MAX_LIMBS`. The word index
/// is reduced into range, so there is nothing to check.
#[inline(always)]
fn window(exp: &[u64; MAX_LIMBS], i: usize) -> u64 {
    let bit = 4 * i;
    (exp[(bit / 64) % MAX_LIMBS] >> (bit % 64)) & 0xF
}

/// Constant-time read of entry `digit` of the table into the first `W` words
/// of `out`; the rest of `out` is left as it is.
///
/// Every entry is read and masked, as in [`super::select`]; which one
/// survives is arithmetic on `digit`, below 16, and the addresses are not.
///
/// The masks are made two at a time in SSE2 registers, by comparing the
/// digit with each entry's index. Made one at a time in general registers,
/// the compiler computed all sixteen at once, and the window loop's counter
/// lost its register to them.
#[inline(always)]
fn select<const N: usize>(table: &[[u64; N]; 16], digit: u64, out: &mut [u64; N]) {
    use core::arch::x86_64::{
        __m128i, _mm_and_si128, _mm_cmpeq_epi32, _mm_set1_epi64x, _mm_set_epi64x, _mm_shuffle_epi32,
    };
    let digit = core::hint::black_box(digit);
    // SAFETY: SSE2 is part of the x86-64 baseline. `[__m128i; 8]` and
    // `[u64; 16]` are the same 128 bytes, and every bit pattern is a valid
    // `u64`.
    let masks = unsafe {
        let d = _mm_set1_epi64x(digit as i64);
        let mut pairs = [d; 8];
        for (p, pair) in pairs.iter_mut().enumerate() {
            let k = 2 * p as i64;
            // Each 32-bit half equal; a 64-bit lane is all ones when both
            // are, and its upper halves are always equal, both being zero.
            let eq = _mm_cmpeq_epi32(d, _mm_set_epi64x(k + 1, k));
            *pair = _mm_and_si128(eq, _mm_shuffle_epi32::<0b10_11_00_01>(eq));
        }
        core::mem::transmute::<[__m128i; 8], [u64; 16]>(pairs)
    };
    // One barrier for all sixteen, so the compiler cannot see that exactly
    // one mask is set and turn the scan into an indexed load.
    let masks = core::hint::black_box(masks);
    for (j, o) in out.iter_mut().enumerate().take(words_for(N)) {
        let mut v = 0u64;
        for (entry, &mask) in table.iter().zip(&masks) {
            v |= entry[j] & mask;
        }
        *o = v;
    }
}

/// A modulus prepared for the kernel of one width, `N = 8K` words a vector,
/// and the kernel's scratch.
///
/// Values are `[u64; N]`: `W` normalised 52-bit limbs and zero above, which
/// is what the kernel reads, `8K` words of `a`.
pub(crate) struct Ctx<const N: usize> {
    /// The modulus in radix `2^52`, zero-padded to `N` words; then
    /// `k0 << 12`; then `a[0..3] << 12` for the call in progress, which the
    /// kernel writes itself, so that no word of `a` is held in a register
    /// across it; from `LANES`, the kernel's `N` output columns; and at
    /// `MASK_AT`, `MASK`. The kernel reaches all of it through one pointer,
    /// which is what lets it fit the registers.
    ///
    /// Not initialised as a whole: [`Ctx::init`] writes the first `N + 1`
    /// words and `MASK_AT`, the kernel the next three and the columns, and
    /// nothing reads a word before it is written. Zeroing all of it would be
    /// a call to `memset` whose destination the constant-time gate cannot
    /// place.
    k: [MaybeUninit<u64>; CTX_WORDS],
}

impl<const N: usize> Drop for Ctx<N> {
    fn drop(&mut self) {
        for w in self.k.iter_mut() {
            // SAFETY: `w` is a valid, aligned, uniquely-borrowed `u64` slot;
            // writing it needs no prior value.
            unsafe { core::ptr::write_volatile(w.as_mut_ptr(), 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl<const N: usize> Ctx<N> {
    /// 52-bit limbs a value.
    pub(crate) const W: usize = words_for(N);
    /// 64-bit limbs of the modulus.
    const L: usize = N - 8;

    /// Prepare for `m`, which must be `N - 8` words wide.
    ///
    /// # Safety
    ///
    /// The CPU must have AVX-512F, IFMA and BMI2: every product after this
    /// runs the kernel.
    #[inline(always)]
    unsafe fn init(&mut self, m: &Modulus) {
        radix52_each::<MAX_LIMBS, N>(&m.n.0, |j, v| {
            self.k[j].write(v);
        });
        // k0 = -n^-1 mod 2^52 is the low 52 bits of -n^-1 mod 2^64, and the
        // kernel wants it shifted left by twelve.
        self.k[N].write((m.n0inv & MASK) << 12);
        self.k[MASK_AT].write(MASK);
    }

    /// `R'^2 mod m`, almost reduced, into `out`, which must be zero, by way
    /// of `scratch`.
    ///
    /// Two products rather than a run of modular doublings, which would be a
    /// loop with sixteen to thirty-two words live in it. With `R^2 mod m`,
    /// which the modulus has, as `A = 2^(128L)`, and `P = 2^t` for
    /// `t = 208W - 256L` -- 64, 96 or 128, so `P` is a valid input -- the
    /// product `A P / R'` is `2^(156W - 128L)`, and `A` times that over `R'`
    /// is `2^(104W) = R'^2`.
    #[inline(never)]
    pub(crate) fn rr(&mut self, m: &Modulus, out: &mut [u64; N], scratch: &mut [u64; N]) {
        const { assert!(208 * Self::W - 256 * Self::L < 52 * Self::W) };
        let t = 208 * Self::W - 256 * Self::L;
        to_radix52::<MAX_LIMBS, N>(&m.r2.0, scratch);
        out[t / 52] = 1 << (t % 52);
        self.mul_assign(out, scratch);
        self.mul_assign(out, scratch);
    }

    /// `a * b / R' mod m` into `out`, almost: congruent, and below `2^(B+1)`
    /// when both inputs are. Inputs must be normalised, every limb below
    /// `2^52`, and zero above `W`; so is the output, given that `out` is
    /// zero above `W` already.
    ///
    /// A call to the one out-of-line copy of the kernel for this width. The
    /// exponentiation's window loop runs [`Ctx::square_inline`] and
    /// [`Ctx::mul_assign_inline`] instead; everything else calls this, which
    /// keeps a copy of the kernel per product out of the code.
    #[inline(always)]
    pub(crate) fn mul(&mut self, a: &[u64; N], b: &[u64; N], out: &mut [u64; N]) {
        // SAFETY: three valid arrays, and `out` is not either input.
        unsafe { self.mul_raw(a, b, out) }
    }

    /// `x = x * b / R' mod m`, as [`Ctx::mul`].
    #[inline(always)]
    pub(crate) fn mul_assign(&mut self, x: &mut [u64; N], b: &[u64; N]) {
        let x: *mut [u64; N] = x;
        // SAFETY: valid arrays; `x` is both an input and the output, which
        // `mul_raw` allows.
        unsafe { self.mul_raw(x, b, x) }
    }

    /// `x = x^2 / R' mod m`, as [`Ctx::mul`].
    #[inline(always)]
    pub(crate) fn square(&mut self, x: &mut [u64; N]) {
        let x: *mut [u64; N] = x;
        // SAFETY: as in `mul_assign`.
        unsafe { self.mul_raw(x, x, x) }
    }

    /// `*out = *a * *b / R' mod m`, out of line.
    ///
    /// # Safety
    ///
    /// Each pointer must be valid for its array, and nothing else may access
    /// them during the call. `out` may be `a` or `b`: the product has read
    /// them before anything is written through it.
    #[inline(never)]
    unsafe fn mul_raw(&mut self, a: *const [u64; N], b: *const [u64; N], out: *mut [u64; N]) {
        // SAFETY: as the caller guarantees. The shared borrows of the inputs
        // end with the product, before `out` is borrowed.
        unsafe {
            self.product(&*a, &*b);
            self.take(&mut *out);
        }
    }

    /// [`Ctx::mul`] with the kernel inlined here, as the exponentiation's
    /// window loop has it: the gate's probe of one product.
    #[cfg(feature = "ct-probes")]
    #[inline(always)]
    pub(crate) fn mul_inline(&mut self, a: &[u64; N], b: &[u64; N], out: &mut [u64; N]) {
        self.product(a, b);
        self.take(out);
    }

    /// [`Ctx::mul_assign`], inlined.
    #[inline(always)]
    fn mul_assign_inline(&mut self, x: &mut [u64; N], b: &[u64; N]) {
        self.product(x, b);
        self.take(x);
    }

    /// [`Ctx::square`], inlined.
    #[inline(always)]
    fn square_inline(&mut self, x: &mut [u64; N]) {
        self.product(x, x);
        self.take(x);
    }

    /// Run the kernel on `a` and `b`, leaving the product's columns in the
    /// context for [`Ctx::take`], which must follow.
    #[inline(always)]
    fn product(&mut self, a: &[u64; N], b: &[u64; N]) {
        let (a, b) = (a.as_ptr(), b.as_ptr());
        let k = self.k.as_mut_ptr().cast::<u64>();
        // SAFETY: `init`'s caller promised AVX-512F, IFMA and BMI2, and `N`
        // is 24, 32 or 40 (`words_for` refuses anything else at compile
        // time), so the kernel for `K = N / 8` reads `N` words of `a`, the
        // `N + 1` words of `k` and `MASK_AT` that `init` wrote, and `W <= N`
        // words of `b`; and writes the three words of `k` after `N + 1` and
        // then reads them, and writes `N` words of `k` from `LANES`, which
        // `k` has room for. `MaybeUninit<u64>` has the layout of `u64`.
        let s = unsafe {
            match N {
                24 => amm3(a, b, k, Self::W),
                32 => amm4(a, b, k, Self::W),
                _ => amm5(a, b, k, Self::W),
            }
        };
        self.k[LANES].write(s);
    }

    /// The last [`Ctx::product`], carried into the first `W` words of `out`
    /// as 52-bit limbs. `out` may be an input of that product. The words above
    /// `W` are left as they are, which is zero: every value here is.
    ///
    /// Column 0 is the scalar's; the rest are the vector's. Every lane is
    /// below 2^61 and the value below 2^(52W), so nothing carries out of the
    /// top.
    #[inline(always)]
    fn take(&self, out: &mut [u64; N]) {
        let mut carry = 0u64;
        for (o, v) in out.iter_mut().zip(&self.k[LANES..]).take(Self::W) {
            // SAFETY: the product before this wrote `N >= W` columns from
            // `LANES`.
            let v = unsafe { v.assume_init() } + carry;
            *o = v & MASK;
            carry = v >> 52;
        }
    }

    /// A context for `m`, where this CPU can run the kernel.
    #[cfg(test)]
    pub(crate) fn for_test(m: &Modulus) -> Option<Ctx<N>> {
        if !available() {
            return None;
        }
        let mut ctx = Ctx {
            k: [const { MaybeUninit::uninit() }; CTX_WORDS],
        };
        // SAFETY: `available` asked the CPU for AVX-512F, IFMA and BMI2.
        unsafe { ctx.init(m) };
        Some(ctx)
    }

    /// The first `L` words of `x` in radix `2^52`.
    #[cfg(test)]
    pub(crate) fn import(x: &Uint) -> [u64; N] {
        let mut out = [0u64; N];
        to_radix52::<MAX_LIMBS, N>(&x.0, &mut out);
        out
    }

    /// A normalised value below `2^(64L)` back to 64-bit words.
    #[cfg(test)]
    pub(crate) fn export(x: &[u64; N]) -> Uint {
        let mut out = Uint::ZERO;
        from_radix52::<N>(x, prefix(&mut out));
        out
    }
}

/// Bits `52j .. 52j + 52` of `x`, a value of `L = N - 8` words, into
/// `out[j]` for `j < W`, and zero above. Words of `x` at and above `L` count
/// as zero.
#[inline(never)]
fn to_radix52<const M: usize, const N: usize>(x: &[u64; M], out: &mut [u64; N]) {
    radix52_each::<M, N>(x, |j, v| out[j] = v);
}

/// [`to_radix52`], handing each of the `N` words to `put` in turn.
///
/// Branch-free however the compiler unrolls it. Every limb below `W` starts
/// in a word below `L`; those below `split` also take bits from the word
/// above, and the rest do not, because it is past `L`. So the loops are
/// split where that changes rather than a loaded word being masked, which
/// the compiler is free to turn into a branch around the load. A shift by
/// `64 - sh`, which is 64 when `sh` is zero, is two shifts.
#[inline(always)]
fn radix52_each<const M: usize, const N: usize>(x: &[u64; M], mut put: impl FnMut(usize, u64)) {
    let (w52, l) = (words_for(N), N - 8);
    let split = (64 * (l - 1)).div_ceil(52);
    let limb = |j: usize, above: bool| {
        let bit = 52 * j;
        let (w, sh) = (bit / 64, bit % 64);
        let lo = x[w.min(M - 1)] >> sh;
        let hi = match above {
            true => (x[(w + 1).min(M - 1)] << 1) << (63 - sh),
            false => 0,
        };
        (lo | hi) & MASK
    };
    for j in 0..split {
        put(j, limb(j, true));
    }
    for j in split..w52 {
        put(j, limb(j, false));
    }
    for j in w52..N {
        put(j, 0);
    }
}

/// The inverse of [`to_radix52`]: a value below `2^(64L)` as `W` normalised
/// limbs and zero above, into the first `L` words of `out`; the rest of `out`
/// is left as it is.
///
/// Each word gathers from the up to three limbs it overlaps. The limbs above
/// `W` are zero, so they need no mask; the third limb lands inside the word
/// only when it starts below bit 64, and a shift by up to 104 is two shifts,
/// which leave zero when it does not.
#[inline(always)]
fn from_radix52<const N: usize>(x: &[u64; N], out: &mut [u64; N]) {
    let l = N - 8;
    for (i, o) in out.iter_mut().enumerate().take(l) {
        let bit = 64 * i;
        let (j, sh) = (bit / 52, bit % 52);
        let s2 = 104 - sh;
        // At 2048 bits the last word's `j + 2` is `N`; the index is held
        // in range, and there `s2` is 96, so the shifts discard the limb.
        let v2 = (x[(j + 2).min(N - 1)] << (s2 / 2)) << (s2 - s2 / 2);
        *o = (x[j] >> sh) | (x[(j + 1).min(N - 1)] << (52 - sh)) | v2;
    }
}

/// One kernel per register count.
///
/// The lists name registers by number: `zero` every accumulator; `extract`
/// the first register of each accumulator set, whose lane 2 is read back;
/// `luq_b`/`luq_u` the low-half multiply-adds by `b[i]` and by `u`, as
/// `(register, word offset / 8)`; `shift` each one-lane shift as
/// `(register, the register above it)`, `zmm13` holding zero; `huq_b`/`huq_u`
/// the high halves; `sum` how the sets fold into the first; `store` where the
/// folded registers go.
macro_rules! kernel {
    (
        $name:ident, $regs:literal,
        zero: [$($z:literal),+],
        extract: [$($e:literal),+],
        luq_b: [$(($lb:literal, $lbc:literal)),+],
        luq_u: [$(($lu:literal, $luc:literal)),+],
        shift: [$(($sd:literal, $sn:literal)),+],
        huq_b: [$(($hb:literal, $hbc:literal)),+],
        huq_u: [$(($hu:literal, $huc:literal)),+],
        sum: [$(($fd:literal, $fs:literal)),+],
        store: [$(($st:literal, $stc:literal)),+]
    ) => {
        /// See the module docs.
        ///
        /// # Safety
        ///
        /// The CPU must have AVX-512F, IFMA and BMI2. `a` must be readable for
        /// `8 * regs` words; `k` readable for `8 * regs + 1` words and at
        /// `MASK_AT`, laid out as [`Ctx::k`] describes, and writable for the
        /// three words after those and for `8 * regs` words from `LANES`; `b` readable for `words` words; and
        /// `3 <= words <= 8 * regs`.
        #[inline(always)]
        unsafe fn $name(a: *const u64, b: *const u64, k: *mut u64, words: usize) -> u64 {
            let s: u64;
            // SAFETY: memory operands are `[a + 64c]` and `[k + 64c]` for
            // `c < regs` (words `0..8 * regs`); `[a + 8j]` for `j < 3`;
            // `[k + 64 * regs + 8j]` for `j < 4` (`k0`, read, and the shifted
            // words, written and then read); `[b]`, advanced one word
            // per row for `words` rows (words `0..words`); and
            // `[k + 8 * LANES + 64c]` for `c < regs`; and `[k + 8 * MASK_AT]`.
            // Nothing is pushed. Every general
            // register written is an operand or declared clobbered, and
            // `xmm0`-`xmm15` are declared clobbered, which in LLVM's model
            // covers the `zmm0`-`zmm15` they alias. `vzeroupper` leaves the
            // upper halves clean for whatever SSE code runs next.
            unsafe {
                asm!(
                    // a[0..3] << 12, for the scalar side's MULX.
                    "mov {x1}, [{a}]",
                    "shl {x1}, 12",
                    "mov [{k} + {ash}], {x1}",
                    "mov {x1}, [{a} + 8]",
                    "shl {x1}, 12",
                    "mov [{k} + {ash} + 8], {x1}",
                    "mov {x1}, [{a} + 16]",
                    "shl {x1}, 12",
                    "mov [{k} + {ash} + 16], {x1}",
                    $( concat!("vpxorq zmm", $z, ", zmm", $z, ", zmm", $z), )+
                    "vpxorq zmm13, zmm13, zmm13",
                    "xor {s:e}, {s:e}",
                    "xor {r:e}, {r:e}",
                    "2:",
                    // x3 = the vector's part of column i + 2: lane 2 of every
                    // accumulator set, before this row touches them.
                    "xor {x3:e}, {x3:e}",
                    $(
                        concat!("vextracti32x4 xmm12, zmm", $e, ", 1"),
                        "vmovq {x4}, xmm12",
                        "add {x3}, {x4}",
                    )+
                    "mov rdx, [{b}]",
                    "vpbroadcastq zmm14, rdx",
                    // s = x0 = column i + lo(a0 b); r = column i + 1 so far,
                    // plus hi(a0 b) + lo(a1 b); x3 += hi(a1 b) + lo(a2 b).
                    "mulx {x2}, {x1}, [{k} + {ash}]",
                    "shr {x1}, 12",
                    "add {s}, {x1}",
                    "add {r}, {x2}",
                    "mulx {x2}, {x1}, [{k} + {ash} + 8]",
                    "shr {x1}, 12",
                    "add {r}, {x1}",
                    "add {x3}, {x2}",
                    "mulx {x2}, {x1}, [{k} + {ash} + 16]",
                    "shr {x1}, 12",
                    "add {x3}, {x1}",
                    // rdx = u << 12 = x0 * (k0 << 12) mod 2^64, which is
                    // (x0 * k0 mod 2^52) << 12 with no masking; the vector
                    // side gets u itself. r += the carry out of column i.
                    "mov rdx, {s}",
                    "imul rdx, [{k} + {koff}]",
                    "mov {u}, rdx",
                    "shr {u}, 12",
                    "vpbroadcastq zmm15, {u}",
                    "mov {x4}, {s}",
                    "add {x4}, [{k} + {moff}]",
                    "shr {x4}, 52",
                    "add {r}, {x4}",
                    // With rdx = u << 12, MULX by m[j] gives hi(m[j] u) in its
                    // high word and lo(m[j] u) << 12 in its low word.
                    // s = column i + 1 = r + lo(m1 u) + hi(m0 u);
                    // r = column i + 2 so far = x3 + hi(m1 u) + lo(m2 u).
                    "mulx {x4}, {s}, [{k} + 8]",
                    "mulx {x2}, {x1}, [{k}]",
                    "shr {s}, 12",
                    "add {s}, {r}",
                    "add {s}, {x2}",
                    "add {x3}, {x4}",
                    "mulx {x2}, {x1}, [{k} + 16]",
                    "shr {x1}, 12",
                    "add {x3}, {x1}",
                    "mov {r}, {x3}",
                    // The vector side: low halves, shift, high halves.
                    $( concat!("vpmadd52luq zmm", $lb, ", zmm14, [{a} + 64*", $lbc, "]"), )+
                    $( concat!("vpmadd52luq zmm", $lu, ", zmm15, [{k} + 64*", $luc, "]"), )+
                    $( concat!("valignq zmm", $sd, ", zmm", $sn, ", zmm", $sd, ", 1"), )+
                    $( concat!("vpmadd52huq zmm", $hb, ", zmm14, [{a} + 64*", $hbc, "]"), )+
                    $( concat!("vpmadd52huq zmm", $hu, ", zmm15, [{k} + 64*", $huc, "]"), )+
                    "lea {b}, [{b} + 8]",
                    "dec {rows}",
                    "jnz 2b",
                    $( concat!("vpaddq zmm", $fd, ", zmm", $fd, ", zmm", $fs), )+
                    $( concat!("vmovdqu64 [{k} + {loff} + 64*", $stc, "], zmm", $st), )+
                    "vzeroupper",
                    a = in(reg) a,
                    k = in(reg) k,
                    b = inout(reg) b => _,
                    rows = inout(reg) words => _,
                    loff = const 8 * LANES,
                    moff = const 8 * MASK_AT,
                    koff = const 64 * $regs,
                    ash = const 64 * $regs + 8,
                    s = out(reg) s,
                    r = out(reg) _,
                    u = out(reg) _,
                    x1 = out(reg) _,
                    x2 = out(reg) _,
                    x3 = out(reg) _,
                    x4 = out(reg) _,
                    out("rdx") _,
                    out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                    out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                    out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
                    out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
                    options(nostack),
                );
            }
            s
        }
    };
}

// 1024 bits: four accumulator sets of three registers, so that each set's
// chain per row is one multiply-add and one shift.
kernel!(amm3, 3,
    zero: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11],
    extract: [0, 3, 6, 9],
    luq_b: [(0, 0), (1, 1), (2, 2)],
    luq_u: [(3, 0), (4, 1), (5, 2)],
    shift: [(0, 1), (1, 2), (2, 13), (3, 4), (4, 5), (5, 13),
            (6, 7), (7, 8), (8, 13), (9, 10), (10, 11), (11, 13)],
    huq_b: [(6, 0), (7, 1), (8, 2)],
    huq_u: [(9, 0), (10, 1), (11, 2)],
    sum: [(0, 3), (6, 9), (0, 6), (1, 4), (7, 10), (1, 7), (2, 5), (8, 11), (2, 8)],
    store: [(0, 0), (1, 1), (2, 2)]);

// 1536 and 2048 bits: two sets, low and high halves. Four would need more
// registers than the sixteen this can name.
kernel!(amm4, 4,
    zero: [0, 1, 2, 3, 5, 6, 7, 8],
    extract: [0, 5],
    luq_b: [(0, 0), (1, 1), (2, 2), (3, 3)],
    luq_u: [(0, 0), (1, 1), (2, 2), (3, 3)],
    shift: [(0, 1), (1, 2), (2, 3), (3, 13), (5, 6), (6, 7), (7, 8), (8, 13)],
    huq_b: [(5, 0), (6, 1), (7, 2), (8, 3)],
    huq_u: [(5, 0), (6, 1), (7, 2), (8, 3)],
    sum: [(0, 5), (1, 6), (2, 7), (3, 8)],
    store: [(0, 0), (1, 1), (2, 2), (3, 3)]);

kernel!(amm5, 5,
    zero: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    extract: [0, 5],
    luq_b: [(0, 0), (1, 1), (2, 2), (3, 3), (4, 4)],
    luq_u: [(0, 0), (1, 1), (2, 2), (3, 3), (4, 4)],
    shift: [(0, 1), (1, 2), (2, 3), (3, 4), (4, 13), (5, 6), (6, 7), (7, 8), (8, 9), (9, 13)],
    huq_b: [(5, 0), (6, 1), (7, 2), (8, 3), (9, 4)],
    huq_u: [(5, 0), (6, 1), (7, 2), (8, 3), (9, 4)],
    sum: [(0, 5), (1, 6), (2, 7), (3, 8), (4, 9)],
    store: [(0, 0), (1, 1), (2, 2), (3, 3), (4, 4)]);
