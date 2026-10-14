//! Hooks for `scripts/ct-audit` and `ctgrind`, not API and not covered by
//! semver; behind the `ct-probes` feature.

use crate::uint::{select, MAX_LIMBS};
use core::sync::atomic::Ordering;

/// The masked table read of the windowed exponentiation at 2048 bits: entry
/// `digit` of a 16-entry table of 32-word values, written to `out`. This is
/// the `select` the private-key path calls for every window.
pub fn select_2048(table: &[[u64; MAX_LIMBS]; 16], digit: u64, out: &mut [u64; MAX_LIMBS]) {
    select(table, 32, digit, out);
}

/// The same read from a 32-entry table, the five-bit window's: entry
/// `digit` of 32-word values. Without `std` this is the SSE2 scan; with it,
/// the AVX2 read where the CPU has AVX2, which `x86::select32_avx2_2048`
/// reads directly.
pub fn select32_2048(table: &[[u64; MAX_LIMBS]; 32], digit: u64, out: &mut [u64; MAX_LIMBS]) {
    select(table, 32, digit, out);
}

/// Runs `f` with the MULX/ADX Montgomery backend taken and IFMA declined,
/// whatever CPUID reports. Valgrind executes ADX but hides the bit from CPUID,
/// so this is how a harness reaches that path under it. Calling it on a CPU
/// without BMI2 and ADX makes the backend's instructions fault.
///
/// # Safety
///
/// The CPU must have BMI2 and ADX.
pub unsafe fn with_forced_adx<T>(f: impl FnOnce() -> T) -> T {
    crate::uint::FORCE_ADX.store(true, Ordering::Relaxed);
    let out = f();
    crate::uint::FORCE_ADX.store(false, Ordering::Relaxed);
    out
}

/// The portable CIOS Montgomery product at 2048 bits, `a * b / 2^2048 mod n`
/// into `out`: the copy [`crate::uint::Modulus`]'s multiplication takes at
/// 32 words, with the final masked subtraction.
pub fn cios_2048(a: &[u64; 32], b: &[u64; 32], n: &[u64; 32], n0inv: u64, out: &mut [u64; 32]) {
    let mut t = [0u64; 34];
    crate::uint::cios(&mut t, a, b, n, n0inv, out);
}

/// The x86-64 Montgomery products, compiled to be read and never run here:
/// they need BMI2 and ADX, or AVX-512F, IFMA and BMI2.
#[cfg(all(target_arch = "x86_64", not(ic_limb32)))]
#[allow(unsafe_code)]
pub mod x86 {
    use crate::uint::{ifma, select_masks, x86, Modulus, Uint, MAX_LIMBS};

    /// The IFMA context at 2048 bits, opaque: the probe takes one by
    /// reference, so that nothing copies or zeroes its buffer around the
    /// product.
    pub struct IfmaCtx(ifma::Ctx<40>);

    /// The MULX/ADCX/ADOX product at 2048 bits, as the multiplication takes
    /// it on that backend: the product by one level of Karatsuba over the
    /// 16-word kernels, the reduction, and the masked subtraction.
    ///
    /// # Safety
    ///
    /// The CPU must support BMI2 and ADX.
    pub unsafe fn adx_mont_mul_2048(
        a: &[u64; 32],
        b: &[u64; 32],
        n: &[u64; 32],
        n0inv: u64,
        out: &mut [u64; 32],
    ) {
        // Not cleared: the kernels write every word of it before reading it,
        // as on the real path.
        let mut t = core::mem::MaybeUninit::<[u64; x86::KARA_T]>::uninit();
        // SAFETY: as the caller guarantees.
        unsafe { x86::mont_mul_2048(&mut t, a, b, n, n0inv, out) };
    }

    /// The MULX/ADCX/ADOX product at 1536 bits, the width of an RSA-3072
    /// prime: the eight-word blocks, the reduction, and the masked
    /// subtraction.
    ///
    /// # Safety
    ///
    /// The CPU must support BMI2 and ADX.
    pub unsafe fn adx_mont_mul_1536(
        a: &[u64; 24],
        b: &[u64; 24],
        n: &[u64; 24],
        n0inv: u64,
        out: &mut [u64; 24],
    ) {
        // Not cleared, as above.
        let mut t = core::mem::MaybeUninit::<[u64; 50]>::uninit();
        // SAFETY: as the caller guarantees.
        unsafe { x86::mont_mul_1536(&mut t, a, b, n, n0inv, out) };
    }

    /// The MULX/ADCX/ADOX square at 1536 bits: the eight-word blocks' cross
    /// products and diagonal, the reduction, and the masked subtraction.
    ///
    /// # Safety
    ///
    /// The CPU must support BMI2 and ADX.
    pub unsafe fn adx_mont_sqr_1536(a: &[u64; 24], n: &[u64; 24], n0inv: u64, out: &mut [u64; 24]) {
        // Not cleared, as above.
        let mut t = core::mem::MaybeUninit::<[u64; 50]>::uninit();
        // SAFETY: as the caller guarantees.
        unsafe { x86::mont_sqr_1536(&mut t, a, n, n0inv, out) };
    }

    /// The AVX2 read of a 32-entry table at 1024 bits, the width of an
    /// RSA-2048 prime: the masks from the secret digit, then four
    /// accumulators over every entry.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    pub unsafe fn select32_avx2_1024(
        table: &[[u64; MAX_LIMBS]; 32],
        digit: u64,
        out: &mut [u64; MAX_LIMBS],
    ) {
        let masks = select_masks::<32>(digit);
        // SAFETY: as the caller guarantees; 32 entries at 16 words.
        unsafe { x86::select_avx2_unchecked(table, 16, &masks, out) };
    }

    /// The same at 1536 bits, an RSA-3072 prime: six accumulators.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    pub unsafe fn select32_avx2_1536(
        table: &[[u64; MAX_LIMBS]; 32],
        digit: u64,
        out: &mut [u64; MAX_LIMBS],
    ) {
        let masks = select_masks::<32>(digit);
        // SAFETY: as the caller guarantees; 32 entries at 24 words.
        unsafe { x86::select_avx2_unchecked(table, 24, &masks, out) };
    }

    /// The same at 2048 bits, an RSA-4096 prime: eight accumulators.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    pub unsafe fn select32_avx2_2048(
        table: &[[u64; MAX_LIMBS]; 32],
        digit: u64,
        out: &mut [u64; MAX_LIMBS],
    ) {
        let masks = select_masks::<32>(digit);
        // SAFETY: as the caller guarantees; 32 entries at 32 words.
        unsafe { x86::select_avx2_unchecked(table, 32, &masks, out) };
    }

    /// The MULX/ADCX/ADOX product at 1024 bits, the width of an RSA-2048
    /// prime: the straight-line kernel and the masked subtraction.
    ///
    /// # Safety
    ///
    /// The CPU must support BMI2 and ADX.
    pub unsafe fn adx_mont_mul_1024(
        a: &[u64; 16],
        b: &[u64; 16],
        n: &[u64; 16],
        n0inv: u64,
        out: &mut [u64; 16],
    ) {
        // Not cleared, as above.
        let mut t = core::mem::MaybeUninit::<[u64; 34]>::uninit();
        // SAFETY: as the caller guarantees.
        unsafe { x86::mont_mul_1024(&mut t, a, b, n, n0inv, out) };
    }

    /// The MULX/ADCX/ADOX square at 1024 bits: the straight-line kernel and
    /// the masked subtraction.
    ///
    /// # Safety
    ///
    /// The CPU must support BMI2 and ADX.
    pub unsafe fn adx_mont_sqr_1024(a: &[u64; 16], n: &[u64; 16], n0inv: u64, out: &mut [u64; 16]) {
        // Not cleared, as above.
        let mut t = core::mem::MaybeUninit::<[u64; 34]>::uninit();
        // SAFETY: as the caller guarantees.
        unsafe { x86::mont_sqr_1024(&mut t, a, n, n0inv, out) };
    }

    /// The MULX/ADCX/ADOX square at 2048 bits, as the squaring takes it on
    /// that backend: three 16-word squares combined by Karatsuba, the
    /// reduction, and the masked subtraction.
    ///
    /// # Safety
    ///
    /// The CPU must support BMI2 and ADX.
    pub unsafe fn adx_mont_sqr_2048(a: &[u64; 32], n: &[u64; 32], n0inv: u64, out: &mut [u64; 32]) {
        // Not cleared: the kernels write every word of it before reading it,
        // as on the real path.
        let mut t = core::mem::MaybeUninit::<[u64; x86::KARA_T]>::uninit();
        // SAFETY: as the caller guarantees.
        unsafe { x86::mont_sqr_2048(&mut t, a, n, n0inv, out) };
    }

    /// One almost-Montgomery product on AVX-512 IFMA at 2048 bits, 40 limbs
    /// of 52 bits: the kernel and the carry of its columns into limbs.
    pub fn ifma_amm_2048(ctx: &mut IfmaCtx, a: &[u64; 40], b: &[u64; 40], out: &mut [u64; 40]) {
        ctx.0.mul_inline(a, b, out);
    }

    /// The whole IFMA exponentiation for a 1024-bit modulus -- each of the
    /// two in an RSA-2048 signature -- from the modulus, base and secret
    /// exponent to the reduced result: into the domain, the table, the
    /// windows, and out. `m` must be 16 words wide.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX-512F, IFMA and BMI2.
    pub unsafe fn ifma_pow_1024(
        m: &Modulus,
        base: &Uint,
        exp: &Uint,
        exp_bits: usize,
        out: &mut [u64; 24],
    ) {
        // SAFETY: as the caller guarantees.
        unsafe { ifma::pow_fixed::<24>(m, base, exp, exp_bits, out) }
    }

    /// The same at 2048 bits, the modulus of RSA-2048 or a prime of RSA-4096.
    /// `m` must be 32 words wide.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX-512F, IFMA and BMI2.
    pub unsafe fn ifma_pow_2048(
        m: &Modulus,
        base: &Uint,
        exp: &Uint,
        exp_bits: usize,
        out: &mut [u64; 40],
    ) {
        // SAFETY: as the caller guarantees.
        unsafe { ifma::pow_fixed::<40>(m, base, exp, exp_bits, out) }
    }
}
