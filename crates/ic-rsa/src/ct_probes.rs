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

/// Runs `f` with the MULX/ADX Montgomery backend taken and IFMA declined,
/// whatever CPUID reports. Valgrind executes ADX but hides the bit from CPUID,
/// so this is how a harness reaches that path under it. Calling it on a CPU
/// without BMI2 and ADX makes the backend's instructions fault.
pub fn with_forced_adx<T>(f: impl FnOnce() -> T) -> T {
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
    use crate::uint::{ifma, x86, Limbs};

    /// The IFMA context, opaque: the probe takes one by reference, so that
    /// nothing copies or zeroes its buffer around the product.
    pub struct IfmaCtx(ifma::Ctx);

    /// The MULX/ADCX/ADOX product at 2048 bits, as the multiplication takes
    /// it on that backend: the product, the reduction, and the masked
    /// subtraction.
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
        let mut t = core::mem::MaybeUninit::<[u64; 66]>::uninit();
        // SAFETY: as the caller guarantees.
        unsafe { x86::mont_mul_2048(&mut t, a, b, n, n0inv, out) };
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
    /// that backend: the cross products, the diagonal, the reduction, and
    /// the masked subtraction.
    ///
    /// # Safety
    ///
    /// The CPU must support BMI2 and ADX.
    pub unsafe fn adx_mont_sqr_2048(a: &[u64; 32], n: &[u64; 32], n0inv: u64, out: &mut [u64; 32]) {
        // Not cleared: the kernels write every word of it before reading it,
        // as on the real path.
        let mut t = core::mem::MaybeUninit::<[u64; 66]>::uninit();
        // SAFETY: as the caller guarantees.
        unsafe { x86::mont_sqr_2048(&mut t, a, n, n0inv, out) };
    }

    /// One almost-Montgomery product on AVX-512 IFMA at 2048 bits: the
    /// kernel and the carry of its columns into 52-bit limbs.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX-512F, IFMA and BMI2.
    pub unsafe fn ifma_amm_2048(ctx: &mut IfmaCtx, a: &Limbs, b: &Limbs, out: &mut Limbs) {
        // SAFETY: as the caller guarantees.
        unsafe { ctx.0.set_width_for_probe(32) };
        ctx.0.amm(a, b, out);
    }
}
