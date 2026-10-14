//! Whether this CPU, and the operating system on it, can run the AVX-512
//! IFMA code in this crate: Curve25519's four-lane field (`f51x4`) and the
//! NIST curves' (`nist::ifma`). And, by the same questions, whether it can
//! run AVX2, which Ed25519 signing's table read uses on the four-limb field.
//!
//! The crate's declared minimum Rust predates the stabilisation of the
//! AVX-512 target features, so support is asked of CPUID and XGETBV here
//! rather than through `is_x86_feature_detected!`, which also makes it
//! available without `std`. `--cfg ic_no_avx512` makes the answer no, for
//! measuring the AVX2 and MULX paths on a CPU that has more (docs/CI.md).

use core::arch::asm;

/// Whether the CPU has AVX2, AVX-512F, AVX-512DQ, AVX-512VL and AVX-512 IFMA,
/// and the OS saves the SSE, AVX and AVX-512 register state, so that the
/// instructions will not fault. Asked once and cached.
#[inline]
pub(crate) fn ifma() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering};
    // 0 not yet asked, 1 yes, 2 no. `ic_no_avx512` answers no without
    // asking, but leaves the IFMA paths compiled in, so that the callers'
    // code is laid out as in a default build on a CPU without IFMA: taking
    // those paths out moved P-256 ECDH's MULX/ADX timing on Zen 5 from 25
    // to 44 us, its own source unchanged (docs/GRAVIOLA.md).
    static CACHED: AtomicU8 = AtomicU8::new(0);
    match CACHED.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let have = !cfg!(ic_no_avx512) && detect();
            CACHED.store(if have { 1 } else { 2 }, Ordering::Relaxed);
            have
        }
    }
}

/// `cpuid` with `eax = leaf`, `ecx = sub`: `(eax, ebx, ecx, edx)`.
fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let (a, b, c, d): (u32, u64, u32, u32);
    // SAFETY: CPUID exists on every x86-64 CPU and has no effect beyond its
    // four output registers. LLVM reserves rbx, so it is saved in another
    // register around the instruction and swapped back.
    unsafe {
        asm!(
            "mov {b}, rbx",
            "cpuid",
            "xchg {b}, rbx",
            b = out(reg) b,
            inout("eax") leaf => a,
            inout("ecx") sub => c,
            out("edx") d,
            options(nostack, preserves_flags, nomem),
        );
    }
    (a, b as u32, c, d)
}

/// Whether the CPU has AVX2 and the OS saves the AVX register state, for
/// signing's table read on the four-limb field (`fe64::edwards`). Asked once
/// and cached. Not affected by `ic_no_avx512`, which stands for a CPU without
/// IFMA, and every CPU with `MULX` and `ADX` has AVX2.
#[inline]
#[cfg_attr(
    any(not(feature = "std"), ic_limb32, ic_ec_portable, ic_approved_only),
    allow(dead_code)
)]
pub(crate) fn avx2() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering};
    // 0 not yet asked, 1 yes, 2 no.
    static CACHED: AtomicU8 = AtomicU8::new(0);
    match CACHED.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let have = detect_avx2();
            CACHED.store(if have { 1 } else { 2 }, Ordering::Relaxed);
            have
        }
    }
}

#[cfg_attr(
    any(not(feature = "std"), ic_limb32, ic_ec_portable, ic_approved_only),
    allow(dead_code)
)]
fn detect_avx2() -> bool {
    let Some(xcr0) = xcr0() else {
        return false;
    };
    // SSE (1) and AVX (2) state.
    if xcr0 & 0b110 != 0b110 {
        return false;
    }
    let (_, ebx7, _, _) = cpuid(7, 0);
    // AVX2 (5).
    ebx7 & (1 << 5) != 0
}

fn detect() -> bool {
    let Some(xcr0) = xcr0() else {
        return false;
    };
    detect_with(xcr0)
}

/// XCR0, or `None` without CPUID leaf 7, OSXSAVE or AVX.
fn xcr0() -> Option<u64> {
    let (max, _, _, _) = cpuid(0, 0);
    if max < 7 {
        return None;
    }
    let (_, _, ecx1, _) = cpuid(1, 0);
    // OSXSAVE (27) and AVX (28).
    if ecx1 & (1 << 27) == 0 || ecx1 & (1 << 28) == 0 {
        return None;
    }
    Some({
        let (lo, hi): (u32, u32);
        // SAFETY: XGETBV with ecx = 0 is available when OSXSAVE is set,
        // which was just checked; it reads XCR0 into edx:eax and nothing
        // else.
        unsafe {
            asm!(
                "xgetbv",
                in("ecx") 0u32,
                out("eax") lo,
                out("edx") hi,
                options(nostack, preserves_flags, nomem),
            );
        }
        (u64::from(hi) << 32) | u64::from(lo)
    })
}

fn detect_with(xcr0: u64) -> bool {
    // SSE (1), AVX (2), and AVX-512's opmask (5), ZMM_Hi256 (6) and
    // Hi16_ZMM (7) state: without them EVEX instructions fault.
    let needed = 0b1110_0110;
    if xcr0 & needed != needed {
        return false;
    }
    let (_, ebx7, _, _) = cpuid(7, 0);
    // AVX2 (5), AVX-512F (16), AVX-512DQ (17), AVX-512 IFMA (21),
    // AVX-512VL (31).
    let want = (1 << 5) | (1 << 16) | (1 << 17) | (1 << 21) | (1 << 31);
    ebx7 & want == want
}
