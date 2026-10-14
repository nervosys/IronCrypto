//! Montgomery multiplication on x86-64 `MULX`, `ADCX` and `ADOX`.
//!
//! # Why assembly
//!
//! A Montgomery multiplication is a sequence of multiply-accumulate rows, and
//! each row is a carry chain. Written with `u128` sums, every step of the
//! chain is an `add` and an `adc` on the one carry flag, so the row runs at the
//! latency of that chain, about two cycles a word. `ADCX` carries through `CF`
//! and `ADOX` through `OF`, and neither touches the other's flag, so the low
//! and high halves of each product go into two chains that run side by side
//! -- about one cycle a word. The compiler does not emit `ADOX` and cannot be
//! asked to through intrinsics (`_addcarryx_u64` becomes a plain `adc`), which
//! is why this is `asm!` rather than Rust.
//!
//! # Which kernel
//!
//! Three shapes, chosen by the width `L`, which is public:
//!
//! - `L = 16`, the primes of an RSA-2048 key: straight-line product and
//!   square, no loop at all (`mont_mul_16`, `mont_sqr_16`).
//! - Other multiples of eight -- 24, 32, 48 and 64 words, every other RSA
//!   modulus and prime: the product or square in full, then a separate
//!   reduction, from blocks of eight words held in registers
//!   (`mont_mul_8n`, `mont_sqr_8n`; see the section comment above them).
//!   The square computes each cross product once.
//! - Other multiples of four: the interleaved kernel described next
//!   (`mont_mul_adx`), for both product and square.
//!
//! All three leave `a * b / 2^(64L)`, below `2n`, in `t[L..=2L]`; [`finish`]
//! then makes the one conditional subtraction, with a mask, into the
//! caller's output. [`select`] is the exponentiation's table read in SSE2.
//!
//! # The interleaved kernel
//!
//! Coarsely integrated operand scanning, as in [`super::Modulus::mont_mul`]'s
//! portable form: for each word `b[i]`, add `a * b[i]` into the accumulator,
//! then add `u * n` with `u = t[0] * n0inv` so that the low word becomes zero,
//! and drop that word. The drop is not a copy: the accumulator is a window
//! into a buffer of `2L + 2` words that slides up one word per row. After `L`
//! rows the result is the `L + 1` words at `t[L..=2L]`, below `2n`.
//!
//! Each row is two passes over the `L` words, unrolled four at a time:
//!
//! ```text
//! mulx hi', lo, [x + j]      hi':lo = x[j] * rdx
//! adcx lo, [t + j]           lo += t[j]       (CF chain)
//! adox lo, hi                lo += previous hi (OF chain)
//! mov  [t + j], lo
//! ```
//!
//! The loop counter runs from `-L` up to zero in `rcx`, stepped by `lea`, and
//! is tested with `jrcxz`; neither touches a flag, so both carry chains survive
//! the loop branch. Both chains are folded into the top two words at the end
//! of each pass.
//!
//! # Constant time
//!
//! Every branch here is on `L`, the width of the modulus, which is public. No
//! instruction's operands select a memory address from a value: every address
//! is a base pointer plus a constant or the loop counter. `MULX`, `ADCX`,
//! `ADOX` and the SSE2 logic have data-independent latency, and the final
//! subtraction and the table read choose by masking, not by branch or
//! conditional move. `scripts/check-ct.py` reads the compiled kernels at 1024
//! and 2048 bits (docs/CONSTANT_TIME.md), and ctgrind runs RSA-2048 signing
//! on this backend under Valgrind (docs/CTGRIND.md).
//!
//! # Safety
//!
//! [`mont_mul`] and [`mont_sqr`] are the only ways in. They check the CPU
//! features (once, then cached), that `L` is a non-zero multiple of four,
//! that every slice is `L` words, and that the scratch buffer holds `2L + 2`,
//! and decline -- return `false` and touch nothing -- otherwise. Given those,
//! every address the assembly forms is inside one of the slices; the
//! comments on each block say which.

use core::arch::asm;

/// Whether this CPU has `MULX` (BMI2) and `ADCX`/`ADOX` (ADX), asked once.
pub(crate) fn available() -> bool {
    if super::adx_forced() {
        return true;
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
                let have =
                    std::is_x86_feature_detected!("bmi2") && std::is_x86_feature_detected!("adx");
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

/// Whether [`mont_mul`] will take a modulus of `limbs` words on this CPU.
pub(crate) fn handles(limbs: usize) -> bool {
    limbs != 0 && limbs.is_multiple_of(4) && available()
}

/// The Montgomery product `a * b / 2^(64L) mod n` into `out[..L]`, where
/// `L = n.len()`, using `t` as scratch.
///
/// Returns `false` without touching anything when this backend cannot run:
/// the CPU lacks the instructions, `L` is not a non-zero multiple of four, or
/// a slice has the wrong length. The caller then uses the portable path.
pub(crate) fn mont_mul(
    t: &mut [u64],
    a: &[u64],
    b: &[u64],
    n: &[u64],
    n0inv: u64,
    out: &mut [u64],
) -> bool {
    let l = n.len();
    if !handles(l) || a.len() != l || b.len() != l || out.len() < l || t.len() < 2 * l + 2 {
        return false;
    }
    if l == 16 {
        // SAFETY: the features were detected above; `a`, `b` and `n` are 16
        // words and `t` at least 34.
        unsafe { mont_mul_16(t.as_mut_ptr(), a.as_ptr(), b.as_ptr(), n.as_ptr(), n0inv) };
    } else if l.is_multiple_of(8) {
        // SAFETY: the features were detected above; `a`, `b` and `n` are `l`
        // words, `t` at least `2l + 2`, and `l` a non-zero multiple of eight.
        unsafe { mont_mul_8n(t.as_mut_ptr(), a.as_ptr(), b.as_ptr(), n.as_ptr(), n0inv, l) };
    } else {
        t[..2 * l + 2].fill(0);
        // SAFETY: the features `mont_mul_adx` is compiled for were detected
        // above, and the lengths it relies on were checked: `a`, `b` and `n`
        // are `l` words, `t` at least `2l + 2` and zeroed, and `l` a non-zero
        // multiple of four.
        unsafe { mont_mul_adx(t.as_mut_ptr(), a.as_ptr(), b.as_ptr(), n.as_ptr(), n0inv, l) };
    }
    // SAFETY: `out` is at least `l` words, `t` at least `2l + 2` and `n` `l`;
    // `out` is a distinct `&mut`, so overlaps neither; `l` is a multiple of
    // four; `t[2l]` is the carry out of the reduction, zero or one.
    unsafe { finish(out.as_mut_ptr(), t.as_ptr().add(l), t[2 * l], n.as_ptr(), l) };
    true
}

/// The Montgomery square `a^2 / 2^(64L) mod n` into `out[..L]`: the same
/// value and contract as [`mont_mul`] of `a` by itself, with each cross
/// product computed once where `L` is a multiple of eight.
pub(crate) fn mont_sqr(t: &mut [u64], a: &[u64], n: &[u64], n0inv: u64, out: &mut [u64]) -> bool {
    let l = n.len();
    if !handles(l) || a.len() != l || out.len() < l || t.len() < 2 * l + 2 {
        return false;
    }
    if l == 16 {
        // SAFETY: as in `mont_mul`, with `a` for both operands.
        unsafe { mont_sqr_16(t.as_mut_ptr(), a.as_ptr(), n.as_ptr(), n0inv) };
    } else if l.is_multiple_of(8) {
        // SAFETY: as in `mont_mul`, with `a` for both operands.
        unsafe { mont_sqr_8n(t.as_mut_ptr(), a.as_ptr(), n.as_ptr(), n0inv, l) };
    } else {
        t[..2 * l + 2].fill(0);
        // SAFETY: as in `mont_mul`.
        unsafe { mont_mul_adx(t.as_mut_ptr(), a.as_ptr(), a.as_ptr(), n.as_ptr(), n0inv, l) };
    }
    // SAFETY: as in `mont_mul`.
    unsafe { finish(out.as_mut_ptr(), t.as_ptr().add(l), t[2 * l], n.as_ptr(), l) };
    true
}

/// The product [`mont_mul`] makes at 2048 bits, after its checks, for
/// `scripts/ct-audit` to read: the kernels at `L = 32`, then the final
/// subtraction.
///
/// # Safety
///
/// The CPU must support BMI2 and ADX.
#[cfg(feature = "ct-probes")]
pub(crate) unsafe fn mont_mul_2048(
    t: &mut core::mem::MaybeUninit<[u64; 66]>,
    a: &[u64; 32],
    b: &[u64; 32],
    n: &[u64; 32],
    n0inv: u64,
    out: &mut [u64; 32],
) {
    // SAFETY: the caller guarantees the features; `a`, `b` and `n` are 32
    // words, `t` is 66 = 2 * 32 + 2, and 32 is a multiple of eight. `t` may
    // be uninitialised: the kernels write every word of it before reading it.
    let t = t.as_mut_ptr().cast::<u64>();
    unsafe {
        mont_mul_8n(t, a.as_ptr(), b.as_ptr(), n.as_ptr(), n0inv, 32);
        finish(out.as_mut_ptr(), t.add(32), *t.add(64), n.as_ptr(), 32);
    }
}

/// The product [`mont_mul`] makes at 1024 bits, after its checks, for
/// `scripts/ct-audit` to read: the straight-line kernel, then the final
/// subtraction.
///
/// # Safety
///
/// The CPU must support BMI2 and ADX.
#[cfg(feature = "ct-probes")]
pub(crate) unsafe fn mont_mul_1024(
    t: &mut core::mem::MaybeUninit<[u64; 34]>,
    a: &[u64; 16],
    b: &[u64; 16],
    n: &[u64; 16],
    n0inv: u64,
    out: &mut [u64; 16],
) {
    // SAFETY: the caller guarantees the features; `a`, `b` and `n` are 16
    // words and `t` is 34 = 2 * 16 + 2, written before it is read.
    let t = t.as_mut_ptr().cast::<u64>();
    unsafe {
        mont_mul_16(t, a.as_ptr(), b.as_ptr(), n.as_ptr(), n0inv);
        finish(out.as_mut_ptr(), t.add(16), *t.add(32), n.as_ptr(), 16);
    }
}

/// The square [`mont_sqr`] makes at 1024 bits, after its checks, for
/// `scripts/ct-audit` to read.
///
/// # Safety
///
/// The CPU must support BMI2 and ADX.
#[cfg(feature = "ct-probes")]
pub(crate) unsafe fn mont_sqr_1024(
    t: &mut core::mem::MaybeUninit<[u64; 34]>,
    a: &[u64; 16],
    n: &[u64; 16],
    n0inv: u64,
    out: &mut [u64; 16],
) {
    // SAFETY: as in `mont_mul_1024`.
    let t = t.as_mut_ptr().cast::<u64>();
    unsafe {
        mont_sqr_16(t, a.as_ptr(), n.as_ptr(), n0inv);
        finish(out.as_mut_ptr(), t.add(16), *t.add(32), n.as_ptr(), 16);
    }
}

/// The square [`mont_sqr`] makes at 2048 bits, after its checks, for
/// `scripts/ct-audit` to read.
///
/// # Safety
///
/// The CPU must support BMI2 and ADX.
#[cfg(feature = "ct-probes")]
pub(crate) unsafe fn mont_sqr_2048(
    t: &mut core::mem::MaybeUninit<[u64; 66]>,
    a: &[u64; 32],
    n: &[u64; 32],
    n0inv: u64,
    out: &mut [u64; 32],
) {
    // SAFETY: as in `mont_mul_2048`.
    let t = t.as_mut_ptr().cast::<u64>();
    unsafe {
        mont_sqr_8n(t, a.as_ptr(), n.as_ptr(), n0inv, 32);
        finish(out.as_mut_ptr(), t.add(32), *t.add(64), n.as_ptr(), 32);
    }
}

/// The masked scan of `uint::select`: `out[..limbs]` = the OR over the
/// sixteen entries of `table` of each entry's low `limbs` words ANDed with
/// its mask, where `masks` are all ones for the entry wanted and zero for
/// the rest. Two words at a time, in SSE2 registers: every entry is read at
/// every position, at addresses that depend only on the position.
///
/// Returns `false` without touching anything when `limbs` is zero, odd or
/// above the capacity; the caller then scans in Rust.
pub(crate) fn select(
    table: &[super::Limbs; 16],
    limbs: usize,
    masks: &[u64; 16],
    out: &mut super::Limbs,
) -> bool {
    if limbs == 0 || !limbs.is_multiple_of(2) || limbs > super::MAX_LIMBS {
        return false;
    }
    // Each mask in both halves of a 16-byte lane, aligned for `pand`.
    #[repr(C, align(16))]
    struct Lanes([u64; 32]);
    let mut lanes = Lanes([0; 32]);
    for (pair, &mask) in lanes.0.chunks_exact_mut(2).zip(masks) {
        pair[0] = mask;
        pair[1] = mask;
    }
    let count = (limbs / 2).wrapping_neg();
    // SAFETY: SSE2 is part of x86-64. Iteration `j` of the loop reads words
    // `2j..2j + 2` of each entry, at `table + 512k + 16j` for entry `k`, and
    // writes the same two words of `out`, for `j < limbs / 2 <= 32`: all in
    // bounds. The masks are read from `lanes`, 16-byte aligned.
    unsafe {
        asm!(
            "2:",
            "pxor xmm0, xmm0",
            "movdqu xmm1, xmmword ptr [rdi]",
            "pand xmm1, xmmword ptr [rsi]",
            "por xmm0, xmm1",
            "movdqu xmm1, xmmword ptr [rdi + 512]",
            "pand xmm1, xmmword ptr [rsi + 16]",
            "por xmm0, xmm1",
            "movdqu xmm1, xmmword ptr [rdi + 1024]",
            "pand xmm1, xmmword ptr [rsi + 32]",
            "por xmm0, xmm1",
            "movdqu xmm1, xmmword ptr [rdi + 1536]",
            "pand xmm1, xmmword ptr [rsi + 48]",
            "por xmm0, xmm1",
            "movdqu xmm1, xmmword ptr [rdi + 2048]",
            "pand xmm1, xmmword ptr [rsi + 64]",
            "por xmm0, xmm1",
            "movdqu xmm1, xmmword ptr [rdi + 2560]",
            "pand xmm1, xmmword ptr [rsi + 80]",
            "por xmm0, xmm1",
            "movdqu xmm1, xmmword ptr [rdi + 3072]",
            "pand xmm1, xmmword ptr [rsi + 96]",
            "por xmm0, xmm1",
            "movdqu xmm1, xmmword ptr [rdi + 3584]",
            "pand xmm1, xmmword ptr [rsi + 112]",
            "por xmm0, xmm1",
            "movdqu xmm1, xmmword ptr [rdi + 4096]",
            "pand xmm1, xmmword ptr [rsi + 128]",
            "por xmm0, xmm1",
            "movdqu xmm1, xmmword ptr [rdi + 4608]",
            "pand xmm1, xmmword ptr [rsi + 144]",
            "por xmm0, xmm1",
            "movdqu xmm1, xmmword ptr [rdi + 5120]",
            "pand xmm1, xmmword ptr [rsi + 160]",
            "por xmm0, xmm1",
            "movdqu xmm1, xmmword ptr [rdi + 5632]",
            "pand xmm1, xmmword ptr [rsi + 176]",
            "por xmm0, xmm1",
            "movdqu xmm1, xmmword ptr [rdi + 6144]",
            "pand xmm1, xmmword ptr [rsi + 192]",
            "por xmm0, xmm1",
            "movdqu xmm1, xmmword ptr [rdi + 6656]",
            "pand xmm1, xmmword ptr [rsi + 208]",
            "por xmm0, xmm1",
            "movdqu xmm1, xmmword ptr [rdi + 7168]",
            "pand xmm1, xmmword ptr [rsi + 224]",
            "por xmm0, xmm1",
            "movdqu xmm1, xmmword ptr [rdi + 7680]",
            "pand xmm1, xmmword ptr [rsi + 240]",
            "por xmm0, xmm1",
            "movdqu xmmword ptr [rdx], xmm0",
            "lea rdi, [rdi + 16]",
            "lea rdx, [rdx + 16]",
            "lea rcx, [rcx + 1]",
            "jrcxz 3f",
            "jmp 2b",
            "3:",
            inout("rdi") table.as_ptr() => _,
            in("rsi") lanes.0.as_ptr(),
            inout("rdx") out.as_mut_ptr() => _,
            inout("rcx") count => _,
            out("xmm0") _,
            out("xmm1") _,
            options(nostack),
        );
    }
    // Which mask was set is the secret digit.
    ic_core::Zeroize::zeroize(&mut lanes.0);
    true
}

/// `out = r - n` if `top` is set or `r >= n`, else `r`, over `l` words: the
/// one conditional subtraction that ends every product, as `uint::finish`
/// does in Rust, where `r` is below `2n`.
///
/// The subtraction runs on one borrow chain; the choice is a mask, applied
/// to every word whichever way it goes, and not a branch or a conditional
/// move. The loops count `l / 4` in rcx with `lea` and `jrcxz`, which leave
/// the borrow alone.
///
/// # Safety
///
/// `out` must be valid for writing `l` words, `r` and `n` for reading `l`,
/// `out` overlapping neither; `top` zero or one; `l` a non-zero multiple of
/// four. Uses SSE2, which every x86-64 CPU has.
unsafe fn finish(out: *mut u64, r: *const u64, top: u64, n: *const u64, l: usize) {
    let count = (l / 4).wrapping_neg();
    // SAFETY: the first loop reads `r[0..l]` and `n[0..l]` and writes
    // `out[0..l]`, four words an iteration; the second reads `r[0..l]` and
    // reads and writes `out[0..l]` again.
    unsafe {
        asm!(
            "mov r8, rsi",
            "mov r9, rdx",
            "mov r10, rcx",
            // out = r - n.
            "xor eax, eax",
            "2:",
            "mov rax, qword ptr [rsi]",
            "sbb rax, qword ptr [rdi]",
            "mov qword ptr [rdx], rax",
            "mov rax, qword ptr [rsi + 8]",
            "sbb rax, qword ptr [rdi + 8]",
            "mov qword ptr [rdx + 8], rax",
            "mov rax, qword ptr [rsi + 16]",
            "sbb rax, qword ptr [rdi + 16]",
            "mov qword ptr [rdx + 16], rax",
            "mov rax, qword ptr [rsi + 24]",
            "sbb rax, qword ptr [rdi + 24]",
            "mov qword ptr [rdx + 24], rax",
            "lea rsi, [rsi + 32]",
            "lea rdi, [rdi + 32]",
            "lea rdx, [rdx + 32]",
            "lea rcx, [rcx + 1]",
            "jrcxz 3f",
            "jmp 2b",
            "3:",
            // Keep r, all ones, when the subtraction borrowed and nothing
            // overflowed: -borrow & (top - 1).
            "sbb rax, rax",
            "lea r11, [r11 - 1]",
            "and rax, r11",
            "movq xmm0, rax",
            "punpcklqdq xmm0, xmm0",
            // out ^= (out ^ r) & keep.
            "mov rcx, r10",
            "4:",
            "movdqu xmm1, xmmword ptr [r9]",
            "movdqu xmm2, xmmword ptr [r8]",
            "pxor xmm2, xmm1",
            "pand xmm2, xmm0",
            "pxor xmm1, xmm2",
            "movdqu xmmword ptr [r9], xmm1",
            "movdqu xmm1, xmmword ptr [r9 + 16]",
            "movdqu xmm2, xmmword ptr [r8 + 16]",
            "pxor xmm2, xmm1",
            "pand xmm2, xmm0",
            "pxor xmm1, xmm2",
            "movdqu xmmword ptr [r9 + 16], xmm1",
            "lea r8, [r8 + 32]",
            "lea r9, [r9 + 32]",
            "lea rcx, [rcx + 1]",
            "jrcxz 5f",
            "jmp 4b",
            "5:",
            inout("rdx") out => _,
            inout("rsi") r => _,
            inout("rdi") n => _,
            inout("rcx") count => _,
            inout("r11") top => _,
            out("rax") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("xmm0") _,
            out("xmm1") _,
            out("xmm2") _,
            options(nostack),
        );
    }
}

/// See the module docs.
///
/// # Safety
///
/// The CPU must support BMI2 and ADX. `a`, `b` and `n` must be valid for
/// reading `l` words, `t` for reading and writing `2l + 2` words and zeroed,
/// none of `a`, `b`, `n` may overlap `t`, and `l` must be a non-zero multiple
/// of four.
#[target_feature(enable = "bmi2,adx")]
unsafe fn mont_mul_adx(
    t: *mut u64,
    a: *const u64,
    b: *const u64,
    n: *const u64,
    n0inv: u64,
    l: usize,
) {
    // Pointers one past the end of `a` and `n`, and to `t[l]`: the inner loops
    // address `[end + rcx*8]` with `rcx` running from `-l` to `-4`, which is
    // the `l` words below each pointer. `t` slides up one word per row, so
    // after row `i` it points at `t[l + i + 1]`; the highest word any row
    // touches is `[t + 8]` on the last row, `t[2l + 1]`.
    //
    // SAFETY: `l` words past `a` and `n` and `l` words into `t` are in bounds
    // (or one past the end), as the caller guarantees.
    let (a_end, n_end, t_mid) = unsafe { (a.add(l), n.add(l), t.add(l)) };
    let neg = l.wrapping_neg();

    // SAFETY: every memory operand is one of:
    // - `[a_end + rcx*8 + k]` and `[n_end + rcx*8 + k]`, `rcx` in `-l..=-4`
    //   stepping by four, `k` in `0, 8, 16, 24`: words `0..l` of `a` and `n`;
    // - `[b]`, with `b` advanced one word per row for `l` rows: `b[0..l]`;
    // - `[t + rcx*8 + k]`, `[t]` and `[t + 8]`, with `t` at `t_mid + 8i` on
    //   row `i`: words `i..=l + i + 1` of the `2l + 2`-word buffer.
    // Nothing is pushed; `rcx`, `rdx` and `rax` are declared clobbered, and
    // the flags are clobbered by default.
    unsafe {
        asm!(
            // Outer loop: one row per word of `b`.
            "2:",
            "mov rdx, [{b}]",
            "lea {b}, [{b} + 8]",
            // Pass A: t[0..=l+1] += a * b[i]. `xor` clears CF and OF.
            "xor {h0:e}, {h0:e}",
            "3:",
            "mulx {h1}, rax, [{a} + rcx*8]",
            "adcx rax, [{t} + rcx*8]",
            "adox rax, {h0}",
            "mov [{t} + rcx*8], rax",
            "mulx {h0}, rax, [{a} + rcx*8 + 8]",
            "adcx rax, [{t} + rcx*8 + 8]",
            "adox rax, {h1}",
            "mov [{t} + rcx*8 + 8], rax",
            "mulx {h1}, rax, [{a} + rcx*8 + 16]",
            "adcx rax, [{t} + rcx*8 + 16]",
            "adox rax, {h0}",
            "mov [{t} + rcx*8 + 16], rax",
            "mulx {h0}, rax, [{a} + rcx*8 + 24]",
            "adcx rax, [{t} + rcx*8 + 24]",
            "adox rax, {h1}",
            "mov [{t} + rcx*8 + 24], rax",
            "lea rcx, [rcx + 4]",
            "jrcxz 4f",
            "jmp 3b",
            "4:",
            // t[l] += CF + hi + OF; t[l+1] = the two carries out. t[l+1] is
            // zero on entry: no earlier row reached it.
            "mov rax, [{t}]",
            "adcx rax, {zero}",
            "adox rax, {h0}",
            "mov [{t}], rax",
            "mov {h1:e}, 0",
            "adcx {h1}, {zero}",
            "adox {h1}, {zero}",
            "mov [{t} + 8], {h1}",
            // Pass B: t += u * n with u = t[0] * n0inv, which zeroes t[0].
            // `imul` sets flags, so it comes before the `xor` that clears them.
            "mov rcx, {neg}",
            "mov rdx, [{t} + rcx*8]",
            "imul rdx, {n0inv}",
            "xor {h0:e}, {h0:e}",
            "5:",
            "mulx {h1}, rax, [{n} + rcx*8]",
            "adcx rax, [{t} + rcx*8]",
            "adox rax, {h0}",
            "mov [{t} + rcx*8], rax",
            "mulx {h0}, rax, [{n} + rcx*8 + 8]",
            "adcx rax, [{t} + rcx*8 + 8]",
            "adox rax, {h1}",
            "mov [{t} + rcx*8 + 8], rax",
            "mulx {h1}, rax, [{n} + rcx*8 + 16]",
            "adcx rax, [{t} + rcx*8 + 16]",
            "adox rax, {h0}",
            "mov [{t} + rcx*8 + 16], rax",
            "mulx {h0}, rax, [{n} + rcx*8 + 24]",
            "adcx rax, [{t} + rcx*8 + 24]",
            "adox rax, {h1}",
            "mov [{t} + rcx*8 + 24], rax",
            "lea rcx, [rcx + 4]",
            "jrcxz 6f",
            "jmp 5b",
            "6:",
            "mov rax, [{t}]",
            "adcx rax, {zero}",
            "adox rax, {h0}",
            "mov [{t}], rax",
            "mov {h1}, [{t} + 8]",
            "adcx {h1}, {zero}",
            "adox {h1}, {zero}",
            "mov [{t} + 8], {h1}",
            // The zeroed word drops off the bottom: slide the window up one.
            "mov rcx, {neg}",
            "lea {t}, [{t} + 8]",
            "dec {rows}",
            "jnz 2b",
            a = in(reg) a_end,
            n = in(reg) n_end,
            b = inout(reg) b => _,
            t = inout(reg) t_mid => _,
            rows = inout(reg) l => _,
            neg = in(reg) neg,
            n0inv = in(reg) n0inv,
            zero = in(reg) 0u64,
            h0 = out(reg) _,
            h1 = out(reg) _,
            inout("rcx") neg => _,
            out("rdx") _,
            out("rax") _,
            options(nostack),
        );
    }
}

// ---------------------------------------------------------------------------
// Eight-word blocks, for widths that are a multiple of eight: every RSA
// modulus this crate accepts and every one of their primes.
//
// The product (or the square) is made in full, into `t[0..2L]`, and then
// reduced; the two are separate, as `uint::sqr` is in Rust. All of it is
// built from one step, repeated:
//
//   rdx = one word x of the operand being streamed;
//   W += A * x, where A is eight words read from memory and W is a window of
//   eight registers over eight consecutive columns of `t`;
//   the lowest column of W is then final: it is stored, and its register
//   becomes the window's new top.
//
// The eight products of a step go into the window as two carry chains, low
// words on CF (`adcx`) and high words on OF (`adox`). Both chains end in the
// new top word, which cannot overflow: eight words, plus eight words times
// one, plus one word, is below 2^576. So no carry outlives its step, and each
// step starts its chains afresh with `xor`, which also breaks the dependency
// of one step's flags on the last's. Eight registers rotate through the eight
// positions of the window, so eight steps -- a group -- bring the assignment
// back where it started, and a group is the body of each loop.
//
// The window holds what is added to a column, not the column: a column's
// earlier value, where it has one, is added on the OF chain as the column
// leaves, so nothing above the window is read or carried into while it moves.
// The first block of a product or square writes columns nothing has written,
// and does not read them (`fresh`); the blocks after it add (`acc`). So `t`
// needs no clearing: clearing it with vector stores just before the 64-bit
// loads that read it back costs more than the reads themselves.
//
// At the end of a block the window is added to the eight columns above it,
// with the carry from the block before, and the carry out is returned for the
// block after, whose window ends exactly where this one's did plus eight.
// For the product and the square those eight columns have not been written
// (the carry in stands for the only one that has), and are only stored; the
// reduction adds them to the product's upper half.
//
// Registers, in every kernel: the window in r8-r15; rdx the multiplier; rax
// and rcx the low and high words of the first product of a step; rdi the
// eight words A; rsi the streamed operand; rbx the column leaving the window;
// rbp the group count; the carry in on the stack. rbx and rbp cannot be named
// as operands, so the kernels save them on the stack and restore them.
//
// Constant time: as for the kernel above, every branch is on a group count
// derived from `L`, every address a base pointer plus a constant, and every
// instruction of fixed latency.
// ---------------------------------------------------------------------------

/// One product of a step after its first: `t:rax = A[off] * rdx`, the low
/// word into the CF chain at `lo`, the high word into the OF chain at `hi`.
macro_rules! mid {
    ($a:literal, $off:literal, $t:literal, $lo:literal, $hi:literal) => {
        concat!(
            "mulx ",
            $t,
            ", rax, qword ptr [",
            $a,
            " + ",
            $off,
            "]\n",
            "adcx ",
            $lo,
            ", rax\n",
            "adox ",
            $hi,
            ", ",
            $t,
            "\n",
        )
    };
}

/// Products one to seven of a full step, the window `r0..r7` with `r0`
/// already stored and free; the last high word lands in `r0`, the new top,
/// and both chains end there.
macro_rules! tail {
    ($a:literal, $r0:literal, $r1:literal, $r2:literal, $r3:literal,
     $r4:literal, $r5:literal, $r6:literal, $r7:literal) => {
        concat!(
            mid!($a, "8", $r0, $r1, $r2),
            mid!($a, "16", $r0, $r2, $r3),
            mid!($a, "24", $r0, $r3, $r4),
            mid!($a, "32", $r0, $r4, $r5),
            mid!($a, "40", $r0, $r5, $r6),
            mid!($a, "48", $r0, $r6, $r7),
            "mulx ",
            $r0,
            ", rax, qword ptr [",
            $a,
            " + 56]\n",
            "adcx ",
            $r7,
            ", rax\n",
            "mov eax, 0\n",
            "adcx ",
            $r0,
            ", rax\n",
            "adox ",
            $r0,
            ", rax\n",
        )
    };
}

/// The lowest column, `r0`, leaves the window into `[rbx + d]`: added to what
/// is there on the OF chain (`acc`), or written over it (`fresh`).
macro_rules! retire {
    (acc, $d:literal, $r0:literal) => {
        concat!(
            "adox ",
            $r0,
            ", qword ptr [rbx + ",
            $d,
            "]\n",
            "mov qword ptr [rbx + ",
            $d,
            "], ",
            $r0,
            "\n",
        )
    };
    (fresh, $d:literal, $r0:literal) => {
        concat!("mov qword ptr [rbx + ", $d, "], ", $r0, "\n")
    };
}

/// A full step: `rdx = [rsi + d]`, the window `r0..r7` += `[rdi..] * rdx`,
/// and the lowest column leaves into `[rbx + d]`.
macro_rules! step {
    ($m:ident, $d:literal, $r0:literal, $r1:literal, $r2:literal, $r3:literal,
     $r4:literal, $r5:literal, $r6:literal, $r7:literal) => {
        concat!(
            "mov rdx, qword ptr [rsi + ",
            $d,
            "]\n",
            "xor eax, eax\n",
            "mulx rcx, rax, qword ptr [rdi]\n",
            "adcx ",
            $r0,
            ", rax\n",
            retire!($m, $d, $r0),
            "adox ",
            $r1,
            ", rcx\n",
            tail!("rdi", $r0, $r1, $r2, $r3, $r4, $r5, $r6, $r7),
        )
    };
}

/// Eight full steps, the registers rotating one place a step.
macro_rules! group {
    ($m:ident, $r0:literal, $r1:literal, $r2:literal, $r3:literal,
     $r4:literal, $r5:literal, $r6:literal, $r7:literal) => {
        concat!(
            step!($m, "0", $r0, $r1, $r2, $r3, $r4, $r5, $r6, $r7),
            step!($m, "8", $r1, $r2, $r3, $r4, $r5, $r6, $r7, $r0),
            step!($m, "16", $r2, $r3, $r4, $r5, $r6, $r7, $r0, $r1),
            step!($m, "24", $r3, $r4, $r5, $r6, $r7, $r0, $r1, $r2),
            step!($m, "32", $r4, $r5, $r6, $r7, $r0, $r1, $r2, $r3),
            step!($m, "40", $r5, $r6, $r7, $r0, $r1, $r2, $r3, $r4),
            step!($m, "48", $r6, $r7, $r0, $r1, $r2, $r3, $r4, $r5),
            step!($m, "56", $r7, $r0, $r1, $r2, $r3, $r4, $r5, $r6),
        )
    };
}

/// The loop over the groups of a block, `rbp` of them, advancing the stream
/// and the leaving column by eight words a group. The count is tested at the
/// top, so a block with no full groups runs none.
macro_rules! groups {
    ($m:ident, $r0:literal, $r1:literal, $r2:literal, $r3:literal,
     $r4:literal, $r5:literal, $r6:literal, $r7:literal) => {
        concat!(
            "2:\n",
            "test rbp, rbp\n",
            "jz 3f\n",
            group!($m, $r0, $r1, $r2, $r3, $r4, $r5, $r6, $r7),
            "lea rsi, [rsi + 64]\n",
            "lea rbx, [rbx + 64]\n",
            "dec rbp\n",
            "jmp 2b\n",
            "3:\n",
        )
    };
}

/// The end of a block: CF = the carry in, from the top of the stack; the
/// window `r0..r7` into `[rbx..rbx + 64]`, added to what is there (`acc`) or
/// with the carry alone (`fresh`); the carry out into `rax`.
macro_rules! merge {
    (acc, $r0:literal, $r1:literal, $r2:literal, $r3:literal,
     $r4:literal, $r5:literal, $r6:literal, $r7:literal) => {
        concat!(
            "mov rax, qword ptr [rsp]\n",
            "neg rax\n",
            merge!(@word "qword ptr [rbx]", "[rbx]", $r0),
            merge!(@word "qword ptr [rbx + 8]", "[rbx + 8]", $r1),
            merge!(@word "qword ptr [rbx + 16]", "[rbx + 16]", $r2),
            merge!(@word "qword ptr [rbx + 24]", "[rbx + 24]", $r3),
            merge!(@word "qword ptr [rbx + 32]", "[rbx + 32]", $r4),
            merge!(@word "qword ptr [rbx + 40]", "[rbx + 40]", $r5),
            merge!(@word "qword ptr [rbx + 48]", "[rbx + 48]", $r6),
            merge!(@word "qword ptr [rbx + 56]", "[rbx + 56]", $r7),
            "mov eax, 0\n",
            "adc eax, 0\n",
        )
    };
    (fresh, $r0:literal, $r1:literal, $r2:literal, $r3:literal,
     $r4:literal, $r5:literal, $r6:literal, $r7:literal) => {
        concat!(
            "mov rax, qword ptr [rsp]\n",
            "neg rax\n",
            merge!(@word "0", "[rbx]", $r0),
            merge!(@word "0", "[rbx + 8]", $r1),
            merge!(@word "0", "[rbx + 16]", $r2),
            merge!(@word "0", "[rbx + 24]", $r3),
            merge!(@word "0", "[rbx + 32]", $r4),
            merge!(@word "0", "[rbx + 40]", $r5),
            merge!(@word "0", "[rbx + 48]", $r6),
            merge!(@word "0", "[rbx + 56]", $r7),
            "mov eax, 0\n",
            "adc eax, 0\n",
        )
    };
    (@word $src:literal, $dst:literal, $r:literal) => {
        concat!("adc ", $r, ", ", $src, "\n", "mov qword ptr ", $dst, ", ", $r, "\n")
    };
}

/// A reduction step: the quotient word `u = r0 * n0inv`, with `n0inv` in
/// rbx, replaces the leaving column at `[rdi + d]`, and the window += `n[0..8]
/// * u` from `[rsi..]`, which makes the leaving column zero. The eight columns
/// a block's quotients come from are loaded into the window before its first
/// step, so `r0` is the whole column.
macro_rules! rstep {
    ($d:literal, $r0:literal, $r1:literal, $r2:literal, $r3:literal,
     $r4:literal, $r5:literal, $r6:literal, $r7:literal) => {
        concat!(
            "mov rdx, ",
            $r0,
            "\n",
            "imul rdx, rbx\n",
            "mov qword ptr [rdi + ",
            $d,
            "], rdx\n",
            "xor eax, eax\n",
            "mulx rcx, rax, qword ptr [rsi]\n",
            "adcx ",
            $r0,
            ", rax\n",
            "adox ",
            $r1,
            ", rcx\n",
            tail!("rsi", $r0, $r1, $r2, $r3, $r4, $r5, $r6, $r7),
        )
    };
}

/// The first product of a partial step of the square: `rdx = A[m]`, `A[0] *
/// rdx` into the window, and the lowest column leaves into `[rbx + d]`.
macro_rules! phead {
    ($mode:ident, $m:literal, $d:literal, $r0:literal, $r1:literal) => {
        concat!(
            "mov rdx, qword ptr [rdi + ",
            $m,
            "]\n",
            "xor eax, eax\n",
            "mulx rcx, rax, qword ptr [rdi]\n",
            "adcx ",
            $r0,
            ", rax\n",
            retire!($mode, $d, $r0),
            "adox ",
            $r1,
            ", rcx\n",
        )
    };
}

/// The last product of a partial step, `A[off] * rdx`: its high word straight
/// into `top`, which nothing has reached yet, both chains closed there, and
/// the freed register `r0` cleared to be the window's new, empty, top.
macro_rules! plast {
    ($off:literal, $lo:literal, $top:literal, $r0:literal) => {
        concat!(
            "mulx ",
            $top,
            ", rax, qword ptr [rdi + ",
            $off,
            "]\n",
            "adcx ",
            $lo,
            ", rax\n",
            "mov eax, 0\n",
            "adcx ",
            $top,
            ", rax\n",
            "adox ",
            $top,
            ", rax\n",
            "mov ",
            $r0,
            ", 0\n",
        )
    };
}

/// One word of the square's diagonal: the two columns `[rsi + z]` and
/// `[rsi + z8]` doubled on the CF chain, and `A[a]^2` added on the OF chain.
macro_rules! diag_word {
    ($a:literal, $z:literal, $z8:literal) => {
        concat!(
            "mov rdx, qword ptr [rdi + ",
            $a,
            "]\n",
            "mulx r9, r8, rdx\n",
            "mov r10, qword ptr [rsi + ",
            $z,
            "]\n",
            "mov r11, qword ptr [rsi + ",
            $z8,
            "]\n",
            "adcx r10, r10\n",
            "adcx r11, r11\n",
            "adox r10, r8\n",
            "adox r11, r9\n",
            "mov qword ptr [rsi + ",
            $z,
            "], r10\n",
            "mov qword ptr [rsi + ",
            $z8,
            "], r11\n",
        )
    };
}

/// The product `a * b`, `2L` words, into `t`, a block of eight words of `b`
/// at a time, then reduced. The result is in `t[L..=2L]`, as from
/// [`mont_mul_adx`]. `t` need not be cleared.
///
/// # Safety
///
/// The CPU must support BMI2 and ADX. `a`, `b` and `n` must be valid for
/// reading `l` words, `t` for reading and writing `2l + 1` words, none of
/// them may overlap `t`, and `l` must be a non-zero multiple of eight.
#[target_feature(enable = "bmi2,adx")]
unsafe fn mont_mul_8n(
    t: *mut u64,
    a: *const u64,
    b: *const u64,
    n: *const u64,
    n0inv: u64,
    l: usize,
) {
    let g = l / 8;
    // SAFETY: block `k` reads `b[8k..8k + 8]` and `a[0..l]`, and writes (block
    // 0) or reads and writes (the rest) `t[8k..8k + l + 8]`, the highest
    // `t[2l - 1]`.
    let mut carry = unsafe { mul_block_first(t, b, a, g, 0) };
    for k in 1..g {
        // SAFETY: as above.
        carry = unsafe { mul_block(t.add(8 * k), b.add(8 * k), a, g, carry) };
    }
    // The product is below 2^(128L): nothing carries out of the top block.
    let _ = carry;
    // SAFETY: as the caller guarantees; all of `t[0..2l]` has been written.
    unsafe { redc_8n(t, n, n0inv, l) };
}

/// The square of `a` into `t`, then reduced. The result is in `t[L..=2L]`.
/// `t` need not be cleared.
///
/// The cross products `a[i] * a[j]`, `i < j`, each once: for each block `I`
/// of eight words, the triangle inside it and the rectangle of it times the
/// words above it, in one pass; then doubled, and the squares `a[i]^2` added
/// on the diagonal. Of the `L^2` products of a multiplication that leaves
/// `L(L - 1)/2 + L`.
///
/// # Safety
///
/// As for [`mont_mul_8n`], with `a` for both operands.
#[target_feature(enable = "bmi2,adx")]
unsafe fn mont_sqr_8n(t: *mut u64, a: *const u64, n: *const u64, n0inv: u64, l: usize) {
    let g = l / 8;
    // No cross product lands in column 0.
    // SAFETY: `t[0]` is in bounds.
    unsafe { *t = 0 };
    // SAFETY: block `i` reads `a[8i..l]`, and writes (block 0) or reads and
    // writes (the rest) `t[16i + 1..8i + l + 8]`, the highest `t[2l - 1]`.
    let mut carry = unsafe { sqr_block_first(t.add(1), a, g - 1, 0) };
    for i in 1..g {
        // SAFETY: as above.
        carry = unsafe { sqr_block(t.add(16 * i + 1), a.add(8 * i), g - 1 - i, carry) };
    }
    // The cross products are below 2^(128L - 1).
    let _ = carry;
    // SAFETY: reads `a[0..l]`, reads and writes `t[0..2l]`.
    unsafe { diag(t, a, g) };
    // SAFETY: as the caller guarantees.
    unsafe { redc_8n(t, n, n0inv, l) };
}

/// Montgomery reduction of the `2L`-word `t` in place, eight words of
/// quotient at a time: the result, below `2n`, in `t[L..=2L]`.
///
/// # Safety
///
/// The CPU must support BMI2 and ADX. `n` must be valid for reading `l`
/// words and `t` for reading and writing `2l + 1`, not overlapping, and `l`
/// a non-zero multiple of eight.
#[target_feature(enable = "bmi2,adx")]
unsafe fn redc_8n(t: *mut u64, n: *const u64, n0inv: u64, l: usize) {
    let g = l / 8;
    let mut carry = 0u64;
    for k in 0..g {
        // SAFETY: block `k` reads `n[0..l]` and reads and writes
        // `t[8k..8k + l + 8]`, the highest `t[2l - 1]`.
        carry = unsafe { redc_block(t.add(8 * k), n, n0inv, g - 1, carry) };
    }
    // SAFETY: `t[2l]` is in bounds.
    unsafe { *t.add(2 * l) = carry };
}

/// The two forms of a block of the product.
macro_rules! mul_block_fn {
    ($(#[$doc:meta])* $name:ident, $m:ident) => {
        $(#[$doc])*
        ///
        /// # Safety
        ///
        /// BMI2 and ADX; `a8` valid for reading 8 words, `s` for `8g`, `z`
        /// for reading and writing `8g + 8`; `z` overlapping neither;
        /// `carry` zero or one; `g` at least one.
        #[target_feature(enable = "bmi2,adx")]
        unsafe fn $name(z: *mut u64, a8: *const u64, s: *const u64, g: usize, carry: u64) -> u64 {
            let out: u64;
            // SAFETY: the steps read `[rdi + 0..64]`, `a8`; `[rsi + 0..64]`
            // in each of `g` groups, `s` advanced 64 bytes a group; and write,
            // or read and write, `[rbx + 0..64]` likewise from `z`. The merge
            // writes the eight words after those, `z[8g..8g + 8]`. rbx and
            // rbp are restored, and the carry popped; everything else
            // written is declared.
            unsafe {
                asm!(
                    "push rbx",
                    "push rbp",
                    "push rdx",
                    "mov rbx, rax",
                    "mov rbp, rcx",
                    "xor r8d, r8d",
                    "xor r9d, r9d",
                    "xor r10d, r10d",
                    "xor r11d, r11d",
                    "xor r12d, r12d",
                    "xor r13d, r13d",
                    "xor r14d, r14d",
                    "xor r15d, r15d",
                    groups!($m, "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
                    merge!(fresh, "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
                    "pop rdx",
                    "pop rbp",
                    "pop rbx",
                    inout("rax") z => out,
                    inout("rcx") g => _,
                    inout("rdi") a8 => _,
                    inout("rsi") s => _,
                    inout("rdx") carry => _,
                    out("r8") _,
                    out("r9") _,
                    out("r10") _,
                    out("r11") _,
                    out("r12") _,
                    out("r13") _,
                    out("r14") _,
                    out("r15") _,
                );
            }
            out
        }
    };
}

mul_block_fn!(
    /// The first block of the product: `z[0..8g + 8] = a8[0..8] * s[0..8g]`
    /// plus the carry in at `z[8g]`, writing `z` without reading it; returns
    /// the carry out of `z[8g + 7]`.
    mul_block_first,
    fresh
);

mul_block_fn!(
    /// A later block of the product: `z[0..8g]` += `a8[0..8] * s[0..8g]`,
    /// and the eight columns above, which only the carry in has reached,
    /// written; returns the carry out of `z[8g + 7]`.
    mul_block,
    acc
);

/// The two forms of a block of the square.
macro_rules! sqr_block_fn {
    ($(#[$doc:meta])* $name:ident, $m:ident) => {
        $(#[$doc])*
        ///
        /// # Safety
        ///
        /// BMI2 and ADX; `a8` valid for reading `8g + 8` words, `z` for
        /// reading and writing `8g + 15`, not overlapping; `carry` zero or
        /// one.
        #[target_feature(enable = "bmi2,adx")]
        unsafe fn $name(z: *mut u64, a8: *const u64, g: usize, carry: u64) -> u64 {
            let out: u64;
            // SAFETY: the partial steps read `a8[0..8]` and write, or read
            // and write, `z[0..7]`; the groups read `a8[8..8g + 8]` and
            // write, or read and write, `z[7..8g + 7]`; the merge writes
            // `z[8g + 7..8g + 15]`.
            unsafe {
                asm!(
                    "push rbx",
                    "push rbp",
                    "push rdx",
                    "mov rbx, rax",
                    "mov rbp, rcx",
                    "lea rsi, [rdi + 64]",
                    "xor r8d, r8d",
                    "xor r9d, r9d",
                    "xor r10d, r10d",
                    "xor r11d, r11d",
                    "xor r12d, r12d",
                    "xor r13d, r13d",
                    "xor r14d, r14d",
                    "xor r15d, r15d",
                    // The triangle: step i multiplies A[i] by A[0..i]. The
                    // window starts at the column of A[0] * A[1].
                    // i = 1: one product, its high word straight into r9.
                    "mov rdx, qword ptr [rdi + 8]",
                    "xor eax, eax",
                    "mulx r9, rax, qword ptr [rdi]",
                    "adcx r8, rax",
                    retire!($m, "0", "r8"),
                    "mov eax, 0",
                    "adcx r9, rax",
                    "adox r9, rax",
                    "mov r8, 0",
                    // i = 2
                    phead!($m, "16", "8", "r9", "r10"),
                    plast!("8", "r10", "r11", "r9"),
                    // i = 3
                    phead!($m, "24", "16", "r10", "r11"),
                    mid!("rdi", "8", "r10", "r11", "r12"),
                    plast!("16", "r12", "r13", "r10"),
                    // i = 4
                    phead!($m, "32", "24", "r11", "r12"),
                    mid!("rdi", "8", "r11", "r12", "r13"),
                    mid!("rdi", "16", "r11", "r13", "r14"),
                    plast!("24", "r14", "r15", "r11"),
                    // i = 5
                    phead!($m, "40", "32", "r12", "r13"),
                    mid!("rdi", "8", "r12", "r13", "r14"),
                    mid!("rdi", "16", "r12", "r14", "r15"),
                    mid!("rdi", "24", "r12", "r15", "r8"),
                    plast!("32", "r8", "r9", "r12"),
                    // i = 6
                    phead!($m, "48", "40", "r13", "r14"),
                    mid!("rdi", "8", "r13", "r14", "r15"),
                    mid!("rdi", "16", "r13", "r15", "r8"),
                    mid!("rdi", "24", "r13", "r8", "r9"),
                    mid!("rdi", "32", "r13", "r9", "r10"),
                    plast!("40", "r10", "r11", "r13"),
                    // i = 7
                    phead!($m, "56", "48", "r14", "r15"),
                    mid!("rdi", "8", "r14", "r15", "r8"),
                    mid!("rdi", "16", "r14", "r8", "r9"),
                    mid!("rdi", "24", "r14", "r9", "r10"),
                    mid!("rdi", "32", "r14", "r10", "r11"),
                    mid!("rdi", "40", "r14", "r11", "r12"),
                    plast!("48", "r12", "r13", "r14"),
                    // The rectangle: A times the words above it, from the
                    // column of A[0] * a8[8], seven columns up.
                    "lea rbx, [rbx + 56]",
                    groups!($m, "r15", "r8", "r9", "r10", "r11", "r12", "r13", "r14"),
                    merge!(fresh, "r15", "r8", "r9", "r10", "r11", "r12", "r13", "r14"),
                    "pop rdx",
                    "pop rbp",
                    "pop rbx",
                    inout("rax") z => out,
                    inout("rcx") g => _,
                    inout("rdi") a8 => _,
                    inout("rdx") carry => _,
                    out("rsi") _,
                    out("r8") _,
                    out("r9") _,
                    out("r10") _,
                    out("r11") _,
                    out("r12") _,
                    out("r13") _,
                    out("r14") _,
                    out("r15") _,
                );
            }
            out
        }
    };
}

sqr_block_fn!(
    /// The first block of the square's cross products, with `A = a8[0..8]`
    /// and the `8g` words after it: the products `A[p] * A[q]`, `p < q`, at
    /// column `p + q - 1` of `z`, and `A[p] * a8[8 + j]` at column
    /// `p + j + 7`, written without reading `z`. `z` is `t + 1`: nothing
    /// lands in column 0. Returns the carry out of `z[8g + 14]`.
    sqr_block_first,
    fresh
);

sqr_block_fn!(
    /// A later block `I` of the square's cross products, as
    /// [`sqr_block_first`] but added to `z = t + 16I + 1`, and the eight
    /// columns above, which only the carry in has reached, written.
    sqr_block,
    acc
);

/// `t[0..16g] = 2 t + sum a[i]^2 2^(128 i)`, for `i < 8g`: the doubling of
/// the cross products and the diagonal. The cross products are below
/// `2^(128L - 1)` and the square below `2^(128L)`, so neither chain carries
/// out of the top.
///
/// # Safety
///
/// BMI2 and ADX; `a` valid for reading `8g` words, `t` for reading and
/// writing `16g`, not overlapping; `g` at least one.
#[target_feature(enable = "bmi2,adx")]
unsafe fn diag(t: *mut u64, a: *const u64, g: usize) {
    // Four words of `a` a loop, so `2g` of them, at least two. Both carry
    // chains run the whole length: the loop's count is in rcx, stepped by
    // `lea` and tested by `jrcxz`, and its pointers by `lea`, none of which
    // touches a flag.
    //
    // SAFETY: iteration `j` reads `a[4j..4j + 4]` and reads and writes
    // `t[8j..8j + 8]`, for `j < 2g`.
    unsafe {
        asm!(
            "xor eax, eax",
            "2:",
            diag_word!("0", "0", "8"),
            diag_word!("8", "16", "24"),
            diag_word!("16", "32", "40"),
            diag_word!("24", "48", "56"),
            "lea rdi, [rdi + 32]",
            "lea rsi, [rsi + 64]",
            "lea rcx, [rcx + 1]",
            // `jrcxz` reaches only 127 bytes, so it exits and `jmp` loops.
            "jrcxz 3f",
            "jmp 2b",
            "3:",
            inout("rcx") (2 * g).wrapping_neg() => _,
            inout("rdi") a => _,
            inout("rsi") t => _,
            out("rax") _,
            out("rdx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            options(nostack),
        );
    }
}

/// One block of the reduction: eight quotient words from the eight columns
/// at `z`, each zeroing its column, stored in place of them; then `z[8..]`
/// += those words times `n[8..8g + 8]`; then the window added to
/// `z[8g + 8..8g + 16]` with `carry` in. Returns the carry out, which belongs
/// to `z[8g + 16]`: the next block's merge starts there.
///
/// # Safety
///
/// BMI2 and ADX; `n` valid for reading `8g + 8` words, `z` for reading and
/// writing `8g + 16`, not overlapping; `carry` zero or one.
#[target_feature(enable = "bmi2,adx")]
unsafe fn redc_block(z: *mut u64, n: *const u64, n0inv: u64, g: usize, carry: u64) -> u64 {
    let out: u64;
    // SAFETY: the quotient steps read `n[0..8]` and read and write `z[0..8]`;
    // the groups read `z[0..8]` (the quotients) and `n[8..8g + 8]`, and read
    // and write `z[8..8g + 8]`; the merge reads and writes `z[8g + 8..8g +
    // 16]`. The carry in is pushed and read back from the top of the stack.
    unsafe {
        asm!(
            "push rbx",
            "push rbp",
            "push rdx",
            "mov rbx, rcx",
            "mov rbp, rax",
            "mov r8, qword ptr [rdi]",
            "mov r9, qword ptr [rdi + 8]",
            "mov r10, qword ptr [rdi + 16]",
            "mov r11, qword ptr [rdi + 24]",
            "mov r12, qword ptr [rdi + 32]",
            "mov r13, qword ptr [rdi + 40]",
            "mov r14, qword ptr [rdi + 48]",
            "mov r15, qword ptr [rdi + 56]",
            rstep!("0", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
            rstep!("8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "r8"),
            rstep!("16", "r10", "r11", "r12", "r13", "r14", "r15", "r8", "r9"),
            rstep!("24", "r11", "r12", "r13", "r14", "r15", "r8", "r9", "r10"),
            rstep!("32", "r12", "r13", "r14", "r15", "r8", "r9", "r10", "r11"),
            rstep!("40", "r13", "r14", "r15", "r8", "r9", "r10", "r11", "r12"),
            rstep!("48", "r14", "r15", "r8", "r9", "r10", "r11", "r12", "r13"),
            rstep!("56", "r15", "r8", "r9", "r10", "r11", "r12", "r13", "r14"),
            // The rest of n, by the eight quotients now at [rdi].
            "lea rbx, [rdi + 64]",
            "lea rsi, [rsi + 64]",
            groups!(acc, "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
            merge!(acc, "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
            "pop rdx",
            "pop rbp",
            "pop rbx",
            inout("rdi") z => _,
            inout("rsi") n => _,
            inout("rcx") n0inv => _,
            inout("rax") g => out,
            inout("rdx") carry => _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
        );
    }
    out
}

// ---------------------------------------------------------------------------
// Sixteen words, straight-line: the product and the square at 1024 bits, the
// primes of an RSA-2048 key, which is where signing spends its time.
//
// The same steps as the blocks above, written out for `L = 16` with every
// address a base register plus a constant: no loop, no call between the
// product and the reduction, and so a register left over. rbp holds zero,
// and each step closes its two chains with `adcx`/`adox` of it, one
// instruction fewer than loading a zero into rax; the reduction reads
// `n0inv` and `n` from the stack. The square keeps its last eight columns in
// the window through the doubling and the diagonal, and the carry between
// the two reduction blocks rides in rdi, which by then is free.
// ---------------------------------------------------------------------------

/// Products one to seven of a step and the close of both chains into `r0`,
/// with the zero register rbp.
macro_rules! ztail {
    ($a:literal, $r0:literal, $r1:literal, $r2:literal, $r3:literal,
     $r4:literal, $r5:literal, $r6:literal, $r7:literal) => {
        concat!(
            mid!($a, "8", $r0, $r1, $r2),
            mid!($a, "16", $r0, $r2, $r3),
            mid!($a, "24", $r0, $r3, $r4),
            mid!($a, "32", $r0, $r4, $r5),
            mid!($a, "40", $r0, $r5, $r6),
            mid!($a, "48", $r0, $r6, $r7),
            "mulx ",
            $r0,
            ", rax, qword ptr [",
            $a,
            " + 56]\n",
            "adcx ",
            $r7,
            ", rax\n",
            "adcx ",
            $r0,
            ", rbp\n",
            "adox ",
            $r0,
            ", rbp\n",
        )
    };
}

/// The lowest column leaves into `[z + d]`, as [`retire`] with a base
/// expression.
macro_rules! zretire {
    (acc, $z:literal, $d:literal, $r0:literal) => {
        concat!(
            "adox ",
            $r0,
            ", qword ptr [",
            $z,
            " + ",
            $d,
            "]\n",
            "mov qword ptr [",
            $z,
            " + ",
            $d,
            "], ",
            $r0,
            "\n",
        )
    };
    (fresh, $z:literal, $d:literal, $r0:literal) => {
        concat!("mov qword ptr [", $z, " + ", $d, "], ", $r0, "\n")
    };
}

/// A full step: `rdx = [s + d]`, the window += `[a..] * rdx`, the lowest
/// column out to `[z + d]`.
macro_rules! zstep {
    ($m:ident, $s:literal, $a:literal, $z:literal, $d:literal,
     $r0:literal, $r1:literal, $r2:literal, $r3:literal,
     $r4:literal, $r5:literal, $r6:literal, $r7:literal) => {
        concat!(
            "mov rdx, qword ptr [",
            $s,
            " + ",
            $d,
            "]\n",
            "xor eax, eax\n",
            "mulx rcx, rax, qword ptr [",
            $a,
            "]\n",
            "adcx ",
            $r0,
            ", rax\n",
            zretire!($m, $z, $d, $r0),
            "adox ",
            $r1,
            ", rcx\n",
            ztail!($a, $r0, $r1, $r2, $r3, $r4, $r5, $r6, $r7),
        )
    };
}

/// Eight full steps from the stream at `s`, columns out from `z`.
macro_rules! zgroup {
    ($m:ident, $s:literal, $a:literal, $z:literal,
     $r0:literal, $r1:literal, $r2:literal, $r3:literal,
     $r4:literal, $r5:literal, $r6:literal, $r7:literal) => {
        concat!(
            zstep!($m, $s, $a, $z, "0", $r0, $r1, $r2, $r3, $r4, $r5, $r6, $r7),
            zstep!($m, $s, $a, $z, "8", $r1, $r2, $r3, $r4, $r5, $r6, $r7, $r0),
            zstep!($m, $s, $a, $z, "16", $r2, $r3, $r4, $r5, $r6, $r7, $r0, $r1),
            zstep!($m, $s, $a, $z, "24", $r3, $r4, $r5, $r6, $r7, $r0, $r1, $r2),
            zstep!($m, $s, $a, $z, "32", $r4, $r5, $r6, $r7, $r0, $r1, $r2, $r3),
            zstep!($m, $s, $a, $z, "40", $r5, $r6, $r7, $r0, $r1, $r2, $r3, $r4),
            zstep!($m, $s, $a, $z, "48", $r6, $r7, $r0, $r1, $r2, $r3, $r4, $r5),
            zstep!($m, $s, $a, $z, "56", $r7, $r0, $r1, $r2, $r3, $r4, $r5, $r6),
        )
    };
}

/// The window `r0..r7` stored to `[z..z + 64]`: columns nothing else has
/// reached.
macro_rules! zstore {
    ($z:literal, $r0:literal, $r1:literal, $r2:literal, $r3:literal,
     $r4:literal, $r5:literal, $r6:literal, $r7:literal) => {
        concat!(
            "mov qword ptr [",
            $z,
            "], ",
            $r0,
            "\n",
            "mov qword ptr [",
            $z,
            " + 8], ",
            $r1,
            "\n",
            "mov qword ptr [",
            $z,
            " + 16], ",
            $r2,
            "\n",
            "mov qword ptr [",
            $z,
            " + 24], ",
            $r3,
            "\n",
            "mov qword ptr [",
            $z,
            " + 32], ",
            $r4,
            "\n",
            "mov qword ptr [",
            $z,
            " + 40], ",
            $r5,
            "\n",
            "mov qword ptr [",
            $z,
            " + 48], ",
            $r6,
            "\n",
            "mov qword ptr [",
            $z,
            " + 56], ",
            $r7,
            "\n",
        )
    };
}

/// The window `r0..r7` added to `[z..z + 64]` on one carry chain, the first
/// addition `first` (`add`, or `adc` with the carry in on CF).
macro_rules! zmerge {
    ($first:literal, $z:literal, $r0:literal, $r1:literal, $r2:literal, $r3:literal,
     $r4:literal, $r5:literal, $r6:literal, $r7:literal) => {
        concat!(
            $first,
            " ",
            $r0,
            ", qword ptr [",
            $z,
            "]\n",
            "mov qword ptr [",
            $z,
            "], ",
            $r0,
            "\n",
            "adc ",
            $r1,
            ", qword ptr [",
            $z,
            " + 8]\n",
            "mov qword ptr [",
            $z,
            " + 8], ",
            $r1,
            "\n",
            "adc ",
            $r2,
            ", qword ptr [",
            $z,
            " + 16]\n",
            "mov qword ptr [",
            $z,
            " + 16], ",
            $r2,
            "\n",
            "adc ",
            $r3,
            ", qword ptr [",
            $z,
            " + 24]\n",
            "mov qword ptr [",
            $z,
            " + 24], ",
            $r3,
            "\n",
            "adc ",
            $r4,
            ", qword ptr [",
            $z,
            " + 32]\n",
            "mov qword ptr [",
            $z,
            " + 32], ",
            $r4,
            "\n",
            "adc ",
            $r5,
            ", qword ptr [",
            $z,
            " + 40]\n",
            "mov qword ptr [",
            $z,
            " + 40], ",
            $r5,
            "\n",
            "adc ",
            $r6,
            ", qword ptr [",
            $z,
            " + 48]\n",
            "mov qword ptr [",
            $z,
            " + 48], ",
            $r6,
            "\n",
            "adc ",
            $r7,
            ", qword ptr [",
            $z,
            " + 56]\n",
            "mov qword ptr [",
            $z,
            " + 56], ",
            $r7,
            "\n",
        )
    };
}

/// A reduction step: `u = r0 * n0inv`, with `n0inv` at `[rsp]`, stored over
/// the leaving column at `[z + d]`; the window += `n[0..8] * u`, `n` in rsi.
macro_rules! zrstep {
    ($z:literal, $d:literal, $r0:literal, $r1:literal, $r2:literal, $r3:literal,
     $r4:literal, $r5:literal, $r6:literal, $r7:literal) => {
        concat!(
            "mov rdx, ",
            $r0,
            "\n",
            "imul rdx, qword ptr [rsp]\n",
            "mov qword ptr [",
            $z,
            " + ",
            $d,
            "], rdx\n",
            "xor eax, eax\n",
            "mulx rcx, rax, qword ptr [rsi]\n",
            "adcx ",
            $r0,
            ", rax\n",
            "adox ",
            $r1,
            ", rcx\n",
            ztail!("rsi", $r0, $r1, $r2, $r3, $r4, $r5, $r6, $r7),
        )
    };
}

/// The eight columns at `[z..z + 64]` loaded into the window.
macro_rules! zload {
    ($z:literal) => {
        concat!(
            "mov r8, qword ptr [",
            $z,
            "]\n",
            "mov r9, qword ptr [",
            $z,
            " + 8]\n",
            "mov r10, qword ptr [",
            $z,
            " + 16]\n",
            "mov r11, qword ptr [",
            $z,
            " + 24]\n",
            "mov r12, qword ptr [",
            $z,
            " + 32]\n",
            "mov r13, qword ptr [",
            $z,
            " + 40]\n",
            "mov r14, qword ptr [",
            $z,
            " + 48]\n",
            "mov r15, qword ptr [",
            $z,
            " + 56]\n",
        )
    };
}

/// One block of the reduction of `t` (rbx) at 16 words: the eight columns at
/// `z` give eight quotients, stored over them; `n[8..16]` times those into
/// the eight columns at `z2`; then `pre`, and the window into the eight at
/// `z3`.
macro_rules! zredc_block {
    ($z:literal, $z2:literal, $z3:literal, $pre:literal, $first:literal) => {
        concat!(
            zload!($z),
            zrstep!($z, "0", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
            zrstep!($z, "8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "r8"),
            zrstep!($z, "16", "r10", "r11", "r12", "r13", "r14", "r15", "r8", "r9"),
            zrstep!($z, "24", "r11", "r12", "r13", "r14", "r15", "r8", "r9", "r10"),
            zrstep!($z, "32", "r12", "r13", "r14", "r15", "r8", "r9", "r10", "r11"),
            zrstep!($z, "40", "r13", "r14", "r15", "r8", "r9", "r10", "r11", "r12"),
            zrstep!($z, "48", "r14", "r15", "r8", "r9", "r10", "r11", "r12", "r13"),
            zrstep!($z, "56", "r15", "r8", "r9", "r10", "r11", "r12", "r13", "r14"),
            zgroup!(acc, "rsi + 64", $z, $z2, "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
            $pre,
            zmerge!($first, $z3, "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
        )
    };
}

/// The reduction of the 32-word `t` (rbx) modulo `n` (`[rsp + 8]`): two
/// blocks, the carry between them in rdi, the last carry to `t[32]`.
macro_rules! zredc {
    () => {
        concat!(
            "mov rsi, qword ptr [rsp + 8]\n",
            zredc_block!("rbx", "rbx + 64", "rbx + 128", "", "add"),
            // The carry out of the first block, as 0 or all ones; `neg` puts
            // it back on CF just before the second block's merge.
            "sbb rdi, rdi\n",
            zredc_block!("rbx + 64", "rbx + 128", "rbx + 192", "neg rdi\n", "adc"),
            "mov eax, 0\n",
            "adc eax, 0\n",
            "mov qword ptr [rbx + 256], rax\n",
        )
    };
}

/// The first product of a partial step of the square, with base expressions:
/// `rdx = [a + m]`, `[a] * rdx`, the lowest column out to `[z + d]`.
macro_rules! zphead {
    ($mode:ident, $a:literal, $m:literal, $z:literal, $d:literal, $r0:literal, $r1:literal) => {
        concat!(
            "mov rdx, qword ptr [",
            $a,
            " + ",
            $m,
            "]\n",
            "xor eax, eax\n",
            "mulx rcx, rax, qword ptr [",
            $a,
            "]\n",
            "adcx ",
            $r0,
            ", rax\n",
            zretire!($mode, $z, $d, $r0),
            "adox ",
            $r1,
            ", rcx\n",
        )
    };
}

/// The last product of a partial step, its high word straight into the
/// empty `top`, both chains closed there, and `r0` cleared.
macro_rules! zplast {
    ($a:literal, $off:literal, $lo:literal, $top:literal, $r0:literal) => {
        concat!(
            "mulx ",
            $top,
            ", rax, qword ptr [",
            $a,
            " + ",
            $off,
            "]\n",
            "adcx ",
            $lo,
            ", rax\n",
            "adcx ",
            $top,
            ", rbp\n",
            "adox ",
            $top,
            ", rbp\n",
            "xor ",
            $r0,
            ", ",
            $r0,
            "\n",
        )
    };
}

/// The triangle of the eight words at `a`, steps two to seven: step `i`
/// multiplies `a[i]` by `a[0..i]`, its lowest column out to `[z + 8(i-1)]`.
/// Step one, which differs between the first block and the second, is the
/// caller's.
macro_rules! ztriangle {
    ($mode:ident, $a:literal, $z:literal) => {
        concat!(
            zphead!($mode, $a, "16", $z, "8", "r9", "r10"),
            zplast!($a, "8", "r10", "r11", "r9"),
            zphead!($mode, $a, "24", $z, "16", "r10", "r11"),
            mid!($a, "8", "r10", "r11", "r12"),
            zplast!($a, "16", "r12", "r13", "r10"),
            zphead!($mode, $a, "32", $z, "24", "r11", "r12"),
            mid!($a, "8", "r11", "r12", "r13"),
            mid!($a, "16", "r11", "r13", "r14"),
            zplast!($a, "24", "r14", "r15", "r11"),
            zphead!($mode, $a, "40", $z, "32", "r12", "r13"),
            mid!($a, "8", "r12", "r13", "r14"),
            mid!($a, "16", "r12", "r14", "r15"),
            mid!($a, "24", "r12", "r15", "r8"),
            zplast!($a, "32", "r8", "r9", "r12"),
            zphead!($mode, $a, "48", $z, "40", "r13", "r14"),
            mid!($a, "8", "r13", "r14", "r15"),
            mid!($a, "16", "r13", "r15", "r8"),
            mid!($a, "24", "r13", "r8", "r9"),
            mid!($a, "32", "r13", "r9", "r10"),
            zplast!($a, "40", "r10", "r11", "r13"),
            zphead!($mode, $a, "56", $z, "48", "r14", "r15"),
            mid!($a, "8", "r14", "r15", "r8"),
            mid!($a, "16", "r14", "r8", "r9"),
            mid!($a, "24", "r14", "r9", "r10"),
            mid!($a, "32", "r14", "r10", "r11"),
            mid!($a, "40", "r14", "r11", "r12"),
            zplast!($a, "48", "r12", "r13", "r14"),
        )
    };
}

/// One word of the diagonal from memory: the columns at `[rbx + z]` and
/// `[rbx + z8]` doubled on CF and `a[i]^2` added on OF, through rsi.
macro_rules! zdiag_mem {
    ($a:literal, $z:literal, $z8:literal) => {
        concat!(
            "mov rdx, qword ptr [rdi + ",
            $a,
            "]\n",
            "mulx rcx, rax, rdx\n",
            "mov rsi, qword ptr [rbx + ",
            $z,
            "]\n",
            "adcx rsi, rsi\n",
            "adox rsi, rax\n",
            "mov qword ptr [rbx + ",
            $z,
            "], rsi\n",
            "mov rsi, qword ptr [rbx + ",
            $z8,
            "]\n",
            "adcx rsi, rsi\n",
            "adox rsi, rcx\n",
            "mov qword ptr [rbx + ",
            $z8,
            "], rsi\n",
        )
    };
}

/// One word of the diagonal on two columns still in registers.
macro_rules! zdiag_reg {
    ($a:literal, $z:literal, $z8:literal, $lo:literal, $hi:literal) => {
        concat!(
            "mov rdx, qword ptr [rdi + ",
            $a,
            "]\n",
            "mulx rcx, rax, rdx\n",
            "adcx ",
            $lo,
            ", ",
            $lo,
            "\n",
            "adox ",
            $lo,
            ", rax\n",
            "mov qword ptr [rbx + ",
            $z,
            "], ",
            $lo,
            "\n",
            "adcx ",
            $hi,
            ", ",
            $hi,
            "\n",
            "adox ",
            $hi,
            ", rcx\n",
            "mov qword ptr [rbx + ",
            $z8,
            "], ",
            $hi,
            "\n",
        )
    };
}

/// The Montgomery product at 16 words, straight-line: `t[0..32] = a * b`,
/// then reduced; the result in `t[16..=32]`, as [`mont_mul_8n`] leaves it.
///
/// # Safety
///
/// BMI2 and ADX; `a`, `b` and `n` valid for reading 16 words, `t` for
/// reading and writing 33, `t` overlapping none of them.
#[target_feature(enable = "bmi2,adx")]
unsafe fn mont_mul_16(t: *mut u64, a: *const u64, b: *const u64, n: *const u64, n0inv: u64) {
    // SAFETY: every address is `a`, `b`, `n` plus 0 to 120, `t` plus 0 to
    // 256, or the stack slots pushed here; rbx and rbp are restored and the
    // two slots popped.
    unsafe {
        asm!(
            "push rbx",
            "push rbp",
            "push rdx",
            "push rcx",
            "mov rbx, rax",
            "xor ebp, ebp",
            // b[0..8] * a into columns 0..23, written without reading.
            "xor r8d, r8d",
            "xor r9d, r9d",
            "xor r10d, r10d",
            "xor r11d, r11d",
            "xor r12d, r12d",
            "xor r13d, r13d",
            "xor r14d, r14d",
            "xor r15d, r15d",
            zgroup!(fresh, "rsi", "rdi", "rbx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
            zgroup!(fresh, "rsi + 64", "rdi", "rbx + 64", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
            zstore!("rbx + 128", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
            // b[8..16] * a added into columns 8..31.
            "xor r8d, r8d",
            "xor r9d, r9d",
            "xor r10d, r10d",
            "xor r11d, r11d",
            "xor r12d, r12d",
            "xor r13d, r13d",
            "xor r14d, r14d",
            "xor r15d, r15d",
            zgroup!(acc, "rsi", "rdi + 64", "rbx + 64", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
            zgroup!(acc, "rsi + 64", "rdi + 64", "rbx + 128", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
            zstore!("rbx + 192", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"),
            zredc!(),
            "pop rcx",
            "pop rdx",
            "pop rbp",
            "pop rbx",
            inout("rax") t => _,
            inout("rsi") a => _,
            inout("rdi") b => _,
            inout("rdx") n => _,
            inout("rcx") n0inv => _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
        );
    }
}

/// The Montgomery square at 16 words, straight-line: the cross products of
/// `a` into `t`, doubled, the diagonal added, then reduced; the result in
/// `t[16..=32]`.
///
/// # Safety
///
/// As for [`mont_mul_16`], with `a` for both operands.
#[target_feature(enable = "bmi2,adx")]
unsafe fn mont_sqr_16(t: *mut u64, a: *const u64, n: *const u64, n0inv: u64) {
    // SAFETY: as in `mont_mul_16`.
    unsafe {
        asm!(
            "push rbx",
            "push rbp",
            "push rsi",
            "push rcx",
            "mov rbx, rax",
            "xor ebp, ebp",
            "mov qword ptr [rbx], rbp",
            // The triangle of a[0..8], from column 1, written without
            // reading. Step one: a[0] * a[1], into column 1 and r9.
            "xor r8d, r8d",
            "xor r9d, r9d",
            "xor r10d, r10d",
            "xor r11d, r11d",
            "xor r12d, r12d",
            "xor r13d, r13d",
            "xor r14d, r14d",
            "xor r15d, r15d",
            "mov rdx, qword ptr [rdi + 8]",
            "mulx r9, rax, qword ptr [rdi]",
            "mov qword ptr [rbx + 8], rax",
            ztriangle!(fresh, "rdi", "rbx + 8"),
            // a[0..8] * a[8..16], columns 8 to 15 out, 16 to 23 stored.
            zgroup!(fresh, "rdi + 64", "rdi", "rbx + 64", "r15", "r8", "r9", "r10", "r11", "r12", "r13", "r14"),
            zstore!("rbx + 128", "r15", "r8", "r9", "r10", "r11", "r12", "r13", "r14"),
            // The triangle of a[8..16], added from column 17. Step one: the
            // window is empty, so the low word and the column's value are
            // the whole of column 17, and the high word all of 18.
            "xor r8d, r8d",
            "xor r9d, r9d",
            "xor r10d, r10d",
            "xor r11d, r11d",
            "xor r12d, r12d",
            "xor r13d, r13d",
            "xor r14d, r14d",
            "xor r15d, r15d",
            "mov rdx, qword ptr [rdi + 72]",
            "xor eax, eax",
            "mulx r9, rax, qword ptr [rdi + 64]",
            "adox rax, qword ptr [rbx + 136]",
            "mov qword ptr [rbx + 136], rax",
            "adox r9, rbp",
            ztriangle!(acc, "rdi + 64", "rbx + 136"),
            // Columns 24 to 31 are in r15, r8 .. r14. Double every column and
            // add the squares, from column 0.
            "xor eax, eax",
            zdiag_mem!("0", "0", "8"),
            zdiag_mem!("8", "16", "24"),
            zdiag_mem!("16", "32", "40"),
            zdiag_mem!("24", "48", "56"),
            zdiag_mem!("32", "64", "72"),
            zdiag_mem!("40", "80", "88"),
            zdiag_mem!("48", "96", "104"),
            zdiag_mem!("56", "112", "120"),
            zdiag_mem!("64", "128", "136"),
            zdiag_mem!("72", "144", "152"),
            zdiag_mem!("80", "160", "168"),
            zdiag_mem!("88", "176", "184"),
            zdiag_reg!("96", "192", "200", "r15", "r8"),
            zdiag_reg!("104", "208", "216", "r9", "r10"),
            zdiag_reg!("112", "224", "232", "r11", "r12"),
            zdiag_reg!("120", "240", "248", "r13", "r14"),
            zredc!(),
            "pop rcx",
            "pop rsi",
            "pop rbp",
            "pop rbx",
            inout("rax") t => _,
            inout("rdi") a => _,
            inout("rsi") n => _,
            inout("rcx") n0inv => _,
            out("rdx") _,
            out("r8") _,
            out("r9") _,
            out("r10") _,
            out("r11") _,
            out("r12") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Limbs, MAX_LIMBS};

    /// The product and the square of this backend, at every width a multiple
    /// of eight (the straight-line 16-word kernels and the blocks for the
    /// rest) and some multiples of four (the older kernel), against the
    /// portable CIOS product and portable square: hundreds of moduli a
    /// width, random and with the top word all ones or a lone top bit, and
    /// operands that are random, zero, one, `n - 1`, and all ones in every
    /// word below the top, which carries through every column.
    #[test]
    fn the_kernels_match_the_portable_products_on_many_operands() {
        if !super::available() {
            return;
        }
        let mut s = 0x0123_4567_89AB_CDEFu64;
        let mut next = || {
            s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = s;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        for l in [4usize, 8, 12, 16, 24, 32, 40, 48, 56, 64] {
            let trials = if l <= 32 { 300 } else { 60 };
            for trial in 0..trials {
                let mut n = [0u64; MAX_LIMBS];
                for w in n[..l].iter_mut() {
                    *w = next();
                }
                match trial % 5 {
                    0 => n[l - 1] = u64::MAX,
                    1 => {
                        n[..l].fill(0);
                        n[l - 1] = 1 << 63;
                    }
                    _ => n[l - 1] |= 1 << 63,
                }
                n[0] |= 1;
                let n0inv = super::super::neg_inv(n[0]);
                let below = |next: &mut dyn FnMut() -> u64| {
                    let mut x = [0u64; MAX_LIMBS];
                    for w in x[..l].iter_mut() {
                        *w = next();
                    }
                    x[l - 1] %= n[l - 1];
                    x
                };
                let mut ones = [0u64; MAX_LIMBS];
                ones[..l].fill(u64::MAX);
                ones[l - 1] = n[l - 1] - 1;
                let mut minus = n;
                minus[0] -= 1;
                let mut one = [0u64; MAX_LIMBS];
                one[0] = 1;
                let ops = [
                    below(&mut next),
                    below(&mut next),
                    ones,
                    minus,
                    one,
                    [0u64; MAX_LIMBS],
                ];
                for a in &ops {
                    for b in &ops[..3] {
                        let (mut t, mut want, mut got) =
                            ([0u64; 130], [0u64; MAX_LIMBS], [7u64; MAX_LIMBS]);
                        super::super::cios(
                            &mut t,
                            &a[..l],
                            &b[..l],
                            &n[..l],
                            n0inv,
                            &mut want[..l],
                        );
                        assert!(super::mont_mul(
                            &mut t,
                            &a[..l],
                            &b[..l],
                            &n[..l],
                            n0inv,
                            &mut got[..l]
                        ));
                        assert_eq!(got[..l], want[..l], "{l} words, trial {trial}: product");
                    }
                    let (mut t, mut want, mut got) =
                        ([0u64; 130], [0u64; MAX_LIMBS], [7u64; MAX_LIMBS]);
                    super::super::sqr(&mut t, &a[..l], &n[..l], n0inv, &mut want[..l]);
                    assert!(super::mont_sqr(
                        &mut t,
                        &a[..l],
                        &n[..l],
                        n0inv,
                        &mut got[..l]
                    ));
                    assert_eq!(got[..l], want[..l], "{l} words, trial {trial}: square");
                }
            }
        }
    }

    /// The SSE2 scan against the scan in Rust, for every digit and every
    /// width it takes, and declining the widths it does not.
    #[test]
    fn the_sse2_table_read_matches_the_masked_scan() {
        let mut table = [[0u64; MAX_LIMBS]; 16];
        let mut x = 0x0123_4567_89AB_CDEFu64;
        for entry in table.iter_mut() {
            for w in entry.iter_mut() {
                x = x.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17) ^ 0xD1B5_4A32_D192_ED03;
                *w = x;
            }
        }
        for limbs in (2..=MAX_LIMBS).step_by(2) {
            for digit in 0..16u64 {
                let mut masks = [0u64; 16];
                masks[digit as usize] = u64::MAX;
                let mut out: Limbs = [0x5555; MAX_LIMBS];
                assert!(super::select(&table, limbs, &masks, &mut out));
                assert_eq!(
                    out[..limbs],
                    table[digit as usize][..limbs],
                    "{limbs} {digit}"
                );
                assert!(
                    out[limbs..].iter().all(|&w| w == 0x5555),
                    "{limbs}: wrote past the width"
                );
            }
        }
        let masks = [0u64; 16];
        let mut out: Limbs = [0; MAX_LIMBS];
        for limbs in [0, 1, 3, 31, MAX_LIMBS + 2] {
            assert!(!super::select(&table, limbs, &masks, &mut out), "{limbs}");
        }
    }
}
