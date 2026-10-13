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
//! # The algorithm
//!
//! Coarsely integrated operand scanning, as in [`super::Modulus::mont_mul`]'s
//! portable form: for each word `b[i]`, add `a * b[i]` into the accumulator,
//! then add `u * n` with `u = t[0] * n0inv` so that the low word becomes zero,
//! and drop that word. The drop is not a copy: the accumulator is a window
//! into a buffer of `2L + 2` words that slides up one word per row. After `L`
//! rows the result is the `L + 1` words at `t[L..=2L]`, below `2n`, and the
//! caller makes the one conditional subtraction in Rust, shared with the
//! portable path.
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
//! is a base pointer plus the loop counter. `MULX`, `ADCX` and `ADOX` have
//! data-independent latency.
//!
//! # Safety
//!
//! [`mont_mul`] is the only way in. It checks the CPU features (once, then
//! cached), that `L` is a non-zero multiple of four, that every slice is `L`
//! words, and that the scratch buffer holds `2L + 2`, and declines -- returns
//! `false` and touches nothing -- otherwise. Given those, every address the
//! assembly forms is inside one of the four slices; the comments on the block
//! say which.

use core::arch::asm;

/// Whether this CPU has `MULX` (BMI2) and `ADCX`/`ADOX` (ADX), asked once.
pub(crate) fn available() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering};
    if super::adx_forced() {
        return true;
    }
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

/// Whether [`mont_mul`] will take a modulus of `limbs` words on this CPU.
pub(crate) fn handles(limbs: usize) -> bool {
    limbs != 0 && limbs.is_multiple_of(4) && available()
}

/// The unreduced Montgomery product `a * b / 2^(64L)`, below `2n`, into
/// `t[L..=2L]`, where `L = n.len()`.
///
/// Returns `false` without touching anything when this backend cannot run:
/// the CPU lacks the instructions, `L` is not a non-zero multiple of four, or
/// a slice has the wrong length. The caller then uses the portable path.
pub(crate) fn mont_mul(t: &mut [u64], a: &[u64], b: &[u64], n: &[u64], n0inv: u64) -> bool {
    let l = n.len();
    if !handles(l) || a.len() != l || b.len() != l || t.len() < 2 * l + 2 {
        return false;
    }
    t[..2 * l + 2].fill(0);
    // SAFETY: the features `mont_mul_adx` is compiled for were detected above,
    // and the lengths it relies on were checked: `a`, `b` and `n` are `l`
    // words, `t` at least `2l + 2`, and `l` a non-zero multiple of four.
    unsafe { mont_mul_adx(t.as_mut_ptr(), a.as_ptr(), b.as_ptr(), n.as_ptr(), n0inv, l) };
    true
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
