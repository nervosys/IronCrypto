//! P-256 field arithmetic in x86-64 assembly.
//!
//! The same functions as [`super::p256_field`], with the same reduction, in
//! instructions every x86-64 CPU has: `mul`, `adc`, `sbb` and `cmov`. Nothing
//! here needs a CPU feature check, so nothing here can be selected wrongly.
//!
//! # Why assembly
//!
//! Measured, not assumed: the Rust in `p256_field` is correct and branch-free,
//! but two things in it cost more than the arithmetic. A `u128` carry chain
//! compiles to `setb`/`movzx` pairs and re-materialised carries, because the
//! compiler cannot hold a carry in the flags across the multiplications that
//! clobber them. And every final selection goes through `select_ct`'s
//! `black_box`, which is a store, an empty `asm!` with a memory clobber and a
//! load -- the barrier that stops the compiler from turning a mask into a
//! branch. Here the carries stay in the flags, and the selection is `cmovc`,
//! which the compiler cannot rewrite at all: an `asm!` block is emitted as
//! written. So the constant-time property that the barrier protects in the
//! Rust is a property of the text here, and `scripts/check-ct.py` reads this
//! text on x86-64, where it is what the P-256 probes compile to.
//!
//! # The algorithms
//!
//! Multiplication is CIOS: one row of `a * b_i` at a time, each followed by a
//! Montgomery step. Squaring forms the 512-bit square -- six cross products
//! doubled, four squares added -- and reduces it in a four-word window.
//!
//! A Montgomery step needs no multiplication on this prime. With the low word
//! `u` as the quotient digit (`-p^-1 = 1 mod 2^64`),
//!
//! ```text
//! (w + u*p) / 2^64 = w1 + u*2^32 + w2*2^64 + (w3 + u*p3)*2^128
//! u*p3 = u*2^64 + u - u*2^32
//! ```
//!
//! so with `u*2^32 = (v_hi, v_lo) = (u >> 32, u << 32)`, the step adds `v_lo`,
//! `v_hi`, `u - v_lo` and `u - v_hi - borrow` to successive words. That is two
//! shifts, a subtraction pair and an addition chain.
//!
//! Every input must be below `p`, as every field element is; the result is
//! then canonical, by the bound argued in `p256_field`.
//!
//! # Registers
//!
//! `rbx` and `rbp` are reserved by the compiler and `rsp` is the stack, which
//! leaves thirteen. Multiplication uses twelve of them, squaring eleven; the
//! compiler assigns every one but `rax` and `rdx`, which `mul` dictates.

use core::arch::asm;

/// `p`'s second word, `2^32 - 1`.
const P1: u64 = 0x0000_0000_ffff_ffff;
/// `p`'s top word, `2^64 - 2^32 + 1`.
const P3: u64 = 0xffff_ffff_0000_0001;

/// The tail `mul` and `square` share: Montgomery-reduce the 512-bit value in
/// `t0..t7` by four steps on the low window, add the high half, and make the
/// result canonical with one subtraction kept or discarded by `cmovc`. Leaves
/// the result in `rax`, `rdx`, `t2`, `t3`.
macro_rules! reduce_tail {
    () => {
        concat!(
            // Four Montgomery steps on the low window (t0..t3); each leaves
            // its new top word where the consumed low word was.
            "mov rax, {t0}\n",
            "shl rax, 32\n",
            "mov rdx, {t0}\n",
            "shr rdx, 32\n",
            "mov {c}, {t0}\n",
            "sub {c}, rax\n",
            "sbb {t0}, rdx\n",
            "add {t1}, rax\n",
            "adc {t2}, rdx\n",
            "adc {t3}, {c}\n",
            "adc {t0}, 0\n",
            //
            "mov rax, {t1}\n",
            "shl rax, 32\n",
            "mov rdx, {t1}\n",
            "shr rdx, 32\n",
            "mov {c}, {t1}\n",
            "sub {c}, rax\n",
            "sbb {t1}, rdx\n",
            "add {t2}, rax\n",
            "adc {t3}, rdx\n",
            "adc {t0}, {c}\n",
            "adc {t1}, 0\n",
            //
            "mov rax, {t2}\n",
            "shl rax, 32\n",
            "mov rdx, {t2}\n",
            "shr rdx, 32\n",
            "mov {c}, {t2}\n",
            "sub {c}, rax\n",
            "sbb {t2}, rdx\n",
            "add {t3}, rax\n",
            "adc {t0}, rdx\n",
            "adc {t1}, {c}\n",
            "adc {t2}, 0\n",
            //
            "mov rax, {t3}\n",
            "shl rax, 32\n",
            "mov rdx, {t3}\n",
            "shr rdx, 32\n",
            "mov {c}, {t3}\n",
            "sub {c}, rax\n",
            "sbb {t3}, rdx\n",
            "add {t0}, rax\n",
            "adc {t1}, rdx\n",
            "adc {t2}, {c}\n",
            "adc {t3}, 0\n",
            // The window, (t0..t3), plus the high half, (t4..t7): below 2p.
            "xor {c:e}, {c:e}\n",
            "add {t4}, {t0}\n",
            "adc {t5}, {t1}\n",
            "adc {t6}, {t2}\n",
            "adc {t7}, {t3}\n",
            "adc {c}, 0\n",
            "mov rax, {t4}\n",
            "mov rdx, {t5}\n",
            "mov {t2}, {t6}\n",
            "mov {t3}, {t7}\n",
            "mov {t0:e}, {p1}\n",
            "mov {t1}, {p3}\n",
            "sub rax, -1\n",
            "sbb rdx, {t0}\n",
            "sbb {t2}, 0\n",
            "sbb {t3}, {t1}\n",
            "sbb {c}, 0\n",
            "cmovc rax, {t4}\n",
            "cmovc rdx, {t5}\n",
            "cmovc {t2}, {t6}\n",
            "cmovc {t3}, {t7}\n",
        )
    };
}

/// Whether this CPU has `mulx` (BMI2) and `adcx`/`adox` (ADX), asked once.
///
/// Under `std` the answer is the CPU's, cached; without `std` there is no
/// runtime detection, and the answer is whether the build was compiled for
/// those features. Either way it depends on the CPU and nothing else.
#[inline]
pub(crate) fn has_adx() -> bool {
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
    #[cfg(not(feature = "std"))]
    {
        cfg!(all(target_feature = "bmi2", target_feature = "adx"))
    }
}

/// Copy field elements into a formula's slots.
#[inline(always)]
fn load<const N: usize>(buf: &mut [u64; N], values: &[&[u64; 4]]) {
    for (i, v) in values.iter().enumerate() {
        buf[4 * i..4 * i + 4].copy_from_slice(&v[..]);
    }
}

/// A field element from slot `slot`.
#[inline(always)]
fn slot<const N: usize>(buf: &[u64; N], slot: usize) -> [u64; 4] {
    [
        buf[4 * slot],
        buf[4 * slot + 1],
        buf[4 * slot + 2],
        buf[4 * slot + 3],
    ]
}

/// Jacobian doubling as one block of assembly, where the CPU has BMI2 and
/// ADX; `None` where it does not.
#[inline(always)]
pub(crate) fn point_double(x: &[u64; 4], y: &[u64; 4], z: &[u64; 4]) -> Option<[[u64; 4]; 3]> {
    if !has_adx() {
        return None;
    }
    let mut buf = [0u64; 56];
    load(&mut buf, &[x, y, z]);
    // SAFETY: the CPU has BMI2 and ADX.
    unsafe { super::p256_x86_point::double_adx(&mut buf) };
    Some([slot(&buf, 3), slot(&buf, 4), slot(&buf, 5)])
}

/// The Jacobian addition formula as one block of assembly, with `h` and `r`;
/// `None` without BMI2 and ADX.
#[inline(always)]
#[allow(clippy::type_complexity)]
pub(crate) fn point_add(
    p: [&[u64; 4]; 3],
    q: [&[u64; 4]; 3],
) -> Option<([[u64; 4]; 3], [u64; 4], [u64; 4])> {
    if !has_adx() {
        return None;
    }
    let mut buf = [0u64; 84];
    load(&mut buf, &[p[0], p[1], p[2], q[0], q[1], q[2]]);
    // SAFETY: the CPU has BMI2 and ADX.
    unsafe { super::p256_x86_point::add_adx(&mut buf) };
    Some((
        [slot(&buf, 6), slot(&buf, 7), slot(&buf, 8)],
        slot(&buf, 9),
        slot(&buf, 10),
    ))
}

/// The mixed addition formula as one block of assembly, with `h` and `r`;
/// `None` without BMI2 and ADX.
#[inline(always)]
#[allow(clippy::type_complexity)]
pub(crate) fn point_add_affine(
    p: [&[u64; 4]; 3],
    q: [&[u64; 4]; 2],
) -> Option<([[u64; 4]; 3], [u64; 4], [u64; 4])> {
    if !has_adx() {
        return None;
    }
    let mut buf = [0u64; 72];
    load(&mut buf, &[p[0], p[1], p[2], q[0], q[1]]);
    // SAFETY: the CPU has BMI2 and ADX.
    unsafe { super::p256_x86_point::add_affine_adx(&mut buf) };
    Some((
        [slot(&buf, 5), slot(&buf, 6), slot(&buf, 7)],
        slot(&buf, 8),
        slot(&buf, 9),
    ))
}

/// `a * b * 2^-256 mod p`, on `mulx`/`adcx`/`adox` where the CPU has them.
#[inline(always)]
pub(crate) fn mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    if has_adx() {
        // SAFETY: the CPU has BMI2 and ADX, which is `mul_adx`'s whole
        // precondition.
        unsafe { mul_adx(a, b) }
    } else {
        mul_plain(a, b)
    }
}

/// `a^2 * 2^-256 mod p`, on `mulx`/`adcx`/`adox` where the CPU has them.
#[inline(always)]
pub(crate) fn square(a: &[u64; 4]) -> [u64; 4] {
    if has_adx() {
        // SAFETY: as for `mul`.
        unsafe { square_adx(a) }
    } else {
        square_plain(a)
    }
}

/// `a * b * 2^-256 mod p` with `mulx` and two carry chains: CIOS, one row
/// `a * b_i` and one Montgomery step at a time. `mulx` leaves the flags alone,
/// so a row's low words ride the carry flag (`adcx`) while its high words ride
/// the overflow flag (`adox`), and neither waits on the other.
///
/// # Safety
///
/// The CPU must support BMI2 and ADX; see [`has_adx`].
#[inline]
pub(crate) unsafe fn mul_adx(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: the caller guarantees the instructions exist. The block reads
    // the 32 bytes behind each of `a` and `b`, which are live references to
    // `[u64; 4]`, writes only registers it declares, and touches neither the
    // stack nor memory. The pointer registers are reused for constants at the
    // end, so they are declared clobbered.
    unsafe {
        asm!(
            // Row 0: (t0..t4) = a * b0.
            "mov rdx, qword ptr [{b}]",
            "mulx {t1}, {t0}, qword ptr [{a}]",
            "mulx {t2}, rax, qword ptr [{a} + 8]",
            "add {t1}, rax",
            "mulx {t3}, rax, qword ptr [{a} + 16]",
            "adc {t2}, rax",
            "mulx {t4}, rax, qword ptr [{a} + 24]",
            "adc {t3}, rax",
            "adc {t4}, 0",
            "xor {t5:e}, {t5:e}",
            // Step, u = t0: see the module documentation.
            "mov rax, {t0}",
            "shl rax, 32",
            "mov {c}, {t0}",
            "shr {c}, 32",
            "mov rdx, {t0}",
            "sub rdx, rax",
            "sbb {t0}, {c}",
            "add {t1}, rax",
            "adc {t2}, {c}",
            "adc {t3}, rdx",
            "adc {t4}, {t0}",
            "adc {t5}, 0",
            // Row 1: (t1, t2, t3, t4, t5) += a * b1, new top word in t0. The
            // `xor` zeroes it and clears both carry flags.
            "mov rdx, qword ptr [{b} + 8]",
            "xor {t0:e}, {t0:e}",
            "mulx {c}, rax, qword ptr [{a}]",
            "adcx {t1}, rax",
            "adox {t2}, {c}",
            "mulx {c}, rax, qword ptr [{a} + 8]",
            "adcx {t2}, rax",
            "adox {t3}, {c}",
            "mulx {c}, rax, qword ptr [{a} + 16]",
            "adcx {t3}, rax",
            "adox {t4}, {c}",
            "mulx {c}, rax, qword ptr [{a} + 24]",
            "adcx {t4}, rax",
            "adox {t5}, {c}",
            // Both flags into the words above; `mov` leaves the flags alone.
            "mov eax, 0",
            "adcx {t5}, rax",
            "adox {t0}, rax",
            "adcx {t0}, rax",
            // Step, u = t1.
            "mov rax, {t1}",
            "shl rax, 32",
            "mov {c}, {t1}",
            "shr {c}, 32",
            "mov rdx, {t1}",
            "sub rdx, rax",
            "sbb {t1}, {c}",
            "add {t2}, rax",
            "adc {t3}, {c}",
            "adc {t4}, rdx",
            "adc {t5}, {t1}",
            "adc {t0}, 0",
            // Row 2: (t2, t3, t4, t5, t0) += a * b2, new top word in t1.
            "mov rdx, qword ptr [{b} + 16]",
            "xor {t1:e}, {t1:e}",
            "mulx {c}, rax, qword ptr [{a}]",
            "adcx {t2}, rax",
            "adox {t3}, {c}",
            "mulx {c}, rax, qword ptr [{a} + 8]",
            "adcx {t3}, rax",
            "adox {t4}, {c}",
            "mulx {c}, rax, qword ptr [{a} + 16]",
            "adcx {t4}, rax",
            "adox {t5}, {c}",
            "mulx {c}, rax, qword ptr [{a} + 24]",
            "adcx {t5}, rax",
            "adox {t0}, {c}",
            "mov eax, 0",
            "adcx {t0}, rax",
            "adox {t1}, rax",
            "adcx {t1}, rax",
            // Step, u = t2.
            "mov rax, {t2}",
            "shl rax, 32",
            "mov {c}, {t2}",
            "shr {c}, 32",
            "mov rdx, {t2}",
            "sub rdx, rax",
            "sbb {t2}, {c}",
            "add {t3}, rax",
            "adc {t4}, {c}",
            "adc {t5}, rdx",
            "adc {t0}, {t2}",
            "adc {t1}, 0",
            // Row 3: (t3, t4, t5, t0, t1) += a * b3, new top word in t2.
            "mov rdx, qword ptr [{b} + 24]",
            "xor {t2:e}, {t2:e}",
            "mulx {c}, rax, qword ptr [{a}]",
            "adcx {t3}, rax",
            "adox {t4}, {c}",
            "mulx {c}, rax, qword ptr [{a} + 8]",
            "adcx {t4}, rax",
            "adox {t5}, {c}",
            "mulx {c}, rax, qword ptr [{a} + 16]",
            "adcx {t5}, rax",
            "adox {t0}, {c}",
            "mulx {c}, rax, qword ptr [{a} + 24]",
            "adcx {t0}, rax",
            "adox {t1}, {c}",
            "mov eax, 0",
            "adcx {t1}, rax",
            "adox {t2}, rax",
            "adcx {t2}, rax",
            // Step, u = t3.
            "mov rax, {t3}",
            "shl rax, 32",
            "mov {c}, {t3}",
            "shr {c}, 32",
            "mov rdx, {t3}",
            "sub rdx, rax",
            "sbb {t3}, {c}",
            "add {t4}, rax",
            "adc {t5}, {c}",
            "adc {t0}, rdx",
            "adc {t1}, {t3}",
            "adc {t2}, 0",
            // (t4, t5, t0, t1) + t2 * 2^256 is below 2p. Subtract p, and keep
            // the difference unless it borrowed.
            "mov rax, {t4}",
            "mov rdx, {t5}",
            "mov {c}, {t0}",
            "mov {t3}, {t1}",
            "mov {a:e}, {p1}",
            "mov {b}, {p3}",
            "sub rax, -1",
            "sbb rdx, {a}",
            "sbb {c}, 0",
            "sbb {t3}, {b}",
            "sbb {t2}, 0",
            "cmovc rax, {t4}",
            "cmovc rdx, {t5}",
            "cmovc {c}, {t0}",
            "cmovc {t3}, {t1}",
            a = inout(reg) a.as_ptr() => _,
            b = inout(reg) b.as_ptr() => _,
            p1 = const P1,
            p3 = const P3,
            t0 = out(reg) _,
            t1 = out(reg) _,
            t2 = out(reg) _,
            t3 = out(reg) r3,
            t4 = out(reg) _,
            t5 = out(reg) _,
            c = out(reg) r2,
            out("rax") r0,
            out("rdx") r1,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `a^2 * 2^-256 mod p` with `mulx` and two carry chains: the cross products,
/// doubled, plus the squares, then [`reduce_tail`].
///
/// # Safety
///
/// The CPU must support BMI2 and ADX; see [`has_adx`].
#[inline]
pub(crate) unsafe fn square_adx(a: &[u64; 4]) -> [u64; 4] {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: the caller guarantees the instructions exist; otherwise as for
    // `mul_plain`.
    unsafe {
        asm!(
            // Cross products a_i * a_j, i < j, into t1..t6.
            "mov rdx, qword ptr [{a}]",
            "mulx {t2}, {t1}, qword ptr [{a} + 8]",
            "mulx {t3}, rax, qword ptr [{a} + 16]",
            "add {t2}, rax",
            "mulx {t4}, rax, qword ptr [{a} + 24]",
            "adc {t3}, rax",
            "adc {t4}, 0",
            "mov rdx, qword ptr [{a} + 8]",
            "xor {t5:e}, {t5:e}",
            "mulx {c}, rax, qword ptr [{a} + 16]",
            "adcx {t3}, rax",
            "adox {t4}, {c}",
            "mulx {c}, rax, qword ptr [{a} + 24]",
            "adcx {t4}, rax",
            "adox {t5}, {c}",
            "mov eax, 0",
            "adcx {t5}, rax",
            "mov rdx, qword ptr [{a} + 16]",
            "mulx {t6}, rax, qword ptr [{a} + 24]",
            "add {t5}, rax",
            "adc {t6}, 0",
            // Doubled, into t1..t7.
            "xor {t7:e}, {t7:e}",
            "add {t1}, {t1}",
            "adc {t2}, {t2}",
            "adc {t3}, {t3}",
            "adc {t4}, {t4}",
            "adc {t5}, {t5}",
            "adc {t6}, {t6}",
            "adc {t7}, 0",
            // Plus the squares: `mulx` and `mov` leave the flags alone, so the
            // four squares are one carry chain.
            "mov rdx, qword ptr [{a}]",
            "mulx {c}, {t0}, rdx",
            "add {t1}, {c}",
            "mov rdx, qword ptr [{a} + 8]",
            "mulx {c}, rax, rdx",
            "adc {t2}, rax",
            "adc {t3}, {c}",
            "mov rdx, qword ptr [{a} + 16]",
            "mulx {c}, rax, rdx",
            "adc {t4}, rax",
            "adc {t5}, {c}",
            "mov rdx, qword ptr [{a} + 24]",
            "mulx {c}, rax, rdx",
            "adc {t6}, rax",
            "adc {t7}, {c}",
            reduce_tail!(),
            a = in(reg) a.as_ptr(),
            p1 = const P1,
            p3 = const P3,
            t0 = out(reg) _,
            t1 = out(reg) _,
            t2 = out(reg) r2,
            t3 = out(reg) r3,
            t4 = out(reg) _,
            t5 = out(reg) _,
            t6 = out(reg) _,
            t7 = out(reg) _,
            c = out(reg) _,
            out("rax") r0,
            out("rdx") r1,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `a * b * 2^-256 mod p`, with `mul` alone.
#[inline]
pub(crate) fn mul_plain(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: the block reads the 32 bytes behind each of `a` and `b`, which
    // are live references to `[u64; 4]`, and writes nothing but registers. It
    // does not touch the stack (`nostack`) and leaves memory unchanged
    // (`readonly`). Every register it writes is declared: `rax` and `rdx`
    // explicitly, the rest as `out` operands, which the compiler allocates
    // apart from the two input pointers.
    unsafe {
        asm!(
            // The 512-bit product, a row of `a * b_i` at a time into t0..t7.
            // Each row's high words absorb the carry from the word below; no
            // word can overflow, since `t + a_j * b_i + carry < 2^128`.
            //
            // Row 0.
            "mov rax, qword ptr [{a}]",
            "mul qword ptr [{b}]",
            "mov {t0}, rax",
            "mov {t1}, rdx",
            "mov rax, qword ptr [{a} + 8]",
            "mul qword ptr [{b}]",
            "add {t1}, rax",
            "adc rdx, 0",
            "mov {t2}, rdx",
            "mov rax, qword ptr [{a} + 16]",
            "mul qword ptr [{b}]",
            "add {t2}, rax",
            "adc rdx, 0",
            "mov {t3}, rdx",
            "mov rax, qword ptr [{a} + 24]",
            "mul qword ptr [{b}]",
            "add {t3}, rax",
            "adc rdx, 0",
            "mov {t4}, rdx",
            // Row 1.
            "mov rax, qword ptr [{a}]",
            "mul qword ptr [{b} + 8]",
            "add {t1}, rax",
            "adc rdx, 0",
            "mov {c}, rdx",
            "mov rax, qword ptr [{a} + 8]",
            "mul qword ptr [{b} + 8]",
            "add {t2}, {c}",
            "adc rdx, 0",
            "add {t2}, rax",
            "adc rdx, 0",
            "mov {c}, rdx",
            "mov rax, qword ptr [{a} + 16]",
            "mul qword ptr [{b} + 8]",
            "add {t3}, {c}",
            "adc rdx, 0",
            "add {t3}, rax",
            "adc rdx, 0",
            "mov {c}, rdx",
            "mov rax, qword ptr [{a} + 24]",
            "mul qword ptr [{b} + 8]",
            "add {t4}, {c}",
            "adc rdx, 0",
            "add {t4}, rax",
            "adc rdx, 0",
            "mov {t5}, rdx",
            // Row 2.
            "mov rax, qword ptr [{a}]",
            "mul qword ptr [{b} + 16]",
            "add {t2}, rax",
            "adc rdx, 0",
            "mov {c}, rdx",
            "mov rax, qword ptr [{a} + 8]",
            "mul qword ptr [{b} + 16]",
            "add {t3}, {c}",
            "adc rdx, 0",
            "add {t3}, rax",
            "adc rdx, 0",
            "mov {c}, rdx",
            "mov rax, qword ptr [{a} + 16]",
            "mul qword ptr [{b} + 16]",
            "add {t4}, {c}",
            "adc rdx, 0",
            "add {t4}, rax",
            "adc rdx, 0",
            "mov {c}, rdx",
            "mov rax, qword ptr [{a} + 24]",
            "mul qword ptr [{b} + 16]",
            "add {t5}, {c}",
            "adc rdx, 0",
            "add {t5}, rax",
            "adc rdx, 0",
            "mov {t6}, rdx",
            // Row 3.
            "mov rax, qword ptr [{a}]",
            "mul qword ptr [{b} + 24]",
            "add {t3}, rax",
            "adc rdx, 0",
            "mov {c}, rdx",
            "mov rax, qword ptr [{a} + 8]",
            "mul qword ptr [{b} + 24]",
            "add {t4}, {c}",
            "adc rdx, 0",
            "add {t4}, rax",
            "adc rdx, 0",
            "mov {c}, rdx",
            "mov rax, qword ptr [{a} + 16]",
            "mul qword ptr [{b} + 24]",
            "add {t5}, {c}",
            "adc rdx, 0",
            "add {t5}, rax",
            "adc rdx, 0",
            "mov {c}, rdx",
            "mov rax, qword ptr [{a} + 24]",
            "mul qword ptr [{b} + 24]",
            "add {t6}, {c}",
            "adc rdx, 0",
            "add {t6}, rax",
            "adc rdx, 0",
            "mov {t7}, rdx",
            // Reduce and make canonical, exactly as `square` does.
            reduce_tail!(),
            a = in(reg) a.as_ptr(),
            b = in(reg) b.as_ptr(),
            p1 = const P1,
            p3 = const P3,
            t0 = out(reg) _,
            t1 = out(reg) _,
            t2 = out(reg) r2,
            t3 = out(reg) r3,
            t4 = out(reg) _,
            t5 = out(reg) _,
            t6 = out(reg) _,
            t7 = out(reg) _,
            c = out(reg) _,
            out("rax") r0,
            out("rdx") r1,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `a^2 * 2^-256 mod p`.
#[inline]
pub(crate) fn square_plain(a: &[u64; 4]) -> [u64; 4] {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: as for `mul`: reads the 32 bytes behind `a`, writes only
    // declared registers, touches neither the stack nor memory.
    unsafe {
        asm!(
            // Cross products a_i * a_j, i < j, into t1..t6.
            "mov rax, qword ptr [{a} + 8]",
            "mul qword ptr [{a}]",
            "mov {t1}, rax",
            "mov {t2}, rdx",
            "mov rax, qword ptr [{a} + 16]",
            "mul qword ptr [{a}]",
            "add {t2}, rax",
            "adc rdx, 0",
            "mov {t3}, rdx",
            "mov rax, qword ptr [{a} + 24]",
            "mul qword ptr [{a}]",
            "add {t3}, rax",
            "adc rdx, 0",
            "mov {t4}, rdx",
            "mov rax, qword ptr [{a} + 16]",
            "mul qword ptr [{a} + 8]",
            "add {t3}, rax",
            "adc rdx, 0",
            "mov {c}, rdx",
            "mov rax, qword ptr [{a} + 24]",
            "mul qword ptr [{a} + 8]",
            "add {t4}, {c}",
            "adc rdx, 0",
            "add {t4}, rax",
            "adc rdx, 0",
            "mov {t5}, rdx",
            "mov rax, qword ptr [{a} + 24]",
            "mul qword ptr [{a} + 16]",
            "add {t5}, rax",
            "adc rdx, 0",
            "mov {t6}, rdx",
            // Doubled, into t1..t7.
            "xor {t7:e}, {t7:e}",
            "add {t1}, {t1}",
            "adc {t2}, {t2}",
            "adc {t3}, {t3}",
            "adc {t4}, {t4}",
            "adc {t5}, {t5}",
            "adc {t6}, {t6}",
            "adc {t7}, 0",
            // Plus the squares a_i^2 at words 2i, 2i + 1. Each square's high
            // word absorbs the carry out of the word below it, and becomes
            // the carry into the next pair; the last cannot overflow.
            "mov rax, qword ptr [{a}]",
            "mul rax",
            "mov {t0}, rax",
            "mov {c}, rdx",
            "mov rax, qword ptr [{a} + 8]",
            "mul rax",
            "add {t1}, {c}",
            "adc {t2}, rax",
            "adc rdx, 0",
            "mov {c}, rdx",
            "mov rax, qword ptr [{a} + 16]",
            "mul rax",
            "add {t3}, {c}",
            "adc {t4}, rax",
            "adc rdx, 0",
            "mov {c}, rdx",
            "mov rax, qword ptr [{a} + 24]",
            "mul rax",
            "add {t5}, {c}",
            "adc {t6}, rax",
            "adc {t7}, rdx",
            reduce_tail!(),
            a = in(reg) a.as_ptr(),
            p1 = const P1,
            p3 = const P3,
            t0 = out(reg) _,
            t1 = out(reg) _,
            t2 = out(reg) r2,
            t3 = out(reg) r3,
            t4 = out(reg) _,
            t5 = out(reg) _,
            t6 = out(reg) _,
            t7 = out(reg) _,
            c = out(reg) _,
            out("rax") r0,
            out("rdx") r1,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `a + b mod p`.
#[inline]
pub(crate) fn add(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: as for `mul`.
    unsafe {
        asm!(
            "mov {t0}, qword ptr [{a}]",
            "mov {t1}, qword ptr [{a} + 8]",
            "mov {t2}, qword ptr [{a} + 16]",
            "mov {t3}, qword ptr [{a} + 24]",
            "xor {c:e}, {c:e}",
            "add {t0}, qword ptr [{b}]",
            "adc {t1}, qword ptr [{b} + 8]",
            "adc {t2}, qword ptr [{b} + 16]",
            "adc {t3}, qword ptr [{b} + 24]",
            "adc {c}, 0",
            "mov {s0}, {t0}",
            "mov {s1}, {t1}",
            "mov {s2}, {t2}",
            "mov {s3}, {t3}",
            "mov {k1:e}, {p1}",
            "mov {k3}, {p3}",
            "sub {s0}, -1",
            "sbb {s1}, {k1}",
            "sbb {s2}, 0",
            "sbb {s3}, {k3}",
            "sbb {c}, 0",
            "cmovc {s0}, {t0}",
            "cmovc {s1}, {t1}",
            "cmovc {s2}, {t2}",
            "cmovc {s3}, {t3}",
            a = in(reg) a.as_ptr(),
            b = in(reg) b.as_ptr(),
            p1 = const P1,
            p3 = const P3,
            t0 = out(reg) _,
            t1 = out(reg) _,
            t2 = out(reg) _,
            t3 = out(reg) _,
            c = out(reg) _,
            k1 = out(reg) _,
            k3 = out(reg) _,
            s0 = out(reg) r0,
            s1 = out(reg) r1,
            s2 = out(reg) r2,
            s3 = out(reg) r3,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

/// `a - b mod p`: subtract, then add back `p` masked by the borrow.
#[inline]
pub(crate) fn sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: as for `mul`.
    unsafe {
        asm!(
            "mov {t0}, qword ptr [{a}]",
            "mov {t1}, qword ptr [{a} + 8]",
            "mov {t2}, qword ptr [{a} + 16]",
            "mov {t3}, qword ptr [{a} + 24]",
            "sub {t0}, qword ptr [{b}]",
            "sbb {t1}, qword ptr [{b} + 8]",
            "sbb {t2}, qword ptr [{b} + 16]",
            "sbb {t3}, qword ptr [{b} + 24]",
            // m = all ones on a borrow, else zero; then p & m, word by word:
            // p0 = 2^64 - 1, p1 = 2^32 - 1, p2 = 0, p3 = P3.
            "sbb {m}, {m}",
            "mov {k1}, {m}",
            "shr {k1}, 32",
            "mov {k3}, {p3}",
            "and {k3}, {m}",
            "add {t0}, {m}",
            "adc {t1}, {k1}",
            "adc {t2}, 0",
            "adc {t3}, {k3}",
            a = in(reg) a.as_ptr(),
            b = in(reg) b.as_ptr(),
            p3 = const P3,
            m = out(reg) _,
            k1 = out(reg) _,
            k3 = out(reg) _,
            t0 = out(reg) r0,
            t1 = out(reg) r1,
            t2 = out(reg) r2,
            t3 = out(reg) r3,
            options(pure, readonly, nostack),
        );
    }
    [r0, r1, r2, r3]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nist::p256_field::{self as rust, P};

    /// SplitMix64.
    fn next(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Below p, half uniform and half whole words of zeros and ones.
    fn operand(state: &mut u64, structured: bool) -> [u64; 4] {
        loop {
            let mut x = [0u64; 4];
            let r = next(state);
            for (i, limb) in x.iter_mut().enumerate() {
                *limb = if structured {
                    match (r >> (2 * i)) & 3 {
                        0 => 0,
                        1 => u64::MAX,
                        2 => next(state),
                        _ => 1 << (next(state) % 64),
                    }
                } else {
                    next(state)
                };
            }
            // x < p
            let mut borrow = 0u64;
            for i in 0..4 {
                let (d, b1) = x[i].overflowing_sub(P[i]);
                let (_, b2) = d.overflowing_sub(borrow);
                borrow = u64::from(b1 | b2);
            }
            if borrow == 1 {
                return x;
            }
        }
    }

    /// Every instruction sequence here against the Rust in `p256_field`,
    /// which `p256_field`'s own tests hold to the generic word loop: the plain
    /// one always, and the `mulx`/`adx` one wherever this CPU can run it.
    fn check(a: [u64; 4], b: [u64; 4], adx: bool) {
        let m = rust::mul(a, b);
        assert_eq!(mul_plain(&a, &b), m, "mul_plain {a:x?} {b:x?}");
        let s = rust::square(a);
        assert_eq!(square_plain(&a), s, "square_plain {a:x?}");
        if adx {
            // SAFETY: only reached when the CPU has BMI2 and ADX.
            unsafe {
                assert_eq!(mul_adx(&a, &b), m, "mul_adx {a:x?} {b:x?}");
                assert_eq!(square_adx(&a), s, "square_adx {a:x?}");
            }
        }
        assert_eq!(mul(&a, &b), m);
        assert_eq!(square(&a), s);
        assert_eq!(add(&a, &b), rust::add(a, b), "add {a:x?} {b:x?}");
        assert_eq!(sub(&a, &b), rust::sub(a, b), "sub {a:x?} {b:x?}");
    }

    #[test]
    fn both_instruction_sequences_agree_with_the_rust() {
        let adx = std::is_x86_feature_detected!("bmi2") && std::is_x86_feature_detected!("adx");
        // The dispatch must follow the CPU: where it has the instructions,
        // the faster sequence is the one that runs.
        assert_eq!(has_adx(), adx);
        std::println!(
            "p256 x86-64 field: mulx/adx {}",
            if adx { "selected" } else { "unavailable" }
        );

        let one = [1u64, 0, 0, 0];
        let pm1 = [P[0] - 1, P[1], P[2], P[3]];
        let r = [1u64, 0xffff_ffff_0000_0000, u64::MAX, 0x0000_0000_ffff_fffe];
        let edges = [
            [0u64; 4],
            one,
            pm1,
            [P[0] - 2, P[1], P[2], P[3]],
            r,
            [u64::MAX, u64::MAX, u64::MAX, 0xffff_ffff_0000_0000],
            [0, 0, 0, 1 << 63],
            [u64::MAX, u64::MAX, u64::MAX, (1 << 63) - 1],
        ];
        for a in edges {
            for b in edges {
                check(a, b, adx);
            }
        }
        let mut state = 0x86;
        for i in 0..1 << 20 {
            let structured = i % 2 == 1;
            let a = operand(&mut state, structured);
            let b = operand(&mut state, structured);
            check(a, b, adx);
        }
    }
}
