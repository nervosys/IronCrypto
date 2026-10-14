//! P-256 field arithmetic in x86-64 assembly.
//!
//! The same functions as [`super::p256_field`], with the same reduction, in
//! two instruction sequences: one in what every x86-64 CPU has -- `mul`,
//! `adc`, `sbb` and `cmov` -- and one on `mulx`, `adcx` and `adox`, chosen
//! where the CPU has BMI2 and ADX (`has_adx`, asked once). `mulx` leaves the
//! flags alone, so a row's low words can ride the carry flag while its high
//! words ride the overflow flag. Both are tested against the Rust and the
//! generic word loop, and the faster one is asserted to be the one selected
//! where the CPU allows it.
//!
//! The point formulas built from these are in `p256_x86_point`, generated;
//! the masked table scans, in SSE2 and AVX2, are here.
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
//! On `mulx`, multiplication is CIOS: one row of `a * b_i` at a time, each
//! followed by a Montgomery step; on `mul` it forms the 512-bit product row
//! by row and reduces it as squaring does. Squaring forms the 512-bit square
//! -- six cross products doubled, four squares added -- and reduces it in a
//! four-word window.
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
//! leaves thirteen. No sequence here uses more than twelve; the compiler
//! assigns every one but `rax` and `rdx`, which `mul` and `mulx` dictate.

use core::arch::asm;
use core::mem::MaybeUninit;

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

/// Whether this CPU has AVX2, asked once; as `has_adx` for `no_std`.
#[inline]
fn has_avx2() -> bool {
    #[cfg(feature = "std")]
    {
        use core::sync::atomic::{AtomicU8, Ordering};
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
    #[cfg(not(feature = "std"))]
    {
        cfg!(target_feature = "avx2")
    }
}

/// `OR` over `entries` of `entry & mask`, word by word: a table scan, every
/// entry read, at most one mask set, as in `gentable`. `W` words per entry.
///
/// The portable loop is scalar: LLVM does not vectorise it, and on P-256's
/// generator table the scans were a third of the cost of `k*G`. Here it is
/// four 128-bit SSE2 operations per entry, or two 256-bit AVX2 ones where the
/// CPU has AVX2 -- what Graviola does. Masks and data only: no branch and no
/// address depends on either.
#[inline]
pub(crate) fn scan<const W: usize>(entries: &[[u64; W]], masks: &[u64]) -> [u64; W] {
    let n = entries.len().min(masks.len());
    let (entries, masks) = (&entries[..n], &masks[..n]);
    // AVX2 for the generator table's eight-word affine entries only: on the
    // twelve-word Jacobian window it measured slower than SSE2 (25.7 against
    // 26.8 microseconds for ECDH, interleaved runs), and faster on the
    // affine table (5.7 against 6.3 for a public key).
    if W.is_multiple_of(8) && has_avx2() {
        // SAFETY: the CPU has AVX2.
        unsafe { scan_avx2(entries, masks) }
    } else {
        // SAFETY: SSE2 is part of the x86-64 baseline; every CPU this
        // module can run on has it.
        unsafe { scan_sse2(entries, masks) }
    }
}

/// [`scan`] in SSE2, which every x86-64 CPU has and every x86-64 target
/// enables.
#[inline]
#[target_feature(enable = "sse2")]
fn scan_sse2<const W: usize>(entries: &[[u64; W]], masks: &[u64]) -> [u64; W] {
    use core::arch::x86_64::*;
    // Up to eighteen words, P-384's Jacobian point, in whole lanes.
    const { assert!(W.is_multiple_of(2) && W <= 18) };
    let mut acc = [0u64; W];
    let mut lanes = [_mm_setzero_si128(); 9];
    for (entry, &mask) in entries.iter().zip(masks) {
        let m = _mm_set1_epi64x(mask as i64);
        for (j, lane) in lanes.iter_mut().enumerate().take(W / 2) {
            // SAFETY: `entry` is `W` words, so words 2j and 2j + 1 are in it
            // for every j below W / 2; the load is unaligned.
            let v = unsafe { _mm_loadu_si128(entry.as_ptr().add(2 * j).cast()) };
            *lane = _mm_or_si128(*lane, _mm_and_si128(v, m));
        }
    }
    for (j, lane) in lanes.iter().enumerate().take(W / 2) {
        // SAFETY: as above, into `acc`.
        unsafe { _mm_storeu_si128(acc.as_mut_ptr().add(2 * j).cast(), *lane) };
    }
    acc
}

/// [`scan`] in AVX2.
///
/// # Safety
///
/// The CPU must support AVX2, and `W` must be a multiple of four.
#[target_feature(enable = "avx2")]
unsafe fn scan_avx2<const W: usize>(entries: &[[u64; W]], masks: &[u64]) -> [u64; W] {
    use core::arch::x86_64::*;
    let mut acc = [0u64; W];
    let mut lanes = [_mm256_setzero_si256(); 3];
    for (entry, &mask) in entries.iter().zip(masks) {
        let m = _mm256_set1_epi64x(mask as i64);
        for (j, lane) in lanes.iter_mut().enumerate().take(W / 4) {
            // SAFETY: `entry` is `W` words and `W` is a multiple of four, so
            // words 4j to 4j + 3 are in it for every j below W / 4.
            let v = unsafe { _mm256_loadu_si256(entry.as_ptr().add(4 * j).cast()) };
            *lane = _mm256_or_si256(*lane, _mm256_and_si256(v, m));
        }
    }
    for (j, lane) in lanes.iter().enumerate().take(W / 4) {
        // SAFETY: as above, into `acc`.
        unsafe { _mm256_storeu_si256(acc.as_mut_ptr().add(4 * j).cast(), *lane) };
    }
    acc
}

/// [`scan`] over affine P-256 points, as their eight words.
#[inline]
pub(crate) fn scan_affine(
    entries: &[crate::nist::point::AffinePoint<crate::p256::P256>],
    masks: &[u64],
) -> crate::nist::point::AffinePoint<crate::p256::P256> {
    use crate::nist::point::AffinePoint;
    use crate::p256::Fp;
    const _: () = assert!(core::mem::size_of::<AffinePoint<crate::p256::P256>>() == 64);
    // SAFETY: `AffinePoint` is `repr(C)` over two `Fp`, each a
    // `repr(transparent)` `[u64; 4]`, so a slice of them is a slice of
    // `[u64; 8]` of the same length, alignment and lifetime; the assertion
    // above holds the size to that.
    let words: &[[u64; 8]] =
        unsafe { core::slice::from_raw_parts(entries.as_ptr().cast(), entries.len()) };
    let w = scan(words, masks);
    AffinePoint {
        x: Fp([w[0], w[1], w[2], w[3]]),
        y: Fp([w[4], w[5], w[6], w[7]]),
    }
}

/// [`scan`] over Jacobian P-256 points, as their twelve words.
#[inline]
pub(crate) fn scan_point(
    entries: &[crate::nist::point::Point<crate::p256::P256>],
    masks: &[u64],
) -> [[u64; 4]; 3] {
    use crate::nist::point::Point;
    const _: () = assert!(core::mem::size_of::<Point<crate::p256::P256>>() == 96);
    // SAFETY: `Point` is `repr(C)` over three `Fp`, each a
    // `repr(transparent)` `[u64; 4]`; as for `scan_affine`.
    let words: &[[u64; 12]] =
        unsafe { core::slice::from_raw_parts(entries.as_ptr().cast(), entries.len()) };
    let w = scan(words, masks);
    [
        [w[0], w[1], w[2], w[3]],
        [w[4], w[5], w[6], w[7]],
        [w[8], w[9], w[10], w[11]],
    ]
}

/// A formula's slots with `values` in the first ones and the rest
/// uninitialised: zeroing them would cost a store per word on every point
/// operation, and the formula writes every slot it reads but these.
#[inline(always)]
fn slots<const N: usize>(values: &[&[u64; 4]]) -> [MaybeUninit<u64>; N] {
    let mut buf = [const { MaybeUninit::uninit() }; N];
    for (i, v) in values.iter().enumerate() {
        for (j, w) in v.iter().enumerate() {
            buf[4 * i + j].write(*w);
        }
    }
    buf
}

/// Field elements from the slots `first..first + K`.
///
/// # Safety
///
/// The formula must have written those slots.
#[inline(always)]
unsafe fn read<const N: usize, const K: usize>(
    buf: &[MaybeUninit<u64>; N],
    first: usize,
) -> [[u64; 4]; K] {
    let mut out = [[0u64; 4]; K];
    for (k, value) in out.iter_mut().enumerate() {
        for (j, w) in value.iter_mut().enumerate() {
            // SAFETY: the caller guarantees the slot was written.
            *w = unsafe { buf[4 * (first + k) + j].assume_init() };
        }
    }
    out
}

/// Jacobian doubling as one block of assembly, where the CPU has BMI2 and
/// ADX; `None` where it does not.
#[inline(always)]
pub(crate) fn point_double(x: &[u64; 4], y: &[u64; 4], z: &[u64; 4]) -> Option<[[u64; 4]; 3]> {
    if !has_adx() {
        return None;
    }
    let mut buf = slots::<60>(&[x, y, z]);
    // SAFETY: the CPU has BMI2 and ADX; the formula writes X3, Y3, Z3, slots
    // 3 to 5.
    unsafe {
        super::p256_x86_point::double_adx(&mut buf);
        Some(read(&buf, 3))
    }
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
    let mut buf = slots::<96>(&[p[0], p[1], p[2], q[0], q[1], q[2]]);
    // SAFETY: the CPU has BMI2 and ADX; the formula writes X3, Y3, Z3, H, R,
    // slots 6 to 10.
    unsafe {
        super::p256_x86_point::add_adx(&mut buf);
        let [h, r] = read(&buf, 9);
        Some((read(&buf, 6), h, r))
    }
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
    let mut buf = slots::<80>(&[p[0], p[1], p[2], q[0], q[1]]);
    // SAFETY: the CPU has BMI2 and ADX; the formula writes X3, Y3, Z3, H, R,
    // slots 5 to 9.
    unsafe {
        super::p256_x86_point::add_affine_adx(&mut buf);
        let [h, r] = read(&buf, 8);
        Some((read(&buf, 5), h, r))
    }
}

/// Words of the buffer [`mul_scalar`] keeps: the addition's slots, the most
/// of any formula it runs. The doubling in place uses a prefix of it.
pub(crate) const LADDER: usize = 96;

/// `scalar * p`, as `Point::mul_scalar_generic` computes it -- the same
/// digits, window, doublings and additions, so the same words -- on one
/// buffer kept for the whole multiplication; `None` without BMI2 and ADX.
///
/// The accumulator lives in the buffer's first three slots, where both
/// `double_in_place_adx` and `add_adx` read it, so the five doublings of a
/// digit run back to back on it in place, and nothing is copied in or out
/// but each digit's entry and the addition's result. The generic loop moves
/// every point through a fresh buffer per formula. `p384_x86::mul_scalar`
/// is the same loop over P-384's formulas.
///
/// The additions are `Point::add_unequal`'s, and the argument there for why
/// they may be incomplete holds unchanged: this is that loop. The identity
/// cases are its selections, on the same masks, behind the same barrier.
/// The last addition is the complete one, on `Point`.
pub(crate) fn mul_scalar(
    p: &crate::nist::point::Point<crate::p256::P256>,
    scalar: &<crate::p256::P256 as crate::nist::point::Curve>::Scalar,
) -> Option<crate::nist::point::Point<crate::p256::P256>> {
    use super::gentable::{digit_count, signed_digits_w, Window, WIDTH};
    use crate::nist::arith::Field;
    use crate::nist::point::Point;
    use crate::p256::Fp;
    if !has_adx() {
        return None;
    }
    let bytes = scalar.to_bytes();
    let bytes = bytes.as_ref();
    let digits = signed_digits_w(bytes, WIDTH);
    let n = digit_count(bytes.len(), WIDTH);
    let window = Window::new(p);

    let mut buf = [const { MaybeUninit::uninit() }; LADDER];
    let put = |buf: &mut [MaybeUninit<u64>; LADDER], slot: usize, q: &Point<crate::p256::P256>| {
        for (k, c) in [q.x(), q.y(), q.z()].iter().enumerate() {
            for (j, w) in c.0.iter().enumerate() {
                buf[4 * (slot + k) + j].write(*w);
            }
        }
    };
    put(&mut buf, 0, &window.select(digits[n - 1]));
    let doublings = |buf: &mut [MaybeUninit<u64>; LADDER]| {
        let ip: &mut [MaybeUninit<u64>; 48] = (&mut buf[..48])
            .try_into()
            .expect("the doubling's slots are a prefix of the buffer");
        for _ in 0..WIDTH {
            // SAFETY: the CPU has BMI2 and ADX; X, Y and Z, slots 0 to 2,
            // hold the accumulator, every coordinate below p.
            unsafe { super::p256_x86_point::double_in_place_adx(ip) };
        }
    };
    for i in (1..n - 1).rev() {
        // The scan first: it does not depend on the accumulator.
        let entry = window.select(digits[i]);
        doublings(&mut buf);
        // SAFETY: the CPU has BMI2 and ADX, and slots 0 to 2 hold the
        // accumulator.
        unsafe { ladder_add(&mut buf, &entry) };
    }
    doublings(&mut buf);
    // SAFETY: slots 0 to 2 are written.
    let [x, y, z] = unsafe { read::<LADDER, 3>(&buf, 0) };
    let acc = Point::from_coordinates(Fp(x), Fp(y), Fp(z));
    Some(acc.add(&window.select(digits[0])))
}

/// Words of the buffer [`table_mul`] keeps: the mixed addition's slots.
// Without `std` there is no table, and only the probes read this.
#[cfg_attr(not(feature = "std"), allow(dead_code))]
pub(crate) const TABLE: usize = 80;

/// `scalar * G` from the generator table, as `gentable::mul_generic`
/// computes it -- the same digits, entries and additions, so the same words
/// -- on one buffer kept for the whole multiplication; `None` without BMI2
/// and ADX.
///
/// The accumulator lives in the buffer's first three slots, where
/// `add_affine_adx` reads it, and each digit's entry is written beside it:
/// nothing else moves per digit. The incomplete additions are
/// `Point::add_affine_unequal_or_keep`'s, on the same masks behind the same
/// barrier, for the windows `gentable::mul` shows cannot meet an equal
/// point; the complete ones that follow are its own, on `Point`.
#[cfg(feature = "std")]
pub(crate) fn table_mul<const E: usize>(
    windows: &crate::nist::gentable::Windows<crate::p256::P256, E>,
    scalar: &<crate::p256::P256 as crate::nist::point::Curve>::Scalar,
) -> Option<crate::nist::point::Point<crate::p256::P256>> {
    use super::gentable::{digit_count, signed_digits_w, width, window};
    use crate::nist::arith::Field;
    use crate::nist::point::{Curve, Point};
    use crate::p256::{Fp, P256};
    if !has_adx() {
        return None;
    }
    let w = width::<E>();
    let bytes = scalar.to_bytes();
    let digits = signed_digits_w(bytes.as_ref(), w);
    let n = digit_count(bytes.as_ref().len(), w);
    // The first window whose addition must be complete: public, from the
    // curve and the width.
    let first_complete = (0..n)
        .find(|&i| w * (i + 1) >= P256::ORDER_BITS)
        .unwrap_or(n);

    let mut buf = [const { MaybeUninit::uninit() }; TABLE];
    let put = |buf: &mut [MaybeUninit<u64>; TABLE], slot: usize, words: &[u64; 4]| {
        for (j, x) in words.iter().enumerate() {
            buf[4 * slot + j].write(*x);
        }
    };
    let identity = Point::<P256>::identity();
    put(&mut buf, 0, &identity.x().0);
    put(&mut buf, 1, &identity.y().0);
    put(&mut buf, 2, &identity.z().0);
    for (i, &digit) in digits.iter().enumerate().take(first_complete) {
        let (x, y) = window(windows, i).select(digit);
        // SAFETY: the CPU has BMI2 and ADX, and slots 0 to 2 hold the
        // accumulator.
        unsafe { table_add(&mut buf, &x.0, &y.0, digit) };
    }
    // SAFETY: slots 0 to 2 are written.
    let [x, y, z] = unsafe { read::<TABLE, 3>(&buf, 0) };
    let mut acc = Point::from_coordinates(Fp(x), Fp(y), Fp(z));
    for (i, &digit) in digits.iter().enumerate().take(n).skip(first_complete) {
        acc = window(windows, i).add_to(&acc, digit, true);
    }
    Some(acc)
}

/// One digit's addition in [`mul_scalar`], after its doublings: `entry`,
/// the window's multiple for the digit, added to the accumulator in slots 0
/// to 2 by the Jacobian addition, and the identity cases selected as
/// `Point::add_unequal` selects them -- an entry at infinity keeps the
/// accumulator, the accumulator at infinity takes the entry -- both tests
/// behind one barrier. The `ct_p256_ladder_add` probe is this and the
/// entry's read.
///
/// # Safety
///
/// The CPU must support BMI2 and ADX, and slots 0 to 2 must hold a point,
/// every coordinate below p.
#[inline(always)]
pub(crate) unsafe fn ladder_add(
    buf: &mut [MaybeUninit<u64>; LADDER],
    entry: &crate::nist::point::Point<crate::p256::P256>,
) {
    use crate::nist::arith::{select, Field};
    use crate::p256::Fp;
    for (k, c) in [entry.x(), entry.y(), entry.z()].iter().enumerate() {
        for (j, w) in c.0.iter().enumerate() {
            buf[4 * (3 + k) + j].write(*w);
        }
    }
    // SAFETY: the caller guarantees the instructions and slots 0 to 2;
    // slots 3 to 5 are written above, below p. The formula writes X3, Y3,
    // Z3, slots 6 to 8.
    unsafe { super::p256_x86_point::add_adx(buf) };
    // SAFETY: slots 0 to 8 are written.
    let [ax, ay, az, ex, ey, ez, sx, sy, sz] = unsafe { read::<LADDER, 9>(buf, 0) };
    let [entry_inf, acc_inf] = core::hint::black_box([Fp(ez).zero_mask(), Fp(az).zero_mask()]);
    for (k, (a, (e, s))) in [ax, ay, az]
        .iter()
        .zip([ex, ey, ez].iter().zip([sx, sy, sz].iter()))
        .enumerate()
    {
        let r = select(acc_inf, *e, select(entry_inf, *a, *s));
        for (j, w) in r.iter().enumerate() {
            buf[4 * k + j].write(*w);
        }
    }
}

/// One digit's addition in [`table_mul`]: `(x, y)`, the window's entry for
/// `digit`, added to the accumulator in slots 0 to 2 by the mixed addition,
/// and the identity cases selected as `Point::add_affine_unequal_or_keep`
/// selects them -- the accumulator at infinity takes the entry, a zero
/// digit keeps the accumulator -- both tests behind one barrier. The
/// `ct_p256_table_add` probe is this and the entry's read.
///
/// # Safety
///
/// The CPU must support BMI2 and ADX, and slots 0 to 2 must hold a point,
/// every coordinate below p.
#[cfg_attr(not(feature = "std"), allow(dead_code))]
#[inline(always)]
pub(crate) unsafe fn table_add(
    buf: &mut [MaybeUninit<u64>; TABLE],
    x: &[u64; 4],
    y: &[u64; 4],
    digit: i8,
) {
    use crate::nist::arith::{select, Field};
    use crate::p256::Fp;
    let put = |buf: &mut [MaybeUninit<u64>; TABLE], slot: usize, w: &[u64; 4]| {
        for (j, v) in w.iter().enumerate() {
            buf[4 * slot + j].write(*v);
        }
    };
    put(buf, 3, x);
    put(buf, 4, y);
    // SAFETY: the caller guarantees the instructions and slots 0 to 2;
    // slots 3 and 4 are written above, below p. The formula writes X3, Y3,
    // Z3, slots 5 to 7.
    unsafe { super::p256_x86_point::add_affine_adx(buf) };
    // SAFETY: slots 0 to 7 are written.
    let [ax, ay, az, _, _, sx, sy, sz] = unsafe { read::<TABLE, 8>(buf, 0) };
    // All ones for a zero digit, which adds the identity: as in
    // `AffineWindow::add_to`.
    let keep = ((digit as u8 as u64).wrapping_sub(1) >> 63).wrapping_neg();
    let [acc_inf, keep] = core::hint::black_box([Fp(az).zero_mask(), keep]);
    let lifted = [*x, *y, Fp::ONE.0];
    for (k, (a, (l, s))) in [ax, ay, az]
        .iter()
        .zip(lifted.iter().zip([sx, sy, sz].iter()))
        .enumerate()
    {
        put(buf, k, &select(keep, *a, select(acc_inf, *l, *s)));
    }
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
/// The CPU must support BMI2 and ADX; see `has_adx`.
#[inline]
pub unsafe fn mul_adx(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: the caller guarantees the instructions exist. The block reads
    // the 32 bytes behind each of `a` and `b`, which are live references to
    // `[u64; 4]`, writes only registers it declares, and touches neither the
    // stack nor memory. The pointer registers are reused for constants at the
    // end, so they are declared clobbered.
    unsafe {
        asm!(
            ".p2align 6",
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
/// doubled, plus the squares, then `reduce_tail`.
///
/// # Safety
///
/// The CPU must support BMI2 and ADX; see `has_adx`.
#[inline]
pub unsafe fn square_adx(a: &[u64; 4]) -> [u64; 4] {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    // SAFETY: the caller guarantees the instructions exist; otherwise as for
    // `mul_plain`.
    unsafe {
        asm!(
            ".p2align 6",
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
            ".p2align 6",
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
            ".p2align 6",
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
            ".p2align 6",
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
            ".p2align 6",
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

    /// `k * a` by the formulas' small-multiple operation, against `k`
    /// additions, for every value that takes each path through its fold: the
    /// carry out of adding `q + q*2^224` with and without a borrow back from
    /// subtracting `q*2^96 + q*2^192`, for every top word `q` the multiple can
    /// have. Those need the low 256 bits of `k * a` within about `q * 2^224`
    /// of `2^256`, which random values reach about once in 2^32 tries, so
    /// they are built: `k * a = q * 2^256 + (2^256 - q * 2^224 + d)`, solved
    /// for `a` where `k` divides it and `a < p`.
    ///
    /// Dropping the carry out of the addition (`adc {c}, 0`) passed every
    /// other test in the crate, the 50,000 arbitrary-coordinate formula
    /// comparisons included, and fails this one. Dropping the borrow out of
    /// the subtraction passes this one too, and is not a missed bug: when it
    /// borrows, the value is above `p` by construction and the final
    /// subtraction happens whatever the top word says.
    #[test]
    fn the_small_multiples_take_every_path_through_their_fold() {
        let times = |k: u64, a: [u64; 4]| -> [u64; 4] {
            let mut buf = [const { MaybeUninit::uninit() }; 8];
            for (i, w) in a.iter().enumerate() {
                buf[i].write(*w);
            }
            // SAFETY: the formula reads slot 0, written above, and writes
            // slot 1, read below; it needs no CPU feature beyond the
            // baseline (`shld`, `adc`, `sbb`, `cmovc`).
            unsafe {
                match k {
                    3 => crate::nist::p256_x86_point::times3_adx(&mut buf),
                    4 => crate::nist::p256_x86_point::times4_adx(&mut buf),
                    _ => crate::nist::p256_x86_point::times8_adx(&mut buf),
                }
                read::<8, 2>(&buf, 0)[1]
            }
        };
        let below_p = |x: &[u64; 4]| {
            (0..4)
                .rev()
                .find(|&i| x[i] != P[i])
                .is_some_and(|i| x[i] < P[i])
        };
        let mut checked = [0usize; 9];
        let mut inputs = std::vec::Vec::new();
        for k in [3u64, 4, 8] {
            for q in 1..k {
                for (d, high) in (0..256u64).flat_map(|d| [(d, false), (d, true)]) {
                    // T = q*2^256 + 2^256 - q*2^224 + d, where adding
                    // q*2^224 wraps to `d + q` and subtracting q*2^192
                    // then borrows; or with 2q*2^192 more, where it wraps
                    // the same way and does not borrow. As five words; then
                    // T / k.
                    let mut t = [d, 0, 0, (q << 32).wrapping_neg(), q];
                    if high {
                        t[3] = t[3].wrapping_add(2 * q);
                    }
                    let mut rem = 0u128;
                    let mut a = [0u64; 5];
                    for i in (0..5).rev() {
                        let cur = (rem << 64) | t[i] as u128;
                        a[i] = (cur / k as u128) as u64;
                        rem = cur % k as u128;
                    }
                    let a4 = [a[0], a[1], a[2], a[3]];
                    if rem == 0 && a[4] == 0 && below_p(&a4) {
                        inputs.push((k, a4));
                        checked[k as usize] += 1;
                    }
                }
            }
        }
        // Every k found inputs on both sides.
        assert!(
            checked[3] > 0 && checked[4] > 0 && checked[8] > 0,
            "{checked:?}"
        );
        let mut state = 0x7175_u64;
        for _ in 0..20_000 {
            for k in [3u64, 4, 8] {
                inputs.push((k, operand(&mut state, false)));
            }
        }
        for (k, a) in [3u64, 4, 8].iter().flat_map(|k| {
            [[0u64; 4], [1, 0, 0, 0], [P[0] - 1, P[1], P[2], P[3]]].map(move |a| (*k, a))
        }) {
            inputs.push((k, a));
        }
        for (k, a) in inputs {
            let mut want = a;
            for _ in 1..k {
                want = rust::add(want, a);
            }
            assert_eq!(times(k, a), want, "{k} * {a:x?}");
        }
    }

    /// The doubling's fused operations, `cm * a - dm * b`, against repeated
    /// generic additions and subtractions: on every pair of edges, on a
    /// million random pairs, and on inputs built to take each side of the
    /// fold (`fold_edges`), where the sum with `(t + 1)(2^256 - p)` carries
    /// out of the top word and where it just fails to.
    #[test]
    fn the_fused_operations_agree_with_repeated_additions() {
        if !has_adx() {
            return;
        }
        let cms = |cm: u64, dm: u64, a: [u64; 4], b: [u64; 4]| -> [u64; 4] {
            let mut buf = [const { MaybeUninit::uninit() }; 12];
            for i in 0..4 {
                buf[i].write(a[i]);
                buf[4 + i].write(b[i]);
            }
            // SAFETY: the CPU has BMI2 and ADX; the formula reads slots 0
            // and 1, written above, and writes slot 2, read below.
            unsafe {
                use crate::nist::p256_x86_point as f;
                match (cm, dm) {
                    (3, 8) => f::cms_3_8_adx(&mut buf),
                    (4, 1) => f::cms_4_1_adx(&mut buf),
                    _ => f::cms_12_9_adx(&mut buf),
                }
                read::<12, 3>(&buf, 0)[2]
            }
        };
        let want = |cm: u64, dm: u64, a: [u64; 4], b: [u64; 4]| -> [u64; 4] {
            let mut r = [0u64; 4];
            for _ in 0..cm {
                r = rust::add(r, a);
            }
            for _ in 0..dm {
                r = rust::sub(r, b);
            }
            r
        };
        let mut checked = 0usize;
        let mut sides = [0usize; 2];
        for (cm, dm) in [(3u64, 8u64), (4, 1), (12, 9)] {
            for (a, b, carries) in crate::nist::fold_edges::cases(&P, cm, dm) {
                let (a, b) = ([a[0], a[1], a[2], a[3]], [b[0], b[1], b[2], b[3]]);
                assert_eq!(
                    cms(cm, dm, a, b),
                    want(cm, dm, a, b),
                    "{cm} {a:x?} - {dm} {b:x?}"
                );
                sides[usize::from(carries)] += 1;
            }
        }
        assert!(sides[0] > 20 && sides[1] > 20, "{sides:?}");
        let pm1 = [P[0] - 1, P[1], P[2], P[3]];
        let edges = [
            [0u64; 4],
            [1, 0, 0, 0],
            [2, 0, 0, 0],
            pm1,
            [P[0] - 2, P[1], P[2], P[3]],
        ];
        let mut state = 0xc35_u64;
        let mut pairs: std::vec::Vec<([u64; 4], [u64; 4])> = std::vec::Vec::new();
        for a in edges {
            for b in edges {
                pairs.push((a, b));
            }
        }
        for i in 0..1 << 18 {
            let s = i % 2 == 1;
            pairs.push((operand(&mut state, s), operand(&mut state, s)));
        }
        for (a, b) in pairs {
            for (cm, dm) in [(3u64, 8u64), (4, 1), (12, 9)] {
                assert_eq!(
                    cms(cm, dm, a, b),
                    want(cm, dm, a, b),
                    "{cm} {a:x?} - {dm} {b:x?}"
                );
            }
            checked += 1;
        }
        assert!(checked > 1 << 18);
    }

    /// The doubling in place against `Point::double_formula`, word for
    /// word, on points with `Z` far from one and on arbitrary coordinates,
    /// and run twice over, as the loop runs it.
    #[test]
    fn the_doubling_in_place_is_the_formula() {
        use crate::nist::point::Point;
        use crate::p256::{Fp, P256};
        if !has_adx() {
            return;
        }
        let mut state = 0x2d_u64;
        let mut p = Point::<P256>::generator().double().double();
        for i in 0..2000 {
            let q = if i % 2 == 0 {
                p = p.add(&Point::generator());
                p
            } else {
                let s = i % 4 == 1;
                let c = [
                    operand(&mut state, s),
                    operand(&mut state, s),
                    operand(&mut state, s),
                ];
                Point::from_coordinates(Fp(c[0]), Fp(c[1]), Fp(c[2]))
            };
            let mut buf = [const { MaybeUninit::uninit() }; 48];
            for (k, c) in [q.x(), q.y(), q.z()].iter().enumerate() {
                for (j, w) in c.0.iter().enumerate() {
                    buf[4 * k + j].write(*w);
                }
            }
            for _ in 0..2 {
                // SAFETY: the CPU has BMI2 and ADX; slots 0 to 2 hold the
                // point, below p.
                unsafe { crate::nist::p256_x86_point::double_in_place_adx(&mut buf) };
            }
            // SAFETY: slots 0 to 2 are written.
            let got: [[u64; 4]; 3] = unsafe { read(&buf, 0) };
            let want = q.double_formula().double_formula();
            assert_eq!(got, [want.x().0, want.y().0, want.z().0], "{i}");
        }
    }

    /// Scalars for the multiplications: zero, `1 .. 40` and `n - 1 .. n -
    /// 40`, where the last, complete addition is needed and where an
    /// incomplete one would fail if the argument for it did not hold, and
    /// `count` random ones.
    fn scalars(
        count: usize,
    ) -> std::vec::Vec<<crate::p256::P256 as crate::nist::point::Curve>::Scalar> {
        use crate::nist::arith::Field;
        use crate::nist::point::Curve;
        type S = <crate::p256::P256 as Curve>::Scalar;
        let mut out = std::vec![S::ZERO];
        let (mut small, mut minus) = (S::ZERO, S::ZERO);
        for _ in 0..40 {
            small = small.add(&S::ONE);
            minus = minus.sub(&S::ONE);
            out.push(small);
            out.push(minus);
        }
        let mut state = 0x5ca1_u64;
        for _ in 0..count {
            let mut bytes = S::zero_bytes();
            for chunk in bytes.as_mut().chunks_mut(8) {
                chunk.copy_from_slice(&next(&mut state).to_le_bytes()[..chunk.len()]);
            }
            out.push(S::from_bytes_reduced(&bytes));
        }
        out
    }

    /// The MULX/ADX scalar multiplications, called directly so that a CPU
    /// with IFMA runs them too, against the generic ones they stand in for:
    /// word for word, since they are the same operations on the same values.
    /// `mul_scalar` on the generator, another point and the identity;
    /// `table_mul` on the generator table.
    #[test]
    fn the_buffer_multiplications_agree_with_the_generic_ones() {
        use crate::nist::gentable::HasGeneratorTable;
        use crate::nist::point::Point;
        use crate::p256::P256;
        if !has_adx() {
            return;
        }
        let words = |p: &Point<P256>| (p.x().0, p.y().0, p.z().0);
        let g = Point::<P256>::generator();
        let points = [g, g.mul_scalar_generic(&scalars(1)[81]), Point::identity()];
        let ks = scalars(1000);
        for p in &points {
            for k in &ks {
                let got = mul_scalar(p, k).expect("BMI2 and ADX");
                assert_eq!(words(&got), words(&p.mul_scalar_generic(k)));
            }
        }
        for k in &ks {
            let got = crate::p256::table_mul_adx_for_tests(k).expect("BMI2 and ADX");
            assert_eq!(words(&got), words(&P256::table_mul_generic_for_tests(k)));
        }
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
