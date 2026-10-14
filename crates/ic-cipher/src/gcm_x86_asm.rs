//! The bulk loops of the 128- and 256-bit fused AES-GCM kernels, as inline
//! assembly.
//!
//! [`crate::gcm_x86`] chooses a kernel and handles the AAD, the message tail,
//! the length block and the tag; the whole groups in between come here, a
//! seal or an open in one `asm!` block, as the 512-bit kernel's loops are.
//! Given the same work as intrinsics, the compiler kept the stitched step out
//! of line, passed all eight AES states back through the stack on every
//! iteration, and multiplied four times a block where three suffice. Written
//! out, every value has a register for the whole of an iteration.
//!
//! # The arithmetic
//!
//! Each block's product is Karatsuba's, three carry-less multiplies, the
//! middle term recovered once per group, as in the 512-bit kernel. The
//! accumulator `Y` is XORed into the group's first block, `(Y ^ X0)*H^n`,
//! and that block is multiplied last of its group.
//!
//! The powers of `H` are twisted, each multiplied by `x^-1` in the field
//! ([`twist`]). The carry-less product of a block and a twisted power
//! is then the field product's 256 bits already in place, where an untwisted
//! one is a bit short and `clmul::reduce` shifts it, and the reduction is
//! two more carry-less multiplies by `x^-1`'s high half (`x8_reduce!`). That
//! reduction is some fifteen instructions where `clmul::reduce`'s shifts are
//! forty, on the same pipes as the AES rounds: the eight-block loop took a
//! fifth less time per group with it.
//!
//! # The schedule
//!
//! Each iteration encrypts one group and hashes another: one block's product
//! after each of AES rounds 1 to 8, the reduction after round 9. Sealing,
//! GHASH needs the ciphertext, so a seal encrypts its first group alone,
//! each iteration hashes the group before its own, and the last group is
//! hashed alone ([`x8_seal`], [`y16_seal`]). Opening, each iteration hashes
//! the group it is about to decrypt, before its store overwrites it
//! ([`x8_open`], [`y16_open`]).
//!
//! Other arrangements were measured and made no difference worth keeping:
//! each product's three multiplies spread among the round's `AESENC`s rather
//! than after them, the products spread over twelve rounds instead of eight,
//! block 0 multiplied first rather than last, hashing two groups behind
//! rather than one, prefetching ahead, and ten blocks per group with the
//! round keys as memory operands (slower). On the CPU measured (Zen 5)
//! `AESENC` issues twice a cycle with four cycles of latency and
//! `PCLMULQDQ` once every two cycles, so eight blocks of AES-256 are sixty
//! cycles of AES and twenty-six multiplies fifty-two of the multiplier; the
//! loop runs within a third of the first.
//!
//! # Encodings
//!
//! - The eight-block kernel runs on any CPU with AES-NI, `PCLMULQDQ` and
//!   SSSE3, AVX or not, so it is written in the legacy SSE encoding. Those
//!   forms fault on a memory operand that is not 16-byte aligned, so every
//!   memory operand here is: the constants, the round keys (`__m128i`), and
//!   the powers of `H` (`gcm_x86::HashKey` is aligned). The message is only
//!   ever loaded and stored with `movdqu`.
//! - The sixteen-block kernel is VEX-encoded on `ymm` registers and needs
//!   AVX2, `VAES` and `VPCLMULQDQ`; it ends with `vzeroupper`.
//!
//! # Key sizes
//!
//! The round count is a const parameter, and the extra rounds of AES-192 and
//! AES-256 are assembled in or out by `.if` on it, so a block has no branch
//! but its loop's back edge, which counts groups. The groups and the key size
//! are public; nothing here branches on, or indexes memory by, a key, `H`,
//! the counter or the message.
//!
//! # Safety, for every function here
//!
//! Each is never inlined and holds nothing live across its one `asm!` block,
//! which names `xmm0`..`xmm15` (and their `ymm` halves) itself and declares
//! all sixteen clobbered, so on Windows the callee-saved `xmm6`..`xmm15` are
//! saved by the function's own prologue. No block touches the stack. Every
//! memory access is to a region the caller vouches for, listed on each
//! function, or to [`CONSTS`].

use core::arch::asm;
use core::arch::x86_64::*;

/// `p * x^-1` in GCM's field, for `p` byte-reversed: shift the 128-bit
/// integer left by one and, if its top bit was set, XOR in `x^-1`, whose
/// byte-reversed form is `0xc2000000_00000000_00000000_00000001`
/// (`x * (x^127 + x^6 + x + 1) = 1` modulo `x^128 + x^7 + x^2 + x + 1`).
///
/// The kernels here multiply by these: for a block `X` and a twisted power,
/// the carry-less product is already the 256-bit product aligned, which
/// `clmul::reduce` reaches only by shifting it a bit.
/// Without a branch on the top bit, which is a bit of `H`.
#[inline]
#[target_feature(enable = "sse2")]
pub(crate) fn twist(p: __m128i) -> __m128i {
    // Each 64-bit half shifted left, and the low half's top bit carried up.
    let shifted = _mm_or_si128(
        _mm_slli_epi64::<1>(p),
        _mm_slli_si128::<8>(_mm_srli_epi64::<63>(p)),
    );
    // All ones if bit 127 was set, from the top 32-bit lane's sign.
    let mask = _mm_srai_epi32::<31>(_mm_shuffle_epi32::<0xff>(p));
    let poly = _mm_set_epi64x(0xc200_0000_0000_0000_u64 as i64, 1);
    _mm_xor_si128(shifted, _mm_and_si128(mask, poly))
}

/// Masks, increments and the reduction constant, laid out so that each is
/// at a 16-byte boundary for the legacy encoding and 32 bytes wide for `ymm`:
///
/// - `0`: byte reversal, in both lanes;
/// - `32`: counter-field reversal (bytes 12..16 reversed, the rest kept), in
///   both lanes: `gcm_x86`'s `ctr_swap`;
/// - `64`: `+2` in each lane's counter;
/// - `96`: the lane offsets `0, 1`;
/// - `128`: `+1` in the counter, one lane;
/// - `144`: `x^-1`, byte-reversed, `0xc2000000_00000000_00000000_00000001`
///   (see `x8_reduce!`).
#[repr(C, align(32))]
pub(crate) struct Consts([u8; 160]);

pub(crate) static CONSTS: Consts = Consts({
    let mut c = [0u8; 160];
    let mut lane = 0;
    while lane < 2 {
        let mut i = 0;
        while i < 16 {
            c[lane * 16 + i] = (15 - i) as u8;
            c[32 + lane * 16 + i] = if i < 12 { i as u8 } else { (27 - i) as u8 };
            i += 1;
        }
        // The counter is the top 32-bit lane, little-endian once swapped.
        c[64 + lane * 16 + 12] = 2;
        c[96 + lane * 16 + 12] = lane as u8;
        lane += 1;
    }
    c[128 + 12] = 1;
    c[144] = 1;
    c[144 + 15] = 0xc2;
    c
});

/// `asm!` with the clobbers every block here shares: all sixteen vector
/// registers.
macro_rules! asm_all_vectors {
    ($($operands:tt)*) => {
        asm!(
            $($operands)*
            out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
            out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
            out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
            out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
        )
    };
}

// ---------------------------------------------------------------------------
// Eight blocks per iteration: AES-NI and PCLMULQDQ, legacy SSE encoding.
//
// Registers: `xmm0..xmm7` the AES states, `xmm8` the round key (and the
// counter before the rounds start), `xmm9` the accumulator `Y`,
// `xmm10..xmm12` the unreduced lo / Karatsuba middle / hi, `xmm13..xmm15`
// GHASH temporaries.

/// The eight counter blocks of this iteration into `xmm0..xmm7`, whitened
/// with round key 0, and the counter at `{st} + 16` advanced past them.
macro_rules! x8_ctr {
    () => {
        concat!(
            "movdqu xmm8, xmmword ptr [{st} + 16]\n",
            "movdqa xmm0, xmm8\n",
            "pshufb xmm0, xmmword ptr [{c} + 32]\n",
            "paddd xmm8, xmmword ptr [{c} + 128]\n",
            "movdqa xmm1, xmm8\n",
            "pshufb xmm1, xmmword ptr [{c} + 32]\n",
            "paddd xmm8, xmmword ptr [{c} + 128]\n",
            "movdqa xmm2, xmm8\n",
            "pshufb xmm2, xmmword ptr [{c} + 32]\n",
            "paddd xmm8, xmmword ptr [{c} + 128]\n",
            "movdqa xmm3, xmm8\n",
            "pshufb xmm3, xmmword ptr [{c} + 32]\n",
            "paddd xmm8, xmmword ptr [{c} + 128]\n",
            "movdqa xmm4, xmm8\n",
            "pshufb xmm4, xmmword ptr [{c} + 32]\n",
            "paddd xmm8, xmmword ptr [{c} + 128]\n",
            "movdqa xmm5, xmm8\n",
            "pshufb xmm5, xmmword ptr [{c} + 32]\n",
            "paddd xmm8, xmmword ptr [{c} + 128]\n",
            "movdqa xmm6, xmm8\n",
            "pshufb xmm6, xmmword ptr [{c} + 32]\n",
            "paddd xmm8, xmmword ptr [{c} + 128]\n",
            "movdqa xmm7, xmm8\n",
            "pshufb xmm7, xmmword ptr [{c} + 32]\n",
            "paddd xmm8, xmmword ptr [{c} + 128]\n",
            "movdqu xmmword ptr [{st} + 16], xmm8\n",
            "movdqu xmm8, xmmword ptr [{rk}]\n",
            "pxor xmm0, xmm8\n",
            "pxor xmm1, xmm8\n",
            "pxor xmm2, xmm8\n",
            "pxor xmm3, xmm8\n",
            "pxor xmm4, xmm8\n",
            "pxor xmm5, xmm8\n",
            "pxor xmm6, xmm8\n",
            "pxor xmm7, xmm8\n",
        )
    };
}

/// One AES round, `$insn`, with the round key at `{rk} + $off`, on all eight
/// states.
macro_rules! x8_round {
    ($insn:literal, $off:literal) => {
        concat!(
            "movdqu xmm8, xmmword ptr [{rk} + ",
            $off,
            "]\n",
            $insn,
            " xmm0, xmm8\n",
            $insn,
            " xmm1, xmm8\n",
            $insn,
            " xmm2, xmm8\n",
            $insn,
            " xmm3, xmm8\n",
            $insn,
            " xmm4, xmm8\n",
            $insn,
            " xmm5, xmm8\n",
            $insn,
            " xmm6, xmm8\n",
            $insn,
            " xmm7, xmm8\n",
        )
    };
}

/// Rounds 10 to the last. `{r}` is the round count, a constant, so the
/// `.if`s choose instructions at assembly time; there is no branch.
macro_rules! x8_last_rounds {
    () => {
        concat!(
            ".if {r} > 10\n",
            x8_round!("aesenc", "160"),
            x8_round!("aesenc", "176"),
            ".endif\n",
            ".if {r} > 12\n",
            x8_round!("aesenc", "192"),
            x8_round!("aesenc", "208"),
            ".endif\n",
            x8_round!("aesenclast", "{last}"),
        )
    };
}

/// XOR the keystream in `xmm0..xmm7` into the 128 bytes at `{p}`, in place.
macro_rules! x8_xor_store {
    () => {
        concat!(
            "movdqu xmm8, xmmword ptr [{p}]\n",
            "pxor xmm0, xmm8\n",
            "movdqu xmmword ptr [{p}], xmm0\n",
            "movdqu xmm8, xmmword ptr [{p} + 16]\n",
            "pxor xmm1, xmm8\n",
            "movdqu xmmword ptr [{p} + 16], xmm1\n",
            "movdqu xmm8, xmmword ptr [{p} + 32]\n",
            "pxor xmm2, xmm8\n",
            "movdqu xmmword ptr [{p} + 32], xmm2\n",
            "movdqu xmm8, xmmword ptr [{p} + 48]\n",
            "pxor xmm3, xmm8\n",
            "movdqu xmmword ptr [{p} + 48], xmm3\n",
            "movdqu xmm8, xmmword ptr [{p} + 64]\n",
            "pxor xmm4, xmm8\n",
            "movdqu xmmword ptr [{p} + 64], xmm4\n",
            "movdqu xmm8, xmmword ptr [{p} + 80]\n",
            "pxor xmm5, xmm8\n",
            "movdqu xmmword ptr [{p} + 80], xmm5\n",
            "movdqu xmm8, xmmword ptr [{p} + 96]\n",
            "pxor xmm6, xmm8\n",
            "movdqu xmmword ptr [{p} + 96], xmm6\n",
            "movdqu xmm8, xmmword ptr [{p} + 112]\n",
            "pxor xmm7, xmm8\n",
            "movdqu xmmword ptr [{p} + 112], xmm7\n",
        )
    };
}

/// Counter mode on one group: AES on its counters, XORed into the 128 bytes
/// at `{p}`.
macro_rules! x8_aes_group {
    () => {
        concat!(
            x8_ctr!(),
            x8_round!("aesenc", "16"),
            x8_round!("aesenc", "32"),
            x8_round!("aesenc", "48"),
            x8_round!("aesenc", "64"),
            x8_round!("aesenc", "80"),
            x8_round!("aesenc", "96"),
            x8_round!("aesenc", "112"),
            x8_round!("aesenc", "128"),
            x8_round!("aesenc", "144"),
            x8_last_rounds!(),
            x8_xor_store!(),
        )
    };
}

/// One block's GHASH product: block `j` at `[$src + $off]`, byte-reversed,
/// times the twisted `H^(8-j)` at `{pw} + $off` by Karatsuba -- `{pk}` holds
/// the XOR of each power's halves -- into the sums `xmm10..xmm12`. `mov`
/// starts the sums with this block; `add` adds to them; `y` adds, after
/// XORing the accumulator into the block.
macro_rules! x8_gblock {
    (mov, $src:literal, $off:literal) => {
        concat!(
            "movdqu xmm13, xmmword ptr [", $src, " + ", $off, "]\n",
            "pshufb xmm13, xmmword ptr [{c}]\n",
            "pshufd xmm11, xmm13, 0x4e\n",
            "pxor xmm11, xmm13\n",
            "pclmulqdq xmm11, xmmword ptr [{pk} + ", $off, "], 0x00\n",
            "movdqa xmm10, xmm13\n",
            "pclmulqdq xmm10, xmmword ptr [{pw} + ", $off, "], 0x00\n",
            "movdqa xmm12, xmm13\n",
            "pclmulqdq xmm12, xmmword ptr [{pw} + ", $off, "], 0x11\n",
        )
    };
    (add, $src:literal, $off:literal) => {
        concat!(
            "movdqu xmm13, xmmword ptr [", $src, " + ", $off, "]\n",
            "pshufb xmm13, xmmword ptr [{c}]\n",
            x8_gblock!(@mul $off),
        )
    };
    (y, $src:literal, $off:literal) => {
        concat!(
            "movdqu xmm13, xmmword ptr [", $src, " + ", $off, "]\n",
            "pshufb xmm13, xmmword ptr [{c}]\n",
            "pxor xmm13, xmm9\n",
            x8_gblock!(@mul $off),
        )
    };
    (@mul $off:literal) => {
        concat!(
            "pshufd xmm14, xmm13, 0x4e\n",
            "pxor xmm14, xmm13\n",
            "pclmulqdq xmm14, xmmword ptr [{pk} + ", $off, "], 0x00\n",
            "pxor xmm11, xmm14\n",
            "movdqa xmm15, xmm13\n",
            "pclmulqdq xmm15, xmmword ptr [{pw} + ", $off, "], 0x00\n",
            "pxor xmm10, xmm15\n",
            "pclmulqdq xmm13, xmmword ptr [{pw} + ", $off, "], 0x11\n",
            "pxor xmm12, xmm13\n",
        )
    };
}

/// Recover the middle term and reduce the 256-bit sum into `xmm9`.
///
/// With twisted powers the sum `[hi:lo]` is the product's 256 bits in place.
/// Each of two folds multiplies the low 64 bits of `lo` by
/// `0xc2000000_00000000` (the high half of the constant at `{c} + 144`,
/// `x^-1`) and adds that to `lo` with its halves swapped, which multiplies
/// by `x^-64` modulo the field polynomial; then `Y = hi ^ lo`. The same
/// field element `clmul::reduce` gives for the untwisted product: the fused
/// tests compare every kernel with a byte-at-a-time reference, and
/// docs/FIPS.md records how the scheme was checked against SP 800-38D's own
/// multiply.
macro_rules! x8_reduce {
    () => {
        concat!(
            // The true middle term: Karatsuba's, minus lo and hi.
            "pxor xmm11, xmm10\n",
            "pxor xmm11, xmm12\n",
            // lo ^= mid << 64; hi ^= mid >> 64.
            "movdqa xmm14, xmm11\n",
            "pslldq xmm14, 8\n",
            "pxor xmm10, xmm14\n",
            "psrldq xmm11, 8\n",
            "pxor xmm12, xmm11\n",
            // Two folds of lo, then Y = hi ^ lo.
            "movdqa xmm14, xmm10\n",
            "pclmulqdq xmm14, xmmword ptr [{c} + 144], 0x10\n",
            "pshufd xmm10, xmm10, 0x4e\n",
            "pxor xmm10, xmm14\n",
            "movdqa xmm14, xmm10\n",
            "pclmulqdq xmm14, xmmword ptr [{c} + 144], 0x10\n",
            "pshufd xmm10, xmm10, 0x4e\n",
            "pxor xmm10, xmm12\n",
            "pxor xmm10, xmm14\n",
            "movdqa xmm9, xmm10\n",
        )
    };
}

/// GHASH over the eight blocks at `$src` into `xmm9`, block 0 last.
macro_rules! x8_ghash8 {
    ($src:literal) => {
        concat!(
            x8_gblock!(mov, $src, "16"),
            x8_gblock!(add, $src, "32"),
            x8_gblock!(add, $src, "48"),
            x8_gblock!(add, $src, "64"),
            x8_gblock!(add, $src, "80"),
            x8_gblock!(add, $src, "96"),
            x8_gblock!(add, $src, "112"),
            x8_gblock!(y, $src, "0"),
            x8_reduce!(),
        )
    };
}

/// One stitched iteration: AES on this group's counters with the GHASH of
/// the 128 bytes at `$src` between rounds 1 to 9, then the keystream XORed in
/// at `{p}`.
macro_rules! x8_stitched {
    ($src:literal) => {
        concat!(
            x8_ctr!(),
            x8_round!("aesenc", "16"),
            x8_gblock!(mov, $src, "16"),
            x8_round!("aesenc", "32"),
            x8_gblock!(add, $src, "32"),
            x8_round!("aesenc", "48"),
            x8_gblock!(add, $src, "48"),
            x8_round!("aesenc", "64"),
            x8_gblock!(add, $src, "64"),
            x8_round!("aesenc", "80"),
            x8_gblock!(add, $src, "80"),
            x8_round!("aesenc", "96"),
            x8_gblock!(add, $src, "96"),
            x8_round!("aesenc", "112"),
            x8_gblock!(add, $src, "112"),
            x8_round!("aesenc", "128"),
            x8_gblock!(y, $src, "0"),
            x8_round!("aesenc", "144"),
            x8_reduce!(),
            x8_last_rounds!(),
            x8_xor_store!(),
        )
    };
}

/// Counter mode alone over the 128 bytes at `p`.
///
/// # Safety
///
/// - The CPU must have AES-NI and SSSE3.
/// - `p` must point to 128 readable and writable bytes; `rk` to the round
///   keys of an AES-NI schedule with `R` rounds (10, 12 or 14), 16-byte
///   aligned; `st` to 32 readable and writable bytes, the accumulator and
///   then the counter in `gcm_x86::Counter`'s form. The counter is advanced
///   by eight.
#[inline(never)]
pub(crate) unsafe fn x8_aes<const R: usize>(p: *mut u8, rk: *const u8, st: *mut u8) {
    // SAFETY: the module's contract and the caller's, above.
    unsafe {
        asm_all_vectors!(
            x8_aes_group!(),
            p = in(reg) p,
            rk = in(reg) rk,
            st = in(reg) st,
            c = in(reg) CONSTS.0.as_ptr(),
            r = const R,
            last = const R * 16,
            options(nostack, preserves_flags),
        );
    }
}

/// GHASH alone over the 128 bytes at `src`, into the accumulator at `st`.
///
/// # Safety
///
/// - The CPU must have `PCLMULQDQ` and SSSE3.
/// - `src` must point to 128 readable bytes; `pw` and `pk` to the last eight
///   entries of `HashKey::twisted` and `HashKey::kara`, 128 bytes
///   each, 16-byte aligned; `st` to 16 readable and writable bytes.
#[inline(never)]
pub(crate) unsafe fn x8_ghash(src: *const u8, pw: *const u8, pk: *const u8, st: *mut u8) {
    // SAFETY: the module's contract and the caller's, above.
    unsafe {
        asm_all_vectors!(
            "movdqu xmm9, xmmword ptr [{st}]",
            x8_ghash8!("{s}"),
            "movdqu xmmword ptr [{st}], xmm9",
            s = in(reg) src,
            pw = in(reg) pw,
            pk = in(reg) pk,
            st = in(reg) st,
            c = in(reg) CONSTS.0.as_ptr(),
            options(nostack, preserves_flags),
        );
    }
}

/// Seal `n + 1` groups at `p`: the first encrypted alone, `n` stitched
/// iterations each hashing the group before its own, and the last group
/// hashed alone.
///
/// # Safety
///
/// As [`x8_aes`] and [`x8_ghash`] together, with `n` at least one and `p`
/// pointing to `(n + 1) * 128` readable and writable bytes.
#[inline(never)]
pub(crate) unsafe fn x8_seal<const R: usize>(
    p: *mut u8,
    n: usize,
    rk: *const u8,
    pw: *const u8,
    pk: *const u8,
    st: *mut u8,
) {
    debug_assert!(n > 0);
    // SAFETY: the module's contract and the caller's, above. Each stitched
    // iteration reads the group before `{p}`, which the one before it (or
    // the first `x8_aes_group!`) wrote.
    unsafe {
        asm_all_vectors!(
            "movdqu xmm9, xmmword ptr [{st}]",
            x8_aes_group!(),
            "add {p}, 128",
            "2:",
            x8_stitched!("{p} - 128"),
            "add {p}, 128",
            "dec {n}",
            "jnz 2b",
            x8_ghash8!("{p} - 128"),
            "movdqu xmmword ptr [{st}], xmm9",
            p = inout(reg) p => _,
            n = inout(reg) n => _,
            rk = in(reg) rk,
            pw = in(reg) pw,
            pk = in(reg) pk,
            st = in(reg) st,
            c = in(reg) CONSTS.0.as_ptr(),
            r = const R,
            last = const R * 16,
            options(nostack),
        );
    }
}

/// Open the `n` groups at `p`, each iteration hashing the group it decrypts
/// before its store overwrites it.
///
/// # Safety
///
/// As [`x8_aes`] and [`x8_ghash`] together, with `n` at least one and `p`
/// pointing to `n * 128` readable and writable bytes.
#[inline(never)]
pub(crate) unsafe fn x8_open<const R: usize>(
    p: *mut u8,
    n: usize,
    rk: *const u8,
    pw: *const u8,
    pk: *const u8,
    st: *mut u8,
) {
    debug_assert!(n > 0);
    // SAFETY: the module's contract and the caller's, above.
    unsafe {
        asm_all_vectors!(
            "movdqu xmm9, xmmword ptr [{st}]",
            "2:",
            x8_stitched!("{p}"),
            "add {p}, 128",
            "dec {n}",
            "jnz 2b",
            "movdqu xmmword ptr [{st}], xmm9",
            p = inout(reg) p => _,
            n = inout(reg) n => _,
            rk = in(reg) rk,
            pw = in(reg) pw,
            pk = in(reg) pk,
            st = in(reg) st,
            c = in(reg) CONSTS.0.as_ptr(),
            r = const R,
            last = const R * 16,
            options(nostack),
        );
    }
}

// ---------------------------------------------------------------------------
// Sixteen blocks per iteration: VAES and VPCLMULQDQ on `ymm` registers, two
// blocks per register.
//
// Registers as above, widened: `ymm0..ymm7` the states, `ymm8` the round key,
// `xmm9` the accumulator (the upper half kept zero, so it can be XORed into a
// pair of blocks), `ymm10..ymm12` the sums, `ymm13..ymm15` temporaries.

/// The sixteen counter blocks of this iteration into `ymm0..ymm7`, whitened,
/// and the counter at `{st} + 16` advanced past them. Register `k` holds
/// counters `2k` and `2k + 1`, low lane first.
macro_rules! y16_ctr {
    () => {
        concat!(
            "vbroadcasti128 ymm8, xmmword ptr [{st} + 16]\n",
            "vpaddd ymm8, ymm8, ymmword ptr [{c} + 96]\n",
            "vpshufb ymm0, ymm8, ymmword ptr [{c} + 32]\n",
            "vpaddd ymm8, ymm8, ymmword ptr [{c} + 64]\n",
            "vpshufb ymm1, ymm8, ymmword ptr [{c} + 32]\n",
            "vpaddd ymm8, ymm8, ymmword ptr [{c} + 64]\n",
            "vpshufb ymm2, ymm8, ymmword ptr [{c} + 32]\n",
            "vpaddd ymm8, ymm8, ymmword ptr [{c} + 64]\n",
            "vpshufb ymm3, ymm8, ymmword ptr [{c} + 32]\n",
            "vpaddd ymm8, ymm8, ymmword ptr [{c} + 64]\n",
            "vpshufb ymm4, ymm8, ymmword ptr [{c} + 32]\n",
            "vpaddd ymm8, ymm8, ymmword ptr [{c} + 64]\n",
            "vpshufb ymm5, ymm8, ymmword ptr [{c} + 32]\n",
            "vpaddd ymm8, ymm8, ymmword ptr [{c} + 64]\n",
            "vpshufb ymm6, ymm8, ymmword ptr [{c} + 32]\n",
            "vpaddd ymm8, ymm8, ymmword ptr [{c} + 64]\n",
            "vpshufb ymm7, ymm8, ymmword ptr [{c} + 32]\n",
            "vpaddd ymm8, ymm8, ymmword ptr [{c} + 64]\n",
            // The low lane is now the counter sixteen on.
            "vmovdqu xmmword ptr [{st} + 16], xmm8\n",
            "vbroadcasti128 ymm8, xmmword ptr [{rk}]\n",
            "vpxor ymm0, ymm0, ymm8\n",
            "vpxor ymm1, ymm1, ymm8\n",
            "vpxor ymm2, ymm2, ymm8\n",
            "vpxor ymm3, ymm3, ymm8\n",
            "vpxor ymm4, ymm4, ymm8\n",
            "vpxor ymm5, ymm5, ymm8\n",
            "vpxor ymm6, ymm6, ymm8\n",
            "vpxor ymm7, ymm7, ymm8\n",
        )
    };
}

/// One AES round, `$insn`, with the round key at `{rk} + $off`, on all eight
/// state registers.
macro_rules! y16_round {
    ($insn:literal, $off:literal) => {
        concat!(
            "vbroadcasti128 ymm8, xmmword ptr [{rk} + ",
            $off,
            "]\n",
            $insn,
            " ymm0, ymm0, ymm8\n",
            $insn,
            " ymm1, ymm1, ymm8\n",
            $insn,
            " ymm2, ymm2, ymm8\n",
            $insn,
            " ymm3, ymm3, ymm8\n",
            $insn,
            " ymm4, ymm4, ymm8\n",
            $insn,
            " ymm5, ymm5, ymm8\n",
            $insn,
            " ymm6, ymm6, ymm8\n",
            $insn,
            " ymm7, ymm7, ymm8\n",
        )
    };
}

/// Rounds 10 to the last, chosen at assembly time as in `x8_last_rounds!`.
macro_rules! y16_last_rounds {
    () => {
        concat!(
            ".if {r} > 10\n",
            y16_round!("vaesenc", "160"),
            y16_round!("vaesenc", "176"),
            ".endif\n",
            ".if {r} > 12\n",
            y16_round!("vaesenc", "192"),
            y16_round!("vaesenc", "208"),
            ".endif\n",
            y16_round!("vaesenclast", "{last}"),
        )
    };
}

/// XOR the keystream in `ymm0..ymm7` into the 256 bytes at `{p}`, in place.
macro_rules! y16_xor_store {
    () => {
        concat!(
            "vpxor ymm0, ymm0, ymmword ptr [{p}]\n",
            "vpxor ymm1, ymm1, ymmword ptr [{p} + 32]\n",
            "vpxor ymm2, ymm2, ymmword ptr [{p} + 64]\n",
            "vpxor ymm3, ymm3, ymmword ptr [{p} + 96]\n",
            "vpxor ymm4, ymm4, ymmword ptr [{p} + 128]\n",
            "vpxor ymm5, ymm5, ymmword ptr [{p} + 160]\n",
            "vpxor ymm6, ymm6, ymmword ptr [{p} + 192]\n",
            "vpxor ymm7, ymm7, ymmword ptr [{p} + 224]\n",
            "vmovdqu ymmword ptr [{p}], ymm0\n",
            "vmovdqu ymmword ptr [{p} + 32], ymm1\n",
            "vmovdqu ymmword ptr [{p} + 64], ymm2\n",
            "vmovdqu ymmword ptr [{p} + 96], ymm3\n",
            "vmovdqu ymmword ptr [{p} + 128], ymm4\n",
            "vmovdqu ymmword ptr [{p} + 160], ymm5\n",
            "vmovdqu ymmword ptr [{p} + 192], ymm6\n",
            "vmovdqu ymmword ptr [{p} + 224], ymm7\n",
        )
    };
}

/// Counter mode on one group of sixteen blocks, XORed in at `{p}`.
macro_rules! y16_aes_group {
    () => {
        concat!(
            y16_ctr!(),
            y16_round!("vaesenc", "16"),
            y16_round!("vaesenc", "32"),
            y16_round!("vaesenc", "48"),
            y16_round!("vaesenc", "64"),
            y16_round!("vaesenc", "80"),
            y16_round!("vaesenc", "96"),
            y16_round!("vaesenc", "112"),
            y16_round!("vaesenc", "128"),
            y16_round!("vaesenc", "144"),
            y16_last_rounds!(),
            y16_xor_store!(),
        )
    };
}

/// `x8_gblock!` on a pair of blocks: blocks `2k` and `2k + 1` at
/// `[$src + $off]`, times the twisted `H^(16-2k)` and `H^(15-2k)` at
/// `{pw} + $off`.
macro_rules! y16_gblock {
    (mov, $src:literal, $off:literal) => {
        concat!(
            "vmovdqu ymm13, ymmword ptr [", $src, " + ", $off, "]\n",
            "vpshufb ymm13, ymm13, ymmword ptr [{c}]\n",
            "vpshufd ymm14, ymm13, 0x4e\n",
            "vpxor ymm14, ymm14, ymm13\n",
            "vpclmulqdq ymm11, ymm14, ymmword ptr [{pk} + ", $off, "], 0x00\n",
            "vpclmulqdq ymm10, ymm13, ymmword ptr [{pw} + ", $off, "], 0x00\n",
            "vpclmulqdq ymm12, ymm13, ymmword ptr [{pw} + ", $off, "], 0x11\n",
        )
    };
    (add, $src:literal, $off:literal) => {
        concat!(
            "vmovdqu ymm13, ymmword ptr [", $src, " + ", $off, "]\n",
            "vpshufb ymm13, ymm13, ymmword ptr [{c}]\n",
            y16_gblock!(@mul $off),
        )
    };
    (y, $src:literal, $off:literal) => {
        concat!(
            "vmovdqu ymm13, ymmword ptr [", $src, " + ", $off, "]\n",
            "vpshufb ymm13, ymm13, ymmword ptr [{c}]\n",
            "vpxor ymm13, ymm13, ymm9\n",
            y16_gblock!(@mul $off),
        )
    };
    (@mul $off:literal) => {
        concat!(
            "vpshufd ymm14, ymm13, 0x4e\n",
            "vpxor ymm14, ymm14, ymm13\n",
            "vpclmulqdq ymm14, ymm14, ymmword ptr [{pk} + ", $off, "], 0x00\n",
            "vpxor ymm11, ymm11, ymm14\n",
            "vpclmulqdq ymm15, ymm13, ymmword ptr [{pw} + ", $off, "], 0x00\n",
            "vpxor ymm10, ymm10, ymm15\n",
            "vpclmulqdq ymm15, ymm13, ymmword ptr [{pw} + ", $off, "], 0x11\n",
            "vpxor ymm12, ymm12, ymm15\n",
        )
    };
}

/// Sum the two lanes of each sum, recover the middle term, and reduce into
/// `xmm9` as `x8_reduce!` does. The VEX 128-bit forms clear the upper lanes,
/// so `ymm9`'s is zero after.
macro_rules! y16_reduce {
    () => {
        concat!(
            "vextracti128 xmm13, ymm10, 1\n",
            "vpxor xmm10, xmm10, xmm13\n",
            "vextracti128 xmm13, ymm11, 1\n",
            "vpxor xmm11, xmm11, xmm13\n",
            "vextracti128 xmm13, ymm12, 1\n",
            "vpxor xmm12, xmm12, xmm13\n",
            "vpxor xmm11, xmm11, xmm10\n",
            "vpxor xmm11, xmm11, xmm12\n",
            "vpslldq xmm14, xmm11, 8\n",
            "vpxor xmm10, xmm10, xmm14\n",
            "vpsrldq xmm11, xmm11, 8\n",
            "vpxor xmm12, xmm12, xmm11\n",
            "vpclmulqdq xmm14, xmm10, xmmword ptr [{c} + 144], 0x10\n",
            "vpshufd xmm10, xmm10, 0x4e\n",
            "vpxor xmm10, xmm10, xmm14\n",
            "vpclmulqdq xmm14, xmm10, xmmword ptr [{c} + 144], 0x10\n",
            "vpshufd xmm10, xmm10, 0x4e\n",
            "vpxor xmm10, xmm10, xmm12\n",
            "vpxor xmm9, xmm10, xmm14\n",
        )
    };
}

/// GHASH over the sixteen blocks at `$src` into `xmm9`, the pair with block
/// 0 last.
macro_rules! y16_ghash16 {
    ($src:literal) => {
        concat!(
            y16_gblock!(mov, $src, "32"),
            y16_gblock!(add, $src, "64"),
            y16_gblock!(add, $src, "96"),
            y16_gblock!(add, $src, "128"),
            y16_gblock!(add, $src, "160"),
            y16_gblock!(add, $src, "192"),
            y16_gblock!(add, $src, "224"),
            y16_gblock!(y, $src, "0"),
            y16_reduce!(),
        )
    };
}

/// One stitched iteration, as `x8_stitched!`, sixteen blocks.
macro_rules! y16_stitched {
    ($src:literal) => {
        concat!(
            y16_ctr!(),
            y16_round!("vaesenc", "16"),
            y16_gblock!(mov, $src, "32"),
            y16_round!("vaesenc", "32"),
            y16_gblock!(add, $src, "64"),
            y16_round!("vaesenc", "48"),
            y16_gblock!(add, $src, "96"),
            y16_round!("vaesenc", "64"),
            y16_gblock!(add, $src, "128"),
            y16_round!("vaesenc", "80"),
            y16_gblock!(add, $src, "160"),
            y16_round!("vaesenc", "96"),
            y16_gblock!(add, $src, "192"),
            y16_round!("vaesenc", "112"),
            y16_gblock!(add, $src, "224"),
            y16_round!("vaesenc", "128"),
            y16_gblock!(y, $src, "0"),
            y16_round!("vaesenc", "144"),
            y16_reduce!(),
            y16_last_rounds!(),
            y16_xor_store!(),
        )
    };
}

/// [`x8_aes`], sixteen blocks: counter mode alone over the 256 bytes at `p`.
///
/// # Safety
///
/// As [`x8_aes`], with `p` pointing to 256 bytes, the counter advanced by
/// sixteen, and the CPU having AVX2 and `VAES` (a `gcm_x86::Wide` token's
/// guarantee). The round keys need no alignment.
#[inline(never)]
pub(crate) unsafe fn y16_aes<const R: usize>(p: *mut u8, rk: *const u8, st: *mut u8) {
    // SAFETY: the module's contract and the caller's, above.
    unsafe {
        asm_all_vectors!(
            y16_aes_group!(),
            "vzeroupper",
            p = in(reg) p,
            rk = in(reg) rk,
            st = in(reg) st,
            c = in(reg) CONSTS.0.as_ptr(),
            r = const R,
            last = const R * 16,
            options(nostack, preserves_flags),
        );
    }
}

/// [`x8_ghash`], sixteen blocks: GHASH alone over the 256 bytes at `src`.
///
/// # Safety
///
/// As [`x8_ghash`], with `src` pointing to 256 bytes, `pw` and `pk` to the
/// last sixteen entries (256 bytes each, no alignment needed), and the CPU
/// having AVX2 and `VPCLMULQDQ`.
#[inline(never)]
pub(crate) unsafe fn y16_ghash(src: *const u8, pw: *const u8, pk: *const u8, st: *mut u8) {
    // SAFETY: the module's contract and the caller's, above.
    unsafe {
        asm_all_vectors!(
            "vmovdqu xmm9, xmmword ptr [{st}]",
            y16_ghash16!("{s}"),
            "vmovdqu xmmword ptr [{st}], xmm9",
            "vzeroupper",
            s = in(reg) src,
            pw = in(reg) pw,
            pk = in(reg) pk,
            st = in(reg) st,
            c = in(reg) CONSTS.0.as_ptr(),
            options(nostack, preserves_flags),
        );
    }
}

/// [`x8_seal`], sixteen blocks per group: `n + 1` groups at `p`.
///
/// # Safety
///
/// As [`y16_aes`] and [`y16_ghash`] together, with `n` at least one and `p`
/// pointing to `(n + 1) * 256` readable and writable bytes.
#[inline(never)]
pub(crate) unsafe fn y16_seal<const R: usize>(
    p: *mut u8,
    n: usize,
    rk: *const u8,
    pw: *const u8,
    pk: *const u8,
    st: *mut u8,
) {
    debug_assert!(n > 0);
    // SAFETY: as for `x8_seal`.
    unsafe {
        asm_all_vectors!(
            "vmovdqu xmm9, xmmword ptr [{st}]",
            y16_aes_group!(),
            "add {p}, 256",
            "2:",
            y16_stitched!("{p} - 256"),
            "add {p}, 256",
            "dec {n}",
            "jnz 2b",
            y16_ghash16!("{p} - 256"),
            "vmovdqu xmmword ptr [{st}], xmm9",
            "vzeroupper",
            p = inout(reg) p => _,
            n = inout(reg) n => _,
            rk = in(reg) rk,
            pw = in(reg) pw,
            pk = in(reg) pk,
            st = in(reg) st,
            c = in(reg) CONSTS.0.as_ptr(),
            r = const R,
            last = const R * 16,
            options(nostack),
        );
    }
}

/// [`x8_open`], sixteen blocks per group.
///
/// # Safety
///
/// As [`y16_aes`] and [`y16_ghash`] together, with `n` at least one and `p`
/// pointing to `n * 256` readable and writable bytes.
#[inline(never)]
pub(crate) unsafe fn y16_open<const R: usize>(
    p: *mut u8,
    n: usize,
    rk: *const u8,
    pw: *const u8,
    pk: *const u8,
    st: *mut u8,
) {
    debug_assert!(n > 0);
    // SAFETY: the module's contract and the caller's, above.
    unsafe {
        asm_all_vectors!(
            "vmovdqu xmm9, xmmword ptr [{st}]",
            "2:",
            y16_stitched!("{p}"),
            "add {p}, 256",
            "dec {n}",
            "jnz 2b",
            "vmovdqu xmmword ptr [{st}], xmm9",
            "vzeroupper",
            p = inout(reg) p => _,
            n = inout(reg) n => _,
            rk = in(reg) rk,
            pw = in(reg) pw,
            pk = in(reg) pk,
            st = in(reg) st,
            c = in(reg) CONSTS.0.as_ptr(),
            r = const R,
            last = const R * 16,
            options(nostack),
        );
    }
}
