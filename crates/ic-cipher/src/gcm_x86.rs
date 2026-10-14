//! AES-GCM on x86-64 in one pass: counter mode and GHASH stitched together.
//!
//! # Why a fused kernel
//!
//! The generic GCM in [`crate::gcm`] runs counter mode over the whole buffer,
//! then GHASH over the whole buffer, through two separate calls. Each is fast
//! on its own, but the message crosses memory twice, the two units never run
//! at the same time, and every call recomputes `H = E_K(0)` and its powers.
//! At 64 bytes that per-call work was most of the cost.
//!
//! Here:
//!
//! - `H` and its powers `H^1..H^32` are computed once, when the key is set
//!   ([`HashKey`]), and wiped when it is dropped.
//! - Each iteration encrypts a group of counter blocks and, between the AES
//!   rounds, multiplies the previous group's ciphertext into the GHASH
//!   accumulator. The AES unit and the carry-less multiplier work in the same
//!   cycles instead of taking turns.
//! - GHASH is aggregated: a group of `n` blocks is
//!   `Y' = (Y ^ X0)*H^n ^ X1*H^(n-1) ^ .. ^ X(n-1)*H`, `n` independent
//!   products summed unreduced and reduced once. The algebra is the same
//!   distributivity argument as `gcm::Ghash::absorb4`. In the kernels each
//!   product is Karatsuba's, three carry-less multiplies instead of four,
//!   by a power of `H` twisted by `x^-1` ([`twist`]) so that the sum needs no
//!   one-bit correction and reduces with two more multiplies; the AAD, the
//!   tail and the length block use `clmul::product` and `clmul::reduce`
//!   unchanged ([`Pending`]).
//! - `E_K(J0)` is computed before a bulk loop, where its latency hides
//!   behind the loop's. Without one, the message tail and `J0` share one
//!   batch, so a short message costs one pass of AES latency; either way the
//!   tail, the length block and anything still queued share one reduction.
//!
//! Three kernels:
//!
//! - [`Kernel::Clmul8`]: AES-NI and `PCLMULQDQ`, eight blocks per iteration.
//!   Any CPU the existing AES-NI and GHASH backends run on.
//! - [`Kernel::Vaes256`]: `VAES` and `VPCLMULQDQ` on 256-bit registers,
//!   sixteen blocks per iteration, two per instruction. Chosen at run time
//!   when the CPU has them and AVX2 but not AVX-512.
//! - [`Kernel::Vaes512`]: the same instructions on 512-bit registers, four
//!   blocks per instruction and thirty-two per iteration, when the CPU also
//!   has AVX-512F and AVX-512BW. See the notes above `z32_ctr!` for why
//!   thirty-two and why stitched.
//!
//! The first two have their loops in [`crate::gcm_x86_asm`], which has the
//! schedule and what was measured; the third's are below.
//!
//! # Why the loops are written as `asm!`
//!
//! The intrinsics and the `vaes`/`vpclmulqdq`/`avx512*` target features were
//! stabilised in Rust 1.89, and this workspace promises 1.87. Without a build
//! script there is no way to `cfg` on the compiler version, and the 512-bit
//! kernel cannot even name a `zmm` register as an operand without the
//! `avx512f` target feature. So each bulk loop is one self-contained `asm!`
//! block: explicit registers, every one declared clobbered, inputs and
//! outputs through memory, in a function that is never inlined. The
//! 128-bit loop could have been intrinsics, and was; written out it keeps
//! every state in a register, which the compiler's version did not. The
//! tail, length block and tag are the shared intrinsic code. When the MSRV
//! reaches 1.89 the wide loops could become intrinsics, if the compiler then
//! does as well as the assembly.
//!
//! Executing one of the wide instructions on a CPU without it is an illegal
//! instruction, so they are only reachable with a [`Wide`] or [`Wide512`]
//! token, and the only way to get one is its `detect`. `--cfg ic_no_avx512`
//! makes `Wide512::detect` report false and `--cfg ic_no_vaes` both, so one
//! machine can test and measure each narrower kernel as the default.
//!
//! All build and pass the tests under 1.87 as well as the current compiler;
//! `cargo check` alone would not show that, because it never assembles.
//!
//! # Trusting it
//!
//! Every kernel is differentially tested against an independent
//! byte-at-a-time GCM built from the portable AES and the portable GHASH
//! multiply (`gcm::fused_tests`), each kernel forced in turn: every length
//! from 0 to 600 bytes, every AAD length from 0 to 100 and some far longer,
//! random keys and nonces, sealing and opening, every key size, nonces of
//! other lengths, buffers at every alignment, and counters arranged to wrap
//! inside a group. The specification vectors and Wycheproof run through
//! whichever kernel the CPU selects. Breaking a power of `H`, a counter
//! increment, a round key, a reduction term, or the stitched loop's source
//! offset each fails those tests; the specification vectors alone catch few
//! of them. The twisted reduction was also checked, before it was written,
//! against SP 800-38D's bit-serial multiply (docs/FIPS.md).
//!
//! # Constant-time properties
//!
//! Nothing here branches on or indexes by key, plaintext, or tag. The loop
//! bounds and the choice of kernel depend on the lengths and the CPU, which
//! are public. `AESENC` and `PCLMULQDQ` and their wide forms have
//! data-independent timing. `scripts/ct-audit` reads the 128- and 256-bit
//! loops' compiled form (`ct_probes`).
//!
//! # Safety
//!
//! The kernels are `#[target_feature]` functions and so callable only from an
//! `unsafe` block, and only after the features were detected; [`HashKey`]
//! carries the proof, because it can only be built by [`HashKey::new`], whose
//! contract is that detection has happened. Inside, the raw-pointer loads and
//! stores are the only other unsafe operations, each bounded by a
//! `chunks_exact` or an explicit length -- and the `asm!` blocks, whose
//! contracts are on [`zmm_groups`], [`zmm32_groups`] and the functions of
//! [`crate::gcm_x86_asm`].

use core::arch::asm;
use core::arch::x86_64::*;

use crate::aes::x86::Keys;
use crate::clmul::{product, reduce};
use crate::gcm_x86_asm::twist;
use ic_core::Zeroize;

const BLOCK: usize = 16;
/// Bytes per iteration of the narrow kernel.
const NARROW: usize = BLOCK * 8;
/// Bytes per iteration of the 256-bit kernel, and of the 512-bit kernel's
/// shorter loop.
const WIDE: usize = BLOCK * 16;
/// Bytes per iteration of the 512-bit kernel's main loop.
const WIDE32: usize = BLOCK * 32;
/// How many powers of `H` are kept: enough for one reduction per 32 blocks.
const NPOW: usize = 32;

/// Which fused kernel a key uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kernel {
    /// AES-NI and `PCLMULQDQ`, eight blocks per iteration.
    Clmul8,
    /// `VAES` and `VPCLMULQDQ` on 256-bit registers, sixteen per iteration.
    Vaes256,
    /// `VAES` and `VPCLMULQDQ` on 512-bit registers, thirty-two per iteration
    /// (sixteen in the loop that takes what the first does not), four per
    /// instruction.
    Vaes512,
}

/// Ask once per process whether every feature named is present, and cache
/// the answer.
macro_rules! cached_detect {
    ($($f:tt),+) => {{
        use core::sync::atomic::{AtomicU8, Ordering};
        static CACHED: AtomicU8 = AtomicU8::new(0);
        match CACHED.load(Ordering::Relaxed) {
            1 => true,
            2 => false,
            _ => {
                let have = true $(&& std::arch::is_x86_feature_detected!($f))+;
                CACHED.store(u8::from(!have) + 1, Ordering::Relaxed);
                have
            }
        }
    }};
}

/// Proof that this CPU has AVX2, `VAES` and `VPCLMULQDQ`, as well as the
/// AES-NI, `PCLMULQDQ` and SSSE3 the narrow pieces use.
///
/// Zero-sized; the only constructor is [`Wide::detect`]. The wrappers around
/// the wide instructions take one, so they cannot be reached on a CPU that
/// would fault on them.
#[derive(Clone, Copy, Debug)]
pub struct Wide(());

impl Wide {
    /// The token, if the CPU has everything the 256-bit kernel uses.
    pub fn detect() -> Option<Wide> {
        // `--cfg ic_no_vaes` reports this false, and with it `Wide512`, for
        // measuring the AES-NI kernel that CPUs without VAES run.
        let have = !cfg!(ic_no_vaes)
            && cached_detect!("avx2", "vaes", "vpclmulqdq", "aes", "pclmulqdq", "ssse3");
        have.then_some(Wide(()))
    }
}

/// Proof that this CPU has, besides everything [`Wide`] proves, AVX-512F and
/// AVX-512BW: what the 512-bit kernel's `zmm` instructions need. `std`'s
/// detection also confirms that the OS saves the `zmm` state.
#[derive(Clone, Copy, Debug)]
pub struct Wide512(());

impl Wide512 {
    /// The token, if the CPU has everything the 512-bit kernel uses.
    pub fn detect() -> Option<Wide512> {
        // `--cfg ic_no_avx512` reports this false, for measuring the AVX2 paths.
        let have = Wide::detect().is_some()
            && !cfg!(ic_no_avx512)
            && cached_detect!("avx512f", "avx512bw");
        have.then_some(Wide512(()))
    }
}

/// The kernel this CPU would use.
pub fn best_kernel() -> Kernel {
    if Wide512::detect().is_some() {
        Kernel::Vaes512
    } else if Wide::detect().is_some() {
        Kernel::Vaes256
    } else {
        Kernel::Clmul8
    }
}

/// A kernel, with the proof that it can run here.
#[derive(Clone, Copy, Debug)]
enum Path {
    Narrow,
    Wide(Wide),
    Wide512(Wide512),
}

/// The per-key GHASH state: powers of `H`, computed once.
///
/// Aligned, and `repr(C)` so that each table starts at a multiple of sixteen
/// bytes: the eight-block kernel's legacy-encoded `PCLMULQDQ` takes `twisted`
/// and `kara` as memory operands, which must be 16-byte aligned.
#[repr(C, align(64))]
pub(crate) struct HashKey {
    /// `powers[i]` is `H^(32-i)`, byte-reversed: the form `clmul::product`
    /// multiplies, for the AAD, the tail and the length block (`Pending`).
    /// Descending, so a group of `n` blocks takes the last `n` entries in
    /// order.
    powers: [[u8; BLOCK]; NPOW],
    /// `H` in GCM byte order, for deriving `J0` from a nonce that is not 96
    /// bits long.
    h: [u8; BLOCK],
    /// `twisted[i]` is `powers[i]` multiplied by `x^-1` in the field
    /// ([`twist`]), the form the assembly kernels multiply: their products
    /// need no one-bit correction, and are reduced with two carry-less
    /// multiplies instead of `clmul::reduce`'s shifts. Two or four adjacent
    /// entries are the multipliers one 256- or 512-bit register needs.
    twisted: [[u8; BLOCK]; NPOW],
    /// `kara[i]` is the XOR of the two 64-bit halves of `twisted[i]`, in both
    /// halves: the second factor of Karatsuba's middle product, with which
    /// the kernels multiply with three carry-less multiplies instead of four.
    kara: [[u8; BLOCK]; NPOW],
    path: Path,
}

impl HashKey {
    /// Compute `H` and its powers under `keys`, for `kernel`.
    ///
    /// # Safety
    ///
    /// The CPU must have `aes`, `pclmulqdq` and `ssse3`. A wide `kernel` is
    /// granted only if its own detection succeeds; otherwise this falls back
    /// to the next narrower one, so that choice cannot be made unsafely.
    pub(crate) unsafe fn new(keys: &Keys, kernel: Kernel) -> HashKey {
        let w512 = match kernel {
            Kernel::Vaes512 => Wide512::detect(),
            _ => None,
        };
        let w256 = match kernel {
            Kernel::Vaes512 | Kernel::Vaes256 => Wide::detect(),
            Kernel::Clmul8 => None,
        };
        let path = match (w512, w256) {
            (Some(t), _) => Path::Wide512(t),
            (None, Some(t)) => Path::Wide(t),
            (None, None) => Path::Narrow,
        };
        let mut hk = HashKey {
            powers: [[0u8; BLOCK]; NPOW],
            h: [0u8; BLOCK],
            twisted: [[0u8; BLOCK]; NPOW],
            kara: [[0u8; BLOCK]; NPOW],
            path,
        };
        // SAFETY: the caller guarantees `aes`, `pclmulqdq` and `ssse3`.
        unsafe { compute_powers(keys, &mut hk) };
        hk
    }

    /// Which kernel this key runs.
    #[cfg(test)]
    pub(crate) fn kernel(&self) -> Kernel {
        match self.path {
            Path::Narrow => Kernel::Clmul8,
            Path::Wide(_) => Kernel::Vaes256,
            Path::Wide512(_) => Kernel::Vaes512,
        }
    }

    /// `H`, in GCM byte order.
    pub(crate) fn h(&self) -> &[u8; BLOCK] {
        &self.h
    }

    /// `H^(32-i)`, byte-reversed.
    #[inline]
    #[target_feature(enable = "sse2")]
    fn power(&self, i: usize) -> __m128i {
        // SAFETY: `powers[i]` is 16 bytes (an out-of-range `i` panics on the
        // index, it does not read past the array); the load is unaligned.
        unsafe { _mm_loadu_si128(self.powers[i].as_ptr() as *const __m128i) }
    }

    /// The last `n` entries of `twisted` and of `kara`, `H^n..H^1`, as the
    /// assembly kernels take them. Both are 16-byte aligned (`HashKey`'s
    /// layout).
    fn last_powers(&self, n: usize) -> (*const u8, *const u8) {
        let pw = self.twisted[NPOW - n..].as_ptr() as *const u8;
        let pk = self.kara[NPOW - n..].as_ptr() as *const u8;
        debug_assert!((pw as usize | pk as usize) & 15 == 0);
        (pw, pk)
    }
}

impl Drop for HashKey {
    fn drop(&mut self) {
        // As key-derived as `H` itself.
        for p in self
            .powers
            .iter_mut()
            .chain(self.twisted.iter_mut())
            .chain(self.kara.iter_mut())
        {
            p.zeroize();
        }
        self.h.zeroize();
    }
}

#[target_feature(enable = "aes,pclmulqdq,ssse3")]
fn compute_powers(keys: &Keys, hk: &mut HashKey) {
    let (rk, rounds) = keys.enc_round_keys();
    let h = aes1(rk, rounds, _mm_setzero_si128());
    // SAFETY: `hk.h` is 16 bytes; the store is unaligned.
    unsafe { _mm_storeu_si128(hk.h.as_mut_ptr() as *mut __m128i, h) };
    let hs = _mm_shuffle_epi8(h, bswap());
    let mut p = hs;
    for i in (0..NPOW).rev() {
        if i < NPOW - 1 {
            let (lo, mid, hi) = product(p, hs);
            p = reduce(lo, mid, hi);
        }
        let t = twist(p);
        let k = _mm_xor_si128(t, _mm_shuffle_epi32::<0x4e>(t));
        // SAFETY: each destination is 16 bytes; the stores are unaligned.
        unsafe {
            _mm_storeu_si128(hk.powers[i].as_mut_ptr() as *mut __m128i, p);
            _mm_storeu_si128(hk.twisted[i].as_mut_ptr() as *mut __m128i, t);
            _mm_storeu_si128(hk.kara[i].as_mut_ptr() as *mut __m128i, k);
        }
    }
}

/// Seal or open `data` in place and return the expected tag.
///
/// `j0` is the pre-counter block: the nonce and `00000001` for a 96-bit nonce,
/// otherwise the GHASH-derived value. The first block of keystream uses
/// `inc32(j0)`, and the tag is masked with `E_K(j0)`, exactly as
/// SP 800-38D §7.1. When opening, GHASH runs over `data` before it is
/// decrypted; the caller compares the tag and wipes `data` on a mismatch.
///
/// # Safety
///
/// `hk` must have been made by [`HashKey::new`] on this CPU; that establishes
/// every feature the selected kernel uses. `keys` is the AES-NI schedule.
pub(crate) unsafe fn seal_or_open(
    keys: &Keys,
    hk: &HashKey,
    j0: &[u8; BLOCK],
    aad: &[u8],
    data: &mut [u8],
    encrypting: bool,
) -> [u8; BLOCK] {
    match hk.path {
        // SAFETY: a `Wide512` token exists only when `Wide512::detect` found
        // AVX-512F and AVX-512BW on top of everything `Wide` proves.
        Path::Wide512(w) => unsafe { run_wide(Bulk::Zmm(w), keys, hk, j0, aad, data, encrypting) },
        // SAFETY: a `Wide` token exists only when `Wide::detect` found AVX2,
        // VAES, VPCLMULQDQ, AES-NI, PCLMULQDQ and SSSE3.
        Path::Wide(w) => unsafe { run_wide(Bulk::Ymm(w), keys, hk, j0, aad, data, encrypting) },
        // SAFETY: `HashKey::new`'s contract: AES-NI, PCLMULQDQ and SSSE3.
        Path::Narrow => unsafe { run_narrow(keys, hk, j0, aad, data, encrypting) },
    }
}

// ---------------------------------------------------------------------------
// Shared pieces.

/// Reverse all sixteen bytes: GCM order to the multiplier's, and back.
#[inline]
#[target_feature(enable = "sse2")]
fn bswap() -> __m128i {
    _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
}

/// Reverse bytes 12..16 only: turns the big-endian 32-bit counter field into
/// a native one in the top lane, so `_mm_add_epi32` is `inc32` -- it wraps
/// within those 32 bits and never carries into the nonce. Its own inverse.
#[inline]
#[target_feature(enable = "sse2")]
fn ctr_swap() -> __m128i {
    _mm_set_epi8(12, 13, 14, 15, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0)
}

/// The counter, kept with its last 32 bits native-endian.
struct Counter(__m128i);

impl Counter {
    /// The counter after `j0`: `inc32(j0)`.
    #[inline]
    #[target_feature(enable = "ssse3")]
    fn after(j0: __m128i) -> Counter {
        Counter(_mm_add_epi32(
            _mm_shuffle_epi8(j0, ctr_swap()),
            _mm_set_epi32(1, 0, 0, 0),
        ))
    }

    /// This counter block, in GCM byte order, and step past it.
    #[inline]
    #[target_feature(enable = "ssse3")]
    fn next(&mut self) -> __m128i {
        let out = _mm_shuffle_epi8(self.0, ctr_swap());
        self.0 = _mm_add_epi32(self.0, _mm_set_epi32(1, 0, 0, 0));
        out
    }
}

/// One block through AES.
#[inline]
#[target_feature(enable = "aes")]
fn aes1(rk: &[__m128i; 15], rounds: usize, block: __m128i) -> __m128i {
    let mut b = _mm_xor_si128(block, rk[0]);
    for k in &rk[1..rounds] {
        b = _mm_aesenc_si128(b, *k);
    }
    _mm_aesenclast_si128(b, rk[rounds])
}

/// The first `N` of `s` through AES together.
#[inline]
#[target_feature(enable = "aes")]
fn aes_batch<const N: usize>(rk: &[__m128i; 15], rounds: usize, s: &mut [__m128i]) {
    let mut b = [_mm_setzero_si128(); N];
    for (x, v) in b.iter_mut().zip(s.iter()) {
        *x = _mm_xor_si128(*v, rk[0]);
    }
    for k in &rk[1..rounds] {
        for x in b.iter_mut() {
            *x = _mm_aesenc_si128(*x, *k);
        }
    }
    for (x, v) in b.iter().zip(s.iter_mut()) {
        *v = _mm_aesenclast_si128(*x, rk[rounds]);
    }
}

/// GHASH blocks that are waiting to be multiplied in as one group.
///
/// Blocks are held byte-reversed. A full group of eight is folded in with one
/// reduction; [`Pending::flush`] folds in however many there are, with the
/// powers that make the result the same as eight serial steps.
struct Pending {
    y: __m128i,
    buf: [__m128i; 8],
    n: usize,
}

impl Pending {
    #[inline]
    #[target_feature(enable = "sse2")]
    fn new() -> Pending {
        Pending {
            y: _mm_setzero_si128(),
            buf: [_mm_setzero_si128(); 8],
            n: 0,
        }
    }

    /// Queue one byte-reversed block.
    #[inline]
    #[target_feature(enable = "pclmulqdq,ssse3")]
    fn push(&mut self, hk: &HashKey, x: __m128i) {
        self.buf[self.n] = x;
        self.n += 1;
        if self.n == self.buf.len() {
            self.flush(hk);
        }
    }

    /// Queue `bytes`, zero-padding a final partial block.
    #[inline]
    #[target_feature(enable = "pclmulqdq,ssse3")]
    fn push_padded(&mut self, hk: &HashKey, bytes: &[u8]) {
        let mask = bswap();
        let mut whole = bytes.chunks_exact(BLOCK);
        for b in &mut whole {
            // SAFETY: `b` is exactly 16 bytes; the load is unaligned.
            let x = unsafe { _mm_loadu_si128(b.as_ptr() as *const __m128i) };
            self.push(hk, _mm_shuffle_epi8(x, mask));
        }
        let rest = whole.remainder();
        if !rest.is_empty() {
            let mut last = [0u8; BLOCK];
            last[..rest.len()].copy_from_slice(rest);
            // SAFETY: `last` is 16 bytes; the load is unaligned.
            let x = unsafe { _mm_loadu_si128(last.as_ptr() as *const __m128i) };
            self.push(hk, _mm_shuffle_epi8(x, mask));
        }
    }

    /// Multiply everything queued into `y`: block `j` of `n` takes `H^(n-j)`.
    #[inline]
    #[target_feature(enable = "pclmulqdq,ssse3")]
    fn flush(&mut self, hk: &HashKey) {
        let n = self.n;
        if n == 0 {
            return;
        }
        let (mut lo, mut mid, mut hi) = (
            _mm_setzero_si128(),
            _mm_setzero_si128(),
            _mm_setzero_si128(),
        );
        for j in 0..n {
            let mut x = self.buf[j];
            if j == 0 {
                x = _mm_xor_si128(x, self.y);
            }
            let (l, m, u) = product(x, hk.power(NPOW - n + j));
            lo = _mm_xor_si128(lo, l);
            mid = _mm_xor_si128(mid, m);
            hi = _mm_xor_si128(hi, u);
        }
        self.y = reduce(lo, mid, hi);
        self.n = 0;
    }
}

impl Drop for Pending {
    fn drop(&mut self) {
        // `y` is the running GHASH value, from which `H` can be solved for
        // given the ciphertext; `gcm::Ghash` wipes its accumulator the same
        // way.
        wipe(core::slice::from_mut(&mut self.y));
        wipe(&mut self.buf);
    }
}

/// Overwrite `regs` with zeros through volatile stores, which the compiler
/// may not elide as dead.
#[inline]
fn wipe(regs: &mut [__m128i]) {
    for r in regs.iter_mut() {
        // SAFETY: `r` is a valid, aligned, exclusive reference, and the
        // all-zero bit pattern is a valid `__m128i`.
        unsafe { core::ptr::write_volatile(r, core::mem::zeroed()) };
    }
}

/// The message tail (under eight blocks), the length block, and the tag.
///
/// Without a bulk part (`ekj0` is `None`), the tail's counter blocks and `J0`
/// go through AES as one batch, so a short message pays AES latency once.
/// After one, `E_K(J0)` was computed before the bulk loop, where its latency
/// hid behind the loop's, and only the tail's blocks are left. The tail, the
/// length block and anything still queued are reduced together.
#[inline]
#[target_feature(enable = "aes,pclmulqdq,ssse3")]
#[allow(clippy::too_many_arguments)]
fn finish(
    keys: &Keys,
    hk: &HashKey,
    g: &mut Pending,
    ctr: &mut Counter,
    j0: __m128i,
    ekj0: Option<__m128i>,
    tail: &mut [u8],
    aad_len: usize,
    data_len: usize,
    encrypting: bool,
) -> [u8; BLOCK] {
    debug_assert!(tail.len() < NARROW);
    let (rk, rounds) = keys.enc_round_keys();
    let mask = bswap();
    let blocks = tail.len().div_ceil(BLOCK);

    // Slot 0 is `E_K(J0)`, for the tag; slots 1..=blocks are the tail's
    // keystream.
    let mut s = [_mm_setzero_si128(); 9];
    for slot in s[1..=blocks].iter_mut() {
        *slot = ctr.next();
    }
    let (batch, n) = match ekj0 {
        Some(e) => {
            s[0] = e;
            (&mut s[1..], blocks)
        }
        None => {
            s[0] = j0;
            (&mut s[..], blocks + 1)
        }
    };
    // A fixed count for each length, so the batch is held in registers
    // through the rounds rather than stored and reloaded at each one.
    match n {
        0 => {}
        1 => aes_batch::<1>(rk, rounds, batch),
        2 => aes_batch::<2>(rk, rounds, batch),
        3 => aes_batch::<3>(rk, rounds, batch),
        4 => aes_batch::<4>(rk, rounds, batch),
        5 => aes_batch::<5>(rk, rounds, batch),
        6 => aes_batch::<6>(rk, rounds, batch),
        7 => aes_batch::<7>(rk, rounds, batch),
        8 => aes_batch::<8>(rk, rounds, batch),
        _ => aes_batch::<9>(rk, rounds, batch),
    }

    let mut whole = tail.chunks_exact_mut(BLOCK);
    let mut i = 1;
    for b in &mut whole {
        let p = b.as_mut_ptr();
        // SAFETY: `b` is exactly 16 bytes; the load and store are unaligned.
        let input = unsafe { _mm_loadu_si128(p as *const __m128i) };
        let output = _mm_xor_si128(input, s[i]);
        // SAFETY: as above.
        unsafe { _mm_storeu_si128(p as *mut __m128i, output) };
        let ct = if encrypting { output } else { input };
        g.push(hk, _mm_shuffle_epi8(ct, mask));
        i += 1;
    }
    let rest = whole.into_remainder();
    if !rest.is_empty() {
        // Through a zeroed buffer, so GHASH sees the ciphertext padded with
        // zeros and not with keystream.
        let mut buf = [0u8; BLOCK];
        buf[..rest.len()].copy_from_slice(rest);
        // SAFETY: `buf` is 16 bytes; the loads and stores are unaligned.
        let input = unsafe { _mm_loadu_si128(buf.as_ptr() as *const __m128i) };
        let output = _mm_xor_si128(input, s[i]);
        // SAFETY: as above.
        unsafe { _mm_storeu_si128(buf.as_mut_ptr() as *mut __m128i, output) };
        rest.copy_from_slice(&buf[..rest.len()]);
        let ct = if encrypting {
            buf[rest.len()..].fill(0);
            // SAFETY: `buf` is 16 bytes; the load is unaligned.
            unsafe { _mm_loadu_si128(buf.as_ptr() as *const __m128i) }
        } else {
            // The ciphertext, as it was loaded: already zero-padded.
            input
        };
        g.push(hk, _mm_shuffle_epi8(ct, mask));
        buf.zeroize();
    }

    // The length block, already byte-reversed: the reversal of
    // `be64(aad bits) || be64(data bits)` is `le64(data bits)` in the low
    // half and `le64(aad bits)` in the high half.
    let len_block = _mm_set_epi64x(
        (aad_len as u64).wrapping_mul(8) as i64,
        (data_len as u64).wrapping_mul(8) as i64,
    );
    g.push(hk, len_block);
    g.flush(hk);

    let tag = _mm_xor_si128(_mm_shuffle_epi8(g.y, mask), s[0]);
    // `E_K(J0)` and the tail's keystream; `gcm_core` wipes the former too.
    wipe(&mut s);
    let mut out = [0u8; BLOCK];
    // SAFETY: `out` is 16 bytes; the store is unaligned.
    unsafe { _mm_storeu_si128(out.as_mut_ptr() as *mut __m128i, tag) };
    out
}

// ---------------------------------------------------------------------------
// The narrow kernel: AES-NI and PCLMULQDQ, eight blocks per iteration.

/// The state the assembly loops read and write: the accumulator `Y`
/// (byte-reversed), then the counter in [`Counter`]'s form.
struct State([u8; 2 * BLOCK]);

impl State {
    #[inline]
    #[target_feature(enable = "sse2")]
    fn new(y: __m128i, ctr: &Counter) -> State {
        let mut s = State([0u8; 2 * BLOCK]);
        // SAFETY: `s.0` is 32 bytes; the stores are unaligned.
        unsafe {
            _mm_storeu_si128(s.0.as_mut_ptr() as *mut __m128i, y);
            _mm_storeu_si128(s.0.as_mut_ptr().add(BLOCK) as *mut __m128i, ctr.0);
        }
        s
    }

    /// `Y` back out, and the counter into `ctr`.
    #[inline]
    #[target_feature(enable = "sse2")]
    fn finish(&self, ctr: &mut Counter) -> __m128i {
        // SAFETY: `self.0` is 32 bytes; the loads are unaligned.
        unsafe {
            ctr.0 = _mm_loadu_si128(self.0.as_ptr().add(BLOCK) as *const __m128i);
            _mm_loadu_si128(self.0.as_ptr() as *const __m128i)
        }
    }
}

impl Drop for State {
    fn drop(&mut self) {
        // `Y`, as `Pending` wipes it.
        self.0.zeroize();
    }
}

/// Counter mode and GHASH over whole 128-byte groups, stitched: see
/// [`crate::gcm_x86_asm`] for the loops.
#[target_feature(enable = "aes,pclmulqdq,ssse3")]
fn bulk_narrow(
    keys: &Keys,
    hk: &HashKey,
    ctr: &mut Counter,
    data: &mut [u8],
    y: __m128i,
    encrypting: bool,
) -> __m128i {
    debug_assert_eq!(data.len() % NARROW, 0);
    let groups = data.len() / NARROW;
    if groups == 0 {
        return y;
    }
    let (rk, rounds) = keys.enc_round_keys();
    let rk = rk.as_ptr() as *const u8;
    let mut st = State::new(y, ctr);
    let p = data.as_mut_ptr();
    // SAFETY: `HashKey::new`'s contract: AES-NI, PCLMULQDQ and SSSE3. `p`
    // is `groups * 128` bytes with `groups > 0`; `rk` is an AES-NI schedule
    // of `rounds` rounds, `__m128i`-aligned.
    unsafe {
        match rounds {
            10 => narrow_groups::<10>(p, groups, rk, hk, &mut st, encrypting),
            12 => narrow_groups::<12>(p, groups, rk, hk, &mut st, encrypting),
            _ => narrow_groups::<14>(p, groups, rk, hk, &mut st, encrypting),
        }
    }
    st.finish(ctr)
}

/// Sealing two groups or more, one call: the first encrypted alone, the
/// stitched loop, the last hashed alone. One group, encrypted and then
/// hashed. Opening, one call, every group stitched to itself.
///
/// # Safety
///
/// As [`bulk_narrow`] establishes: the features, `p` and `rk`.
#[inline]
unsafe fn narrow_groups<const R: usize>(
    p: *mut u8,
    groups: usize,
    rk: *const u8,
    hk: &HashKey,
    st: &mut State,
    encrypting: bool,
) {
    use crate::gcm_x86_asm::{x8_aes, x8_ghash, x8_open, x8_seal};
    let s = st.0.as_mut_ptr();
    let (pw, pk) = hk.last_powers(8);
    // SAFETY: the caller's: `groups * 128` bytes at `p`, `groups > 0`; `pw`
    // and `pk` are the eight aligned powers each function names.
    unsafe {
        if !encrypting {
            x8_open::<R>(p, groups, rk, pw, pk, s);
        } else if groups > 1 {
            x8_seal::<R>(p, groups - 1, rk, pw, pk, s);
        } else {
            x8_aes::<R>(p, rk, s);
            x8_ghash(p, pw, pk, s);
        }
    }
}

#[target_feature(enable = "aes,pclmulqdq,ssse3")]
fn run_narrow(
    keys: &Keys,
    hk: &HashKey,
    j0: &[u8; BLOCK],
    aad: &[u8],
    data: &mut [u8],
    encrypting: bool,
) -> [u8; BLOCK] {
    // SAFETY: `j0` is 16 bytes; the load is unaligned.
    let j0 = unsafe { _mm_loadu_si128(j0.as_ptr() as *const __m128i) };
    let mut g = Pending::new();
    g.push_padded(hk, aad);
    let mut ctr = Counter::after(j0);
    let data_len = data.len();
    let whole = data_len - data_len % NARROW;
    let (body, tail) = data.split_at_mut(whole);
    let mut ekj0 = None;
    if !body.is_empty() {
        // `E_K(J0)` first, so its latency overlaps the loop's.
        let (rk, rounds) = keys.enc_round_keys();
        ekj0 = Some(aes1(rk, rounds, j0));
        // The bulk loop takes `y` reduced. Without one, the AAD stays queued
        // and shares the tail's reduction.
        g.flush(hk);
        g.y = bulk_narrow(keys, hk, &mut ctr, body, g.y, encrypting);
    }
    finish(
        keys,
        hk,
        &mut g,
        &mut ctr,
        j0,
        ekj0,
        tail,
        aad.len(),
        data_len,
        encrypting,
    )
}

// ---------------------------------------------------------------------------
// The wide kernel: VAES and VPCLMULQDQ on ymm registers, sixteen blocks per
// iteration.

/// [`bulk_narrow`], sixteen blocks at a time.
#[target_feature(enable = "aes,pclmulqdq,ssse3")]
fn bulk_wide(
    _w: Wide,
    keys: &Keys,
    hk: &HashKey,
    ctr: &mut Counter,
    data: &mut [u8],
    y: __m128i,
    encrypting: bool,
) -> __m128i {
    debug_assert_eq!(data.len() % WIDE, 0);
    let groups = data.len() / WIDE;
    if groups == 0 {
        return y;
    }
    let (rk, rounds) = keys.enc_round_keys();
    let rk = rk.as_ptr() as *const u8;
    let mut st = State::new(y, ctr);
    let p = data.as_mut_ptr();
    // SAFETY: `_w` proves AVX2, VAES and VPCLMULQDQ. `p` is `groups * 256`
    // bytes with `groups > 0`; `rk` is an AES-NI schedule of `rounds`
    // rounds.
    unsafe {
        match rounds {
            10 => wide_groups::<10>(p, groups, rk, hk, &mut st, encrypting),
            12 => wide_groups::<12>(p, groups, rk, hk, &mut st, encrypting),
            _ => wide_groups::<14>(p, groups, rk, hk, &mut st, encrypting),
        }
    }
    st.finish(ctr)
}

/// [`narrow_groups`], sixteen blocks a group.
///
/// # Safety
///
/// As [`bulk_wide`] establishes.
#[inline]
unsafe fn wide_groups<const R: usize>(
    p: *mut u8,
    groups: usize,
    rk: *const u8,
    hk: &HashKey,
    st: &mut State,
    encrypting: bool,
) {
    use crate::gcm_x86_asm::{y16_aes, y16_ghash, y16_open, y16_seal};
    let s = st.0.as_mut_ptr();
    let (pw, pk) = hk.last_powers(16);
    // SAFETY: as in `narrow_groups`, with `groups * 256` bytes and sixteen
    // powers.
    unsafe {
        if !encrypting {
            y16_open::<R>(p, groups, rk, pw, pk, s);
        } else if groups > 1 {
            y16_seal::<R>(p, groups - 1, rk, pw, pk, s);
        } else {
            y16_aes::<R>(p, rk, s);
            y16_ghash(p, pw, pk, s);
        }
    }
}

/// Which wide bulk loop [`run_wide`] uses, with its proof.
#[derive(Clone, Copy)]
enum Bulk {
    Ymm(Wide),
    Zmm(Wide512),
}

#[target_feature(enable = "avx2,aes,pclmulqdq,ssse3")]
fn run_wide(
    bulk: Bulk,
    keys: &Keys,
    hk: &HashKey,
    j0: &[u8; BLOCK],
    aad: &[u8],
    data: &mut [u8],
    encrypting: bool,
) -> [u8; BLOCK] {
    // SAFETY: `j0` is 16 bytes; the load is unaligned.
    let j0 = unsafe { _mm_loadu_si128(j0.as_ptr() as *const __m128i) };
    let mut g = Pending::new();
    g.push_padded(hk, aad);
    let mut ctr = Counter::after(j0);
    let data_len = data.len();
    let wide = data_len - data_len % WIDE;
    let (body, rest) = data.split_at_mut(wide);
    let narrow = rest.len() - rest.len() % NARROW;
    let (mid, tail) = rest.split_at_mut(narrow);
    let mut ekj0 = None;
    if !body.is_empty() || !mid.is_empty() {
        // As in `run_narrow`: `E_K(J0)` first, and only a bulk loop needs `y`
        // reduced first.
        let (rk, rounds) = keys.enc_round_keys();
        ekj0 = Some(aes1(rk, rounds, j0));
        g.flush(hk);
    }
    if !body.is_empty() {
        g.y = match bulk {
            Bulk::Ymm(w) => bulk_wide(w, keys, hk, &mut ctr, body, g.y, encrypting),
            Bulk::Zmm(w) => bulk_zmm(w, keys, hk, &mut ctr, body, g.y, encrypting),
        };
    }
    if !mid.is_empty() {
        g.y = bulk_narrow(keys, hk, &mut ctr, mid, g.y, encrypting);
    }
    finish(
        keys,
        hk,
        &mut g,
        &mut ctr,
        j0,
        ekj0,
        tail,
        aad.len(),
        data_len,
        encrypting,
    )
}

// ---------------------------------------------------------------------------
// The 512-bit kernel: VAES and VPCLMULQDQ on zmm registers, sixteen blocks
// per iteration in four registers.
//
// Unlike the 256-bit kernel, this cannot be built from one-instruction
// wrappers: naming a `zmm` register as an `asm!` operand needs the `avx512f`
// target feature, which Rust 1.87 does not have. So the whole loop over
// 256-byte groups is one `asm!` block that names its registers itself --
// `zmm0` to `zmm15` only, every one of them declared clobbered -- inside a
// function that is never inlined and holds nothing else live. Its inputs and
// outputs pass through memory: the counter and the GHASH accumulator in
// `state`, and the constants below.
//
// The arithmetic is the 256-bit kernel's, widened: the same counter layout,
// the same field arithmetic -- products by Karatsuba with twisted powers, see
// `zmm_ghash!`, and the two-multiply reduction of `gcm_x86_asm::x8_reduce!`.

/// Masks and increments for the 512-bit kernel, one 128-bit lane per block:
/// the byte reversal, the counter-field reversal, `+4` in each lane's counter,
/// and the lane offsets `0, 1, 2, 3`; then, at 256, the reduction's constant
/// `x^-1` (as `gcm_x86_asm::CONSTS` holds it at 144).
#[repr(C, align(64))]
struct ZmmConsts([u8; 272]);

static ZMM_CONSTS: ZmmConsts = ZmmConsts({
    let mut c = [0u8; 272];
    let mut lane = 0;
    while lane < 4 {
        let mut i = 0;
        while i < 16 {
            // Byte reversal.
            c[lane * 16 + i] = (15 - i) as u8;
            // Counter-field reversal: bytes 12..16 reversed, the rest kept.
            c[64 + lane * 16 + i] = if i < 12 { i as u8 } else { (27 - i) as u8 };
            i += 1;
        }
        // `+4` in the top 32-bit lane, little-endian.
        c[128 + lane * 16 + 12] = 4;
        // Lane `k` starts `k` counters on.
        c[192 + lane * 16 + 12] = lane as u8;
        lane += 1;
    }
    // `x^-1`, byte-reversed: the reduction's constant, as in `gcm_x86_asm`.
    c[256] = 1;
    c[256 + 15] = 0xc2;
    c
});

/// One AES round, `$insn`, with the round key at `$addr`, on all four state
/// registers.
macro_rules! zmm_round {
    ($insn:literal, $addr:literal) => {
        concat!(
            "vbroadcasti32x4 zmm4, xmmword ptr [",
            $addr,
            "]\n",
            $insn,
            " zmm0, zmm0, zmm4\n",
            $insn,
            " zmm1, zmm1, zmm4\n",
            $insn,
            " zmm2, zmm2, zmm4\n",
            $insn,
            " zmm3, zmm3, zmm4\n",
        )
    };
}

/// Sixteen counter blocks, encrypted, in `zmm0..zmm3`; the counter in `zmm10`
/// advanced by sixteen.
macro_rules! zmm_aes {
    () => {
        concat!(
            "vpshufb zmm0, zmm10, zmm12\n",
            "vpaddd zmm10, zmm10, zmm11\n",
            "vpshufb zmm1, zmm10, zmm12\n",
            "vpaddd zmm10, zmm10, zmm11\n",
            "vpshufb zmm2, zmm10, zmm12\n",
            "vpaddd zmm10, zmm10, zmm11\n",
            "vpshufb zmm3, zmm10, zmm12\n",
            "vpaddd zmm10, zmm10, zmm11\n",
            "vbroadcasti32x4 zmm4, xmmword ptr [{rk}]\n",
            "vpxorq zmm0, zmm0, zmm4\n",
            "vpxorq zmm1, zmm1, zmm4\n",
            "vpxorq zmm2, zmm2, zmm4\n",
            "vpxorq zmm3, zmm3, zmm4\n",
            zmm_round!("vaesenc", "{rk} + 16"),
            zmm_round!("vaesenc", "{rk} + 32"),
            zmm_round!("vaesenc", "{rk} + 48"),
            zmm_round!("vaesenc", "{rk} + 64"),
            zmm_round!("vaesenc", "{rk} + 80"),
            zmm_round!("vaesenc", "{rk} + 96"),
            zmm_round!("vaesenc", "{rk} + 112"),
            zmm_round!("vaesenc", "{rk} + 128"),
            zmm_round!("vaesenc", "{rk} + 144"),
            // AES-128 has ten rounds and is done; AES-192 two more, AES-256
            // four. The branch is on the key size, which is public.
            "cmp {rounds}, 10\n",
            "je 3f\n",
            zmm_round!("vaesenc", "{rk} + 160"),
            zmm_round!("vaesenc", "{rk} + 176"),
            "cmp {rounds}, 12\n",
            "je 3f\n",
            zmm_round!("vaesenc", "{rk} + 192"),
            zmm_round!("vaesenc", "{rk} + 208"),
            "3:\n",
            zmm_round!("vaesenclast", "{rkl}"),
        )
    };
}

/// XOR the keystream in `zmm0..zmm3` into the group at `{p}`, in place.
macro_rules! zmm_xor_store {
    () => {
        concat!(
            "vpxorq zmm0, zmm0, zmmword ptr [{p}]\n",
            "vpxorq zmm1, zmm1, zmmword ptr [{p} + 64]\n",
            "vpxorq zmm2, zmm2, zmmword ptr [{p} + 128]\n",
            "vpxorq zmm3, zmm3, zmmword ptr [{p} + 192]\n",
            "vmovdqu64 zmmword ptr [{p}], zmm0\n",
            "vmovdqu64 zmmword ptr [{p} + 64], zmm1\n",
            "vmovdqu64 zmmword ptr [{p} + 128], zmm2\n",
            "vmovdqu64 zmmword ptr [{p} + 192], zmm3\n",
        )
    };
}

/// Byte-reverse four blocks into `zmm5`: from a register (`reg`), or loaded
/// from `{p}` at an offset (`mem`).
macro_rules! zmm_load {
    (reg $src:literal) => {
        concat!("vpshufb zmm5, ", $src, ", zmm13\n")
    };
    (mem $off:literal) => {
        concat!(
            "vmovdqu64 zmm5, zmmword ptr [{p} + ",
            $off,
            "]\n",
            "vpshufb zmm5, zmm5, zmm13\n",
        )
    };
}

/// GHASH over sixteen blocks, the four groups of four loaded by `$l0..$l3`,
/// into the accumulator `xmm9`.
///
/// Two things keep the accumulator's dependency chain short, which is what
/// bounds this loop: the carry-less multiplier issues once every two cycles
/// whatever the width, with five cycles of latency, so a chain through it is
/// expensive and the sixteen independent products are not.
///
/// - The sixteen block products do not involve the accumulator at all. `Y`
///   enters as its own product, `Y*H^16`, in 128-bit registers, added after
///   the lanes are summed: `(Y ^ X0)*H^16 = Y*H^16 ^ X0*H^16`. So the chain
///   from one group's `Y` to the next is three multiplies and the reduction,
///   and everything else overlaps it.
/// - Each product is Karatsuba's: `lo = a0*b0`, `hi = a1*b1`, and
///   `(a0^a1)*(b0^b1)`, from which the middle term is recovered as that
///   XOR `lo ^ hi` once, after the sums. Three multiplies a block, not four.
///   `kara` at `{pk}` holds `b0^b1` for each power.
/// - The powers are twisted ([`twist`]), so the sums are the product in place
///   and the reduction is two more multiplies, as in
///   `gcm_x86_asm::x8_reduce!`, rather than `clmul::reduce`'s shifts: nine
///   percent off the 512-bit loop's time per byte, measured.
///
/// `zmm6`/`zmm7`/`zmm8` collect lo, Karatsuba middle, and hi.
macro_rules! zmm_ghash {
    ($l0:expr, $l1:expr, $l2:expr, $l3:expr) => {
        concat!(
            // Blocks 0..4 times H^16..H^13.
            $l0,
            "vpshufd zmm4, zmm5, 0x4e\n",
            "vpxorq zmm4, zmm4, zmm5\n",
            "vpclmulqdq zmm6, zmm5, zmmword ptr [{pw}], 0x00\n",
            "vpclmulqdq zmm8, zmm5, zmmword ptr [{pw}], 0x11\n",
            "vpclmulqdq zmm7, zmm4, zmmword ptr [{pk}], 0x00\n",
            $l1,
            zmm_mul_acc!("64"),
            $l2,
            zmm_mul_acc!("128"),
            $l3,
            zmm_mul_acc!("192"),
            // Sum the four lanes of each of lo, mid, hi.
            "vextracti64x4 ymm14, zmm6, 1\n",
            "vpxor ymm6, ymm6, ymm14\n",
            "vextracti128 xmm14, ymm6, 1\n",
            "vpxor xmm6, xmm6, xmm14\n",
            "vextracti64x4 ymm14, zmm7, 1\n",
            "vpxor ymm7, ymm7, ymm14\n",
            "vextracti128 xmm14, ymm7, 1\n",
            "vpxor xmm7, xmm7, xmm14\n",
            "vextracti64x4 ymm14, zmm8, 1\n",
            "vpxor ymm8, ymm8, ymm14\n",
            "vextracti128 xmm14, ymm8, 1\n",
            "vpxor xmm8, xmm8, xmm14\n",
            // Y*H^16, Karatsuba too, added in.
            "vpshufd xmm4, xmm9, 0x4e\n",
            "vpxor xmm4, xmm4, xmm9\n",
            "vpclmulqdq xmm14, xmm9, xmmword ptr [{pw}], 0x00\n",
            "vpclmulqdq xmm15, xmm9, xmmword ptr [{pw}], 0x11\n",
            "vpclmulqdq xmm4, xmm4, xmmword ptr [{pk}], 0x00\n",
            "vpxor xmm6, xmm6, xmm14\n",
            "vpxor xmm8, xmm8, xmm15\n",
            "vpxor xmm7, xmm7, xmm4\n",
            // The true middle term: Karatsuba's, minus lo and hi.
            "vpxor xmm7, xmm7, xmm6\n",
            "vpxor xmm7, xmm7, xmm8\n",
            // lo ^= mid << 64; hi ^= mid >> 64; then the two folds of
            // `gcm_x86_asm::x8_reduce!`, the powers being twisted.
            "vpslldq xmm14, xmm7, 8\n",
            "vpxor xmm6, xmm6, xmm14\n",
            "vpsrldq xmm14, xmm7, 8\n",
            "vpxor xmm8, xmm8, xmm14\n",
            "vpclmulqdq xmm14, xmm6, xmmword ptr [{c} + 256], 0x10\n",
            "vpshufd xmm6, xmm6, 0x4e\n",
            "vpxor xmm6, xmm6, xmm14\n",
            "vpclmulqdq xmm14, xmm6, xmmword ptr [{c} + 256], 0x10\n",
            "vpshufd xmm6, xmm6, 0x4e\n",
            "vpxor xmm6, xmm6, xmm8\n",
            "vpxor xmm9, xmm6, xmm14\n",
        )
    };
}

/// Four blocks in `zmm5` times the four powers at `{pw} + $off`, Karatsuba,
/// added into the unreduced sums.
macro_rules! zmm_mul_acc {
    ($off:literal) => {
        concat!(
            "vpshufd zmm4, zmm5, 0x4e\n",
            "vpxorq zmm4, zmm4, zmm5\n",
            "vpclmulqdq zmm14, zmm5, zmmword ptr [{pw} + ",
            $off,
            "], 0x00\n",
            "vpclmulqdq zmm15, zmm5, zmmword ptr [{pw} + ",
            $off,
            "], 0x11\n",
            "vpclmulqdq zmm4, zmm4, zmmword ptr [{pk} + ",
            $off,
            "], 0x00\n",
            // zmm6 ^= lo, zmm8 ^= hi, zmm7 ^= middle.
            "vpxorq zmm6, zmm6, zmm14\n",
            "vpxorq zmm8, zmm8, zmm15\n",
            "vpxorq zmm7, zmm7, zmm4\n",
        )
    };
}

/// The loop over `groups` 256-byte groups at `p`, sealing (`ENC`) or opening.
///
/// `state` is the GHASH accumulator (byte-reversed) followed by the counter
/// (in [`Counter`]'s form); both are read on entry and written back on exit.
///
/// # Safety
///
/// - The CPU must have AVX-512F, AVX-512BW, VAES and VPCLMULQDQ: a
///   [`Wide512`] token's guarantee.
/// - `p` must point to `groups * 256` readable and writable bytes, and
///   `groups` must be at least one.
/// - `rk` must point to the 15 round keys of an AES-NI schedule with `rounds`
///   rounds (10, 12 or 14), and `rk_last` to round key `rounds`.
/// - `pw` and `pk` must point to [`HashKey::twisted`] and [`HashKey::kara`],
///   256 bytes each; `state` to 32 readable and writable bytes.
#[inline(never)]
#[allow(clippy::too_many_arguments)]
unsafe fn zmm_groups<const ENC: bool>(
    p: *mut u8,
    groups: usize,
    rk: *const u8,
    rk_last: *const u8,
    rounds: usize,
    pw: *const u8,
    pk: *const u8,
    state: *mut u8,
) {
    debug_assert!(groups > 0);
    // SAFETY: the caller upholds the contract above, which is every memory
    // access the block makes: the groups at `p`, the round keys, the powers,
    // `state`, and the static constants. It uses `zmm0`..`zmm15` only, and
    // declares all sixteen clobbered (an `xmm` clobber covers the whole
    // `ymm`/`zmm` register), so on Windows the callee-saved `xmm6`..`xmm15`
    // are preserved by this function's prologue. It ends with `vzeroupper`.
    // It touches no stack. `zmm16`..`zmm31` and the mask registers are not
    // used, and this function is never inlined, so no caller value can be
    // live in them across it.
    unsafe {
        if ENC {
            asm!(
                "vmovdqu64 zmm13, zmmword ptr [{c}]",
                "vmovdqu64 zmm12, zmmword ptr [{c} + 64]",
                "vmovdqu64 zmm11, zmmword ptr [{c} + 128]",
                "vbroadcasti32x4 zmm10, xmmword ptr [{st} + 16]",
                "vpaddd zmm10, zmm10, zmmword ptr [{c} + 192]",
                "vmovdqu xmm9, xmmword ptr [{st}]",
                "2:",
                zmm_aes!(),
                zmm_xor_store!(),
                // Sealing: GHASH the ciphertext, still in zmm0..zmm3.
                zmm_ghash!(
                    zmm_load!(reg "zmm0"),
                    zmm_load!(reg "zmm1"),
                    zmm_load!(reg "zmm2"),
                    zmm_load!(reg "zmm3")
                ),
                "add {p}, 256",
                "dec {n}",
                "jnz 2b",
                "vmovdqu xmmword ptr [{st}], xmm9",
                "vmovdqu xmmword ptr [{st} + 16], xmm10",
                "vzeroupper",
                p = inout(reg) p => _,
                n = inout(reg) groups => _,
                rk = in(reg) rk,
                rkl = in(reg) rk_last,
                rounds = in(reg) rounds,
                pw = in(reg) pw,
                pk = in(reg) pk,
                st = in(reg) state,
                c = in(reg) ZMM_CONSTS.0.as_ptr(),
                out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
                out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
                options(nostack),
            );
        } else {
            asm!(
                "vmovdqu64 zmm13, zmmword ptr [{c}]",
                "vmovdqu64 zmm12, zmmword ptr [{c} + 64]",
                "vmovdqu64 zmm11, zmmword ptr [{c} + 128]",
                "vbroadcasti32x4 zmm10, xmmword ptr [{st} + 16]",
                "vpaddd zmm10, zmm10, zmmword ptr [{c} + 192]",
                "vmovdqu xmm9, xmmword ptr [{st}]",
                "2:",
                // Opening: GHASH the ciphertext before it is overwritten.
                zmm_ghash!(
                    zmm_load!(mem "0"),
                    zmm_load!(mem "64"),
                    zmm_load!(mem "128"),
                    zmm_load!(mem "192")
                ),
                zmm_aes!(),
                zmm_xor_store!(),
                "add {p}, 256",
                "dec {n}",
                "jnz 2b",
                "vmovdqu xmmword ptr [{st}], xmm9",
                "vmovdqu xmmword ptr [{st} + 16], xmm10",
                "vzeroupper",
                p = inout(reg) p => _,
                n = inout(reg) groups => _,
                rk = in(reg) rk,
                rkl = in(reg) rk_last,
                rounds = in(reg) rounds,
                pw = in(reg) pw,
                pk = in(reg) pk,
                st = in(reg) state,
                c = in(reg) ZMM_CONSTS.0.as_ptr(),
                out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
                out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
                options(nostack),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// The 512-bit kernel's main loop: thirty-two blocks per iteration, in eight
// registers, with GHASH stitched between the AES rounds.
//
// Why thirty-two, and why stitched. On the CPU this was measured on (Zen 5),
// `VAESENC` issues twice a cycle with four cycles of latency, and
// `VPCLMULQDQ` once every two cycles, whatever the width, with five. Four
// registers of AES -- the sixteen-block loop above -- are four dependency
// chains, so AES runs at half rate on its own; and when each group's GHASH
// waits for that group's ciphertext, the two never overlap and their times
// add. Eight chains keep AES at full rate, and hashing the *previous* group's
// ciphertext, which is already in memory, between this group's rounds gives
// the multiplier independent work for the whole of them.
//
// Register use: `zmm0..zmm7` the AES states, `zmm8` the round key (and the
// counter before the rounds start), `zmm9` the accumulator `Y` (lane 0),
// `zmm10..zmm12` the unreduced lo / Karatsuba middle / hi, `zmm13..zmm15`
// GHASH temporaries. The masks and increments are memory operands.

/// The thirty-two counter blocks of this iteration into `zmm0..zmm7`, and the
/// counter at `{st} + 16` advanced past them.
macro_rules! z32_ctr {
    () => {
        concat!(
            "vbroadcasti32x4 zmm8, xmmword ptr [{st} + 16]\n",
            "vpaddd zmm8, zmm8, zmmword ptr [{c} + 192]\n",
            "vpshufb zmm0, zmm8, zmmword ptr [{c} + 64]\n",
            "vpaddd zmm8, zmm8, zmmword ptr [{c} + 128]\n",
            "vpshufb zmm1, zmm8, zmmword ptr [{c} + 64]\n",
            "vpaddd zmm8, zmm8, zmmword ptr [{c} + 128]\n",
            "vpshufb zmm2, zmm8, zmmword ptr [{c} + 64]\n",
            "vpaddd zmm8, zmm8, zmmword ptr [{c} + 128]\n",
            "vpshufb zmm3, zmm8, zmmword ptr [{c} + 64]\n",
            "vpaddd zmm8, zmm8, zmmword ptr [{c} + 128]\n",
            "vpshufb zmm4, zmm8, zmmword ptr [{c} + 64]\n",
            "vpaddd zmm8, zmm8, zmmword ptr [{c} + 128]\n",
            "vpshufb zmm5, zmm8, zmmword ptr [{c} + 64]\n",
            "vpaddd zmm8, zmm8, zmmword ptr [{c} + 128]\n",
            "vpshufb zmm6, zmm8, zmmword ptr [{c} + 64]\n",
            "vpaddd zmm8, zmm8, zmmword ptr [{c} + 128]\n",
            "vpshufb zmm7, zmm8, zmmword ptr [{c} + 64]\n",
            "vpaddd zmm8, zmm8, zmmword ptr [{c} + 128]\n",
            // Lane 0 is now the counter thirty-two on.
            "vmovdqu xmmword ptr [{st} + 16], xmm8\n",
            "vbroadcasti32x4 zmm8, xmmword ptr [{rk}]\n",
            "vpxorq zmm0, zmm0, zmm8\n",
            "vpxorq zmm1, zmm1, zmm8\n",
            "vpxorq zmm2, zmm2, zmm8\n",
            "vpxorq zmm3, zmm3, zmm8\n",
            "vpxorq zmm4, zmm4, zmm8\n",
            "vpxorq zmm5, zmm5, zmm8\n",
            "vpxorq zmm6, zmm6, zmm8\n",
            "vpxorq zmm7, zmm7, zmm8\n",
        )
    };
}

/// One AES round, `$insn`, with the round key at `$addr`, on all eight state
/// registers.
macro_rules! z32_round {
    ($insn:literal, $addr:literal) => {
        concat!(
            "vbroadcasti32x4 zmm8, xmmword ptr [",
            $addr,
            "]\n",
            $insn,
            " zmm0, zmm0, zmm8\n",
            $insn,
            " zmm1, zmm1, zmm8\n",
            $insn,
            " zmm2, zmm2, zmm8\n",
            $insn,
            " zmm3, zmm3, zmm8\n",
            $insn,
            " zmm4, zmm4, zmm8\n",
            $insn,
            " zmm5, zmm5, zmm8\n",
            $insn,
            " zmm6, zmm6, zmm8\n",
            $insn,
            " zmm7, zmm7, zmm8\n",
        )
    };
}

/// Rounds 10 to the last, which depend on the key size. The branch is on the
/// key size, which is public.
macro_rules! z32_last_rounds {
    () => {
        concat!(
            "cmp {rounds}, 10\n",
            "je 3f\n",
            z32_round!("vaesenc", "{rk} + 160"),
            z32_round!("vaesenc", "{rk} + 176"),
            "cmp {rounds}, 12\n",
            "je 3f\n",
            z32_round!("vaesenc", "{rk} + 192"),
            z32_round!("vaesenc", "{rk} + 208"),
            "3:\n",
            z32_round!("vaesenclast", "{rkl}"),
        )
    };
}

/// XOR the keystream in `zmm0..zmm7` into the 512 bytes at `{p}`, in place.
macro_rules! z32_xor_store {
    () => {
        concat!(
            "vpxorq zmm0, zmm0, zmmword ptr [{p}]\n",
            "vpxorq zmm1, zmm1, zmmword ptr [{p} + 64]\n",
            "vpxorq zmm2, zmm2, zmmword ptr [{p} + 128]\n",
            "vpxorq zmm3, zmm3, zmmword ptr [{p} + 192]\n",
            "vpxorq zmm4, zmm4, zmmword ptr [{p} + 256]\n",
            "vpxorq zmm5, zmm5, zmmword ptr [{p} + 320]\n",
            "vpxorq zmm6, zmm6, zmmword ptr [{p} + 384]\n",
            "vpxorq zmm7, zmm7, zmmword ptr [{p} + 448]\n",
            "vmovdqu64 zmmword ptr [{p}], zmm0\n",
            "vmovdqu64 zmmword ptr [{p} + 64], zmm1\n",
            "vmovdqu64 zmmword ptr [{p} + 128], zmm2\n",
            "vmovdqu64 zmmword ptr [{p} + 192], zmm3\n",
            "vmovdqu64 zmmword ptr [{p} + 256], zmm4\n",
            "vmovdqu64 zmmword ptr [{p} + 320], zmm5\n",
            "vmovdqu64 zmmword ptr [{p} + 384], zmm6\n",
            "vmovdqu64 zmmword ptr [{p} + 448], zmm7\n",
        )
    };
}

/// GHASH step `k` of eight: the four blocks at `[$src + $off]`, times the four
/// powers at `{pw} + $off` (Karatsuba, `{pk}`), added into the sums. `first`
/// starts the sums instead of adding to them.
macro_rules! z32_gstep {
    (first, $src:literal) => {
        concat!(
            "vmovdqu64 zmm13, zmmword ptr [",
            $src,
            "]\n",
            "vpshufb zmm13, zmm13, zmmword ptr [{c}]\n",
            "vpshufd zmm14, zmm13, 0x4e\n",
            "vpxorq zmm14, zmm14, zmm13\n",
            "vpclmulqdq zmm10, zmm13, zmmword ptr [{pw}], 0x00\n",
            "vpclmulqdq zmm12, zmm13, zmmword ptr [{pw}], 0x11\n",
            "vpclmulqdq zmm11, zmm14, zmmword ptr [{pk}], 0x00\n",
        )
    };
    ($src:literal, $off:literal) => {
        concat!(
            "vmovdqu64 zmm13, zmmword ptr [",
            $src,
            " + ",
            $off,
            "]\n",
            "vpshufb zmm13, zmm13, zmmword ptr [{c}]\n",
            "vpshufd zmm14, zmm13, 0x4e\n",
            "vpxorq zmm14, zmm14, zmm13\n",
            "vpclmulqdq zmm15, zmm13, zmmword ptr [{pw} + ",
            $off,
            "], 0x00\n",
            "vpxorq zmm10, zmm10, zmm15\n",
            "vpclmulqdq zmm15, zmm13, zmmword ptr [{pw} + ",
            $off,
            "], 0x11\n",
            "vpxorq zmm12, zmm12, zmm15\n",
            "vpclmulqdq zmm15, zmm14, zmmword ptr [{pk} + ",
            $off,
            "], 0x00\n",
            "vpxorq zmm11, zmm11, zmm15\n",
        )
    };
}

/// Sum the lanes, add `Y*H^32`, recover the middle term, and reduce into
/// `xmm9`: the same steps as `zmm_ghash!`'s, on `xmm10..xmm12`.
macro_rules! z32_reduce {
    () => {
        concat!(
            "vextracti64x4 ymm13, zmm10, 1\n",
            "vpxor ymm10, ymm10, ymm13\n",
            "vextracti128 xmm13, ymm10, 1\n",
            "vpxor xmm10, xmm10, xmm13\n",
            "vextracti64x4 ymm13, zmm11, 1\n",
            "vpxor ymm11, ymm11, ymm13\n",
            "vextracti128 xmm13, ymm11, 1\n",
            "vpxor xmm11, xmm11, xmm13\n",
            "vextracti64x4 ymm13, zmm12, 1\n",
            "vpxor ymm12, ymm12, ymm13\n",
            "vextracti128 xmm13, ymm12, 1\n",
            "vpxor xmm12, xmm12, xmm13\n",
            // Y*H^32, Karatsuba.
            "vpshufd xmm13, xmm9, 0x4e\n",
            "vpxor xmm13, xmm13, xmm9\n",
            "vpclmulqdq xmm14, xmm9, xmmword ptr [{pw}], 0x00\n",
            "vpclmulqdq xmm15, xmm9, xmmword ptr [{pw}], 0x11\n",
            "vpclmulqdq xmm13, xmm13, xmmword ptr [{pk}], 0x00\n",
            "vpxor xmm10, xmm10, xmm14\n",
            "vpxor xmm12, xmm12, xmm15\n",
            "vpxor xmm11, xmm11, xmm13\n",
            "vpxor xmm11, xmm11, xmm10\n",
            "vpxor xmm11, xmm11, xmm12\n",
            // lo ^= mid << 64; hi ^= mid >> 64; then the two folds.
            "vpslldq xmm14, xmm11, 8\n",
            "vpxor xmm10, xmm10, xmm14\n",
            "vpsrldq xmm14, xmm11, 8\n",
            "vpxor xmm12, xmm12, xmm14\n",
            "vpclmulqdq xmm14, xmm10, xmmword ptr [{c} + 256], 0x10\n",
            "vpshufd xmm10, xmm10, 0x4e\n",
            "vpxor xmm10, xmm10, xmm14\n",
            "vpclmulqdq xmm14, xmm10, xmmword ptr [{c} + 256], 0x10\n",
            "vpshufd xmm10, xmm10, 0x4e\n",
            "vpxor xmm10, xmm10, xmm12\n",
            "vpxor xmm9, xmm10, xmm14\n",
        )
    };
}

/// AES on this iteration's thirty-two counters, with GHASH over the 512
/// bytes at `$src` stitched between rounds 1 to 9; then the keystream XORed
/// in at `{p}`.
macro_rules! z32_stitched {
    ($src:literal) => {
        concat!(
            z32_ctr!(),
            z32_round!("vaesenc", "{rk} + 16"),
            z32_gstep!(first, $src),
            z32_round!("vaesenc", "{rk} + 32"),
            z32_gstep!($src, "64"),
            z32_round!("vaesenc", "{rk} + 48"),
            z32_gstep!($src, "128"),
            z32_round!("vaesenc", "{rk} + 64"),
            z32_gstep!($src, "192"),
            z32_round!("vaesenc", "{rk} + 80"),
            z32_gstep!($src, "256"),
            z32_round!("vaesenc", "{rk} + 96"),
            z32_gstep!($src, "320"),
            z32_round!("vaesenc", "{rk} + 112"),
            z32_gstep!($src, "384"),
            z32_round!("vaesenc", "{rk} + 128"),
            z32_gstep!($src, "448"),
            z32_round!("vaesenc", "{rk} + 144"),
            z32_reduce!(),
            z32_last_rounds!(),
            z32_xor_store!(),
        )
    };
}

/// AES alone on this iteration's counters, and the XOR at `{p}`.
macro_rules! z32_aes_only {
    () => {
        concat!(
            z32_ctr!(),
            z32_round!("vaesenc", "{rk} + 16"),
            z32_round!("vaesenc", "{rk} + 32"),
            z32_round!("vaesenc", "{rk} + 48"),
            z32_round!("vaesenc", "{rk} + 64"),
            z32_round!("vaesenc", "{rk} + 80"),
            z32_round!("vaesenc", "{rk} + 96"),
            z32_round!("vaesenc", "{rk} + 112"),
            z32_round!("vaesenc", "{rk} + 128"),
            z32_round!("vaesenc", "{rk} + 144"),
            z32_last_rounds!(),
            z32_xor_store!(),
        )
    };
}

/// GHASH alone over the 512 bytes at `$src`.
macro_rules! z32_ghash_only {
    ($src:literal) => {
        concat!(
            z32_gstep!(first, $src),
            z32_gstep!($src, "64"),
            z32_gstep!($src, "128"),
            z32_gstep!($src, "192"),
            z32_gstep!($src, "256"),
            z32_gstep!($src, "320"),
            z32_gstep!($src, "384"),
            z32_gstep!($src, "448"),
            z32_reduce!(),
        )
    };
}

/// The loop over `groups` 512-byte groups at `p`, sealing (`ENC`) or opening.
///
/// Sealing, GHASH needs the ciphertext, so the first group is encrypted
/// alone, each later iteration hashes the group before it while encrypting
/// its own, and the last group is hashed after the loop. Opening, each
/// iteration hashes the group it is about to decrypt; the hash reads it
/// before the store at the end of the iteration overwrites it.
///
/// `state` is as for [`zmm_groups`]: the accumulator, then the counter.
///
/// # Safety
///
/// As [`zmm_groups`], with `p` pointing to `groups * 512` bytes, and `pw`
/// and `pk` to all 32 entries (512 bytes) of [`HashKey::twisted`] and
/// [`HashKey::kara`].
#[inline(never)]
#[allow(clippy::too_many_arguments)]
unsafe fn zmm32_groups<const ENC: bool>(
    p: *mut u8,
    groups: usize,
    rk: *const u8,
    rk_last: *const u8,
    rounds: usize,
    pw: *const u8,
    pk: *const u8,
    state: *mut u8,
) {
    debug_assert!(groups > 0);
    // SAFETY: as for `zmm_groups`: every memory access is within the regions
    // the caller vouches for (sealing also reads the group before `{p}`,
    // which it has just written, never before the first); `zmm0`..`zmm15`
    // only, all declared clobbered; no stack; `vzeroupper` at the end; never
    // inlined.
    unsafe {
        if ENC {
            asm!(
                "vmovdqu xmm9, xmmword ptr [{st}]",
                z32_aes_only!(),
                "add {p}, 512",
                "dec {n}",
                "jz 4f",
                "2:",
                z32_stitched!("{p} - 512"),
                "add {p}, 512",
                "dec {n}",
                "jnz 2b",
                "4:",
                z32_ghash_only!("{p} - 512"),
                "vmovdqu xmmword ptr [{st}], xmm9",
                "vzeroupper",
                p = inout(reg) p => _,
                n = inout(reg) groups => _,
                rk = in(reg) rk,
                rkl = in(reg) rk_last,
                rounds = in(reg) rounds,
                pw = in(reg) pw,
                pk = in(reg) pk,
                st = in(reg) state,
                c = in(reg) ZMM_CONSTS.0.as_ptr(),
                out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
                out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
                options(nostack),
            );
        } else {
            asm!(
                "vmovdqu xmm9, xmmword ptr [{st}]",
                "2:",
                z32_stitched!("{p}"),
                "add {p}, 512",
                "dec {n}",
                "jnz 2b",
                "vmovdqu xmmword ptr [{st}], xmm9",
                "vzeroupper",
                p = inout(reg) p => _,
                n = inout(reg) groups => _,
                rk = in(reg) rk,
                rkl = in(reg) rk_last,
                rounds = in(reg) rounds,
                pw = in(reg) pw,
                pk = in(reg) pk,
                st = in(reg) state,
                c = in(reg) ZMM_CONSTS.0.as_ptr(),
                out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                out("xmm8") _, out("xmm9") _, out("xmm10") _, out("xmm11") _,
                out("xmm12") _, out("xmm13") _, out("xmm14") _, out("xmm15") _,
                options(nostack),
            );
        }
    }
}

/// [`bulk_narrow`], thirty-two blocks at a time in 512-bit registers, then
/// sixteen for a remaining 256 bytes.
#[target_feature(enable = "sse2")]
fn bulk_zmm(
    _w: Wide512,
    keys: &Keys,
    hk: &HashKey,
    ctr: &mut Counter,
    data: &mut [u8],
    y: __m128i,
    encrypting: bool,
) -> __m128i {
    debug_assert_eq!(data.len() % WIDE, 0);
    if data.is_empty() {
        return y;
    }
    let (rk, rounds) = keys.enc_round_keys();
    let mut state = [0u8; 32];
    // SAFETY: `state` is 32 bytes; the stores are unaligned.
    unsafe {
        _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, y);
        _mm_storeu_si128(state.as_mut_ptr().add(BLOCK) as *mut __m128i, ctr.0);
    }
    let rk_ptr = rk.as_ptr() as *const u8;
    let rk_last = rk[rounds..].as_ptr() as *const u8;
    let st = state.as_mut_ptr();

    let big = data.len() / WIDE32;
    let (head, rest) = data.split_at_mut(big * WIDE32);
    if big > 0 {
        // All 32 powers.
        let (pw, pk) = hk.last_powers(NPOW);
        // SAFETY: `_w` proves the features; `head` is `big * 512` bytes with
        // `big > 0`; `rk`, `rk_last` and `rounds` come from one AES-NI
        // schedule; `pw` and `pk` are 512 bytes each and `st` 32.
        unsafe {
            if encrypting {
                zmm32_groups::<true>(head.as_mut_ptr(), big, rk_ptr, rk_last, rounds, pw, pk, st);
            } else {
                zmm32_groups::<false>(head.as_mut_ptr(), big, rk_ptr, rk_last, rounds, pw, pk, st);
            }
        }
    }
    let small = rest.len() / WIDE;
    if small > 0 {
        // The last sixteen powers, H^16..H^1.
        let (pw, pk) = hk.last_powers(16);
        // SAFETY: as above, with `rest` `small * 256` bytes, `small > 0`, and
        // `pw` and `pk` 256 bytes each.
        unsafe {
            if encrypting {
                zmm_groups::<true>(
                    rest.as_mut_ptr(),
                    small,
                    rk_ptr,
                    rk_last,
                    rounds,
                    pw,
                    pk,
                    st,
                );
            } else {
                zmm_groups::<false>(
                    rest.as_mut_ptr(),
                    small,
                    rk_ptr,
                    rk_last,
                    rounds,
                    pw,
                    pk,
                    st,
                );
            }
        }
    }
    // SAFETY: `state` is 32 bytes; the loads are unaligned.
    let (y, c) = unsafe {
        (
            _mm_loadu_si128(state.as_ptr() as *const __m128i),
            _mm_loadu_si128(state.as_ptr().add(BLOCK) as *const __m128i),
        )
    };
    state.zeroize();
    ctr.0 = c;
    y
}
