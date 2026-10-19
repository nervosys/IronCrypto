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
//!   has AVX-512F and AVX-512BW. See the notes above `z32_ctr!` in `gcm_x86_asm` for why
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
//! contracts are on [`crate::gcm_x86_asm::zmm_groups`], [`crate::gcm_x86_asm::zmm32_groups`] and the functions of
//! [`crate::gcm_x86_asm`].

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
                crate::gcm_x86_asm::zmm32_groups::<true>(
                    head.as_mut_ptr(),
                    big,
                    rk_ptr,
                    rk_last,
                    rounds,
                    pw,
                    pk,
                    st,
                );
            } else {
                crate::gcm_x86_asm::zmm32_groups::<false>(
                    head.as_mut_ptr(),
                    big,
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
    let small = rest.len() / WIDE;
    if small > 0 {
        // The last sixteen powers, H^16..H^1.
        let (pw, pk) = hk.last_powers(16);
        // SAFETY: as above, with `rest` `small * 256` bytes, `small > 0`, and
        // `pw` and `pk` 256 bytes each.
        unsafe {
            if encrypting {
                crate::gcm_x86_asm::zmm_groups::<true>(
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
                crate::gcm_x86_asm::zmm_groups::<false>(
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
