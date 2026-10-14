//! RFC 8439 ChaCha20, Poly1305, and the ChaCha20-Poly1305 AEAD; and
//! XChaCha20-Poly1305, the same AEAD with a 192-bit nonce.
//!
//! **Not FIPS-approved.** These are included because they are the right answer
//! on hardware without AES acceleration, and because interoperating with TLS
//! 1.3, WireGuard, and age requires them. The ontology marks the whole family
//! `fips_status: NotApproved`, and `ic-fips` refuses to construct them while
//! the module is in approved mode.

use ic_core::traits::internal::Mac;

use ic_core::traits::{Aead, Algorithm, RandomSource, SelfTest};
use ic_core::{ensure, Result, Zeroize};

const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[inline(always)]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// The twenty ChaCha rounds, in place, without adding the input back.
#[inline(always)]
fn rounds(working: &mut [u32; 16]) {
    for _ in 0..10 {
        // Column rounds.
        quarter_round(working, 0, 4, 8, 12);
        quarter_round(working, 1, 5, 9, 13);
        quarter_round(working, 2, 6, 10, 14);
        quarter_round(working, 3, 7, 11, 15);
        // Diagonal rounds.
        quarter_round(working, 0, 5, 10, 15);
        quarter_round(working, 1, 6, 11, 12);
        quarter_round(working, 2, 7, 8, 13);
        quarter_round(working, 3, 4, 9, 14);
    }
}

/// HChaCha20 (draft-irtf-cfrg-xchacha-03 section 2.2): a subkey from a key
/// and a 128-bit nonce.
///
/// The state is ChaCha20's with the counter and nonce words replaced by the
/// four words of `nonce`. After the rounds, and without adding the input
/// back, the first row and the last are the subkey.
fn hchacha20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&SIGMA);
    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    for i in 0..4 {
        state[12 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }
    rounds(&mut state);
    let mut subkey = [0u8; 32];
    for i in 0..4 {
        subkey[i * 4..i * 4 + 4].copy_from_slice(&state[i].to_le_bytes());
        subkey[16 + i * 4..16 + i * 4 + 4].copy_from_slice(&state[12 + i].to_le_bytes());
    }
    state.zeroize();
    subkey
}

/// Produce one 64-byte ChaCha20 keystream block.
fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8; 64]) {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&SIGMA);
    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }

    let mut working = state;
    rounds(&mut working);
    for i in 0..16 {
        let v = working[i].wrapping_add(state[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    working.zeroize();
    state.zeroize();
}

// The x86-64 backends, selected by `std`'s run-time detection. The AVX-512
// keystream and the AVX2 Poly1305 are also compiled for `ct-probes`, whose
// harness reads them.
#[cfg(all(target_arch = "x86_64", any(feature = "std", feature = "ct-probes")))]
#[cfg_attr(not(feature = "std"), allow(dead_code))]
pub(crate) mod avx2;
// Poly1305 in radix 2^64, for the AEAD's short messages. Pure Rust and no
// detection, so on every x86-64 build.
#[cfg(target_arch = "x86_64")]
pub(crate) mod poly64;
#[cfg(all(target_arch = "x86_64", any(feature = "std", feature = "ct-probes")))]
#[cfg_attr(not(feature = "std"), allow(dead_code))]
pub(crate) mod poly_avx2;
#[cfg(all(target_arch = "x86_64", any(feature = "std", feature = "ct-probes")))]
#[cfg_attr(not(feature = "std"), allow(dead_code))]
pub(crate) mod zmm;

/// Ask once per process whether every feature named is present, and cache
/// the answer; see the SHA-256 dispatch for why.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
macro_rules! cached_detect {
    ($($f:tt),+) => {{
        use core::sync::atomic::{AtomicU8, Ordering};
        static CACHED: AtomicU8 = AtomicU8::new(0);
        match CACHED.load(Ordering::Relaxed) {
            1 => true,
            2 => false,
            _ => {
                let have = true $(&& std::is_x86_feature_detected!($f))+;
                CACHED.store(u8::from(!have) + 1, Ordering::Relaxed);
                have
            }
        }
    }};
}

/// Whether this CPU has AVX2.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
fn avx2() -> bool {
    cached_detect!("avx2")
}

/// Whether this CPU has AVX-512F, which the sixteen-block kernel needs. `std`'s
/// detection also confirms that the OS saves the `zmm` state.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
fn zmm_available() -> bool {
    // `--cfg ic_no_avx512` reports this false, for measuring the AVX2 paths.
    !cfg!(ic_no_avx512) && cached_detect!("avx512f")
}

/// Which keystream kernel runs the bulk of a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    /// One block at a time, everywhere.
    Portable,
    /// Eight blocks at a time on AVX2, then the portable path.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    Avx2,
    /// Sixteen blocks at a time on AVX-512F, then AVX2, then portable.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    Zmm,
}

/// The fastest kernel this CPU has.
fn best_backend() -> Backend {
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    {
        if zmm_available() && avx2() {
            return Backend::Zmm;
        }
        if avx2() {
            return Backend::Avx2;
        }
    }
    Backend::Portable
}

/// XOR `data` with the ChaCha20 keystream, starting at `counter`.
pub fn chacha20_xor(key: &[u8], nonce: &[u8], counter: u32, data: &mut [u8]) -> Result<()> {
    ic_core::module::operational()?;
    ensure!(
        key.len() == 32,
        InvalidLength,
        "chacha20 key must be 32 bytes"
    );
    ensure!(
        nonce.len() == 12,
        InvalidLength,
        "chacha20 nonce must be 12 bytes"
    );
    let mut k = [0u8; 32];
    k.copy_from_slice(key);
    let mut n = [0u8; 12];
    n.copy_from_slice(nonce);
    let result = xor_keystream(best_backend(), &k, &n, counter, data);
    k.zeroize();
    result
}

/// The keystream XOR behind [`chacha20_xor`] and the AEAD, on `backend`.
///
/// Refuses, before touching `data`, a message whose blocks would run the
/// 32-bit counter past its last value. The wide kernels rely on that: they
/// step the counter sixteen or eight blocks at a time and must not step over
/// the boundary. (They used to be guarded by a check made in 64 bits that
/// could never fail, so a message crossing the boundary wrapped the counter
/// in the AVX2 path and reused keystream, where the portable path stopped
/// with an error halfway through. Now every path refuses the whole message.)
fn xor_keystream(
    backend: Backend,
    k: &[u8; 32],
    n: &[u8; 12],
    counter: u32,
    data: &mut [u8],
) -> Result<()> {
    let blocks = (data.len() as u64).div_ceil(64);
    ensure!(
        u64::from(counter) + blocks <= 1 << 32,
        CounterExhausted,
        "chacha20 block counter"
    );
    let _ = backend;
    #[allow(unused_mut)]
    let (mut data, mut counter) = (data, counter);

    // Sixteen blocks at a time where the CPU has AVX-512F.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    if backend == Backend::Zmm && data.len() >= zmm::STRIDE {
        let mut start = zmm::Start::new(k, n, counter);
        let mut groups = data.chunks_exact_mut(zmm::STRIDE);
        for group in &mut groups {
            if let Ok(group) = <&mut [u8; zmm::STRIDE]>::try_from(group) {
                // SAFETY: `Backend::Zmm` is chosen only where
                // `zmm_available()` confirmed AVX-512F.
                unsafe { zmm::group(&start, group) };
            }
            counter = counter.wrapping_add(zmm::LANES as u32);
            start.set_counter(counter);
        }
        data = groups.into_remainder();
    }

    // Eight at a time on AVX2: the whole message there, the tail here.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    if backend != Backend::Portable {
        let mut groups = data.chunks_exact_mut(avx2::STRIDE);
        for group in &mut groups {
            // SAFETY: both wide backends are chosen only where `avx2()`
            // confirmed AVX2, and the slice is exactly STRIDE bytes.
            unsafe { avx2::eight_blocks(k, n, counter, group) };
            counter = counter.wrapping_add(avx2::LANES as u32);
        }
        data = groups.into_remainder();
    }

    // What is left, under eight blocks, two or four at a time on AVX2 -- but
    // a last single block by the block function, which is the faster for
    // one: the pair kernel's twenty rounds are one dependent chain of vector
    // operations, the block function's four chains of scalar ones. The
    // kernel computes whole pairs; a block past the message is computed and
    // not used, and its counter may wrap, which is harmless because the
    // check above has bounded every block that is used.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    if backend != Backend::Portable && data.len() > 64 {
        // SAFETY: both wide backends are chosen only where `avx2()`
        // confirmed AVX2.
        unsafe { avx2_tail(k, n, counter, data) };
        return Ok(());
    }

    // What is left one block at a time; on the portable backend, all of it.
    let mut block = [0u8; 64];
    for (i, chunk) in data.chunks_mut(64).enumerate() {
        chacha20_block(k, counter.wrapping_add(i as u32), n, &mut block);
        for (d, b) in chunk.iter_mut().zip(block.iter()) {
            *d ^= b;
        }
    }
    block.zeroize();
    Ok(())
}

/// The tail of [`xor_keystream`] on AVX2, under eight blocks: four blocks at
/// a time, then two. Out of line, so that the bulk path around it compiles as
/// it did before it existed.
///
/// # Safety
///
/// The CPU must support AVX2.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
#[inline(never)]
unsafe fn avx2_tail(k: &[u8; 32], n: &[u8; 12], mut counter: u32, data: &mut [u8]) {
    let mut ks = [0u8; 256];
    let mut used = 128;
    for chunk in data.chunks_mut(256) {
        let pairs = if chunk.len() > 128 {
            used = 256;
            avx2::Pairs::Two
        } else {
            avx2::Pairs::One
        };
        // SAFETY: AVX2, as the caller guarantees.
        unsafe { avx2::short_blocks(k, n, counter, pairs, &mut ks) };
        for (d, b) in chunk.iter_mut().zip(ks.iter()) {
            *d ^= b;
        }
        counter = counter.wrapping_add(4);
    }
    ks[..used].zeroize();
}

/// RFC 8439 Poly1305 one-time authenticator.
///
/// Every key must be used for exactly one message. Reuse reveals the key.
#[derive(Clone)]
pub struct Poly1305 {
    r: [u32; 5],
    s: [u32; 4],
    /// `r^2`, `r^3`, `r^4`, for absorbing four blocks at a time.
    ///
    /// Poly1305 is a Horner evaluation -- `h = (h + m) * r` -- so each block
    /// waits on the one before it, exactly as GHASH does. The same identity
    /// unrolls it:
    ///
    /// ```text
    /// h' = (h + m0)*r^4  +  m1*r^3  +  m2*r^2  +  m3*r
    /// ```
    ///
    /// Four independent products rather than four dependent ones. It also
    /// reduces once instead of four times: the products are summed while still
    /// unreduced, which the limb bounds allow, so the carry chain runs once per
    /// group rather than once per block.
    powers: [[u32; 5]; 3],
    acc: [u32; 5],
    buf: [u8; 16],
    buffered: usize,
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.r.zeroize();
        self.s.zeroize();
        for p in &mut self.powers {
            p.zeroize();
        }
        self.acc.zeroize();
        self.buf.zeroize();
    }
}

impl Algorithm for Poly1305 {
    const ID: &'static str = "poly1305";
    const NAME: &'static str = "Poly1305";
}

impl Poly1305 {
    /// Absorb one block. Blocks shorter than 16 bytes are the final block and
    /// get an explicit 0x01 terminator instead of the implicit 2^128 bit.
    fn absorb_block(&mut self, block: &[u8]) {
        let mut b = [0u8; 16];
        b[..block.len()].copy_from_slice(block);
        let pad = if block.len() < 16 {
            b[block.len()] = 1;
            0
        } else {
            1 << 24
        };

        let t0 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let t1 = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        let t2 = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
        let t3 = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);

        self.acc[0] += t0 & 0x3ff_ffff;
        self.acc[1] += ((t0 >> 26) | (t1 << 6)) & 0x3ff_ffff;
        self.acc[2] += ((t1 >> 20) | (t2 << 12)) & 0x3ff_ffff;
        self.acc[3] += ((t2 >> 14) | (t3 << 18)) & 0x3ff_ffff;
        self.acc[4] += (t3 >> 8) | pad;

        self.multiply_by_r();
    }

    fn multiply_by_r(&mut self) {
        self.acc = reduce(mul_unreduced(self.acc, self.r, five_times(self.r)));
    }

    /// Absorb four whole blocks with four independent products.
    ///
    /// Correct for the same reason the one-at-a-time path is; see `powers`.
    fn absorb4(&mut self, blocks: &[u8]) {
        debug_assert_eq!(blocks.len(), 64);
        let mut m = [[0u32; 5]; 4];
        for (i, slot) in m.iter_mut().enumerate() {
            let b = &blocks[i * 16..(i + 1) * 16];
            let t0 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            let t1 = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
            let t2 = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
            let t3 = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
            // Whole blocks only, so the 2^128 bit is always set.
            *slot = [
                t0 & 0x3ff_ffff,
                ((t0 >> 26) | (t1 << 6)) & 0x3ff_ffff,
                ((t1 >> 20) | (t2 << 12)) & 0x3ff_ffff,
                ((t2 >> 14) | (t3 << 18)) & 0x3ff_ffff,
                (t3 >> 8) | (1 << 24),
            ];
        }

        // The oldest block carries the accumulator and takes the highest power.
        for (limb, a) in m[0].iter_mut().zip(self.acc) {
            *limb += a;
        }

        let multipliers = [self.powers[2], self.powers[1], self.powers[0], self.r];
        let mut d = [0u64; 5];
        for (block, r) in m.iter().zip(multipliers) {
            let part = mul_unreduced(*block, r, five_times(r));
            for (acc, term) in d.iter_mut().zip(part) {
                *acc += term;
            }
        }
        self.acc = reduce(d);
    }
}

/// The shortest input `update` hands to the AVX2 Poly1305: below two groups
/// the lanes' final multiplication by distinct powers costs as much as it
/// saves.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
const POLY_AVX2_MIN: usize = 128;

/// `[5*r1, 5*r2, 5*r3, 5*r4]`, the companion the reduction folds in.
fn five_times(r: [u32; 5]) -> [u32; 4] {
    [r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5]
}

/// The five limb products, summed but not carried.
///
/// Each term is at most `2^27 * 5*2^26`, and five of them stay under `2^57`,
/// so four of these vectors can be added before carrying without leaving
/// `u64`. That headroom is what lets `absorb4` reduce once instead of四 times.
fn mul_unreduced(h: [u32; 5], r: [u32; 5], s: [u32; 4]) -> [u64; 5] {
    let m = |a: u32, b: u32| a as u64 * b as u64;
    [
        m(h[0], r[0]) + m(h[1], s[3]) + m(h[2], s[2]) + m(h[3], s[1]) + m(h[4], s[0]),
        m(h[0], r[1]) + m(h[1], r[0]) + m(h[2], s[3]) + m(h[3], s[2]) + m(h[4], s[1]),
        m(h[0], r[2]) + m(h[1], r[1]) + m(h[2], r[0]) + m(h[3], s[3]) + m(h[4], s[2]),
        m(h[0], r[3]) + m(h[1], r[2]) + m(h[2], r[1]) + m(h[3], r[0]) + m(h[4], s[3]),
        m(h[0], r[4]) + m(h[1], r[3]) + m(h[2], r[2]) + m(h[3], r[1]) + m(h[4], r[0]),
    ]
}

/// Carry-propagate back into 26-bit limbs, folding `2^130` into `5`.
///
/// The carries are 64-bit, and have to be. One product's limbs are under
/// `2^58` and its carries under `2^32`, which is what this function was
/// first written for. `absorb4` hands it four products summed: limbs up to
/// about `2^60`, a first carry up to about `2^34`, and a last carry whose
/// five-fold is about `2^34` too. Held in a `u32`, the first could be cut
/// short by its cast and the last could overflow its multiplication. That
/// needs the message limbs to be large: for a kilobyte of `0xff` bytes it
/// happened under about one key in twenty, and for random bytes never.
///
/// With 64-bit carries nothing here can wrap: a limb plus a carry is under
/// `2^61`, and `c * 5` under `2^41`.
fn reduce(d: [u64; 5]) -> [u32; 5] {
    const MASK: u64 = 0x3ff_ffff;
    let mut c = d[0] >> 26;
    let a0 = d[0] & MASK;
    let d1 = d[1] + c;
    c = d1 >> 26;
    let a1 = d1 & MASK;
    let d2 = d[2] + c;
    c = d2 >> 26;
    let a2 = d2 & MASK;
    let d3 = d[3] + c;
    c = d3 >> 26;
    let a3 = d3 & MASK;
    let d4 = d[4] + c;
    c = d4 >> 26;
    let a4 = d4 & MASK;
    // 2^130 = 5 mod p, so what carried out of the top comes back in at the
    // bottom five times over.
    let folded = a0 + c * 5;
    let a0 = folded & MASK;
    // Under 2^26 + 2^15: the one limb left a little over its width, as the
    // multiplication expects.
    let a1 = a1 + (folded >> 26);
    [a0 as u32, a1 as u32, a2 as u32, a3 as u32, a4 as u32]
}

impl Mac for Poly1305 {
    type Tag = [u8; 16];
    const TAG_LEN: usize = 16;

    fn new(key: &[u8]) -> Result<Self> {
        ic_core::module::operational()?;
        ensure!(
            key.len() == 32,
            InvalidLength,
            "poly1305 key must be 32 bytes"
        );
        let t0 = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
        let t1 = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);
        let t2 = u32::from_le_bytes([key[8], key[9], key[10], key[11]]);
        let t3 = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);
        // `r` is clamped per RFC 8439 §2.5.
        let r = [
            t0 & 0x3ff_ffff,
            ((t0 >> 26) | (t1 << 6)) & 0x3ff_ff03,
            ((t1 >> 20) | (t2 << 12)) & 0x3ff_c0ff,
            ((t2 >> 14) | (t3 << 18)) & 0x3f0_3fff,
            (t3 >> 8) & 0x000_fffff,
        ];
        let s = [
            u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
            u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
            u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
            u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        ];
        // r^2, r^3 and r^4, each from the previous by the same multiply the
        // hot path uses. Once per key, off the hot path.
        let rr = five_times(r);
        let mut powers = [[0u32; 5]; 3];
        let mut p = r;
        for slot in powers.iter_mut() {
            p = reduce(mul_unreduced(p, r, rr));
            *slot = p;
        }

        Ok(Self {
            r,
            s,
            powers,
            acc: [0u32; 5],
            buf: [0u8; 16],
            buffered: 0,
        })
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.buffered > 0 {
            let take = core::cmp::min(16 - self.buffered, data.len());
            self.buf[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < 16 {
                return;
            }
            let block = self.buf;
            self.absorb_block(&block);
            self.buffered = 0;
        }
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        if data.len() >= POLY_AVX2_MIN && avx2() {
            let whole = data.len() & !63;
            // SAFETY: `avx2()` confirmed AVX2; `whole` is a nonzero multiple
            // of 64.
            let d = unsafe { poly_avx2::absorb(&self.acc, &self.r, &self.powers, &data[..whole]) };
            self.acc = reduce(d);
            data = &data[whole..];
        }
        while data.len() >= 64 {
            self.absorb4(&data[..64]);
            data = &data[64..];
        }
        let mut chunks = data.chunks_exact(16);
        for block in &mut chunks {
            self.absorb_block(block);
        }
        let rest = chunks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    fn finalize(mut self) -> [u8; 16] {
        if self.buffered > 0 {
            let n = self.buffered;
            let block = self.buf;
            self.absorb_block(&block[..n]);
            self.buffered = 0;
        }

        // Final reduction modulo 2^130 - 5.
        let mut h = self.acc;
        let mut c = h[1] >> 26;
        h[1] &= 0x3ff_ffff;
        h[2] += c;
        c = h[2] >> 26;
        h[2] &= 0x3ff_ffff;
        h[3] += c;
        c = h[3] >> 26;
        h[3] &= 0x3ff_ffff;
        h[4] += c;
        c = h[4] >> 26;
        h[4] &= 0x3ff_ffff;
        h[0] += c * 5;
        c = h[0] >> 26;
        h[0] &= 0x3ff_ffff;
        h[1] += c;

        // g = h + 5, then select g if it did not overflow past 2^130.
        let mut g = [0u32; 5];
        let mut carry = 5u32;
        for i in 0..4 {
            let v = h[i] + carry;
            g[i] = v & 0x3ff_ffff;
            carry = v >> 26;
        }
        // The top limb is left unmasked so the borrow out of 2^130 is visible
        // in its sign bit.
        g[4] = h[4].wrapping_add(carry).wrapping_sub(1 << 26);
        let mask = ((g[4] >> 31) ^ 1).wrapping_neg();
        for i in 0..5 {
            h[i] = (h[i] & !mask) | (g[i] & mask);
        }

        // Serialize as a 128-bit little-endian value, then add `s`.
        let h0 = h[0] | (h[1] << 26);
        let h1 = (h[1] >> 6) | (h[2] << 20);
        let h2 = (h[2] >> 12) | (h[3] << 14);
        let h3 = (h[3] >> 18) | (h[4] << 8);

        let mut f = h0 as u64 + self.s[0] as u64;
        let r0 = f as u32;
        f = h1 as u64 + self.s[1] as u64 + (f >> 32);
        let r1 = f as u32;
        f = h2 as u64 + self.s[2] as u64 + (f >> 32);
        let r2 = f as u32;
        f = h3 as u64 + self.s[3] as u64 + (f >> 32);
        let r3 = f as u32;

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&r0.to_le_bytes());
        tag[4..8].copy_from_slice(&r1.to_le_bytes());
        tag[8..12].copy_from_slice(&r2.to_le_bytes());
        tag[12..16].copy_from_slice(&r3.to_le_bytes());
        tag
    }
}

impl SelfTest for Poly1305 {
    fn self_test() -> Result<()> {
        // RFC 8439 §2.5.2.
        let mut key = [0u8; 32];
        ic_core::codec::hex_decode(
            b"85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
            &mut key,
        )?;
        let tag = <Self as Mac>::mac(&key, b"Cryptographic Forum Research Group")?;
        let mut want = [0u8; 16];
        ic_core::codec::hex_decode(b"a8061dc1305136c6c22b8baf0c0127a9", &mut want)?;
        ensure!(ic_core::ct::verify(&want, &tag), SelfTestFailed, "poly1305");
        Ok(())
    }
}

/// RFC 8439 ChaCha20-Poly1305 AEAD.
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Algorithm for ChaCha20Poly1305 {
    const ID: &'static str = "chacha20-poly1305";
    const NAME: &'static str = "ChaCha20-Poly1305";
}

impl ChaCha20Poly1305 {
    /// Derive the one-time Poly1305 key from block 0 of the ChaCha20 keystream.
    fn poly_key(&self, nonce: &[u8]) -> Result<[u8; 32]> {
        let mut block = [0u8; 64];
        let mut n = [0u8; 12];
        ensure!(nonce.len() == 12, InvalidLength, "chacha20-poly1305 nonce");
        n.copy_from_slice(nonce);
        chacha20_block(&self.key, 0, &n, &mut block);
        let mut k = [0u8; 32];
        k.copy_from_slice(&block[..32]);
        block.zeroize();
        Ok(k)
    }

    /// Compute the AEAD tag over `aad || pad || ciphertext || pad || lengths`.
    ///
    /// Two passes over the message, the keystream and then this, rather than
    /// one pass of cache-sized pieces. Both were measured, at 4 MiB and at
    /// 256 MiB, and the single pass was not distinguishably faster on Zen 5;
    /// and opening in one pass would have to decrypt before the tag is
    /// checked.
    fn tag(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<[u8; 16]> {
        let mut poly_key = self.poly_key(nonce)?;
        // The body of `tag_under`, written out again rather than called: as
        // a call, with the key passed through memory, it cost the bulk path
        // measurably in one of the benchmark's builds.
        #[cfg(target_arch = "x86_64")]
        if aad.len().saturating_add(ciphertext.len()) <= POLY64_MAX {
            let t = poly64::aead_tag(&poly_key, aad, ciphertext);
            poly_key.zeroize();
            return Ok(t);
        }
        let mut m = Poly1305::new(&poly_key)?;
        poly_key.zeroize();

        m.update(aad);
        m.update(&[0u8; 16][..(16 - aad.len() % 16) % 16]);
        m.update(ciphertext);
        m.update(&[0u8; 16][..(16 - ciphertext.len() % 16) % 16]);

        let mut lens = [0u8; 16];
        lens[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        lens[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        m.update(&lens);
        Ok(m.finalize())
    }

    /// Seal or open a message of at most [`SHORT_MAX`] bytes in one call of
    /// the two-block kernel: blocks 0 and 1, or 0 to 3, block 0 the Poly1305
    /// key and the rest the message's keystream. Opening checks the tag over
    /// the ciphertext before the keystream touches it, as the long path does.
    ///
    /// Out of line: inlined into `seal_detached`, it cost the long path about
    /// two percent at 1 KiB (rdtsc, minimum of many, against the build
    /// without it), and out of line nothing measurable at either length.
    ///
    /// # Safety
    ///
    /// The CPU must support AVX2.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[inline(never)]
    unsafe fn short(
        &self,
        nonce: &[u8; 12],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8; 16],
        seal: bool,
    ) -> Result<()> {
        debug_assert!(in_out.len() <= SHORT_MAX);
        let (pairs, used) = if in_out.len() <= 64 {
            (avx2::Pairs::One, 128)
        } else {
            (avx2::Pairs::Two, 256)
        };
        let mut ks = [0u8; 256];
        // SAFETY: AVX2, as the caller guarantees.
        unsafe { avx2::short_blocks(&self.key, nonce, 0, pairs, &mut ks) };
        let (head, stream) = ks.split_at(64);
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&head[..32]);
        let result = if seal {
            for (d, k) in in_out.iter_mut().zip(stream) {
                *d ^= k;
            }
            tag_under(&poly_key, aad, in_out).map(|t| *tag = t)
        } else {
            match tag_under(&poly_key, aad, in_out) {
                Ok(expected) if ic_core::ct::verify(&expected, tag) => {
                    for (d, k) in in_out.iter_mut().zip(stream) {
                        *d ^= k;
                    }
                    Ok(())
                }
                Ok(_) => {
                    in_out.zeroize();
                    Err(ic_core::err!(AuthenticationFailed, "chacha20-poly1305"))
                }
                Err(e) => Err(e),
            }
        };
        poly_key.zeroize();
        ks[..used].zeroize();
        result
    }
}

/// The longest message [`ChaCha20Poly1305`] seals and opens by its short
/// path: three blocks, so that with the Poly1305 key's block it is one call
/// of the two-block kernel on two pairs.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
const SHORT_MAX: usize = 192;

/// The longest associated data and ciphertext, together, whose tag is
/// computed in radix 2^64 ([`poly64`]) rather than by [`Poly1305`], whose
/// AVX2 path is the faster from about here.
#[cfg(target_arch = "x86_64")]
const POLY64_MAX: usize = 256;

/// The AEAD tag (RFC 8439 section 2.8) under the one-time key `poly_key`:
/// Poly1305 over `aad`, padding, `ciphertext`, padding and the two lengths.
/// For the short path, whose key comes out of the same kernel call as its
/// keystream.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
fn tag_under(poly_key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> Result<[u8; 16]> {
    if aad.len().saturating_add(ciphertext.len()) <= POLY64_MAX {
        return Ok(poly64::aead_tag(poly_key, aad, ciphertext));
    }

    let mut m = Poly1305::new(poly_key)?;
    m.update(aad);
    m.update(&[0u8; 16][..(16 - aad.len() % 16) % 16]);
    m.update(ciphertext);
    m.update(&[0u8; 16][..(16 - ciphertext.len() % 16) % 16]);

    let mut lens = [0u8; 16];
    lens[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lens[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    m.update(&lens);
    Ok(m.finalize())
}

impl Aead for ChaCha20Poly1305 {
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;

    fn new(key: &[u8]) -> Result<Self> {
        ic_core::module::operational()?;
        ensure!(key.len() == 32, InvalidLength, "chacha20-poly1305 key");
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        Ok(Self { key: k })
    }

    fn seal_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8],
    ) -> Result<()> {
        ic_core::module::operational()?;
        ensure!(
            tag.len() == 16,
            InvalidLength,
            "chacha20-poly1305 tag buffer"
        );
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        if in_out.len() <= SHORT_MAX && avx2() {
            let n: &[u8; 12] = nonce
                .try_into()
                .map_err(|_| ic_core::err!(InvalidLength, "chacha20-poly1305 nonce"))?;
            let mut t = [0u8; 16];
            // SAFETY: `avx2()` confirmed AVX2.
            unsafe { self.short(n, aad, in_out, &mut t, true)? };
            tag.copy_from_slice(&t);
            return Ok(());
        }
        // Block 0 is reserved for the Poly1305 key, so data starts at block 1.
        chacha20_xor(&self.key, nonce, 1, in_out)?;
        let t = self.tag(nonce, aad, in_out)?;
        tag.copy_from_slice(&t);
        Ok(())
    }

    fn open_detached(&self, nonce: &[u8], aad: &[u8], in_out: &mut [u8], tag: &[u8]) -> Result<()> {
        ic_core::module::operational()?;
        ensure!(tag.len() == 16, InvalidLength, "chacha20-poly1305 tag");
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        if in_out.len() <= SHORT_MAX && avx2() {
            let n: &[u8; 12] = nonce
                .try_into()
                .map_err(|_| ic_core::err!(InvalidLength, "chacha20-poly1305 nonce"))?;
            let mut t = [0u8; 16];
            t.copy_from_slice(tag);
            // SAFETY: `avx2()` confirmed AVX2.
            return unsafe { self.short(n, aad, in_out, &mut t, false) };
        }
        let expected = self.tag(nonce, aad, in_out)?;
        if !ic_core::ct::verify(&expected, tag) {
            in_out.zeroize();
            return Err(ic_core::err!(AuthenticationFailed, "chacha20-poly1305"));
        }
        chacha20_xor(&self.key, nonce, 1, in_out)
    }
}

impl SelfTest for ChaCha20Poly1305 {
    fn self_test() -> Result<()> {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let c = <Self as Aead>::new(&key)?;
        let mut buf = *b"self-test payload";
        let original = buf;
        let mut tag = [0u8; 16];
        c.seal_detached(&nonce, b"aad", &mut buf, &mut tag)?;
        ensure!(buf != original, SelfTestFailed, "chacha20-poly1305");
        c.open_detached(&nonce, b"aad", &mut buf, &tag)?;
        ensure!(buf == original, SelfTestFailed, "chacha20-poly1305");
        Ok(())
    }
}

/// XChaCha20-Poly1305: ChaCha20-Poly1305 with a 192-bit nonce
/// (draft-irtf-cfrg-xchacha-03).
///
/// The first 16 bytes of the nonce and the key give a subkey through
/// HChaCha20; the last 8, after four zero bytes, are the nonce
/// ChaCha20-Poly1305 runs with under that subkey.
///
/// The point is the nonce's length. A 96-bit nonce drawn at random collides
/// often enough that a long-lived key cannot use one; a 192-bit one does not,
/// so [`seal_with_random_nonce`](Self::seal_with_random_nonce) draws each
/// nonce and needs no counter kept anywhere. That is what to use. Passing a
/// nonce by hand through [`Aead`] is for a protocol that dictates one, and
/// carries the same rule as every AEAD: never twice under one key.
///
/// The specification is an Internet-Draft that expired in 2020 without
/// becoming an RFC. The construction is what libsodium, Go and Tink implement,
/// and it is checked here against the draft's vectors and Project
/// Wycheproof's.
pub struct XChaCha20Poly1305 {
    key: [u8; 32],
}

impl Drop for XChaCha20Poly1305 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Algorithm for XChaCha20Poly1305 {
    const ID: &'static str = "xchacha20-poly1305";
    const NAME: &'static str = "XChaCha20-Poly1305";
}

impl XChaCha20Poly1305 {
    /// The ChaCha20-Poly1305 instance and 96-bit nonce a 192-bit nonce names.
    ///
    /// The subkey lives only inside the returned cipher, which wipes it when
    /// dropped.
    fn inner(&self, nonce: &[u8]) -> Result<(ChaCha20Poly1305, [u8; 12])> {
        ensure!(
            nonce.len() == 24,
            InvalidLength,
            "xchacha20-poly1305 nonce must be 24 bytes"
        );
        let mut prefix = [0u8; 16];
        prefix.copy_from_slice(&nonce[..16]);
        let inner = ChaCha20Poly1305 {
            key: hchacha20(&self.key, &prefix),
        };
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&nonce[16..]);
        Ok((inner, n))
    }

    /// Seal under a nonce drawn from `rng`, and return the nonce.
    ///
    /// The nonce is not secret; send it with the ciphertext. Pass
    /// `ic_drbg::Rng`, not raw OS bytes.
    pub fn seal_with_random_nonce<R: RandomSource + ?Sized>(
        &self,
        rng: &mut R,
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8],
    ) -> Result<[u8; 24]> {
        ic_core::module::operational()?;
        ensure!(
            tag.len() == 16,
            InvalidLength,
            "xchacha20-poly1305 tag buffer"
        );
        let mut nonce = [0u8; 24];
        rng.fill(&mut nonce)?;
        self.seal_detached(&nonce, aad, in_out, tag)?;
        Ok(nonce)
    }
}

impl Aead for XChaCha20Poly1305 {
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 24;
    const TAG_LEN: usize = 16;

    fn new(key: &[u8]) -> Result<Self> {
        ic_core::module::operational()?;
        ensure!(key.len() == 32, InvalidLength, "xchacha20-poly1305 key");
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        Ok(Self { key: k })
    }

    fn seal_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8],
    ) -> Result<()> {
        ic_core::module::operational()?;
        let (inner, n) = self.inner(nonce)?;
        inner.seal_detached(&n, aad, in_out, tag)
    }

    fn open_detached(&self, nonce: &[u8], aad: &[u8], in_out: &mut [u8], tag: &[u8]) -> Result<()> {
        ic_core::module::operational()?;
        let (inner, n) = self.inner(nonce)?;
        inner.open_detached(&n, aad, in_out, tag)
    }
}

impl SelfTest for XChaCha20Poly1305 {
    /// The AEAD vector of draft-irtf-cfrg-xchacha-03 appendix A.3.1, sealed
    /// and opened.
    fn self_test() -> Result<()> {
        let mut key = [0u8; 32];
        for (i, k) in key.iter_mut().enumerate() {
            *k = 0x80 + i as u8;
        }
        let mut nonce = [0u8; 24];
        for (i, n) in nonce.iter_mut().enumerate() {
            *n = 0x40 + i as u8;
        }
        let aad = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext: &[u8; 114] = b"Ladies and Gentlemen of the class of '99: If I could offer \
you only one tip for the future, sunscreen would be it.";
        let mut want = [0u8; 114];
        ic_core::codec::hex_decode(
            b"bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
              731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
              2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
              21f9664c97637da9768812f615c68b13b52e",
            &mut want,
        )?;
        let mut want_tag = [0u8; 16];
        ic_core::codec::hex_decode(b"c0875924c1c7987947deafd8780acf49", &mut want_tag)?;

        let c = <Self as Aead>::new(&key)?;
        let mut buf = *plaintext;
        let mut tag = [0u8; 16];
        c.seal_detached(&nonce, &aad, &mut buf, &mut tag)?;
        ensure!(buf == want, SelfTestFailed, "xchacha20-poly1305");
        ensure!(
            ic_core::ct::verify(&want_tag, &tag),
            SelfTestFailed,
            "xchacha20-poly1305"
        );
        c.open_detached(&nonce, &aad, &mut buf, &tag)?;
        ensure!(&buf == plaintext, SelfTestFailed, "xchacha20-poly1305");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Under `--cfg ic_no_avx512` the sixteen-block kernel must not be chosen,
    /// or the AVX2-only measurement would be measuring AVX-512 after all.
    #[test]
    #[cfg(all(ic_no_avx512, target_arch = "x86_64", feature = "std"))]
    fn no_avx512_build_never_selects_the_zmm_kernel() {
        assert!(!zmm_available());
        assert_ne!(best_backend(), Backend::Zmm);
    }

    /// The eight-way path must produce the same keystream as the block path.
    ///
    /// RFC 8439's vectors do not establish this. The longest of them is 114
    /// bytes and the AVX2 stride is 512, so on this machine they exercise the
    /// scalar path exclusively and would pass with the vector code producing
    /// anything at all. This builds the expected keystream one block at a time
    /// -- the function the RFC vectors do validate -- and compares.
    ///
    /// Lengths straddle the stride in both directions, including several whole
    /// groups plus a tail, because the dispatch splits there and an off-by-one
    /// in the split is the likely error rather than a wrong round function.
    ///
    /// The same holds for the sixteen-block AVX-512 kernel, whose stride is
    /// 1024, and for both together: on that backend a message is cut into
    /// sixteen-block groups, then eight-block ones, then single blocks. So
    /// every length from 0 to 2100 is run -- each split, each tail -- on
    /// every backend this CPU has, at several counters, from an unaligned
    /// start, with data that is not all zeros.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[test]
    fn the_wide_keystreams_match_the_block_function() {
        let mut backends = std::vec![Backend::Portable];
        if avx2() {
            backends.push(Backend::Avx2);
        }
        if zmm_available() && avx2() {
            backends.push(Backend::Zmm);
        }
        if backends.len() < 3 {
            println!("only {backends:?} on this CPU; the others were not exercised");
        }

        let key: [u8; 32] = core::array::from_fn(|i| 0x5a ^ (i as u8).wrapping_mul(37));
        let nonce: [u8; 12] = core::array::from_fn(|i| 0x21 + i as u8);
        let data: std::vec::Vec<u8> = (0..2101 + 3)
            .map(|i| ((i as u32).wrapping_mul(0x9e37_79b9) >> 13) as u8)
            .collect();

        let mut checked = 0;
        for &backend in &backends {
            for counter in [0u32, 1, 15, 16, 17, 1000] {
                // The reference: one block at a time, no grouping, once for
                // the longest length; every shorter one is a prefix of it.
                let mut expect = data[3..].to_vec();
                let mut block = [0u8; 64];
                for (i, chunk) in expect.chunks_mut(64).enumerate() {
                    chacha20_block(&key, counter + i as u32, &nonce, &mut block);
                    for (d, b) in chunk.iter_mut().zip(block.iter()) {
                        *d ^= b;
                    }
                }
                for len in 0..=2100usize {
                    // Three bytes in, so no kernel sees an aligned buffer.
                    let mut buf = data.clone();
                    let region = &mut buf[3..3 + len];
                    xor_keystream(backend, &key, &nonce, counter, region).unwrap();
                    assert_eq!(
                        &buf[3..3 + len],
                        &expect[..len],
                        "{backend:?} and the block function differ at {len} bytes, counter {counter}"
                    );
                    assert_eq!(buf[..3], data[..3], "{backend:?} wrote before the buffer");
                    assert_eq!(
                        buf[3 + len..],
                        data[3 + len..],
                        "{backend:?} wrote past the buffer"
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(
            checked,
            backends.len() * 6 * 2101,
            "the comparison did not run"
        );

        // And the public entry point, which picks the best backend itself,
        // at lengths well past one group.
        for len in [65536usize, 65536 + 1000, 200_000] {
            let mut actual = std::vec![0u8; len];
            chacha20_xor(&key, &nonce, 7, &mut actual).unwrap();
            let mut expect = std::vec![0u8; len];
            xor_keystream(Backend::Portable, &key, &nonce, 7, &mut expect).unwrap();
            assert!(actual == expect, "chacha20_xor differs at {len} bytes");
        }
    }

    /// The counter is 32 bits and must not wrap: a message whose blocks would
    /// run past the last counter is refused whole, on every backend, before
    /// anything is written; one that ends on the last counter is accepted.
    #[test]
    fn the_counter_is_refused_before_it_wraps() {
        let key = [3u8; 32];
        let nonce = [4u8; 12];
        // `mut` is used only where there is a backend to add; on other
        // targets it is a warning, and an aarch64 clippy run is -D warnings.
        #[cfg_attr(not(all(target_arch = "x86_64", feature = "std")), allow(unused_mut))]
        let mut backends = std::vec![Backend::Portable];
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        {
            if avx2() {
                backends.push(Backend::Avx2);
            }
            if zmm_available() && avx2() {
                backends.push(Backend::Zmm);
            }
        }
        for backend in backends {
            for (counter, len) in [(u32::MAX, 65), (u32::MAX - 3, 1024), (u32::MAX - 15, 1025)] {
                let mut buf = std::vec![0u8; len];
                let err = xor_keystream(backend, &key, &nonce, counter, &mut buf).unwrap_err();
                assert_eq!(err.kind(), ic_core::ErrorKind::CounterExhausted);
                assert!(
                    buf.iter().all(|&b| b == 0),
                    "{backend:?} wrote before refusing"
                );
            }
            // Ending exactly on the last counter is allowed, and the last
            // block is the block function's at u32::MAX.
            let mut buf = std::vec![0u8; 1024];
            xor_keystream(backend, &key, &nonce, u32::MAX - 15, &mut buf).unwrap();
            let mut last = [0u8; 64];
            chacha20_block(&key, u32::MAX, &nonce, &mut last);
            assert_eq!(buf[960..], last[..], "{backend:?}");
        }
    }

    /// Say which path this build will take.
    #[test]
    fn the_active_chacha_path_is_reported() {
        println!("chacha20 backend: {:?}", best_backend());
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        println!(
            "poly1305: {}",
            if avx2() { "AVX2 (4 lanes)" } else { "scalar" }
        );
    }
    use ic_core::codec::{hex, unhex};

    #[test]
    fn rfc8439_chacha20_keystream_vector() {
        let key: Vec<u8> = (0..32u8).collect();
        let mut nonce = [0u8; 12];
        nonce[3] = 0x09;
        nonce[7] = 0x4a;
        let mut data = [0u8; 64];
        chacha20_xor(&key, &nonce, 1, &mut data).unwrap();
        assert_eq!(
            hex(&data),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        );
    }

    #[test]
    fn rfc8439_chacha20_encryption_vector() {
        let key: Vec<u8> = (0..32u8).collect();
        let mut nonce = [0u8; 12];
        nonce[7] = 0x4a;
        let mut data =
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        chacha20_xor(&key, &nonce, 1, &mut data).unwrap();
        assert_eq!(
            hex(&data),
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
        );
    }

    #[test]
    fn rfc8439_poly1305_vector() {
        let key =
            unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").unwrap();
        let tag = Poly1305::mac(&key, b"Cryptographic Forum Research Group").unwrap();
        assert_eq!(hex(&tag), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    #[test]
    fn poly1305_streaming_matches_one_shot() {
        let key = [0x11u8; 32];
        let data: Vec<u8> = (0..100u8).collect();
        for split in [0usize, 1, 15, 16, 17, 50, 100] {
            let mut m = Poly1305::new(&key).unwrap();
            m.update(&data[..split]);
            m.update(&data[split..]);
            assert_eq!(
                m.finalize(),
                Poly1305::mac(&key, &data).unwrap(),
                "split at {split}"
            );
        }
    }

    #[test]
    fn rfc8439_aead_vector() {
        let key =
            unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
        let nonce = unhex("070000004041424344454647").unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7").unwrap();
        let mut buf =
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();

        let c = ChaCha20Poly1305::new(&key).unwrap();
        let mut tag = [0u8; 16];
        c.seal_detached(&nonce, &aad, &mut buf, &mut tag).unwrap();
        assert_eq!(
            hex(&buf),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
        );
        assert_eq!(hex(&tag), "1ae10b594f09e26a7e902ecbd0600691");

        c.open_detached(&nonce, &aad, &mut buf, &tag).unwrap();
        assert_eq!(
            &buf[..],
            &b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."[..]
        );
    }

    #[test]
    fn aead_rejects_tampering_and_wipes() {
        let c = ChaCha20Poly1305::new(&[1u8; 32]).unwrap();
        let mut buf = b"secret".to_vec();
        let mut tag = [0u8; 16];
        c.seal_detached(&[2u8; 12], b"", &mut buf, &mut tag)
            .unwrap();
        tag[15] ^= 0x80;
        assert!(c.open_detached(&[2u8; 12], b"", &mut buf, &tag).is_err());
        assert_eq!(buf, vec![0u8; 6]);
    }

    /// The four-at-a-time Poly1305 must agree with the one-at-a-time path.
    ///
    /// RFC 8439's Poly1305 vector is 34 bytes and the group is 64, so it never
    /// reaches `absorb4`: it would pass with the grouped arithmetic returning
    /// anything. This drives both over lengths either side of the boundary and
    /// compares the tags.
    ///
    /// The powers are the likely error. `r^2`, `r^3` and `r^4` are built from
    /// `r` at construction, and a multiply that reduces wrongly, or passes the
    /// key addend where it wants five times `r`, produces powers that are
    /// self-consistent and wrong -- which every short vector still accepts.
    /// The grouped path at the top of its range.
    ///
    /// Four products are summed before one reduction, so the reduction's
    /// carries are four times what the one-block path gives it. With every
    /// message limb at its largest -- a message of `0xff` bytes, which a
    /// peer can simply send -- the last carry times five can exceed 32 bits,
    /// and so can the first carry itself. For fifteen releases the reduction
    /// held both in a `u32`: where they did not fit, a build with overflow
    /// checks stopped, and one without them computed a wrong tag. The test
    /// beside this one could not see it, because its message bytes are
    /// spread evenly and such sums never come near the top.
    ///
    /// So this is the same comparison on the inputs that reach it: the
    /// largest message limbs, under keys whose `r` is as large as clamping
    /// allows and under ordinary ones.
    #[test]
    fn the_grouped_poly1305_agrees_with_the_serial_one_at_its_largest_carries() {
        let mut keys = Vec::new();
        // r with every bit that clamping leaves: 0x0ffffffc0ffffffc0ffffffc0fffffff.
        let mut largest = [0xffu8; 32];
        largest[..16].copy_from_slice(&[
            0xff, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff,
            0xff, 0x0f,
        ]);
        keys.push(largest);
        keys.push([0xffu8; 32]);
        for seed in 0u8..62 {
            let mut key = [0u8; 32];
            for (i, b) in key.iter_mut().enumerate() {
                *b = (i as u8)
                    .wrapping_mul(0x9d)
                    .wrapping_add(seed.wrapping_mul(0x3b))
                    ^ seed;
            }
            keys.push(key);
        }

        let mut checked = 0;
        for key in &keys {
            for fill in [0xffu8, 0xfe, 0x80] {
                for len in [64usize, 128, 129, 192, 256, 1024] {
                    let data = vec![fill; len];
                    let grouped = Poly1305::mac(key, &data).unwrap();

                    let mut serial = Poly1305::new(key).unwrap();
                    for chunk in data.chunks(16) {
                        serial.absorb_block(chunk);
                    }
                    assert_eq!(
                        grouped,
                        serial.finalize(),
                        "grouped and serial Poly1305 differ: {len} bytes of {fill:#04x}"
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 64 * 3 * 6, "the comparison did not run");
    }

    #[test]
    fn the_grouped_poly1305_agrees_with_the_serial_one() {
        let key = [0x8eu8; 32];

        let mut checked = 0;
        for len in [
            0usize, 1, 15, 16, 17, 31, 32, 63, 64, 65, 79, 80, 127, 128, 129, 255, 256, 1023, 1024,
            1025,
        ] {
            let data: Vec<u8> = (0..len)
                .map(|i| ((i as u64).wrapping_mul(0x9e37_79b9) >> 5) as u8)
                .collect();

            let grouped = Poly1305::mac(&key, &data).unwrap();

            // The reference: absorb_block only, never absorb4.
            let mut serial = Poly1305::new(&key).unwrap();
            for chunk in data.chunks(16) {
                serial.absorb_block(chunk);
            }
            let serial = serial.finalize();

            assert_eq!(
                grouped, serial,
                "grouped and serial Poly1305 differ at {len} bytes"
            );
            checked += 1;
        }
        assert_eq!(checked, 20, "the comparison did not run");
    }

    /// The AVX2 Poly1305 must agree with the one-block-at-a-time path.
    ///
    /// `update` hands it every whole 64-byte group of an input of 128 bytes
    /// or more, so this runs every length from 0 to 600 and some far longer,
    /// in one call and split where the buffering, the vector path and the
    /// scalar tail meet, under the largest clamped `r` and ordinary keys, on
    /// message bytes that are all `0xff` -- the largest limbs, where a carry
    /// dropped or held too narrow shows -- and on mixed ones.
    #[test]
    fn the_avx2_poly1305_agrees_with_the_serial_one() {
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        if !avx2() {
            println!("no AVX2 on this CPU; the vector path was not exercised");
        }
        let mut largest = [0xffu8; 32];
        largest[..16].copy_from_slice(&[
            0xff, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff,
            0xff, 0x0f,
        ]);
        let ordinary: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(0x9d) ^ 0x3b);
        let mixed: Vec<u8> = (0..70_000u32)
            .map(|i| (i.wrapping_mul(0x9e37_79b9) >> 11) as u8)
            .collect();
        let ones = vec![0xffu8; 70_000];

        let serial = |key: &[u8; 32], data: &[u8]| {
            let mut m = Poly1305::new(key).unwrap();
            for chunk in data.chunks(16) {
                m.absorb_block(chunk);
            }
            m.finalize()
        };

        let mut lengths: Vec<usize> = (0..=600).collect();
        lengths.extend([1023, 1024, 1025, 4096, 16_383, 16_384, 16_385, 69_999]);
        let mut checked = 0;
        for key in [&largest, &ordinary] {
            for source in [&ones, &mixed] {
                for &len in &lengths {
                    let data = &source[..len];
                    let want = serial(key, data);
                    assert_eq!(Poly1305::mac(key, data).unwrap(), want, "{len} bytes");
                    // Split so that a buffered partial block, a vector run
                    // and a scalar tail all occur in one tag.
                    for split in [1usize, 15, 17, 64, 129] {
                        if split > len {
                            continue;
                        }
                        let mut m = Poly1305::new(key).unwrap();
                        m.update(&data[..split]);
                        m.update(&data[split..]);
                        assert_eq!(m.finalize(), want, "{len} bytes split at {split}");
                    }
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 2 * 2 * lengths.len(), "the comparison did not run");
    }

    /// The AEAD, on whichever kernels this CPU selects, must give what the
    /// portable forms give: the one-block keystream over the message and then
    /// the one-block Poly1305 over the ciphertext. Every length from 0 to 600
    /// and some far longer, with and without associated data, sealed and
    /// opened, from unaligned buffers.
    #[test]
    fn the_aead_matches_the_portable_forms() {
        let key: [u8; 32] = core::array::from_fn(|i| 0x80 + i as u8);
        let nonce: [u8; 12] = core::array::from_fn(|i| 0x40 + i as u8);
        let c = ChaCha20Poly1305::new(&key).unwrap();
        let reference = |aad: &[u8], pt: &[u8]| {
            let mut ct = pt.to_vec();
            xor_keystream(Backend::Portable, &key, &nonce, 1, &mut ct).unwrap();
            let mut block = [0u8; 64];
            chacha20_block(&key, 0, &nonce, &mut block);
            let mut m = Poly1305::new(&block[..32]).unwrap();
            let mut mac_input = aad.to_vec();
            mac_input.resize(aad.len().div_ceil(16) * 16, 0);
            mac_input.extend_from_slice(&ct);
            mac_input.resize(mac_input.len().div_ceil(16) * 16, 0);
            mac_input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
            mac_input.extend_from_slice(&(ct.len() as u64).to_le_bytes());
            for chunk in mac_input.chunks(16) {
                m.absorb_block(chunk);
            }
            (ct, m.finalize())
        };
        let source: Vec<u8> = (0..70_000u32)
            .map(|i| (i.wrapping_mul(0x2545_f491) >> 7) as u8)
            .collect();
        let mut lengths: Vec<usize> = (0..=600).collect();
        lengths.extend([1024, 16_383, 16_384, 16_385, 32_768 + 1000, 69_000]);
        for aad in [&b""[..], &b"0123456789abcdefXYZ"[..]] {
            for &len in &lengths {
                let pt = &source[1..1 + len];
                let (want_ct, want_tag) = reference(aad, pt);
                let mut buf = source[..1 + len].to_vec();
                let mut tag = [0u8; 16];
                c.seal_detached(&nonce, aad, &mut buf[1..], &mut tag)
                    .unwrap();
                assert!(buf[1..] == want_ct[..], "ciphertext at {len} bytes");
                assert_eq!(tag, want_tag, "tag at {len} bytes");
                c.open_detached(&nonce, aad, &mut buf[1..], &tag).unwrap();
                assert!(&buf[1..] == pt, "round trip at {len} bytes");
            }
        }

        // The short path (to 192 bytes) and the radix-2^64 tag (to 256 bytes
        // of associated data and ciphertext together) with associated data
        // of every length to 48, from an unaligned start, either side of both
        // limits; and a forged tag refused there, with the buffer wiped.
        let aad_all = &source[3..3 + 48];
        let mut checked = 0;
        for aad_len in 0..=48 {
            let aad = &aad_all[..aad_len];
            for len in 0..=300 {
                let pt = &source[1..1 + len];
                let (want_ct, want_tag) = reference(aad, pt);
                let mut buf = source[..1 + len].to_vec();
                let mut tag = [0u8; 16];
                c.seal_detached(&nonce, aad, &mut buf[1..], &mut tag)
                    .unwrap();
                assert!(buf[1..] == want_ct[..], "ciphertext at {len}+{aad_len}");
                assert_eq!(tag, want_tag, "tag at {len}+{aad_len}");
                let mut forged = tag;
                forged[(len + aad_len) % 16] ^= 0x10;
                let mut copy = buf.clone();
                assert!(c
                    .open_detached(&nonce, aad, &mut copy[1..], &forged)
                    .is_err());
                assert!(
                    copy[1..].iter().all(|&b| b == 0),
                    "a refused open left output at {len}+{aad_len}"
                );
                c.open_detached(&nonce, aad, &mut buf[1..], &tag).unwrap();
                assert!(&buf[1..] == pt, "round trip at {len}+{aad_len}");
                checked += 1;
            }
        }
        assert_eq!(checked, 49 * 301, "the comparison did not run");
    }

    /// The radix-2^64 Poly1305 at the top of its bounds: every message bit
    /// set, under the largest `r` clamping allows and under ordinary keys,
    /// against the 26-bit one-block path that the RFC 8439 vector validates.
    /// `h2` reaches its largest values only with message limbs this large,
    /// and the fold of everything above 2^130 is what a wrong bound breaks.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_short_poly1305_agrees_at_its_largest_limbs() {
        let mut keys = Vec::new();
        let mut largest = [0xffu8; 32];
        largest[..16].copy_from_slice(&[
            0xff, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff, 0xff, 0x0f, 0xfc, 0xff,
            0xff, 0x0f,
        ]);
        keys.push(largest);
        keys.push([0xffu8; 32]);
        keys.push([0u8; 32]);
        for seed in 0u8..29 {
            keys.push(core::array::from_fn(|i| {
                (i as u8)
                    .wrapping_mul(0x9d)
                    .wrapping_add(seed.wrapping_mul(0x3b))
                    ^ seed
            }));
        }
        let mut checked = 0;
        for key in &keys {
            for fill in [0xffu8, 0xfe, 0x00] {
                for aad_len in [0usize, 1, 15, 16, 17, 64] {
                    for len in 0..=192 {
                        let aad = vec![fill; aad_len];
                        let ct = vec![fill; len];
                        let mut input = aad.clone();
                        input.resize(aad_len.div_ceil(16) * 16, 0);
                        input.extend_from_slice(&ct);
                        input.resize(input.len().div_ceil(16) * 16, 0);
                        input.extend_from_slice(&(aad_len as u64).to_le_bytes());
                        input.extend_from_slice(&(len as u64).to_le_bytes());
                        let mut serial = Poly1305::new(key).unwrap();
                        for block in input.chunks(16) {
                            serial.absorb_block(block);
                        }
                        assert_eq!(
                            poly64::aead_tag(key, &aad, &ct),
                            serial.finalize(),
                            "{len} bytes and {aad_len} of {fill:#04x}"
                        );
                        checked += 1;
                    }
                }
            }
        }
        assert_eq!(checked, 32 * 3 * 6 * 193, "the comparison did not run");
    }

    /// The final reduction, which takes `h - p` only when `h >= p`: random
    /// inputs reach that with probability about 2^-128, so no test of
    /// random or patterned messages above ever has. With `r = 1` the
    /// accumulator is the sum of the blocks, each with its 2^128 bit, so a
    /// first block chosen against the lengths block puts `h` at `p + d`
    /// exactly, for `d` from -2 to 4. The tag is then known by the rule, `(h
    /// mod p + s) mod 2^128` with `s = 0`: `d` itself at and above `p`, `2^128
    /// - 5 + d` below it. Both Poly1305 forms are held to that.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn the_short_poly1305_reduces_at_and_above_p() {
        let mut key = [0u8; 32];
        key[0] = 1;
        // aad empty, 32 bytes of ciphertext: blocks m1, 0, and (0, 32).
        let lens = 32u128 << 64;
        for d in -2i128..=4 {
            // 2^128 - 5 + d - lens, so that m1 + 2^128 + 2^128 + lens + 2^128
            // is 2^130 - 5 + d.
            let m1 = 0u128
                .wrapping_sub(5)
                .wrapping_add(d as u128)
                .wrapping_sub(lens);
            let mut ct = [0u8; 32];
            ct[..16].copy_from_slice(&m1.to_le_bytes());
            let want = if d >= 0 {
                d as u128
            } else {
                (u128::MAX - 4).wrapping_add(d as u128)
            };
            let got = poly64::aead_tag(&key, &[], &ct);
            assert_eq!(u128::from_le_bytes(got), want, "radix 2^64, h = p + {d}");

            let mut serial = Poly1305::new(&key).unwrap();
            serial.absorb_block(&ct[..16]);
            serial.absorb_block(&ct[16..]);
            serial.absorb_block(&lens.to_le_bytes());
            assert_eq!(
                u128::from_le_bytes(serial.finalize()),
                want,
                "radix 2^26, h = p + {d}"
            );
        }
    }

    /// `r^2`, `r^3` and `r^4` must be powers of `r`.
    ///
    /// Checked against repeated single multiplication, which the RFC vector
    /// validates, so a wrong multiplier in the precomputation fails here rather
    /// than showing up as a wrong tag on long inputs only.
    #[test]
    fn the_poly1305_powers_are_powers_of_r() {
        let m = Poly1305::new(&[0x3bu8; 32]).unwrap();
        let mut expect = m.r;
        for (i, stored) in m.powers.iter().enumerate() {
            expect = reduce(mul_unreduced(expect, m.r, five_times(m.r)));
            assert_eq!(*stored, expect, "power {} is not r^{}", i, i + 2);
        }
        assert_ne!(m.powers[0], m.powers[1]);
        assert_ne!(m.powers[0], m.r);
    }

    /// Hex with whitespace, as the draft prints it.
    fn spaced_hex(s: &str) -> Vec<u8> {
        let s: std::string::String = s.split_whitespace().collect();
        let mut out = vec![0u8; s.len() / 2];
        ic_core::codec::hex_decode(s.as_bytes(), &mut out).unwrap();
        out
    }

    /// The key and nonce of draft-irtf-cfrg-xchacha-03's appendix A.3: the
    /// bytes 0x80..0x9f and 0x40..0x57, with the keystream vectors' nonce
    /// ending 0x58 instead.
    fn draft_key() -> [u8; 32] {
        core::array::from_fn(|i| 0x80 + i as u8)
    }

    /// draft-irtf-cfrg-xchacha-03 section 2.2.1.
    #[test]
    fn hchacha20_matches_the_draft() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce: [u8; 16] = spaced_hex("000000090000004a0000000031415927")
            .try_into()
            .unwrap();
        let subkey = hchacha20(&key, &nonce);
        assert_eq!(
            subkey.to_vec(),
            spaced_hex("82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")
        );
    }

    /// XChaCha20 as the draft's pseudocode in section 2.3.1 has it, built
    /// from the same subkey and nonce the AEAD uses.
    fn xchacha20_xor(key: &[u8; 32], nonce: &[u8; 24], counter: u32, data: &mut [u8]) {
        let (inner, n) = XChaCha20Poly1305 { key: *key }.inner(nonce).unwrap();
        chacha20_xor(&inner.key, &n, counter, data).unwrap();
    }

    /// draft-irtf-cfrg-xchacha-03 appendix A.3.2, at both block counters.
    #[test]
    fn xchacha20_keystream_matches_the_draft() {
        let nonce: [u8; 24] = core::array::from_fn(|i| 0x40 + i as u8 + u8::from(i == 23));
        let plaintext = spaced_hex(
            "5468652064686f6c65202870726f6e6f756e6365642022646f6c652229206973
             20616c736f206b6e6f776e2061732074686520417369617469632077696c6420
             646f672c2072656420646f672c20616e642077686973746c696e6720646f672e
             2049742069732061626f7574207468652073697a65206f662061204765726d61
             6e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061
             206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c
             757369766520616e6420736b696c6c6564206a756d70657220697320636c6173
             736966696564207769746820776f6c7665732c20636f796f7465732c206a6163
             6b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d6963
             2066616d696c792043616e696461652e",
        );
        let at_zero = spaced_hex(
            "4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e9
             8d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d
             4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0da
             ece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e744
             3056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b74814240
             7c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c
             09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae
             577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486c
             cb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a663
             93b93111c1a55dd7421a10184974c7c5",
        );
        let at_one = spaced_hex(
            "7d0a2e6b7f7c65a236542630294e063b7ab9b555a5d5149aa21e4ae1e4fbce87
             ecc8e08a8b5e350abe622b2ffa617b202cfad72032a3037e76ffdcdc4376ee05
             3a190d7e46ca1de04144850381b9cb29f051915386b8a710b8ac4d027b8b050f
             7cba5854e028d564e453b8a968824173fc16488b8970cac828f11ae53cabd201
             12f87107df24ee6183d2274fe4c8b1485534ef2c5fbc1ec24bfc3663efaa08bc
             047d29d25043532db8391a8a3d776bf4372a6955827ccb0cdd4af403a7ce4c63
             d595c75a43e045f0cce1f29c8b93bd65afc5974922f214a40b7c402cdb91ae73
             c0b63615cdad0480680f16515a7ace9d39236464328a37743ffc28f4ddb324f4
             d0f5bbdc270c65b1749a6efff1fbaa09536175ccd29fb9e6057b307320d31683
             8a9c71f70b5b5907a66f7ea49aadc409",
        );
        for (counter, want) in [(0, at_zero), (1, at_one)] {
            let mut buf = plaintext.clone();
            xchacha20_xor(&draft_key(), &nonce, counter, &mut buf);
            assert_eq!(buf, want, "block counter {counter}");
        }
    }

    /// draft-irtf-cfrg-xchacha-03 appendix A.3.1 gives the one-time Poly1305
    /// key as well as the ciphertext, which separates a wrong subkey or nonce
    /// from a wrong tag.
    #[test]
    fn xchacha20_poly1305_derives_the_drafts_poly1305_key() {
        let nonce: [u8; 24] = core::array::from_fn(|i| 0x40 + i as u8);
        let (inner, n) = XChaCha20Poly1305 { key: draft_key() }
            .inner(&nonce)
            .unwrap();
        assert_eq!(n[..4], [0u8; 4], "the 32-bit fixed-common part");
        assert_eq!(
            inner.poly_key(&n).unwrap().to_vec(),
            spaced_hex("7b191f80f361f099094f6f4b8fb97df847cc6873a8f2b190dd73807183f907d5")
        );
    }

    /// Each half of the nonce matters, and only a 24-byte one is taken.
    ///
    /// The draft's vectors vary every nonce byte at once, so they would also
    /// pass against a construction that ignored some of them only if those
    /// bytes happened not to matter; this changes one byte of each half and
    /// requires the ciphertext to change.
    #[test]
    fn xchacha20_poly1305_uses_the_whole_nonce_and_refuses_other_lengths() {
        let c = XChaCha20Poly1305::new(&draft_key()).unwrap();
        let seal = |nonce: &[u8]| {
            let mut buf = *b"sixteen bytes!!!";
            let mut tag = [0u8; 16];
            c.seal_detached(nonce, b"", &mut buf, &mut tag)
                .map(|()| (buf, tag))
        };
        let base = [7u8; 24];
        let reference = seal(&base).unwrap();
        for at in [0, 15, 16, 23] {
            let mut other = base;
            other[at] ^= 1;
            assert_ne!(seal(&other).unwrap().0, reference.0, "nonce byte {at}");
        }
        for len in [0, 12, 16, 23, 25] {
            let err = seal(&vec![7u8; len]).unwrap_err();
            assert_eq!(
                err.kind(),
                ic_core::ErrorKind::InvalidLength,
                "{len}-byte nonce"
            );
        }
    }

    /// A random nonce is drawn once, used, and returned; and a forged tag
    /// wipes the buffer as the 96-bit AEAD's does.
    #[test]
    fn xchacha20_poly1305_seals_with_a_drawn_nonce_and_refuses_a_forgery() {
        struct Counting(u8, usize);
        impl RandomSource for Counting {
            fn fill(&mut self, out: &mut [u8]) -> Result<()> {
                self.1 += 1;
                for b in out.iter_mut() {
                    self.0 = self.0.wrapping_add(1);
                    *b = self.0;
                }
                Ok(())
            }
        }
        let c = XChaCha20Poly1305::new(&draft_key()).unwrap();
        let mut rng = Counting(0, 0);
        let mut buf = *b"attack at dawn";
        let mut tag = [0u8; 16];
        let nonce = c
            .seal_with_random_nonce(&mut rng, b"hdr", &mut buf, &mut tag)
            .unwrap();
        assert_eq!(rng.1, 1);
        assert_eq!(nonce, core::array::from_fn::<u8, 24, _>(|i| i as u8 + 1));

        let mut short = [0u8; 15];
        assert!(c
            .seal_with_random_nonce(&mut rng, b"hdr", &mut buf, &mut short)
            .is_err());
        assert_eq!(
            rng.1, 1,
            "nothing drawn for a buffer that cannot hold the tag"
        );

        let mut opened = buf;
        c.open_detached(&nonce, b"hdr", &mut opened, &tag).unwrap();
        assert_eq!(&opened, b"attack at dawn");

        let mut forged = tag;
        forged[0] ^= 1;
        let mut attempt = buf;
        let err = c
            .open_detached(&nonce, b"hdr", &mut attempt, &forged)
            .unwrap_err();
        assert_eq!(err.kind(), ic_core::ErrorKind::AuthenticationFailed);
        assert_eq!(attempt, [0u8; 14], "wiped");
    }

    #[test]
    fn self_tests_pass() {
        XChaCha20Poly1305::self_test().unwrap();
        Poly1305::self_test().unwrap();
        ChaCha20Poly1305::self_test().unwrap();
    }
}
