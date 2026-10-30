//! FIPS 180-4 SHA-2 family.
//!
//! Two cores (32-bit and 64-bit) are shared by six published output variants,
//! which differ only in their initial hash value and truncation length.

//! Indexed loops over fixed-size limb and word arrays are used throughout; they
//! mirror the index algebra in the specifications these routines implement, so
//! `needless_range_loop` is allowed rather than obscuring the correspondence.
#![allow(clippy::needless_range_loop)]

use ic_core::traits::internal::Digest;
use ic_core::traits::{Algorithm, SelfTest};
use ic_core::{ensure, Result, Zeroize};

// SHA-NI, where the CPU has it. Only under `std`, because the detection does:
// a `no_std` build has no way to ask, and guessing wrong is an illegal
// instruction rather than a wrong answer. Also compiled, without `std` and
// without the detection, for `ct-probes`, so `scripts/ct-audit` can read the
// HMAC compositions.
#[cfg(all(target_arch = "x86_64", any(feature = "std", feature = "ct-probes")))]
#[cfg_attr(not(feature = "std"), allow(dead_code))]
mod x86;

// SHA-512's schedule, four words at a time. Same reasoning as `x86`: only
// under `std`, because the detection needs it.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
mod avx2_512;

// The guard the SHA-NI short paths hold their padded tails and pads in, so
// that the wipe is their `Drop` and cannot be skipped by a return.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
mod scratch;
#[cfg(all(target_arch = "x86_64", feature = "std"))]
use scratch::Scratch;

// The ARMv8 SHA-256 and SHA-512 instructions, behind the off-by-default
// `aarch64-crypto` feature and runtime detection. See `sha2::aarch64`. Also
// compiled, without `std` and without the detection, for `ct-probes`, so
// `scripts/ct-audit` can read the kernels.
#[cfg(all(
    target_arch = "aarch64",
    feature = "aarch64-crypto",
    any(feature = "std", feature = "ct-probes")
))]
mod aarch64;

/// The ARMv8 SHA-256 and SHA-512 kernels, and on x86-64 HMAC-SHA256's SHA-NI
/// compositions, for `scripts/ct-audit` to inspect after LTO. Not API, not
/// covered by semver; behind the `ct-probes` feature. Never executed by the
/// audit: compiled to be read.
#[cfg(all(
    feature = "ct-probes",
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", feature = "aarch64-crypto")
    )
))]
#[doc(hidden)]
#[allow(missing_docs)]
pub mod ct_probes {
    /// HMAC-SHA256's two key-pad compressions, the outer pad made from the
    /// inner in registers.
    ///
    /// # Safety
    ///
    /// The CPU must have SHA-NI and SSE4.1.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn hmac_sha256_pads(inner: &mut [u32; 8], outer: &mut [u32; 8], ipad: &[u8; 64]) {
        // SAFETY: as the caller guarantees.
        unsafe { super::x86::compress_pads(inner, outer, ipad) }
    }

    /// HMAC-SHA256's end over one whole block of message and one padding
    /// block, then the outer block from the inner digest in registers.
    ///
    /// # Safety
    ///
    /// The CPU must have SHA-NI and SSE4.1.
    #[cfg(target_arch = "x86_64")]
    pub unsafe fn hmac_sha256_tail(
        inner: &[u32; 8],
        block: &[u8; 64],
        tail: &[u8; 64],
        outer: &mut [u32; 8],
    ) {
        // SAFETY: as the caller guarantees; both are one whole block.
        unsafe { super::x86::hmac_tail(inner, block, tail, outer) }
    }

    /// SHA-256 compression over a fixed four blocks.
    ///
    /// # Safety
    ///
    /// The CPU must have the SHA-256 instructions.
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon,sha2")]
    pub unsafe fn sha256_armv8_compress(state: &mut [u32; 8], blocks: &[u8; 256]) {
        // SAFETY: as the caller guarantees.
        unsafe { super::aarch64::compress256(state, blocks) }
    }

    /// SHA-512 compression over a fixed two blocks.
    ///
    /// # Safety
    ///
    /// The CPU must have the SHA-512 instructions.
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "neon,sha3")]
    pub unsafe fn sha512_armv8_compress(state: &mut [u64; 8], blocks: &[u8; 256]) {
        // SAFETY: as the caller guarantees.
        unsafe { super::aarch64::compress512(state, blocks) }
    }
}

// The block structure the ARMv8 backend and its model share, and the model,
// which runs on every host so the structure is checked where the instructions
// cannot run.
#[cfg(test)]
mod armv8_model;
#[cfg(any(
    test,
    all(
        target_arch = "aarch64",
        feature = "aarch64-crypto",
        any(feature = "std", feature = "ct-probes")
    )
))]
mod armv8_rounds;

/// Whether this CPU has AVX2, asked once.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
pub(crate) fn avx2() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering};
    // 0 not yet asked, 1 yes, 2 no.
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

/// Whether this CPU has the instructions [`x86::compress`] needs.
///
/// Asked once. `is_x86_feature_detected!` is not free, and SHA-256 is called
/// often enough on small inputs that paying for the query per block would show
/// up in exactly the workloads this is meant to help.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
fn sha_ni() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering};
    // 0 not yet asked, 1 yes, 2 no.
    static CACHED: AtomicU8 = AtomicU8::new(0);
    match CACHED.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let have = std::is_x86_feature_detected!("sha")
                && std::is_x86_feature_detected!("sse2")
                && std::is_x86_feature_detected!("ssse3")
                && std::is_x86_feature_detected!("sse4.1");
            CACHED.store(u8::from(!have) + 1, Ordering::Relaxed);
            have
        }
    }
}

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const K512: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

/// The shared 32-bit SHA-2 compression core (SHA-224 / SHA-256).
#[derive(Clone)]
struct Core256 {
    h: [u32; 8],
    buf: [u8; 64],
    buffered: usize,
    len: u64,
}

impl Drop for Core256 {
    /// Wipe the chaining state and the buffered block.
    ///
    /// A hash is not a secret, but this state is not only used for hashing:
    /// `Hmac<D>` holds two of these with the key already absorbed into them,
    /// so the ipad and opad states are key-derived material. Putting the wipe
    /// here rather than on `Hmac` means every consumer inherits it through
    /// ordinary field drop, with no `Zeroize` bound threaded through the
    /// `Digest` trait and no chance of a new wrapper forgetting.
    fn drop(&mut self) {
        self.h.zeroize();
        self.buf.zeroize();
        self.buffered = 0;
        self.len = 0;
    }
}

impl Core256 {
    const fn new(iv: [u32; 8]) -> Self {
        Self {
            h: iv,
            buf: [0u8; 64],
            buffered: 0,
            len: 0,
        }
    }

    fn compress(&mut self, block: &[u8]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = self.h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K256[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        let upd = [a, b, c, d, e, f, g, hh];
        for i in 0..8 {
            self.h[i] = self.h[i].wrapping_add(upd[i]);
        }
        w.zeroize();
    }

    /// Compress a whole number of blocks, using the hardware path when there
    /// is one.
    ///
    /// Taking a run rather than a block at a time is the point: the SHA-NI
    /// backend shuffles the state into and out of its register layout once per
    /// call, so feeding it one block at a time would pay that on every block.
    fn compress_blocks(&mut self, data: &[u8]) {
        debug_assert!(data.len().is_multiple_of(64));
        if data.is_empty() {
            return;
        }
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        if sha_ni() {
            // SAFETY: `sha_ni()` is exactly the feature test this requires, and
            // the length is a multiple of the block size by the assertion above.
            unsafe { x86::compress(&mut self.h, data) };
            return;
        }
        #[cfg(all(target_arch = "aarch64", feature = "aarch64-crypto", feature = "std"))]
        if aarch64::sha256_available() {
            // SAFETY: `sha256_available()` is exactly the feature test this
            // requires, and the length is a whole number of blocks.
            unsafe { aarch64::compress256(&mut self.h, data) };
            return;
        }
        for block in data.chunks_exact(64) {
            self.compress(block);
        }
    }

    /// Compress the buffered block in place.
    ///
    /// The buffer is copied out first only on the portable path, whose round
    /// function borrows the whole core; SHA-NI takes the chaining value and
    /// the block as separate fields, so finishing a short message does not
    /// copy its last block twice.
    fn compress_buffer(&mut self) {
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        if sha_ni() {
            // SAFETY: `sha_ni()` is exactly the feature test this requires, and
            // the buffer is one whole block.
            unsafe { x86::compress(&mut self.h, &self.buf) };
            return;
        }
        #[cfg(all(target_arch = "aarch64", feature = "aarch64-crypto", feature = "std"))]
        if aarch64::sha256_available() {
            // SAFETY: as above; the buffer is one whole block.
            unsafe { aarch64::compress256(&mut self.h, &self.buf) };
            return;
        }
        let block = self.buf;
        self.compress(&block);
    }

    fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        if self.buffered > 0 {
            let need = 64 - self.buffered;
            let take = core::cmp::min(need, data.len());
            self.buf[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < 64 {
                // The whole input fit in the partial block; nothing to compress.
                return;
            }
            // Through the dispatcher, not `compress`: that is the portable
            // round function, and calling it here sent every block assembled
            // in the buffer -- the tail of any message not a multiple of 64
            // bytes, and every final padding block -- past SHA-NI. Short
            // messages are mostly such blocks, so a 200-byte hash ran at a
            // third of the bulk rate and HMAC, which finishes two hashes per
            // tag, at about a quarter of what SHA-NI allows.
            self.compress_buffer();
            self.buffered = 0;
        }
        let whole = data.len() - data.len() % 64;
        self.compress_blocks(&data[..whole]);
        let rest = &data[whole..];
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    fn finalize(mut self) -> [u32; 8] {
        let bit_len = self.len.wrapping_mul(8);
        // The padding is written into the block buffer where it goes, rather
        // than assembled in a buffer of its own and fed through `update`: the
        // 0x80, zeros to byte 56, and the length, with one extra block when
        // fewer than nine bytes are left. Short messages -- every HMAC tag
        // finishes two -- spent a fair part of their time in that detour.
        let n = self.buffered;
        self.buf[n] = 0x80;
        self.buf[n + 1..].fill(0);
        if n >= 56 {
            self.compress_buffer();
            self.buf = [0u8; 64];
        }
        self.buf[56..].copy_from_slice(&bit_len.to_be_bytes());
        self.compress_buffer();
        // `self` is dropped on return, and `Drop` wipes `h` and `buf`. They
        // used to be wiped here as well, so every hash wiped its state twice;
        // HMAC finishes two hashes per tag, so that was four wipes of 96 bytes
        // where two do the same job.
        self.h
    }
}

/// The padded final block or two of a SHA-256 message: `rest`, the bytes
/// after its last whole block, then `0x80`, zeros and the length in bits of
/// the whole message, `total` bytes, into the front of `out`. Returns how
/// many bytes that is, 64 or 128.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
#[inline(always)]
fn pad256(rest: &[u8], total: u64, out: &mut [u8; 128]) -> usize {
    debug_assert!(rest.len() < 64);
    out[..rest.len()].copy_from_slice(rest);
    out[rest.len()] = 0x80;
    let end = if rest.len() < 56 { 64 } else { 128 };
    out[end - 8..end].copy_from_slice(&total.wrapping_mul(8).to_be_bytes());
    end
}

/// SHA-224 or SHA-256 of `data` from the starting value in `h`, on SHA-NI:
/// the message's whole blocks straight from `data` and its padded tail from a
/// buffer, in one call that keeps the state in registers across them.
///
/// For a short message that is most of the work saved over `new`, `update`
/// and `finalize`: one load and store of the state in the instructions'
/// layout rather than two, and no block buffer to fill, copy and wipe. The
/// tail buffer, which holds the end of the message, is wiped.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
fn one_shot_sha_ni(h: &mut [u32; 8], data: &[u8]) {
    let whole = data.len() - data.len() % 64;
    let mut tail = Scratch::new([0u8; 128]);
    let end = pad256(&data[whole..], data.len() as u64, &mut tail);
    // SAFETY: the callers checked `sha_ni()`; both lengths are whole blocks.
    unsafe { x86::compress_parts(h, &data[..whole], &tail[..end]) };
}

/// SHA-256's starting value, FIPS 180-4 section 5.3.3.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
const IV256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// HMAC-SHA256 (FIPS 198-1) of `data` under `key`, in one pass on SHA-NI, or
/// `None` where this CPU has no SHA-NI or the key is longer than a block --
/// the caller then takes the generic path, which gives the same tag. Not API:
/// `ic_mac::HmacSha256::mac` calls it.
///
/// Three calls into the SHA-NI code where the generic path makes six: the two
/// key-pad blocks together, as two independent chains the CPU overlaps; and
/// the message's blocks, its padding, and the outer block -- which is the
/// inner digest, so it goes from registers into the outer compression without
/// being stored or swapped to bytes and back.
///
/// The padded key, both chaining values and the message's padded tail are
/// wiped before it returns.
#[doc(hidden)]
pub fn hmac_sha256_one_shot(key: &[u8], data: &[u8]) -> Option<[u8; 32]> {
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    if key.len() <= 64 && sha_ni() {
        let mut ipad = Scratch::new([0x36u8; 64]);
        for (p, k) in ipad.iter_mut().zip(key) {
            *p ^= k;
        }
        let mut inner = Scratch::new(IV256);
        let mut outer = Scratch::new(IV256);
        // SAFETY: `sha_ni()` is the feature test these require.
        unsafe { x86::compress_pads(&mut inner, &mut outer, &ipad) };

        let whole = data.len() - data.len() % 64;
        let mut tail = Scratch::new([0u8; 128]);
        // The inner hash's message is the 64-byte pad, then `data`.
        let end = pad256(&data[whole..], 64 + data.len() as u64, &mut tail);
        // SAFETY: as above; both lengths are whole blocks.
        unsafe { x86::hmac_tail(&inner, &data[..whole], &tail[..end], &mut outer) };

        let mut tag = [0u8; 32];
        for (t, w) in tag.chunks_exact_mut(4).zip(*outer) {
            t.copy_from_slice(&w.to_be_bytes());
        }
        // `ipad`, `tail`, `inner` and `outer` are wiped as they drop here.
        return Some(tag);
    }
    let _ = (key, data);
    None
}

/// HMAC-SHA256's tag from its two keyed states, `inner` having absorbed the
/// message, on SHA-NI; or `None` where the CPU has no SHA-NI or `outer` is
/// not a state that has absorbed exactly one block, the outer pad -- the
/// caller then finishes the generic way, which gives the same tag. Not API:
/// `ic_mac::HmacSha256`'s `finalize` calls it, as HKDF's expansion does once
/// per block of output.
///
/// The inner hash's padding and the outer block are one call, the outer block
/// built from the inner digest in registers ([`hmac_sha256_one_shot`] has the
/// same end). The states themselves are the caller's, and wiped when it drops
/// them; the padded tail and the outer chaining value copied here are wiped
/// before this returns.
#[doc(hidden)]
pub fn hmac_sha256_finish(inner: &Sha256, outer: &Sha256) -> Option<[u8; 32]> {
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    if outer.0.buffered == 0 && outer.0.len == 64 && sha_ni() {
        let core = &inner.0;
        let mut tail = Scratch::new([0u8; 128]);
        let end = pad256(&core.buf[..core.buffered], core.len, &mut tail);
        let mut h = Scratch::new(outer.0.h);
        // SAFETY: `sha_ni()` is the feature test this requires; there are no
        // whole blocks, and the tail is one or two.
        unsafe { x86::hmac_tail(&core.h, &[], &tail[..end], &mut h) };
        let mut tag = [0u8; 32];
        for (t, w) in tag.chunks_exact_mut(4).zip(*h) {
            t.copy_from_slice(&w.to_be_bytes());
        }
        // `tail` and `h` are wiped as they drop here.
        return Some(tag);
    }
    let _ = (inner, outer);
    None
}

/// The shared 64-bit SHA-2 compression core (SHA-384 / SHA-512 / SHA-512-t).
#[derive(Clone)]
struct Core512 {
    h: [u64; 8],
    buf: [u8; 128],
    buffered: usize,
    len: u128,
    /// The message schedule, kept here rather than built on the stack.
    ///
    /// It lives in the struct so that wiping it costs once per hash instead of
    /// once per block. `Zeroize` writes element by element through
    /// `write_volatile`, which is what makes the wipe non-elidable and also
    /// what makes it expensive: eighty volatile stores cannot be merged into a
    /// `memset` or vectorised, and measured in isolation they were 159ns of a
    /// 258ns block -- 62% of SHA-512's compression spent clearing the schedule
    /// rather than computing it. `what_the_schedule_wipe_costs` is that
    /// measurement.
    ///
    /// The schedule is still wiped, on drop, beside `h` and `buf`. What
    /// changes is how often. Wiping after every block bought nothing that
    /// survived the block anyway: the next block immediately overwrites the
    /// whole array, and the material it is derived from is in the caller's
    /// input buffer, which this library neither owns nor clears.
    w: [u64; 80],
}

impl Drop for Core512 {
    /// Wipe the chaining state, the buffered block and the schedule. See
    /// [`Core256`].
    ///
    /// The schedule is wiped here rather than in `finalize`, which consumes
    /// the state and so runs this anyway: a finalized state is wiped once, as
    /// before, and one dropped unfinalized is wiped at all. That case matters
    /// for HMAC, whose keyed states compress the padded key on construction,
    /// leaving its first sixteen words, the key XOR ipad or opad, in `w`.
    fn drop(&mut self) {
        self.h.zeroize();
        self.buf.zeroize();
        self.w.zeroize();
        #[cfg(all(test, feature = "std"))]
        tests::SCHEDULE_AT_DROP.with(|c| c.set(Some(self.w.iter().all(|x| *x == 0))));
        self.buffered = 0;
        self.len = 0;
    }
}

/// SHA-512's compression, and what has already been tried on it.
///
/// It runs about 1.5 times behind RustCrypto's, which has an AVX2 backend for
/// the message schedule. There is no SHA-512 instruction on x86 the way there
/// is for SHA-256, so the portable path below is what runs.
///
/// What closed the gap from 1.76x was not an optimisation of the arithmetic at
/// all: 62% of the compression was the per-block `zeroize` of the schedule,
/// whose volatile writes cannot be merged into a `memset`. The schedule now
/// lives in the struct and is wiped once per hash. See the note on `w`.
///
/// The remaining gap is not scalar slack, and it is worth saying why before
/// anyone looks for some. At 715 MiB/s this compresses a block in about 180ns,
/// which on this machine is roughly 2900 instructions in 600 cycles: close to
/// five per cycle, near what a four-wide core can retire. RustCrypto's 1070
/// MiB/s would need better than seven per cycle for the same instruction count,
/// which is not possible -- so they are executing fewer instructions, not
/// scheduling the same ones better. `sha2 0.10.9` has an AVX2 SHA-512 backend
/// in `sha512/x86.rs`, selected by runtime detection; that is the difference.
/// Matching it means writing one, not tuning this.
///
/// Two source-level optimisations were measured and reverted, and are recorded
/// so they are not tried a third time:
///
/// - **A rolling sixteen-word schedule window** instead of the eighty-word
///   array. The array is 640 bytes cleared per 128-byte block, five bytes wiped
///   per byte hashed, which looks like the cost. A controlled A/B showed it
///   *slower*: 640 bytes sits in L1, and the modulo indexing defeats whatever
///   unrolling the flat array was getting.
/// - **Unrolling the round loop by eight**, naming the working variables in
///   rotation so the eight moves per round disappear. No measurable change in
///   either direction; LLVM already renames and unrolls this shape.
///
/// Both failed the same way: the waste was visible in the source and absent
/// from the object code. What did pay elsewhere in this workspace was work the
/// compiler cannot do -- breaking a serial dependency chain, selecting a
/// hardware instruction, changing the algorithm. The remaining gap here is the
/// vectorised schedule, and even that addresses only the third or so of the
/// work the schedule represents, since the rounds are inherently serial.
impl Core512 {
    const fn new(iv: [u64; 8]) -> Self {
        Self {
            h: iv,
            buf: [0u8; 128],
            buffered: 0,
            len: 0,
            w: [0u64; 80],
        }
    }

    fn compress(&mut self, block: &[u8]) {
        // The ARMv8 instructions do the whole compression, schedule and rounds
        // alike, so that backend shares nothing below.
        #[cfg(all(target_arch = "aarch64", feature = "aarch64-crypto", feature = "std"))]
        if aarch64::sha512_available() {
            // SAFETY: `sha512_available()` is the feature test this requires,
            // and `block` is one block by `update`'s chunking.
            unsafe { aarch64::compress512(&mut self.h, block) };
            return;
        }
        // The schedule is about a third of the work and is the only part with
        // anything to run in parallel; the rounds are a chain. So the backends
        // differ in how `w` is filled and share everything after it.
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        if avx2() {
            // SAFETY: `avx2()` is the feature test this requires, and `block`
            // is one block by `update`'s chunking.
            unsafe { avx2_512::compress(&mut self.h, &mut self.w, block) };
            return;
        }
        Self::schedule(&mut self.w, block);
        Self::rounds(&mut self.h, &self.w);
    }

    /// Compress a whole number of blocks.
    ///
    /// A run rather than a block at a time so the ARMv8 backend moves the
    /// state into its registers once per call, not once per block.
    fn compress_blocks(&mut self, data: &[u8]) {
        debug_assert!(data.len().is_multiple_of(128));
        #[cfg(all(target_arch = "aarch64", feature = "aarch64-crypto", feature = "std"))]
        if aarch64::sha512_available() {
            // SAFETY: `sha512_available()` is the feature test this requires,
            // and the length is a whole number of blocks.
            unsafe { aarch64::compress512(&mut self.h, data) };
            return;
        }
        for block in data.chunks_exact(128) {
            self.compress(block);
        }
    }

    /// Build the message schedule.
    ///
    /// The AVX2 backend does not call this -- it interleaves the same steps
    /// into its round loop, which is the whole reason it is faster -- but it is
    /// checked against that backend word for word.
    fn schedule(w: &mut [u64; 80], block: &[u8]) {
        for i in 0..16 {
            let mut b = [0u8; 8];
            b.copy_from_slice(&block[i * 8..i * 8 + 8]);
            w[i] = u64::from_be_bytes(b);
        }
        for i in 16..80 {
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
    }

    /// The eighty rounds.
    fn rounds(h: &mut [u64; 8], w: &[u64; 80]) {
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
        for i in 0..80 {
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K512[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        let upd = [a, b, c, d, e, f, g, hh];
        for i in 0..8 {
            h[i] = h[i].wrapping_add(upd[i]);
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u128);
        if self.buffered > 0 {
            let need = 128 - self.buffered;
            let take = core::cmp::min(need, data.len());
            self.buf[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < 128 {
                // The whole input fit in the partial block; nothing to compress.
                return;
            }
            let block = self.buf;
            self.compress(&block);
            self.buffered = 0;
        }
        let whole = data.len() - data.len() % 128;
        self.compress_blocks(&data[..whole]);
        let rest = &data[whole..];
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    fn finalize(mut self) -> [u64; 8] {
        let bit_len = self.len.wrapping_mul(8);
        let mut pad = [0u8; 145];
        pad[0] = 0x80;
        let zeros = (111 + 128 - (self.buffered % 128)) % 128;
        pad[1 + zeros..1 + zeros + 16].copy_from_slice(&bit_len.to_be_bytes());
        let saved = self.len;
        self.update(&pad[..1 + zeros + 16]);
        self.len = saved;
        let out = self.h;
        self.buf.zeroize();
        self.h.zeroize();
        out
    }
}

macro_rules! sha2_32 {
    ($name:ident, $id:literal, $disp:literal, $out:literal, $iv:expr, $kat:literal) => {
        #[doc = concat!("FIPS 180-4 ", $disp, ".")]
        #[derive(Clone)]
        pub struct $name(Core256);

        impl Default for $name {
            fn default() -> Self {
                Self(Core256::new($iv))
            }
        }

        impl Algorithm for $name {
            const ID: &'static str = $id;
            const NAME: &'static str = $disp;
        }

        impl Digest for $name {
            type Output = [u8; $out];
            const OUTPUT_LEN: usize = $out;
            const BLOCK_LEN: usize = 64;

            fn update(&mut self, data: &[u8]) {
                self.0.update(data);
            }

            fn finalize(self) -> Self::Output {
                let h = self.0.finalize();
                let mut full = [0u8; 32];
                for i in 0..8 {
                    full[i * 4..i * 4 + 4].copy_from_slice(&h[i].to_be_bytes());
                }
                let mut out = [0u8; $out];
                out.copy_from_slice(&full[..$out]);
                out
            }

            fn digest(data: &[u8]) -> Self::Output {
                #[cfg(all(target_arch = "x86_64", feature = "std"))]
                if sha_ni() {
                    let mut h = $iv;
                    one_shot_sha_ni(&mut h, data);
                    let mut out = [0u8; $out];
                    for (o, w) in out.chunks_mut(4).zip(h) {
                        o.copy_from_slice(&w.to_be_bytes()[..o.len()]);
                    }
                    h.zeroize();
                    return out;
                }
                let mut h = Self::default();
                h.update(data);
                h.finalize()
            }
        }

        impl SelfTest for $name {
            fn self_test() -> Result<()> {
                let got = <Self as Digest>::digest(b"abc");
                let mut want = [0u8; $out];
                ic_core::codec::hex_decode($kat.as_bytes(), &mut want)?;
                ensure!(
                    ic_core::ct::verify(&want, got.as_ref()),
                    SelfTestFailed,
                    $id
                );
                Ok(())
            }
        }
    };
}

macro_rules! sha2_64 {
    ($name:ident, $id:literal, $disp:literal, $out:literal, $iv:expr, $kat:literal) => {
        #[doc = concat!("FIPS 180-4 ", $disp, ".")]
        #[derive(Clone)]
        pub struct $name(Core512);

        impl Default for $name {
            fn default() -> Self {
                Self(Core512::new($iv))
            }
        }

        impl Algorithm for $name {
            const ID: &'static str = $id;
            const NAME: &'static str = $disp;
        }

        impl Digest for $name {
            type Output = [u8; $out];
            const OUTPUT_LEN: usize = $out;
            const BLOCK_LEN: usize = 128;

            fn update(&mut self, data: &[u8]) {
                self.0.update(data);
            }

            fn finalize(self) -> Self::Output {
                let h = self.0.finalize();
                let mut full = [0u8; 64];
                for i in 0..8 {
                    full[i * 8..i * 8 + 8].copy_from_slice(&h[i].to_be_bytes());
                }
                let mut out = [0u8; $out];
                out.copy_from_slice(&full[..$out]);
                out
            }
        }

        impl SelfTest for $name {
            fn self_test() -> Result<()> {
                let got = <Self as Digest>::digest(b"abc");
                let mut want = [0u8; $out];
                ic_core::codec::hex_decode($kat.as_bytes(), &mut want)?;
                ensure!(
                    ic_core::ct::verify(&want, got.as_ref()),
                    SelfTestFailed,
                    $id
                );
                Ok(())
            }
        }
    };
}

sha2_32!(
    Sha224,
    "sha2-224",
    "SHA-224",
    28,
    [
        0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7,
        0xbefa4fa4
    ],
    "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
);

sha2_32!(
    Sha256,
    "sha2-256",
    "SHA-256",
    32,
    [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19
    ],
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
);

sha2_64!(
    Sha384,
    "sha2-384",
    "SHA-384",
    48,
    [
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
        0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
    ],
    "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
);

sha2_64!(
    Sha512,
    "sha2-512",
    "SHA-512",
    64,
    [
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
    ],
    "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
);

sha2_64!(
    Sha512_224,
    "sha2-512-224",
    "SHA-512/224",
    28,
    [
        0x8c3d37c819544da2,
        0x73e1996689dcd4d6,
        0x1dfab7ae32ff9c82,
        0x679dd514582f9fcf,
        0x0f6d2b697bd44da8,
        0x77e36f7304c48942,
        0x3f9d85a86a1d36c8,
        0x1112e6ad91d692a1
    ],
    "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
);

sha2_64!(
    Sha512_256,
    "sha2-512-256",
    "SHA-512/256",
    32,
    [
        0x22312194fc2bf72c,
        0x9f555fa3c84c64c2,
        0x2393b86b6f53b151,
        0x963877195940eabd,
        0x96283ee2a88effe3,
        0xbe5e1e2553863992,
        0x2b0199fc2c85b8aa,
        0x0eb72ddc81c52ca2
    ],
    "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "std")]
    std::thread_local! {
        /// Whether the last `Core512` dropped on this thread left its schedule
        /// all zero, as its `Drop` saw it after wiping.
        pub(super) static SCHEDULE_AT_DROP: core::cell::Cell<Option<bool>> =
            const { core::cell::Cell::new(None) };
    }

    /// A SHA-512 state dropped unfinalized wipes its schedule. HMAC's keyed
    /// states are that case: they compress the padded key on construction
    /// and may never finalize, and the schedule's first sixteen words are
    /// then the key XOR the pad. Checked: with the wipe removed from `Drop`,
    /// this fails.
    #[cfg(feature = "std")]
    #[test]
    fn an_unfinalized_sha512_state_wipes_its_schedule_on_drop() {
        let mut core = Core512::new([1, 2, 3, 4, 5, 6, 7, 8]);
        core.update(&[0x5cu8; 128]);
        if core.w.iter().all(|x| *x == 0) {
            println!("this backend does not use the schedule array; nothing to wipe");
            return;
        }
        SCHEDULE_AT_DROP.with(|c| c.set(None));
        drop(core);
        assert_eq!(SCHEDULE_AT_DROP.with(|c| c.get()), Some(true));
    }

    /// Bytes that vary in every position: a counter through a multiply and a
    /// rotate, seeded so two calls need not agree.
    fn pattern(len: usize, seed: u64) -> std::vec::Vec<u8> {
        (0..len)
            .map(|i| {
                ((i as u64 ^ seed)
                    .wrapping_mul(0x9e37_79b9_7f4a_7c15)
                    .rotate_left(23)
                    >> 7) as u8
            })
            .collect()
    }

    /// Block counts a SHA-256 kernel is held to: every count up to ten, and
    /// two large runs, from several starting states.
    const KERNEL_BLOCKS: [usize; 13] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 257, 1024];

    /// Hold a SHA-256 block kernel to the portable compression.
    ///
    /// Shared by the ARMv8 model, which runs everywhere, and the ARMv8 backend,
    /// which runs where the instructions exist. Starting states other than the
    /// IV, because an error in how the state is loaded into or stored out of
    /// vector lanes can be symmetric enough to survive the IV.
    pub(super) fn check_sha256_kernel(kernel: impl Fn(&mut [u32; 8], &[u8])) {
        let mut checked = 0;
        for (seed, blocks) in KERNEL_BLOCKS.iter().enumerate() {
            let data = pattern(blocks * 64, seed as u64);
            let start: [u32; 8] = core::array::from_fn(|i| {
                (seed as u32 + 1).wrapping_mul(0x0101_0101) ^ (K256[i] << (i % 5))
            });
            let mut want = Core256::new(start);
            for block in data.chunks_exact(64) {
                want.compress(block);
            }
            let mut got = start;
            kernel(&mut got, &data);
            assert_eq!(got, want.h, "{blocks} blocks");
            checked += 1;
        }
        assert_eq!(checked, KERNEL_BLOCKS.len());
    }

    /// Hold a SHA-512 block kernel to the portable compression, as above.
    pub(super) fn check_sha512_kernel(kernel: impl Fn(&mut [u64; 8], &[u8])) {
        let mut checked = 0;
        for (seed, blocks) in KERNEL_BLOCKS.iter().enumerate() {
            let data = pattern(blocks * 128, seed as u64 + 100);
            let start: [u64; 8] = core::array::from_fn(|i| {
                (seed as u64 + 1).wrapping_mul(0x0101_0101_0101_0101) ^ K512[i + 8]
            });
            // `schedule` and `rounds` directly: the portable path on every
            // target, whatever `compress` dispatches to.
            let mut want = start;
            let mut w = [0u64; 80];
            for block in data.chunks_exact(128) {
                Core512::schedule(&mut w, block);
                Core512::rounds(&mut want, &w);
            }
            let mut got = start;
            kernel(&mut got, &data);
            assert_eq!(got, want, "{blocks} blocks");
            checked += 1;
        }
        assert_eq!(checked, KERNEL_BLOCKS.len());
    }

    /// SHA-256 of `msg` by the portable compression alone: FIPS 180-4 section
    /// 5.1.1 padding built separately, then block by block.
    fn portable_sha256(msg: &[u8]) -> [u8; 32] {
        const IV: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        let mut padded = msg.to_vec();
        padded.push(0x80);
        while padded.len() % 64 != 56 {
            padded.push(0);
        }
        padded.extend_from_slice(&((msg.len() as u64) * 8).to_be_bytes());
        let mut core = Core256::new(IV);
        for block in padded.chunks_exact(64) {
            core.compress(block);
        }
        let mut out = [0u8; 32];
        for (i, w) in core.h.iter().enumerate() {
            out[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    /// SHA-512 of `msg` by the portable compression alone, section 5.1.2.
    fn portable_sha512(msg: &[u8]) -> [u8; 64] {
        const IV: [u64; 8] = [
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ];
        let mut padded = msg.to_vec();
        padded.push(0x80);
        while padded.len() % 128 != 112 {
            padded.push(0);
        }
        padded.extend_from_slice(&((msg.len() as u128) * 8).to_be_bytes());
        let mut h = IV;
        let mut w = [0u64; 80];
        for block in padded.chunks_exact(128) {
            Core512::schedule(&mut w, block);
            Core512::rounds(&mut h, &w);
        }
        let mut out = [0u8; 64];
        for (i, v) in h.iter().enumerate() {
            out[8 * i..8 * i + 8].copy_from_slice(&v.to_be_bytes());
        }
        out
    }

    /// Whatever backend this build dispatches to, against the portable
    /// compression, at every message length from 0 to 600 bytes and at two
    /// large ones, whole and in two pieces.
    ///
    /// Through `Sha256` and `Sha512` themselves, so the buffered block, the
    /// padding block and the bulk run all reach the backend: an error confined
    /// to one of those entry points shows up at some length here.
    #[test]
    fn the_active_backend_matches_the_portable_compression_at_every_length() {
        let mut lengths: std::vec::Vec<usize> = (0..=600).collect();
        lengths.extend([64 * 1024 + 7, 1 << 20]);
        for &len in &lengths {
            let msg = pattern(len, len as u64);
            let want256 = portable_sha256(&msg);
            let want512 = portable_sha512(&msg);
            assert_eq!(Sha256::digest(&msg), want256, "sha-256, {len} bytes");
            assert_eq!(Sha512::digest(&msg), want512, "sha-512, {len} bytes");

            let (a, b) = msg.split_at(len / 3);
            let mut h = Sha256::new();
            h.update(a);
            h.update(b);
            assert_eq!(h.finalize(), want256, "sha-256, {len} bytes in two pieces");
            let mut h = Sha512::new();
            h.update(a);
            h.update(b);
            assert_eq!(h.finalize(), want512, "sha-512, {len} bytes in two pieces");
        }
    }

    /// The one-shot `digest`, which on SHA-NI pads into a buffer of its own
    /// and compresses in one call, against `new`, `update` and `finalize` on
    /// the portable round function, for SHA-224 and SHA-256, at every length
    /// to 600 bytes from an unaligned start.
    #[test]
    fn the_one_shot_digest_matches_the_portable_streaming_one() {
        fn portable<const N: usize>(iv: [u32; 8], msg: &[u8]) -> [u8; N] {
            let mut padded = msg.to_vec();
            padded.push(0x80);
            while padded.len() % 64 != 56 {
                padded.push(0);
            }
            padded.extend_from_slice(&((msg.len() as u64) * 8).to_be_bytes());
            let mut core = Core256::new(iv);
            for block in padded.chunks_exact(64) {
                core.compress(block);
            }
            let mut out = [0u8; N];
            for (o, w) in out.chunks_mut(4).zip(core.h) {
                o.copy_from_slice(&w.to_be_bytes()[..o.len()]);
            }
            out
        }
        let source = pattern(603, 9);
        for len in 0..=600usize {
            let msg = &source[3..3 + len];
            assert_eq!(
                Sha256::digest(msg),
                portable::<32>(Sha256::default().0.h, msg),
                "sha-256, {len} bytes"
            );
            assert_eq!(
                Sha224::digest(msg),
                portable::<28>(Sha224::default().0.h, msg),
                "sha-224, {len} bytes"
            );
        }
    }

    /// HMAC-SHA256's one-pass SHA-NI path against HMAC built by hand from the
    /// portable round function, FIPS 198-1 section 4, at every message length
    /// to 600 bytes and every key length to the block's 64, from unaligned
    /// starts; and `None`, for the generic path, for a longer key. The RFC
    /// 4231 vectors reach it through `ic_mac` and pin it to published values;
    /// this pins it everywhere between them, the length of the padding block
    /// above all, and the outer block that never exists in memory.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[test]
    fn the_one_pass_hmac_matches_hmac_by_hand() {
        if !sha_ni() {
            println!("no SHA-NI on this CPU; the one-pass HMAC was not exercised");
            return;
        }
        fn hash(msg: &[u8]) -> [u8; 32] {
            let mut padded = msg.to_vec();
            padded.push(0x80);
            while padded.len() % 64 != 56 {
                padded.push(0);
            }
            padded.extend_from_slice(&((msg.len() as u64) * 8).to_be_bytes());
            let mut core = Core256::new(IV256);
            for block in padded.chunks_exact(64) {
                core.compress(block);
            }
            let mut out = [0u8; 32];
            for (o, w) in out.chunks_mut(4).zip(core.h) {
                o.copy_from_slice(&w.to_be_bytes());
            }
            out
        }
        fn by_hand(key: &[u8], msg: &[u8]) -> [u8; 32] {
            let mut k = key.to_vec();
            k.resize(64, 0);
            let mut inner: std::vec::Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
            inner.extend_from_slice(msg);
            let mut outer: std::vec::Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
            outer.extend_from_slice(&hash(&inner));
            hash(&outer)
        }
        let source = pattern(700, 3);
        let mut checked = 0;
        for key_len in 0..=64usize {
            let key = &source[1..1 + key_len];
            let lengths: std::vec::Vec<usize> = if key_len % 8 == 0 || key_len > 60 {
                (0..=600).collect()
            } else {
                (0..=600).step_by(7).chain(50..=70).collect()
            };
            for len in lengths {
                let msg = &source[5..5 + len];
                let want = by_hand(key, msg);
                assert_eq!(
                    hmac_sha256_one_shot(key, msg),
                    Some(want),
                    "one pass, key {key_len}, message {len}"
                );

                // The finish from keyed states, the message absorbed in two
                // pieces so the inner state's buffer is reached both ways.
                let mut k = key.to_vec();
                k.resize(64, 0);
                let ipad: std::vec::Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
                let opad: std::vec::Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
                let mut inner = Sha256::default();
                inner.update(&ipad);
                let (a, b) = msg.split_at(len / 3);
                inner.update(a);
                inner.update(b);
                let mut outer = Sha256::default();
                outer.update(&opad);
                assert_eq!(
                    hmac_sha256_finish(&inner, &outer),
                    Some(want),
                    "finish, key {key_len}, message {len}"
                );
                checked += 1;
            }
        }
        assert!(checked > 10_000, "the comparison did not run");
        assert_eq!(hmac_sha256_one_shot(&source[..65], b"m"), None);
        // An outer state that is not one block of pad is refused.
        let mut outer = Sha256::default();
        outer.update(&source[..65]);
        assert_eq!(hmac_sha256_finish(&Sha256::default(), &outer), None);
        let mut outer = Sha256::default();
        outer.update(&source[..128]);
        assert_eq!(hmac_sha256_finish(&Sha256::default(), &outer), None);
    }

    /// The SHA-NI short paths wipe their padded tails and pads when they
    /// return. Each guard is observed at its drop: if the wipe is removed from
    /// `Scratch`'s `Drop`, the padding's `0x80` or the key pad is still in the
    /// array and `dirty` is non-zero, so this fails. Checked: with the wipe
    /// deleted, the one-shot digest's assertion fails with `(1, 1)`.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[test]
    fn the_sha_ni_short_paths_wipe_their_scratch() {
        use scratch::probe;
        if !sha_ni() {
            println!("no SHA-NI; the short paths were not exercised");
            return;
        }
        let msg = pattern(100, 9);

        probe::reset();
        let mut h = IV256;
        one_shot_sha_ni(&mut h, &msg);
        assert_eq!(probe::snapshot(), (1, 0), "one-shot digest: padded tail");

        probe::reset();
        assert!(hmac_sha256_one_shot(b"key", &msg).is_some());
        // ipad, the padded tail, the inner state and the outer state.
        assert_eq!(probe::snapshot(), (4, 0), "one-pass HMAC");

        probe::reset();
        let mut inner = Sha256::default();
        inner.update(&msg[..70]);
        let mut outer = Sha256::default();
        outer.update(&[0x5c; 64]);
        assert!(hmac_sha256_finish(&inner, &outer).is_some());
        // The padded tail and a copy of the outer state.
        assert_eq!(probe::snapshot(), (2, 0), "HMAC finish");
    }

    /// The ARMv8 SHA-256 backend against the portable compression.
    ///
    /// Reports a skip rather than failing where the CPU lacks the
    /// instructions, as the AES backend's tests do.
    #[cfg(all(target_arch = "aarch64", feature = "aarch64-crypto", feature = "std"))]
    #[test]
    fn the_armv8_sha256_backend_agrees_with_the_portable_one() {
        if !aarch64::sha256_available() {
            println!("no ARMv8 SHA-256 instructions; the backend was not exercised");
            return;
        }
        // SAFETY: guarded by the detection above, and every input the check
        // passes is a whole number of blocks.
        check_sha256_kernel(|h, d| unsafe { aarch64::compress256(h, d) });
    }

    /// The ARMv8 SHA-512 backend against the portable compression.
    #[cfg(all(target_arch = "aarch64", feature = "aarch64-crypto", feature = "std"))]
    #[test]
    fn the_armv8_sha512_backend_agrees_with_the_portable_one() {
        if !aarch64::sha512_available() {
            println!("no ARMv8 SHA-512 instructions; the backend was not exercised");
            return;
        }
        // SAFETY: guarded by the detection above, and every input the check
        // passes is a whole number of blocks.
        check_sha512_kernel(|h, d| unsafe { aarch64::compress512(h, d) });
    }

    /// The hardware path must agree with the portable one, block for block.
    ///
    /// The published vectors above do not establish this. They pass whichever
    /// path runs, so on a machine with SHA-NI they check the backend and on one
    /// without they check the fallback -- and either way they cannot notice
    /// that the two disagree, which is the failure a second implementation
    /// introduces. This runs both over the same input and compares the states.
    ///
    /// It reports which path it took rather than asserting one, because a CPU
    /// without the instructions is a legitimate machine to run the suite on.
    /// What it does assert is that the comparison happened when it could.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[test]
    fn the_sha_ni_backend_agrees_with_the_portable_one() {
        if !sha_ni() {
            println!("no SHA-NI on this CPU; the backend was not exercised");
            return;
        }

        // Lengths either side of the block boundary, and long enough to run the
        // message schedule over several blocks.
        let mut checked = 0;
        for blocks in [1usize, 2, 3, 4, 7, 16] {
            let mut data = vec![0u8; blocks * 64];
            // Not random, but not uniform either: a counter through a couple of
            // multiplications, so every byte position varies between cases.
            for (i, b) in data.iter_mut().enumerate() {
                *b = ((i as u64).wrapping_mul(0x9e37_79b9).rotate_left(7) & 0xff) as u8;
            }

            // FIPS 180-4 section 5.3.3, the same value the macro below passes.
            const IV: [u32; 8] = [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ];
            let mut portable = Core256::new(IV);
            for block in data.chunks_exact(64) {
                portable.compress(block);
            }

            let mut hardware = Core256::new(IV);
            // SAFETY: guarded by the `sha_ni()` check above.
            unsafe { x86::compress(&mut hardware.h, &data) };

            assert_eq!(
                portable.h, hardware.h,
                "SHA-NI and portable disagree after {blocks} blocks"
            );
            checked += 1;
        }
        assert_eq!(checked, 6, "the comparison did not run");
    }

    /// `finalize` writes the padding into the block buffer itself, branching
    /// on whether the length still fits. Against the padding of FIPS 180-4
    /// section 5.1.1 built separately -- the message, 0x80, zeros to 56 mod
    /// 64, the 64-bit bit length -- and compressed block by block with the
    /// portable round function, at every length either side of one and two
    /// blocks, and fed whole and in two pieces so the bytes reach the buffer
    /// both ways.
    #[test]
    fn padding_matches_fips_180_4_at_every_short_length() {
        const IV: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        for len in 0..=200usize {
            let msg: std::vec::Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let mut padded = msg.clone();
            padded.push(0x80);
            while padded.len() % 64 != 56 {
                padded.push(0);
            }
            padded.extend_from_slice(&((len as u64) * 8).to_be_bytes());
            let mut reference = Core256::new(IV);
            for block in padded.chunks_exact(64) {
                reference.compress(block);
            }
            let mut want = [0u8; 32];
            for (i, w) in reference.h.iter().enumerate() {
                want[4 * i..4 * i + 4].copy_from_slice(&w.to_be_bytes());
            }

            assert_eq!(Sha256::digest(&msg), want, "{len} bytes");
            let mut h = Sha256::new();
            let (a, b) = msg.split_at(len / 3);
            h.update(a);
            h.update(b);
            assert_eq!(h.finalize(), want, "{len} bytes in two pieces");
        }
    }

    /// Say which path this build will take, so a benchmark or a vector run is
    /// not silently measuring the fallback.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[test]
    fn the_active_sha256_path_is_reported() {
        println!(
            "sha-256 backend: {}",
            if sha_ni() { "SHA-NI" } else { "portable" }
        );
    }

    /// The same report on aarch64, where the backend is feature-gated.
    #[cfg(all(target_arch = "aarch64", feature = "aarch64-crypto", feature = "std"))]
    #[test]
    fn the_active_armv8_paths_are_reported() {
        println!(
            "sha-256 backend: {}; sha-512 backend: {}",
            if aarch64::sha256_available() {
                "ARMv8 SHA2"
            } else {
                "portable"
            },
            if aarch64::sha512_available() {
                "ARMv8 SHA512"
            } else {
                "portable"
            },
        );
    }

    #[test]
    fn nist_abc_vectors() {
        assert_eq!(
            ic_core::codec::hex(Sha256::digest(b"abc").as_ref()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            ic_core::codec::hex(Sha224::digest(b"abc").as_ref()),
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        );
        assert_eq!(
            ic_core::codec::hex(Sha512::digest(b"abc").as_ref()),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
        assert_eq!(
            ic_core::codec::hex(Sha384::digest(b"abc").as_ref()),
            "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        );
    }

    #[test]
    fn empty_input_vectors() {
        assert_eq!(
            ic_core::codec::hex(Sha256::digest(b"").as_ref()),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            ic_core::codec::hex(Sha512::digest(b"").as_ref()),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    /// The 448-bit boundary case: input length forces an extra padding block.
    #[test]
    fn two_block_vector() {
        let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        assert_eq!(
            ic_core::codec::hex(Sha256::digest(msg).as_ref()),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
    }

    #[test]
    fn million_a_vector() {
        let mut h = Sha256::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            h.update(&chunk);
        }
        assert_eq!(
            ic_core::codec::hex(h.finalize().as_ref()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data: [u8; 300] = core::array::from_fn(|i| i as u8);
        for split in [0usize, 1, 63, 64, 65, 127, 128, 200, 300] {
            let mut h = Sha512::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize(), Sha512::digest(&data), "split at {split}");
        }
    }

    #[test]
    fn truncated_variants() {
        assert_eq!(
            ic_core::codec::hex(Sha512_224::digest(b"abc").as_ref()),
            "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
        );
        assert_eq!(
            ic_core::codec::hex(Sha512_256::digest(b"abc").as_ref()),
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23"
        );
    }

    #[test]
    fn all_self_tests_pass() {
        Sha224::self_test().unwrap();
        Sha256::self_test().unwrap();
        Sha384::self_test().unwrap();
        Sha512::self_test().unwrap();
        Sha512_224::self_test().unwrap();
        Sha512_256::self_test().unwrap();
    }

    /// The ARMv8 probe wrappers, executed on fixed inputs against the portable
    /// compression (`ct_probes`, which the audit only reads). Needs the SHA
    /// instructions, so it runs under QEMU via `scripts/test-aarch64.sh`; it
    /// asserts the detection rather than skipping, since a probe that never ran
    /// is not a pass.
    #[cfg(all(
        test,
        target_arch = "aarch64",
        feature = "aarch64-crypto",
        feature = "ct-probes"
    ))]
    mod armv8_probe_tests {
        use super::*;

        #[test]
        fn sha256_probe_matches_the_portable_compression() {
            assert!(
                aarch64::sha256_available(),
                "no ARMv8 SHA-256 instructions: the probe was not run"
            );
            let data: [u8; 256] =
                core::array::from_fn(|i| (i as u8).wrapping_mul(29).wrapping_add(3));
            let start: [u32; 8] =
                core::array::from_fn(|i| 0x6a09_e667u32.wrapping_mul(i as u32 + 1));
            let mut want = Core256::new(start);
            for block in data.chunks_exact(64) {
                want.compress(block);
            }
            let mut got = start;
            // SAFETY: guarded by the detection above.
            unsafe { ct_probes::sha256_armv8_compress(&mut got, &data) };
            assert_eq!(got, want.h, "sha256_armv8_compress");
        }

        #[test]
        fn sha512_probe_matches_the_portable_compression() {
            assert!(
                aarch64::sha512_available(),
                "no ARMv8 SHA-512 instructions: the probe was not run"
            );
            let data: [u8; 256] =
                core::array::from_fn(|i| (i as u8).wrapping_mul(29).wrapping_add(9));
            let start: [u64; 8] =
                core::array::from_fn(|i| 0x6a09_e667_f3bc_c908u64.wrapping_mul(i as u64 + 1));
            let mut want = start;
            let mut w = [0u64; 80];
            for block in data.chunks_exact(128) {
                Core512::schedule(&mut w, block);
                Core512::rounds(&mut want, &w);
            }
            let mut got = start;
            // SAFETY: guarded by the detection above.
            unsafe { ct_probes::sha512_armv8_compress(&mut got, &data) };
            assert_eq!(got, want, "sha512_armv8_compress");
        }
    }

    /// What the schedule wipe costs SHA-512, measured in one process.
    ///
    /// Ignored: a measurement. Run it with
    /// `cargo test -p ic-hash --release -- --ignored --nocapture what_the_schedule_wipe_costs`.
    ///
    /// Both variants are timed in the same binary, alternating, because this
    /// machine has other work on it: an attempt to compare across two benchmark
    /// runs had RustCrypto's own SHA-512 moving 700 -> 1087 MiB/s between them,
    /// untouched, which is larger than the effect being looked for.
    #[test]
    #[ignore = "diagnostic, not a test"]
    fn what_the_schedule_wipe_costs() {
        use std::time::Instant;

        // A copy of Core512::compress with the wipe left out, and nothing else
        // changed. Only for this measurement.
        fn compress_unwiped(h: &mut [u64; 8], block: &[u8]) {
            let mut w = [0u64; 80];
            for i in 0..16 {
                let mut b = [0u8; 8];
                b.copy_from_slice(&block[i * 8..i * 8 + 8]);
                w[i] = u64::from_be_bytes(b);
            }
            for i in 16..80 {
                let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
                let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
            for i in 0..80 {
                let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
                let ch = (e & f) ^ ((!e) & g);
                let t1 = hh
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K512[i])
                    .wrapping_add(w[i]);
                let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
                let maj = (a & b) ^ (a & c) ^ (b & c);
                let t2 = s0.wrapping_add(maj);
                hh = g;
                g = f;
                f = e;
                e = d.wrapping_add(t1);
                d = c;
                c = b;
                b = a;
                a = t1.wrapping_add(t2);
            }
            let upd = [a, b, c, d, e, f, g, hh];
            for i in 0..8 {
                h[i] = h[i].wrapping_add(upd[i]);
            }
        }

        let block: Vec<u8> = (0..128u32).map(|i| (i * 7 + 1) as u8).collect();
        let n = 50_000;
        let (mut best_wiped, mut best_plain) = (f64::INFINITY, f64::INFINITY);

        for _ in 0..30 {
            let mut core = Core512::new([1, 2, 3, 4, 5, 6, 7, 8]);
            let t = Instant::now();
            for _ in 0..n {
                core.compress(core::hint::black_box(&block));
            }
            best_wiped = best_wiped.min(t.elapsed().as_secs_f64() / n as f64 * 1e9);

            let mut h = [1u64, 2, 3, 4, 5, 6, 7, 8];
            let t = Instant::now();
            for _ in 0..n {
                compress_unwiped(&mut h, core::hint::black_box(&block));
            }
            best_plain = best_plain.min(t.elapsed().as_secs_f64() / n as f64 * 1e9);
        }
        println!(
            "
  sha-512 compress, with w.zeroize()   {best_wiped:>8.1} ns/block"
        );
        println!("  sha-512 compress, without            {best_plain:>8.1} ns/block");
        println!(
            "  the wipe costs                       {:>8.1} ns/block ({:.0}%)",
            best_wiped - best_plain,
            (best_wiped - best_plain) / best_wiped * 100.0
        );
    }
}
