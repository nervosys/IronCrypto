//! NIST SP 800-38D Galois/Counter Mode.
//!
//! GHASH is implemented with a branch-free bit-by-bit multiplication in
//! GF(2^128). Table-driven GHASH is faster but indexes memory with key-derived
//! values; the portable backend refuses that trade.
//!
//! # Nonce discipline
//!
//! Reusing a `(key, nonce)` pair under GCM is catastrophic: it leaks the
//! authentication subkey and lets an attacker forge arbitrary messages. The
//! ontology records this as a hard usage constraint
//! (`nonce_reuse_consequence: "catastrophic"`) so an agent selecting GCM is
//! told to pair it with a counter or a random 96-bit nonce under a message
//! limit. See [`GcmLimits`].

//! Indexed loops over fixed-size limb and word arrays are used throughout; they
//! mirror the index algebra in the specifications these routines implement, so
//! `needless_range_loop` is allowed rather than obscuring the correspondence.
#![allow(clippy::needless_range_loop)]

use crate::aes::{Aes128, Aes192, Aes256, BLOCK_LEN};
use crate::modes::increment_be32;
use ic_core::traits::{Aead, Algorithm, BlockCipher, SelfTest};
use ic_core::{ensure, Result, Zeroize};

/// The GF(2^128) reduction constant for GHASH, `x^128 + x^7 + x^2 + x + 1`.
const R: u8 = 0xe1;

/// Invocation limits an agent must respect for a single GCM key.
///
/// From SP 800-38D §8.3 and the AES-GCM analysis behind RFC 8446.
pub struct GcmLimits;

impl GcmLimits {
    /// Maximum plaintext bytes in one invocation: `2^39 - 256` bits.
    pub const MAX_PLAINTEXT_BYTES: u64 = (1 << 36) - 32;
    /// Maximum invocations under one key with random 96-bit nonces.
    pub const MAX_RANDOM_NONCE_INVOCATIONS: u64 = 1 << 32;
    /// Recommended nonce length in bytes; other lengths are legal but slower
    /// and lose the injectivity guarantee that makes counters safe.
    pub const RECOMMENDED_NONCE_LEN: usize = 12;
}

/// Whether GHASH can use the carry-less multiply on this CPU.
///
/// Needs `ssse3` for the byte-reversal shuffle as well as `pclmulqdq` for the
/// multiply itself. Detection lives in `ic-core`, like AES-NI's, so the
/// ontology reports the same answer this dispatches on.
#[inline]
#[must_use]
pub fn ghash_accelerated() -> bool {
    ic_core::cpu::has_ghash_clmul()
}

/// Multiply `x` by `h` in GF(2^128) using the GCM bit ordering, in place.
///
/// Exposed within the crate so the accelerated backend can be differentially
/// tested against it.
pub(crate) fn portable_ghash_mul(x: &mut [u8; BLOCK_LEN], h: &[u8; BLOCK_LEN]) {
    let mut z = [0u8; BLOCK_LEN];
    let mut v = *h;
    for i in 0..128 {
        let bit = (x[i / 8] >> (7 - (i % 8))) & 1;
        let m = bit.wrapping_neg();
        for j in 0..BLOCK_LEN {
            z[j] ^= v[j] & m;
        }
        // v >>= 1 over the whole 128-bit word, then conditionally reduce.
        let lsb = v[BLOCK_LEN - 1] & 1;
        let mut carry = 0u8;
        for byte in v.iter_mut() {
            let next = *byte & 1;
            *byte = (*byte >> 1) | (carry << 7);
            carry = next;
        }
        v[0] ^= R & lsb.wrapping_neg();
    }
    *x = z;
    z.zeroize();
    v.zeroize();
}

/// The GHASH universal hash over a sequence of 16-byte blocks.
struct Ghash {
    h: [u8; BLOCK_LEN],
    /// `H`, `H^2` .. `H^8`: index `i` holds `H^(i+1)`. The first four serve
    /// the four-block path; the rest the eight-block `PCLMULQDQ` kernel, and
    /// are only computed once an input long enough to use them arrives.
    ///
    /// GHASH is a serial chain by definition -- each block's product feeds the
    /// next -- and on a CPU where one multiply has several cycles of latency
    /// and issues one per cycle, that chain, not the multiplier, is what bounds
    /// AES-GCM. Expanding four steps of the recurrence removes it:
    ///
    /// ```text
    /// Y' = (Y ^ X0)*H^4  ^  X1*H^3  ^  X2*H^2  ^  X3*H
    /// ```
    ///
    /// Four independent multiplies where there were four dependent ones. The
    /// identity is just distributivity over XOR in GF(2^128), and every product
    /// here is separately reduced, so this reuses `mul` exactly as it is rather
    /// than introducing a second reduction to get wrong.
    powers: [[u8; BLOCK_LEN]; 8],
    /// Whether `powers[4..]` has been computed.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    high_powers: bool,
    acc: [u8; BLOCK_LEN],
    /// Whether the `PCLMULQDQ` multiply is available. Decided once per value,
    /// from the CPU alone, so it is not a side channel.
    ///
    /// Only exists where an accelerated backend could be compiled in; on other
    /// targets there is nothing to select between.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    accelerated: bool,
}

impl Ghash {
    fn new(h: [u8; BLOCK_LEN]) -> Self {
        let mut me = Self {
            h,
            powers: [[0u8; BLOCK_LEN]; 8],
            #[cfg(all(target_arch = "x86_64", feature = "std"))]
            high_powers: false,
            acc: [0u8; BLOCK_LEN],
            #[cfg(all(target_arch = "x86_64", feature = "std"))]
            accelerated: ghash_accelerated(),
        };
        // H^2, H^3, H^4, each built from the previous one by the same multiply
        // the hot path uses. Once per key, off the hot path.
        me.powers[0] = h;
        for slot in 1..4 {
            let mut p = me.powers[slot - 1];
            me.mul_by(&mut p, &h);
            me.powers[slot] = p;
        }
        me
    }

    /// `x *= y` in GCM's field, via whichever backend is live.
    #[inline]
    fn mul_by(&self, x: &mut [u8; BLOCK_LEN], y: &[u8; BLOCK_LEN]) {
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        if self.accelerated {
            // SAFETY: `accelerated` is only true when `ghash_accelerated()`
            // confirmed both `pclmulqdq` and `ssse3`.
            unsafe { crate::clmul::mul(x, y) };
            return;
        }
        portable_ghash_mul(x, y);
    }

    /// Absorb four whole blocks with four independent multiplies.
    ///
    /// Correct for the same reason the one-at-a-time path is: see `powers`.
    #[inline]
    fn absorb4(&mut self, blocks: &[u8]) {
        debug_assert_eq!(blocks.len(), BLOCK_LEN * 4);
        let mut terms = [[0u8; BLOCK_LEN]; 4];
        for (i, t) in terms.iter_mut().enumerate() {
            t.copy_from_slice(&blocks[i * BLOCK_LEN..(i + 1) * BLOCK_LEN]);
        }
        // The first term carries the accumulator in, and takes the highest
        // power because it is the oldest.
        for j in 0..BLOCK_LEN {
            terms[0][j] ^= self.acc[j];
        }
        let multipliers = [
            &self.powers[3],
            &self.powers[2],
            &self.powers[1],
            &self.powers[0],
        ];
        for (t, m) in terms.iter_mut().zip(multipliers) {
            self.mul_by(t, m);
        }
        self.acc = terms[0];
        for t in &terms[1..] {
            for j in 0..BLOCK_LEN {
                self.acc[j] ^= t[j];
            }
        }
    }

    /// Multiply the accumulator by `H`, via whichever backend is live.
    #[inline]
    fn mul_acc(&mut self) {
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        if self.accelerated {
            // SAFETY: `accelerated` is only true when `ghash_accelerated()`
            // confirmed both `pclmulqdq` and `ssse3`.
            unsafe { crate::clmul::mul(&mut self.acc, &self.h) };
            return;
        }
        portable_ghash_mul(&mut self.acc, &self.h);
    }

    /// Absorb `data`, zero-padding the final partial block.
    fn update_padded(&mut self, mut data: &[u8]) {
        // Whole groups of eight through the `PCLMULQDQ` kernel, which reduces
        // once per group; see `clmul::absorb8`.
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        if self.accelerated && data.len() >= BLOCK_LEN * 8 {
            if !self.high_powers {
                for slot in 4..8 {
                    let mut p = self.powers[slot - 1];
                    self.mul_by(&mut p, &self.h);
                    self.powers[slot] = p;
                }
                self.high_powers = true;
            }
            let whole = data.len() - data.len() % (BLOCK_LEN * 8);
            // SAFETY: `accelerated` is only true when `ghash_accelerated()`
            // confirmed both `pclmulqdq` and `ssse3`, and `whole` is a
            // multiple of 128 bytes.
            unsafe { crate::clmul::absorb8(&mut self.acc, &self.powers, &data[..whole]) };
            data = &data[whole..];
        }
        // Then whole groups of four; the tail falls through to the serial
        // path, which also handles the final partial block.
        while data.len() >= BLOCK_LEN * 4 {
            self.absorb4(&data[..BLOCK_LEN * 4]);
            data = &data[BLOCK_LEN * 4..];
        }
        for chunk in data.chunks(BLOCK_LEN) {
            let mut block = [0u8; BLOCK_LEN];
            block[..chunk.len()].copy_from_slice(chunk);
            for j in 0..BLOCK_LEN {
                self.acc[j] ^= block[j];
            }
            self.mul_acc();
        }
    }

    fn finalize(self) -> [u8; BLOCK_LEN] {
        self.acc
    }
}

impl Drop for Ghash {
    fn drop(&mut self) {
        self.h.zeroize();
        self.acc.zeroize();
        // Powers of `H` are as key-derived as `H` itself. These were not wiped
        // before, when there were three of them.
        for p in self.powers.iter_mut() {
            p.zeroize();
        }
    }
}

/// GCM's counter mode: XOR `data` with the keystream from `counter`,
/// incrementing its last 32 bits big-endian (`inc32`).
///
/// A trait so the AES types can take their backend's own path; see
/// `aes::x86::ctr32_xor`. The default is the portable construction, and it is
/// what the accelerated path is tested against.
pub(crate) trait Ctr32: BlockCipher {
    fn ctr32_xor(&self, counter: &mut [u8; BLOCK_LEN], data: &mut [u8]) -> Result<()> {
        ctr32_xor_generic(self, counter, data)
    }
}

/// [`Ctr32`] through `encrypt_blocks`, eight blocks per call.
pub(crate) fn ctr32_xor_generic<C: BlockCipher + ?Sized>(
    cipher: &C,
    counter: &mut [u8; BLOCK_LEN],
    data: &mut [u8],
) -> Result<()> {
    const CTR_BATCH: usize = 8;
    let mut keystream = [0u8; BLOCK_LEN * CTR_BATCH];
    for chunk in data.chunks_mut(BLOCK_LEN * CTR_BATCH) {
        let blocks = chunk.len().div_ceil(BLOCK_LEN);
        for i in 0..blocks {
            keystream[i * BLOCK_LEN..(i + 1) * BLOCK_LEN].copy_from_slice(counter);
            increment_be32(counter);
        }
        cipher.encrypt_blocks(&mut keystream[..blocks * BLOCK_LEN])?;
        for (d, k) in chunk.iter_mut().zip(keystream.iter()) {
            *d ^= k;
        }
    }
    keystream.zeroize();
    Ok(())
}

/// Derive the initial counter block J0 from a nonce of any length.
fn derive_j0(nonce: &[u8], h: &[u8; BLOCK_LEN]) -> [u8; BLOCK_LEN] {
    if nonce.len() == 12 {
        let mut j0 = [0u8; BLOCK_LEN];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        j0
    } else {
        let mut g = Ghash::new(*h);
        g.update_padded(nonce);
        let mut len_block = [0u8; BLOCK_LEN];
        len_block[8..].copy_from_slice(&((nonce.len() as u64) * 8).to_be_bytes());
        g.update_padded(&len_block);
        g.finalize()
    }
}

/// The argument checks every GCM invocation makes first, whichever path then
/// runs it, so the fused path fails exactly where this one does.
fn check_invocation(nonce: &[u8], in_out: &[u8]) -> Result<()> {
    ensure!(
        !nonce.is_empty(),
        InvalidParameter,
        "gcm nonce must be non-empty"
    );
    ensure!(
        in_out.len() as u64 <= GcmLimits::MAX_PLAINTEXT_BYTES,
        CounterExhausted,
        "gcm plaintext exceeds 2^39-256 bits"
    );
    Ok(())
}

/// Shared GCM machinery over any 128-bit block cipher.
fn gcm_core<C: Ctr32>(
    cipher: &C,
    nonce: &[u8],
    aad: &[u8],
    in_out: &mut [u8],
    encrypting: bool,
) -> Result<[u8; BLOCK_LEN]> {
    check_invocation(nonce, in_out)?;

    // H = E_K(0^128)
    let mut h = [0u8; BLOCK_LEN];
    cipher.encrypt_block(&mut h)?;

    let j0 = derive_j0(nonce, &h);

    // When decrypting, GHASH must run over the ciphertext, which is what
    // `in_out` holds *before* the CTR pass.
    let mut g = Ghash::new(h);
    g.update_padded(aad);
    if !encrypting {
        g.update_padded(in_out);
    }

    // CTR starting at inc32(J0).
    let mut counter = j0;
    increment_be32(&mut counter);
    cipher.ctr32_xor(&mut counter, in_out)?;

    if encrypting {
        g.update_padded(in_out);
    }

    let mut len_block = [0u8; BLOCK_LEN];
    len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..].copy_from_slice(&((in_out.len() as u64) * 8).to_be_bytes());
    g.update_padded(&len_block);

    let mut tag = g.finalize();
    let mut ek_j0 = j0;
    cipher.encrypt_block(&mut ek_j0)?;
    for j in 0..BLOCK_LEN {
        tag[j] ^= ek_j0[j];
    }
    ek_j0.zeroize();
    h.zeroize();
    Ok(tag)
}

/// The fused x86-64 kernel's per-key state, when this CPU can run it.
///
/// Built once in `new`: `H`, its powers, and which kernel. `None` where the
/// AES backend is not AES-NI or GHASH has no carry-less multiply, and then
/// every call takes [`gcm_core`] exactly as before.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
type Fast = Option<crate::gcm_x86::HashKey>;

/// [`Fast`] for a freshly expanded cipher, using `kernel`.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
fn fast_for(keys: Option<&crate::aes::x86::Keys>, kernel: crate::gcm_x86::Kernel) -> Fast {
    let keys = keys?;
    if !ghash_accelerated() {
        return None;
    }
    // SAFETY: `keys` exists only on the AES-NI backend, which is only chosen
    // after detecting `aes`, and `ghash_accelerated()` has just confirmed
    // `pclmulqdq` and `ssse3`. `HashKey::new` checks the wide kernel's
    // features itself.
    Some(unsafe { crate::gcm_x86::HashKey::new(keys, kernel) })
}

macro_rules! aes_gcm {
    ($name:ident, $inner:ty, $id:literal, $disp:literal, $keylen:literal) => {
        #[doc = concat!("SP 800-38D ", $disp, ".")]
        pub struct $name {
            cipher: $inner,
            #[cfg(all(target_arch = "x86_64", feature = "std"))]
            fast: Fast,
        }

        impl $name {
            /// The expected tag for `in_out`, sealing or opening it in place,
            /// by the fused kernel where there is one and [`gcm_core`]
            /// otherwise.
            fn run(
                &self,
                nonce: &[u8],
                aad: &[u8],
                in_out: &mut [u8],
                encrypting: bool,
            ) -> Result<[u8; BLOCK_LEN]> {
                #[cfg(all(target_arch = "x86_64", feature = "std"))]
                if let (Some(hk), Some(keys)) = (&self.fast, self.cipher.aesni_keys()) {
                    check_invocation(nonce, in_out)?;
                    let j0 = derive_j0(nonce, hk.h());
                    // SAFETY: `hk` was built by `HashKey::new` after the
                    // feature checks in `fast_for`, and `keys` is the AES-NI
                    // schedule it was built from.
                    return Ok(unsafe {
                        crate::gcm_x86::seal_or_open(keys, hk, &j0, aad, in_out, encrypting)
                    });
                }
                gcm_core(&self.cipher, nonce, aad, in_out, encrypting)
            }

            /// Which fused kernel this key runs, if any.
            #[cfg(all(test, target_arch = "x86_64", feature = "std"))]
            fn kernel(&self) -> Option<crate::gcm_x86::Kernel> {
                self.fast.as_ref().map(|hk| hk.kernel())
            }

            /// A key forced onto `kernel`, or onto [`gcm_core`] with `None`,
            /// so each path can be compared with the others on one CPU.
            #[cfg(all(test, target_arch = "x86_64", feature = "std"))]
            fn with_kernel(key: &[u8], kernel: Option<crate::gcm_x86::Kernel>) -> Result<Self> {
                ic_core::module::operational()?;
                let cipher = <$inner as BlockCipher>::new(key)?;
                let fast = match kernel {
                    Some(k) => fast_for(cipher.aesni_keys(), k),
                    None => None,
                };
                Ok(Self { cipher, fast })
            }
        }

        impl Algorithm for $name {
            const ID: &'static str = $id;
            const NAME: &'static str = $disp;
        }

        impl Aead for $name {
            const KEY_LEN: usize = $keylen;
            const NONCE_LEN: usize = 12;
            const TAG_LEN: usize = 16;

            fn new(key: &[u8]) -> Result<Self> {
                ic_core::module::operational()?;
                let cipher = <$inner as BlockCipher>::new(key)?;
                #[cfg(all(target_arch = "x86_64", feature = "std"))]
                let fast = fast_for(cipher.aesni_keys(), crate::gcm_x86::best_kernel());
                Ok(Self {
                    cipher,
                    #[cfg(all(target_arch = "x86_64", feature = "std"))]
                    fast,
                })
            }

            fn seal_detached(
                &self,
                nonce: &[u8],
                aad: &[u8],
                in_out: &mut [u8],
                tag: &mut [u8],
            ) -> Result<()> {
                ic_core::module::operational()?;
                ensure!(tag.len() == 16, InvalidLength, "gcm tag buffer");
                let t = self.run(nonce, aad, in_out, true)?;
                tag.copy_from_slice(&t);
                Ok(())
            }

            fn open_detached(
                &self,
                nonce: &[u8],
                aad: &[u8],
                in_out: &mut [u8],
                tag: &[u8],
            ) -> Result<()> {
                ic_core::module::operational()?;
                ensure!(tag.len() == 16, InvalidLength, "gcm tag");
                let expected = self.run(nonce, aad, in_out, false)?;
                if ic_core::ct::verify(&expected, tag) {
                    Ok(())
                } else {
                    // Never hand back unauthenticated plaintext.
                    in_out.zeroize();
                    Err(ic_core::err!(AuthenticationFailed, $id))
                }
            }
        }

        impl SelfTest for $name {
            fn self_test() -> Result<()> {
                let key = [0u8; $keylen];
                let nonce = [0u8; 12];
                let c = <Self as Aead>::new(&key)?;
                let mut buf = [0u8; 16];
                let mut tag = [0u8; 16];
                c.seal_detached(&nonce, &[], &mut buf, &mut tag)?;
                c.open_detached(&nonce, &[], &mut buf, &tag)?;
                ensure!(buf == [0u8; 16], SelfTestFailed, $id);
                // A flipped tag bit must be rejected.
                tag[0] ^= 1;
                ensure!(
                    c.open_detached(&nonce, &[], &mut buf, &tag).is_err(),
                    SelfTestFailed,
                    $id
                );
                Ok(())
            }
        }
    };
}

aes_gcm!(Aes128Gcm, Aes128, "aes-128-gcm", "AES-128-GCM", 16);
aes_gcm!(Aes192Gcm, Aes192, "aes-192-gcm", "AES-192-GCM", 24);
aes_gcm!(Aes256Gcm, Aes256, "aes-256-gcm", "AES-256-GCM", 32);

#[cfg(test)]
mod tests {
    use super::*;

    /// The backend's counter mode against the generic one, on the portable
    /// cipher.
    ///
    /// The specification vectors are at most four blocks, so they never reach
    /// the kernel's whole-group path more than once, never cross the 32-bit
    /// counter wrap, and never end a message partway through a group. This
    /// covers every length from 0 to 300 bytes at counters that wrap inside a
    /// group, and the counter left behind.
    #[test]
    fn the_backend_counter_mode_agrees_with_the_generic_one() {
        use crate::aes::{Aes128, Aes256, Backend};
        type CtrFn = std::boxed::Box<dyn Fn(&mut [u8; 16], &mut [u8])>;
        let mut checked = 0;
        for key_len in [16usize, 32] {
            let key: std::vec::Vec<u8> = (0..key_len).map(|i| (i * 7 + 3) as u8).collect();
            let (fast, slow): (CtrFn, CtrFn) = if key_len == 16 {
                let f = Aes128::new(&key).unwrap();
                let s = Aes128::new_portable(&key).unwrap();
                if crate::aes::aesni_available() {
                    assert_eq!(f.backend(), Backend::Aesni);
                }
                (
                    std::boxed::Box::new(move |c, d| f.ctr32_xor(c, d).unwrap()),
                    std::boxed::Box::new(move |c, d| ctr32_xor_generic(&s, c, d).unwrap()),
                )
            } else {
                let f = Aes256::new(&key).unwrap();
                let s = Aes256::new_portable(&key).unwrap();
                (
                    std::boxed::Box::new(move |c, d| f.ctr32_xor(c, d).unwrap()),
                    std::boxed::Box::new(move |c, d| ctr32_xor_generic(&s, c, d).unwrap()),
                )
            };
            // A counter far from the edge, and ones that wrap inside the last
            // 32 bits partway through a group of eight.
            for tail in [0x0000_0001u32, 0xffff_fffd, 0xffff_fff9, 0xffff_ffff] {
                for len in 0..=300usize {
                    let mut counter = [0x5au8; 16];
                    counter[12..].copy_from_slice(&tail.to_be_bytes());
                    let data: std::vec::Vec<u8> = (0..len).map(|i| (i * 13) as u8).collect();
                    let (mut a, mut b) = (data.clone(), data.clone());
                    let (mut ca, mut cb) = (counter, counter);
                    fast(&mut ca, &mut a);
                    slow(&mut cb, &mut b);
                    assert_eq!(a, b, "key {key_len}, counter tail {tail:#x}, {len} bytes");
                    assert_eq!(
                        ca, cb,
                        "final counter, key {key_len}, tail {tail:#x}, {len} bytes"
                    );
                    checked += 1;
                }
            }
        }
        assert_eq!(checked, 2 * 4 * 301);
    }

    /// The four-at-a-time path must agree with the one-at-a-time path.
    ///
    /// The specification vectors do not establish this. The longest of them is
    /// four blocks, so they barely reach `absorb4` and never exercise it
    /// repeatedly or alongside a tail -- a version that was wrong from the
    /// second group onward, or wrong about the remainder, would pass all of
    /// them. This drives both paths over every length either side of the group
    /// boundary and compares the accumulators.
    #[test]
    fn the_batched_ghash_agrees_with_the_serial_one() {
        let h = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];

        let mut checked = 0;
        // Around one group, two groups, and the ragged lengths between.
        for len in [
            0usize, 1, 15, 16, 17, 31, 63, 64, 65, 79, 80, 127, 128, 129, 255, 256, 1024, 1025,
        ] {
            let data: std::vec::Vec<u8> = (0..len)
                .map(|i| ((i as u64).wrapping_mul(0x9e37_79b9) >> 3) as u8)
                .collect();

            let mut batched = Ghash::new(h);
            batched.update_padded(&data);

            // The serial reference: one block at a time, no grouping.
            let mut serial = Ghash::new(h);
            for chunk in data.chunks(BLOCK_LEN) {
                let mut block = [0u8; BLOCK_LEN];
                block[..chunk.len()].copy_from_slice(chunk);
                for j in 0..BLOCK_LEN {
                    serial.acc[j] ^= block[j];
                }
                serial.mul_acc();
            }

            assert_eq!(
                batched.acc, serial.acc,
                "batched and serial GHASH disagree at {len} bytes"
            );
            checked += 1;
        }
        assert_eq!(checked, 18, "the comparison did not run");

        // The eight-block kernel with an accumulator already carrying state,
        // as it does after the AAD: a short prefix first, then long inputs
        // either side of a group boundary.
        for (prefix, len) in [(17usize, 128usize), (16, 2048), (5, 2048 + 48), (33, 1023)] {
            let data: std::vec::Vec<u8> = (0..prefix + len)
                .map(|i| ((i as u64).wrapping_mul(0x2545_f491_4f6c_dd1d) >> 11) as u8)
                .collect();
            let (head, tail) = data.split_at(prefix);
            let mut batched = Ghash::new(h);
            batched.update_padded(head);
            batched.update_padded(tail);

            let mut serial = Ghash::new(h);
            for part in [head, tail] {
                for chunk in part.chunks(BLOCK_LEN) {
                    let mut block = [0u8; BLOCK_LEN];
                    block[..chunk.len()].copy_from_slice(chunk);
                    for j in 0..BLOCK_LEN {
                        serial.acc[j] ^= block[j];
                    }
                    serial.mul_acc();
                }
            }
            assert_eq!(batched.acc, serial.acc, "prefix {prefix}, then {len} bytes");

            // Where the kernel exists it must have run, or this is the
            // four-block path agreeing with the serial one again.
            #[cfg(all(target_arch = "x86_64", feature = "std"))]
            assert_eq!(batched.high_powers, batched.accelerated);
        }

        // And the grouping must actually have been used, or the agreement
        // above is two serial paths agreeing with each other.
        let long = std::vec![0xa5u8; BLOCK_LEN * 4];
        let mut g = Ghash::new(h);
        g.absorb4(&long);
        let mut serial = Ghash::new(h);
        for chunk in long.chunks(BLOCK_LEN) {
            for j in 0..BLOCK_LEN {
                serial.acc[j] ^= chunk[j];
            }
            serial.mul_acc();
        }
        assert_eq!(g.acc, serial.acc, "absorb4 alone disagrees with four steps");
    }

    /// `H^2`, `H^3` and `H^4` must be what they claim.
    #[test]
    fn the_precomputed_powers_are_powers_of_h() {
        let h = [0x3cu8; BLOCK_LEN];
        let mut g = Ghash::new(h);
        // Long enough to make the eight-block path build H^5..H^8 where it
        // runs; elsewhere only the first four exist.
        g.update_padded(&[0u8; BLOCK_LEN * 8]);
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        let built = if g.high_powers { 8 } else { 4 };
        #[cfg(not(all(target_arch = "x86_64", feature = "std")))]
        let built = 4;

        let mut expect = h;
        for (i, stored) in g.powers[..built].iter().enumerate() {
            if i > 0 {
                g.mul_by(&mut expect, &h);
            }
            assert_eq!(*stored, expect, "powers[{i}] is not H^{}", i + 1);
        }
        // Distinct, so a table of copies would fail rather than pass.
        for i in 1..built {
            assert_ne!(g.powers[i - 1], g.powers[i]);
        }
    }
    use ic_core::codec::{hex, unhex};

    /// Runs one of the McGrew–Viega GCM test vectors end to end.
    fn check(key: &str, nonce: &str, pt: &str, aad: &str, ct: &str, tag: &str) {
        let k = unhex(key).unwrap();
        let mut buf = unhex(pt).unwrap();
        let mut got_tag = [0u8; 16];
        let n = unhex(nonce).unwrap();
        let a = unhex(aad).unwrap();

        match k.len() {
            16 => {
                let c = Aes128Gcm::new(&k).unwrap();
                c.seal_detached(&n, &a, &mut buf, &mut got_tag).unwrap();
            }
            24 => {
                let c = Aes192Gcm::new(&k).unwrap();
                c.seal_detached(&n, &a, &mut buf, &mut got_tag).unwrap();
            }
            _ => {
                let c = Aes256Gcm::new(&k).unwrap();
                c.seal_detached(&n, &a, &mut buf, &mut got_tag).unwrap();
            }
        }
        assert_eq!(hex(&buf), ct, "ciphertext");
        assert_eq!(hex(&got_tag), tag, "tag");

        // And through every path this CPU has, each forced in turn, opening
        // as well as sealing.
        #[cfg(all(target_arch = "x86_64", feature = "std"))]
        super::fused_tests::check_every_path(&k, &n, &a, &unhex(pt).unwrap(), ct, tag);
    }

    #[test]
    fn gcm_spec_case_1_empty() {
        check(
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "",
            "",
            "",
            "58e2fccefa7e3061367f1d57a4e7455a",
        );
    }

    #[test]
    fn gcm_spec_case_2_single_block() {
        check(
            "00000000000000000000000000000000",
            "000000000000000000000000",
            "00000000000000000000000000000000",
            "",
            "0388dace60b6a392f328c2b971b2fe78",
            "ab6e47d42cec13bdf53a67b21257bddf",
        );
    }

    /// Case 3 authenticates the full 64-byte plaintext with no AAD; case 4
    /// below truncates it to 60 bytes and adds AAD, exercising both the
    /// partial-block and the AAD paths through GHASH.
    #[test]
    fn gcm_spec_case_3_multi_block() {
        check(
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
            "",
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
            "4d5c2af327cd64a62cf35abd2ba6fab4",
        );
    }

    #[test]
    fn gcm_spec_case_4_with_aad() {
        check(
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
            "5bc94fbc3221a5db94fae95ae7121a47",
        );
    }

    /// Case 5: a 64-bit nonce, which exercises the GHASH-based J0 derivation.
    #[test]
    fn gcm_short_nonce_uses_ghash_j0() {
        check(
            "feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbad",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
            "3612d2e79e3b0785561be14aaca2fccb",
        );
    }

    #[test]
    fn aes256_gcm_vector() {
        check(
            "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
            "cafebabefacedbaddecaf888",
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
            "feedfacedeadbeeffeedfacedeadbeefabaddad2",
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
            "76fc6ece0f4e1768cddf8853bb2d551b",
        );
    }

    #[test]
    fn roundtrip_and_tamper_detection() {
        let c = Aes256Gcm::new(&[7u8; 32]).unwrap();
        let nonce = [9u8; 12];
        let aad = b"header";
        let plaintext = b"attack at dawn, bring the ontology";

        let mut buf = plaintext.to_vec();
        let mut tag = [0u8; 16];
        c.seal_detached(&nonce, aad, &mut buf, &mut tag).unwrap();
        assert_ne!(&buf[..], &plaintext[..]);

        let mut ok = buf.clone();
        c.open_detached(&nonce, aad, &mut ok, &tag).unwrap();
        assert_eq!(&ok[..], &plaintext[..]);

        // Tampered ciphertext must fail and must not leak plaintext.
        let mut bad = buf.clone();
        bad[0] ^= 1;
        assert!(c.open_detached(&nonce, aad, &mut bad, &tag).is_err());
        assert_eq!(
            bad,
            vec![0u8; bad.len()],
            "plaintext must be wiped on failure"
        );

        // Wrong AAD must fail.
        let mut wrong_aad = buf.clone();
        assert!(c
            .open_detached(&nonce, b"other", &mut wrong_aad, &tag)
            .is_err());

        // Wrong nonce must fail.
        let mut wrong_nonce = buf.clone();
        assert!(c
            .open_detached(&[0u8; 12], aad, &mut wrong_nonce, &tag)
            .is_err());
    }

    #[test]
    fn self_tests_pass() {
        Aes128Gcm::self_test().unwrap();
        Aes192Gcm::self_test().unwrap();
        Aes256Gcm::self_test().unwrap();
    }
}

/// The fused x86-64 kernels against an independent GCM.
///
/// The reference below is SP 800-38D §7 written out a block at a time: the
/// portable AES (validated by the FIPS 197 vectors) and the portable GHASH
/// multiply (validated by the GCM specification vectors), no batching, no
/// precomputed powers, no SIMD. Every kernel this CPU can run -- and
/// [`gcm_core`], the path every other CPU takes -- must agree with it on
/// every message length from 0 to 600 bytes, AAD lengths across 0..=100 and
/// beyond, every key size, nonces of several lengths, and counters that wrap
/// inside a group.
///
/// The specification vectors alone would not do. The longest is four blocks,
/// so they never reach a 128- or 256-byte group, never leave a ragged tail
/// after one, and never put AAD and data in the same reduction.
#[cfg(all(test, target_arch = "x86_64", feature = "std"))]
mod fused_tests {
    use super::*;
    use crate::gcm_x86::{self, best_kernel, Kernel, Wide, Wide512};
    use std::boxed::Box;
    use std::vec::Vec;

    type Block = [u8; BLOCK_LEN];

    /// A small xorshift, so the sweep covers varied keys, nonces and data
    /// without an RNG dependency.
    struct Xs(u64);

    impl Xs {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| (self.next() >> 24) as u8).collect()
        }
    }

    /// Every path this CPU can run: `None` is [`gcm_core`].
    fn paths() -> Vec<Option<Kernel>> {
        let mut v = std::vec![None];
        if crate::aes::aesni_available() && ghash_accelerated() {
            v.push(Some(Kernel::Clmul8));
            if Wide::detect().is_some() {
                v.push(Some(Kernel::Vaes256));
            }
            if Wide512::detect().is_some() {
                v.push(Some(Kernel::Vaes512));
            }
        }
        v
    }

    /// The portable block cipher for `key`.
    fn portable(key: &[u8]) -> Box<dyn Fn(&mut Block)> {
        match key.len() {
            16 => {
                let c = crate::aes::Aes128::new_portable(key).unwrap();
                Box::new(move |b| c.encrypt_block(b).unwrap())
            }
            24 => {
                let c = crate::aes::Aes192::new_portable(key).unwrap();
                Box::new(move |b| c.encrypt_block(b).unwrap())
            }
            _ => {
                let c = crate::aes::Aes256::new_portable(key).unwrap();
                Box::new(move |b| c.encrypt_block(b).unwrap())
            }
        }
    }

    /// One serial GHASH step per 16-byte block, the last zero-padded.
    fn ghash_serial(h: &Block, y: &mut Block, bytes: &[u8]) {
        for chunk in bytes.chunks(BLOCK_LEN) {
            for (a, b) in y.iter_mut().zip(chunk) {
                *a ^= b;
            }
            portable_ghash_mul(y, h);
        }
    }

    fn inc32(c: &mut Block) {
        let n = u32::from_be_bytes([c[12], c[13], c[14], c[15]]).wrapping_add(1);
        c[12..].copy_from_slice(&n.to_be_bytes());
    }

    /// SP 800-38D §7.1 (and §7.2 when opening) from a given `J0`: the output
    /// and the tag.
    fn reference_j0(
        key: &[u8],
        j0: Block,
        aad: &[u8],
        data: &[u8],
        sealing: bool,
    ) -> (Vec<u8>, Block) {
        let e = portable(key);
        let mut h = [0u8; BLOCK_LEN];
        e(&mut h);
        let mut out = data.to_vec();
        let mut ctr = j0;
        for chunk in out.chunks_mut(BLOCK_LEN) {
            inc32(&mut ctr);
            let mut ks = ctr;
            e(&mut ks);
            for (d, k) in chunk.iter_mut().zip(ks.iter()) {
                *d ^= k;
            }
        }
        let ciphertext = if sealing { &out[..] } else { data };
        let mut y = [0u8; BLOCK_LEN];
        ghash_serial(&h, &mut y, aad);
        ghash_serial(&h, &mut y, ciphertext);
        let mut len = [0u8; BLOCK_LEN];
        len[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
        len[8..].copy_from_slice(&((data.len() as u64) * 8).to_be_bytes());
        ghash_serial(&h, &mut y, &len);
        let mut mask = j0;
        e(&mut mask);
        for (t, m) in y.iter_mut().zip(mask.iter()) {
            *t ^= m;
        }
        (out, y)
    }

    /// `J0` from a nonce of any length, serially.
    fn reference_j0_of(key: &[u8], nonce: &[u8]) -> Block {
        if nonce.len() == 12 {
            let mut j0 = [0u8; BLOCK_LEN];
            j0[..12].copy_from_slice(nonce);
            j0[15] = 1;
            return j0;
        }
        let e = portable(key);
        let mut h = [0u8; BLOCK_LEN];
        e(&mut h);
        let mut y = [0u8; BLOCK_LEN];
        ghash_serial(&h, &mut y, nonce);
        let mut len = [0u8; BLOCK_LEN];
        len[8..].copy_from_slice(&((nonce.len() as u64) * 8).to_be_bytes());
        ghash_serial(&h, &mut y, &len);
        y
    }

    /// Seal through one path; open the result through it; open it again with
    /// a flipped tag bit.
    fn through(
        key: &[u8],
        path: Option<Kernel>,
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
    ) -> (Vec<u8>, Block, Vec<u8>, bool) {
        macro_rules! go {
            ($ty:ty) => {{
                let c = <$ty>::with_kernel(key, path).unwrap();
                // The forced path is the one that runs, or this compares the
                // default path with itself.
                assert_eq!(c.kernel(), path, "{} did not take {path:?}", <$ty>::ID);
                let mut ct = pt.to_vec();
                let mut tag = [0u8; BLOCK_LEN];
                c.seal_detached(nonce, aad, &mut ct, &mut tag).unwrap();
                let mut opened = ct.clone();
                c.open_detached(nonce, aad, &mut opened, &tag).unwrap();
                let mut bad_tag = tag;
                bad_tag[(pt.len() + aad.len()) % BLOCK_LEN] ^= 0x01;
                let mut tampered = ct.clone();
                let refused = c
                    .open_detached(nonce, aad, &mut tampered, &bad_tag)
                    .is_err()
                    && tampered.iter().all(|&b| b == 0);
                (ct, tag, opened, refused)
            }};
        }
        match key.len() {
            16 => go!(Aes128Gcm),
            24 => go!(Aes192Gcm),
            _ => go!(Aes256Gcm),
        }
    }

    /// Every path against the reference on one input.
    fn agree(key: &[u8], nonce: &[u8], aad: &[u8], pt: &[u8]) -> usize {
        let j0 = reference_j0_of(key, nonce);
        let (want_ct, want_tag) = reference_j0(key, j0, aad, pt, true);
        let mut n = 0;
        for path in paths() {
            let (ct, tag, opened, refused) = through(key, path, nonce, aad, pt);
            let what = std::format!(
                "{path:?}, key {} bytes, nonce {} bytes, aad {} bytes, {} bytes",
                key.len(),
                nonce.len(),
                aad.len(),
                pt.len()
            );
            assert_eq!(ct, want_ct, "ciphertext: {what}");
            assert_eq!(tag, want_tag, "tag: {what}");
            assert_eq!(opened, pt, "opened: {what}");
            assert!(
                refused,
                "a flipped tag bit was accepted, or left plaintext: {what}"
            );
            n += 1;
        }
        n
    }

    /// The CPU's best kernel is the one `new` installs.
    #[test]
    fn new_selects_the_best_kernel_this_cpu_has() {
        let c = Aes256Gcm::new(&[1u8; 32]).unwrap();
        if crate::aes::aesni_available() && ghash_accelerated() {
            assert_eq!(c.kernel(), Some(best_kernel()));
            let expect = if Wide512::detect().is_some() {
                Kernel::Vaes512
            } else if Wide::detect().is_some() {
                Kernel::Vaes256
            } else {
                Kernel::Clmul8
            };
            assert_eq!(best_kernel(), expect);
            // Under `--cfg ic_no_avx512` the 512-bit kernel must stay off, so
            // this build measures the 256-bit one.
            #[cfg(ic_no_avx512)]
            assert_ne!(c.kernel(), Some(Kernel::Vaes512));
            // And under `--cfg ic_no_vaes` neither wide one, so this build
            // measures the AES-NI kernel that CPUs without VAES run.
            #[cfg(ic_no_vaes)]
            assert_eq!(c.kernel(), Some(Kernel::Clmul8));
            std::eprintln!("AES-GCM kernel on this CPU: {:?}", best_kernel());
        } else {
            assert_eq!(c.kernel(), None);
        }
        // And forcing a narrower kernel takes it.
        if c.kernel().is_some() {
            let n = Aes128Gcm::with_kernel(&[1u8; 16], Some(Kernel::Clmul8)).unwrap();
            assert_eq!(n.kernel(), Some(Kernel::Clmul8));
        }
    }

    #[test]
    fn every_path_matches_the_reference_at_every_length_to_600() {
        let mut rng = Xs(0x9e37_79b9_7f4a_7c15);
        let mut checked = 0;
        for key_len in [16usize, 24, 32] {
            for len in 0..=600usize {
                let key = rng.bytes(key_len);
                let nonce = rng.bytes(12);
                // Every AAD length from 0 to 100 occurs at many message
                // lengths.
                let aad = rng.bytes((len * 37 + key_len) % 101);
                let pt = rng.bytes(len);
                checked += agree(&key, &nonce, &aad, &pt);
            }
        }
        assert!(checked >= 3 * 601 * 2, "only {checked} comparisons ran");
    }

    #[test]
    fn every_path_matches_the_reference_for_every_aad_length_to_100() {
        let mut rng = Xs(0x2545_f491_4f6c_dd1d);
        for key_len in [16usize, 32] {
            for len in [
                0usize, 1, 15, 16, 17, 127, 128, 129, 255, 256, 257, 383, 513,
            ] {
                for aad_len in 0..=100usize {
                    let key = rng.bytes(key_len);
                    let nonce = rng.bytes(12);
                    let aad = rng.bytes(aad_len);
                    let pt = rng.bytes(len);
                    agree(&key, &nonce, &aad, &pt);
                }
            }
        }
    }

    #[test]
    fn every_path_matches_the_reference_on_large_inputs() {
        let mut rng = Xs(0xd1b5_4a32_d192_ed03);
        for (aad_len, len) in [
            (1000usize, 0usize),
            (4099, 1),
            (16, 4096),
            (13, 4096 + 255),
            (300, 65536 + 17),
            (0, 3 * 256 + 128 + 15),
        ] {
            for key_len in [16usize, 24, 32] {
                let key = rng.bytes(key_len);
                let nonce = rng.bytes(12);
                let aad = rng.bytes(aad_len);
                let pt = rng.bytes(len);
                agree(&key, &nonce, &aad, &pt);
            }
        }
    }

    /// The kernels load and store the message unaligned, and the eight-block
    /// one's aligned memory operands must never be the message: every path
    /// on buffers at each of the sixteen offsets from a 16-byte boundary,
    /// sealing and opening in place, against the reference.
    #[test]
    fn every_path_matches_the_reference_on_unaligned_buffers() {
        let mut rng = Xs(0x510e_527f_ade6_82d1);
        let mut checked = 0;
        for key_len in [16usize, 24, 32] {
            for offset in 0..16usize {
                for len in [1usize, 127, 128, 129, 256, 300, 512 + 17, 1024, 2048 + 255] {
                    let key = rng.bytes(key_len);
                    let nonce = rng.bytes(12);
                    let aad = rng.bytes((len + offset) % 41);
                    let pt = rng.bytes(len);
                    let j0 = reference_j0_of(&key, &nonce);
                    let (want_ct, want_tag) = reference_j0(&key, j0, &aad, &pt, true);
                    for path in paths() {
                        macro_rules! go {
                            ($ty:ty) => {{
                                let c = <$ty>::with_kernel(&key, path).unwrap();
                                assert_eq!(c.kernel(), path);
                                // A 16-byte-aligned allocation, entered at `offset`.
                                let mut store = std::vec![0u128; (len + offset) / 16 + 2];
                                let base = store.as_mut_ptr() as *mut u8;
                                // SAFETY: `store` holds at least `len + offset` bytes,
                                // all initialised, exclusively borrowed here.
                                let buf = unsafe {
                                    core::slice::from_raw_parts_mut(base.add(offset), len)
                                };
                                assert_eq!((buf.as_ptr() as usize) % 16, offset);
                                buf.copy_from_slice(&pt);
                                let mut tag = [0u8; BLOCK_LEN];
                                c.seal_detached(&nonce, &aad, buf, &mut tag).unwrap();
                                let what = std::format!(
                                    "{path:?}, key {key_len}, offset {offset}, {len} bytes"
                                );
                                assert!(buf == &want_ct[..], "ciphertext: {what}");
                                assert_eq!(tag, want_tag, "tag: {what}");
                                c.open_detached(&nonce, &aad, buf, &tag).unwrap();
                                assert!(buf == &pt[..], "opened: {what}");
                            }};
                        }
                        match key_len {
                            16 => go!(Aes128Gcm),
                            24 => go!(Aes192Gcm),
                            _ => go!(Aes256Gcm),
                        }
                        checked += 1;
                    }
                }
            }
        }
        assert!(checked >= 3 * 16 * 9, "only {checked} cases ran");
    }

    /// Past what the reference can do quickly in a debug build: every path
    /// against [`gcm_core`].
    #[test]
    fn every_path_matches_gcm_core_on_a_megabyte() {
        let mut rng = Xs(0x6a09_e667_f3bc_c909);
        for (key_len, len) in [(16usize, (1 << 20) + 13), (32, (1 << 20) + 256 + 7)] {
            let key = rng.bytes(key_len);
            let nonce = rng.bytes(12);
            let aad = rng.bytes(77);
            let pt = rng.bytes(len);
            let (want_ct, want_tag, _, _) = through(&key, None, &nonce, &aad, &pt);
            for path in paths().into_iter().skip(1) {
                let (ct, tag, opened, refused) = through(&key, path, &nonce, &aad, &pt);
                assert!(ct == want_ct, "{path:?}: ciphertext differs at {len} bytes");
                assert_eq!(tag, want_tag, "{path:?}: tag at {len} bytes");
                assert!(opened == pt, "{path:?}: open at {len} bytes");
                assert!(refused, "{path:?}: tampered tag at {len} bytes");
            }
        }
    }

    /// Nonces other than 96 bits take `J0` from GHASH, so the counter starts
    /// anywhere.
    #[test]
    fn every_path_matches_the_reference_with_other_nonce_lengths() {
        let mut rng = Xs(0xbb67_ae85_84ca_a73b);
        for nonce_len in [1usize, 8, 11, 13, 16, 60, 128] {
            for len in [0usize, 5, 64, 200, 256, 300, 600] {
                let key = rng.bytes(32);
                let nonce = rng.bytes(nonce_len);
                let aad = rng.bytes(len % 37);
                let pt = rng.bytes(len);
                agree(&key, &nonce, &aad, &pt);
            }
        }
    }

    /// The counter wraps within its last 32 bits, and must do so inside a
    /// group of 8 or 16 and in the tail, without carrying into the nonce.
    #[test]
    fn every_kernel_wraps_the_counter_as_inc32_does() {
        let mut rng = Xs(0x3c6e_f372_fe94_f82b);
        let mut checked = 0;
        for kernel in paths().into_iter().flatten() {
            for key_len in [16usize, 32] {
                let key = rng.bytes(key_len);
                macro_rules! keys {
                    ($ty:ty) => {{
                        <$ty as BlockCipher>::new(&key).unwrap()
                    }};
                }
                for back in [1u32, 2, 3, 7, 8, 9, 15, 16, 17, 31] {
                    for len in [
                        16usize,
                        100,
                        128,
                        255,
                        256,
                        257,
                        512,
                        600,
                        1072,
                        2048 + 256 + 128 + 33,
                    ] {
                        let mut j0 = [0xa5u8; BLOCK_LEN];
                        j0[12..].copy_from_slice(&0u32.wrapping_sub(back).to_be_bytes());
                        let aad = rng.bytes(len % 23);
                        let pt = rng.bytes(len);
                        let (want_ct, want_tag) = reference_j0(&key, j0, &aad, &pt, true);
                        let mut got = pt.clone();
                        let tag = if key_len == 16 {
                            let c = keys!(crate::aes::Aes128);
                            let keys = c.aesni_keys().unwrap();
                            // SAFETY: `paths()` lists only kernels whose
                            // features were detected, AES-NI included.
                            let hk = unsafe { gcm_x86::HashKey::new(keys, kernel) };
                            assert_eq!(hk.kernel(), kernel);
                            unsafe { gcm_x86::seal_or_open(keys, &hk, &j0, &aad, &mut got, true) }
                        } else {
                            let c = keys!(crate::aes::Aes256);
                            let keys = c.aesni_keys().unwrap();
                            // SAFETY: as above.
                            let hk = unsafe { gcm_x86::HashKey::new(keys, kernel) };
                            assert_eq!(hk.kernel(), kernel);
                            unsafe { gcm_x86::seal_or_open(keys, &hk, &j0, &aad, &mut got, true) }
                        };
                        let what = std::format!(
                            "{kernel:?}, key {key_len}, wrap {back} back, {len} bytes"
                        );
                        assert_eq!(got, want_ct, "ciphertext: {what}");
                        assert_eq!(tag, want_tag, "tag: {what}");
                        checked += 1;
                    }
                }
            }
        }
        if crate::aes::aesni_available() && ghash_accelerated() {
            assert!(checked >= 2 * 10 * 10, "only {checked} wrap cases ran");
        }
    }

    /// The specification vectors through every path, sealing and opening.
    pub(super) fn check_every_path(
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        pt: &[u8],
        ct: &str,
        tag: &str,
    ) {
        use ic_core::codec::hex;
        for path in paths() {
            let (got_ct, got_tag, opened, refused) = through(key, path, nonce, aad, pt);
            assert_eq!(hex(&got_ct), ct, "{path:?} ciphertext");
            assert_eq!(hex(&got_tag), tag, "{path:?} tag");
            assert_eq!(opened, pt, "{path:?} open");
            assert!(refused, "{path:?} accepted a bad tag");
        }
    }
}
