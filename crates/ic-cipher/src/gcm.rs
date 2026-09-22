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
/// multiply itself.
#[inline]
#[must_use]
pub fn ghash_accelerated() -> bool {
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    {
        ic_core::cpu::has_pclmulqdq() && std::arch::is_x86_feature_detected!("ssse3")
    }
    #[cfg(not(all(target_arch = "x86_64", feature = "std")))]
    {
        false
    }
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
    /// `H^2`, `H^3`, `H^4`, for absorbing four blocks at a time.
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
    powers: [[u8; BLOCK_LEN]; 3],
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
            powers: [[0u8; BLOCK_LEN]; 3],
            acc: [0u8; BLOCK_LEN],
            #[cfg(all(target_arch = "x86_64", feature = "std"))]
            accelerated: ghash_accelerated(),
        };
        // H^2, H^3, H^4, each built from the previous one by the same multiply
        // the hot path uses. Once per key, off the hot path.
        let mut p = h;
        for slot in 0..3 {
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
        let multipliers = [&self.powers[2], &self.powers[1], &self.powers[0], &self.h];
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
        // Whole groups of four first; the tail falls through to the serial
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
    }
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

/// Shared GCM machinery over any 128-bit block cipher.
fn gcm_core<C: BlockCipher>(
    cipher: &C,
    nonce: &[u8],
    aad: &[u8],
    in_out: &mut [u8],
    encrypting: bool,
) -> Result<[u8; BLOCK_LEN]> {
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

    // CTR starting at inc32(J0), batched so an accelerated backend can keep its
    // pipeline full.
    const CTR_BATCH: usize = 8;
    let mut counter = j0;
    increment_be32(&mut counter);
    let mut keystream = [0u8; BLOCK_LEN * CTR_BATCH];
    for chunk in in_out.chunks_mut(BLOCK_LEN * CTR_BATCH) {
        let blocks = chunk.len().div_ceil(BLOCK_LEN);
        for i in 0..blocks {
            keystream[i * BLOCK_LEN..(i + 1) * BLOCK_LEN].copy_from_slice(&counter);
            increment_be32(&mut counter);
        }
        cipher.encrypt_blocks(&mut keystream[..blocks * BLOCK_LEN])?;
        for (d, k) in chunk.iter_mut().zip(keystream.iter()) {
            *d ^= k;
        }
    }
    keystream.zeroize();

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

macro_rules! aes_gcm {
    ($name:ident, $inner:ty, $id:literal, $disp:literal, $keylen:literal) => {
        #[doc = concat!("SP 800-38D ", $disp, ".")]
        pub struct $name($inner);

        impl Algorithm for $name {
            const ID: &'static str = $id;
            const NAME: &'static str = $disp;
        }

        impl Aead for $name {
            const KEY_LEN: usize = $keylen;
            const NONCE_LEN: usize = 12;
            const TAG_LEN: usize = 16;

            fn new(key: &[u8]) -> Result<Self> {
                Ok(Self(<$inner as BlockCipher>::new(key)?))
            }

            fn seal_detached(
                &self,
                nonce: &[u8],
                aad: &[u8],
                in_out: &mut [u8],
                tag: &mut [u8],
            ) -> Result<()> {
                ensure!(tag.len() == 16, InvalidLength, "gcm tag buffer");
                let t = gcm_core(&self.0, nonce, aad, in_out, true)?;
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
                ensure!(tag.len() == 16, InvalidLength, "gcm tag");
                let expected = gcm_core(&self.0, nonce, aad, in_out, false)?;
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
        let g = Ghash::new(h);
        let mut expect = h;
        for (i, stored) in g.powers.iter().enumerate() {
            g.mul_by(&mut expect, &h);
            assert_eq!(*stored, expect, "power {} is not H^{}", i, i + 2);
        }
        // Distinct, so a table of copies would fail rather than pass.
        assert_ne!(g.powers[0], g.powers[1]);
        assert_ne!(g.powers[1], g.powers[2]);
        assert_ne!(g.powers[0], h);
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
