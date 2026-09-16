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
use ac_core::traits::{Aead, Algorithm, BlockCipher, SelfTest};
use ac_core::{ensure, Result, Zeroize};

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

/// Multiply `x` by `h` in GF(2^128) using the GCM bit ordering, in place.
fn ghash_mul(x: &mut [u8; BLOCK_LEN], h: &[u8; BLOCK_LEN]) {
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
    acc: [u8; BLOCK_LEN],
}

impl Ghash {
    fn new(h: [u8; BLOCK_LEN]) -> Self {
        Self {
            h,
            acc: [0u8; BLOCK_LEN],
        }
    }

    /// Absorb `data`, zero-padding the final partial block.
    fn update_padded(&mut self, data: &[u8]) {
        for chunk in data.chunks(BLOCK_LEN) {
            let mut block = [0u8; BLOCK_LEN];
            block[..chunk.len()].copy_from_slice(chunk);
            for j in 0..BLOCK_LEN {
                self.acc[j] ^= block[j];
            }
            ghash_mul(&mut self.acc, &self.h);
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

    // CTR starting at inc32(J0).
    let mut counter = j0;
    increment_be32(&mut counter);
    let mut keystream = [0u8; BLOCK_LEN];
    for chunk in in_out.chunks_mut(BLOCK_LEN) {
        keystream.copy_from_slice(&counter);
        cipher.encrypt_block(&mut keystream)?;
        for (d, k) in chunk.iter_mut().zip(keystream.iter()) {
            *d ^= k;
        }
        increment_be32(&mut counter);
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
                if ac_core::ct::verify(&expected, tag) {
                    Ok(())
                } else {
                    // Never hand back unauthenticated plaintext.
                    in_out.zeroize();
                    Err(ac_core::err!(AuthenticationFailed, $id))
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
    use ac_core::codec::{hex, unhex};

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
