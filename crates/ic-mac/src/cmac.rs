//! SP 800-38B CMAC over AES.
//!
//! CMAC is the approved way to authenticate with a block cipher when a hash is
//! unavailable or undesirable, and it underpins the SP 800-90A CTR_DRBG
//! derivation function and SP 800-108 KDFs in CMAC mode.

//! Indexed loops over fixed-size limb and word arrays are used throughout; they
//! mirror the index algebra in the specifications these routines implement, so
//! `needless_range_loop` is allowed rather than obscuring the correspondence.
#![allow(clippy::needless_range_loop)]

use ic_cipher::aes::{Aes128, Aes192, Aes256, BLOCK_LEN};
use ic_core::traits::{Algorithm, BlockCipher, Mac, SelfTest};
use ic_core::{ensure, Result, Zeroize};

/// The CMAC subkey generation constant for a 128-bit block, `x^128 + x^7 + x^2 + x + 1`.
const RB: u8 = 0x87;

/// Double a 128-bit value in GF(2^128), constant-time.
fn dbl(block: &mut [u8; BLOCK_LEN]) {
    let msb = block[0] >> 7;
    let mut carry = 0u8;
    for byte in block.iter_mut().rev() {
        let next = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = next;
    }
    block[BLOCK_LEN - 1] ^= RB & msb.wrapping_neg();
}

/// Generic CMAC state over a 128-bit block cipher.
#[derive(Clone)]
pub struct Cmac<C: BlockCipher + Clone> {
    cipher: C,
    k1: [u8; BLOCK_LEN],
    k2: [u8; BLOCK_LEN],
    acc: [u8; BLOCK_LEN],
    buf: [u8; BLOCK_LEN],
    buffered: usize,
}

impl<C: BlockCipher + Clone> Drop for Cmac<C> {
    fn drop(&mut self) {
        self.k1.zeroize();
        self.k2.zeroize();
        self.acc.zeroize();
        self.buf.zeroize();
    }
}

impl<C: BlockCipher + Clone> Cmac<C> {
    fn build(cipher: C) -> Result<Self> {
        // L = E_K(0^128); K1 = dbl(L); K2 = dbl(K1).
        let mut l = [0u8; BLOCK_LEN];
        cipher.encrypt_block(&mut l)?;
        let mut k1 = l;
        dbl(&mut k1);
        let mut k2 = k1;
        dbl(&mut k2);
        l.zeroize();
        Ok(Self {
            cipher,
            k1,
            k2,
            acc: [0u8; BLOCK_LEN],
            buf: [0u8; BLOCK_LEN],
            buffered: 0,
        })
    }

    fn absorb(&mut self, block: &[u8]) -> Result<()> {
        for i in 0..BLOCK_LEN {
            self.acc[i] ^= block[i];
        }
        let mut tmp = self.acc;
        self.cipher.encrypt_block(&mut tmp)?;
        self.acc = tmp;
        Ok(())
    }

    fn absorb_buffered(&mut self) {
        let block = self.buf;
        // The cipher cannot fail on a correctly sized block; a failure here
        // would be an internal invariant break, so the accumulator is poisoned
        // rather than silently accepting a short MAC.
        if self.absorb(&block).is_err() {
            self.acc = [0xFFu8; BLOCK_LEN];
        }
        self.buffered = 0;
    }
}

/// A CMAC tag: always one block.
pub type CmacTag = [u8; BLOCK_LEN];

macro_rules! cmac_variant {
    (
        $name:ident, $inner:ty, $id:literal, $disp:literal, $keylen:literal,
        $kat_key:literal, $kat_tag:literal
    ) => {
        #[doc = concat!($disp, " (SP 800-38B).")]
        pub type $name = Cmac<$inner>;

        impl Algorithm for Cmac<$inner> {
            const ID: &'static str = $id;
            const NAME: &'static str = $disp;
        }

        impl SelfTest for Cmac<$inner> {
            fn self_test() -> Result<()> {
                // SP 800-38B example 1: the empty message.
                let mut key = [0u8; $keylen];
                ic_core::codec::hex_decode($kat_key.as_bytes(), &mut key)?;
                let tag = <Self as Mac>::mac(&key, b"")?;
                let mut want = [0u8; BLOCK_LEN];
                ic_core::codec::hex_decode($kat_tag.as_bytes(), &mut want)?;
                key.zeroize();
                ensure!(ic_core::ct::verify(&want, &tag), SelfTestFailed, $id);
                Ok(())
            }
        }
    };
}

impl<C: BlockCipher + Clone> Mac for Cmac<C>
where
    Cmac<C>: Algorithm,
{
    type Tag = CmacTag;
    const TAG_LEN: usize = BLOCK_LEN;

    fn new(key: &[u8]) -> Result<Self> {
        ensure!(
            C::BLOCK_LEN == BLOCK_LEN,
            InvalidParameter,
            "cmac needs a 128-bit block"
        );
        Self::build(C::new(key)?)
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.buffered > 0 {
            let take = core::cmp::min(BLOCK_LEN - self.buffered, data.len());
            self.buf[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            // The final block is handled in `finalize`, so a full buffer is
            // only flushed once more data is known to follow.
            if self.buffered < BLOCK_LEN || data.is_empty() {
                return;
            }
            self.absorb_buffered();
        }
        while data.len() > BLOCK_LEN {
            let (block, rest) = data.split_at(BLOCK_LEN);
            let _ = self.absorb(block);
            data = rest;
        }
        self.buf[..data.len()].copy_from_slice(data);
        self.buffered = data.len();
    }

    fn finalize(mut self) -> CmacTag {
        let mut last = self.buf;
        if self.buffered == BLOCK_LEN {
            // Complete final block: XOR with K1.
            for i in 0..BLOCK_LEN {
                last[i] ^= self.k1[i];
            }
        } else {
            // Incomplete (or empty) final block: 10* padding, XOR with K2.
            last[self.buffered] = 0x80;
            for b in last[self.buffered + 1..].iter_mut() {
                *b = 0;
            }
            for i in 0..BLOCK_LEN {
                last[i] ^= self.k2[i];
            }
        }
        if self.absorb(&last).is_err() {
            return [0xFFu8; BLOCK_LEN];
        }
        last.zeroize();
        self.acc
    }
}

cmac_variant!(
    CmacAes128,
    Aes128,
    "cmac-aes-128",
    "CMAC-AES-128",
    16,
    "2b7e151628aed2a6abf7158809cf4f3c",
    "bb1d6929e95937287fa37d129b756746"
);
cmac_variant!(
    CmacAes192,
    Aes192,
    "cmac-aes-192",
    "CMAC-AES-192",
    24,
    "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
    "d17ddf46adaacde531cac483de7a9367"
);
cmac_variant!(
    CmacAes256,
    Aes256,
    "cmac-aes-256",
    "CMAC-AES-256",
    32,
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
    "028962f61b7bf89efc6b551f4667d983"
);

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::codec::{hex, unhex};

    /// The SP 800-38B example message, from which each case takes a prefix.
    const MSG: &str = "6bc1bee22e409f96e93d7e117393172a\
                       ae2d8a571e03ac9c9eb76fac45af8e51\
                       30c81c46a35ce411e5fbc1191a0a52ef\
                       f69f2445df4f9b17ad2b417be66c3710";

    fn msg_prefix(len: usize) -> Vec<u8> {
        unhex(&MSG.replace(char::is_whitespace, "")).unwrap()[..len].to_vec()
    }

    #[test]
    fn sp800_38b_aes128_examples() {
        let key = unhex("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        for (len, want) in [
            (0usize, "bb1d6929e95937287fa37d129b756746"),
            (16, "070a16b46b4d4144f79bdd9dd04a287c"),
            (40, "dfa66747de9ae63030ca32611497c827"),
            (64, "51f0bebf7e3b9d92fc49741779363cfe"),
        ] {
            let tag = CmacAes128::mac(&key, &msg_prefix(len)).unwrap();
            assert_eq!(hex(&tag), want, "AES-128 CMAC over {len} bytes");
        }
    }

    #[test]
    fn sp800_38b_aes192_examples() {
        let key = unhex("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b").unwrap();
        for (len, want) in [
            (0usize, "d17ddf46adaacde531cac483de7a9367"),
            (16, "9e99a7bf31e710900662f65e617c5184"),
            (64, "a1d5df0eed790f794d77589659f39a11"),
        ] {
            let tag = CmacAes192::mac(&key, &msg_prefix(len)).unwrap();
            assert_eq!(hex(&tag), want, "AES-192 CMAC over {len} bytes");
        }
    }

    #[test]
    fn sp800_38b_aes256_examples() {
        let key =
            unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4").unwrap();
        for (len, want) in [
            (0usize, "028962f61b7bf89efc6b551f4667d983"),
            (16, "28a7023f452e8f82bd4bf28d8c37c35c"),
            (64, "e1992190549f6ed5696a2c056c315410"),
        ] {
            let tag = CmacAes256::mac(&key, &msg_prefix(len)).unwrap();
            assert_eq!(hex(&tag), want, "AES-256 CMAC over {len} bytes");
        }
    }

    #[test]
    fn streaming_matches_one_shot() {
        let key = unhex("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let data = msg_prefix(64);
        for split in [0usize, 1, 15, 16, 17, 32, 63, 64] {
            let mut m = CmacAes128::new(&key).unwrap();
            m.update(&data[..split]);
            m.update(&data[split..]);
            assert_eq!(
                m.finalize(),
                CmacAes128::mac(&key, &data).unwrap(),
                "split at {split}"
            );
        }
    }

    #[test]
    fn subkey_doubling_reduces() {
        // A value with the high bit set must pick up the Rb constant.
        let mut b = [0u8; BLOCK_LEN];
        b[0] = 0x80;
        dbl(&mut b);
        assert_eq!(b[BLOCK_LEN - 1], RB);
        assert_eq!(b[0], 0);
    }

    #[test]
    fn verify_detects_tampering() {
        let key = unhex("2b7e151628aed2a6abf7158809cf4f3c").unwrap();
        let tag = CmacAes128::mac(&key, b"data").unwrap();
        CmacAes128::verify(&key, b"data", &tag).unwrap();
        assert!(CmacAes128::verify(&key, b"datb", &tag).is_err());
    }

    #[test]
    fn self_tests_pass() {
        CmacAes128::self_test().unwrap();
        CmacAes192::self_test().unwrap();
        CmacAes256::self_test().unwrap();
    }
}
