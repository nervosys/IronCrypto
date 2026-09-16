//! RFC 5869 HKDF: extract-then-expand.

use ac_core::traits::{Algorithm, Kdf, Mac, SelfTest};
use ac_core::{ensure, Result, Zeroize};
use core::marker::PhantomData;

/// The largest PRK any supported HMAC produces (SHA-512).
const MAX_PRK_LEN: usize = 64;

/// HKDF instantiated with the MAC `M`.
pub struct Hkdf<M: Mac>(PhantomData<M>);

impl<M: Mac> Hkdf<M> {
    /// HKDF-Extract: compress arbitrary input keying material into a PRK.
    ///
    /// An empty salt is replaced by `HashLen` zero bytes, as RFC 5869 requires.
    pub fn extract(salt: &[u8], ikm: &[u8], prk: &mut [u8]) -> Result<()> {
        ensure!(prk.len() == M::TAG_LEN, InvalidLength, "hkdf prk buffer");
        let zeros = [0u8; MAX_PRK_LEN];
        let salt = if salt.is_empty() {
            &zeros[..M::TAG_LEN]
        } else {
            salt
        };
        let tag = M::mac(salt, ikm)?;
        prk.copy_from_slice(tag.as_ref());
        Ok(())
    }

    /// HKDF-Expand: stretch a PRK to `out.len()` bytes bound to `info`.
    pub fn expand(prk: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
        let n = M::TAG_LEN;
        ensure!(prk.len() >= n, InvalidLength, "hkdf prk too short");
        // RFC 5869 caps output at 255 * HashLen because the counter is a byte.
        ensure!(
            out.len() <= 255 * n,
            InvalidLength,
            "hkdf output exceeds 255*HashLen"
        );

        let mut previous = [0u8; MAX_PRK_LEN];
        let mut previous_len = 0usize;
        let mut counter: u8 = 1;

        for chunk in out.chunks_mut(n) {
            let mut m = M::new(prk)?;
            m.update(&previous[..previous_len]);
            m.update(info);
            m.update(&[counter]);
            let t = m.finalize();
            chunk.copy_from_slice(&t.as_ref()[..chunk.len()]);
            previous[..n].copy_from_slice(t.as_ref());
            previous_len = n;
            counter = counter.wrapping_add(1);
        }
        previous.zeroize();
        Ok(())
    }
}

impl<M: Mac> Algorithm for Hkdf<M> {
    const ID: &'static str = M::ID;
    const NAME: &'static str = "HKDF";
}

impl<M: Mac> Kdf for Hkdf<M> {
    /// One-shot extract-then-expand.
    fn derive(secret: &[u8], salt: &[u8], info: &[u8], out: &mut [u8]) -> Result<()> {
        let mut prk = [0u8; MAX_PRK_LEN];
        Self::extract(salt, secret, &mut prk[..M::TAG_LEN])?;
        let r = Self::expand(&prk[..M::TAG_LEN], info, out);
        prk.zeroize();
        r
    }
}

impl SelfTest for Hkdf<ac_mac::HmacSha256> {
    fn self_test() -> Result<()> {
        // RFC 5869 test case 1.
        let ikm = [0x0bu8; 22];
        let mut salt = [0u8; 13];
        ac_core::codec::hex_decode(b"000102030405060708090a0b0c", &mut salt)?;
        let mut info = [0u8; 10];
        ac_core::codec::hex_decode(b"f0f1f2f3f4f5f6f7f8f9", &mut info)?;

        let mut okm = [0u8; 42];
        <Self as Kdf>::derive(&ikm, &salt, &info, &mut okm)?;

        let mut want = [0u8; 42];
        ac_core::codec::hex_decode(
            b"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            &mut want,
        )?;
        ensure!(
            ac_core::ct::verify(&want, &okm),
            SelfTestFailed,
            "hkdf-sha2-256"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ac_core::codec::{hex, unhex};
    use ac_mac::{HmacSha256, HmacSha512};

    /// RFC 5869 test case 1 (SHA-256, with salt and info).
    #[test]
    fn rfc5869_case_1() {
        let ikm = [0x0bu8; 22];
        let salt = unhex("000102030405060708090a0b0c").unwrap();
        let info = unhex("f0f1f2f3f4f5f6f7f8f9").unwrap();

        let mut prk = [0u8; 32];
        Hkdf::<HmacSha256>::extract(&salt, &ikm, &mut prk).unwrap();
        assert_eq!(
            hex(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );

        let mut okm = [0u8; 42];
        Hkdf::<HmacSha256>::expand(&prk, &info, &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    /// RFC 5869 test case 3: empty salt and empty info.
    #[test]
    fn rfc5869_case_3_empty_salt_and_info() {
        let ikm = [0x0bu8; 22];
        let mut prk = [0u8; 32];
        Hkdf::<HmacSha256>::extract(b"", &ikm, &mut prk).unwrap();
        assert_eq!(
            hex(&prk),
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
        );

        let mut okm = [0u8; 42];
        Hkdf::<HmacSha256>::expand(&prk, b"", &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
        );
    }

    /// RFC 5869 test case 2: inputs longer than one hash block.
    #[test]
    fn rfc5869_case_2_long_inputs() {
        let ikm: Vec<u8> = (0..80u8).collect();
        let salt: Vec<u8> = (0x60..0xb0u8).collect();
        let info: Vec<u8> = (0xb0..=0xffu8).collect();

        let mut okm = [0u8; 82];
        Hkdf::<HmacSha256>::derive(&ikm, &salt, &info, &mut okm).unwrap();
        assert_eq!(
            hex(&okm),
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"
        );
    }

    #[test]
    fn derive_matches_extract_then_expand() {
        let mut a = [0u8; 40];
        Hkdf::<HmacSha512>::derive(b"ikm", b"salt", b"info", &mut a).unwrap();

        let mut prk = [0u8; 64];
        Hkdf::<HmacSha512>::extract(b"salt", b"ikm", &mut prk).unwrap();
        let mut b = [0u8; 40];
        Hkdf::<HmacSha512>::expand(&prk, b"info", &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn info_separates_derived_keys() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        Hkdf::<HmacSha256>::derive(b"ikm", b"salt", b"context-a", &mut a).unwrap();
        Hkdf::<HmacSha256>::derive(b"ikm", b"salt", b"context-b", &mut b).unwrap();
        assert_ne!(a, b, "distinct info must yield independent keys");
    }

    #[test]
    fn rejects_output_beyond_255_blocks() {
        let mut too_long = vec![0u8; 255 * 32 + 1];
        assert!(Hkdf::<HmacSha256>::expand(&[0u8; 32], b"", &mut too_long).is_err());
        let mut at_limit = vec![0u8; 255 * 32];
        assert!(Hkdf::<HmacSha256>::expand(&[0u8; 32], b"", &mut at_limit).is_ok());
    }

    #[test]
    fn self_test_passes() {
        Hkdf::<HmacSha256>::self_test().unwrap();
    }
}
