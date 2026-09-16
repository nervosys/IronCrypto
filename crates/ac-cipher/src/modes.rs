//! NIST SP 800-38A confidentiality modes.
//!
//! These are *unauthenticated*. The ontology marks them `requires_mac: true`
//! and an agent asking for "encryption" is steered to an AEAD instead — see
//! `ac_ontology::select`. They are exposed because protocol implementations
//! (TLS record layers, KDF counter modes, disk formats) genuinely need them.

use crate::aes::BLOCK_LEN;
use ac_core::traits::BlockCipher;
use ac_core::{ensure, Result, Zeroize};

/// Counter mode: a stream cipher built from a block cipher.
///
/// Encryption and decryption are the same operation. The counter is the full
/// 128-bit big-endian value of `iv`, incremented per block, matching SP 800-38A
/// Appendix B and the counter convention used by AES-GCM.
pub fn ctr_xor<C: BlockCipher>(cipher: &C, iv: &[u8], data: &mut [u8]) -> Result<()> {
    ensure!(
        iv.len() == BLOCK_LEN,
        InvalidLength,
        "ctr iv must be 16 bytes"
    );
    let mut counter = [0u8; BLOCK_LEN];
    counter.copy_from_slice(iv);
    let mut keystream = [0u8; BLOCK_LEN];

    for chunk in data.chunks_mut(BLOCK_LEN) {
        keystream.copy_from_slice(&counter);
        cipher.encrypt_block(&mut keystream)?;
        for (d, k) in chunk.iter_mut().zip(keystream.iter()) {
            *d ^= k;
        }
        increment_be(&mut counter);
    }
    keystream.zeroize();
    Ok(())
}

/// Increment a big-endian counter block in place, with wraparound.
#[inline]
pub fn increment_be(counter: &mut [u8]) {
    for byte in counter.iter_mut().rev() {
        let (v, carry) = byte.overflowing_add(1);
        *byte = v;
        if !carry {
            break;
        }
    }
}

/// Increment only the trailing 32 bits, as AES-GCM specifies.
#[inline]
pub fn increment_be32(counter: &mut [u8; BLOCK_LEN]) {
    let mut n = u32::from_be_bytes([counter[12], counter[13], counter[14], counter[15]]);
    n = n.wrapping_add(1);
    counter[12..].copy_from_slice(&n.to_be_bytes());
}

/// CBC encryption over a plaintext that is already a whole number of blocks.
///
/// Use [`pkcs7_pad`] first if your data is not block-aligned.
pub fn cbc_encrypt<C: BlockCipher>(cipher: &C, iv: &[u8], data: &mut [u8]) -> Result<()> {
    ensure!(
        iv.len() == BLOCK_LEN,
        InvalidLength,
        "cbc iv must be 16 bytes"
    );
    ensure!(
        data.len() % BLOCK_LEN == 0,
        InvalidLength,
        "cbc input must be block-aligned"
    );
    let mut prev = [0u8; BLOCK_LEN];
    prev.copy_from_slice(iv);
    for block in data.chunks_mut(BLOCK_LEN) {
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        cipher.encrypt_block(block)?;
        prev.copy_from_slice(block);
    }
    Ok(())
}

/// CBC decryption over a block-aligned ciphertext.
pub fn cbc_decrypt<C: BlockCipher>(cipher: &C, iv: &[u8], data: &mut [u8]) -> Result<()> {
    ensure!(
        iv.len() == BLOCK_LEN,
        InvalidLength,
        "cbc iv must be 16 bytes"
    );
    ensure!(
        data.len() % BLOCK_LEN == 0,
        InvalidLength,
        "cbc input must be block-aligned"
    );
    let mut prev = [0u8; BLOCK_LEN];
    prev.copy_from_slice(iv);
    let mut saved = [0u8; BLOCK_LEN];
    for block in data.chunks_mut(BLOCK_LEN) {
        saved.copy_from_slice(block);
        cipher.decrypt_block(block)?;
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= p;
        }
        prev.copy_from_slice(&saved);
    }
    saved.zeroize();
    Ok(())
}

/// Append PKCS#7 padding, returning the new length.
///
/// `buf` must have room for up to [`BLOCK_LEN`] extra bytes.
pub fn pkcs7_pad(buf: &mut [u8], len: usize) -> Result<usize> {
    let pad = BLOCK_LEN - (len % BLOCK_LEN);
    ensure!(
        len + pad <= buf.len(),
        InvalidLength,
        "pkcs7 padding buffer"
    );
    for b in buf[len..len + pad].iter_mut() {
        *b = pad as u8;
    }
    Ok(len + pad)
}

/// Strip PKCS#7 padding in constant time, returning the plaintext length.
///
/// The check is branch-free over the padding *contents*, so a padding-oracle
/// attacker learns nothing beyond pass/fail — and callers of the AEAD APIs
/// never reach this path at all.
pub fn pkcs7_unpad(buf: &[u8]) -> Result<usize> {
    ensure!(
        !buf.is_empty() && buf.len() % BLOCK_LEN == 0,
        InvalidLength,
        "pkcs7 input must be block-aligned"
    );
    let pad = buf[buf.len() - 1];
    // Valid pad values are 1..=16; fold the range check into a mask.
    let in_range = ((pad.wrapping_sub(1)) < BLOCK_LEN as u8) as u8;
    let mut bad = in_range ^ 1;
    for i in 0..BLOCK_LEN {
        let idx = buf.len() - BLOCK_LEN + i;
        // Bytes within the padding region must all equal `pad`.
        let is_pad_byte = (((pad as i16) - ((BLOCK_LEN - i) as i16)) >= 0) as u8;
        bad |= (buf[idx] ^ pad) & is_pad_byte.wrapping_neg();
    }
    ensure!(bad == 0, MalformedEncoding, "pkcs7 padding");
    Ok(buf.len() - pad as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::Aes128;
    use ac_core::codec::{hex, unhex};

    const SP_KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
    const SP_IV: &str = "000102030405060708090a0b0c0d0e0f";
    /// SP 800-38A F.2 / F.5 four-block plaintext.
    const SP_PT: &str = "6bc1bee22e409f96e93d7e117393172a\
                         ae2d8a571e03ac9c9eb76fac45af8e51\
                         30c81c46a35ce411e5fbc1191a0a52ef\
                         f69f2445df4f9b17ad2b417be66c3710";

    #[test]
    fn sp800_38a_cbc_vector() {
        let c = Aes128::new(&unhex(SP_KEY).unwrap()).unwrap();
        let mut data = unhex(SP_PT).unwrap();
        cbc_encrypt(&c, &unhex(SP_IV).unwrap(), &mut data).unwrap();
        assert_eq!(
            hex(&data),
            "7649abac8119b246cee98e9b12e9197d\
             5086cb9b507219ee95db113a917678b2\
             73bed6b8e3c1743b7116e69e22229516\
             3ff1caa1681fac09120eca307586e1a7"
                .replace(char::is_whitespace, "")
        );
        cbc_decrypt(&c, &unhex(SP_IV).unwrap(), &mut data).unwrap();
        assert_eq!(hex(&data), SP_PT.replace(char::is_whitespace, ""));
    }

    #[test]
    fn sp800_38a_ctr_vector() {
        let c = Aes128::new(&unhex(SP_KEY).unwrap()).unwrap();
        let iv = unhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff").unwrap();
        let mut data = unhex(SP_PT).unwrap();
        ctr_xor(&c, &iv, &mut data).unwrap();
        assert_eq!(
            hex(&data),
            "874d6191b620e3261bef6864990db6ce\
             9806f66b7970fdff8617187bb9fffdff\
             5ae4df3edbd5d35e5b4f09020db03eab\
             1e031dda2fbe03d1792170a0f3009cee"
                .replace(char::is_whitespace, "")
        );
        // CTR is an involution: re-applying recovers the plaintext.
        ctr_xor(&c, &iv, &mut data).unwrap();
        assert_eq!(hex(&data), SP_PT.replace(char::is_whitespace, ""));
    }

    #[test]
    fn ctr_handles_partial_final_block() {
        let c = Aes128::new(&[0u8; 16]).unwrap();
        let mut data = [0u8; 37];
        ctr_xor(&c, &[0u8; 16], &mut data).unwrap();
        let encrypted = data;
        ctr_xor(&c, &[0u8; 16], &mut data).unwrap();
        assert_eq!(data, [0u8; 37]);
        assert_ne!(encrypted, [0u8; 37]);
    }

    #[test]
    fn counter_increment_carries() {
        let mut c = [0xffu8; 16];
        increment_be(&mut c);
        assert_eq!(c, [0u8; 16]);
        let mut c = [0u8; 16];
        c[15] = 0xff;
        increment_be(&mut c);
        assert_eq!(c[14], 1);
        assert_eq!(c[15], 0);
    }

    #[test]
    fn gcm_counter_wraps_only_low_32_bits() {
        let mut c = [0u8; 16];
        c[11] = 0x7f;
        c[12..].copy_from_slice(&0xffff_ffffu32.to_be_bytes());
        increment_be32(&mut c);
        assert_eq!(&c[12..], &[0, 0, 0, 0]);
        assert_eq!(
            c[11], 0x7f,
            "carry must not propagate past the counter field"
        );
    }

    #[test]
    fn pkcs7_roundtrip_including_full_block() {
        for len in 0..33usize {
            let mut buf = vec![0xAAu8; len + BLOCK_LEN];
            let padded = pkcs7_pad(&mut buf, len).unwrap();
            assert_eq!(padded % BLOCK_LEN, 0);
            assert_eq!(pkcs7_unpad(&buf[..padded]).unwrap(), len, "len {len}");
        }
    }

    #[test]
    fn pkcs7_rejects_corrupt_padding() {
        let mut buf = [0u8; 16];
        let n = pkcs7_pad(&mut buf, 8).unwrap();
        buf[n - 2] ^= 1;
        assert!(pkcs7_unpad(&buf[..n]).is_err());
        let mut zero = [0u8; 16];
        zero[15] = 0;
        assert!(pkcs7_unpad(&zero).is_err());
        let mut big = [0u8; 16];
        big[15] = 17;
        assert!(pkcs7_unpad(&big).is_err());
    }
}
