//! AES Key Wrap (SP 800-38F, RFC 3394 and RFC 5649).
//!
//! A cipher for encrypting keys with keys. It exists because the obvious
//! alternative — a general AEAD — needs a nonce, and the places key wrapping is
//! used are exactly the places where nonce management is hardest: a hardware
//! token with no clock, a backup file written once and read years later, a JOSE
//! header with nowhere to put one.
//!
//! Key Wrap solves that by being deterministic and taking no nonce at all. It
//! buys the missing randomization with six passes over the data, so every output
//! block depends on every input block, and integrity comes from a fixed check
//! value recovered on unwrap rather than from a separate tag.
//!
//! # Two variants
//!
//! [`Aes256Kw`] wraps data that is a whole number of 64-bit blocks, at least two
//! of them — which covers every symmetric key anyone actually wraps.
//! [`Aes256Kwp`] adds RFC 5649 padding for arbitrary lengths, at the cost of
//! revealing the length to within eight bytes.
//!
//! # What it does not do
//!
//! There is no associated data, and the integrity check is 64 bits, not 128.
//! SP 800-38F is explicit that this is a key-wrapping mechanism and not a
//! general-purpose AEAD; for bulk data use AES-GCM or ChaCha20-Poly1305, which
//! this workspace also has.

use ic_core::traits::{Algorithm, BlockCipher, SelfTest};
use ic_core::{ensure, Result, Zeroize};

/// The fixed check value from RFC 3394 section 2.2.3.1.
///
/// Recovering it on unwrap is what authenticates the ciphertext. Sixty-four
/// bits of integrity is weaker than an AEAD tag, and deliberate: the
/// construction predates modern AEADs and its security argument accounts for
/// the width.
const KW_IV: [u8; 8] = [0xa6; 8];

/// The RFC 5649 alternative check value, which carries a length.
const KWP_IV: [u8; 4] = [0xa6, 0x59, 0x59, 0xa6];

/// Largest wrapped payload this handles, in 64-bit blocks.
///
/// Sized for a 4096-bit RSA private key with room to spare. The bound exists so
/// the implementation can work on the stack.
const MAX_BLOCKS: usize = 128;

/// Ciphertext is one block longer than plaintext.
pub const OVERHEAD: usize = 8;

/// The core RFC 3394 wrapping loop, over `n` 64-bit blocks already in `r`.
///
/// Indexed rather than iterated because the index is the point: block `i` in
/// round `j` is combined with the counter `n*j + i + 1`, and that relationship
/// is what the six passes are built on.
#[allow(clippy::needless_range_loop)]
fn wrap_blocks<C: BlockCipher>(
    cipher: &C,
    a: &mut [u8; 8],
    r: &mut [[u8; 8]],
    n: usize,
) -> Result<()> {
    let mut block = [0u8; 16];
    for j in 0..6u64 {
        for i in 0..n {
            block[..8].copy_from_slice(a);
            block[8..].copy_from_slice(&r[i]);
            cipher.encrypt_block(&mut block)?;

            // t = n*j + i + 1, xored into the low end of A.
            let t = (n as u64) * j + (i as u64) + 1;
            a.copy_from_slice(&block[..8]);
            for (k, byte) in t.to_be_bytes().iter().enumerate() {
                a[k] ^= *byte;
            }
            r[i].copy_from_slice(&block[8..]);
        }
    }
    block.zeroize();
    Ok(())
}

/// The inverse loop. Runs the rounds and counters backwards.
#[allow(clippy::needless_range_loop)]
fn unwrap_blocks<C: BlockCipher>(
    cipher: &C,
    a: &mut [u8; 8],
    r: &mut [[u8; 8]],
    n: usize,
) -> Result<()> {
    let mut block = [0u8; 16];
    for j in (0..6u64).rev() {
        for i in (0..n).rev() {
            let t = (n as u64) * j + (i as u64) + 1;
            block[..8].copy_from_slice(a);
            for (k, byte) in t.to_be_bytes().iter().enumerate() {
                block[k] ^= *byte;
            }
            block[8..].copy_from_slice(&r[i]);
            cipher.decrypt_block(&mut block)?;

            a.copy_from_slice(&block[..8]);
            r[i].copy_from_slice(&block[8..]);
        }
    }
    block.zeroize();
    Ok(())
}

/// Declare a key-wrap pair over one AES key size.
macro_rules! key_wrap {
    ($kw:ident, $kwp:ident, $cipher:ty, $key_len:literal, $kw_id:literal, $kwp_id:literal) => {
        #[doc = concat!("SP 800-38F KW with AES-", stringify!($key_len), "*8.")]
        pub struct $kw;

        impl Algorithm for $kw {
            const ID: &'static str = $kw_id;
            const NAME: &'static str = $kw_id;
        }

        impl $kw {
            /// Key-encryption key length.
            pub const KEY_LEN: usize = $key_len;

            /// Wrap `plaintext`, writing `plaintext.len() + 8` bytes.
            ///
            /// The input must be a whole number of 64-bit blocks and at least
            /// two of them. A single block is refused: RFC 3394's loop
            /// degenerates there, and RFC 5649 exists to cover it.
            pub fn wrap(kek: &[u8], plaintext: &[u8], out: &mut [u8]) -> Result<()> {
                ensure!(kek.len() == $key_len, InvalidLength, "key-wrap kek");
                ensure!(
                    plaintext.len() % 8 == 0,
                    InvalidLength,
                    "key-wrap input must be a whole number of 64-bit blocks"
                );
                let n = plaintext.len() / 8;
                ensure!(
                    n >= 2,
                    InvalidLength,
                    "key-wrap input must be at least 16 bytes"
                );
                ensure!(n <= MAX_BLOCKS, InvalidLength, "key-wrap input too large");
                ensure!(
                    out.len() == plaintext.len() + OVERHEAD,
                    InvalidLength,
                    "key-wrap output"
                );

                let cipher = <$cipher>::new(kek)?;
                let mut a = KW_IV;
                let mut r = [[0u8; 8]; MAX_BLOCKS];
                for i in 0..n {
                    r[i].copy_from_slice(&plaintext[i * 8..(i + 1) * 8]);
                }

                wrap_blocks(&cipher, &mut a, &mut r[..n], n)?;

                out[..8].copy_from_slice(&a);
                for i in 0..n {
                    out[8 + i * 8..16 + i * 8].copy_from_slice(&r[i]);
                }
                for block in r.iter_mut() {
                    block.zeroize();
                }
                Ok(())
            }

            /// Unwrap, writing `ciphertext.len() - 8` bytes.
            ///
            /// Fails if the recovered check value is wrong, which is the only
            /// integrity signal the construction has.
            pub fn unwrap(kek: &[u8], ciphertext: &[u8], out: &mut [u8]) -> Result<()> {
                ensure!(kek.len() == $key_len, InvalidLength, "key-wrap kek");
                ensure!(
                    ciphertext.len() % 8 == 0 && ciphertext.len() >= 24,
                    InvalidLength,
                    "key-wrap ciphertext"
                );
                let n = ciphertext.len() / 8 - 1;
                ensure!(
                    n <= MAX_BLOCKS,
                    InvalidLength,
                    "key-wrap ciphertext too large"
                );
                ensure!(
                    out.len() == ciphertext.len() - OVERHEAD,
                    InvalidLength,
                    "key-wrap output"
                );

                let cipher = <$cipher>::new(kek)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(&ciphertext[..8]);
                let mut r = [[0u8; 8]; MAX_BLOCKS];
                for i in 0..n {
                    r[i].copy_from_slice(&ciphertext[8 + i * 8..16 + i * 8]);
                }

                unwrap_blocks(&cipher, &mut a, &mut r[..n], n)?;

                // Constant-time: an early return on the check value would leak
                // nothing much here, but there is no reason to leak it.
                let ok = ic_core::ct::verify(&a, &KW_IV);
                if !ok {
                    for block in r.iter_mut() {
                        block.zeroize();
                    }
                    return Err(ic_core::err!(AuthenticationFailed, $kw_id));
                }
                for i in 0..n {
                    out[i * 8..(i + 1) * 8].copy_from_slice(&r[i]);
                }
                for block in r.iter_mut() {
                    block.zeroize();
                }
                Ok(())
            }
        }

        #[doc = concat!("SP 800-38F KWP with AES-", stringify!($key_len), "*8, per RFC 5649.")]
        pub struct $kwp;

        impl Algorithm for $kwp {
            const ID: &'static str = $kwp_id;
            const NAME: &'static str = $kwp_id;
        }

        impl $kwp {
            /// Key-encryption key length.
            pub const KEY_LEN: usize = $key_len;

            /// Output length for a given input length: padded up to a multiple
            /// of eight, plus the eight-byte header.
            pub const fn wrapped_len(plaintext_len: usize) -> usize {
                plaintext_len.div_ceil(8) * 8 + OVERHEAD
            }

            /// Wrap data of any length from one byte upwards.
            ///
            /// The length is carried in the check value, so unwrapping recovers
            /// it exactly. It is not hidden: an observer learns the length to
            /// within eight bytes from the ciphertext size alone.
            pub fn wrap(kek: &[u8], plaintext: &[u8], out: &mut [u8]) -> Result<()> {
                ensure!(kek.len() == $key_len, InvalidLength, "key-wrap kek");
                ensure!(
                    !plaintext.is_empty(),
                    InvalidLength,
                    "key-wrap input is empty"
                );
                ensure!(
                    plaintext.len() <= MAX_BLOCKS * 8,
                    InvalidLength,
                    "key-wrap input too large"
                );
                ensure!(
                    out.len() == Self::wrapped_len(plaintext.len()),
                    InvalidLength,
                    "key-wrap output"
                );

                let cipher = <$cipher>::new(kek)?;
                let mut a = [0u8; 8];
                a[..4].copy_from_slice(&KWP_IV);
                a[4..].copy_from_slice(&(plaintext.len() as u32).to_be_bytes());

                let n = plaintext.len().div_ceil(8);
                let mut r = [[0u8; 8]; MAX_BLOCKS];
                for (i, chunk) in plaintext.chunks(8).enumerate() {
                    r[i][..chunk.len()].copy_from_slice(chunk);
                }

                if n == 1 {
                    // A single padded block is encrypted directly: the RFC 3394
                    // loop needs at least two blocks to mix anything.
                    let mut block = [0u8; 16];
                    block[..8].copy_from_slice(&a);
                    block[8..].copy_from_slice(&r[0]);
                    cipher.encrypt_block(&mut block)?;
                    out.copy_from_slice(&block);
                    block.zeroize();
                } else {
                    wrap_blocks(&cipher, &mut a, &mut r[..n], n)?;
                    out[..8].copy_from_slice(&a);
                    for i in 0..n {
                        out[8 + i * 8..16 + i * 8].copy_from_slice(&r[i]);
                    }
                }
                for block in r.iter_mut() {
                    block.zeroize();
                }
                Ok(())
            }

            /// Unwrap, returning the recovered length.
            ///
            /// `out` must be large enough for the padded data; the return value
            /// says how much of it is real.
            pub fn unwrap(kek: &[u8], ciphertext: &[u8], out: &mut [u8]) -> Result<usize> {
                ensure!(kek.len() == $key_len, InvalidLength, "key-wrap kek");
                ensure!(
                    ciphertext.len() % 8 == 0 && ciphertext.len() >= 16,
                    InvalidLength,
                    "key-wrap ciphertext"
                );
                let n = ciphertext.len() / 8 - 1;
                ensure!(
                    n <= MAX_BLOCKS,
                    InvalidLength,
                    "key-wrap ciphertext too large"
                );
                ensure!(out.len() >= n * 8, InvalidLength, "key-wrap output");

                let cipher = <$cipher>::new(kek)?;
                let mut a = [0u8; 8];
                let mut r = [[0u8; 8]; MAX_BLOCKS];

                if n == 1 {
                    let mut block = [0u8; 16];
                    block.copy_from_slice(ciphertext);
                    cipher.decrypt_block(&mut block)?;
                    a.copy_from_slice(&block[..8]);
                    r[0].copy_from_slice(&block[8..]);
                    block.zeroize();
                } else {
                    a.copy_from_slice(&ciphertext[..8]);
                    for i in 0..n {
                        r[i].copy_from_slice(&ciphertext[8 + i * 8..16 + i * 8]);
                    }
                    unwrap_blocks(&cipher, &mut a, &mut r[..n], n)?;
                }

                // Check the fixed half, then the length, then the padding —
                // accumulating into one decision so the failure mode does not
                // say which part was wrong.
                let mut ok = ic_core::ct::eq(&a[..4], &KWP_IV);
                let declared = u32::from_be_bytes([a[4], a[5], a[6], a[7]]) as usize;
                let padded = n * 8;
                let plausible = declared <= padded && padded - declared < 8 && declared > 0;
                ok = ok.and(ic_core::ct::Choice::from_u8(u8::from(plausible)));

                if plausible {
                    // Every padding byte must be zero.
                    let mut zeros = 0u8;
                    for i in declared..padded {
                        zeros |= r[i / 8][i % 8];
                    }
                    ok = ok.and(ic_core::ct::is_zero(&[zeros]));
                }

                if !bool::from(ok) {
                    for block in r.iter_mut() {
                        block.zeroize();
                    }
                    return Err(ic_core::err!(AuthenticationFailed, $kwp_id));
                }

                for i in 0..n {
                    out[i * 8..(i + 1) * 8].copy_from_slice(&r[i]);
                }
                for block in r.iter_mut() {
                    block.zeroize();
                }
                Ok(declared)
            }
        }
    };
}

key_wrap!(
    Aes128Kw,
    Aes128Kwp,
    crate::Aes128,
    16,
    "aes-128-kw",
    "aes-128-kwp"
);
key_wrap!(
    Aes192Kw,
    Aes192Kwp,
    crate::Aes192,
    24,
    "aes-192-kw",
    "aes-192-kwp"
);
key_wrap!(
    Aes256Kw,
    Aes256Kwp,
    crate::Aes256,
    32,
    "aes-256-kw",
    "aes-256-kwp"
);

impl SelfTest for Aes128Kw {
    /// RFC 3394 section 4.1: the published vector, wrapping a 128-bit key with
    /// a 128-bit KEK.
    fn self_test() -> Result<()> {
        let mut kek = [0u8; 16];
        ic_core::codec::hex_decode(b"000102030405060708090a0b0c0d0e0f", &mut kek)?;
        let mut key = [0u8; 16];
        ic_core::codec::hex_decode(b"00112233445566778899aabbccddeeff", &mut key)?;
        let mut want = [0u8; 24];
        ic_core::codec::hex_decode(
            b"1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5",
            &mut want,
        )?;

        let mut got = [0u8; 24];
        Aes128Kw::wrap(&kek, &key, &mut got)?;
        ensure!(
            ic_core::ct::verify(&want, &got),
            SelfTestFailed,
            "aes-128-kw"
        );

        let mut back = [0u8; 16];
        Aes128Kw::unwrap(&kek, &want, &mut back)?;
        ensure!(
            ic_core::ct::verify(&key, &back),
            SelfTestFailed,
            "aes-128-kw"
        );

        let mut tampered = want;
        tampered[0] ^= 1;
        ensure!(
            Aes128Kw::unwrap(&kek, &tampered, &mut back).is_err(),
            SelfTestFailed,
            "aes-128-kw"
        );
        Ok(())
    }
}

impl SelfTest for Aes256Kw {
    /// RFC 3394 section 4.6: a 256-bit key under a 256-bit KEK.
    fn self_test() -> Result<()> {
        let mut kek = [0u8; 32];
        ic_core::codec::hex_decode(
            b"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            &mut kek,
        )?;
        let mut key = [0u8; 32];
        ic_core::codec::hex_decode(
            b"00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f",
            &mut key,
        )?;
        let mut want = [0u8; 40];
        ic_core::codec::hex_decode(
            b"28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21",
            &mut want,
        )?;

        let mut got = [0u8; 40];
        Aes256Kw::wrap(&kek, &key, &mut got)?;
        ensure!(
            ic_core::ct::verify(&want, &got),
            SelfTestFailed,
            "aes-256-kw"
        );

        let mut back = [0u8; 32];
        Aes256Kw::unwrap(&kek, &want, &mut back)?;
        ensure!(
            ic_core::ct::verify(&key, &back),
            SelfTestFailed,
            "aes-256-kw"
        );
        Ok(())
    }
}

impl SelfTest for Aes192Kwp {
    /// RFC 5649 section 6: the twenty-byte published vector, which exercises
    /// padding across several blocks.
    fn self_test() -> Result<()> {
        let mut kek = [0u8; 24];
        ic_core::codec::hex_decode(
            b"5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8",
            &mut kek,
        )?;
        let mut key = [0u8; 20];
        ic_core::codec::hex_decode(b"c37b7e6492584340bed12207808941155068f738", &mut key)?;
        let mut want = [0u8; 32];
        ic_core::codec::hex_decode(
            b"138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a",
            &mut want,
        )?;

        let mut got = [0u8; 32];
        Aes192Kwp::wrap(&kek, &key, &mut got)?;
        ensure!(
            ic_core::ct::verify(&want, &got),
            SelfTestFailed,
            "aes-192-kwp"
        );

        let mut back = [0u8; 24];
        let len = Aes192Kwp::unwrap(&kek, &want, &mut back)?;
        ensure!(len == key.len(), SelfTestFailed, "aes-192-kwp");
        ensure!(
            ic_core::ct::verify(&key, &back[..len]),
            SelfTestFailed,
            "aes-192-kwp"
        );

        let mut tampered = want;
        tampered[3] ^= 1;
        ensure!(
            Aes192Kwp::unwrap(&kek, &tampered, &mut back).is_err(),
            SelfTestFailed,
            "aes-192-kwp"
        );
        Ok(())
    }
}

impl SelfTest for Aes256Kwp {
    /// No published RFC 5649 vector uses a 256-bit KEK, so this checks the
    /// round trip and the rejection of tampering at that size. The padded
    /// construction itself is vector-tested through [`Aes192Kwp`], which shares
    /// every line of it but the cipher.
    fn self_test() -> Result<()> {
        let kek = [0x5au8; 32];
        let secret = b"nineteen bytes here";
        let mut wrapped = [0u8; 32];
        Aes256Kwp::wrap(&kek, secret, &mut wrapped)?;

        let mut out = [0u8; 24];
        let len = Aes256Kwp::unwrap(&kek, &wrapped, &mut out)?;
        ensure!(len == secret.len(), SelfTestFailed, "aes-256-kwp");
        ensure!(
            ic_core::ct::verify(secret, &out[..len]),
            SelfTestFailed,
            "aes-256-kwp"
        );

        let mut tampered = wrapped;
        tampered[3] ^= 1;
        ensure!(
            Aes256Kwp::unwrap(&kek, &tampered, &mut out).is_err(),
            SelfTestFailed,
            "aes-256-kwp"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::codec::{hex, unhex};

    /// RFC 3394's six published vectors, section 4.1 through 4.6.
    ///
    /// These are the anchor for everything else here. A wrong implementation
    /// does not accidentally reproduce a published ciphertext, so matching even
    /// one of them establishes that the construction is right; matching all six
    /// across three key sizes and three data sizes leaves very little room.
    #[test]
    fn rfc_3394_vectors() {
        struct Case {
            kek: &'static str,
            key: &'static str,
            wrapped: &'static str,
        }
        let cases = [
            // 4.1: 128-bit data, 128-bit KEK
            Case {
                kek: "000102030405060708090a0b0c0d0e0f",
                key: "00112233445566778899aabbccddeeff",
                wrapped: "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5",
            },
            // 4.2: 128-bit data, 192-bit KEK
            Case {
                kek: "000102030405060708090a0b0c0d0e0f1011121314151617",
                key: "00112233445566778899aabbccddeeff",
                wrapped: "96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d",
            },
            // 4.3: 128-bit data, 256-bit KEK
            Case {
                kek: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                key: "00112233445566778899aabbccddeeff",
                wrapped: "64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7",
            },
            // 4.4: 192-bit data, 192-bit KEK
            Case {
                kek: "000102030405060708090a0b0c0d0e0f1011121314151617",
                key: "00112233445566778899aabbccddeeff0001020304050607",
                wrapped: "031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2",
            },
            // 4.5: 192-bit data, 256-bit KEK
            Case {
                kek: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                key: "00112233445566778899aabbccddeeff0001020304050607",
                wrapped: "a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1",
            },
            // 4.6: 256-bit data, 256-bit KEK
            Case {
                kek: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                key: "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f",
                wrapped: "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21",
            },
        ];

        for (index, case) in cases.iter().enumerate() {
            let kek = unhex(case.kek).unwrap();
            let key = unhex(case.key).unwrap();
            let want = unhex(case.wrapped).unwrap();

            let mut got = vec![0u8; key.len() + OVERHEAD];
            match kek.len() {
                16 => Aes128Kw::wrap(&kek, &key, &mut got).unwrap(),
                24 => Aes192Kw::wrap(&kek, &key, &mut got).unwrap(),
                _ => Aes256Kw::wrap(&kek, &key, &mut got).unwrap(),
            }
            assert_eq!(hex(&got), case.wrapped, "RFC 3394 case 4.{}", index + 1);

            let mut back = vec![0u8; key.len()];
            match kek.len() {
                16 => Aes128Kw::unwrap(&kek, &want, &mut back).unwrap(),
                24 => Aes192Kw::unwrap(&kek, &want, &mut back).unwrap(),
                _ => Aes256Kw::unwrap(&kek, &want, &mut back).unwrap(),
            }
            assert_eq!(hex(&back), case.key, "RFC 3394 unwrap 4.{}", index + 1);
        }
    }

    /// RFC 5649 section 6's two published vectors, both under a 192-bit KEK.
    ///
    /// These cover the padded construction: the first needs padding across
    /// several blocks, the second is short enough to take the single-block
    /// path, which is a separate branch entirely.
    #[test]
    fn rfc_5649_vectors() {
        let kek = unhex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8").unwrap();

        let key = unhex("c37b7e6492584340bed12207808941155068f738").unwrap();
        let mut wrapped = vec![0u8; Aes192Kwp::wrapped_len(key.len())];
        Aes192Kwp::wrap(&kek, &key, &mut wrapped).unwrap();
        assert_eq!(
            hex(&wrapped),
            "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a",
            "RFC 5649 twenty-byte vector"
        );
        let mut back = vec![0u8; wrapped.len() - 8];
        let len = Aes192Kwp::unwrap(&kek, &wrapped, &mut back).unwrap();
        assert_eq!(hex(&back[..len]), hex(&key));

        let key = unhex("466f7250617369").unwrap();
        let mut wrapped = vec![0u8; Aes192Kwp::wrapped_len(key.len())];
        Aes192Kwp::wrap(&kek, &key, &mut wrapped).unwrap();
        assert_eq!(
            hex(&wrapped),
            "afbeb0f07dfbf5419200f2ccb50bb24f",
            "RFC 5649 seven-byte vector, the single-block path"
        );
        let mut back = vec![0u8; wrapped.len() - 8];
        let len = Aes192Kwp::unwrap(&kek, &wrapped, &mut back).unwrap();
        assert_eq!(hex(&back[..len]), hex(&key));
    }

    #[test]
    fn wrapping_round_trips_at_every_supported_size() {
        let kek = [0x11u8; 32];
        for blocks in 2..=16usize {
            let plaintext: Vec<u8> = (0..blocks * 8).map(|i| i as u8).collect();
            let mut wrapped = vec![0u8; plaintext.len() + OVERHEAD];
            Aes256Kw::wrap(&kek, &plaintext, &mut wrapped).unwrap();
            assert_ne!(&wrapped[8..], &plaintext[..], "the data must be encrypted");

            let mut back = vec![0u8; plaintext.len()];
            Aes256Kw::unwrap(&kek, &wrapped, &mut back).unwrap();
            assert_eq!(back, plaintext, "{blocks} blocks");
        }
    }

    /// Every bit of the ciphertext is authenticated by the check value.
    #[test]
    fn tampering_is_rejected() {
        let kek = [0x22u8; 32];
        let plaintext = [0x33u8; 32];
        let mut wrapped = [0u8; 40];
        Aes256Kw::wrap(&kek, &plaintext, &mut wrapped).unwrap();

        let mut back = [0u8; 32];
        for byte in 0..wrapped.len() {
            let mut bad = wrapped;
            bad[byte] ^= 1;
            assert!(
                Aes256Kw::unwrap(&kek, &bad, &mut back).is_err(),
                "a flip in byte {byte} was accepted"
            );
        }
        // And the wrong KEK.
        assert!(Aes256Kw::unwrap(&[0x23u8; 32], &wrapped, &mut back).is_err());
    }

    /// Determinism is the point: no nonce, same output every time.
    #[test]
    fn wrapping_is_deterministic() {
        let kek = [0x44u8; 32];
        let plaintext = [0x55u8; 24];
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        Aes256Kw::wrap(&kek, &plaintext, &mut a).unwrap();
        Aes256Kw::wrap(&kek, &plaintext, &mut b).unwrap();
        assert_eq!(a, b);
    }

    /// The six passes exist so that every output block depends on every input
    /// block. A one-bit change anywhere must scramble the whole wrap.
    #[test]
    fn every_output_block_depends_on_every_input_block() {
        let kek = [0x66u8; 32];
        let base = [0u8; 64];
        let mut reference = [0u8; 72];
        Aes256Kw::wrap(&kek, &base, &mut reference).unwrap();

        for index in [0usize, 8, 32, 63] {
            let mut changed = base;
            changed[index] ^= 1;
            let mut wrapped = [0u8; 72];
            Aes256Kw::wrap(&kek, &changed, &mut wrapped).unwrap();

            let same = reference
                .chunks(8)
                .zip(wrapped.chunks(8))
                .filter(|(a, b)| a == b)
                .count();
            assert_eq!(
                same, 0,
                "changing input byte {index} left {same} output blocks unchanged"
            );
        }
    }

    #[test]
    fn padded_wrapping_round_trips_at_every_length() {
        let kek = [0x77u8; 32];
        for len in 1..=64usize {
            let plaintext: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
            let mut wrapped = vec![0u8; Aes256Kwp::wrapped_len(len)];
            Aes256Kwp::wrap(&kek, &plaintext, &mut wrapped).unwrap();
            assert_eq!(wrapped.len(), len.div_ceil(8) * 8 + 8);

            let mut back = vec![0u8; wrapped.len() - 8];
            let got = Aes256Kwp::unwrap(&kek, &wrapped, &mut back).unwrap();
            assert_eq!(got, len, "recovered length at {len}");
            assert_eq!(&back[..got], &plaintext[..], "round trip at {len}");
        }
    }

    /// The single-block path is a different code path in RFC 5649, so it gets
    /// its own check.
    #[test]
    fn the_single_block_padded_path_works() {
        let kek = [0x88u8; 32];
        for len in 1..=8usize {
            let plaintext = vec![0xabu8; len];
            let mut wrapped = vec![0u8; 16];
            Aes256Kwp::wrap(&kek, &plaintext, &mut wrapped).unwrap();
            assert_eq!(wrapped.len(), 16, "one block plus the header");

            let mut back = [0u8; 8];
            let got = Aes256Kwp::unwrap(&kek, &wrapped, &mut back).unwrap();
            assert_eq!(got, len);
            assert_eq!(&back[..got], &plaintext[..]);
        }
    }

    #[test]
    fn padded_wrapping_rejects_tampering() {
        let kek = [0x99u8; 32];
        let plaintext = b"a secret of awkward length";
        let mut wrapped = vec![0u8; Aes256Kwp::wrapped_len(plaintext.len())];
        Aes256Kwp::wrap(&kek, plaintext, &mut wrapped).unwrap();

        let mut back = vec![0u8; wrapped.len() - 8];
        for byte in 0..wrapped.len() {
            let mut bad = wrapped.clone();
            bad[byte] ^= 1;
            assert!(
                Aes256Kwp::unwrap(&kek, &bad, &mut back).is_err(),
                "a flip in byte {byte} was accepted"
            );
        }
    }

    #[test]
    fn lengths_are_validated() {
        let kek = [0u8; 32];
        let mut out = [0u8; 64];

        // Not a whole number of blocks.
        assert!(Aes256Kw::wrap(&kek, &[0u8; 20], &mut out[..28]).is_err());
        // A single block: RFC 3394 needs two.
        assert!(Aes256Kw::wrap(&kek, &[0u8; 8], &mut out[..16]).is_err());
        // Empty.
        assert!(Aes256Kw::wrap(&kek, &[], &mut out[..8]).is_err());
        assert!(Aes256Kwp::wrap(&kek, &[], &mut out[..8]).is_err());
        // Wrong KEK size.
        assert!(Aes256Kw::wrap(&[0u8; 16], &[0u8; 16], &mut out[..24]).is_err());
        // Wrong output size.
        assert!(Aes256Kw::wrap(&kek, &[0u8; 16], &mut out[..23]).is_err());
        // Ciphertext too short to contain anything.
        assert!(Aes256Kw::unwrap(&kek, &[0u8; 16], &mut out[..8]).is_err());
    }

    #[test]
    fn all_self_tests_pass() {
        Aes128Kw::self_test().unwrap();
        Aes256Kw::self_test().unwrap();
        Aes192Kwp::self_test().unwrap();
        Aes256Kwp::self_test().unwrap();
    }
}
