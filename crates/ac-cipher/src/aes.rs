//! FIPS 197 AES block cipher, in a portable constant-time formulation.

use crate::gf;
use ac_core::traits::{Algorithm, BlockCipher, SelfTest};
use ac_core::{ensure, Result, Zeroize};

/// AES block size in bytes.
pub const BLOCK_LEN: usize = 16;

const MAX_ROUND_KEYS: usize = 15 * BLOCK_LEN;

/// Round-constant sequence for the key schedule, `rcon[i] = x^i` in GF(2^8).
fn rcon(i: usize) -> u8 {
    let mut c = 1u8;
    for _ in 1..i {
        c = gf::xtime(c);
    }
    c
}

/// An expanded AES key schedule, generic over key length.
///
/// Dropping the schedule zeroizes it, so round keys never outlive the value.
#[derive(Clone)]
struct Schedule {
    round_keys: [u8; MAX_ROUND_KEYS],
    rounds: usize,
}

impl Drop for Schedule {
    fn drop(&mut self) {
        self.round_keys.zeroize();
    }
}

impl Schedule {
    fn expand(key: &[u8]) -> Result<Self> {
        let nk = key.len() / 4;
        let rounds = match key.len() {
            16 => 10,
            24 => 12,
            32 => 14,
            _ => {
                return Err(ac_core::err!(
                    InvalidLength,
                    "aes key must be 16, 24, or 32 bytes"
                ))
            }
        };
        let total_words = (rounds + 1) * 4;
        let mut rk = [0u8; MAX_ROUND_KEYS];
        rk[..key.len()].copy_from_slice(key);

        for i in nk..total_words {
            let mut t = [
                rk[(i - 1) * 4],
                rk[(i - 1) * 4 + 1],
                rk[(i - 1) * 4 + 2],
                rk[(i - 1) * 4 + 3],
            ];
            if i % nk == 0 {
                t.rotate_left(1);
                for b in t.iter_mut() {
                    *b = gf::sbox(*b);
                }
                t[0] ^= rcon(i / nk);
            } else if nk > 6 && i % nk == 4 {
                for b in t.iter_mut() {
                    *b = gf::sbox(*b);
                }
            }
            for j in 0..4 {
                rk[i * 4 + j] = rk[(i - nk) * 4 + j] ^ t[j];
            }
        }
        Ok(Self {
            round_keys: rk,
            rounds,
        })
    }

    #[inline]
    fn round_key(&self, round: usize) -> &[u8] {
        &self.round_keys[round * BLOCK_LEN..(round + 1) * BLOCK_LEN]
    }
}

#[inline]
fn add_round_key(state: &mut [u8; BLOCK_LEN], rk: &[u8]) {
    for i in 0..BLOCK_LEN {
        state[i] ^= rk[i];
    }
}

#[inline]
fn sub_bytes(state: &mut [u8; BLOCK_LEN]) {
    for b in state.iter_mut() {
        *b = gf::sbox(*b);
    }
}

#[inline]
fn inv_sub_bytes(state: &mut [u8; BLOCK_LEN]) {
    for b in state.iter_mut() {
        *b = gf::inv_sbox(*b);
    }
}

/// ShiftRows on the column-major AES state: row `r` rotates left by `r`.
#[inline]
fn shift_rows(s: &mut [u8; BLOCK_LEN]) {
    let t = *s;
    for c in 0..4 {
        for r in 0..4 {
            s[c * 4 + r] = t[((c + r) % 4) * 4 + r];
        }
    }
}

#[inline]
fn inv_shift_rows(s: &mut [u8; BLOCK_LEN]) {
    let t = *s;
    for c in 0..4 {
        for r in 0..4 {
            s[((c + r) % 4) * 4 + r] = t[c * 4 + r];
        }
    }
}

#[inline]
fn mix_columns(s: &mut [u8; BLOCK_LEN]) {
    for c in 0..4 {
        let col = [s[c * 4], s[c * 4 + 1], s[c * 4 + 2], s[c * 4 + 3]];
        s[c * 4] = gf::xtime(col[0]) ^ (gf::xtime(col[1]) ^ col[1]) ^ col[2] ^ col[3];
        s[c * 4 + 1] = col[0] ^ gf::xtime(col[1]) ^ (gf::xtime(col[2]) ^ col[2]) ^ col[3];
        s[c * 4 + 2] = col[0] ^ col[1] ^ gf::xtime(col[2]) ^ (gf::xtime(col[3]) ^ col[3]);
        s[c * 4 + 3] = (gf::xtime(col[0]) ^ col[0]) ^ col[1] ^ col[2] ^ gf::xtime(col[3]);
    }
}

#[inline]
fn inv_mix_columns(s: &mut [u8; BLOCK_LEN]) {
    for c in 0..4 {
        let col = [s[c * 4], s[c * 4 + 1], s[c * 4 + 2], s[c * 4 + 3]];
        s[c * 4] =
            gf::mul(col[0], 14) ^ gf::mul(col[1], 11) ^ gf::mul(col[2], 13) ^ gf::mul(col[3], 9);
        s[c * 4 + 1] =
            gf::mul(col[0], 9) ^ gf::mul(col[1], 14) ^ gf::mul(col[2], 11) ^ gf::mul(col[3], 13);
        s[c * 4 + 2] =
            gf::mul(col[0], 13) ^ gf::mul(col[1], 9) ^ gf::mul(col[2], 14) ^ gf::mul(col[3], 11);
        s[c * 4 + 3] =
            gf::mul(col[0], 11) ^ gf::mul(col[1], 13) ^ gf::mul(col[2], 9) ^ gf::mul(col[3], 14);
    }
}

fn encrypt_with(sched: &Schedule, block: &mut [u8]) -> Result<()> {
    ensure!(block.len() == BLOCK_LEN, InvalidLength, "aes block");
    let mut s = [0u8; BLOCK_LEN];
    s.copy_from_slice(block);
    add_round_key(&mut s, sched.round_key(0));
    for r in 1..sched.rounds {
        sub_bytes(&mut s);
        shift_rows(&mut s);
        mix_columns(&mut s);
        add_round_key(&mut s, sched.round_key(r));
    }
    sub_bytes(&mut s);
    shift_rows(&mut s);
    add_round_key(&mut s, sched.round_key(sched.rounds));
    block.copy_from_slice(&s);
    s.zeroize();
    Ok(())
}

fn decrypt_with(sched: &Schedule, block: &mut [u8]) -> Result<()> {
    ensure!(block.len() == BLOCK_LEN, InvalidLength, "aes block");
    let mut s = [0u8; BLOCK_LEN];
    s.copy_from_slice(block);
    add_round_key(&mut s, sched.round_key(sched.rounds));
    for r in (1..sched.rounds).rev() {
        inv_shift_rows(&mut s);
        inv_sub_bytes(&mut s);
        add_round_key(&mut s, sched.round_key(r));
        inv_mix_columns(&mut s);
    }
    inv_shift_rows(&mut s);
    inv_sub_bytes(&mut s);
    add_round_key(&mut s, sched.round_key(0));
    block.copy_from_slice(&s);
    s.zeroize();
    Ok(())
}

macro_rules! aes_variant {
    ($name:ident, $id:literal, $disp:literal, $keylen:literal, $kat_key:literal, $kat_ct:literal) => {
        #[doc = concat!("FIPS 197 ", $disp, ".")]
        #[derive(Clone)]
        pub struct $name(Schedule);

        impl Algorithm for $name {
            const ID: &'static str = $id;
            const NAME: &'static str = $disp;
        }

        impl BlockCipher for $name {
            const BLOCK_LEN: usize = BLOCK_LEN;
            const KEY_LEN: usize = $keylen;

            fn new(key: &[u8]) -> Result<Self> {
                ensure!(key.len() == $keylen, InvalidLength, $id);
                Ok(Self(Schedule::expand(key)?))
            }

            fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
                encrypt_with(&self.0, block)
            }

            fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
                decrypt_with(&self.0, block)
            }
        }

        impl SelfTest for $name {
            fn self_test() -> Result<()> {
                // FIPS 197 Appendix C: plaintext 00112233..ff.
                let mut key = [0u8; $keylen];
                ac_core::codec::hex_decode($kat_key.as_bytes(), &mut key)?;
                let mut want = [0u8; 16];
                ac_core::codec::hex_decode($kat_ct.as_bytes(), &mut want)?;

                let cipher = <Self as BlockCipher>::new(&key)?;
                let mut block: [u8; 16] = core::array::from_fn(|i| (i * 0x11) as u8);
                cipher.encrypt_block(&mut block)?;
                ensure!(ac_core::ct::verify(&want, &block), SelfTestFailed, $id);

                cipher.decrypt_block(&mut block)?;
                let plain: [u8; 16] = core::array::from_fn(|i| (i * 0x11) as u8);
                ensure!(ac_core::ct::verify(&plain, &block), SelfTestFailed, $id);
                Ok(())
            }
        }
    };
}

aes_variant!(
    Aes128,
    "aes-128",
    "AES-128",
    16,
    "000102030405060708090a0b0c0d0e0f",
    "69c4e0d86a7b0430d8cdb78070b4c55a"
);
aes_variant!(
    Aes192,
    "aes-192",
    "AES-192",
    24,
    "000102030405060708090a0b0c0d0e0f1011121314151617",
    "dda97ca4864cdfe06eaf70a0ec0d7191"
);
aes_variant!(
    Aes256,
    "aes-256",
    "AES-256",
    32,
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
    "8ea2b7ca516745bfeafc49904b496089"
);

#[cfg(test)]
mod tests {
    use super::*;
    use ac_core::codec::{hex, unhex};

    fn enc<C: BlockCipher>(key: &str, pt: &str) -> String {
        let c = C::new(&unhex(key).unwrap()).unwrap();
        let mut b = unhex(pt).unwrap();
        c.encrypt_block(&mut b).unwrap();
        hex(&b)
    }

    #[test]
    fn fips197_appendix_c_vectors() {
        assert_eq!(
            enc::<Aes128>(
                "000102030405060708090a0b0c0d0e0f",
                "00112233445566778899aabbccddeeff"
            ),
            "69c4e0d86a7b0430d8cdb78070b4c55a"
        );
        assert_eq!(
            enc::<Aes192>(
                "000102030405060708090a0b0c0d0e0f1011121314151617",
                "00112233445566778899aabbccddeeff"
            ),
            "dda97ca4864cdfe06eaf70a0ec0d7191"
        );
        assert_eq!(
            enc::<Aes256>(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "00112233445566778899aabbccddeeff"
            ),
            "8ea2b7ca516745bfeafc49904b496089"
        );
    }

    /// NIST SP 800-38A F.1.1 uses this key/block pair; it exercises a schedule
    /// distinct from the FIPS 197 one.
    #[test]
    fn sp800_38a_ecb_vector() {
        assert_eq!(
            enc::<Aes128>(
                "2b7e151628aed2a6abf7158809cf4f3c",
                "6bc1bee22e409f96e93d7e117393172a"
            ),
            "3ad77bb40d7a3660a89ecaf32466ef97"
        );
    }

    #[test]
    fn decryption_inverts_encryption() {
        let key = [0x42u8; 32];
        let c = Aes256::new(&key).unwrap();
        let original: [u8; 16] = core::array::from_fn(|i| (i * 13) as u8);
        let mut block = original;
        c.encrypt_block(&mut block).unwrap();
        assert_ne!(block, original);
        c.decrypt_block(&mut block).unwrap();
        assert_eq!(block, original);
    }

    #[test]
    fn rejects_wrong_key_and_block_lengths() {
        assert!(Aes128::new(&[0u8; 17]).is_err());
        assert!(Aes256::new(&[0u8; 16]).is_err());
        let c = Aes128::new(&[0u8; 16]).unwrap();
        assert!(c.encrypt_block(&mut [0u8; 15]).is_err());
    }

    #[test]
    fn self_tests_pass() {
        Aes128::self_test().unwrap();
        Aes192::self_test().unwrap();
        Aes256::self_test().unwrap();
    }
}
