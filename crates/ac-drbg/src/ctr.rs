//! SP 800-90A CTR_DRBG over AES-256, without a derivation function.
//!
//! "Without a derivation function" means the caller must supply full-entropy
//! seed material of exactly [`SEED_LEN`] bytes. That is the right shape when
//! entropy comes from a conditioned SP 800-90B source, and it is the variant
//! with the least machinery to get wrong. Callers holding non-uniform entropy
//! should use [`HmacDrbg`][crate::HmacDrbg] instead, which conditions its own
//! input.

use ac_cipher::aes::{Aes256, BLOCK_LEN};
use ac_core::traits::{Algorithm, BlockCipher, Drbg, SelfTest};
use ac_core::{ensure, Result, Zeroize};

/// AES-256 key length in bytes.
const KEY_LEN: usize = 32;

/// Seed length: key length plus block length, per SP 800-90A Table 3.
pub const SEED_LEN: usize = KEY_LEN + BLOCK_LEN;

/// CTR_DRBG instantiated with AES-256.
pub struct CtrDrbg {
    key: [u8; KEY_LEN],
    v: [u8; BLOCK_LEN],
    reseed_counter: u64,
}

impl Drop for CtrDrbg {
    fn drop(&mut self) {
        self.key.zeroize();
        self.v.zeroize();
    }
}

impl CtrDrbg {
    /// The SP 800-90A `CTR_DRBG_Update` process.
    fn update(&mut self, provided: &[u8; SEED_LEN]) -> Result<()> {
        let cipher = Aes256::new(&self.key)?;
        let mut temp = [0u8; SEED_LEN];

        for chunk in temp.chunks_mut(BLOCK_LEN) {
            increment(&mut self.v);
            let mut block = self.v;
            cipher.encrypt_block(&mut block)?;
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        for i in 0..SEED_LEN {
            temp[i] ^= provided[i];
        }

        self.key.copy_from_slice(&temp[..KEY_LEN]);
        self.v.copy_from_slice(&temp[KEY_LEN..]);
        temp.zeroize();
        Ok(())
    }

    /// Number of generate calls made since the last reseed.
    pub fn reseed_counter(&self) -> u64 {
        self.reseed_counter
    }

    /// Combine entropy with an optional personalization or additional string.
    fn seed_material(entropy: &[u8], extra: &[u8]) -> Result<[u8; SEED_LEN]> {
        ensure!(
            entropy.len() == SEED_LEN,
            InvalidLength,
            "ctr_drbg without a derivation function needs exactly 48 bytes of entropy"
        );
        ensure!(
            extra.len() <= SEED_LEN,
            InvalidLength,
            "ctr_drbg personalization exceeds the seed length"
        );
        let mut material = [0u8; SEED_LEN];
        material.copy_from_slice(entropy);
        // Shorter strings are right-padded with zeroes, per SP 800-90A §10.2.1.3.1.
        for (i, b) in extra.iter().enumerate() {
            material[i] ^= b;
        }
        Ok(material)
    }
}

/// Increment a 128-bit big-endian counter block.
fn increment(v: &mut [u8; BLOCK_LEN]) {
    for byte in v.iter_mut().rev() {
        let (n, carry) = byte.overflowing_add(1);
        *byte = n;
        if !carry {
            break;
        }
    }
}

impl Algorithm for CtrDrbg {
    const ID: &'static str = "ctr-drbg-aes-256";
    const NAME: &'static str = "CTR_DRBG(AES-256, no df)";
}

impl Drbg for CtrDrbg {
    fn instantiate(entropy: &[u8], nonce: &[u8], personalization: &[u8]) -> Result<Self> {
        // Without a derivation function the nonce is folded into the
        // personalization string; the spec requires the caller's entropy input
        // to already carry full entropy.
        ensure!(
            nonce.is_empty() || personalization.is_empty(),
            InvalidParameter,
            "ctr_drbg without a derivation function accepts a nonce or a personalization string, not both"
        );
        let extra = if personalization.is_empty() {
            nonce
        } else {
            personalization
        };
        let mut material = Self::seed_material(entropy, extra)?;

        let mut state = Self {
            key: [0u8; KEY_LEN],
            v: [0u8; BLOCK_LEN],
            reseed_counter: 1,
        };
        state.update(&material)?;
        material.zeroize();
        Ok(state)
    }

    fn reseed(&mut self, entropy: &[u8], additional: &[u8]) -> Result<()> {
        let mut material = Self::seed_material(entropy, additional)?;
        self.update(&material)?;
        material.zeroize();
        self.reseed_counter = 1;
        Ok(())
    }

    fn generate(&mut self, additional: &[u8], out: &mut [u8]) -> Result<()> {
        ensure!(
            self.reseed_counter <= crate::RESEED_INTERVAL,
            CounterExhausted,
            "drbg reseed interval exceeded; reseed before generating"
        );
        ensure!(
            additional.len() <= SEED_LEN,
            InvalidLength,
            "ctr_drbg additional input exceeds the seed length"
        );

        let mut extra = [0u8; SEED_LEN];
        extra[..additional.len()].copy_from_slice(additional);
        if !additional.is_empty() {
            self.update(&extra)?;
        }

        let cipher = Aes256::new(&self.key)?;
        for chunk in out.chunks_mut(BLOCK_LEN) {
            increment(&mut self.v);
            let mut block = self.v;
            cipher.encrypt_block(&mut block)?;
            chunk.copy_from_slice(&block[..chunk.len()]);
            block.zeroize();
        }

        self.update(&extra)?;
        extra.zeroize();
        self.reseed_counter = self.reseed_counter.saturating_add(1);
        Ok(())
    }
}

impl SelfTest for CtrDrbg {
    fn self_test() -> Result<()> {
        let entropy = [0x01u8; SEED_LEN];
        let mut d = <Self as Drbg>::instantiate(&entropy, &[], &[])?;
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        d.generate(&[], &mut a)?;
        d.generate(&[], &mut b)?;
        ensure!(a != [0u8; 64], SelfTestFailed, "ctr-drbg-aes-256");
        ensure!(a != b, SelfTestFailed, "ctr-drbg-aes-256");

        // The same seed must reproduce the same stream.
        let mut e = <Self as Drbg>::instantiate(&entropy, &[], &[])?;
        let mut c = [0u8; 64];
        e.generate(&[], &mut c)?;
        ensure!(
            ac_core::ct::verify(&a, &c),
            SelfTestFailed,
            "ctr-drbg-aes-256"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instantiate() -> CtrDrbg {
        CtrDrbg::instantiate(&[0x2Au8; SEED_LEN], &[], &[]).unwrap()
    }

    #[test]
    fn is_deterministic_for_identical_seeds() {
        let mut a = instantiate();
        let mut b = instantiate();
        let mut x = [0u8; 80];
        let mut y = [0u8; 80];
        a.generate(&[], &mut x).unwrap();
        b.generate(&[], &mut y).unwrap();
        assert_eq!(x, y);
    }

    #[test]
    fn successive_outputs_differ() {
        let mut d = instantiate();
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        d.generate(&[], &mut a).unwrap();
        d.generate(&[], &mut b).unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn personalization_changes_the_stream() {
        let mut a = instantiate();
        let mut b = CtrDrbg::instantiate(&[0x2Au8; SEED_LEN], &[], b"app").unwrap();
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        a.generate(&[], &mut x).unwrap();
        b.generate(&[], &mut y).unwrap();
        assert_ne!(x, y);
    }

    #[test]
    fn additional_input_changes_the_stream() {
        let mut a = instantiate();
        let mut b = instantiate();
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        a.generate(b"extra", &mut x).unwrap();
        b.generate(&[], &mut y).unwrap();
        assert_ne!(x, y);
    }

    #[test]
    fn reseed_resets_the_counter_and_diverges() {
        let mut d = instantiate();
        let mut before = [0u8; 32];
        d.generate(&[], &mut before).unwrap();
        d.reseed(&[0xFFu8; SEED_LEN], &[]).unwrap();
        assert_eq!(d.reseed_counter(), 1);
        let mut after = [0u8; 32];
        d.generate(&[], &mut after).unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn partial_final_block_is_handled() {
        let mut d = instantiate();
        let mut out = [0u8; 37];
        d.generate(&[], &mut out).unwrap();
        assert_ne!(out, [0u8; 37]);
    }

    #[test]
    fn counter_increments_with_carry() {
        let mut v = [0xFFu8; BLOCK_LEN];
        increment(&mut v);
        assert_eq!(v, [0u8; BLOCK_LEN]);
        let mut v = [0u8; BLOCK_LEN];
        v[BLOCK_LEN - 1] = 0xFF;
        increment(&mut v);
        assert_eq!(v[BLOCK_LEN - 2], 1);
        assert_eq!(v[BLOCK_LEN - 1], 0);
    }

    #[test]
    fn rejects_wrong_sized_entropy_and_oversized_inputs() {
        assert!(CtrDrbg::instantiate(&[0u8; 32], &[], &[]).is_err());
        assert!(CtrDrbg::instantiate(&[0u8; SEED_LEN], b"n", b"p").is_err());
        let mut d = instantiate();
        assert!(d.generate(&[0u8; SEED_LEN + 1], &mut [0u8; 8]).is_err());
    }

    #[test]
    fn refuses_to_generate_past_the_reseed_interval() {
        let mut d = instantiate();
        d.reseed_counter = crate::RESEED_INTERVAL + 1;
        assert!(d.generate(&[], &mut [0u8; 8]).is_err());
    }

    #[test]
    fn self_test_passes() {
        CtrDrbg::self_test().unwrap();
    }
}
