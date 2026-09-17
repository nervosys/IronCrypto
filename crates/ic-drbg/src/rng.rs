//! An OS-seeded, self-reseeding random number generator.
//!
//! This is the generator every other crate should reach for. It owns an
//! [`HmacDrbg`] seeded from [`ic_core::entropy`], tracks the reseed interval,
//! and pulls fresh entropy automatically when the interval is reached — so the
//! `CounterExhausted` failure mode never surfaces to ordinary callers.

use crate::{HmacDrbgSha256, MIN_ENTROPY_LEN};
use ic_core::traits::{Drbg, RandomSource};
use ic_core::{Result, Zeroize};

/// A ready-to-use CSPRNG: OS entropy in, approved DRBG output out.
pub struct Rng {
    drbg: HmacDrbgSha256,
    calls_since_reseed: u64,
}

impl Rng {
    /// Seed a generator from the operating system entropy source.
    ///
    /// Draws a 48-byte entropy input and a 16-byte nonce, matching the
    /// SP 800-90A requirement of `3/2 * security_strength` bits of entropy for
    /// a 256-bit instantiation.
    pub fn from_os() -> Result<Self> {
        let mut seed = [0u8; 48];
        let mut nonce = [0u8; 16];
        ic_core::entropy::fill(&mut seed)?;
        ic_core::entropy::fill(&mut nonce)?;
        let drbg = HmacDrbgSha256::instantiate(&seed, &nonce, b"IronCrypto/Rng")?;
        seed.zeroize();
        nonce.zeroize();
        Ok(Self {
            drbg,
            calls_since_reseed: 0,
        })
    }

    /// Seed a generator from caller-supplied entropy.
    ///
    /// Use this on platforms with no OS backend, or when entropy comes from a
    /// hardware source the library does not know about. `entropy` must carry at
    /// least 256 bits of real entropy.
    pub fn from_entropy(entropy: &[u8], personalization: &[u8]) -> Result<Self> {
        let drbg = HmacDrbgSha256::instantiate(entropy, &[], personalization)?;
        Ok(Self {
            drbg,
            calls_since_reseed: 0,
        })
    }

    /// Fill `out` with random bytes, reseeding from the OS when due.
    pub fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        // Reseed well before the DRBG's own hard limit so the interval is a
        // maintenance event, not an error path.
        if self.calls_since_reseed >= crate::RESEED_INTERVAL / 2 {
            self.reseed_from_os()?;
        }
        self.calls_since_reseed = self.calls_since_reseed.saturating_add(1);
        self.drbg.generate(&[], out)
    }

    /// Generate a fixed-size array of random bytes.
    pub fn random_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        self.fill(&mut out)?;
        Ok(out)
    }

    /// Pull fresh entropy from the OS and reseed.
    pub fn reseed_from_os(&mut self) -> Result<()> {
        let mut seed = [0u8; MIN_ENTROPY_LEN];
        ic_core::entropy::fill(&mut seed)?;
        let r = self.drbg.reseed(&seed, b"");
        seed.zeroize();
        r?;
        self.calls_since_reseed = 0;
        Ok(())
    }
}

impl RandomSource for Rng {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        Rng::fill(self, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn produces_distinct_nonzero_output() {
        let mut rng = Rng::from_os().unwrap();
        let a: [u8; 32] = rng.random_array().unwrap();
        let b: [u8; 32] = rng.random_array().unwrap();
        assert_ne!(a, [0u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn two_generators_diverge() {
        let mut a = Rng::from_os().unwrap();
        let mut b = Rng::from_os().unwrap();
        let x: [u8; 32] = a.random_array().unwrap();
        let y: [u8; 32] = b.random_array().unwrap();
        assert_ne!(x, y, "independently seeded generators must not agree");
    }

    #[test]
    fn manual_seeding_is_reproducible() {
        let mut a = Rng::from_entropy(&[0x11u8; 32], b"ctx").unwrap();
        let mut b = Rng::from_entropy(&[0x11u8; 32], b"ctx").unwrap();
        let x: [u8; 32] = a.random_array().unwrap();
        let y: [u8; 32] = b.random_array().unwrap();
        assert_eq!(x, y);
    }

    #[test]
    fn reseeding_diverges_the_stream() {
        let mut rng = Rng::from_entropy(&[0x22u8; 32], b"ctx").unwrap();
        let before: [u8; 32] = rng.random_array().unwrap();
        rng.reseed_from_os().unwrap();
        let after: [u8; 32] = rng.random_array().unwrap();
        assert_ne!(before, after);
    }

    #[test]
    fn rejects_insufficient_entropy() {
        assert!(Rng::from_entropy(&[0u8; 8], b"").is_err());
    }
}
