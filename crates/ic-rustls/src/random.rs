//! Randomness.
//!
//! Signing lives in `crate::sign`; this module used to hold a `KeyProvider`
//! that refused every key, and no longer needs to.

use rustls::crypto::{GetRandomFailed, SecureRandom};

/// The SP 800-90A HMAC\_DRBG, seeded from the operating system.
///
/// rustls draws the client and server randoms, session identifiers and ticket
/// nonces through this. A fresh generator per call is deliberate: the
/// alternative is one shared instance behind a lock, which would either
/// serialise every handshake in the process or need care about fork safety that
/// a per-call draw does not.
#[derive(Debug)]
pub struct Random;

impl SecureRandom for Random {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        let mut rng = ic_drbg::Rng::from_os().map_err(|_| GetRandomFailed)?;
        rng.fill(buf).map_err(|_| GetRandomFailed)
    }

    /// Always false; see the crate documentation.
    fn fips(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The generator must generate.
    ///
    /// Two draws being equal would mean a fixed output, which for a client
    /// random is the difference between a handshake and a replay.
    #[test]
    fn the_random_source_produces_fresh_bytes() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        Random.fill(&mut a).unwrap();
        Random.fill(&mut b).unwrap();
        assert_ne!(a, b, "two draws were identical");
        assert_ne!(a, [0u8; 32], "the buffer was left untouched");

        // An empty request is not an error, and a large one is filled.
        Random.fill(&mut []).unwrap();
        let mut big = alloc::vec![0u8; 4096];
        Random.fill(&mut big).unwrap();
        assert!(big.iter().any(|b| *b != 0));
    }

    #[test]
    fn the_random_source_claims_no_fips_validation() {
        assert!(!Random.fips());
    }
}
