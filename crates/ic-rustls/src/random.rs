//! Randomness, and the absence of a signing key provider.

use alloc::sync::Arc;

use rustls::crypto::{GetRandomFailed, KeyProvider, SecureRandom};
use rustls::pki_types::PrivateKeyDer;
use rustls::sign::SigningKey;
use rustls::Error;

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

/// A key provider that holds no keys.
///
/// This provider verifies signatures but does not make them, so it cannot load
/// a private key: there is no `SigningKey` implementation behind it. That means
/// it can authenticate a peer -- which is what a client does to a server -- and
/// cannot present a certificate of its own.
///
/// It refuses with a message saying so, rather than returning a key that fails
/// later at a point far from the cause. Combine this provider's verification
/// with another provider's `key_provider` if you need both halves.
#[derive(Debug)]
pub struct NoKeys;

impl KeyProvider for NoKeys {
    fn load_private_key(&self, _key: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        Err(Error::General(
            "ic-rustls verifies signatures but does not produce them: it has no signing key \
             provider, so it cannot present a certificate. Use it for client-side verification, \
             or supply another provider's key_provider alongside it."
                .into(),
        ))
    }

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

    /// Loading a key must fail with an explanation, not a key that fails later.
    #[test]
    fn loading_a_private_key_says_why_it_cannot() {
        // The variant is built directly rather than parsed: the refusal happens
        // before anything looks at the bytes, and `try_from` would reject this
        // for its own reasons and test the wrong thing.
        let der = PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            alloc::vec![0x30u8; 48],
        ));
        let err = NoKeys.load_private_key(der).unwrap_err();
        let text = alloc::format!("{err}");
        assert!(
            text.contains("does not produce them") && text.contains("key_provider"),
            "the refusal does not explain itself: {text}"
        );
    }

    #[test]
    fn neither_claims_fips_validation() {
        assert!(!Random.fips());
        assert!(!NoKeys.fips());
    }
}
