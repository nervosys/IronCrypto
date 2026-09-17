//! Key exchange: X25519 and ECDH over P-256 and P-384.
//!
//! The private key lives in the `ActiveKeyExchange` until `complete` consumes
//! it, which is the shape rustls asks for and also the right one: an ephemeral
//! scalar should not outlive the one exchange it was generated for. Each
//! implementation wipes it on drop, so an abandoned exchange -- a handshake
//! that fails after the key share is sent -- does not leave the scalar behind.

use alloc::boxed::Box;
use alloc::vec::Vec;

use ic_core::traits::KeyAgreement as _;
use ic_core::Zeroize;
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup};

pub(crate) static X25519: X25519Group = X25519Group;
pub(crate) static SECP256R1: NistGroup = NistGroup {
    group: NamedGroup::secp256r1,
    scalar_len: 32,
    point_len: 65,
};
pub(crate) static SECP384R1: NistGroup = NistGroup {
    group: NamedGroup::secp384r1,
    scalar_len: 48,
    point_len: 97,
};

/// Draw an ephemeral scalar from the OS-seeded DRBG.
fn random_scalar(len: usize) -> Result<Vec<u8>, Error> {
    let mut rng = ic_drbg::Rng::from_os()
        .map_err(|_| Error::General("the operating system entropy source failed".into()))?;
    let mut scalar = alloc::vec![0u8; len];
    rng.fill(&mut scalar)
        .map_err(|_| Error::General("the drbg failed to generate a scalar".into()))?;
    Ok(scalar)
}

// ---------------------------------------------------------------------------
// X25519
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) struct X25519Group;

impl SupportedKxGroup for X25519Group {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = random_scalar(32)?;
        let mut public = [0u8; 32];
        ic_ec::X25519::public_key(&secret, &mut public)
            .map_err(|_| Error::General("x25519 public key derivation failed".into()))?;
        Ok(Box::new(X25519Exchange {
            secret,
            public: public.to_vec(),
        }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }

    fn fips(&self) -> bool {
        false
    }
}

struct X25519Exchange {
    secret: Vec<u8>,
    public: Vec<u8>,
}

impl Drop for X25519Exchange {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl ActiveKeyExchange for X25519Exchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let mut shared = [0u8; 32];
        // `agree` rejects the low-order points, which drive the shared secret
        // to zero whatever the private key is. RFC 7748 section 6.1 permits
        // either accepting or rejecting them; rejecting is what a TLS stack
        // wants, since a peer offering one is not doing key agreement.
        ic_ec::X25519::agree(&self.secret, peer, &mut shared)
            .map_err(|_| Error::PeerMisbehaved(rustls::PeerMisbehaved::InvalidKeyShare))?;
        Ok(SharedSecret::from(&shared[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

// ---------------------------------------------------------------------------
// The NIST curves
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) struct NistGroup {
    group: NamedGroup,
    scalar_len: usize,
    point_len: usize,
}

impl SupportedKxGroup for NistGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        // A scalar must be in [1, n-1]. Rejection sampling rather than
        // reduction, because reducing a uniform value modulo n biases the
        // result towards the low end of the range.
        for _ in 0..64 {
            let secret = random_scalar(self.scalar_len)?;
            let mut public = alloc::vec![0u8; self.point_len];
            let derived = match self.group {
                NamedGroup::secp256r1 => ic_ec::p256::EcdhP256::public_key(&secret, &mut public),
                NamedGroup::secp384r1 => ic_ec::p384::EcdhP384::public_key(&secret, &mut public),
                _ => return Err(Error::General("unsupported curve".into())),
            };
            if derived.is_ok() {
                return Ok(Box::new(NistExchange {
                    group: self.group,
                    secret,
                    public,
                }));
            }
        }
        // 64 consecutive rejections is not bad luck. For P-256 the chance a
        // uniform 32-byte value is out of range is about 2^-32 per draw, so
        // this means the generator is not producing what it should.
        Err(Error::General(
            "could not draw a valid scalar; the generator is suspect".into(),
        ))
    }

    fn name(&self) -> NamedGroup {
        self.group
    }

    fn fips(&self) -> bool {
        false
    }
}

struct NistExchange {
    group: NamedGroup,
    secret: Vec<u8>,
    public: Vec<u8>,
}

impl Drop for NistExchange {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl ActiveKeyExchange for NistExchange {
    fn complete(self: Box<Self>, peer: &[u8]) -> Result<SharedSecret, Error> {
        let mut shared = alloc::vec![0u8; self.secret.len()];
        // The peer's point is validated against the curve equation inside
        // `agree`. Skipping that is the invalid-curve attack, which recovers
        // the private scalar a few bits at a time from a point on a weaker
        // curve sharing the same `a` coefficient.
        let agreed = match self.group {
            NamedGroup::secp256r1 => ic_ec::p256::EcdhP256::agree(&self.secret, peer, &mut shared),
            NamedGroup::secp384r1 => ic_ec::p384::EcdhP384::agree(&self.secret, peer, &mut shared),
            _ => return Err(Error::General("unsupported curve".into())),
        };
        agreed.map_err(|_| Error::PeerMisbehaved(rustls::PeerMisbehaved::InvalidKeyShare))?;

        let out = SharedSecret::from(&shared[..]);
        shared.zeroize();
        Ok(out)
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        self.group
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two exchanges must agree, and that is the whole point of the module.
    #[test]
    fn each_group_agrees_with_itself() {
        for group in [
            &X25519 as &dyn SupportedKxGroup,
            &SECP256R1 as &dyn SupportedKxGroup,
            &SECP384R1 as &dyn SupportedKxGroup,
        ] {
            let a = group.start().unwrap();
            let b = group.start().unwrap();
            let a_pub = a.pub_key().to_vec();
            let b_pub = b.pub_key().to_vec();

            let a_secret = a.complete(&b_pub).unwrap();
            let b_secret = b.complete(&a_pub).unwrap();
            assert_eq!(
                a_secret.secret_bytes(),
                b_secret.secret_bytes(),
                "{:?} did not agree with itself",
                group.name()
            );
            assert!(!a_secret.secret_bytes().is_empty());
        }
    }

    /// Two independent exchanges must not produce the same secret, or the
    /// generator is not generating.
    #[test]
    fn separate_exchanges_produce_separate_secrets() {
        let g = &SECP256R1 as &dyn SupportedKxGroup;
        let peer = g.start().unwrap();
        let peer_pub = peer.pub_key().to_vec();

        let one = g.start().unwrap().complete(&peer_pub).unwrap();
        let two = g.start().unwrap().complete(&peer_pub).unwrap();
        assert_ne!(one.secret_bytes(), two.secret_bytes());
    }

    /// A peer key that is not on the curve must be refused, not agreed with.
    #[test]
    fn a_hostile_peer_key_is_refused() {
        for group in [
            &SECP256R1 as &dyn SupportedKxGroup,
            &SECP384R1 as &dyn SupportedKxGroup,
        ] {
            let ours = group.start().unwrap();
            let len = ours.pub_key().len();

            // Right length, uncompressed marker, coordinates that do not
            // satisfy the curve equation.
            let mut bad = alloc::vec![0xAAu8; len];
            bad[0] = 0x04;
            assert!(
                group.start().unwrap().complete(&bad).is_err(),
                "{:?} accepted an off-curve point",
                group.name()
            );

            // And a length nothing could be.
            assert!(group.start().unwrap().complete(&[]).is_err());
            assert!(group.start().unwrap().complete(&[0x04]).is_err());
        }

        // X25519 takes any 32 bytes as a u-coordinate by design, but must
        // refuse the low-order ones: they force the shared secret to zero.
        let low_order = [0u8; 32];
        assert!(X25519.start().unwrap().complete(&low_order).is_err());
        assert!(X25519.start().unwrap().complete(&[]).is_err());
    }

    #[test]
    fn the_groups_name_themselves_correctly() {
        assert_eq!(X25519.name(), NamedGroup::X25519);
        assert_eq!(SECP256R1.name(), NamedGroup::secp256r1);
        assert_eq!(SECP384R1.name(), NamedGroup::secp384r1);
    }

    #[test]
    fn no_group_claims_fips_validation() {
        assert!(!X25519.fips());
        assert!(!SECP256R1.fips());
        assert!(!SECP384R1.fips());
    }
}
