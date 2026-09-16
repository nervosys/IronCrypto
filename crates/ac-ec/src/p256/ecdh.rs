//! SP 800-56A elliptic-curve Diffie-Hellman over P-256.
//!
//! The shared secret is the x-coordinate of `[d]Q`, as SP 800-56A §5.7.1.2
//! specifies. It is **not** a key: it is a uniformly-distributed-ish field
//! element that must go through a KDF before use. The ontology records that as
//! a `serious` constraint, and the example below shows the intended shape.
//!
//! ```
//! use ac_ec::p256::EcdhP256;
//! use ac_core::traits::KeyAgreement;
//! use ac_core::Zeroizing;
//!
//! let (alice_sk, bob_sk) = ([0x11u8; 32], [0x22u8; 32]);
//! let (mut alice_pk, mut bob_pk) = ([0u8; 65], [0u8; 65]);
//! EcdhP256::public_key(&alice_sk, &mut alice_pk)?;
//! EcdhP256::public_key(&bob_sk, &mut bob_pk)?;
//!
//! let mut shared = Zeroizing::new([0u8; 32]);
//! EcdhP256::agree(&alice_sk, &bob_pk, shared.get_mut())?;
//!
//! // `shared` is a curve coordinate, not a key. Derive from it before use:
//! //
//! //     ac_kdf::Hkdf::<ac_mac::HmacSha256>::derive(
//! //         shared.get(), salt, b"app v1", &mut key,
//! //     )?;
//! //
//! // (shown as a comment because `ac-ec` does not depend on `ac-kdf`; the
//! // runnable version lives in the `agentic-crypto` crate docs).
//! # Ok::<(), ac_core::Error>(())
//! ```

use super::arith::Fn;
use super::point::{AffinePoint, Point};
use ac_core::traits::{Algorithm, KeyAgreement, SelfTest};
use ac_core::{ensure, Result, Zeroize};

/// ECDH over P-256.
pub struct EcdhP256;

impl Algorithm for EcdhP256 {
    const ID: &'static str = "ecdh-p256";
    const NAME: &'static str = "ECDH P-256";
}

/// Load and validate a private scalar.
fn load_scalar(bytes: &[u8]) -> Result<Fn> {
    ensure!(bytes.len() == 32, InvalidLength, "p256 private key");
    let mut b = [0u8; 32];
    b.copy_from_slice(bytes);
    let d = Fn::from_bytes(&b).ok_or(ac_core::err!(
        InvalidParameter,
        "p256 private key is not less than n"
    ))?;
    b.zeroize();
    ensure!(
        !bool::from(d.is_zero()),
        InvalidParameter,
        "p256 private key must not be zero"
    );
    Ok(d)
}

impl KeyAgreement for EcdhP256 {
    const PRIVATE_KEY_LEN: usize = 32;
    /// SEC1 uncompressed: `0x04 || X || Y`.
    const PUBLIC_KEY_LEN: usize = 65;
    const SHARED_SECRET_LEN: usize = 32;

    fn public_key(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ensure!(out.len() == 65, InvalidLength, "p256 public key buffer");
        let d = load_scalar(private_key)?;
        let q = Point::generator()
            .mul_scalar(&d)
            .to_affine()
            .ok_or(ac_core::err!(Internal, "public key is the identity"))?;
        out.copy_from_slice(&q.to_uncompressed());
        Ok(())
    }

    fn agree(private_key: &[u8], peer_public_key: &[u8], out: &mut [u8]) -> Result<()> {
        ensure!(out.len() == 32, InvalidLength, "p256 shared secret buffer");
        let d = load_scalar(private_key)?;

        // SP 800-56A full public-key validation: the decoder checks that the
        // point is on the curve and refuses the identity, and P-256 has
        // cofactor 1, so there is no small subgroup left to land in.
        let q = AffinePoint::from_sec1(peer_public_key).ok_or(ac_core::err!(
            InvalidParameter,
            "p256 peer public key is not a valid curve point"
        ))?;

        let shared = Point::from_affine(&q).mul_scalar(&d);
        let affine = shared.to_affine().ok_or(ac_core::err!(
            InvalidParameter,
            "p256 key agreement produced the identity"
        ))?;

        out.copy_from_slice(&affine.x.to_bytes());
        Ok(())
    }
}

impl EcdhP256 {
    /// Compute the public key in SEC1 compressed form (33 bytes).
    ///
    /// Interoperates with TLS, COSE, and JOSE, which all prefer compressed
    /// points. [`KeyAgreement::agree`] accepts either form.
    pub fn public_key_compressed(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ensure!(out.len() == 33, InvalidLength, "p256 compressed key buffer");
        let d = load_scalar(private_key)?;
        let q = Point::generator()
            .mul_scalar(&d)
            .to_affine()
            .ok_or(ac_core::err!(Internal, "public key is the identity"))?;
        out.copy_from_slice(&q.to_compressed());
        Ok(())
    }
}

impl SelfTest for EcdhP256 {
    fn self_test() -> Result<()> {
        // NIST CAVP ECC CDH, P-256, the first published key-agreement case.
        let mut d = [0u8; 32];
        ac_core::codec::hex_decode(
            b"7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
            &mut d,
        )?;
        let mut peer = [0u8; 65];
        peer[0] = 0x04;
        ac_core::codec::hex_decode(
            b"700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
            &mut peer[1..33],
        )?;
        ac_core::codec::hex_decode(
            b"db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
            &mut peer[33..],
        )?;
        let mut want = [0u8; 32];
        ac_core::codec::hex_decode(
            b"46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b",
            &mut want,
        )?;

        let mut got = [0u8; 32];
        <Self as KeyAgreement>::agree(&d, &peer, &mut got)?;
        ensure!(
            ac_core::ct::verify(&want, &got),
            SelfTestFailed,
            "ecdh-p256"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ac_core::codec::{hex, unhex};

    /// NIST CAVP ECC CDH primitive, P-256, first published case.
    ///
    /// This is an external vector for key agreement specifically, independent
    /// of the RFC 6979 vectors that exercise signing.
    #[test]
    fn cavp_ecc_cdh_vector() {
        let d = unhex("7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534").unwrap();
        let mut peer = vec![0x04u8];
        peer.extend_from_slice(
            &unhex("700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287").unwrap(),
        );
        peer.extend_from_slice(
            &unhex("db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac").unwrap(),
        );

        let mut z = [0u8; 32];
        EcdhP256::agree(&d, &peer, &mut z).unwrap();
        assert_eq!(
            hex(&z),
            "46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b"
        );
    }

    #[test]
    fn both_parties_derive_the_same_secret() {
        let alice = [0x11u8; 32];
        let bob = [0x22u8; 32];
        let mut alice_pk = [0u8; 65];
        let mut bob_pk = [0u8; 65];
        EcdhP256::public_key(&alice, &mut alice_pk).unwrap();
        EcdhP256::public_key(&bob, &mut bob_pk).unwrap();

        let mut z1 = [0u8; 32];
        let mut z2 = [0u8; 32];
        EcdhP256::agree(&alice, &bob_pk, &mut z1).unwrap();
        EcdhP256::agree(&bob, &alice_pk, &mut z2).unwrap();
        assert_eq!(z1, z2);
        assert_ne!(z1, [0u8; 32]);
    }

    #[test]
    fn compressed_and_uncompressed_peers_agree() {
        let alice = [0x33u8; 32];
        let bob = [0x44u8; 32];
        let mut bob_uncompressed = [0u8; 65];
        let mut bob_compressed = [0u8; 33];
        EcdhP256::public_key(&bob, &mut bob_uncompressed).unwrap();
        EcdhP256::public_key_compressed(&bob, &mut bob_compressed).unwrap();

        let mut z1 = [0u8; 32];
        let mut z2 = [0u8; 32];
        EcdhP256::agree(&alice, &bob_uncompressed, &mut z1).unwrap();
        EcdhP256::agree(&alice, &bob_compressed, &mut z2).unwrap();
        assert_eq!(z1, z2, "the encoding of the peer key must not matter");
    }

    #[test]
    fn distinct_key_pairs_produce_distinct_secrets() {
        let alice = [0x11u8; 32];
        let mut bob_pk = [0u8; 65];
        let mut carol_pk = [0u8; 65];
        EcdhP256::public_key(&[0x22u8; 32], &mut bob_pk).unwrap();
        EcdhP256::public_key(&[0x23u8; 32], &mut carol_pk).unwrap();

        let mut z1 = [0u8; 32];
        let mut z2 = [0u8; 32];
        EcdhP256::agree(&alice, &bob_pk, &mut z1).unwrap();
        EcdhP256::agree(&alice, &carol_pk, &mut z2).unwrap();
        assert_ne!(z1, z2);
    }

    #[test]
    fn rejects_invalid_peer_keys() {
        let alice = [0x11u8; 32];
        let mut z = [0u8; 32];

        // Not a point at all.
        assert!(
            EcdhP256::agree(&alice, &[0u8; 65], &mut z).is_err(),
            "all zeroes"
        );
        assert!(EcdhP256::agree(&alice, &[], &mut z).is_err(), "empty");
        assert!(
            EcdhP256::agree(&alice, &[4u8; 64], &mut z).is_err(),
            "wrong length"
        );

        // A valid point with one bit flipped is off the curve.
        let mut bob_pk = [0u8; 65];
        EcdhP256::public_key(&[0x22u8; 32], &mut bob_pk).unwrap();
        bob_pk[64] ^= 1;
        assert!(
            EcdhP256::agree(&alice, &bob_pk, &mut z).is_err(),
            "off-curve peer key must be rejected"
        );
    }

    #[test]
    fn rejects_invalid_private_keys() {
        let mut pk = [0u8; 65];
        let mut z = [0u8; 32];
        let mut valid_peer = [0u8; 65];
        EcdhP256::public_key(&[0x22u8; 32], &mut valid_peer).unwrap();

        assert!(EcdhP256::public_key(&[0u8; 32], &mut pk).is_err(), "zero");
        assert!(
            EcdhP256::public_key(&[0xffu8; 32], &mut pk).is_err(),
            ">= n"
        );
        assert!(EcdhP256::public_key(&[1u8; 31], &mut pk).is_err(), "short");
        assert!(EcdhP256::agree(&[0u8; 32], &valid_peer, &mut z).is_err());
    }

    #[test]
    fn rejects_wrong_sized_output_buffers() {
        let mut short = [0u8; 31];
        let mut peer = [0u8; 65];
        EcdhP256::public_key(&[0x22u8; 32], &mut peer).unwrap();
        assert!(EcdhP256::agree(&[0x11u8; 32], &peer, &mut short).is_err());
        assert!(EcdhP256::public_key(&[0x11u8; 32], &mut [0u8; 64]).is_err());
    }

    #[test]
    fn self_test_passes() {
        EcdhP256::self_test().unwrap();
    }
}
