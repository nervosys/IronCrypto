//! FIPS 186-5 ECDSA over P-256 with SHA-256.
//!
//! # Deterministic nonces
//!
//! ECDSA's notorious failure mode is the signing nonce `k`: reuse it across two
//! signatures, or let an attacker predict a few bits, and the private key falls
//! out by simple algebra. This has broken real systems repeatedly (the PS3, and
//! several Bitcoin wallets).
//!
//! Signing here derives `k` deterministically from the private key and the
//! message, per [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979). There is no
//! RNG in the signing path, so there is no entropy failure that can produce a
//! repeated nonce — the same class of protection Ed25519 gets by construction.
//! It also makes signatures reproducible, which is why the RFC's published
//! vectors can serve as known-answer tests for the whole stack beneath.

use super::arith::{Fn, Fp};
use super::point::{AffinePoint, Point};
use ac_core::traits::{Algorithm, Digest, Mac, SelfTest, SignatureScheme};
use ac_core::{ensure, Result, Zeroize};
use ac_hash::Sha256;
use ac_mac::HmacSha256;

/// ECDSA over P-256 with SHA-256.
pub struct EcdsaP256Sha256;

impl Algorithm for EcdsaP256Sha256 {
    const ID: &'static str = "ecdsa-p256-sha256";
    const NAME: &'static str = "ECDSA P-256 with SHA-256";
}

/// Derive the RFC 6979 nonce for a given attempt.
///
/// The `K`/`V` state machine is run from scratch and advanced `attempt` times,
/// so a rejected candidate (`r == 0` or `s == 0`) moves to the next one exactly
/// as the RFC specifies. Those rejections have probability around 2^-128, so
/// the loop effectively never runs twice; it exists for correctness, not speed.
fn rfc6979_nonce(private_key: &[u8; 32], h1: &[u8; 32], attempt: usize) -> Result<Fn> {
    // bits2octets(h1): reduce the hash modulo n, then re-encode.
    let e_octets = Fn::from_bytes_reduced(h1).to_bytes();

    let mut v = [0x01u8; 32];
    let mut k = [0x00u8; 32];

    // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    let mut mac = HmacSha256::new(&k)?;
    mac.update(&v);
    mac.update(&[0x00]);
    mac.update(private_key);
    mac.update(&e_octets);
    k = mac.finalize();
    v = HmacSha256::mac(&k, &v)?;

    // K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    let mut mac = HmacSha256::new(&k)?;
    mac.update(&v);
    mac.update(&[0x01]);
    mac.update(private_key);
    mac.update(&e_octets);
    k = mac.finalize();
    v = HmacSha256::mac(&k, &v)?;

    let mut candidate = Fn::ZERO;
    let mut found = 0usize;
    // Bounded so a pathological key cannot spin forever.
    for _ in 0..(attempt + 1) * 8 + 16 {
        // T = HMAC_K(V), which is exactly qlen bits for P-256 with SHA-256.
        v = HmacSha256::mac(&k, &v)?;

        // Accept only a canonical, non-zero scalar.
        if let Some(t) = Fn::from_bytes(&v) {
            if !bool::from(t.is_zero()) {
                if found == attempt {
                    candidate = t;
                    k.zeroize();
                    v.zeroize();
                    return Ok(candidate);
                }
                found += 1;
            }
        }

        // K = HMAC_K(V || 0x00); V = HMAC_K(V)
        let mut mac = HmacSha256::new(&k)?;
        mac.update(&v);
        mac.update(&[0x00]);
        k = mac.finalize();
        v = HmacSha256::mac(&k, &v)?;
    }

    k.zeroize();
    v.zeroize();
    let _ = candidate;
    Err(ac_core::err!(
        Internal,
        "rfc6979 nonce generation did not converge"
    ))
}

/// Load a private key, rejecting zero and anything at or above `n`.
fn load_private_key(bytes: &[u8]) -> Result<(Fn, [u8; 32])> {
    ensure!(bytes.len() == 32, InvalidLength, "p256 private key");
    let mut b = [0u8; 32];
    b.copy_from_slice(bytes);
    let d = Fn::from_bytes(&b).ok_or(ac_core::err!(
        InvalidParameter,
        "p256 private key is not less than n"
    ))?;
    ensure!(
        !bool::from(d.is_zero()),
        InvalidParameter,
        "p256 private key must not be zero"
    );
    Ok((d, b))
}

/// Reduce a field element into the scalar ring by way of its encoding.
fn field_to_scalar(x: &Fp) -> Fn {
    Fn::from_bytes_reduced(&x.to_bytes())
}

impl SignatureScheme for EcdsaP256Sha256 {
    const PRIVATE_KEY_LEN: usize = 32;
    /// SEC1 uncompressed: `0x04 || X || Y`.
    const PUBLIC_KEY_LEN: usize = 65;
    /// Fixed-width `r || s`.
    const SIGNATURE_LEN: usize = 64;

    fn public_key(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ensure!(out.len() == 65, InvalidLength, "p256 public key buffer");
        let (d, mut raw) = load_private_key(private_key)?;
        let q = Point::generator()
            .mul_scalar(&d)
            .to_affine()
            .ok_or(ac_core::err!(Internal, "public key is the identity"))?;
        out.copy_from_slice(&q.to_uncompressed());
        raw.zeroize();
        Ok(())
    }

    fn sign(private_key: &[u8], message: &[u8], signature: &mut [u8]) -> Result<()> {
        ensure!(
            signature.len() == 64,
            InvalidLength,
            "p256 signature buffer"
        );
        let (d, mut raw) = load_private_key(private_key)?;

        let digest = Sha256::digest(message);
        let mut h1 = [0u8; 32];
        h1.copy_from_slice(digest.as_ref());
        let e = Fn::from_bytes_reduced(&h1);

        // Both rejections below have negligible probability; the loop is here
        // so that "negligible" never becomes "silently wrong".
        for attempt in 0..8 {
            let k = rfc6979_nonce(&raw, &h1, attempt)?;

            let point = Point::generator()
                .mul_scalar(&k)
                .to_affine()
                .ok_or(ac_core::err!(Internal, "kG is the identity"))?;
            let r = field_to_scalar(&point.x);
            if bool::from(r.is_zero()) {
                continue;
            }

            // s = k^-1 (e + r*d)
            let s = k.invert().mul(&e.add(&r.mul(&d)));
            if bool::from(s.is_zero()) {
                continue;
            }

            signature[..32].copy_from_slice(&r.to_bytes());
            signature[32..].copy_from_slice(&s.to_bytes());
            raw.zeroize();
            return Ok(());
        }

        raw.zeroize();
        Err(ac_core::err!(Internal, "ecdsa signing did not converge"))
    }

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        ensure!(signature.len() == 64, InvalidLength, "p256 signature");

        let q = AffinePoint::from_sec1(public_key).ok_or(ac_core::err!(
            MalformedEncoding,
            "p256 public key is not a curve point"
        ))?;

        let mut rb = [0u8; 32];
        let mut sb = [0u8; 32];
        rb.copy_from_slice(&signature[..32]);
        sb.copy_from_slice(&signature[32..]);

        // r and s must both be canonical and non-zero. A non-canonical encoding
        // is rejected rather than reduced, so a signature has exactly one valid
        // byte representation.
        let r = Fn::from_bytes(&rb).ok_or(ac_core::err!(
            MalformedEncoding,
            "ecdsa r is not less than n"
        ))?;
        let s = Fn::from_bytes(&sb).ok_or(ac_core::err!(
            MalformedEncoding,
            "ecdsa s is not less than n"
        ))?;
        ensure!(
            !bool::from(r.is_zero()) && !bool::from(s.is_zero()),
            MalformedEncoding,
            "ecdsa r and s must be non-zero"
        );

        let digest = Sha256::digest(message);
        let mut h1 = [0u8; 32];
        h1.copy_from_slice(digest.as_ref());
        let e = Fn::from_bytes_reduced(&h1);

        let w = s.invert();
        let u1 = e.mul(&w);
        let u2 = r.mul(&w);

        let point = Point::mul_double(&u1, &Point::from_affine(&q), &u2);
        let affine = point
            .to_affine()
            .ok_or(ac_core::err!(AuthenticationFailed, "ecdsa-p256-sha256"))?;

        let v = field_to_scalar(&affine.x);
        if bool::from(v.ct_eq(&r)) {
            Ok(())
        } else {
            Err(ac_core::err!(AuthenticationFailed, "ecdsa-p256-sha256"))
        }
    }
}

impl EcdsaP256Sha256 {
    /// Rewrite a signature to its low-`s` form, if it is not already.
    ///
    /// ECDSA is malleable: `(r, s)` and `(r, n - s)` are both valid for the
    /// same message, so a signature is not a unique identifier unless one form
    /// is chosen. FIPS 186-5 and RFC 6979 accept both, and this library signs
    /// and verifies per the standard, so normalization is offered rather than
    /// imposed — apply it when a signature doubles as a database key or a
    /// transaction id.
    pub fn normalize_s(signature: &mut [u8]) -> Result<()> {
        ensure!(signature.len() == 64, InvalidLength, "p256 signature");
        let mut sb = [0u8; 32];
        sb.copy_from_slice(&signature[32..]);
        let s = Fn::from_bytes(&sb).ok_or(ac_core::err!(
            MalformedEncoding,
            "ecdsa s is not less than n"
        ))?;

        if Self::is_high_s(&s) {
            signature[32..].copy_from_slice(&Fn::ZERO.sub(&s).to_bytes());
        }
        Ok(())
    }

    /// Whether `s > n/2`.
    fn is_high_s(s: &Fn) -> bool {
        let limbs = s.from_mont();
        // n/2, computed by shifting the modulus right one bit.
        let n = Fn::MODULUS;
        let half = [
            (n[0] >> 1) | (n[1] << 63),
            (n[1] >> 1) | (n[2] << 63),
            (n[2] >> 1) | (n[3] << 63),
            n[3] >> 1,
        ];
        // s > half, by comparing from the top limb down. Both operands are
        // public in every context where this is called.
        for i in (0..4).rev() {
            if limbs[i] != half[i] {
                return limbs[i] > half[i];
            }
        }
        false
    }

    /// Whether a signature is already in low-`s` form.
    pub fn has_low_s(signature: &[u8]) -> Result<bool> {
        ensure!(signature.len() == 64, InvalidLength, "p256 signature");
        let mut sb = [0u8; 32];
        sb.copy_from_slice(&signature[32..]);
        let s = Fn::from_bytes(&sb).ok_or(ac_core::err!(
            MalformedEncoding,
            "ecdsa s is not less than n"
        ))?;
        Ok(!Self::is_high_s(&s))
    }
}

impl SelfTest for EcdsaP256Sha256 {
    fn self_test() -> Result<()> {
        // RFC 6979 A.2.5: P-256, SHA-256, message "sample".
        let mut key = [0u8; 32];
        ac_core::codec::hex_decode(
            b"c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
            &mut key,
        )?;
        let mut want = [0u8; 64];
        ac_core::codec::hex_decode(
            b"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716\
              f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
            &mut want,
        )?;

        let mut sig = [0u8; 64];
        <Self as SignatureScheme>::sign(&key, b"sample", &mut sig)?;
        ensure!(
            ac_core::ct::verify(&want, &sig),
            SelfTestFailed,
            "ecdsa-p256-sha256"
        );

        let mut pk = [0u8; 65];
        <Self as SignatureScheme>::public_key(&key, &mut pk)?;
        <Self as SignatureScheme>::verify(&pk, b"sample", &sig)?;

        // A flipped bit must be rejected.
        sig[0] ^= 1;
        ensure!(
            <Self as SignatureScheme>::verify(&pk, b"sample", &sig).is_err(),
            SelfTestFailed,
            "ecdsa-p256-sha256"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ac_core::codec::{hex, unhex};

    /// The RFC 6979 A.2.5 private key.
    const KEY: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";

    /// RFC 6979 A.2.5, message "sample".
    ///
    /// Matching this exercises the field, the group law, the scalar ring, the
    /// nonce derivation, and the signing equation in one shot: any error in any
    /// of them produces a different signature.
    #[test]
    fn rfc6979_sample_vector() {
        let key = unhex(KEY).unwrap();
        let mut sig = [0u8; 64];
        EcdsaP256Sha256::sign(&key, b"sample", &mut sig).unwrap();
        assert_eq!(
            hex(&sig[..32]),
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
            "r"
        );
        assert_eq!(
            hex(&sig[32..]),
            "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
            "s"
        );
    }

    /// RFC 6979 A.2.5, message "test".
    #[test]
    fn rfc6979_test_vector() {
        let key = unhex(KEY).unwrap();
        let mut sig = [0u8; 64];
        EcdsaP256Sha256::sign(&key, b"test", &mut sig).unwrap();
        assert_eq!(
            hex(&sig[..32]),
            "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367",
            "r"
        );
        assert_eq!(
            hex(&sig[32..]),
            "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
            "s"
        );
    }

    /// The public key published alongside the RFC 6979 vectors.
    #[test]
    fn rfc6979_public_key() {
        let key = unhex(KEY).unwrap();
        let mut pk = [0u8; 65];
        EcdsaP256Sha256::public_key(&key, &mut pk).unwrap();
        assert_eq!(pk[0], 0x04);
        assert_eq!(
            hex(&pk[1..33]),
            "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6",
            "Ux"
        );
        assert_eq!(
            hex(&pk[33..]),
            "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
            "Uy"
        );
    }

    #[test]
    fn signing_is_deterministic() {
        let key = unhex(KEY).unwrap();
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        EcdsaP256Sha256::sign(&key, b"same message", &mut a).unwrap();
        EcdsaP256Sha256::sign(&key, b"same message", &mut b).unwrap();
        assert_eq!(a, b, "RFC 6979 signing must not depend on an RNG");
    }

    #[test]
    fn different_messages_use_different_nonces() {
        let key = unhex(KEY).unwrap();
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        EcdsaP256Sha256::sign(&key, b"message one", &mut a).unwrap();
        EcdsaP256Sha256::sign(&key, b"message two", &mut b).unwrap();
        // A shared nonce would produce an identical r, and leak the key.
        assert_ne!(&a[..32], &b[..32], "r must differ between messages");
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let key = unhex(KEY).unwrap();
        let mut pk = [0u8; 65];
        EcdsaP256Sha256::public_key(&key, &mut pk).unwrap();

        for message in [&b""[..], b"short", &[0x5au8; 1000][..]] {
            let mut sig = [0u8; 64];
            EcdsaP256Sha256::sign(&key, message, &mut sig).unwrap();
            EcdsaP256Sha256::verify(&pk, message, &sig).unwrap();
        }
    }

    #[test]
    fn verification_rejects_tampering() {
        let key = unhex(KEY).unwrap();
        let mut pk = [0u8; 65];
        EcdsaP256Sha256::public_key(&key, &mut pk).unwrap();
        let mut sig = [0u8; 64];
        EcdsaP256Sha256::sign(&key, b"authentic", &mut sig).unwrap();

        assert!(
            EcdsaP256Sha256::verify(&pk, b"forged", &sig).is_err(),
            "wrong message"
        );

        let mut bad = sig;
        bad[0] ^= 1;
        assert!(
            EcdsaP256Sha256::verify(&pk, b"authentic", &bad).is_err(),
            "corrupt r"
        );

        let mut bad = sig;
        bad[63] ^= 1;
        assert!(
            EcdsaP256Sha256::verify(&pk, b"authentic", &bad).is_err(),
            "corrupt s"
        );

        // A different key.
        let mut other_pk = [0u8; 65];
        EcdsaP256Sha256::public_key(&[0x11u8; 32], &mut other_pk).unwrap();
        assert!(
            EcdsaP256Sha256::verify(&other_pk, b"authentic", &sig).is_err(),
            "wrong key"
        );
    }

    #[test]
    fn verification_rejects_degenerate_signatures() {
        let key = unhex(KEY).unwrap();
        let mut pk = [0u8; 65];
        EcdsaP256Sha256::public_key(&key, &mut pk).unwrap();

        // r = 0 or s = 0.
        let mut zero_r = [0u8; 64];
        zero_r[63] = 1;
        assert!(EcdsaP256Sha256::verify(&pk, b"m", &zero_r).is_err());

        let mut zero_s = [0u8; 64];
        zero_s[31] = 1;
        assert!(EcdsaP256Sha256::verify(&pk, b"m", &zero_s).is_err());

        // r = n and s = n are non-canonical.
        let mut at_n = [0u8; 64];
        let n_bytes =
            unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551").unwrap();
        at_n[..32].copy_from_slice(&n_bytes);
        at_n[32..].copy_from_slice(&n_bytes);
        assert!(EcdsaP256Sha256::verify(&pk, b"m", &at_n).is_err());
    }

    #[test]
    fn verification_rejects_bad_public_keys() {
        let mut sig = [0u8; 64];
        EcdsaP256Sha256::sign(&unhex(KEY).unwrap(), b"m", &mut sig).unwrap();

        assert!(
            EcdsaP256Sha256::verify(&[0u8; 65], b"m", &sig).is_err(),
            "identity-ish"
        );
        assert!(
            EcdsaP256Sha256::verify(&[0u8; 64], b"m", &sig).is_err(),
            "wrong length"
        );

        let mut pk = [0u8; 65];
        EcdsaP256Sha256::public_key(&unhex(KEY).unwrap(), &mut pk).unwrap();
        pk[40] ^= 1;
        assert!(
            EcdsaP256Sha256::verify(&pk, b"m", &sig).is_err(),
            "off-curve"
        );
    }

    #[test]
    fn signing_rejects_invalid_private_keys() {
        let mut sig = [0u8; 64];
        assert!(
            EcdsaP256Sha256::sign(&[0u8; 32], b"m", &mut sig).is_err(),
            "zero key"
        );
        assert!(
            EcdsaP256Sha256::sign(&[0xffu8; 32], b"m", &mut sig).is_err(),
            "key >= n"
        );
        assert!(
            EcdsaP256Sha256::sign(&[1u8; 31], b"m", &mut sig).is_err(),
            "short key"
        );

        let mut pk = [0u8; 65];
        assert!(EcdsaP256Sha256::public_key(&[0u8; 32], &mut pk).is_err());
    }

    /// Both `(r, s)` and `(r, n - s)` verify; normalization picks one.
    #[test]
    fn malleability_and_normalization() {
        let key = unhex(KEY).unwrap();
        let mut pk = [0u8; 65];
        EcdsaP256Sha256::public_key(&key, &mut pk).unwrap();

        // The "sample" signature has a high s, per RFC 6979.
        let mut sig = [0u8; 64];
        EcdsaP256Sha256::sign(&key, b"sample", &mut sig).unwrap();
        assert!(
            !EcdsaP256Sha256::has_low_s(&sig).unwrap(),
            "RFC 6979 s is high here"
        );

        // Flipping s to n - s still verifies: that is the malleability.
        let mut flipped = sig;
        EcdsaP256Sha256::normalize_s(&mut flipped).unwrap();
        assert_ne!(flipped, sig, "normalization must change a high-s signature");
        EcdsaP256Sha256::verify(&pk, b"sample", &flipped).unwrap();
        assert!(EcdsaP256Sha256::has_low_s(&flipped).unwrap());

        // Normalizing again is a no-op.
        let mut twice = flipped;
        EcdsaP256Sha256::normalize_s(&mut twice).unwrap();
        assert_eq!(twice, flipped, "normalization must be idempotent");
    }

    #[test]
    fn nonce_derivation_is_reproducible_per_attempt() {
        let key = unhex(KEY).unwrap();
        let mut k = [0u8; 32];
        k.copy_from_slice(&key);
        let h = Sha256::digest(b"sample");
        let mut h1 = [0u8; 32];
        h1.copy_from_slice(h.as_ref());

        let a = rfc6979_nonce(&k, &h1, 0).unwrap();
        let b = rfc6979_nonce(&k, &h1, 0).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes(), "attempt 0 must be stable");

        // RFC 6979 A.2.5 publishes k for "sample".
        assert_eq!(
            hex(&a.to_bytes()),
            "a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60"
        );

        // A later attempt must yield a different nonce.
        let c = rfc6979_nonce(&k, &h1, 1).unwrap();
        assert_ne!(a.to_bytes(), c.to_bytes());
    }

    #[test]
    fn self_test_passes() {
        EcdsaP256Sha256::self_test().unwrap();
    }
}
