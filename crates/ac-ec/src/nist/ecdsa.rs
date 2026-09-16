//! FIPS 186-5 ECDSA over the NIST prime curves, with RFC 6979 nonces.
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
//! vectors serve as known-answer tests for the whole stack beneath.
//!
//! # Pairing a curve with a hash
//!
//! Each instantiation fixes the hash at the curve's security level: SHA-256
//! with P-256, SHA-384 with P-384. For both, the hash output and the group
//! order are the same width, so RFC 6979's bit-length juggling collapses to a
//! straight reduction.

use super::arith::Field;
use super::point::{AffinePoint, Curve, Point};
use ac_core::traits::{Digest, Mac};
use ac_core::{ensure, Result, Zeroize};

/// A curve paired with the hash and MAC its signatures use.
pub trait EcdsaCurve: Curve {
    /// The message digest, at the curve's security level.
    type Digest: Digest;
    /// HMAC over the same digest, for RFC 6979.
    type Hmac: Mac;

    /// The ontology identifier of this signature scheme.
    const SIGNATURE_ID: &'static str;
}

/// Widest scalar this module handles, for stack buffers.
const MAX_SCALAR: usize = 64;

/// Derive the RFC 6979 nonce for a given attempt.
///
/// The `K`/`V` state machine is run from scratch and advanced `attempt` times,
/// so a rejected candidate (`r == 0` or `s == 0`) moves to the next one exactly
/// as the RFC specifies. Those rejections have negligible probability, so the
/// loop exists for correctness rather than speed.
fn rfc6979_nonce<C: EcdsaCurve>(
    private_key: &[u8],
    h1: &[u8],
    attempt: usize,
) -> Result<C::Scalar> {
    let n = C::SCALAR_BYTES;
    ensure!(n <= MAX_SCALAR, InvalidParameter, "scalar too wide");

    // bits2octets(h1): reduce the hash modulo n, then re-encode.
    let e = C::scalar_reduce_slice(h1);
    let e_octets = e.to_bytes();
    let e_octets = e_octets.as_ref();

    let tag_len = <C::Hmac as Mac>::TAG_LEN;
    let mut v_buf = [0x01u8; MAX_SCALAR];
    let mut k_buf = [0x00u8; MAX_SCALAR];
    let v = &mut v_buf[..tag_len];
    let k = &mut k_buf[..tag_len];

    // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    let mut mac = C::Hmac::new(k)?;
    mac.update(v);
    mac.update(&[0x00]);
    mac.update(private_key);
    mac.update(e_octets);
    k.copy_from_slice(mac.finalize().as_ref());
    let t = C::Hmac::mac(k, v)?;
    v.copy_from_slice(t.as_ref());

    // K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    let mut mac = C::Hmac::new(k)?;
    mac.update(v);
    mac.update(&[0x01]);
    mac.update(private_key);
    mac.update(e_octets);
    k.copy_from_slice(mac.finalize().as_ref());
    let t = C::Hmac::mac(k, v)?;
    v.copy_from_slice(t.as_ref());

    let mut found = 0usize;
    // Bounded so a pathological key cannot spin forever.
    for _ in 0..(attempt + 1) * 8 + 16 {
        // T = HMAC_K(V), which is exactly qlen bits for every pairing here.
        let t = C::Hmac::mac(k, v)?;
        v.copy_from_slice(t.as_ref());

        // Accept only a canonical, non-zero scalar.
        if let Some(candidate) = C::scalar_from_slice(&v[..n]) {
            if !bool::from(candidate.is_zero()) {
                if found == attempt {
                    k_buf.zeroize();
                    v_buf.zeroize();
                    return Ok(candidate);
                }
                found += 1;
            }
        }

        // K = HMAC_K(V || 0x00); V = HMAC_K(V)
        let mut mac = C::Hmac::new(k)?;
        mac.update(v);
        mac.update(&[0x00]);
        k.copy_from_slice(mac.finalize().as_ref());
        let t = C::Hmac::mac(k, v)?;
        v.copy_from_slice(t.as_ref());
    }

    k_buf.zeroize();
    v_buf.zeroize();
    Err(ac_core::err!(
        Internal,
        "rfc6979 nonce generation did not converge"
    ))
}

/// Load a private key, rejecting zero and anything at or above `n`.
fn load_private_key<C: Curve>(bytes: &[u8]) -> Result<C::Scalar> {
    ensure!(
        bytes.len() == C::SCALAR_BYTES,
        InvalidLength,
        "ecdsa private key"
    );
    let d = C::scalar_from_slice(bytes).ok_or(ac_core::err!(
        InvalidParameter,
        "ecdsa private key is not less than n"
    ))?;
    ensure!(
        !bool::from(d.is_zero()),
        InvalidParameter,
        "ecdsa private key must not be zero"
    );
    Ok(d)
}

/// Compute the public key, SEC1 uncompressed.
pub fn public_key<C: EcdsaCurve>(private_key: &[u8], out: &mut [u8]) -> Result<()> {
    ensure!(
        out.len() == 1 + 2 * C::FIELD_BYTES,
        InvalidLength,
        "ecdsa public key buffer"
    );
    let d = load_private_key::<C>(private_key)?;
    let q = Point::<C>::generator()
        .mul_scalar(&d)
        .to_affine()
        .ok_or(ac_core::err!(Internal, "public key is the identity"))?;
    q.write_uncompressed(out);
    Ok(())
}

/// Compute the public key, SEC1 compressed.
pub fn public_key_compressed<C: EcdsaCurve>(private_key: &[u8], out: &mut [u8]) -> Result<()> {
    ensure!(
        out.len() == 1 + C::FIELD_BYTES,
        InvalidLength,
        "ecdsa compressed key buffer"
    );
    let d = load_private_key::<C>(private_key)?;
    let q = Point::<C>::generator()
        .mul_scalar(&d)
        .to_affine()
        .ok_or(ac_core::err!(Internal, "public key is the identity"))?;
    q.write_compressed(out);
    Ok(())
}

/// Sign `message`, writing fixed-width `r || s`.
pub fn sign<C: EcdsaCurve>(private_key: &[u8], message: &[u8], signature: &mut [u8]) -> Result<()> {
    let n = C::SCALAR_BYTES;
    ensure!(
        signature.len() == 2 * n,
        InvalidLength,
        "ecdsa signature buffer"
    );
    let d = load_private_key::<C>(private_key)?;

    let digest = C::Digest::digest(message);
    let h1 = digest.as_ref();
    let e = C::scalar_reduce_slice(h1);

    // Both rejections below have negligible probability; the loop is here so
    // that "negligible" never becomes "silently wrong".
    for attempt in 0..8 {
        let k = rfc6979_nonce::<C>(private_key, h1, attempt)?;

        let point = Point::<C>::generator()
            .mul_scalar(&k)
            .to_affine()
            .ok_or(ac_core::err!(Internal, "kG is the identity"))?;
        let r = C::scalar_reduce_slice(point.x.to_bytes().as_ref());
        if bool::from(r.is_zero()) {
            continue;
        }

        // s = k^-1 (e + r*d)
        let s = k.invert().mul(&e.add(&r.mul(&d)));
        if bool::from(s.is_zero()) {
            continue;
        }

        signature[..n].copy_from_slice(r.to_bytes().as_ref());
        signature[n..].copy_from_slice(s.to_bytes().as_ref());
        return Ok(());
    }

    Err(ac_core::err!(Internal, "ecdsa signing did not converge"))
}

/// Verify a fixed-width `r || s` signature.
pub fn verify<C: EcdsaCurve>(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    let n = C::SCALAR_BYTES;
    ensure!(signature.len() == 2 * n, InvalidLength, "ecdsa signature");

    let q = AffinePoint::<C>::from_sec1(public_key).ok_or(ac_core::err!(
        MalformedEncoding,
        "ecdsa public key is not a curve point"
    ))?;

    // r and s must both be canonical and non-zero. A non-canonical encoding is
    // rejected rather than reduced, so a signature has exactly one valid byte
    // representation.
    let r = C::scalar_from_slice(&signature[..n]).ok_or(ac_core::err!(
        MalformedEncoding,
        "ecdsa r is not less than n"
    ))?;
    let s = C::scalar_from_slice(&signature[n..]).ok_or(ac_core::err!(
        MalformedEncoding,
        "ecdsa s is not less than n"
    ))?;
    ensure!(
        !bool::from(r.is_zero()) && !bool::from(s.is_zero()),
        MalformedEncoding,
        "ecdsa r and s must be non-zero"
    );

    let digest = C::Digest::digest(message);
    let e = C::scalar_reduce_slice(digest.as_ref());

    let w = s.invert();
    let u1 = e.mul(&w);
    let u2 = r.mul(&w);

    let point = Point::<C>::mul_double(&u1, &Point::<C>::from_affine(&q), &u2);
    let affine = point
        .to_affine()
        .ok_or(ac_core::err!(AuthenticationFailed, "ecdsa"))?;

    let v = C::scalar_reduce_slice(affine.x.to_bytes().as_ref());
    if bool::from(v.ct_eq(&r)) {
        Ok(())
    } else {
        Err(ac_core::err!(AuthenticationFailed, "ecdsa"))
    }
}

/// Whether `s` is above `n/2`.
fn is_high_s<C: Curve>(s: &C::Scalar) -> bool {
    let bytes = s.to_bytes();
    let bytes = bytes.as_ref();

    // n/2, by shifting the modulus encoding right one bit.
    let n_bytes = C::Scalar::ZERO.sub(&C::Scalar::ONE).to_bytes();
    let n_bytes = n_bytes.as_ref();
    // `n - 1` encoded; adding one back gives n, but the top bit of n/2 is what
    // matters and n is odd, so (n-1)/2 == n/2 rounded down.
    let mut half = [0u8; MAX_SCALAR];
    let len = n_bytes.len();
    let mut carry = 0u8;
    for i in 0..len {
        let v = n_bytes[i];
        half[i] = (v >> 1) | (carry << 7);
        carry = v & 1;
    }

    // Compare big-endian, most significant byte first. Both operands are public
    // wherever this is called.
    for i in 0..len {
        if bytes[i] != half[i] {
            return bytes[i] > half[i];
        }
    }
    false
}

/// Rewrite a signature to its low-`s` form, if it is not already.
///
/// ECDSA is malleable: `(r, s)` and `(r, n - s)` are both valid for the same
/// message, so a signature is not a unique identifier unless one form is
/// chosen. FIPS 186-5 and RFC 6979 accept both, and this library signs and
/// verifies per the standard, so normalization is offered rather than imposed —
/// apply it when a signature doubles as a database key or a transaction id.
pub fn normalize_s<C: EcdsaCurve>(signature: &mut [u8]) -> Result<()> {
    let n = C::SCALAR_BYTES;
    ensure!(signature.len() == 2 * n, InvalidLength, "ecdsa signature");
    let s = C::scalar_from_slice(&signature[n..]).ok_or(ac_core::err!(
        MalformedEncoding,
        "ecdsa s is not less than n"
    ))?;
    if is_high_s::<C>(&s) {
        let flipped = C::Scalar::ZERO.sub(&s);
        signature[n..].copy_from_slice(flipped.to_bytes().as_ref());
    }
    Ok(())
}

/// Whether a signature is already in low-`s` form.
pub fn has_low_s<C: EcdsaCurve>(signature: &[u8]) -> Result<bool> {
    let n = C::SCALAR_BYTES;
    ensure!(signature.len() == 2 * n, InvalidLength, "ecdsa signature");
    let s = C::scalar_from_slice(&signature[n..]).ok_or(ac_core::err!(
        MalformedEncoding,
        "ecdsa s is not less than n"
    ))?;
    Ok(!is_high_s::<C>(&s))
}
