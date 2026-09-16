//! SP 800-56A elliptic-curve Diffie-Hellman over the NIST prime curves.
//!
//! The shared secret is the x-coordinate of `[d]Q`, as SP 800-56A §5.7.1.2
//! specifies. It is **not** a key: it is a field element that must go through a
//! KDF before use. The ontology records that as a `serious` constraint.

use super::arith::Field;
use super::point::{AffinePoint, Curve, Point};
use ac_core::{ensure, Result};

/// Load and validate a private scalar.
fn load_scalar<C: Curve>(bytes: &[u8]) -> Result<C::Scalar> {
    ensure!(
        bytes.len() == C::SCALAR_BYTES,
        InvalidLength,
        "ecdh private key"
    );
    let d = C::scalar_from_slice(bytes).ok_or(ac_core::err!(
        InvalidParameter,
        "ecdh private key is not less than n"
    ))?;
    ensure!(
        !bool::from(d.is_zero()),
        InvalidParameter,
        "ecdh private key must not be zero"
    );
    Ok(d)
}

/// Compute the public key, SEC1 uncompressed.
pub fn public_key<C: Curve>(private_key: &[u8], out: &mut [u8]) -> Result<()> {
    ensure!(
        out.len() == 1 + 2 * C::FIELD_BYTES,
        InvalidLength,
        "ecdh public key buffer"
    );
    let d = load_scalar::<C>(private_key)?;
    let q = Point::<C>::generator()
        .mul_scalar(&d)
        .to_affine()
        .ok_or(ac_core::err!(Internal, "public key is the identity"))?;
    q.write_uncompressed(out);
    Ok(())
}

/// Compute the public key, SEC1 compressed.
pub fn public_key_compressed<C: Curve>(private_key: &[u8], out: &mut [u8]) -> Result<()> {
    ensure!(
        out.len() == 1 + C::FIELD_BYTES,
        InvalidLength,
        "ecdh compressed key buffer"
    );
    let d = load_scalar::<C>(private_key)?;
    let q = Point::<C>::generator()
        .mul_scalar(&d)
        .to_affine()
        .ok_or(ac_core::err!(Internal, "public key is the identity"))?;
    q.write_compressed(out);
    Ok(())
}

/// Compute the shared secret: the x-coordinate of `[d]Q`.
pub fn agree<C: Curve>(private_key: &[u8], peer_public_key: &[u8], out: &mut [u8]) -> Result<()> {
    ensure!(
        out.len() == C::FIELD_BYTES,
        InvalidLength,
        "ecdh shared secret buffer"
    );
    let d = load_scalar::<C>(private_key)?;

    // SP 800-56A full public-key validation: the decoder checks that the point
    // is on the curve and refuses the identity, and every NIST prime curve has
    // cofactor 1, so there is no small subgroup left to land in.
    let q = AffinePoint::<C>::from_sec1(peer_public_key).ok_or(ac_core::err!(
        InvalidParameter,
        "ecdh peer public key is not a valid curve point"
    ))?;

    let shared = Point::<C>::from_affine(&q).mul_scalar(&d);
    let affine = shared.to_affine().ok_or(ac_core::err!(
        InvalidParameter,
        "ecdh key agreement produced the identity"
    ))?;

    out.copy_from_slice(affine.x.to_bytes().as_ref());
    Ok(())
}
