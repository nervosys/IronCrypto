//! Hashing to P-256: RFC 9380's `P256_XMD:SHA-256_SSWU_RO_`.
//!
//! A hash onto the curve whose output no one knows the discrete logarithm
//! of, which is what an OPRF and a PAKE need. Three steps, each from the RFC:
//!
//! 1. [`expand_message_xmd`] (section 5.3.1) stretches the message and a
//!    domain separation tag into uniform bytes with SHA-256;
//! 2. `hash_to_field` (section 5.2) reads 48 of those bytes per element and
//!    reduces them modulo p -- 48 rather than 32 so the reduction's bias is
//!    below 2^-128;
//! 3. the simplified SWU map (section 6.6.2) sends each of two field
//!    elements to a point, and their sum is the result. P-256 has cofactor
//!    one, so nothing is cleared.
//!
//! The input is usually secret -- a password, in OPAQUE -- so the map runs in
//! constant time: both candidate square roots are computed and one chosen by
//! a mask, the exceptional case is selected rather than branched to, and the
//! sign is fixed with a conditional negation.

use crate::nist::arith::Field;
use crate::nist::point::{AffinePoint, Curve, Point};
use crate::p256::{Fn as Scalar, Fp, P256};
use ic_core::ct::Choice;
use ic_core::traits::internal::Digest;
use ic_core::{ensure, Result, Zeroize};
use ic_hash::Sha256;

/// SHA-256's output and block lengths.
const B_IN_BYTES: usize = 32;
const S_IN_BYTES: usize = 64;

/// `L` for P-256 at the 128-bit level: `ceil((256 + 128) / 8)`.
const L: usize = 48;

/// RFC 9380 section 5.3.1, `expand_message_xmd` with SHA-256: fill `out`
/// with `out.len()` uniform bytes from `msg` under `dst`.
///
/// `dst` is at most 255 bytes and `out` at most 8160 (255 SHA-256 blocks);
/// longer is refused.
pub fn expand_message_xmd(msg: &[u8], dst: &[u8], out: &mut [u8]) -> Result<()> {
    let len = out.len();
    let ell = len.div_ceil(B_IN_BYTES);
    ensure!(
        ell <= 255 && len <= 65535 && !out.is_empty(),
        InvalidLength,
        "expand_message_xmd output length"
    );
    ensure!(
        dst.len() <= 255,
        InvalidParameter,
        "expand_message_xmd DST longer than 255 bytes"
    );
    let dst_len = [dst.len() as u8];

    // b_0 = H(Z_pad || msg || I2OSP(len, 2) || 0 || DST_prime)
    let mut h = Sha256::new();
    h.update(&[0u8; S_IN_BYTES]);
    h.update(msg);
    h.update(&(len as u16).to_be_bytes());
    h.update(&[0]);
    h.update(dst);
    h.update(&dst_len);
    let b0 = h.finalize();

    // b_i = H((b_0 xor b_{i-1}) || i || DST_prime), with b_1 over b_0 alone.
    let mut previous = [0u8; B_IN_BYTES];
    for (i, chunk) in out.chunks_mut(B_IN_BYTES).enumerate() {
        let mut input = [0u8; B_IN_BYTES];
        for ((slot, a), b) in input.iter_mut().zip(b0.as_ref()).zip(previous.iter()) {
            *slot = if i == 0 { *a } else { a ^ b };
        }
        let mut h = Sha256::new();
        h.update(&input);
        h.update(&[(i + 1) as u8]);
        h.update(dst);
        h.update(&dst_len);
        let bi = h.finalize();
        previous.copy_from_slice(bi.as_ref());
        chunk.copy_from_slice(&previous[..chunk.len()]);
        input.zeroize();
    }
    previous.zeroize();
    Ok(())
}

/// A field element from 48 big-endian bytes: `OS2IP(bytes) mod modulus`.
///
/// The value is `hi * 2^256 + lo` for the first 16 and last 32 bytes. Both
/// halves are below `2^256`, which is below twice either P-256 modulus, so
/// each reduces by the field's own single subtraction; `2^256 mod modulus`
/// is `(2^128)^2`, computed in the field.
fn reduce_wide<F: Field<Bytes = [u8; 32]>>(bytes: &[u8]) -> F {
    let mut lo = [0u8; 32];
    lo.copy_from_slice(&bytes[16..48]);
    let mut hi = [0u8; 32];
    hi[16..].copy_from_slice(&bytes[..16]);
    let mut two128 = [0u8; 32];
    two128[15] = 1;
    let r = F::from_bytes_reduced(&two128).square();
    let v = F::from_bytes_reduced(&hi)
        .mul(&r)
        .add(&F::from_bytes_reduced(&lo));
    lo.zeroize();
    hi.zeroize();
    v
}

/// `hash_to_field` for a scalar: one element modulo the group order, as
/// RFC 9497's `HashToScalar` is defined for P-256.
pub(crate) fn hash_to_scalar(msg: &[&[u8]], dst: &[u8]) -> Result<Scalar> {
    let mut uniform = [0u8; L];
    expand_parts(msg, dst, &mut uniform)?;
    let s = reduce_wide::<Scalar>(&uniform);
    uniform.zeroize();
    Ok(s)
}

/// [`expand_message_xmd`] over a message given in parts, which is how every
/// caller here builds one. Joined on the stack: no caller's parts exceed a
/// few hundred bytes, and anything longer is refused rather than truncated.
fn expand_parts(msg: &[&[u8]], dst: &[u8], out: &mut [u8]) -> Result<()> {
    let total: usize = msg.iter().map(|p| p.len()).sum();
    let mut joined = [0u8; 1024];
    ensure!(
        total <= joined.len(),
        InvalidLength,
        "hash_to_field message too long"
    );
    let mut at = 0;
    for part in msg {
        joined[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    let r = expand_message_xmd(&joined[..total], dst, out);
    joined.zeroize();
    r
}

/// The simplified SWU map of RFC 9380 section 6.6.2, for P-256: `A = -3`,
/// `Z = -10`. Constant time in `u`.
fn map_to_curve(u: &Fp) -> AffinePoint<P256> {
    let small = |n: u64| Fp::to_mont([n, 0, 0, 0]);
    let a = small(3).neg();
    let b = P256::B;
    let z = small(10).neg();
    // -B / A and B / (Z * A), the two constants the map uses.
    let c1 = b.neg().mul(&a.invert());
    let c2 = b.mul(&z.mul(&a).invert());

    let zu2 = z.mul(&u.square());
    let tv1 = zu2.square().add(&zu2).invert(); // inv0: zero maps to zero
    let mut x1 = c1.mul(&Fp::ONE.add(&tv1));
    Fp::cmov(&mut x1, &c2, tv1.is_zero());
    let g = |x: &Fp| x.square().mul(x).add(&a.mul(x)).add(&b);
    let gx1 = g(&x1);
    let x2 = zu2.mul(&x1);
    let gx2 = g(&x2);

    let y1 = P256::sqrt(&gx1);
    let y2 = P256::sqrt(&gx2);
    let gx1_square = y1.square().ct_eq(&gx1);
    let mut x = x2;
    let mut y = y2;
    Fp::cmov(&mut x, &x1, gx1_square);
    Fp::cmov(&mut y, &y1, gx1_square);

    // sgn0 for a prime field is the parity of the canonical value.
    let differ = Choice::from_u8(u.is_odd().unwrap_u8() ^ y.is_odd().unwrap_u8());
    let neg = y.neg();
    Fp::cmov(&mut y, &neg, differ);
    AffinePoint { x, y }
}

/// RFC 9380's `hash_to_curve` for `P256_XMD:SHA-256_SSWU_RO_`, as a point.
pub(crate) fn hash_to_curve_point(msg: &[&[u8]], dst: &[u8]) -> Result<Point<P256>> {
    let mut uniform = [0u8; 2 * L];
    expand_parts(msg, dst, &mut uniform)?;
    let u0: Fp = reduce_wide(&uniform[..L]);
    let u1: Fp = reduce_wide(&uniform[L..]);
    uniform.zeroize();
    let q0 = Point::from_affine(&map_to_curve(&u0));
    let q1 = Point::from_affine(&map_to_curve(&u1));
    Ok(q0.add(&q1))
}

/// RFC 9380's `hash_to_curve` for `P256_XMD:SHA-256_SSWU_RO_`: `msg` hashed
/// onto P-256 under `dst`, as a SEC1 uncompressed point.
///
/// The result is never the identity in practice; if it were, this returns
/// an error rather than an encoding of it.
pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> Result<[u8; 65]> {
    ic_core::module::operational()?;
    let p = hash_to_curve_point(&[msg], dst)?;
    let affine = p.to_affine().ok_or(ic_core::err!(
        InvalidParameter,
        "hash_to_curve reached the identity"
    ))?;
    let mut out = [0u8; 65];
    // The buffer is the exact length, so this cannot fail.
    let _ = affine.write_uncompressed(&mut out);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        ic_core::codec::hex_decode(s.as_bytes(), &mut out).unwrap();
        out
    }

    const DST: &[u8] = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";

    /// RFC 9380 appendix J.1.1, the empty message, stage by stage: the two
    /// field elements, the two mapped points, and their sum. The other
    /// messages, and appendix K.1, are in `ironcrypto/tests/oprf.rs`.
    #[test]
    fn each_stage_matches_rfc_9380_for_the_empty_message() {
        let mut uniform = [0u8; 2 * L];
        expand_message_xmd(b"", DST, &mut uniform).unwrap();
        let u0: Fp = reduce_wide(&uniform[..L]);
        let u1: Fp = reduce_wide(&uniform[L..]);
        assert_eq!(
            u0.to_bytes(),
            h("ad5342c66a6dd0ff080df1da0ea1c04b96e0330dd89406465eeba11582515009")
        );
        assert_eq!(
            u1.to_bytes(),
            h("8c0f1d43204bd6f6ea70ae8013070a1518b43873bcd850aafa0a9e220e2eea5a")
        );
        let q0 = map_to_curve(&u0);
        assert_eq!(
            q0.x.to_bytes(),
            h("ab640a12220d3ff283510ff3f4b1953d09fad35795140b1c5d64f313967934d5")
        );
        assert_eq!(
            q0.y.to_bytes(),
            h("dccb558863804a881d4fff3455716c836cef230e5209594ddd33d85c565b19b1")
        );
        let q1 = map_to_curve(&u1);
        assert_eq!(
            q1.x.to_bytes(),
            h("51cce63c50d972a6e51c61334f0f4875c9ac1cd2d3238412f84e31da7d980ef5")
        );
        assert_eq!(
            q1.y.to_bytes(),
            h("b45d1a36d00ad90e5ec7840a60a4de411917fbe7c82c3949a6e699e5a1b66aac")
        );
        let p = hash_to_curve(b"", DST).unwrap();
        assert_eq!(
            p[1..33],
            h("2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4")
        );
        assert_eq!(
            p[33..],
            h("8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415")
        );
    }

    /// The exceptional case: u = 0 makes the denominator zero, and the map
    /// must still land on the curve, at x = B / (Z * A).
    #[test]
    fn the_exceptional_input_maps_onto_the_curve() {
        let q = map_to_curve(&Fp::ZERO);
        assert!(bool::from(q.is_on_curve()));
        let c2 = P256::B.mul(&Fp::to_mont([30, 0, 0, 0]).invert());
        assert_eq!(q.x, c2);
    }

    #[test]
    fn expand_message_refuses_what_rfc_9380_forbids() {
        assert!(expand_message_xmd(b"", &[0u8; 256], &mut [0u8; 32]).is_err());
        assert!(expand_message_xmd(b"", b"d", &mut [0u8; 255 * 32 + 1]).is_err());
        assert!(expand_message_xmd(b"", b"d", &mut []).is_err());
    }
}
