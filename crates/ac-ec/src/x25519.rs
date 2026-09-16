//! RFC 7748 X25519 key agreement.

use crate::field::Fe;
use ac_core::ct::Choice;
use ac_core::traits::{Algorithm, KeyAgreement, SelfTest};
use ac_core::{ensure, Result};

/// The RFC 7748 base point, `u = 9`.
const BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// X25519, the Diffie-Hellman function on Curve25519.
pub struct X25519;

impl Algorithm for X25519 {
    const ID: &'static str = "x25519";
    const NAME: &'static str = "X25519";
}

/// Apply the RFC 7748 clamping to a scalar.
///
/// Clearing the low three bits kills the small-order component; forcing bit 254
/// fixes the ladder length so timing does not reveal the scalar's magnitude.
fn clamp(scalar: &[u8], out: &mut [u8; 32]) {
    out.copy_from_slice(&scalar[..32]);
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
}

/// The Montgomery ladder: compute `scalar * u`.
///
/// The loop is fixed at 255 iterations with a constant-time conditional swap,
/// so neither the number of operations nor their operands depend on the scalar.
fn ladder(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let x1 = Fe::from_bytes(u);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    let mut swap = Choice::FALSE;

    for pos in (0..255).rev() {
        let bit = Choice::from_u8((scalar[pos / 8] >> (pos & 7)) & 1);
        swap = Choice::from_u8(swap.unwrap_u8() ^ bit.unwrap_u8());
        Fe::cswap(&mut x2, &mut x3, swap);
        Fe::cswap(&mut z2, &mut z3, swap);
        swap = bit;

        let a = x2.add(&z2);
        let b = x2.sub(&z2);
        let aa = a.square();
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);

        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        // RFC 7748 writes this as E * (AA + 121665*E). Expanding both forms
        // gives 121666*AA - 121665*BB, so the 121666 variant below is the same
        // value with the multiplier the field module already provides.
        z2 = e.mul(&bb.add(&e.mul121666()));
    }

    Fe::cswap(&mut x2, &mut x3, swap);
    Fe::cswap(&mut z2, &mut z3, swap);
    x2.mul(&z2.invert()).to_bytes()
}

impl KeyAgreement for X25519 {
    const PRIVATE_KEY_LEN: usize = 32;
    const PUBLIC_KEY_LEN: usize = 32;
    const SHARED_SECRET_LEN: usize = 32;

    fn public_key(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ensure!(private_key.len() == 32, InvalidLength, "x25519 private key");
        ensure!(out.len() == 32, InvalidLength, "x25519 public key buffer");
        let mut k = [0u8; 32];
        clamp(private_key, &mut k);
        out.copy_from_slice(&ladder(&k, &BASEPOINT));
        Ok(())
    }

    fn agree(private_key: &[u8], peer_public_key: &[u8], out: &mut [u8]) -> Result<()> {
        ensure!(private_key.len() == 32, InvalidLength, "x25519 private key");
        ensure!(
            peer_public_key.len() == 32,
            InvalidLength,
            "x25519 public key"
        );
        ensure!(
            out.len() == 32,
            InvalidLength,
            "x25519 shared secret buffer"
        );

        let mut k = [0u8; 32];
        clamp(private_key, &mut k);
        let mut u = [0u8; 32];
        u.copy_from_slice(peer_public_key);

        let shared = ladder(&k, &u);

        // RFC 7748 §6.1: an all-zero shared secret means the peer supplied a
        // small-order point. Rejecting it stops a peer from forcing a known
        // secret, which matters for any protocol that does not hash a
        // transcript over the public keys.
        ensure!(
            !bool::from(ac_core::ct::is_zero(&shared)),
            InvalidParameter,
            "x25519 peer public key has small order"
        );
        out.copy_from_slice(&shared);
        Ok(())
    }
}

impl SelfTest for X25519 {
    fn self_test() -> Result<()> {
        // RFC 7748 §6.1: Alice's key pair.
        let mut sk = [0u8; 32];
        ac_core::codec::hex_decode(
            b"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            &mut sk,
        )?;
        let mut want = [0u8; 32];
        ac_core::codec::hex_decode(
            b"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            &mut want,
        )?;
        let mut got = [0u8; 32];
        <Self as KeyAgreement>::public_key(&sk, &mut got)?;
        ensure!(ac_core::ct::verify(&want, &got), SelfTestFailed, "x25519");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ac_core::codec::{hex, unhex};

    /// RFC 7748 §5.2, first scalar-multiplication vector.
    #[test]
    fn rfc7748_scalar_mult_vector_1() {
        let k = unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4").unwrap();
        let u = unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c").unwrap();
        let mut sk = [0u8; 32];
        clamp(&k, &mut sk);
        let mut up = [0u8; 32];
        up.copy_from_slice(&u);
        assert_eq!(
            hex(&ladder(&sk, &up)),
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        );
    }

    /// RFC 7748 §5.2, second vector.
    #[test]
    fn rfc7748_scalar_mult_vector_2() {
        let k = unhex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d").unwrap();
        let u = unhex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493").unwrap();
        let mut sk = [0u8; 32];
        clamp(&k, &mut sk);
        let mut up = [0u8; 32];
        up.copy_from_slice(&u);
        assert_eq!(
            hex(&ladder(&sk, &up)),
            "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
        );
    }

    /// RFC 7748 §6.1, the full Diffie-Hellman exchange.
    #[test]
    fn rfc7748_diffie_hellman() {
        let a_sk =
            unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").unwrap();
        let b_sk =
            unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb").unwrap();

        let mut a_pk = [0u8; 32];
        let mut b_pk = [0u8; 32];
        X25519::public_key(&a_sk, &mut a_pk).unwrap();
        X25519::public_key(&b_sk, &mut b_pk).unwrap();
        assert_eq!(
            hex(&a_pk),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        assert_eq!(
            hex(&b_pk),
            "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        );

        let mut s1 = [0u8; 32];
        let mut s2 = [0u8; 32];
        X25519::agree(&a_sk, &b_pk, &mut s1).unwrap();
        X25519::agree(&b_sk, &a_pk, &mut s2).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(
            hex(&s1),
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        );
    }

    #[test]
    fn rejects_small_order_points() {
        let sk = [0x11u8; 32];
        let mut out = [0u8; 32];
        // The identity and the other RFC 7748 small-order points.
        for bad in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            let pk = unhex(bad).unwrap();
            assert!(
                X25519::agree(&sk, &pk, &mut out).is_err(),
                "small-order point {bad} must be rejected"
            );
        }
    }

    #[test]
    fn rejects_wrong_lengths() {
        let mut out = [0u8; 32];
        assert!(X25519::public_key(&[0u8; 31], &mut out).is_err());
        assert!(X25519::public_key(&[0u8; 32], &mut out[..31]).is_err());
        assert!(X25519::agree(&[1u8; 32], &[0u8; 31], &mut out).is_err());
    }

    /// Clamping must be applied even when the caller passes an unclamped scalar,
    /// so two scalars differing only in the cleared bits agree.
    #[test]
    fn clamping_is_applied_to_caller_scalars() {
        let mut a = [0x42u8; 32];
        let mut b = a;
        a[0] |= 0x07;
        b[0] &= !0x07;
        a[31] |= 0x80;
        b[31] &= 0x7f;

        let mut pa = [0u8; 32];
        let mut pb = [0u8; 32];
        X25519::public_key(&a, &mut pa).unwrap();
        X25519::public_key(&b, &mut pb).unwrap();
        assert_eq!(pa, pb);
    }

    #[test]
    fn self_test_passes() {
        X25519::self_test().unwrap();
    }
}
