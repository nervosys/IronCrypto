//! NIST P-256 (secp256r1, prime256v1).
//!
//! The most widely deployed approved curve. The field, group law, and schemes
//! come from [`crate::nist`]; this module supplies the constants and the
//! public API.

use crate::mont_field;
use crate::nist::arith::{sqrt_p3mod4, Field};
use crate::nist::point::Curve;
use crate::nist::{ecdh, ecdsa};
use ic_core::traits::{Algorithm, KeyAgreement, SelfTest, SignatureScheme};
use ic_core::{ensure, Result};

mont_field!(
    Fp,
    4,
    32,
    [
        0xffff_ffff_ffff_ffff,
        0x0000_0000_ffff_ffff,
        0x0000_0000_0000_0000,
        0xffff_ffff_0000_0001,
    ],
    "The P-256 coordinate field, GF(p) with p = 2^256 - 2^224 + 2^192 + 2^96 - 1."
);

mont_field!(
    Fn,
    4,
    32,
    [
        0xf3b9_cac2_fc63_2551,
        0xbce6_faad_a717_9e84,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_0000_0000,
    ],
    "The P-256 scalar ring, Z/nZ where n is the order of the base point."
);

/// The P-256 curve.
#[derive(Debug, Clone, Copy)]
pub struct P256;

impl Curve for P256 {
    type Field = Fp;
    type Scalar = Fn;

    const NAME: &'static str = "P-256";
    const FIELD_BYTES: usize = 32;
    const SCALAR_BYTES: usize = 32;
    const ORDER_BITS: usize = 256;

    /// `b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b`
    const B: Fp = Fp::to_mont([
        0x3bce_3c3e_27d2_604b,
        0x651d_06b0_cc53_b0f6,
        0xb3eb_bd55_7698_86bc,
        0x5ac6_35d8_aa3a_93e7,
    ]);

    const GX: Fp = Fp::to_mont([
        0xf4a1_3945_d898_c296,
        0x7703_7d81_2deb_33a0,
        0xf8bc_e6e5_63a4_40f2,
        0x6b17_d1f2_e12c_4247,
    ]);

    const GY: Fp = Fp::to_mont([
        0xcbb6_4068_37bf_51f5,
        0x2bce_3357_6b31_5ece,
        0x8ee7_eb4a_7c0f_9e16,
        0x4fe3_42e2_fe1a_7f9b,
    ]);

    /// `p = 3 mod 4`, so a square root is `x^((p+1)/4)`.
    fn sqrt(x: &Fp) -> Fp {
        // p = 3 mod 4, so the root is x^((p+1)/4). The shared helper computes
        // that exponent rather than this file unrolling it by limb: an unrolled
        // shift is easy to get subtly wrong and would only misbehave on inputs
        // rare enough that a round-trip test would not find them.
        sqrt_p3mod4(x, Fp::MODULUS, |v, e| v.pow(e))
    }

    fn field_from_slice(bytes: &[u8]) -> Option<Fp> {
        let mut b = [0u8; 32];
        if bytes.len() != 32 {
            return None;
        }
        b.copy_from_slice(bytes);
        Fp::from_bytes(&b)
    }

    fn scalar_from_slice(bytes: &[u8]) -> Option<Fn> {
        let mut b = [0u8; 32];
        if bytes.len() != 32 {
            return None;
        }
        b.copy_from_slice(bytes);
        Fn::from_bytes(&b)
    }

    fn scalar_reduce_slice(bytes: &[u8]) -> Fn {
        let mut b = [0u8; 32];
        let n = core::cmp::min(32, bytes.len());
        // Take the leftmost bytes, which is what bits2int does when the input
        // is at least as wide as the group order.
        b[32 - n..].copy_from_slice(&bytes[..n]);
        Fn::from_bytes_reduced(&b)
    }
}

impl ecdsa::EcdsaCurve for P256 {
    type Digest = ic_hash::Sha256;
    type Hmac = ic_mac::HmacSha256;
    const SIGNATURE_ID: &'static str = "ecdsa-p256-sha256";
}

/// ECDSA over P-256 with SHA-256.
pub struct EcdsaP256Sha256;

impl Algorithm for EcdsaP256Sha256 {
    const ID: &'static str = "ecdsa-p256-sha256";
    const NAME: &'static str = "ECDSA P-256 with SHA-256";
}

impl SignatureScheme for EcdsaP256Sha256 {
    const PRIVATE_KEY_LEN: usize = 32;
    /// SEC1 uncompressed: `0x04 || X || Y`.
    const PUBLIC_KEY_LEN: usize = 65;
    /// Fixed-width `r || s`.
    const SIGNATURE_LEN: usize = 64;

    fn public_key(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ecdsa::public_key::<P256>(private_key, out)
    }

    fn sign(private_key: &[u8], message: &[u8], signature: &mut [u8]) -> Result<()> {
        ecdsa::sign::<P256>(private_key, message, signature)
    }

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        ecdsa::verify::<P256>(public_key, message, signature)
    }
}

impl EcdsaP256Sha256 {
    /// Compute the public key in SEC1 compressed form (33 bytes).
    pub fn public_key_compressed(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ecdsa::public_key_compressed::<P256>(private_key, out)
    }

    /// Rewrite a signature to its low-`s` form. See [`ecdsa::normalize_s`].
    pub fn normalize_s(signature: &mut [u8]) -> Result<()> {
        ecdsa::normalize_s::<P256>(signature)
    }

    /// Whether a signature is already in low-`s` form.
    pub fn has_low_s(signature: &[u8]) -> Result<bool> {
        ecdsa::has_low_s::<P256>(signature)
    }
}

impl SelfTest for EcdsaP256Sha256 {
    fn self_test() -> Result<()> {
        // RFC 6979 A.2.5: P-256, SHA-256, message "sample".
        let mut key = [0u8; 32];
        ic_core::codec::hex_decode(
            b"c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
            &mut key,
        )?;
        let mut want = [0u8; 64];
        ic_core::codec::hex_decode(
            b"efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
            &mut want,
        )?;

        let mut sig = [0u8; 64];
        <Self as SignatureScheme>::sign(&key, b"sample", &mut sig)?;
        ensure!(
            ic_core::ct::verify(&want, &sig),
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

/// ECDH over P-256.
pub struct EcdhP256;

impl Algorithm for EcdhP256 {
    const ID: &'static str = "ecdh-p256";
    const NAME: &'static str = "ECDH P-256";
}

impl KeyAgreement for EcdhP256 {
    const PRIVATE_KEY_LEN: usize = 32;
    /// SEC1 uncompressed: `0x04 || X || Y`.
    const PUBLIC_KEY_LEN: usize = 65;
    const SHARED_SECRET_LEN: usize = 32;

    fn public_key(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ecdh::public_key::<P256>(private_key, out)
    }

    fn agree(private_key: &[u8], peer_public_key: &[u8], out: &mut [u8]) -> Result<()> {
        ecdh::agree::<P256>(private_key, peer_public_key, out)
    }
}

impl EcdhP256 {
    /// Compute the public key in SEC1 compressed form (33 bytes).
    ///
    /// Interoperates with TLS, COSE, and JOSE, which all prefer compressed
    /// points. [`KeyAgreement::agree`] accepts either form.
    pub fn public_key_compressed(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ecdh::public_key_compressed::<P256>(private_key, out)
    }
}

impl SelfTest for EcdhP256 {
    fn self_test() -> Result<()> {
        // NIST CAVP ECC CDH, P-256, the first published key-agreement case.
        let mut d = [0u8; 32];
        ic_core::codec::hex_decode(
            b"7d7dc5f71eb29ddaf80d6214632eeae03d9058af1fb6d22ed80badb62bc1a534",
            &mut d,
        )?;
        let mut peer = [0u8; 65];
        peer[0] = 0x04;
        ic_core::codec::hex_decode(
            b"700c48f77f56584c5cc632ca65640db91b6bacce3a4df6b42ce7cc838833d287",
            &mut peer[1..33],
        )?;
        ic_core::codec::hex_decode(
            b"db71e509e3fd9b060ddb20ba5c51dcc5948d46fbf640dfe0441782cab85fa4ac",
            &mut peer[33..],
        )?;
        let mut want = [0u8; 32];
        ic_core::codec::hex_decode(
            b"46fc62106420ff012e54a434fbdd2d25ccc5852060561e68040dd7778997bd7b",
            &mut want,
        )?;

        let mut got = [0u8; 32];
        <Self as KeyAgreement>::agree(&d, &peer, &mut got)?;
        ensure!(
            ic_core::ct::verify(&want, &got),
            SelfTestFailed,
            "ecdh-p256"
        );
        Ok(())
    }
}

/// A P-256 point in Jacobian coordinates.
pub type Point = crate::nist::point::Point<P256>;
/// A P-256 point in affine coordinates.
pub type AffinePoint = crate::nist::point::AffinePoint<P256>;

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::codec::{hex, unhex};

    fn scalar(v: u64) -> Fn {
        Fn::to_mont([v, 0, 0, 0])
    }

    fn fp(v: u64) -> Fp {
        Fp::to_mont([v, 0, 0, 0])
    }

    // -- field ------------------------------------------------------------

    #[test]
    fn montgomery_constants_are_consistent() {
        assert_eq!(Fp::MODULUS[0].wrapping_mul(Fp::NEG_INV), u64::MAX, "p");
        assert_eq!(Fn::MODULUS[0].wrapping_mul(Fn::NEG_INV), u64::MAX, "n");
    }

    #[test]
    fn small_arithmetic_matches_integers() {
        assert_eq!(fp(2).add(&fp(3)), fp(5));
        assert_eq!(fp(5).sub(&fp(3)), fp(2));
        assert_eq!(fp(6).mul(&fp(7)), fp(42));
        assert_eq!(fp(9).square(), fp(81));
        assert_eq!(fp(5).double(), fp(10));
        assert_eq!(fp(5).triple(), fp(15));
        assert_eq!(Fp::ONE.from_mont(), [1, 0, 0, 0]);
    }

    #[test]
    fn inversion_is_correct() {
        for v in [1u64, 2, 3, 19, 65537, u32::MAX as u64] {
            assert_eq!(fp(v).mul(&fp(v).invert()), Fp::ONE, "1/{v} in Fp");
            assert_eq!(scalar(v).mul(&scalar(v).invert()), Fn::ONE, "1/{v} in Fn");
        }
        assert_eq!(Fp::ZERO.invert(), Fp::ZERO);
    }

    #[test]
    fn arithmetic_laws_hold_on_large_values() {
        let a = P256::field_from_slice(&[0x3a; 32]).unwrap();
        let b = P256::field_from_slice(&[0x91; 32]).unwrap();
        let c = P256::field_from_slice(&[0xc7; 32]).unwrap();
        assert_eq!(a.mul(&b).mul(&c), a.mul(&b.mul(&c)), "associativity");
        assert_eq!(a.mul(&b), b.mul(&a), "commutativity");
        assert_eq!(
            a.mul(&b.add(&c)),
            a.mul(&b).add(&a.mul(&c)),
            "distributivity"
        );
        assert_eq!(a.add(&a.neg()), Fp::ZERO);
    }

    #[test]
    fn byte_encoding_round_trips_and_rejects_non_canonical() {
        let bytes = [0x7fu8; 32];
        let a = P256::field_from_slice(&bytes).unwrap();
        assert_eq!(a.to_bytes(), bytes);

        // p itself must be refused but reduce to zero.
        let mut p_bytes = [0u8; 32];
        for i in 0..4 {
            let hi = 32 - i * 8;
            p_bytes[hi - 8..hi].copy_from_slice(&Fp::MODULUS[i].to_be_bytes());
        }
        assert!(P256::field_from_slice(&p_bytes).is_none());
    }

    // -- group law --------------------------------------------------------

    /// Validates B, GX, GY and the curve equation together: if any of the four
    /// constants were mistranscribed, the base point would not satisfy it.
    #[test]
    fn the_base_point_is_on_the_curve() {
        let g = Point::generator().to_affine().unwrap();
        assert!(bool::from(g.is_on_curve()));
    }

    /// Validates the group order n against the base point.
    #[test]
    fn the_base_point_has_order_n() {
        let n_minus_1 = Fn::ZERO.sub(&Fn::ONE);
        let p = Point::generator().mul_scalar(&n_minus_1);
        assert!(
            bool::from(p.ct_eq(&Point::generator().neg())),
            "[n-1]G == -G"
        );
        assert!(
            bool::from(p.add(&Point::generator()).is_identity()),
            "[n]G is the identity"
        );
    }

    #[test]
    fn identity_and_negation_behave() {
        let g = Point::generator();
        assert!(bool::from(g.add(&Point::identity()).ct_eq(&g)));
        assert!(bool::from(Point::identity().add(&g).ct_eq(&g)));
        assert!(bool::from(Point::identity().double().is_identity()));
        assert!(bool::from(g.add(&g.neg()).is_identity()));
        assert!(Point::identity().to_affine().is_none());
    }

    /// The exceptional case a naive Jacobian addition gets wrong.
    #[test]
    fn addition_handles_equal_inputs_as_a_doubling() {
        let g = Point::generator();
        assert!(bool::from(g.add(&g).ct_eq(&g.double())));
        let p = g.mul_scalar(&scalar(5));
        assert!(bool::from(p.add(&p).ct_eq(&p.double())));
    }

    #[test]
    fn scalar_multiplication_matches_repeated_addition() {
        let g = Point::generator();
        let mut acc = Point::identity();
        for k in 1..=10u64 {
            acc = acc.add(&g);
            assert!(bool::from(acc.ct_eq(&g.mul_scalar(&scalar(k)))), "[{k}]G");
        }
    }

    #[test]
    fn scalar_multiplication_is_linear() {
        let g = Point::generator();
        let a = scalar(1_234_567);
        let b = scalar(7_654_321);
        assert!(bool::from(
            g.mul_scalar(&a.add(&b))
                .ct_eq(&g.mul_scalar(&a).add(&g.mul_scalar(&b)))
        ));
        assert!(bool::from(
            g.mul_scalar(&a)
                .mul_scalar(&b)
                .ct_eq(&g.mul_scalar(&a.mul(&b)))
        ));
    }

    /// The published `[2]G`, an independent check on the group law rather than
    /// on self-consistency.
    #[test]
    fn two_g_matches_the_published_value() {
        let two_g = Point::generator().double().to_affine().unwrap();
        assert_eq!(
            hex(two_g.x.to_bytes().as_ref()),
            "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"
        );
        assert_eq!(
            hex(two_g.y.to_bytes().as_ref()),
            "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"
        );
    }

    #[test]
    fn sec1_round_trips_in_both_forms() {
        let g = Point::generator();
        for k in [1u64, 2, 3, 4, 5, 6, 7, 8] {
            let p = g.mul_scalar(&scalar(k)).to_affine().unwrap();
            let mut unc = [0u8; 65];
            let mut comp = [0u8; 33];
            assert!(p.write_uncompressed(&mut unc));
            assert!(p.write_compressed(&mut comp));
            assert_eq!(unc[0], 0x04);
            assert!(comp[0] == 0x02 || comp[0] == 0x03);

            let a = AffinePoint::from_sec1(&unc).unwrap();
            let b = AffinePoint::from_sec1(&comp).unwrap();
            assert_eq!(a.x, p.x);
            assert_eq!(a.y, p.y);
            assert_eq!(b.x, p.x);
            assert_eq!(b.y, p.y, "compressed y for [{k}]G");
        }
    }

    #[test]
    fn decoding_rejects_bad_encodings() {
        let g = Point::generator().to_affine().unwrap();
        let mut unc = [0u8; 65];
        assert!(g.write_uncompressed(&mut unc));

        assert!(AffinePoint::from_sec1(&[]).is_none());
        assert!(AffinePoint::from_sec1(&[0u8; 65]).is_none(), "identity");
        assert!(AffinePoint::from_sec1(&unc[..64]).is_none(), "truncated");

        let mut bad = unc;
        bad[0] = 0x05;
        assert!(AffinePoint::from_sec1(&bad).is_none(), "bad tag");

        let mut bad = unc;
        bad[64] ^= 1;
        assert!(AffinePoint::from_sec1(&bad).is_none(), "off curve");
    }

    // -- ECDSA ------------------------------------------------------------

    const KEY: &str = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";

    /// RFC 6979 A.2.5, message "sample". Matching this exercises the field, the
    /// group law, the scalar ring, the nonce derivation, and the signing
    /// equation in one shot.
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

    #[test]
    fn rfc6979_public_key() {
        let key = unhex(KEY).unwrap();
        let mut pk = [0u8; 65];
        EcdsaP256Sha256::public_key(&key, &mut pk).unwrap();
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
    fn signing_is_deterministic_and_message_bound() {
        let key = unhex(KEY).unwrap();
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        EcdsaP256Sha256::sign(&key, b"same", &mut a).unwrap();
        EcdsaP256Sha256::sign(&key, b"same", &mut b).unwrap();
        assert_eq!(a, b, "RFC 6979 signing must not depend on an RNG");

        EcdsaP256Sha256::sign(&key, b"other", &mut b).unwrap();
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

        assert!(EcdsaP256Sha256::verify(&pk, b"forged", &sig).is_err());
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(EcdsaP256Sha256::verify(&pk, b"authentic", &bad).is_err());
        let mut bad = sig;
        bad[63] ^= 1;
        assert!(EcdsaP256Sha256::verify(&pk, b"authentic", &bad).is_err());

        let mut other = [0u8; 65];
        EcdsaP256Sha256::public_key(&[0x11u8; 32], &mut other).unwrap();
        assert!(EcdsaP256Sha256::verify(&other, b"authentic", &sig).is_err());
    }

    #[test]
    fn verification_rejects_degenerate_signatures() {
        let key = unhex(KEY).unwrap();
        let mut pk = [0u8; 65];
        EcdsaP256Sha256::public_key(&key, &mut pk).unwrap();

        let mut zero_r = [0u8; 64];
        zero_r[63] = 1;
        assert!(EcdsaP256Sha256::verify(&pk, b"m", &zero_r).is_err());

        let mut zero_s = [0u8; 64];
        zero_s[31] = 1;
        assert!(EcdsaP256Sha256::verify(&pk, b"m", &zero_s).is_err());

        let n_bytes =
            unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551").unwrap();
        let mut at_n = [0u8; 64];
        at_n[..32].copy_from_slice(&n_bytes);
        at_n[32..].copy_from_slice(&n_bytes);
        assert!(EcdsaP256Sha256::verify(&pk, b"m", &at_n).is_err());
    }

    #[test]
    fn signing_rejects_invalid_private_keys() {
        let mut sig = [0u8; 64];
        assert!(
            EcdsaP256Sha256::sign(&[0u8; 32], b"m", &mut sig).is_err(),
            "zero"
        );
        assert!(
            EcdsaP256Sha256::sign(&[0xffu8; 32], b"m", &mut sig).is_err(),
            ">= n"
        );
        assert!(
            EcdsaP256Sha256::sign(&[1u8; 31], b"m", &mut sig).is_err(),
            "short"
        );
    }

    /// Both `(r, s)` and `(r, n - s)` verify; normalization picks one.
    #[test]
    fn malleability_and_normalization() {
        let key = unhex(KEY).unwrap();
        let mut pk = [0u8; 65];
        EcdsaP256Sha256::public_key(&key, &mut pk).unwrap();
        let mut sig = [0u8; 64];
        EcdsaP256Sha256::sign(&key, b"sample", &mut sig).unwrap();
        assert!(
            !EcdsaP256Sha256::has_low_s(&sig).unwrap(),
            "RFC 6979 s is high here"
        );

        let mut flipped = sig;
        EcdsaP256Sha256::normalize_s(&mut flipped).unwrap();
        assert_ne!(flipped, sig);
        EcdsaP256Sha256::verify(&pk, b"sample", &flipped).unwrap();
        assert!(EcdsaP256Sha256::has_low_s(&flipped).unwrap());

        let mut twice = flipped;
        EcdsaP256Sha256::normalize_s(&mut twice).unwrap();
        assert_eq!(twice, flipped, "normalization must be idempotent");
    }

    #[test]
    fn ecdsa_self_test_passes() {
        EcdsaP256Sha256::self_test().unwrap();
    }

    // -- ECDH -------------------------------------------------------------

    /// NIST CAVP ECC CDH, first published case.
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
        let (alice, bob) = ([0x11u8; 32], [0x22u8; 32]);
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
        let (alice, bob) = ([0x33u8; 32], [0x44u8; 32]);
        let mut unc = [0u8; 65];
        let mut comp = [0u8; 33];
        EcdhP256::public_key(&bob, &mut unc).unwrap();
        EcdhP256::public_key_compressed(&bob, &mut comp).unwrap();

        let mut z1 = [0u8; 32];
        let mut z2 = [0u8; 32];
        EcdhP256::agree(&alice, &unc, &mut z1).unwrap();
        EcdhP256::agree(&alice, &comp, &mut z2).unwrap();
        assert_eq!(z1, z2, "the peer key encoding must not matter");
    }

    #[test]
    fn ecdh_rejects_invalid_inputs() {
        let alice = [0x11u8; 32];
        let mut z = [0u8; 32];
        assert!(EcdhP256::agree(&alice, &[0u8; 65], &mut z).is_err());
        assert!(EcdhP256::agree(&alice, &[], &mut z).is_err());

        let mut bob_pk = [0u8; 65];
        EcdhP256::public_key(&[0x22u8; 32], &mut bob_pk).unwrap();
        bob_pk[64] ^= 1;
        assert!(
            EcdhP256::agree(&alice, &bob_pk, &mut z).is_err(),
            "off curve"
        );

        let mut pk = [0u8; 65];
        assert!(EcdhP256::public_key(&[0u8; 32], &mut pk).is_err());
        assert!(EcdhP256::public_key(&[0xffu8; 32], &mut pk).is_err());
    }

    #[test]
    fn ecdh_self_test_passes() {
        EcdhP256::self_test().unwrap();
    }
}
