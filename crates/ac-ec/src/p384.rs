//! NIST P-384 (secp384r1).
//!
//! The curve a CNSA-aligned profile requires, and the one TLS reaches for when
//! 128-bit security is not considered enough. The field, group law, and schemes
//! come from [`crate::nist`]; this module supplies the constants and the public
//! API.
//!
//! Paired with SHA-384 throughout, which is the matching security level and
//! also makes RFC 6979's bit-length handling collapse to a straight reduction,
//! since the hash and the group order are both 384 bits wide.

use crate::mont_field;
use crate::nist::arith::{sqrt_p3mod4, Field};
use crate::nist::point::Curve;
use crate::nist::{ecdh, ecdsa};
use ac_core::traits::{Algorithm, KeyAgreement, SelfTest, SignatureScheme};
use ac_core::{ensure, Result};

mont_field!(
    Fp,
    6,
    48,
    [
        0x0000_0000_ffff_ffff,
        0xffff_ffff_0000_0000,
        0xffff_ffff_ffff_fffe,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
    ],
    "The P-384 coordinate field, GF(p) with p = 2^384 - 2^128 - 2^96 + 2^32 - 1."
);

mont_field!(
    Fn,
    6,
    48,
    [
        0xecec_196a_ccc5_2973,
        0x581a_0db2_48b0_a77a,
        0xc763_4d81_f437_2ddf,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
    ],
    "The P-384 scalar ring, Z/nZ where n is the order of the base point."
);

/// The P-384 curve.
#[derive(Debug, Clone, Copy)]
pub struct P384;

impl Curve for P384 {
    type Field = Fp;
    type Scalar = Fn;

    const NAME: &'static str = "P-384";
    const FIELD_BYTES: usize = 48;
    const SCALAR_BYTES: usize = 48;
    const ORDER_BITS: usize = 384;

    /// `b = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a`
    ///     `c656398d8a2ed19d2a85c8edd3ec2aef`
    const B: Fp = Fp::to_mont([
        0x2a85_c8ed_d3ec_2aef,
        0xc656_398d_8a2e_d19d,
        0x0314_088f_5013_875a,
        0x181d_9c6e_fe81_4112,
        0x988e_056b_e3f8_2d19,
        0xb331_2fa7_e23e_e7e4,
    ]);

    const GX: Fp = Fp::to_mont([
        0x3a54_5e38_7276_0ab7,
        0x5502_f25d_bf55_296c,
        0x59f7_41e0_8254_2a38,
        0x6e1d_3b62_8ba7_9b98,
        0x8eb1_c71e_f320_ad74,
        0xaa87_ca22_be8b_0537,
    ]);

    const GY: Fp = Fp::to_mont([
        0x7a43_1d7c_90ea_0e5f,
        0x0a60_b1ce_1d7e_819d,
        0xe9da_3113_b5f0_b8c0,
        0xf8f4_1dbd_289a_147c,
        0x5d9e_98bf_9292_dc29,
        0x3617_de4a_9626_2c6f,
    ]);

    /// `p = 3 mod 4`, so a square root is `x^((p+1)/4)`.
    fn sqrt(x: &Fp) -> Fp {
        sqrt_p3mod4(x, Fp::MODULUS, |v, e| v.pow(e))
    }

    fn field_from_slice(bytes: &[u8]) -> Option<Fp> {
        let mut b = [0u8; 48];
        if bytes.len() != 48 {
            return None;
        }
        b.copy_from_slice(bytes);
        Fp::from_bytes(&b)
    }

    fn scalar_from_slice(bytes: &[u8]) -> Option<Fn> {
        let mut b = [0u8; 48];
        if bytes.len() != 48 {
            return None;
        }
        b.copy_from_slice(bytes);
        Fn::from_bytes(&b)
    }

    fn scalar_reduce_slice(bytes: &[u8]) -> Fn {
        let mut b = [0u8; 48];
        let n = core::cmp::min(48, bytes.len());
        // Take the leftmost bytes, which is what bits2int does when the input
        // is at least as wide as the group order.
        b[48 - n..].copy_from_slice(&bytes[..n]);
        Fn::from_bytes_reduced(&b)
    }
}

impl ecdsa::EcdsaCurve for P384 {
    type Digest = ac_hash::Sha384;
    type Hmac = ac_mac::HmacSha384;
    const SIGNATURE_ID: &'static str = "ecdsa-p384-sha384";
}

/// ECDSA over P-384 with SHA-384.
pub struct EcdsaP384Sha384;

impl Algorithm for EcdsaP384Sha384 {
    const ID: &'static str = "ecdsa-p384-sha384";
    const NAME: &'static str = "ECDSA P-384 with SHA-384";
}

impl SignatureScheme for EcdsaP384Sha384 {
    const PRIVATE_KEY_LEN: usize = 48;
    /// SEC1 uncompressed: `0x04 || X || Y`.
    const PUBLIC_KEY_LEN: usize = 97;
    /// Fixed-width `r || s`.
    const SIGNATURE_LEN: usize = 96;

    fn public_key(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ecdsa::public_key::<P384>(private_key, out)
    }

    fn sign(private_key: &[u8], message: &[u8], signature: &mut [u8]) -> Result<()> {
        ecdsa::sign::<P384>(private_key, message, signature)
    }

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        ecdsa::verify::<P384>(public_key, message, signature)
    }
}

impl EcdsaP384Sha384 {
    /// Compute the public key in SEC1 compressed form (49 bytes).
    pub fn public_key_compressed(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ecdsa::public_key_compressed::<P384>(private_key, out)
    }

    /// Rewrite a signature to its low-`s` form. See [`ecdsa::normalize_s`].
    pub fn normalize_s(signature: &mut [u8]) -> Result<()> {
        ecdsa::normalize_s::<P384>(signature)
    }

    /// Whether a signature is already in low-`s` form.
    pub fn has_low_s(signature: &[u8]) -> Result<bool> {
        ecdsa::has_low_s::<P384>(signature)
    }
}

impl SelfTest for EcdsaP384Sha384 {
    fn self_test() -> Result<()> {
        // Round-trip plus tamper rejection. The published RFC 6979 vector is
        // asserted by the unit tests; this CAST is the startup integrity check.
        let key = [0x2au8; 48];
        let mut pk = [0u8; 97];
        <Self as SignatureScheme>::public_key(&key, &mut pk)?;

        let mut sig = [0u8; 96];
        <Self as SignatureScheme>::sign(&key, b"self-test", &mut sig)?;
        <Self as SignatureScheme>::verify(&pk, b"self-test", &sig)?;

        // Signing is deterministic, so a repeat must agree exactly.
        let mut again = [0u8; 96];
        <Self as SignatureScheme>::sign(&key, b"self-test", &mut again)?;
        ensure!(
            ac_core::ct::verify(&sig, &again),
            SelfTestFailed,
            "ecdsa-p384-sha384"
        );

        sig[0] ^= 1;
        ensure!(
            <Self as SignatureScheme>::verify(&pk, b"self-test", &sig).is_err(),
            SelfTestFailed,
            "ecdsa-p384-sha384"
        );
        Ok(())
    }
}

/// ECDH over P-384.
pub struct EcdhP384;

impl Algorithm for EcdhP384 {
    const ID: &'static str = "ecdh-p384";
    const NAME: &'static str = "ECDH P-384";
}

impl KeyAgreement for EcdhP384 {
    const PRIVATE_KEY_LEN: usize = 48;
    /// SEC1 uncompressed: `0x04 || X || Y`.
    const PUBLIC_KEY_LEN: usize = 97;
    const SHARED_SECRET_LEN: usize = 48;

    fn public_key(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ecdh::public_key::<P384>(private_key, out)
    }

    fn agree(private_key: &[u8], peer_public_key: &[u8], out: &mut [u8]) -> Result<()> {
        ecdh::agree::<P384>(private_key, peer_public_key, out)
    }
}

impl EcdhP384 {
    /// Compute the public key in SEC1 compressed form (49 bytes).
    pub fn public_key_compressed(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ecdh::public_key_compressed::<P384>(private_key, out)
    }
}

impl SelfTest for EcdhP384 {
    fn self_test() -> Result<()> {
        // Both sides of an exchange must agree, and the result must not be the
        // trivial one.
        let (a, b) = ([0x11u8; 48], [0x22u8; 48]);
        let mut a_pk = [0u8; 97];
        let mut b_pk = [0u8; 97];
        <Self as KeyAgreement>::public_key(&a, &mut a_pk)?;
        <Self as KeyAgreement>::public_key(&b, &mut b_pk)?;

        let mut z1 = [0u8; 48];
        let mut z2 = [0u8; 48];
        <Self as KeyAgreement>::agree(&a, &b_pk, &mut z1)?;
        <Self as KeyAgreement>::agree(&b, &a_pk, &mut z2)?;
        ensure!(ac_core::ct::verify(&z1, &z2), SelfTestFailed, "ecdh-p384");
        ensure!(z1 != [0u8; 48], SelfTestFailed, "ecdh-p384");
        Ok(())
    }
}

/// A P-384 point in Jacobian coordinates.
pub type Point = crate::nist::point::Point<P384>;
/// A P-384 point in affine coordinates.
pub type AffinePoint = crate::nist::point::AffinePoint<P384>;

#[cfg(test)]
mod tests {
    use super::*;
    use ac_core::codec::{hex, unhex};

    fn scalar(v: u64) -> Fn {
        Fn::to_mont([v, 0, 0, 0, 0, 0])
    }

    fn fp(v: u64) -> Fp {
        Fp::to_mont([v, 0, 0, 0, 0, 0])
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
        assert_eq!(fp(5).triple(), fp(15));
        assert_eq!(Fp::ONE.from_mont(), [1, 0, 0, 0, 0, 0]);
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
        let a = P384::field_from_slice(&[0x3a; 48]).unwrap();
        let b = P384::field_from_slice(&[0x91; 48]).unwrap();
        let c = P384::field_from_slice(&[0xc7; 48]).unwrap();
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
    fn byte_encoding_round_trips() {
        let bytes = [0x7fu8; 48];
        let a = P384::field_from_slice(&bytes).unwrap();
        assert_eq!(a.to_bytes(), bytes);
    }

    // -- group law --------------------------------------------------------

    /// Validates B, GX, GY and the curve equation together: if any of the four
    /// constants were mistranscribed, the base point would not satisfy it.
    #[test]
    fn the_base_point_is_on_the_curve() {
        let g = Point::generator().to_affine().unwrap();
        assert!(bool::from(g.is_on_curve()));
    }

    /// Validates the group order n against the base point. Together with the
    /// test above this pins down every curve constant.
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
        assert!(bool::from(Point::identity().double().is_identity()));
        assert!(bool::from(g.add(&g.neg()).is_identity()));
    }

    #[test]
    fn addition_handles_equal_inputs_as_a_doubling() {
        let g = Point::generator();
        assert!(bool::from(g.add(&g).ct_eq(&g.double())));
    }

    #[test]
    fn scalar_multiplication_matches_repeated_addition() {
        let g = Point::generator();
        let mut acc = Point::identity();
        for k in 1..=8u64 {
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
    }

    /// The published `[2]G`, an independent check on the group law rather than
    /// on self-consistency.
    #[test]
    fn two_g_matches_the_published_value() {
        let two_g = Point::generator().double().to_affine().unwrap();
        assert_eq!(
            hex(two_g.x.to_bytes().as_ref()),
            "08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e9e\
             4fe0e86ebe0e64f85b96a9c75295df61"
                .replace(char::is_whitespace, "")
        );
        assert_eq!(
            hex(two_g.y.to_bytes().as_ref()),
            "8e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab425\
             5ffd43e94d39e22d61501e700a940e80"
                .replace(char::is_whitespace, "")
        );
    }

    #[test]
    fn every_multiple_stays_on_the_curve() {
        let g = Point::generator();
        for k in [1u64, 2, 3, 17, 255, 65537] {
            let p = g.mul_scalar(&scalar(k)).to_affine().unwrap();
            assert!(bool::from(p.is_on_curve()), "[{k}]G is off the curve");
        }
    }

    #[test]
    fn sec1_round_trips_in_both_forms() {
        let g = Point::generator();
        for k in [1u64, 2, 3, 4, 5, 6] {
            let p = g.mul_scalar(&scalar(k)).to_affine().unwrap();
            let mut unc = [0u8; 97];
            let mut comp = [0u8; 49];
            assert!(p.write_uncompressed(&mut unc));
            assert!(p.write_compressed(&mut comp));

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
        let mut unc = [0u8; 97];
        g.write_uncompressed(&mut unc);

        assert!(AffinePoint::from_sec1(&[0u8; 97]).is_none(), "identity");
        assert!(AffinePoint::from_sec1(&unc[..96]).is_none(), "truncated");
        // A P-256-sized encoding must not be accepted here.
        assert!(
            AffinePoint::from_sec1(&[0x04u8; 65]).is_none(),
            "wrong width"
        );

        let mut bad = unc;
        bad[96] ^= 1;
        assert!(AffinePoint::from_sec1(&bad).is_none(), "off curve");
    }

    // -- ECDSA ------------------------------------------------------------

    /// RFC 6979 A.2.6: P-384 with SHA-384.
    ///
    /// The private key, public key and both message signatures are published
    /// together, so matching them exercises the whole stack: the 6-limb field,
    /// the group law, the scalar ring, the nonce derivation, and the signing
    /// equation.
    const KEY: &str = "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d8\
                       96d5724e4c70a825f872c9ea60d2edf5";

    fn key_bytes() -> Vec<u8> {
        unhex(&KEY.replace(char::is_whitespace, "")).unwrap()
    }

    #[test]
    fn rfc6979_public_key() {
        let mut pk = [0u8; 97];
        EcdsaP384Sha384::public_key(&key_bytes(), &mut pk).unwrap();
        assert_eq!(pk[0], 0x04);
        assert_eq!(
            hex(&pk[1..49]),
            "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64\
             def8f0ea9055866064a254515480bc13"
                .replace(char::is_whitespace, ""),
            "Ux"
        );
        assert_eq!(
            hex(&pk[49..]),
            "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1\
             288b231c3ae0d4fe7344fd2533264720"
                .replace(char::is_whitespace, ""),
            "Uy"
        );
    }

    #[test]
    fn rfc6979_sample_vector() {
        let mut sig = [0u8; 96];
        EcdsaP384Sha384::sign(&key_bytes(), b"sample", &mut sig).unwrap();
        assert_eq!(
            hex(&sig[..48]),
            "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c\
             81a648152e44acf96e36dd1e80fabe46"
                .replace(char::is_whitespace, ""),
            "r"
        );
        assert_eq!(
            hex(&sig[48..]),
            "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94f\
             a329c145786e679e7b82c71a38628ac8"
                .replace(char::is_whitespace, ""),
            "s"
        );
    }

    #[test]
    fn rfc6979_test_vector() {
        let mut sig = [0u8; 96];
        EcdsaP384Sha384::sign(&key_bytes(), b"test", &mut sig).unwrap();
        assert_eq!(
            hex(&sig[..48]),
            "8203b63d3c853e8d77227fb377bcf7b7b772e97892a80f36ab775d509d7a5feb\
             0542a7f0812998da8f1dd3ca3cf023db"
                .replace(char::is_whitespace, ""),
            "r"
        );
        assert_eq!(
            hex(&sig[48..]),
            "ddd0760448d42d8a43af45af836fce4de8be06b485e9b61b827c2f13173923e0\
             6a739f040649a667bf3b828246baa5a5"
                .replace(char::is_whitespace, ""),
            "s"
        );
    }

    #[test]
    fn signing_is_deterministic_and_message_bound() {
        let key = key_bytes();
        let mut a = [0u8; 96];
        let mut b = [0u8; 96];
        EcdsaP384Sha384::sign(&key, b"same", &mut a).unwrap();
        EcdsaP384Sha384::sign(&key, b"same", &mut b).unwrap();
        assert_eq!(a, b);
        EcdsaP384Sha384::sign(&key, b"other", &mut b).unwrap();
        assert_ne!(&a[..48], &b[..48]);
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let key = key_bytes();
        let mut pk = [0u8; 97];
        EcdsaP384Sha384::public_key(&key, &mut pk).unwrap();
        for message in [&b""[..], b"short", &[0x5au8; 1000][..]] {
            let mut sig = [0u8; 96];
            EcdsaP384Sha384::sign(&key, message, &mut sig).unwrap();
            EcdsaP384Sha384::verify(&pk, message, &sig).unwrap();
        }
    }

    #[test]
    fn verification_rejects_tampering() {
        let key = key_bytes();
        let mut pk = [0u8; 97];
        EcdsaP384Sha384::public_key(&key, &mut pk).unwrap();
        let mut sig = [0u8; 96];
        EcdsaP384Sha384::sign(&key, b"authentic", &mut sig).unwrap();

        assert!(EcdsaP384Sha384::verify(&pk, b"forged", &sig).is_err());
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(EcdsaP384Sha384::verify(&pk, b"authentic", &bad).is_err());
        let mut bad = sig;
        bad[95] ^= 1;
        assert!(EcdsaP384Sha384::verify(&pk, b"authentic", &bad).is_err());

        let mut other = [0u8; 97];
        EcdsaP384Sha384::public_key(&[0x11u8; 48], &mut other).unwrap();
        assert!(EcdsaP384Sha384::verify(&other, b"authentic", &sig).is_err());
    }

    #[test]
    fn signing_rejects_invalid_private_keys() {
        let mut sig = [0u8; 96];
        assert!(
            EcdsaP384Sha384::sign(&[0u8; 48], b"m", &mut sig).is_err(),
            "zero"
        );
        assert!(
            EcdsaP384Sha384::sign(&[0xffu8; 48], b"m", &mut sig).is_err(),
            ">= n"
        );
        assert!(
            EcdsaP384Sha384::sign(&[1u8; 32], b"m", &mut sig).is_err(),
            "P-256 sized"
        );
    }

    #[test]
    fn malleability_and_normalization() {
        let key = key_bytes();
        let mut pk = [0u8; 97];
        EcdsaP384Sha384::public_key(&key, &mut pk).unwrap();
        let mut sig = [0u8; 96];
        EcdsaP384Sha384::sign(&key, b"sample", &mut sig).unwrap();

        let mut normalized = sig;
        EcdsaP384Sha384::normalize_s(&mut normalized).unwrap();
        assert!(EcdsaP384Sha384::has_low_s(&normalized).unwrap());
        // Both forms verify: that is the malleability.
        EcdsaP384Sha384::verify(&pk, b"sample", &normalized).unwrap();
        EcdsaP384Sha384::verify(&pk, b"sample", &sig).unwrap();

        let mut twice = normalized;
        EcdsaP384Sha384::normalize_s(&mut twice).unwrap();
        assert_eq!(twice, normalized, "normalization must be idempotent");
    }

    #[test]
    fn ecdsa_self_test_passes() {
        EcdsaP384Sha384::self_test().unwrap();
    }

    // -- ECDH -------------------------------------------------------------

    #[test]
    fn both_parties_derive_the_same_secret() {
        let (alice, bob) = ([0x11u8; 48], [0x22u8; 48]);
        let mut alice_pk = [0u8; 97];
        let mut bob_pk = [0u8; 97];
        EcdhP384::public_key(&alice, &mut alice_pk).unwrap();
        EcdhP384::public_key(&bob, &mut bob_pk).unwrap();

        let mut z1 = [0u8; 48];
        let mut z2 = [0u8; 48];
        EcdhP384::agree(&alice, &bob_pk, &mut z1).unwrap();
        EcdhP384::agree(&bob, &alice_pk, &mut z2).unwrap();
        assert_eq!(z1, z2);
        assert_ne!(z1, [0u8; 48]);
    }

    #[test]
    fn compressed_and_uncompressed_peers_agree() {
        let (alice, bob) = ([0x33u8; 48], [0x44u8; 48]);
        let mut unc = [0u8; 97];
        let mut comp = [0u8; 49];
        EcdhP384::public_key(&bob, &mut unc).unwrap();
        EcdhP384::public_key_compressed(&bob, &mut comp).unwrap();

        let mut z1 = [0u8; 48];
        let mut z2 = [0u8; 48];
        EcdhP384::agree(&alice, &unc, &mut z1).unwrap();
        EcdhP384::agree(&alice, &comp, &mut z2).unwrap();
        assert_eq!(z1, z2);
    }

    #[test]
    fn ecdh_rejects_invalid_inputs() {
        let alice = [0x11u8; 48];
        let mut z = [0u8; 48];
        assert!(EcdhP384::agree(&alice, &[0u8; 97], &mut z).is_err());
        assert!(EcdhP384::agree(&alice, &[], &mut z).is_err());

        let mut bob_pk = [0u8; 97];
        EcdhP384::public_key(&[0x22u8; 48], &mut bob_pk).unwrap();
        bob_pk[96] ^= 1;
        assert!(
            EcdhP384::agree(&alice, &bob_pk, &mut z).is_err(),
            "off curve"
        );
    }

    #[test]
    fn ecdh_self_test_passes() {
        EcdhP384::self_test().unwrap();
    }
}
