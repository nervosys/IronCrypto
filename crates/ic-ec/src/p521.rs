//! NIST P-521 (secp521r1).
//!
//! The largest of the NIST prime curves, and the only one here whose field
//! width is not a multiple of 64 bits: `p = 2^521 - 1`, which needs nine limbs
//! of which the top carries nine significant bits. That awkwardness is confined
//! to this module's constants and to the byte conversion in
//! [`crate::nist::arith`]; the group law and the schemes are the same generic
//! code P-256 and P-384 use.
//!
//! Paired with SHA-512. The hash is 512 bits and the group order is 521, so
//! RFC 6979's `bits2int` takes the digest whole with no truncation and no
//! shift — the one case where a shorter hash than the order is handled by doing
//! nothing.
//!
//! # A Mersenne prime has conveniences
//!
//! `p = 2^521 - 1` means `(p + 1) / 4 = 2^519` exactly, so a square root is 519
//! squarings with no multiplications at all. [`P521::sqrt`] says so directly
//! rather than running the generic square-and-multiply over an exponent that
//! happens to be a power of two.

use crate::mont_field;
use crate::nist::arith::Field;
use crate::nist::point::Curve;
use crate::nist::{ecdh, ecdsa};
use ic_core::traits::{Algorithm, KeyAgreement, SelfTest, SignatureScheme};
use ic_core::{ensure, Result};

mont_field!(
    Fp,
    9,
    66,
    [
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0x0000_0000_0000_01ff,
    ],
    "The P-521 coordinate field, GF(p) with p = 2^521 - 1."
);

mont_field!(
    Fn,
    9,
    66,
    [
        0xbb6f_b71e_9138_6409,
        0x3bb5_c9b8_899c_47ae,
        0x7fcc_0148_f709_a5d0,
        0x5186_8783_bf2f_966b,
        0xffff_ffff_ffff_fffa,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff,
        0x0000_0000_0000_01ff,
    ],
    "The P-521 scalar ring, Z/nZ where n is the order of the base point."
);

/// The P-521 curve.
#[derive(Debug, Clone, Copy)]
pub struct P521;

impl Curve for P521 {
    type Field = Fp;
    type Scalar = Fn;

    const NAME: &'static str = "P-521";
    /// 521 bits rounds up to 66 bytes, with the top seven bits of the first
    /// byte always zero.
    const FIELD_BYTES: usize = 66;
    const SCALAR_BYTES: usize = 66;
    /// 521, not 528. The seven-bit gap is what makes RFC 6979's `bits2int`
    /// shift here where it does not for the other curves.
    const ORDER_BITS: usize = 521;

    /// `b = 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef1`
    ///     `09e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00`
    const B: Fp = Fp::to_mont([
        0xef45_1fd4_6b50_3f00,
        0x3573_df88_3d2c_34f1,
        0x1652_c0bd_3bb1_bf07,
        0x5619_3951_ec7e_937b,
        0xb8b4_8991_8ef1_09e1,
        0xa2da_725b_99b3_15f3,
        0x929a_21a0_b685_40ee,
        0x953e_b961_8e1c_9a1f,
        0x0000_0000_0000_0051,
    ]);

    const GX: Fp = Fp::to_mont([
        0xf97e_7e31_c2e5_bd66,
        0x3348_b3c1_856a_429b,
        0xfe1d_c127_a2ff_a8de,
        0xa14b_5e77_efe7_5928,
        0xf828_af60_6b4d_3dba,
        0x9c64_8139_053f_b521,
        0x9e3e_cb66_2395_b442,
        0x858e_06b7_0404_e9cd,
        0x0000_0000_0000_00c6,
    ]);

    const GY: Fp = Fp::to_mont([
        0x88be_9476_9fd1_6650,
        0x353c_7086_a272_c240,
        0xc550_b901_3fad_0761,
        0x97ee_7299_5ef4_2640,
        0x17af_bd17_273e_662c,
        0x98f5_4449_579b_4468,
        0x5c8a_5fb4_2c7d_1bd9,
        0x3929_6a78_9a3b_c004,
        0x0000_0000_0000_0118,
    ]);

    /// `(p + 1) / 4 = 2^519`, so the square root is a chain of squarings.
    ///
    /// The other curves compute the exponent from the modulus and run
    /// square-and-multiply. Here the exponent is a power of two, so every
    /// multiply in that loop would be by one.
    fn sqrt(x: &Fp) -> Fp {
        x.square_n(519)
    }

    fn field_from_slice(bytes: &[u8]) -> Option<Fp> {
        let mut b = [0u8; 66];
        if bytes.len() != 66 {
            return None;
        }
        b.copy_from_slice(bytes);
        Fp::from_bytes(&b)
    }

    fn scalar_from_slice(bytes: &[u8]) -> Option<Fn> {
        let mut b = [0u8; 66];
        if bytes.len() != 66 {
            return None;
        }
        b.copy_from_slice(bytes);
        Fn::from_bytes(&b)
    }

    fn scalar_reduce_slice(bytes: &[u8]) -> Fn {
        let mut b = [0u8; 66];
        let n = core::cmp::min(66, bytes.len());
        // RFC 6979 bits2int: take the leftmost min(blen, qlen) bits. SHA-512 is
        // 512 bits and the order is 521, so the digest is used whole and lands
        // right-aligned here — no shift, which is what the specification means
        // by "the integer represented by those bits".
        b[66 - n..].copy_from_slice(&bytes[..n]);
        Fn::from_bytes_reduced(&b)
    }
}

impl ecdsa::EcdsaCurve for P521 {
    type Digest = ic_hash::Sha512;
    type Hmac = ic_mac::HmacSha512;
    const SIGNATURE_ID: &'static str = "ecdsa-p521-sha512";
}

/// ECDSA over P-521 with SHA-512.
pub struct EcdsaP521Sha512;

impl Algorithm for EcdsaP521Sha512 {
    const ID: &'static str = "ecdsa-p521-sha512";
    const NAME: &'static str = "ECDSA P-521 with SHA-512";
}

impl SignatureScheme for EcdsaP521Sha512 {
    const PRIVATE_KEY_LEN: usize = 66;
    /// SEC1 uncompressed: `0x04 || X || Y`.
    const PUBLIC_KEY_LEN: usize = 133;
    /// Fixed-width `r || s`.
    const SIGNATURE_LEN: usize = 132;

    fn public_key(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ecdsa::public_key::<P521>(private_key, out)
    }

    fn sign(private_key: &[u8], message: &[u8], signature: &mut [u8]) -> Result<()> {
        ecdsa::sign::<P521>(private_key, message, signature)
    }

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        ecdsa::verify::<P521>(public_key, message, signature)
    }
}

impl EcdsaP521Sha512 {
    /// Compute the public key in SEC1 compressed form (67 bytes).
    pub fn public_key_compressed(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ecdsa::public_key_compressed::<P521>(private_key, out)
    }

    /// Rewrite a signature to its low-`s` form. See [`ecdsa::normalize_s`].
    pub fn normalize_s(signature: &mut [u8]) -> Result<()> {
        ecdsa::normalize_s::<P521>(signature)
    }

    /// Whether a signature is already in low-`s` form.
    pub fn has_low_s(signature: &[u8]) -> Result<bool> {
        ecdsa::has_low_s::<P521>(signature)
    }
}

impl SelfTest for EcdsaP521Sha512 {
    fn self_test() -> Result<()> {
        // Round-trip plus tamper rejection. The cross-check against an
        // independent RFC 6979 implementation lives in the unit tests; this
        // CAST is the startup integrity check.
        // A 66-byte scalar must stay below the 521-bit order, so the top byte
        // cannot be filled the way the other curves' self-test keys are.
        let mut key = [0x2au8; 66];
        key[0] = 0x00;
        let mut pk = [0u8; 133];
        <Self as SignatureScheme>::public_key(&key, &mut pk)?;

        let mut sig = [0u8; 132];
        <Self as SignatureScheme>::sign(&key, b"self-test", &mut sig)?;
        <Self as SignatureScheme>::verify(&pk, b"self-test", &sig)?;

        // Signing is deterministic, so a repeat must agree exactly.
        let mut again = [0u8; 132];
        <Self as SignatureScheme>::sign(&key, b"self-test", &mut again)?;
        ensure!(
            ic_core::ct::verify(&sig, &again),
            SelfTestFailed,
            "ecdsa-p521-sha512"
        );

        sig[0] ^= 1;
        ensure!(
            <Self as SignatureScheme>::verify(&pk, b"self-test", &sig).is_err(),
            SelfTestFailed,
            "ecdsa-p521-sha512"
        );
        Ok(())
    }
}

/// ECDH over P-521.
pub struct EcdhP521;

impl Algorithm for EcdhP521 {
    const ID: &'static str = "ecdh-p521";
    const NAME: &'static str = "ECDH P-521";
}

impl KeyAgreement for EcdhP521 {
    const PRIVATE_KEY_LEN: usize = 66;
    const PUBLIC_KEY_LEN: usize = 133;
    const SHARED_SECRET_LEN: usize = 66;

    fn public_key(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ecdh::public_key::<P521>(private_key, out)
    }

    fn agree(private_key: &[u8], peer_public_key: &[u8], out: &mut [u8]) -> Result<()> {
        ecdh::agree::<P521>(private_key, peer_public_key, out)
    }
}

impl EcdhP521 {
    /// Compute the public key in SEC1 compressed form (67 bytes).
    pub fn public_key_compressed(private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ecdh::public_key_compressed::<P521>(private_key, out)
    }
}

impl SelfTest for EcdhP521 {
    fn self_test() -> Result<()> {
        // Both sides of an exchange must agree, and the result must not be the
        // trivial one.
        // As above: the leading byte is cleared so both scalars are in range.
        let (mut a, mut b) = ([0x11u8; 66], [0x22u8; 66]);
        a[0] = 0x00;
        b[0] = 0x00;
        let mut a_pk = [0u8; 133];
        let mut b_pk = [0u8; 133];
        <Self as KeyAgreement>::public_key(&a, &mut a_pk)?;
        <Self as KeyAgreement>::public_key(&b, &mut b_pk)?;

        let mut z1 = [0u8; 66];
        let mut z2 = [0u8; 66];
        <Self as KeyAgreement>::agree(&a, &b_pk, &mut z1)?;
        <Self as KeyAgreement>::agree(&b, &a_pk, &mut z2)?;
        ensure!(ic_core::ct::verify(&z1, &z2), SelfTestFailed, "ecdh-p521");
        ensure!(z1 != [0u8; 66], SelfTestFailed, "ecdh-p521");
        Ok(())
    }
}

/// A P-521 point in Jacobian coordinates.
pub type Point = crate::nist::point::Point<P521>;
/// A P-521 point in affine coordinates.
pub type AffinePoint = crate::nist::point::AffinePoint<P521>;

#[cfg(test)]
mod tests {
    use super::*;

    /// P-521 takes a shortcut for square roots, and this is what checks it.
    ///
    /// Because `p = 2^521 - 1`, the exponent `(p+1)/4` is exactly `2^519`, so
    /// the root is 519 repeated squarings and no exponentiation ladder is
    /// needed. That is a genuine saving and a genuine risk: an off-by-one in
    /// the count produces a value that is wrong for every input, but a
    /// round-trip through point compression would still reject it as "not on
    /// the curve" rather than pointing at the square root.
    ///
    /// So the shortcut is compared against the generic `(p+1)/4` computation
    /// used by P-256 and P-384. Two independent routes to the same value.
    #[test]
    fn the_square_root_shortcut_matches_the_generic_exponent() {
        use crate::nist::arith::sqrt_p3mod4;

        let mut checked = 0;
        for seed in 1u64..40 {
            let mut bytes = [0u8; 66];
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = (seed.wrapping_mul(i as u64 + 7) & 0xff) as u8;
            }
            // Keep it inside the field.
            bytes[0] &= 0x01;
            let Some(x) = P521::field_from_slice(&bytes) else {
                continue;
            };
            // Square first, so the input is definitely a quadratic residue and
            // both routes must land on a genuine root.
            let y2 = x.square();

            let shortcut = <P521 as Curve>::sqrt(&y2);
            let generic = sqrt_p3mod4(&y2, Fp::MODULUS, |v, e| v.pow(e));
            assert_eq!(
                shortcut, generic,
                "the shortcut disagrees with the generic exponent at seed {seed}"
            );
            assert_eq!(shortcut.square(), y2, "and it must actually be a root");
            checked += 1;
        }
        assert!(
            checked > 20,
            "the sweep should reach real inputs: {checked}"
        );
    }

    /// The generic helper must agree with each curve's own notion of a root.
    ///
    /// P-256 and P-384 now call it directly, so this mostly guards against the
    /// helper being changed in a way that happens to keep those two working.
    #[test]
    fn a_root_squares_back_to_its_input_on_every_curve() {
        for seed in 1u8..12 {
            let mut b = [0u8; 66];
            b[65] = seed;
            let x = P521::field_from_slice(&b).unwrap();
            let y2 = x.square();
            let root = <P521 as Curve>::sqrt(&y2);
            assert_eq!(root.square(), y2, "P-521 at seed {seed}");
        }
    }
    use ic_core::codec::hex;

    fn scalar(v: u64) -> Fn {
        Fn::to_mont([v, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    fn fp(v: u64) -> Fp {
        Fp::to_mont([v, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    // -- field ------------------------------------------------------------

    #[test]
    fn montgomery_constants_are_consistent() {
        assert_eq!(Fp::MODULUS[0].wrapping_mul(Fp::NEG_INV), u64::MAX, "p");
        assert_eq!(Fn::MODULUS[0].wrapping_mul(Fn::NEG_INV), u64::MAX, "n");
    }

    /// `p = 2^521 - 1` is a Mersenne prime, so the modulus is checkable by
    /// inspection: eight limbs of ones and a ninth holding nine more bits.
    #[test]
    fn the_modulus_is_two_to_the_521_minus_one() {
        for (i, limb) in Fp::MODULUS.iter().enumerate().take(8) {
            assert_eq!(*limb, u64::MAX, "limb {i}");
        }
        assert_eq!(Fp::MODULUS[8], 0x1ff);
        // 8 * 64 + 9 = 521 significant bits.
        assert_eq!(64 - Fp::MODULUS[8].leading_zeros(), 9);
    }

    #[test]
    fn small_arithmetic_matches_integers() {
        assert_eq!(fp(2).add(&fp(3)), fp(5));
        assert_eq!(fp(5).sub(&fp(3)), fp(2));
        assert_eq!(fp(6).mul(&fp(7)), fp(42));
        assert_eq!(fp(9).square(), fp(81));
        assert_eq!(fp(5).triple(), fp(15));
        assert_eq!(Fp::ONE.from_mont(), [1, 0, 0, 0, 0, 0, 0, 0, 0]);
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
        // The top byte must stay below 0x02: field elements are 521 bits in a
        // 66-byte encoding, so seven leading bits are always zero.
        let mut a_bytes = [0x3au8; 66];
        a_bytes[0] = 0x01;
        let mut b_bytes = [0x91u8; 66];
        b_bytes[0] = 0x00;
        let mut c_bytes = [0xc7u8; 66];
        c_bytes[0] = 0x01;
        let a = P521::field_from_slice(&a_bytes).unwrap();
        let b = P521::field_from_slice(&b_bytes).unwrap();
        let c = P521::field_from_slice(&c_bytes).unwrap();
        assert_eq!(a.mul(&b).mul(&c), a.mul(&b.mul(&c)), "associativity");
        assert_eq!(a.mul(&b), b.mul(&a), "commutativity");
        assert_eq!(
            a.mul(&b.add(&c)),
            a.mul(&b).add(&a.mul(&c)),
            "distributivity"
        );
        assert_eq!(a.add(&a.neg()), Fp::ZERO);
    }

    /// The nine-limb field is the first here whose byte width is not eight
    /// times its limb count, so the encoding boundary gets its own test.
    #[test]
    fn byte_encoding_round_trips_across_the_partial_top_limb() {
        // A value whose top bits sit in the ninth limb.
        let mut bytes = [0x00u8; 66];
        bytes[0] = 0x01;
        bytes[1] = 0xff;
        for (i, b) in bytes[2..].iter_mut().enumerate() {
            *b = i as u8;
        }
        let a = P521::field_from_slice(&bytes).unwrap();
        assert_eq!(a.to_bytes(), bytes);

        // The largest value below the modulus: p - 1, which is 2^521 - 2.
        let p_minus_1 = Fp::ZERO.sub(&Fp::ONE);
        let encoded = p_minus_1.to_bytes();
        assert_eq!(encoded[0], 0x01, "bit 520 is set");
        assert_eq!(encoded[1], 0xff);
        assert_eq!(encoded[65], 0xfe, "and the low bit is clear");
        assert_eq!(P521::field_from_slice(&encoded).unwrap(), p_minus_1);
    }

    /// Anything at or above the modulus is refused rather than reduced.
    #[test]
    fn out_of_range_encodings_are_rejected() {
        // p itself.
        let mut p_bytes = [0xffu8; 66];
        p_bytes[0] = 0x01;
        assert!(P521::field_from_slice(&p_bytes).is_none(), "p");

        // A value with bits above 521 set.
        let too_big = [0xffu8; 66];
        assert!(P521::field_from_slice(&too_big).is_none(), "2^528 - 1");

        // Wrong width.
        assert!(P521::field_from_slice(&[0u8; 65]).is_none());
        assert!(P521::field_from_slice(&[0u8; 67]).is_none());
    }

    /// `(p + 1) / 4 = 2^519`, so the square root is 519 squarings. Check the
    /// shortcut against the property it is supposed to have.
    #[test]
    fn square_roots_are_correct() {
        for v in [1u64, 4, 9, 16, 12345] {
            let x = fp(v);
            let root = P521::sqrt(&x.square());
            // The root is +/-x; squaring it must return the input either way.
            assert_eq!(root.square(), x.square(), "sqrt({v}^2)^2");
            assert!(
                bool::from(root.ct_eq(&x)) || bool::from(root.ct_eq(&x.neg())),
                "sqrt({v}^2) is +/-{v}"
            );
        }
    }

    // -- group law --------------------------------------------------------

    /// Validates B, GX and GY together. A single mistyped digit in any of them
    /// puts the base point off the curve.
    #[test]
    fn the_base_point_is_on_the_curve() {
        let g = Point::generator().to_affine().unwrap();
        assert!(bool::from(g.is_on_curve()));
    }

    /// Validates the group order n. With the test above, every curve constant
    /// is pinned down.
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

    /// `[2]G`, computed by a separate naive implementation over Python
    /// integers rather than by this code. See docs/FIPS.md on provenance: no
    /// published P-521 vector is wired in here, so the oracle is an independent
    /// implementation of the same group law.
    #[test]
    fn two_g_matches_an_independent_computation() {
        let two_g = Point::generator().double().to_affine().unwrap();
        assert_eq!(
            hex(two_g.x.to_bytes().as_ref()),
            "00433c219024277e7e682fcb288148c282747403279b1ccc06352c6e5505d769\
             be97b3b204da6ef55507aa104a3a35c5af41cf2fa364d60fd967f43e3933ba6d783d"
                .replace(char::is_whitespace, "")
        );
        assert_eq!(
            hex(two_g.y.to_bytes().as_ref()),
            "00f4bb8cc7f86db26700a7f3eceeeed3f0b5c6b5107c4da97740ab21a29906c4\
             2dbbb3e377de9f251f6b93937fa99a3248f4eafcbe95edc0f4f71be356d661f41b02"
                .replace(char::is_whitespace, "")
        );
    }

    /// `[k]G` for a k large enough to exercise the whole ladder, again against
    /// the independent computation.
    #[test]
    fn a_large_multiple_matches_an_independent_computation() {
        let k = scalar(0x0123_4567_89ab_cdef);
        let p = Point::generator().mul_scalar(&k).to_affine().unwrap();
        assert_eq!(
            hex(p.x.to_bytes().as_ref()),
            "004e54b334cb2a1e40cc9712808f78e4adf7e1cd31acb0bc0d969efdfa82de8f\
             bada7ca6c3e22ba5d47b5dc024e93ffd8c2cb3f1f88d3224050914a8ad9dcd593a59"
                .replace(char::is_whitespace, "")
        );
        assert_eq!(
            hex(p.y.to_bytes().as_ref()),
            "010b8759ce9c47342e92da648fd25aeaadd28c3f6cfad8c5fa1beec990ca9e7f\
             bf0939bf66c1b8d9918db4795980329872afcf99e0f774f84b144bfa60e5587d7abd"
                .replace(char::is_whitespace, "")
        );
    }

    #[test]
    fn every_multiple_stays_on_the_curve() {
        let g = Point::generator();
        for k in [1u64, 2, 3, 17, 255, 65537, u32::MAX as u64] {
            let p = g.mul_scalar(&scalar(k)).to_affine().unwrap();
            assert!(bool::from(p.is_on_curve()), "[{k}]G is off the curve");
        }
    }

    #[test]
    fn sec1_round_trips_in_both_forms() {
        let g = Point::generator();
        for k in [1u64, 2, 3, 4, 5, 6] {
            let p = g.mul_scalar(&scalar(k)).to_affine().unwrap();
            let mut unc = [0u8; 133];
            let mut comp = [0u8; 67];
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
        let mut unc = [0u8; 133];
        assert!(g.write_uncompressed(&mut unc));

        assert!(AffinePoint::from_sec1(&[0u8; 133]).is_none(), "identity");
        assert!(AffinePoint::from_sec1(&unc[..132]).is_none(), "truncated");
        // A P-384-sized encoding must not be accepted here.
        assert!(
            AffinePoint::from_sec1(&[0x04u8; 97]).is_none(),
            "wrong width"
        );

        let mut bad = unc;
        bad[132] ^= 1;
        assert!(AffinePoint::from_sec1(&bad).is_none(), "off curve");
    }

    // -- ECDSA ------------------------------------------------------------

    #[test]
    fn sign_and_verify_round_trip() {
        let mut key = [0u8; 66];
        key[65] = 7;
        let mut public = [0u8; 133];
        EcdsaP521Sha512::public_key(&key, &mut public).unwrap();

        for message in [&b""[..], b"a", b"the quick brown fox", &[0x5au8; 1000][..]] {
            let mut signature = [0u8; 132];
            EcdsaP521Sha512::sign(&key, message, &mut signature).unwrap();
            EcdsaP521Sha512::verify(&public, message, &signature).unwrap();
        }
    }

    /// ECDSA signatures are malleable: `(r, s)` and `(r, n - s)` both verify.
    /// Normalizing picks the low-`s` representative, and doing it twice must
    /// change nothing.
    #[test]
    fn normalizing_s_is_idempotent() {
        let mut key = [0u8; 66];
        key[65] = 7;
        let mut public = [0u8; 133];
        EcdsaP521Sha512::public_key(&key, &mut public).unwrap();

        for message in [&b"a"[..], b"b", b"c", b"d"] {
            let mut signature = [0u8; 132];
            EcdsaP521Sha512::sign(&key, message, &mut signature).unwrap();

            let mut normalized = signature;
            EcdsaP521Sha512::normalize_s(&mut normalized).unwrap();
            assert!(EcdsaP521Sha512::has_low_s(&normalized).unwrap());
            EcdsaP521Sha512::verify(&public, message, &normalized).unwrap();

            let mut twice = normalized;
            EcdsaP521Sha512::normalize_s(&mut twice).unwrap();
            assert_eq!(twice, normalized, "normalization is idempotent");
        }
    }

    /// Cross-check against an independent RFC 6979 implementation.
    ///
    /// # Provenance
    ///
    /// RFC 6979 publishes P-521 vectors, but this project's rule is not to
    /// assert a constant it cannot verify, and those were not available to
    /// check against here. So these come from a separate implementation
    /// written from the text of RFC 6979 section 3.2 and from the affine group
    /// law, sharing no code with this one. docs/FIPS.md records the
    /// distinction.
    ///
    /// What makes this worth having: P-521 is the only pairing where the HMAC
    /// output is *narrower* than the group order, so `T` takes two rounds and
    /// `bits2int` has seven bits to shift off. Nothing in the P-256 or P-384
    /// vectors exercises either path.
    #[test]
    fn signatures_match_an_independent_rfc6979_implementation() {
        let mut key = [0u8; 66];
        key[65] = 7;

        // The public key for x = 7, from the same reference.
        let mut public = [0u8; 133];
        EcdsaP521Sha512::public_key(&key, &mut public).unwrap();
        assert_eq!(
            hex(&public[1..67]),
            "0056d5d1d99d5b7f6346eeb65fda0b073a0c5f22e0e8f5483228f018d2c2f711             4c5d8c308d0abfc698d8c9a6df30dce3bbc46f953f50fdc2619a01cead882816ecd4"
                .replace(char::is_whitespace, ""),
            "public key x"
        );
        assert_eq!(
            hex(&public[67..]),
            "003d2d1b7d9baaa2a110d1d8317a39d68478b5c582d02824f0dd71dbd98a26cb             de556bd0f293cdec9e2b9523a34591ce1a5f9e76712a5ddefc7b5c6b8bc90525251b"
                .replace(char::is_whitespace, ""),
            "public key y"
        );

        let cases: &[(&[u8], &str, &str)] = &[
            (
                b"",
                "018a0314748952a0558e30db613981ac046c21bb434d98e8825ad07d192adcfb                 12f0f29c86fee2f59368c77d101e208f289b5b8d563fd0dcb126450a4cf64f33af21",
                "00c17a5af4890ee28950f4477900ad734ea90aa9985cc98c4e5a9242b1aece0a                 19f05ecdfd30e67dab5c0539239913aa82fd19a3d9e250bd6e46f2b30e43d1e47d61",
            ),
            (
                b"a",
                "01e49d6aaa49524d7d9d0a9724bc96ab5271edff11ccbcb56ad4c7353b5d5e35                 d66d7fc592c3039f020cf61388a67a73a9d1dada4fa286357f8fd2f80726383967ca",
                "0185747858829becbeb6d1ae2a1138a56661658ec1c866d9400ca134e1572254                 8ee41e7e0b7852d68c91e5650be30a4da44f72125c6eb2bf382251304ea74109bdf0",
            ),
            (
                b"the quick brown fox",
                "01e8f7a260a7462706d1a3eeb21b244aad1894084cb39d05f5ecb667086d1087                 c9d3d66666aa86b411e81318bf2741120acf0f89ba9494277663dda70ab13e6c645c",
                "0080157cf57486201170f705525fa22c05fcd8e1bd0dd382935f20a4123c2b59                 0f80e15854f33b18a770f1d746218ecff89832af5b62f3bc61e72a013051a2a5d47c",
            ),
        ];

        for (message, want_r, want_s) in cases {
            let mut signature = [0u8; 132];
            EcdsaP521Sha512::sign(&key, message, &mut signature).unwrap();
            assert_eq!(
                hex(&signature[..66]),
                want_r.replace(char::is_whitespace, ""),
                "r for {message:?}"
            );
            assert_eq!(
                hex(&signature[66..]),
                want_s.replace(char::is_whitespace, ""),
                "s for {message:?}"
            );
            EcdsaP521Sha512::verify(&public, message, &signature).unwrap();
        }
    }

    /// RFC 6979 nonces make signing deterministic, so two runs must agree.
    #[test]
    fn signing_is_deterministic() {
        let mut key = [0u8; 66];
        key[65] = 9;
        let mut a = [0u8; 132];
        let mut b = [0u8; 132];
        EcdsaP521Sha512::sign(&key, b"determinism", &mut a).unwrap();
        EcdsaP521Sha512::sign(&key, b"determinism", &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn verification_rejects_tampering() {
        let mut key = [0u8; 66];
        key[65] = 11;
        let mut public = [0u8; 133];
        EcdsaP521Sha512::public_key(&key, &mut public).unwrap();
        let mut signature = [0u8; 132];
        EcdsaP521Sha512::sign(&key, b"message", &mut signature).unwrap();

        assert!(EcdsaP521Sha512::verify(&public, b"messagf", &signature).is_err());
        for bit in [0usize, 7, 260, 527, 1055] {
            let mut bad = signature;
            bad[bit / 8] ^= 1 << (bit % 8);
            assert!(
                EcdsaP521Sha512::verify(&public, b"message", &bad).is_err(),
                "flipped signature bit {bit}"
            );
        }
        assert!(EcdsaP521Sha512::verify(&public, b"message", &signature[..131]).is_err());
    }

    /// A P-384 key must not verify as P-521, which the length checks enforce.
    #[test]
    fn keys_from_another_curve_are_refused() {
        let mut signature = [0u8; 132];
        assert!(EcdsaP521Sha512::sign(&[7u8; 48], b"x", &mut signature).is_err());
        assert!(EcdsaP521Sha512::verify(&[4u8; 97], b"x", &signature).is_err());
    }

    // -- ECDH -------------------------------------------------------------

    #[test]
    fn ecdh_agrees_in_both_directions() {
        let mut alice = [0u8; 66];
        alice[65] = 3;
        let mut bob = [0u8; 66];
        bob[65] = 5;

        let mut alice_public = [0u8; 133];
        let mut bob_public = [0u8; 133];
        EcdhP521::public_key(&alice, &mut alice_public).unwrap();
        EcdhP521::public_key(&bob, &mut bob_public).unwrap();

        let mut a = [0u8; 66];
        let mut b = [0u8; 66];
        EcdhP521::agree(&alice, &bob_public, &mut a).unwrap();
        EcdhP521::agree(&bob, &alice_public, &mut b).unwrap();
        assert_eq!(a, b, "both sides derive the same secret");

        // And the secret is the x-coordinate of [ab]G, not something else.
        let ab = Point::generator()
            .mul_scalar(&scalar(15))
            .to_affine()
            .unwrap();
        assert_eq!(a, ab.x.to_bytes());
    }

    #[test]
    fn ecdh_rejects_a_malformed_peer_key() {
        let mut alice = [0u8; 66];
        alice[65] = 3;
        let mut out = [0u8; 66];
        assert!(
            EcdhP521::agree(&alice, &[0u8; 133], &mut out).is_err(),
            "identity"
        );
        assert!(
            EcdhP521::agree(&alice, &[0x04u8; 133], &mut out).is_err(),
            "off curve"
        );
        assert!(
            EcdhP521::agree(&alice, &[0x04u8; 97], &mut out).is_err(),
            "p-384 width"
        );
    }

    #[test]
    fn compressed_public_keys_match_the_uncompressed_ones() {
        let mut key = [0u8; 66];
        key[65] = 13;
        let mut unc = [0u8; 133];
        let mut comp = [0u8; 67];
        EcdsaP521Sha512::public_key(&key, &mut unc).unwrap();
        EcdsaP521Sha512::public_key_compressed(&key, &mut comp).unwrap();
        assert_eq!(&comp[1..], &unc[1..67], "the x-coordinates agree");
        assert_eq!(comp[0], 0x02 | (unc[132] & 1), "the sign bit");
    }
}
