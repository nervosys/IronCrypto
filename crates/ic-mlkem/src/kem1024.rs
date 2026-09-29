//! ML-KEM-1024 (FIPS 203), checked against NIST's ACVP vectors.
//!
//! The same scheme as [`crate::kem`], ML-KEM-768, instantiated with FIPS 203's
//! ML-KEM-1024 parameters: module rank 4, noise widths 2 and 2, and
//! ciphertext compression widths 11 and 5. The private `scheme` module says why it
//! is one body with three instantiations.
//!
//! Checked against every ML-KEM-1024 key-generation and encapsulation case in
//! NIST's ACVP vectors, 25 of each, drawn from the same pinned ACVP-Server
//! commit as ML-KEM-768's.

crate::scheme::ml_kem!(MlKem1024, "ML-KEM-1024.", 4, 2, 2, 11, 5);

#[cfg(test)]
mod tests {
    use super::*;

    /// The sizes FIPS 203 tabulates for ML-KEM-1024. They follow from the
    /// parameters rather than from this code, so a wrong parameter shows here.
    #[test]
    fn the_sizes_match_the_standard() {
        assert_eq!(ENCAPS_KEY_LEN, 1568);
        assert_eq!(DECAPS_KEY_LEN, 3168);
        assert_eq!(CIPHERTEXT_LEN, 1568);
        assert_eq!(SHARED_SECRET_LEN, 32);
    }

    /// Generate, encapsulate, decapsulate, and agree; then tamper and disagree.
    #[test]
    fn encapsulation_and_decapsulation_agree() {
        let mut rng = ic_drbg::Rng::from_entropy(&[0u8; 32], b"ml-kem-1024").unwrap();
        let mut ek = [0u8; ENCAPS_KEY_LEN];
        let mut dk = [0u8; DECAPS_KEY_LEN];
        MlKem1024::keygen(&mut rng, &mut ek, &mut dk).unwrap();
        let mut ct = [0u8; CIPHERTEXT_LEN];
        let (mut sent, mut received) = ([0u8; 32], [0u8; 32]);
        MlKem1024::encapsulate(&mut rng, &ek, &mut ct, &mut sent).unwrap();
        MlKem1024::decapsulate(&dk, &ct, &mut received).unwrap();
        assert_eq!(sent, received);
        ct[7] ^= 1;
        MlKem1024::decapsulate(&dk, &ct, &mut received).unwrap();
        assert_ne!(
            sent, received,
            "a tampered ciphertext must not yield the secret"
        );
    }
}
