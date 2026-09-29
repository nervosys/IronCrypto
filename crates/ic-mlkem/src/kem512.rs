//! ML-KEM-512 (FIPS 203), checked against NIST's ACVP vectors.
//!
//! The same scheme as [`crate::kem`], ML-KEM-768, instantiated with FIPS 203's
//! ML-KEM-512 parameters: module rank 2, noise widths 3 and 2, and
//! ciphertext compression widths 10 and 4. The private `scheme` module says why it
//! is one body with three instantiations.
//!
//! Checked against every ML-KEM-512 key-generation and encapsulation case in
//! NIST's ACVP vectors, 25 of each, drawn from the same pinned ACVP-Server
//! commit as ML-KEM-768's.

crate::scheme::ml_kem!(MlKem512, "ML-KEM-512.", 2, 3, 2, 10, 4);

#[cfg(test)]
mod tests {
    use super::*;

    /// The sizes FIPS 203 tabulates for ML-KEM-512. They follow from the
    /// parameters rather than from this code, so a wrong parameter shows here.
    #[test]
    fn the_sizes_match_the_standard() {
        assert_eq!(ENCAPS_KEY_LEN, 800);
        assert_eq!(DECAPS_KEY_LEN, 1632);
        assert_eq!(CIPHERTEXT_LEN, 768);
        assert_eq!(SHARED_SECRET_LEN, 32);
    }

    /// Generate, encapsulate, decapsulate, and agree; then tamper and disagree.
    #[test]
    fn encapsulation_and_decapsulation_agree() {
        let mut rng = ic_drbg::Rng::from_entropy(&[0u8; 32], b"ml-kem-512").unwrap();
        let mut ek = [0u8; ENCAPS_KEY_LEN];
        let mut dk = [0u8; DECAPS_KEY_LEN];
        MlKem512::keygen(&mut rng, &mut ek, &mut dk).unwrap();
        let mut ct = [0u8; CIPHERTEXT_LEN];
        let (mut sent, mut received) = ([0u8; 32], [0u8; 32]);
        MlKem512::encapsulate(&mut rng, &ek, &mut ct, &mut sent).unwrap();
        MlKem512::decapsulate(&dk, &ct, &mut received).unwrap();
        assert_eq!(sent, received);
        ct[7] ^= 1;
        MlKem512::decapsulate(&dk, &ct, &mut received).unwrap();
        assert_ne!(
            sent, received,
            "a tampered ciphertext must not yield the secret"
        );
    }
}
