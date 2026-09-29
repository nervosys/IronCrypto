//! ML-DSA-87 (FIPS 204), checked against NIST's ACVP vectors.
//!
//! The same scheme as [`crate::sign`], ML-DSA-65, instantiated with FIPS 204's
//! ML-DSA-87 parameters: a 8 by 7 matrix, `eta` 2, `tau` 60,
//! `gamma1` 2^19, `gamma2` (q-1)/32, `omega` 75, and a
//! 64-byte challenge digest. It is security category 5. The private
//! `scheme` module says why it is one body with three instantiations.
//!
//! Checked against every ML-DSA-87 key-generation case and every external,
//! pure signature case in NIST's ACVP vectors -- 25 and 30, the signatures 15
//! deterministic and 15 hedged -- drawn from the same pinned ACVP-Server
//! commit as ML-DSA-65's.

crate::scheme::ml_dsa!(8, 7, 2, ETA2_BITS, 60, 1 << 19, GAMMA2_32, 75, 64);

#[cfg(test)]
mod tests {
    use super::*;

    /// The sizes FIPS 204 tabulates for ML-DSA-87. They follow from the
    /// parameters rather than from this code, so a wrong parameter shows here.
    #[test]
    fn the_sizes_match_the_standard() {
        assert_eq!(PUBLIC_KEY_LEN, 2592);
        assert_eq!(SECRET_KEY_LEN, 4896);
        assert_eq!(SIGNATURE_LEN, 4627);
    }

    /// Generate, sign, verify; then tamper and fail.
    #[test]
    fn sign_and_verify_agree() {
        let mut pk = [0u8; PUBLIC_KEY_LEN];
        let mut sk = [0u8; SECRET_KEY_LEN];
        assert!(keygen(&[87u8; 32], &mut pk, &mut sk));
        let mut sig = [0u8; SIGNATURE_LEN];
        assert!(sign(&sk, b"ml-dsa-87", b"ctx", &[7u8; 32], &mut sig));
        assert!(verify(&pk, b"ml-dsa-87", b"ctx", &sig));
        assert!(
            !verify(&pk, b"ml-dsa-87", b"other", &sig),
            "context is bound"
        );
        sig[3] ^= 1;
        assert!(!verify(&pk, b"ml-dsa-87", b"ctx", &sig));
    }
}
