//! ML-DSA-44 (FIPS 204), checked against NIST's ACVP vectors.
//!
//! The same scheme as [`crate::sign`], ML-DSA-65, instantiated with FIPS 204's
//! ML-DSA-44 parameters: a 4 by 4 matrix, `eta` 2, `tau` 39,
//! `gamma1` 2^17, `gamma2` (q-1)/88, `omega` 80, and a
//! 32-byte challenge digest. It is security category 2. The private
//! `scheme` module says why it is one body with three instantiations.
//!
//! Checked against every ML-DSA-44 key-generation case and every external,
//! pure signature case in NIST's ACVP vectors -- 25 and 30, the signatures 15
//! deterministic and 15 hedged -- drawn from the same pinned ACVP-Server
//! commit as ML-DSA-65's.

crate::scheme::ml_dsa!(4, 4, 2, ETA2_BITS, 39, 1 << 17, GAMMA2_88, 80, 32);

#[cfg(test)]
mod tests {
    use super::*;

    /// The sizes FIPS 204 tabulates for ML-DSA-44. They follow from the
    /// parameters rather than from this code, so a wrong parameter shows here.
    #[test]
    fn the_sizes_match_the_standard() {
        assert_eq!(PUBLIC_KEY_LEN, 1312);
        assert_eq!(SECRET_KEY_LEN, 2560);
        assert_eq!(SIGNATURE_LEN, 2420);
    }

    /// Generate, sign, verify; then tamper and fail.
    #[test]
    fn sign_and_verify_agree() {
        let mut pk = [0u8; PUBLIC_KEY_LEN];
        let mut sk = [0u8; SECRET_KEY_LEN];
        assert!(keygen(&[44u8; 32], &mut pk, &mut sk));
        let mut sig = [0u8; SIGNATURE_LEN];
        assert!(sign(&sk, b"ml-dsa-44", b"ctx", &[7u8; 32], &mut sig));
        assert!(verify(&pk, b"ml-dsa-44", b"ctx", &sig));
        assert!(
            !verify(&pk, b"ml-dsa-44", b"other", &sig),
            "context is bound"
        );
        sig[3] ^= 1;
        assert!(!verify(&pk, b"ml-dsa-44", b"ctx", &sig));
    }
}
