//! CPU feature detection.
//!
//! Lives in `ic-core` so that both the implementation crates and the ontology
//! can consult it without either depending on the other: `ic-cipher` uses it to
//! pick a backend, and `ic-ontology` uses it to tell an agent which backend is
//! live.
//!
//! Detection is compile-time when the feature is already enabled for the build
//! (`-C target-cpu=native`, or an explicit `-C target-feature=+aes`), and
//! runtime otherwise. Under `no_std` only the compile-time path exists, because
//! runtime detection needs `std`.
//!
//! Every query here depends only on the CPU, never on key material, so none of
//! it is a side channel.

/// Whether x86 AES-NI is available.
///
/// x86 only, deliberately. The ARMv8 cryptographic extension is detected in
/// `ic_cipher::aes::armv8_aes_available`, because selecting it also depends on
/// a cargo feature that this crate has no business knowing about. Reporting it
/// here would additionally make the ontology call an ARM build
/// `hardware-accelerated`, which would be an overclaim: that label means the
/// cipher and the carry-less multiply, and there is no `PMULL` GHASH backend.
#[inline]
#[must_use]
pub fn has_aes() -> bool {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "std"))]
    {
        std::arch::is_x86_feature_detected!("aes")
    }
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        not(feature = "std"),
        target_feature = "aes"
    ))]
    {
        true
    }
    #[cfg(not(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        any(feature = "std", target_feature = "aes")
    )))]
    {
        false
    }
}

/// Whether carry-less multiplication (`PCLMULQDQ`) is available.
///
/// This is what GHASH needs; AES-GCM is only fast when *both* this and
/// [`has_aes`] are true, because the portable GHASH costs far more per block
/// than the portable AES does.
#[inline]
#[must_use]
pub fn has_pclmulqdq() -> bool {
    #[cfg(all(any(target_arch = "x86", target_arch = "x86_64"), feature = "std"))]
    {
        std::arch::is_x86_feature_detected!("pclmulqdq")
    }
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        not(feature = "std"),
        target_feature = "pclmulqdq"
    ))]
    {
        true
    }
    #[cfg(not(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        any(feature = "std", target_feature = "pclmulqdq")
    )))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Detection must not panic and must be stable within a process — a
    /// backend chosen once per key would otherwise be able to disagree with
    /// itself.
    #[test]
    fn detection_is_total_and_stable() {
        let a = has_aes();
        let b = has_pclmulqdq();
        for _ in 0..8 {
            assert_eq!(has_aes(), a);
            assert_eq!(has_pclmulqdq(), b);
        }
    }

    /// On a non-x86 target both must report false rather than guessing.
    #[test]
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    fn non_x86_reports_no_acceleration() {
        assert!(!has_aes());
        assert!(!has_pclmulqdq());
    }
}
