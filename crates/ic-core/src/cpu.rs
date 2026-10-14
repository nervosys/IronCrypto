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
/// x86 only, deliberately: `ic_cipher::aes::aesni_available` is this, and it
/// selects the x86 backend. The ARMv8 extension is [`has_armv8_aes`].
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
/// The instruction GHASH needs, but not a sufficient condition for GHASH to use
/// it: whether it will is [`has_ghash_clmul`], which is what to ask before
/// concluding that AES-GCM is fast.
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

/// Whether GHASH will run on the carry-less multiply in this build.
///
/// Not the same question as [`has_pclmulqdq`]. The instruction is necessary but
/// the backend also needs `ssse3` for its byte-reversal shuffle, and it exists
/// only on x86-64 with `std`. A 32-bit x86 build on a CPU that has every one of
/// those instructions still runs the portable GHASH.
///
/// This is the predicate `ic_cipher::gcm` dispatches on and the one the
/// ontology reports from, so the two cannot disagree. They did: the report
/// used to ask only whether the CPU had the instruction, and told agents on
/// 32-bit x86 that AES-GCM was fast when it ran at a fortieth of the speed of
/// ChaCha20-Poly1305.
#[inline]
#[must_use]
pub fn has_ghash_clmul() -> bool {
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    {
        std::arch::is_x86_feature_detected!("pclmulqdq")
            && std::arch::is_x86_feature_detected!("ssse3")
    }
    #[cfg(not(all(target_arch = "x86_64", feature = "std")))]
    {
        false
    }
}

/// Whether the ARMv8 AES backend is compiled in and this CPU can run it.
///
/// Two conditions. The CPU must have `FEAT_AES`, and the build must have the
/// `aarch64-crypto` feature, which `ic-cipher`'s feature of the same name turns
/// on here. The feature exists because the ARM backends have not yet run on
/// ARM hardware, only under emulation; without it an ARM build keeps the
/// portable code, and this says so. `ic_cipher::aes::armv8_aes_available` is
/// this function, so the ontology and the cipher cannot disagree.
#[inline]
#[must_use]
pub fn has_armv8_aes() -> bool {
    #[cfg(all(target_arch = "aarch64", feature = "aarch64-crypto", feature = "std"))]
    {
        std::arch::is_aarch64_feature_detected!("aes")
    }
    #[cfg(not(all(target_arch = "aarch64", feature = "aarch64-crypto", feature = "std")))]
    {
        false
    }
}

/// Whether GHASH will run on `PMULL` in this build.
///
/// The ARM counterpart of [`has_ghash_clmul`], under the same two conditions
/// as [`has_armv8_aes`]. `ic_cipher::gcm` dispatches on it, and the ontology
/// reports from it.
#[inline]
#[must_use]
pub fn has_ghash_pmull() -> bool {
    #[cfg(all(target_arch = "aarch64", feature = "aarch64-crypto", feature = "std"))]
    {
        std::arch::is_aarch64_feature_detected!("neon")
            && std::arch::is_aarch64_feature_detected!("pmull")
    }
    #[cfg(not(all(target_arch = "aarch64", feature = "aarch64-crypto", feature = "std")))]
    {
        false
    }
}

/// Whether the x86-64 wide-multiply instructions are available: `MULX` (BMI2)
/// and the two independent carry chains of `ADCX`/`ADOX` (ADX).
///
/// What `ic_ec`'s four-limb Curve25519 field needs. x86-64 only: the field is
/// written for sixteen 64-bit registers, and a 32-bit x86 build has neither
/// those nor a 64x64 multiply to put in them. Every x86-64 CPU since Intel
/// Broadwell (2014) and AMD Zen (2017) has both.
#[inline]
#[must_use]
pub fn has_bmi2_adx() -> bool {
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    {
        std::arch::is_x86_feature_detected!("bmi2") && std::arch::is_x86_feature_detected!("adx")
    }
    #[cfg(all(
        target_arch = "x86_64",
        not(feature = "std"),
        target_feature = "bmi2",
        target_feature = "adx"
    ))]
    {
        true
    }
    #[cfg(not(all(
        target_arch = "x86_64",
        any(feature = "std", all(target_feature = "bmi2", target_feature = "adx"))
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
        let c = has_bmi2_adx();
        let d = has_armv8_aes();
        let e = has_ghash_pmull();
        for _ in 0..8 {
            assert_eq!(has_aes(), a);
            assert_eq!(has_pclmulqdq(), b);
            assert_eq!(has_bmi2_adx(), c);
            assert_eq!(has_armv8_aes(), d);
            assert_eq!(has_ghash_pmull(), e);
        }
    }

    /// Off aarch64, or without the feature, the ARM predicates must say no.
    #[test]
    #[cfg(not(all(target_arch = "aarch64", feature = "aarch64-crypto", feature = "std")))]
    fn the_arm_backends_are_absent_without_the_feature() {
        assert!(!has_armv8_aes());
        assert!(!has_ghash_pmull());
    }

    /// On a non-x86 target both must report false rather than guessing.
    #[test]
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    fn non_x86_reports_no_acceleration() {
        assert!(!has_aes());
        assert!(!has_pclmulqdq());
    }
}
