//! What this particular build can actually do.
//!
//! The registry describes algorithms in the abstract. This module describes the
//! *binary in front of you*: which backend is compiled in, what it implies for
//! throughput, and which optional features are on. An agent deciding whether to
//! stream a gigabyte through AES-GCM needs this, not the specification.

/// The cryptographic backend compiled into this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Pure Rust, constant-time, no hardware acceleration and no C.
    ///
    /// AES computes its S-box algebraically and GHASH multiplies bit by bit, so
    /// neither indexes memory with a secret. Correct and portable; not fast.
    PortableConstantTime,
    /// Hardware-accelerated: x86-64 AES-NI for the cipher and `PCLMULQDQ` for
    /// GHASH.
    ///
    /// Selected automatically when the CPU supports both. The accelerated
    /// paths are differentially tested against the portable ones, so this is a
    /// speed choice rather than a trust choice.
    HardwareAccelerated,
}

impl Backend {
    /// Stable identifier used in CLI and MCP output.
    pub const fn id(self) -> &'static str {
        match self {
            Self::PortableConstantTime => "portable-constant-time",
            Self::HardwareAccelerated => "hardware-accelerated",
        }
    }

    /// Whether bulk symmetric throughput is expected to be competitive.
    pub const fn fast_bulk_symmetric(self) -> bool {
        matches!(self, Self::HardwareAccelerated)
    }
}

/// The backend this build is using, determined from the CPU.
///
/// This is a runtime query rather than a constant: the same binary reports
/// `HardwareAccelerated` on a CPU with AES-NI and `PortableConstantTime` on one
/// without, and an agent sizing a workload needs the answer for the machine it
/// is actually on.
pub fn backend() -> Backend {
    // AES-GCM is only fast when *both* are present: without the carry-less
    // multiply, GHASH dominates and the AES speedup is invisible.
    if ac_core::cpu::has_aes() && ac_core::cpu::has_pclmulqdq() {
        Backend::HardwareAccelerated
    } else {
        Backend::PortableConstantTime
    }
}

/// A capability an agent may want to check before relying on it.
#[derive(Debug, Clone, Copy)]
pub struct Capability {
    /// Stable identifier.
    pub id: &'static str,
    /// Whether this build has it.
    pub present: bool,
    /// What it means.
    pub note: &'static str,
}

/// Everything this build does and does not provide.
pub fn capabilities() -> impl Iterator<Item = Capability> {
    [
        Capability {
            id: "no-std",
            present: true,
            note: "Every crate builds without the standard library; only the CLI and the string \
                   codec helpers require std.",
        },
        Capability {
            id: "zero-dependencies",
            present: true,
            note: "No third-party crates, no C, no build scripts. The dependency graph is the \
                   workspace itself.",
        },
        Capability {
            id: "constant-time-symmetric",
            present: true,
            note:
                "AES and GHASH avoid secret-dependent memory addressing, closing the cache-timing \
                   channel that table-driven implementations leave open.",
        },
        Capability {
            id: "hardware-acceleration",
            present: backend().fast_bulk_symmetric(),
            note: "x86-64 AES-NI and PCLMULQDQ, selected at runtime and validated against the                    portable backend. Absent on other targets, where AES falls back to the                    constant-time portable path at single-digit MB/s.",
        },
        Capability {
            id: "fips-validated",
            present: false,
            note: "This module implements the FIPS 140-3 discipline — approved-mode policy, \
                   power-on self-tests, service indicators — but it holds no CMVP certificate. Do \
                   not represent it as validated.",
        },
        Capability {
            id: "post-quantum",
            present: false,
            note: "ML-KEM and ML-DSA are registered in the ontology as planned, not implemented.",
        },
        Capability {
            id: "approved-asymmetric",
            present: true,
            note: "ECDSA and ECDH over P-256 are implemented. P-384, P-521, and RSA are not; the \
                   ontology registers them as planned.",
        },
    ]
    .into_iter()
}

/// Look up one capability by identifier.
pub fn capability(id: &str) -> Option<Capability> {
    capabilities().find(|c| c.id == id)
}

/// Whether this build has the named capability.
pub fn has(id: &str) -> bool {
    capability(id).map(|c| c.present).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The backend reported must match what the cipher crate actually selects.
    /// A disagreement would make the ontology lie about the binary it ships in.
    #[test]
    fn backend_matches_the_cpu() {
        let accelerated = ac_core::cpu::has_aes() && ac_core::cpu::has_pclmulqdq();
        assert_eq!(
            backend(),
            if accelerated {
                Backend::HardwareAccelerated
            } else {
                Backend::PortableConstantTime
            }
        );
        assert_eq!(backend().fast_bulk_symmetric(), accelerated);
        assert_eq!(has("hardware-acceleration"), accelerated);
    }

    #[test]
    fn capabilities_are_unique_and_documented() {
        let caps: std::vec::Vec<_> = capabilities().collect();
        assert!(!caps.is_empty());
        for (i, a) in caps.iter().enumerate() {
            for b in caps.iter().skip(i + 1) {
                assert_ne!(a.id, b.id);
            }
            assert!(!a.note.is_empty(), "{} needs a note", a.id);
        }
    }

    /// The point of this module is honesty about what is absent, so the absent
    /// ones are asserted explicitly.
    #[test]
    fn unimplemented_capabilities_report_false() {
        assert!(!has("fips-validated"));
        assert!(!has("post-quantum"));
    }

    #[test]
    fn implemented_capabilities_report_true() {
        assert!(has("no-std"));
        assert!(has("zero-dependencies"));
        assert!(has("constant-time-symmetric"));
        assert!(has("approved-asymmetric"));
    }

    #[test]
    fn unknown_capability_is_false_not_a_panic() {
        assert!(!has("teleportation"));
        assert!(capability("teleportation").is_none());
    }
}
