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
    if ic_core::cpu::has_aes() && ic_core::cpu::has_pclmulqdq() {
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
            note: "No third-party crates, no C, no build scripts: for every crate that implements \
                   an algorithm, the dependency graph is the workspace itself, and a per-crate \
                   check enforces that on each build. One crate is outside it -- ic-rustls \
                   implements rustls's traits and so depends on rustls -- and what rustls may \
                   bring is listed by name, so it cannot grow unnoticed. Depend on ic-rustls and \
                   you inherit that; depend on anything else here and you do not.",
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
            note: "x86-64 AES-NI and PCLMULQDQ, selected at runtime and validated against the \
                   portable backend. Absent on other targets, where AES falls back to the \
                   constant-time portable path at single-digit MB/s.",
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
            present: true,
            note: "ML-KEM-768 and ML-DSA-65, both checked against NIST's published ACVP vectors -- \
                   every case in each parameter set, not a selection. Only the 768 and 65 parameter \
                   sets are present. Deploy the KEM in a hybrid with X25519 rather than alone: \
                   lattice cryptanalysis is young, and that is a judgement about the scheme's age \
                   rather than about this implementation.",
        },
        Capability {
            id: "approved-asymmetric",
            present: true,
            note: "ECDSA and ECDH over P-256, P-384 and P-521, and RSA signatures in both \
                   PKCS#1 v1.5 and PSS, with CRT private operations.",
        },
        Capability {
            id: "tls-provider",
            present: true,
            note: "AES-GCM, SHA-2, HMAC, HKDF, ECDSA verification and ECDH, wired to rustls as a \
                   CryptoProvider by the ic-rustls crate, for TLS 1.3 and TLS 1.2. That crate is \
                   the one here that depends on anything outside the workspace, because a rustls \
                   provider must depend on rustls. It verifies signatures and does not make them, \
                   so it has no signing key provider and cannot present a certificate.",
        },
        Capability {
            id: "key-encoding",
            present: true,
            note: "Keys and signatures read and write as DER and PEM: SubjectPublicKeyInfo, \
                   PKCS#8, SEC1, and Ecdsa-Sig-Value, through ic_pkix. X.509 certificate parsing \
                   is not included.",
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
        let accelerated = ic_core::cpu::has_aes() && ic_core::cpu::has_pclmulqdq();
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
    }

    /// A capability's note is prose an agent reads, so it must read as prose.
    ///
    /// A Rust string broken across lines needs a trailing backslash, which eats
    /// the newline and the next line's indentation. Without it the indentation
    /// stays in the string. Four MCP tool descriptions had exactly that defect;
    /// the check that catches them looks only at tool descriptions, and this
    /// found `hardware-acceleration` carrying two runs of twenty spaces.
    #[test]
    fn capability_notes_read_as_prose() {
        let mut checked = 0;
        for c in capabilities() {
            assert!(
                !c.note.contains("  "),
                "{}: the note has a run of spaces, so a line continuation is missing: {:?}",
                c.id,
                c.note
            );
            assert!(
                !c.note.contains('\n') && !c.note.contains('\t'),
                "{}: the note has a literal newline or tab",
                c.id
            );
            assert!(
                c.note.trim() == c.note && c.note.len() > 20,
                "{}: the note is padded, or too short to say anything",
                c.id
            );
            checked += 1;
        }
        assert!(checked >= 8, "only {checked} capabilities examined");
    }

    #[test]
    fn implemented_capabilities_report_true() {
        // `post-quantum` was in the test above until ML-KEM-768 and ML-DSA-65
        // were checked against ACVP vectors. `fips-validated` stays there, and
        // stays until a certificate exists: it is not a property of code.
        assert!(has("post-quantum"));
        assert!(has("no-std"));
        assert!(has("zero-dependencies"));
        assert!(has("constant-time-symmetric"));
        assert!(has("approved-asymmetric"));
        assert!(has("key-encoding"));
        assert!(has("tls-provider"));
    }

    #[test]
    fn unknown_capability_is_false_not_a_panic() {
        assert!(!has("teleportation"));
        assert!(capability("teleportation").is_none());
    }
}
