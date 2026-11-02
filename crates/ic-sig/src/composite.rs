//! Composite ML-DSA: ML-DSA and EdDSA signatures over one message, both
//! required, per draft-ietf-lamps-pq-composite-sigs-19.
//!
//! Three of the draft's algorithms, the ones whose traditional half is EdDSA:
//!
//! | algorithm | OID | pre-hash |
//! |---|---|---|
//! | `id-MLDSA44-Ed25519-SHA512` | 1.3.6.1.5.5.7.6.39 | SHA-512 |
//! | `id-MLDSA65-Ed25519-SHA512` | 1.3.6.1.5.5.7.6.48 | SHA-512 |
//! | `id-MLDSA87-Ed448-SHAKE256` | 1.3.6.1.5.5.7.6.51 | SHAKE256, 64 bytes |
//!
//! Both components sign the message representative
//!
//! ```text
//! M' = "CompositeAlgorithmSignatures2025" || Label || len(ctx) || ctx || PH(M)
//! ```
//!
//! ML-DSA under the algorithm's label as its own context, EdDSA with none.
//! A signature verifies only if both halves do, so it stands while either
//! ML-DSA or the curve does.
//!
//! The encodings are concatenations (draft section 4): a public key is the
//! ML-DSA key then the EdDSA key, a private key the 32-byte ML-DSA seed then
//! the EdDSA seed, a signature the ML-DSA signature then the EdDSA one. Every
//! component is fixed length, so each total is exact and checked exactly.
//!
//! An Internet-Draft, not yet an RFC: the label, the prefix and the OIDs are
//! the draft's and change if it does. Checked against its Appendix E vectors.

// The operations need EdDSA, which an approved-only build leaves out; the
// algorithm names and lengths do not, so keys and SignatureAlgorithm can name
// a composite in every build.
#[cfg(not(ic_approved_only))]
mod ops;
#[cfg(not(ic_approved_only))]
pub use ops::{public_key, self_test, sign, verify};

/// A composite ML-DSA algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Composite {
    /// `id-MLDSA44-Ed25519-SHA512`.
    MlDsa44Ed25519Sha512,
    /// `id-MLDSA65-Ed25519-SHA512`.
    MlDsa65Ed25519Sha512,
    /// `id-MLDSA87-Ed448-SHAKE256`.
    MlDsa87Ed448Shake256,
}

impl Composite {
    /// Every composite here.
    pub const ALL: [Composite; 3] = [
        Self::MlDsa44Ed25519Sha512,
        Self::MlDsa65Ed25519Sha512,
        Self::MlDsa87Ed448Shake256,
    ];

    /// The ontology identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::MlDsa44Ed25519Sha512 => "mldsa44-ed25519-sha512",
            Self::MlDsa65Ed25519Sha512 => "mldsa65-ed25519-sha512",
            Self::MlDsa87Ed448Shake256 => "mldsa87-ed448-shake256",
        }
    }

    /// The signature label, bound into every signature (draft section 6).
    pub const fn label(self) -> &'static [u8] {
        match self {
            Self::MlDsa44Ed25519Sha512 => b"COMPSIG-MLDSA44-Ed25519-SHA512",
            Self::MlDsa65Ed25519Sha512 => b"COMPSIG-MLDSA65-Ed25519-SHA512",
            Self::MlDsa87Ed448Shake256 => b"COMPSIG-MLDSA87-Ed448-SHAKE256",
        }
    }

    /// The object identifier's DER content bytes: 1.3.6.1.5.5.7.6.39, .48
    /// and .51.
    pub const fn oid(self) -> &'static [u8] {
        match self {
            Self::MlDsa44Ed25519Sha512 => &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x27],
            Self::MlDsa65Ed25519Sha512 => &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x30],
            Self::MlDsa87Ed448Shake256 => &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x33],
        }
    }

    /// The composite whose object identifier this is.
    pub fn from_oid(oid: &[u8]) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.oid() == oid)
    }

    /// Lengths of the ML-DSA and EdDSA public keys, private keys and
    /// signatures, in that order.
    const fn parts(self) -> [(usize, usize); 3] {
        use ic_mldsa::{sign as m65, sign44 as m44, sign87 as m87};
        match self {
            Self::MlDsa44Ed25519Sha512 => [
                (m44::PUBLIC_KEY_LEN, 32),
                (32, 32),
                (m44::SIGNATURE_LEN, 64),
            ],
            Self::MlDsa65Ed25519Sha512 => [
                (m65::PUBLIC_KEY_LEN, 32),
                (32, 32),
                (m65::SIGNATURE_LEN, 64),
            ],
            Self::MlDsa87Ed448Shake256 => [
                (m87::PUBLIC_KEY_LEN, 57),
                (32, 57),
                (m87::SIGNATURE_LEN, 114),
            ],
        }
    }

    /// The public key's length: 1344, 1984 or 2649 bytes.
    pub const fn public_key_len(self) -> usize {
        let (a, b) = self.parts()[0];
        a + b
    }

    /// The private key's length: 64, 64 or 89 bytes.
    pub const fn private_key_len(self) -> usize {
        let (a, b) = self.parts()[1];
        a + b
    }

    /// The signature's length: 2484, 3373 or 4741 bytes.
    pub const fn signature_len(self) -> usize {
        let (a, b) = self.parts()[2];
        a + b
    }
}
