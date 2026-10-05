//! ML-DSA private keys in PKCS#8, in the three forms RFC 9881 defines.
//!
//! ```text
//! ML-DSA-PrivateKey ::= CHOICE {
//!     seed        [0] IMPLICIT OCTET STRING (SIZE (32)),
//!     expandedKey     OCTET STRING,
//!     both            SEQUENCE {
//!         seed        OCTET STRING (SIZE (32)),
//!         expandedKey OCTET STRING } }
//! ```
//!
//! That choice sits inside `PrivateKeyInfo`'s `privateKey` octet string, under
//! `id-ml-dsa-44`, `-65` or `-87` with the parameters absent. The expanded key
//! is FIPS 204's encoded signing key: 2560, 4032 or 4896 bytes.
//!
//! # Why this is not a variant of [`crate::PrivateKeyInfo`]
//!
//! [`crate::PrivateKeyInfo`] is an exhaustive enum, and adding a variant would
//! break every caller that matches on it. So it goes on reporting an ML-DSA
//! key as [`crate::PrivateKeyInfo::Unsupported`] with the ML-DSA OID, and a
//! caller hands the same DER to [`MlDsaPrivateKey::from_der`].
//!
//! # What this does not check
//!
//! A key in the `both` form carries the seed and the expanded key it should
//! generate. Whether they agree is a question for ML-DSA key generation, and
//! this crate performs no cryptography: regenerate the key from the seed with
//! `ic_mldsa` and compare the result with [`MlDsaPrivateKey::expanded_key`]
//! using `ic_core::ct::verify`, and refuse the file if they differ. A file
//! whose halves disagree is either corrupt or built to have one party use a
//! different key from the one the other half names.
//!
//! As with every private key in this crate, the parsed key borrows from the
//! caller's buffer, and erasing that buffer is the caller's part.

use crate::der::{self, Reader, Writer};
use crate::oid;
use ic_core::{ensure, Result};

/// An ML-DSA parameter set, as a PKCS#8 algorithm identifier names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaParameterSet {
    /// ML-DSA-44, `id-ml-dsa-44`.
    MlDsa44,
    /// ML-DSA-65, `id-ml-dsa-65`.
    MlDsa65,
    /// ML-DSA-87, `id-ml-dsa-87`.
    MlDsa87,
}

impl MlDsaParameterSet {
    /// The parameter set an algorithm OID names, if it names one.
    pub fn from_oid(oid: &[u8]) -> Option<Self> {
        if oid == oid::ML_DSA_44 {
            Some(Self::MlDsa44)
        } else if oid == oid::ML_DSA_65 {
            Some(Self::MlDsa65)
        } else if oid == oid::ML_DSA_87 {
            Some(Self::MlDsa87)
        } else {
            None
        }
    }

    /// The algorithm OID's content bytes.
    pub const fn oid(self) -> &'static [u8] {
        match self {
            Self::MlDsa44 => oid::ML_DSA_44,
            Self::MlDsa65 => oid::ML_DSA_65,
            Self::MlDsa87 => oid::ML_DSA_87,
        }
    }

    /// Stable identifier, matching the ontology.
    pub const fn id(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ml-dsa-44",
            Self::MlDsa65 => "ml-dsa-65",
            Self::MlDsa87 => "ml-dsa-87",
        }
    }

    /// Length of FIPS 204's encoded signing key, the `expandedKey`.
    pub const fn expanded_key_len(self) -> usize {
        match self {
            Self::MlDsa44 => 2560,
            Self::MlDsa65 => 4032,
            Self::MlDsa87 => 4896,
        }
    }
}

/// Length of an ML-DSA seed, `xi` in FIPS 204.
pub const SEED_LEN: usize = 32;

/// An ML-DSA private key, in whichever of RFC 9881's forms it was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaPrivateKey<'a> {
    /// The 32-byte seed alone. RFC 9881 recommends this form.
    Seed {
        /// Which parameter set.
        set: MlDsaParameterSet,
        /// The seed, exactly [`SEED_LEN`] bytes.
        seed: &'a [u8],
    },
    /// FIPS 204's encoded signing key alone, without the seed it came from.
    ExpandedKey {
        /// Which parameter set.
        set: MlDsaParameterSet,
        /// The encoded signing key, [`MlDsaParameterSet::expanded_key_len`] bytes.
        expanded_key: &'a [u8],
    },
    /// Both. OpenSSL 3.5 writes this form by default. See the module note on
    /// checking that the two agree.
    Both {
        /// Which parameter set.
        set: MlDsaParameterSet,
        /// The seed, exactly [`SEED_LEN`] bytes.
        seed: &'a [u8],
        /// The encoded signing key, [`MlDsaParameterSet::expanded_key_len`] bytes.
        expanded_key: &'a [u8],
    },
}

impl<'a> MlDsaPrivateKey<'a> {
    /// Parse a PKCS#8 `PrivateKeyInfo` holding an ML-DSA key.
    ///
    /// As strict as [`crate::PrivateKeyInfo::from_der`]: version 0 only, no
    /// attributes, nothing trailing at any level, and here also no algorithm
    /// parameters, which RFC 9881 requires to be absent. A key for any other
    /// algorithm is refused with `Unsupported`; a seed or expanded key of the
    /// wrong length for its parameter set with `InvalidLength`.
    pub fn from_der(input: &'a [u8]) -> Result<Self> {
        let mut outer = Reader::new(input);
        let mut pki = outer.sequence()?;
        outer.finish()?;
        pki.expect_version(0)?;

        let mut alg = pki.sequence()?;
        let algorithm_oid = alg.oid()?;
        let set = MlDsaParameterSet::from_oid(algorithm_oid)
            .ok_or(ic_core::err!(Unsupported, "not an ML-DSA private key"))?;
        alg.finish()?;

        let inner = pki.octet_string()?;
        ensure!(
            pki.peek_tag() != Some(der::context(0)),
            Unsupported,
            "pkcs#8 attributes are not supported, and are refused rather than dropped"
        );
        pki.finish()?;

        let mut choice = Reader::new(inner);
        let key = match choice.peek_tag() {
            Some(SEED_TAG) => {
                let seed = choice.expect(SEED_TAG)?;
                Self::Seed { set, seed }
            }
            Some(der::OCTET_STRING) => {
                let expanded_key = choice.octet_string()?;
                Self::ExpandedKey { set, expanded_key }
            }
            Some(der::SEQUENCE) => {
                let mut both = choice.sequence()?;
                let seed = both.octet_string()?;
                let expanded_key = both.octet_string()?;
                both.finish()?;
                Self::Both {
                    set,
                    seed,
                    expanded_key,
                }
            }
            _ => {
                return Err(ic_core::err!(
                    MalformedEncoding,
                    "ML-DSA private key is none of seed, expandedKey or both"
                ))
            }
        };
        choice.finish()?;
        key.check_lengths()?;
        Ok(key)
    }

    /// Which parameter set.
    pub fn parameter_set(&self) -> MlDsaParameterSet {
        match self {
            Self::Seed { set, .. } | Self::ExpandedKey { set, .. } | Self::Both { set, .. } => *set,
        }
    }

    /// The seed, if this form carries one.
    pub fn seed(&self) -> Option<&'a [u8]> {
        match self {
            Self::Seed { seed, .. } | Self::Both { seed, .. } => Some(seed),
            Self::ExpandedKey { .. } => None,
        }
    }

    /// The expanded key, if this form carries one.
    pub fn expanded_key(&self) -> Option<&'a [u8]> {
        match self {
            Self::ExpandedKey { expanded_key, .. } | Self::Both { expanded_key, .. } => {
                Some(expanded_key)
            }
            Self::Seed { .. } => None,
        }
    }

    fn check_lengths(&self) -> Result<()> {
        let set = self.parameter_set();
        if let Some(seed) = self.seed() {
            ensure!(
                seed.len() == SEED_LEN,
                InvalidLength,
                "ML-DSA seed must be 32 bytes"
            );
        }
        if let Some(expanded) = self.expanded_key() {
            ensure!(
                expanded.len() == set.expanded_key_len(),
                InvalidLength,
                "ML-DSA expanded key length does not match its parameter set"
            );
        }
        Ok(())
    }

    /// Write the PKCS#8 encoding into `out`, returning its length.
    ///
    /// The exact bytes [`Self::from_der`] reads, in the same form: a key read
    /// and written back is unchanged.
    pub fn to_der(&self, out: &mut [u8]) -> Result<usize> {
        self.check_lengths()?;
        let mut w = Writer::new(out);
        let start = w.len();

        // privateKey's content, innermost first because the writer runs
        // backwards.
        match self {
            Self::Seed { seed, .. } => w.push_element(SEED_TAG, seed)?,
            Self::ExpandedKey { expanded_key, .. } => w.push_octet_string(expanded_key)?,
            Self::Both {
                seed, expanded_key, ..
            } => {
                let both_start = w.len();
                w.push_octet_string(expanded_key)?;
                w.push_octet_string(seed)?;
                w.push_wrapper(der::SEQUENCE, both_start)?;
            }
        }
        w.push_wrapper(der::OCTET_STRING, start)?;

        let alg_start = w.len();
        w.push_oid(self.parameter_set().oid())?;
        w.push_wrapper(der::SEQUENCE, alg_start)?;

        w.push_unsigned_u64(0)?;
        w.push_wrapper(der::SEQUENCE, start)?;
        Ok(w.finish())
    }
}

/// The `seed` choice's tag: `[0] IMPLICIT OCTET STRING`, context-specific and
/// primitive.
const SEED_TAG: u8 = 0x80;

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_key() -> [u8; 64] {
        // A seed-form ML-DSA-65 key built by hand: SEQUENCE { 0, SEQUENCE {
        // id-ml-dsa-65 }, OCTET STRING { [0] 32 bytes } }.
        let mut der = [0u8; 64];
        let head = [
            0x30, 0x34, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
            0x03, 0x04, 0x03, 0x12, 0x04, 0x22, 0x80, 0x20,
        ];
        der[..head.len()].copy_from_slice(&head);
        for (i, b) in der[head.len()..head.len() + 32].iter_mut().enumerate() {
            *b = i as u8;
        }
        der
    }

    const SEED_KEY_LEN: usize = 54;

    #[test]
    fn a_seed_key_parses_and_writes_back_unchanged() {
        let der = seed_key();
        let key = MlDsaPrivateKey::from_der(&der[..SEED_KEY_LEN]).unwrap();
        assert_eq!(key.parameter_set(), MlDsaParameterSet::MlDsa65);
        assert_eq!(key.seed().unwrap()[31], 31);
        assert!(key.expanded_key().is_none());
        let mut out = [0u8; 64];
        let n = key.to_der(&mut out).unwrap();
        assert_eq!(&out[..n], &der[..SEED_KEY_LEN]);
    }

    /// The general parser goes on reporting ML-DSA as unsupported, with the
    /// OID, which is what tells a caller to use this one.
    #[test]
    fn the_general_parser_still_reports_ml_dsa_as_unsupported() {
        let der = seed_key();
        assert_eq!(
            crate::PrivateKeyInfo::from_der(&der[..SEED_KEY_LEN]).unwrap(),
            crate::PrivateKeyInfo::Unsupported {
                oid: oid::ML_DSA_65
            }
        );
    }

    #[test]
    fn malformed_keys_are_refused() {
        let good = seed_key();
        let refused = |der: &[u8], why: &str| {
            assert!(MlDsaPrivateKey::from_der(der).is_err(), "{why}");
        };
        refused(&good[..SEED_KEY_LEN - 1], "truncated");
        let mut trailing = good;
        trailing[1] += 1;
        refused(
            &trailing[..SEED_KEY_LEN + 1],
            "trailing byte inside the key",
        );
        refused(&good[..SEED_KEY_LEN + 1], "trailing byte after the key");

        // A 31-byte seed, with every length fixed up to match.
        let mut short = good;
        short[1] -= 1;
        short[19] -= 1;
        short[21] -= 1;
        assert_eq!(
            MlDsaPrivateKey::from_der(&short[..SEED_KEY_LEN - 1])
                .unwrap_err()
                .kind(),
            ic_core::ErrorKind::InvalidLength,
            "short seed"
        );

        // Version 1.
        let mut v1 = good;
        v1[4] = 1;
        refused(&v1[..SEED_KEY_LEN], "version 1");

        // An unknown choice tag where the seed's [0] belongs.
        let mut tag = good;
        tag[20] = 0x81;
        refused(&tag[..SEED_KEY_LEN], "unknown choice");

        // Ed25519's OID in place of ML-DSA's is another algorithm, not malformed.
        let mut ed = good;
        ed[8] = 0x03;
        ed[9..12].copy_from_slice(oid::ED25519);
        assert!(
            MlDsaPrivateKey::from_der(&ed[..SEED_KEY_LEN]).is_err(),
            "other algorithm"
        );
    }

    /// An expanded key must be exactly its parameter set's length, whichever
    /// form carries it, and a seed-and-expanded pair is written back as it was.
    #[test]
    fn expanded_lengths_are_checked_per_set_and_round_trip() {
        for set in [
            MlDsaParameterSet::MlDsa44,
            MlDsaParameterSet::MlDsa65,
            MlDsaParameterSet::MlDsa87,
        ] {
            let seed = [7u8; SEED_LEN];
            let expanded = [9u8; 4896];
            let n = set.expanded_key_len();
            let mut buf = [0u8; 5100];
            for key in [
                MlDsaPrivateKey::ExpandedKey {
                    set,
                    expanded_key: &expanded[..n],
                },
                MlDsaPrivateKey::Both {
                    set,
                    seed: &seed,
                    expanded_key: &expanded[..n],
                },
            ] {
                let len = key.to_der(&mut buf).unwrap();
                assert_eq!(MlDsaPrivateKey::from_der(&buf[..len]).unwrap(), key);
            }
            let wrong = MlDsaPrivateKey::ExpandedKey {
                set,
                expanded_key: &expanded[..n - 1],
            };
            assert_eq!(
                wrong.to_der(&mut buf).unwrap_err().kind(),
                ic_core::ErrorKind::InvalidLength
            );
        }
    }
}
