//! X.509 certificate issuance for one fixed profile.
//!
//! This builds certificates; it does not read them. Parsing stays out of scope
//! for the reason given in the crate documentation -- names, extensions and
//! path validation are a large surface where a partial implementation is
//! worse than none. Issuance is a much smaller one: the output is whatever this
//! module chooses to write, so the question is only whether that is correct,
//! and every field below is checked against OpenSSL.
//!
//! # The profile
//!
//! A version 3 certificate with a common name for subject and issuer, a
//! validity period, and these extensions, in this order:
//!
//! - basic constraints, critical: whether the subject is a CA, and optionally
//!   how many CAs may follow it;
//! - key usage, critical;
//! - extended key usage, if any purpose is given: TLS server and client;
//! - subject alternative names, if any: DNS names and IP addresses;
//! - subject key identifier and authority key identifier, if given.
//!
//! That is what a private CA and the leaf certificates it signs need, and it is
//! what `rcgen` is most often used for. Anything outside it -- other name
//! attributes, policies, CRL distribution points, name constraints -- is not
//! written, rather than written partly.
//!
//! # Signing
//!
//! This crate performs no cryptography, so signing is two calls with the
//! caller's signer between them. [`write_tbs_certificate`] produces the bytes
//! to sign; the caller signs them with the issuer's key; [`write_certificate`]
//! wraps the signature. For ECDSA the signature is taken as the fixed-width
//! `r || s` the curve crates produce and converted to the DER X.509 carries.
//!
//! Key identifiers are inputs, not computed here, because computing one means
//! hashing and this crate depends on nothing that hashes. RFC 5280 section
//! 4.2.1.2 suggests the SHA-1 of the public key bit string; any stable,
//! distinct value serves.

use crate::der::{self, Writer};
use crate::oid;
use ic_core::{ensure, Result};

/// `BOOLEAN`.
const BOOLEAN: u8 = 0x01;
/// `UTF8String`.
const UTF8_STRING: u8 = 0x0c;
/// `SET`, constructed.
const SET: u8 = 0x31;
/// `UTCTime`.
const UTC_TIME: u8 = 0x17;
/// `GeneralizedTime`.
const GENERALIZED_TIME: u8 = 0x18;
/// `[2] IMPLICIT IA5String`: a `dNSName` in `GeneralName`.
const DNS_NAME: u8 = 0x82;
/// `[7] IMPLICIT OCTET STRING`: an `iPAddress` in `GeneralName`.
const IP_ADDRESS: u8 = 0x87;
/// `[0] IMPLICIT OCTET STRING`: `keyIdentifier` in `AuthorityKeyIdentifier`.
const KEY_IDENTIFIER: u8 = 0x80;

/// The algorithm that signs a certificate.
///
/// Also the algorithm of the issuer's key: the two are one choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignatureAlgorithm {
    /// ECDSA over P-256 with SHA-256.
    EcdsaP256Sha256,
    /// ECDSA over P-384 with SHA-384.
    EcdsaP384Sha384,
    /// Ed25519.
    Ed25519,
    /// ML-DSA-44 (FIPS 204), per RFC 9881.
    MlDsa44,
    /// ML-DSA-65 (FIPS 204), per RFC 9881.
    MlDsa65,
    /// ML-DSA-87 (FIPS 204), per RFC 9881.
    MlDsa87,
}

impl SignatureAlgorithm {
    /// The algorithm's object identifier. Every one here takes no parameters.
    fn oid(self) -> &'static [u8] {
        match self {
            Self::EcdsaP256Sha256 => oid::ECDSA_WITH_SHA256,
            Self::EcdsaP384Sha384 => oid::ECDSA_WITH_SHA384,
            Self::Ed25519 => oid::ED25519,
            Self::MlDsa44 => oid::ML_DSA_44,
            Self::MlDsa65 => oid::ML_DSA_65,
            Self::MlDsa87 => oid::ML_DSA_87,
        }
    }

    /// The signature length the signer produces, before any encoding.
    fn raw_signature_len(self) -> usize {
        match self {
            Self::EcdsaP256Sha256 => 64,
            Self::EcdsaP384Sha384 => 96,
            Self::Ed25519 => 64,
            Self::MlDsa44 => 2420,
            Self::MlDsa65 => 3309,
            Self::MlDsa87 => 4627,
        }
    }

    fn push_identifier(self, w: &mut Writer) -> Result<()> {
        let start = w.len();
        w.push_oid(self.oid())?;
        w.push_wrapper(der::SEQUENCE, start)
    }
}

/// Write an ML-DSA public key as a `SubjectPublicKeyInfo`, per RFC 9881.
///
/// [`crate::PublicKeyInfo`] covers the classical algorithms; this is the
/// ML-DSA counterpart a certificate needs for its subject key. `algorithm`
/// must be one of the ML-DSA variants, and `key` the encoded public key of
/// that set.
pub fn write_ml_dsa_public_key(
    algorithm: SignatureAlgorithm,
    key: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    let want = match algorithm {
        SignatureAlgorithm::MlDsa44 => 1312,
        SignatureAlgorithm::MlDsa65 => 1952,
        SignatureAlgorithm::MlDsa87 => 2592,
        _ => return Err(ic_core::err!(InvalidParameter, "not an ML-DSA algorithm")),
    };
    ensure!(key.len() == want, InvalidLength, "ml-dsa public key length");
    let mut w = Writer::new(out);
    w.push_bit_string(key)?;
    algorithm.push_identifier(&mut w)?;
    w.push_wrapper(der::SEQUENCE, 0)?;
    Ok(w.finish())
}

/// What the certified key may be used for: the `KeyUsage` bits this profile
/// writes. Combine with `|`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyUsage(u8);

impl KeyUsage {
    /// Signing other than certificates and CRLs: TLS handshakes, for one.
    pub const DIGITAL_SIGNATURE: KeyUsage = KeyUsage(0x80);
    /// Key transport, as RSA key exchange uses it.
    pub const KEY_ENCIPHERMENT: KeyUsage = KeyUsage(0x20);
    /// Key agreement, as ECDH uses it.
    pub const KEY_AGREEMENT: KeyUsage = KeyUsage(0x08);
    /// Signing certificates: what makes a CA key a CA key.
    pub const KEY_CERT_SIGN: KeyUsage = KeyUsage(0x04);
    /// Signing certificate revocation lists.
    pub const CRL_SIGN: KeyUsage = KeyUsage(0x02);

    /// The DER `BIT STRING` content: the unused-bit count, then the bits.
    ///
    /// DER requires a named bit string to drop trailing zero bits, and to say
    /// how many of the last byte's bits are padding. Getting that count wrong
    /// is a common way to produce a certificate strict parsers refuse.
    fn encoded(self) -> [u8; 2] {
        [self.0.trailing_zeros() as u8, self.0]
    }
}

impl core::ops::BitOr for KeyUsage {
    type Output = KeyUsage;
    fn bitor(self, rhs: KeyUsage) -> KeyUsage {
        KeyUsage(self.0 | rhs.0)
    }
}

/// A purpose for the extended key usage extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExtendedKeyUsage {
    /// TLS server authentication.
    ServerAuth,
    /// TLS client authentication.
    ClientAuth,
}

/// A subject alternative name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SubjectAltName<'a> {
    /// A DNS name, `example.com` or `*.example.com`. ASCII only: an
    /// internationalised name must already be in its `xn--` form.
    Dns(&'a str),
    /// An IPv4 address, four bytes.
    Ipv4([u8; 4]),
    /// An IPv6 address, sixteen bytes.
    Ipv6([u8; 16]),
}

/// Whether the subject is a certificate authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BasicConstraints {
    /// An end entity: it may not sign certificates.
    EndEntity,
    /// A CA, with an optional limit on how many CAs may follow it in a path.
    Ca {
        /// `pathLenConstraint`: `Some(0)` means it may sign only end entities.
        path_len: Option<u8>,
    },
}

/// Everything in a certificate except its signature.
#[derive(Debug, Clone, Copy)]
pub struct CertificateParams<'a> {
    /// The serial number, big-endian. It must be positive and at most 20
    /// octets once encoded, per RFC 5280 section 4.1.2.2, and it should be
    /// unpredictable: sixteen random bytes with the top bit cleared is the
    /// usual choice. The issuer must not reuse one.
    pub serial: &'a [u8],
    /// The issuer's common name. For a self-signed certificate, the subject's.
    pub issuer_common_name: &'a str,
    /// The subject's common name.
    pub subject_common_name: &'a str,
    /// Start of validity, in seconds since the Unix epoch.
    pub not_before: u64,
    /// End of validity, in seconds since the Unix epoch, inclusive.
    pub not_after: u64,
    /// The subject's public key as a DER `SubjectPublicKeyInfo`: from
    /// [`crate::PublicKeyInfo::to_der`], or [`write_ml_dsa_public_key`].
    pub subject_public_key_info: &'a [u8],
    /// Whether the subject is a CA.
    pub basic_constraints: BasicConstraints,
    /// What the subject's key may be used for.
    pub key_usage: KeyUsage,
    /// Extended purposes. Empty omits the extension.
    pub extended_key_usage: &'a [ExtendedKeyUsage],
    /// Alternative names. Empty omits the extension. A TLS server
    /// certificate needs its host names here: clients match against these,
    /// not the common name.
    pub subject_alt_names: &'a [SubjectAltName<'a>],
    /// The subject key identifier, if the extension is wanted.
    pub subject_key_id: Option<&'a [u8]>,
    /// The issuer's key identifier, if the extension is wanted. For a
    /// self-signed certificate, the subject's.
    pub authority_key_id: Option<&'a [u8]>,
}

/// Write the `TBSCertificate`: the bytes the issuer signs.
///
/// `algorithm` is the signature algorithm, which the `TBSCertificate` itself
/// records, so it must be the one the issuer then signs with.
pub fn write_tbs_certificate(
    params: &CertificateParams,
    algorithm: SignatureAlgorithm,
    out: &mut [u8],
) -> Result<usize> {
    validate(params)?;
    let mut w = Writer::new(out);

    // The writer prepends, so the fields go in last first.
    let ext_start = w.len();
    push_extensions(&mut w, params)?;
    w.push_wrapper(der::SEQUENCE, ext_start)?;
    w.push_wrapper(der::context(3), ext_start)?;

    w.push(params.subject_public_key_info)?;
    push_name(&mut w, params.subject_common_name)?;

    let validity_start = w.len();
    push_time(&mut w, params.not_after)?;
    push_time(&mut w, params.not_before)?;
    w.push_wrapper(der::SEQUENCE, validity_start)?;

    push_name(&mut w, params.issuer_common_name)?;
    algorithm.push_identifier(&mut w)?;
    w.push_unsigned_integer(params.serial)?;

    // [0] EXPLICIT Version: v3 is the INTEGER 2.
    let version_start = w.len();
    w.push_unsigned_u64(2)?;
    w.push_wrapper(der::context(0), version_start)?;

    w.push_wrapper(der::SEQUENCE, 0)?;
    Ok(w.finish())
}

/// Wrap a `TBSCertificate` and the issuer's signature over it into a
/// `Certificate`.
///
/// `signature` is what the signer produced: `r || s` for ECDSA, which is
/// converted to DER here, and the raw signature for the others.
pub fn write_certificate(
    tbs_certificate: &[u8],
    algorithm: SignatureAlgorithm,
    signature: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    ensure!(
        signature.len() == algorithm.raw_signature_len(),
        InvalidLength,
        "signature length does not match the algorithm"
    );
    let mut w = Writer::new(out);
    match algorithm {
        SignatureAlgorithm::EcdsaP256Sha256 | SignatureAlgorithm::EcdsaP384Sha384 => {
            let mut der_sig = [0u8; crate::ecdsa_signature::max_der_len(96)];
            let n = crate::ecdsa_signature::to_der(signature, &mut der_sig)?;
            w.push_bit_string(&der_sig[..n])?;
        }
        _ => w.push_bit_string(signature)?,
    }
    algorithm.push_identifier(&mut w)?;
    w.push(tbs_certificate)?;
    w.push_wrapper(der::SEQUENCE, 0)?;
    Ok(w.finish())
}

fn validate(params: &CertificateParams) -> Result<()> {
    let trimmed = match params.serial.iter().position(|b| *b != 0) {
        Some(first) => &params.serial[first..],
        None => &[][..],
    };
    ensure!(
        !trimmed.is_empty(),
        InvalidParameter,
        "serial number must be positive"
    );
    // A set top bit costs a sign byte, which counts toward the 20.
    let encoded = trimmed.len() + usize::from(trimmed[0] & 0x80 != 0);
    ensure!(
        encoded <= 20,
        InvalidParameter,
        "serial number exceeds 20 octets"
    );
    for name in [params.issuer_common_name, params.subject_common_name] {
        // ub-common-name is 64 characters.
        ensure!(
            !name.is_empty() && name.chars().count() <= 64,
            InvalidParameter,
            "common name must be 1 to 64 characters"
        );
    }
    ensure!(
        params.not_before <= params.not_after,
        InvalidParameter,
        "validity ends before it starts"
    );
    ensure!(
        params.key_usage.0 != 0,
        InvalidParameter,
        "key usage is empty"
    );
    for san in params.subject_alt_names {
        if let SubjectAltName::Dns(name) = san {
            ensure!(
                !name.is_empty() && name.bytes().all(|b| b.is_ascii_graphic()),
                InvalidParameter,
                "dns name must be non-empty printable ascii"
            );
        }
    }
    for id in [params.subject_key_id, params.authority_key_id]
        .into_iter()
        .flatten()
    {
        ensure!(!id.is_empty(), InvalidParameter, "key identifier is empty");
    }
    // The key is embedded as given, so it must at least be one DER element.
    let mut r = der::Reader::new(params.subject_public_key_info);
    r.sequence()?;
    r.finish()
}

/// `Name ::= SEQUENCE OF SET OF AttributeTypeAndValue`, with one
/// attribute: the common name, as a `UTF8String`.
fn push_name(w: &mut Writer, common_name: &str) -> Result<()> {
    let start = w.len();
    w.push_element(UTF8_STRING, common_name.as_bytes())?;
    w.push_oid(oid::COMMON_NAME)?;
    w.push_wrapper(der::SEQUENCE, start)?;
    w.push_wrapper(SET, start)?;
    w.push_wrapper(der::SEQUENCE, start)
}

/// A `Time`: `UTCTime` through 2049 and `GeneralizedTime` from 2050, as RFC
/// 5280 section 4.1.2.5 requires. Both in UTC and to the second.
fn push_time(w: &mut Writer, unix: u64) -> Result<()> {
    let (year, month, day, hour, minute, second) = civil(unix);
    ensure!(year <= 9999, InvalidParameter, "time is beyond year 9999");
    let mut text = [0u8; 15];
    let digits = |v: u32, out: &mut [u8]| {
        let n = out.len();
        let mut v = v;
        for i in (0..n).rev() {
            out[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    };
    if year < 2050 {
        digits(year % 100, &mut text[0..2]);
        digits(month, &mut text[2..4]);
        digits(day, &mut text[4..6]);
        digits(hour, &mut text[6..8]);
        digits(minute, &mut text[8..10]);
        digits(second, &mut text[10..12]);
        text[12] = b'Z';
        w.push_element(UTC_TIME, &text[..13])
    } else {
        digits(year, &mut text[0..4]);
        digits(month, &mut text[4..6]);
        digits(day, &mut text[6..8]);
        digits(hour, &mut text[8..10]);
        digits(minute, &mut text[10..12]);
        digits(second, &mut text[12..14]);
        text[14] = b'Z';
        w.push_element(GENERALIZED_TIME, &text[..15])
    }
}

/// Unix seconds to a UTC calendar date and time.
///
/// Howard Hinnant's `civil_from_days`, which counts in 400-year eras so leap
/// years need no special cases. Tested against a day-by-day count.
fn civil(unix: u64) -> (u32, u32, u32, u32, u32, u32) {
    let days = unix / 86_400;
    let secs = unix % 86_400;
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (
        year as u32,
        month as u32,
        day as u32,
        (secs / 3_600) as u32,
        (secs / 60 % 60) as u32,
        (secs % 60) as u32,
    )
}

/// `Extension ::= SEQUENCE { extnID, critical BOOLEAN DEFAULT FALSE,
/// extnValue OCTET STRING }`, with `value` already written and starting at
/// `value_start`. DER omits `critical` when it is the default.
fn wrap_extension(w: &mut Writer, value_start: usize, id: &[u8], critical: bool) -> Result<()> {
    w.push_wrapper(der::OCTET_STRING, value_start)?;
    if critical {
        w.push_element(BOOLEAN, &[0xff])?;
    }
    w.push_oid(id)?;
    w.push_wrapper(der::SEQUENCE, value_start)
}

fn push_extensions(w: &mut Writer, p: &CertificateParams) -> Result<()> {
    // Last first, so the certificate carries them in the order the module
    // documentation lists.
    if let Some(id) = p.authority_key_id {
        let start = w.len();
        w.push_element(KEY_IDENTIFIER, id)?;
        w.push_wrapper(der::SEQUENCE, start)?;
        wrap_extension(w, start, oid::AUTHORITY_KEY_IDENTIFIER, false)?;
    }
    if let Some(id) = p.subject_key_id {
        let start = w.len();
        w.push_octet_string(id)?;
        wrap_extension(w, start, oid::SUBJECT_KEY_IDENTIFIER, false)?;
    }
    if !p.subject_alt_names.is_empty() {
        let start = w.len();
        for san in p.subject_alt_names.iter().rev() {
            match san {
                SubjectAltName::Dns(name) => w.push_element(DNS_NAME, name.as_bytes())?,
                SubjectAltName::Ipv4(ip) => w.push_element(IP_ADDRESS, ip)?,
                SubjectAltName::Ipv6(ip) => w.push_element(IP_ADDRESS, ip)?,
            }
        }
        w.push_wrapper(der::SEQUENCE, start)?;
        wrap_extension(w, start, oid::SUBJECT_ALT_NAME, false)?;
    }
    if !p.extended_key_usage.is_empty() {
        let start = w.len();
        for purpose in p.extended_key_usage.iter().rev() {
            w.push_oid(match purpose {
                ExtendedKeyUsage::ServerAuth => oid::SERVER_AUTH,
                ExtendedKeyUsage::ClientAuth => oid::CLIENT_AUTH,
            })?;
        }
        w.push_wrapper(der::SEQUENCE, start)?;
        wrap_extension(w, start, oid::EXTENDED_KEY_USAGE, false)?;
    }
    {
        let start = w.len();
        let bits = p.key_usage.encoded();
        w.push(&bits)?;
        w.push_header(der::BIT_STRING, bits.len())?;
        wrap_extension(w, start, oid::KEY_USAGE, true)?;
    }
    {
        let start = w.len();
        if let BasicConstraints::Ca { path_len } = p.basic_constraints {
            if let Some(n) = path_len {
                w.push_unsigned_u64(u64::from(n))?;
            }
            w.push_element(BOOLEAN, &[0xff])?;
        }
        w.push_wrapper(der::SEQUENCE, start)?;
        wrap_extension(w, start, oid::BASIC_CONSTRAINTS, true)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The calendar conversion against a day-by-day count, which shares
    /// nothing with the era arithmetic it checks. Every day from 1970 into
    /// 2100, so every leap-year rule is crossed, including 2000's.
    #[test]
    fn civil_agrees_with_counting_days() {
        let mut year = 1970u32;
        let mut month = 1u32;
        let mut day = 1u32;
        let is_leap = |y: u32| (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let month_len = |y: u32, m: u32| match m {
            2 if is_leap(y) => 29,
            2 => 28,
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
        let mut checked = 0;
        for n in 0..(131 * 366) as u64 {
            let got = civil(n * 86_400 + 3_723);
            assert_eq!(got, (year, month, day, 1, 2, 3), "day {n}");
            checked += 1;
            day += 1;
            if day > month_len(year, month) {
                day = 1;
                month += 1;
                if month > 12 {
                    month = 1;
                    year += 1;
                }
            }
        }
        assert!(checked > 47_000);
    }

    /// `UTCTime` up to the end of 2049, `GeneralizedTime` from 2050.
    #[test]
    fn times_switch_encoding_at_2050() {
        let enc = |t: u64| {
            let mut buf = [0u8; 32];
            let mut w = Writer::new(&mut buf);
            push_time(&mut w, t).unwrap();
            let n = w.finish();
            buf[..n].to_vec()
        };
        // 2049-12-31T23:59:59Z and 2050-01-01T00:00:00Z.
        assert_eq!(
            enc(2_524_607_999),
            [&[UTC_TIME, 13][..], b"491231235959Z"].concat()
        );
        assert_eq!(
            enc(2_524_608_000),
            [&[GENERALIZED_TIME, 15][..], b"20500101000000Z"].concat()
        );
        assert_eq!(enc(0), [&[UTC_TIME, 13][..], b"700101000000Z"].concat());
    }

    /// Named bit strings drop trailing zero bits and count them.
    #[test]
    fn key_usage_bits_are_minimal() {
        assert_eq!(KeyUsage::DIGITAL_SIGNATURE.encoded(), [7, 0x80]);
        assert_eq!(
            (KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN).encoded(),
            [1, 0x06]
        );
        assert_eq!(
            (KeyUsage::DIGITAL_SIGNATURE | KeyUsage::KEY_CERT_SIGN | KeyUsage::CRL_SIGN).encoded(),
            [1, 0x86]
        );
        assert_eq!(KeyUsage::KEY_AGREEMENT.encoded(), [3, 0x08]);
    }

    fn params<'a>(spki: &'a [u8]) -> CertificateParams<'a> {
        CertificateParams {
            serial: &[0x01, 0x02],
            issuer_common_name: "Issuer",
            subject_common_name: "Subject",
            not_before: 1_700_000_000,
            not_after: 1_800_000_000,
            subject_public_key_info: spki,
            basic_constraints: BasicConstraints::EndEntity,
            key_usage: KeyUsage::DIGITAL_SIGNATURE,
            extended_key_usage: &[],
            subject_alt_names: &[],
            subject_key_id: None,
            authority_key_id: None,
        }
    }

    /// The inputs RFC 5280 constrains are refused rather than encoded.
    #[test]
    fn out_of_profile_inputs_are_refused() {
        let spki = [0x30, 0x00];
        let mut out = [0u8; 512];
        let alg = SignatureAlgorithm::Ed25519;
        assert!(write_tbs_certificate(&params(&spki), alg, &mut out).is_ok());

        let refused =
            |p: CertificateParams| write_tbs_certificate(&p, alg, &mut [0u8; 512]).is_err();
        assert!(
            refused(CertificateParams {
                serial: &[0, 0],
                ..params(&spki)
            }),
            "zero serial"
        );
        assert!(
            refused(CertificateParams {
                serial: &[0x80; 20],
                ..params(&spki)
            }),
            "21 octets"
        );
        assert!(
            !refused(CertificateParams {
                serial: &[0x7f; 20],
                ..params(&spki)
            }),
            "20 octets"
        );
        assert!(refused(CertificateParams {
            subject_common_name: "",
            ..params(&spki)
        }));
        assert!(refused(CertificateParams {
            not_before: 2,
            not_after: 1,
            ..params(&spki)
        }));
        assert!(refused(CertificateParams {
            key_usage: KeyUsage(0),
            ..params(&spki)
        }));
        assert!(refused(CertificateParams {
            subject_alt_names: &[SubjectAltName::Dns("has space")],
            ..params(&spki)
        }));
        assert!(refused(CertificateParams {
            subject_public_key_info: &[0x30],
            ..params(&spki)
        }));
    }
}
