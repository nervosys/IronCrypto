//! PKCS#10 certification requests (RFC 2986), written, not read.
//!
//! A request is how a key's holder asks a CA for a certificate without the
//! private key leaving it: the request carries the public key and the names
//! wanted, and is signed by the private key to show it is held. This writes
//! one, for the same profile [`crate::cert`] issues: a common name for the
//! subject, and optionally the subject alternative names to put in the
//! certificate, as an `extensionRequest` attribute.
//!
//! Reading a request is the CA's side, and is parsing untrusted DER; it is not
//! here, for the reason the crate gives for certificates. A CA that reads one
//! must verify its signature against the public key it carries, and must not
//! copy the names it asks for without checking them against its own policy:
//! the signature proves possession of the key and nothing about the names.
//!
//! # Signing
//!
//! As for certificates, two calls with the caller's signer between them:
//! [`write_certification_request_info`] produces the bytes to sign, with the
//! key the request is for; [`write_certification_request`] wraps the
//! signature. The signature algorithm is not part of the signed bytes here, so
//! it is named only to the second call.

use crate::cert::{self, SignatureAlgorithm, SubjectAltName};
use crate::der::{self, Writer};
use crate::oid;
use ic_core::Result;

/// `SET`.
const SET: u8 = 0x31;

/// Everything in a request except its signature.
#[derive(Debug, Clone, Copy)]
pub struct RequestParams<'a> {
    /// The subject's common name, 1 to 64 characters.
    pub subject_common_name: &'a str,
    /// The public key to certify, as a DER `SubjectPublicKeyInfo`. Its
    /// private half must sign the request.
    pub subject_public_key_info: &'a [u8],
    /// The alternative names asked for. Empty omits the `extensionRequest`
    /// attribute, leaving the attribute set empty, as RFC 2986 allows.
    pub subject_alt_names: &'a [SubjectAltName<'a>],
}

/// Write the `CertificationRequestInfo`: the bytes the key signs.
pub fn write_certification_request_info(params: &RequestParams, out: &mut [u8]) -> Result<usize> {
    ic_core::ensure!(
        !params.subject_common_name.is_empty() && params.subject_common_name.chars().count() <= 64,
        InvalidParameter,
        "common name must be 1 to 64 characters"
    );
    cert::validate_alt_names(params.subject_alt_names)?;
    let mut spki = der::Reader::new(params.subject_public_key_info);
    spki.sequence()?;
    spki.finish()?;

    let mut w = Writer::new(out);
    // The writer prepends, so the fields go in last first.
    //
    // attributes [0] IMPLICIT SET OF Attribute, where the one attribute is
    // extensionRequest: SEQUENCE { type, SET { Extensions } }.
    let attributes_start = w.len();
    if !params.subject_alt_names.is_empty() {
        let start = w.len();
        cert::push_alt_names_extension(&mut w, params.subject_alt_names)?;
        w.push_wrapper(der::SEQUENCE, start)?;
        w.push_wrapper(SET, start)?;
        w.push_oid(oid::EXTENSION_REQUEST)?;
        w.push_wrapper(der::SEQUENCE, start)?;
    }
    w.push_wrapper(der::context(0), attributes_start)?;

    w.push(params.subject_public_key_info)?;
    cert::push_name(&mut w, params.subject_common_name)?;
    // version INTEGER { v1(0) }
    w.push_unsigned_u64(0)?;
    w.push_wrapper(der::SEQUENCE, 0)?;
    Ok(w.finish())
}

/// Wrap a `CertificationRequestInfo` and the signature over it into a
/// `CertificationRequest`.
///
/// `signature` is what the signer produced: `r || s` for ECDSA, which is
/// converted to DER here, and the raw signature for the others.
pub fn write_certification_request(
    request_info: &[u8],
    algorithm: SignatureAlgorithm,
    signature: &[u8],
    out: &mut [u8],
) -> Result<usize> {
    cert::write_signed(request_info, algorithm, signature, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The structure RFC 2986 section 4 gives, read back element by element.
    #[test]
    fn the_request_info_has_rfc_2986_s_shape() {
        let spki = [0x30, 0x00];
        let names = [SubjectAltName::Uri("nanda:x:y")];
        let mut out = [0u8; 256];
        let n = write_certification_request_info(
            &RequestParams {
                subject_common_name: "a",
                subject_public_key_info: &spki,
                subject_alt_names: &names,
            },
            &mut out,
        )
        .unwrap();
        let mut r = der::Reader::new(&out[..n]);
        let mut info = r.sequence().unwrap();
        r.finish().unwrap();
        assert_eq!(info.expect(der::INTEGER).unwrap(), [0]);
        info.sequence().unwrap(); // subject
        assert_eq!(info.expect(der::SEQUENCE).unwrap(), []); // the key, as given
        let mut attributes = der::Reader::new(info.expect(der::context(0)).unwrap());
        info.finish().unwrap();
        let mut attribute = attributes.sequence().unwrap();
        attributes.finish().unwrap();
        assert_eq!(attribute.expect(der::OID).unwrap(), oid::EXTENSION_REQUEST);
        let mut values = der::Reader::new(attribute.expect(SET).unwrap());
        attribute.finish().unwrap();
        let mut extensions = values.sequence().unwrap();
        values.finish().unwrap();
        let mut extension = extensions.sequence().unwrap();
        extensions.finish().unwrap();
        assert_eq!(extension.expect(der::OID).unwrap(), oid::SUBJECT_ALT_NAME);
    }

    /// No names, no attribute; the empty set is still written, since
    /// `attributes` is not optional.
    #[test]
    fn a_request_without_names_has_an_empty_attribute_set() {
        let spki = [0x30, 0x00];
        let mut out = [0u8; 64];
        let n = write_certification_request_info(
            &RequestParams {
                subject_common_name: "a",
                subject_public_key_info: &spki,
                subject_alt_names: &[],
            },
            &mut out,
        )
        .unwrap();
        assert_eq!(&out[n - 2..n], &[der::context(0), 0x00]);
    }

    #[test]
    fn out_of_profile_requests_are_refused() {
        let spki = [0x30, 0x00];
        let refused =
            |p: RequestParams| write_certification_request_info(&p, &mut [0u8; 256]).is_err();
        let base = RequestParams {
            subject_common_name: "a",
            subject_public_key_info: &spki,
            subject_alt_names: &[],
        };
        assert!(!refused(base));
        assert!(refused(RequestParams {
            subject_common_name: "",
            ..base
        }));
        assert!(refused(RequestParams {
            subject_public_key_info: &[0x30],
            ..base
        }));
        assert!(refused(RequestParams {
            subject_alt_names: &[SubjectAltName::Uri("relative/path")],
            ..base
        }));
        assert!(refused(RequestParams {
            subject_alt_names: &[SubjectAltName::Dns("has space")],
            ..base
        }));
    }
}
