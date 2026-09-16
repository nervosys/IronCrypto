//! RFC 7468 textual encoding — the `-----BEGIN ...-----` wrapper.
//!
//! # What this accepts
//!
//! RFC 7468 distinguishes *strict* generators from *lax* parsers. This follows
//! that split: [`encode`] emits the strict form — 64 base64 characters per
//! line, `\n` endings, no leading or trailing whitespace inside the body — and
//! [`decode`] tolerates the variations that occur in practice:
//!
//! - `\r\n` as well as `\n`;
//! - trailing whitespace after any line;
//! - anything at all before the `-----BEGIN` line, which is where OpenSSL puts
//!   its human-readable summaries.
//!
//! It does **not** tolerate a label mismatch between the BEGIN and END lines,
//! base64 outside the alphabet, or a label other than the one the caller asked
//! for. A caller that wanted a public key and was handed a private key should
//! find out here rather than three layers down.
//!
//! # No allocation
//!
//! Both directions work line by line. Encoding takes 48 input bytes to a
//! 64-character line; decoding takes each line's base64 independently, which
//! works because every line's length is a multiple of four.

use ac_core::{codec, ensure, Result};

/// Label for a `SubjectPublicKeyInfo`.
pub const PUBLIC_KEY: &str = "PUBLIC KEY";
/// Label for a PKCS#8 `PrivateKeyInfo`.
pub const PRIVATE_KEY: &str = "PRIVATE KEY";
/// Label for a bare PKCS#1 `RSAPublicKey`.
pub const RSA_PUBLIC_KEY: &str = "RSA PUBLIC KEY";
/// Label for a bare PKCS#1 `RSAPrivateKey`.
pub const RSA_PRIVATE_KEY: &str = "RSA PRIVATE KEY";
/// Label for a bare SEC1 `ECPrivateKey`.
pub const EC_PRIVATE_KEY: &str = "EC PRIVATE KEY";
/// Label for an X.509 certificate.
pub const CERTIFICATE: &str = "CERTIFICATE";

/// Input bytes per output line: 48 bytes encode to exactly 64 characters.
const BYTES_PER_LINE: usize = 48;
/// Base64 characters per line, per RFC 7468 §2. Referenced by the tests,
/// which is where the line width is actually asserted.
#[cfg(test)]
const CHARS_PER_LINE: usize = 64;

/// The exact length [`encode`] will write for `der_len` bytes under `label`.
///
/// Use it to size a buffer rather than guessing.
pub const fn encoded_len(label: &str, der_len: usize) -> usize {
    let lines = der_len.div_ceil(BYTES_PER_LINE);
    let body = codec::base64_encoded_len(der_len) + lines; // each line plus its \n
                                                           // "-----BEGIN " + label + "-----\n", then the body, then the END line.
    (11 + label.len() + 6) + body + (9 + label.len() + 6)
}

/// Encode `der` under `label` in the strict RFC 7468 form.
///
/// Returns the number of bytes written.
pub fn encode(label: &str, der: &[u8], out: &mut [u8]) -> Result<usize> {
    let needed = encoded_len(label, der.len());
    ensure!(out.len() >= needed, InvalidLength, "pem output buffer");
    ensure!(is_valid_label(label), InvalidParameter, "pem label");

    let mut at = 0;
    let put = |bytes: &[u8], out: &mut [u8], at: &mut usize| {
        out[*at..*at + bytes.len()].copy_from_slice(bytes);
        *at += bytes.len();
    };

    put(b"-----BEGIN ", out, &mut at);
    put(label.as_bytes(), out, &mut at);
    put(b"-----\n", out, &mut at);

    for chunk in der.chunks(BYTES_PER_LINE) {
        let encoded = codec::base64_encoded_len(chunk.len());
        codec::base64_encode(chunk, &mut out[at..at + encoded])?;
        at += encoded;
        put(b"\n", out, &mut at);
    }

    put(b"-----END ", out, &mut at);
    put(label.as_bytes(), out, &mut at);
    put(b"-----\n", out, &mut at);

    debug_assert_eq!(at, needed, "encoded_len must be exact");
    Ok(at)
}

/// Decode a PEM document, requiring `label`.
///
/// Returns the number of DER bytes written to `out`.
pub fn decode(label: &str, text: &[u8], out: &mut [u8]) -> Result<usize> {
    ensure!(is_valid_label(label), InvalidParameter, "pem label");

    // The body runs from just after the BEGIN line to just before the END one.
    let (_, body_start) = find_line(text, b"-----BEGIN ", label)?;
    let (end_start, _) = find_line(&text[body_start..], b"-----END ", label)
        .map_err(|_| ac_core::err!(MalformedEncoding, "pem is missing its END line"))?;
    let body_end = body_start + end_start;

    let mut written = 0;
    for line in text[body_start..body_end].split(|b| *b == b'\n') {
        let line = trim(line);
        if line.is_empty() {
            continue;
        }
        ensure!(
            line.len() % 4 == 0,
            MalformedEncoding,
            "pem line is not a whole number of base64 quanta"
        );
        let n = codec::base64_decode(line, &mut out[written..])?;
        written += n;
    }
    Ok(written)
}

/// A label is printable ASCII without hyphens, per RFC 7468 §3.
fn is_valid_label(label: &str) -> bool {
    !label.is_empty()
        && label
            .bytes()
            .all(|b| (0x20..=0x7e).contains(&b) && b != b'-')
}

/// Find `prefix || label || "-----"` on a line of its own.
///
/// Returns `(start of that line, start of the next line)`. Both are needed: the
/// BEGIN line's end is where the body starts, and the END line's start is where
/// it stops. Computing one from the other invites an off-by-one that shows up
/// as a stray `-` at the end of the base64.
fn find_line(text: &[u8], prefix: &[u8], label: &str) -> Result<(usize, usize)> {
    let mut at = 0;
    loop {
        let rest = &text[at..];
        let newline = rest.iter().position(|b| *b == b'\n');
        let line_len = newline.unwrap_or(rest.len());
        let trimmed = trim(&rest[..line_len]);
        if trimmed.len() == prefix.len() + label.len() + 5
            && trimmed.starts_with(prefix)
            && &trimmed[prefix.len()..prefix.len() + label.len()] == label.as_bytes()
            && trimmed.ends_with(b"-----")
        {
            return Ok((at, at + line_len + usize::from(newline.is_some())));
        }
        match newline {
            Some(_) => at += line_len + 1,
            None => break,
        }
    }
    Err(ac_core::err!(
        MalformedEncoding,
        "pem boundary line not found"
    ))
}

/// Strip ASCII whitespace from both ends.
fn trim(mut line: &[u8]) -> &[u8] {
    while let Some((first, rest)) = line.split_first() {
        if first.is_ascii_whitespace() {
            line = rest;
        } else {
            break;
        }
    }
    while let Some((last, rest)) = line.split_last() {
        if last.is_ascii_whitespace() {
            line = rest;
        } else {
            break;
        }
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(bytes: &[u8]) -> &str {
        core::str::from_utf8(bytes).unwrap()
    }

    #[test]
    fn a_short_document_matches_a_hand_written_one() {
        let der = b"hello world";
        let mut out = std::vec![0u8; encoded_len(PUBLIC_KEY, der.len())];
        let n = encode(PUBLIC_KEY, der, &mut out).unwrap();
        assert_eq!(
            text(&out[..n]),
            "-----BEGIN PUBLIC KEY-----\naGVsbG8gd29ybGQ=\n-----END PUBLIC KEY-----\n"
        );
        assert_eq!(n, out.len(), "encoded_len is exact, not an upper bound");
    }

    /// RFC 7468 §2 fixes the line length at 64 characters. Getting this wrong
    /// produces documents that some parsers accept and others do not.
    #[test]
    fn lines_are_wrapped_at_sixty_four_characters() {
        for len in [1usize, 47, 48, 49, 96, 97, 256, 294] {
            let der = std::vec![0x5au8; len];
            let mut out = std::vec![0u8; encoded_len(PUBLIC_KEY, len)];
            let n = encode(PUBLIC_KEY, &der, &mut out).unwrap();
            assert_eq!(n, out.len(), "exact length for {len} bytes");

            let s = text(&out[..n]);
            let body: std::vec::Vec<&str> = s.lines().filter(|l| !l.starts_with("-----")).collect();
            assert_eq!(body.len(), len.div_ceil(48), "line count for {len} bytes");
            for line in &body[..body.len() - 1] {
                assert_eq!(line.len(), CHARS_PER_LINE, "full line for {len} bytes");
            }
            assert!(body[body.len() - 1].len() <= CHARS_PER_LINE);

            let mut back = std::vec![0u8; len];
            assert_eq!(decode(PUBLIC_KEY, &out[..n], &mut back).unwrap(), len);
            assert_eq!(back, der, "round trip of {len} bytes");
        }
    }

    #[test]
    fn crlf_and_trailing_whitespace_are_tolerated() {
        let der = std::vec![0x11u8; 100];
        let mut out = std::vec![0u8; encoded_len(PRIVATE_KEY, der.len())];
        let n = encode(PRIVATE_KEY, &der, &mut out).unwrap();

        let crlf = text(&out[..n]).replace('\n', "  \r\n");
        let mut back = std::vec![0u8; der.len()];
        assert_eq!(
            decode(PRIVATE_KEY, crlf.as_bytes(), &mut back).unwrap(),
            der.len()
        );
        assert_eq!(back, der);
    }

    /// OpenSSL prefixes its output with a human-readable summary. RFC 7468 §5.2
    /// says a parser may ignore text before the BEGIN line.
    #[test]
    fn leading_explanatory_text_is_ignored() {
        let der = std::vec![0x22u8; 60];
        let mut out = std::vec![0u8; encoded_len(CERTIFICATE, der.len())];
        let n = encode(CERTIFICATE, &der, &mut out).unwrap();

        let mut doc = std::string::String::from("Certificate:\n  Issuer: CN=example\n");
        doc.push_str(text(&out[..n]));
        let mut back = std::vec![0u8; der.len()];
        assert_eq!(
            decode(CERTIFICATE, doc.as_bytes(), &mut back).unwrap(),
            der.len()
        );
        assert_eq!(back, der);
    }

    /// A caller asking for a public key must not be handed a private key.
    #[test]
    fn the_label_must_match_what_the_caller_asked_for() {
        let der = std::vec![0x33u8; 40];
        let mut out = std::vec![0u8; encoded_len(PRIVATE_KEY, der.len())];
        let n = encode(PRIVATE_KEY, &der, &mut out).unwrap();
        let mut back = std::vec![0u8; der.len()];
        assert!(decode(PUBLIC_KEY, &out[..n], &mut back).is_err());
        assert!(decode(PRIVATE_KEY, &out[..n], &mut back).is_ok());
    }

    #[test]
    fn mismatched_begin_and_end_labels_are_rejected() {
        let doc = "-----BEGIN PUBLIC KEY-----\naGk=\n-----END PRIVATE KEY-----\n";
        let mut back = [0u8; 16];
        assert!(decode(PUBLIC_KEY, doc.as_bytes(), &mut back).is_err());
        assert!(decode(PRIVATE_KEY, doc.as_bytes(), &mut back).is_err());
    }

    #[test]
    fn a_missing_end_line_is_rejected() {
        let doc = "-----BEGIN PUBLIC KEY-----\naGk=\n";
        let mut back = [0u8; 16];
        assert!(decode(PUBLIC_KEY, doc.as_bytes(), &mut back).is_err());
    }

    #[test]
    fn non_base64_content_is_rejected() {
        let doc = "-----BEGIN PUBLIC KEY-----\naG!=\n-----END PUBLIC KEY-----\n";
        let mut back = [0u8; 16];
        assert!(decode(PUBLIC_KEY, doc.as_bytes(), &mut back).is_err());

        // A line that is not a whole number of base64 quanta.
        let doc = "-----BEGIN PUBLIC KEY-----\naGk\n-----END PUBLIC KEY-----\n";
        assert!(decode(PUBLIC_KEY, doc.as_bytes(), &mut back).is_err());
    }

    #[test]
    fn labels_with_hyphens_are_refused() {
        let mut out = [0u8; 128];
        assert!(encode("BAD-LABEL", b"x", &mut out).is_err());
        assert!(encode("", b"x", &mut out).is_err());
        let mut back = [0u8; 16];
        assert!(decode("BAD-LABEL", b"", &mut back).is_err());
    }

    #[test]
    fn a_small_buffer_is_an_error_not_a_panic() {
        let mut out = [0u8; 8];
        assert!(encode(PUBLIC_KEY, b"hello", &mut out).is_err());

        let der = std::vec![0x44u8; 100];
        let mut full = std::vec![0u8; encoded_len(PUBLIC_KEY, der.len())];
        let n = encode(PUBLIC_KEY, &der, &mut full).unwrap();
        let mut small = [0u8; 10];
        assert!(decode(PUBLIC_KEY, &full[..n], &mut small).is_err());
    }

    #[test]
    fn an_empty_payload_round_trips() {
        let mut out = std::vec![0u8; encoded_len(PUBLIC_KEY, 0)];
        let n = encode(PUBLIC_KEY, &[], &mut out).unwrap();
        let mut back = [0u8; 4];
        assert_eq!(decode(PUBLIC_KEY, &out[..n], &mut back).unwrap(), 0);
    }
}
