//! Strict DER: a reader that rejects everything BER allows and DER does not,
//! and a writer that can only produce canonical output.
//!
//! # Why strictness is a security property, not pedantry
//!
//! Every ambiguity a parser tolerates is a place where two implementations can
//! disagree about what a signed document says. Accepting a non-minimal length
//! means the same object has two encodings, so a hash over the encoding is no
//! longer a hash over the object. Accepting trailing bytes after a structure
//! means an attacker can append data that one party sees and another does not.
//! Accepting indefinite-length encodings means the parser has to guess where a
//! value ends. All three have produced real signature-verification bypasses.
//!
//! So this reader rejects, with no option to relax:
//!
//! - indefinite lengths (`0x80`);
//! - long-form lengths that would fit in fewer bytes, or that have a leading
//!   zero byte;
//! - long-form lengths above four bytes, which no object here can need;
//! - `INTEGER`s with a redundant leading `0x00`, or with the sign bit set where
//!   an unsigned value is expected;
//! - `BIT STRING`s with a non-zero unused-bit count, which no key format uses;
//! - trailing data after the outermost value.
//!
//! # No allocation
//!
//! [`Reader`] borrows from the input and never copies. [`Writer`] builds
//! *backwards* from the end of the caller's buffer, which is what lets it emit
//! a length header without knowing the content length in advance and without a
//! scratch buffer. The public entry points move the result to the front of the
//! buffer and return its length.

use ic_core::{ensure, Result};

/// `INTEGER`.
pub const INTEGER: u8 = 0x02;
/// `BIT STRING`.
pub const BIT_STRING: u8 = 0x03;
/// `OCTET STRING`.
pub const OCTET_STRING: u8 = 0x04;
/// `NULL`.
pub const NULL: u8 = 0x05;
/// `OBJECT IDENTIFIER`.
pub const OID: u8 = 0x06;
/// `SEQUENCE`, constructed.
pub const SEQUENCE: u8 = 0x30;

/// Context-specific constructed tag `[n]`, as used for the optional fields of
/// `ECPrivateKey` and `PrivateKeyInfo`.
pub const fn context(n: u8) -> u8 {
    0xA0 | n
}

/// A cursor over a DER-encoded byte string.
#[derive(Clone, Copy)]
pub struct Reader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// Start reading `input`.
    pub fn new(input: &'a [u8]) -> Self {
        Reader { input, pos: 0 }
    }

    /// Whether every byte has been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.pos >= self.input.len()
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> &'a [u8] {
        &self.input[self.pos..]
    }

    /// Require that the input is fully consumed.
    ///
    /// Call this at the end of every top-level parse. Trailing bytes after a
    /// well-formed structure are how an attacker smuggles data past one party
    /// and not another.
    pub fn finish(self) -> Result<()> {
        ensure!(
            self.is_empty(),
            MalformedEncoding,
            "trailing data after der value"
        );
        Ok(())
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(
            self.input.len() - self.pos >= n,
            MalformedEncoding,
            "der value runs past the end of the input"
        );
        let out = &self.input[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    /// Read a length, enforcing the minimal encoding.
    fn length(&mut self) -> Result<usize> {
        let first = self.byte()?;
        if first < 0x80 {
            return Ok(first as usize);
        }
        ensure!(first != 0x80, MalformedEncoding, "indefinite der length");
        let count = (first & 0x7f) as usize;
        ensure!(
            count <= 4,
            MalformedEncoding,
            "der length is implausibly large"
        );
        let bytes = self.take(count)?;
        ensure!(bytes[0] != 0, MalformedEncoding, "non-minimal der length");
        let mut len = 0usize;
        for b in bytes {
            len = (len << 8) | *b as usize;
        }
        // A value under 128 has to use the short form, so the long form here
        // would be a second encoding of the same number.
        ensure!(len >= 0x80, MalformedEncoding, "non-minimal der length");
        Ok(len)
    }

    /// Read the value of the next element, which must carry `tag`.
    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8]> {
        let actual = self.byte()?;
        ensure!(actual == tag, MalformedEncoding, "unexpected der tag");
        let len = self.length()?;
        self.take(len)
    }

    /// Peek at the next element's tag without consuming it.
    pub fn peek_tag(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    /// Read a nested constructed element as its own reader.
    pub fn expect_nested(&mut self, tag: u8) -> Result<Reader<'a>> {
        Ok(Reader::new(self.expect(tag)?))
    }

    /// Read a `SEQUENCE` as its own reader.
    pub fn sequence(&mut self) -> Result<Reader<'a>> {
        self.expect_nested(SEQUENCE)
    }

    /// Read an unsigned `INTEGER`, returning its minimal big-endian bytes with
    /// any DER sign-padding byte removed.
    ///
    /// DER integers are signed two's complement, so an unsigned value whose top
    /// bit is set carries a leading `0x00`. That byte is part of the encoding,
    /// not part of the number, and is stripped here.
    pub fn unsigned_integer(&mut self) -> Result<&'a [u8]> {
        let raw = self.expect(INTEGER)?;
        ensure!(!raw.is_empty(), MalformedEncoding, "empty der integer");
        ensure!(
            raw[0] & 0x80 == 0,
            MalformedEncoding,
            "negative der integer where unsigned was expected"
        );
        if raw[0] == 0 {
            // A lone 0x00 is the canonical encoding of zero, not padding.
            if raw.len() == 1 {
                return Ok(raw);
            }
            ensure!(
                raw[1] & 0x80 != 0,
                MalformedEncoding,
                "non-minimal der integer"
            );
            return Ok(&raw[1..]);
        }
        Ok(raw)
    }

    /// Read an unsigned `INTEGER` that fits in a `u64`.
    pub fn unsigned_integer_u64(&mut self) -> Result<u64> {
        let bytes = self.unsigned_integer()?;
        ensure!(
            bytes.len() <= 8,
            MalformedEncoding,
            "der integer too large for u64"
        );
        let mut v = 0u64;
        for b in bytes {
            v = (v << 8) | *b as u64;
        }
        Ok(v)
    }

    /// Read a `BIT STRING`, which must have no unused trailing bits.
    ///
    /// Every key and signature format this crate handles stores whole bytes, so
    /// a non-zero unused-bit count is malformed rather than merely unusual.
    pub fn bit_string(&mut self) -> Result<&'a [u8]> {
        let raw = self.expect(BIT_STRING)?;
        ensure!(!raw.is_empty(), MalformedEncoding, "empty der bit string");
        ensure!(
            raw[0] == 0,
            MalformedEncoding,
            "der bit string has unused bits"
        );
        Ok(&raw[1..])
    }

    /// Read an `OCTET STRING`.
    pub fn octet_string(&mut self) -> Result<&'a [u8]> {
        self.expect(OCTET_STRING)
    }

    /// Read an `OBJECT IDENTIFIER`, returning its content bytes.
    pub fn oid(&mut self) -> Result<&'a [u8]> {
        let raw = self.expect(OID)?;
        ensure!(!raw.is_empty(), MalformedEncoding, "empty der oid");
        // Each arc is base-128 with a continuation bit; the last byte of the
        // last arc must have it clear.
        ensure!(
            raw[raw.len() - 1] & 0x80 == 0,
            MalformedEncoding,
            "truncated der oid arc"
        );
        Ok(raw)
    }

    /// Read a `NULL`, which must be empty.
    pub fn null(&mut self) -> Result<()> {
        let raw = self.expect(NULL)?;
        ensure!(raw.is_empty(), MalformedEncoding, "der null with content");
        Ok(())
    }

    /// Read the `version` field of a PKCS#8 or SEC1 structure and require a
    /// specific value.
    pub fn expect_version(&mut self, want: u64) -> Result<()> {
        let got = self.unsigned_integer_u64()?;
        ensure!(got == want, Unsupported, "unsupported structure version");
        Ok(())
    }
}

/// Builds DER backwards from the end of a buffer.
///
/// Writing in reverse is what makes a single pass possible: the content of a
/// `SEQUENCE` is emitted before its header, so by the time the header is
/// written the length is already known.
pub struct Writer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Writer<'a> {
    /// Start writing into `buf`, from its end.
    pub fn new(buf: &'a mut [u8]) -> Self {
        let pos = buf.len();
        Writer { buf, pos }
    }

    /// How many bytes have been written.
    pub fn len(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Whether nothing has been written yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Prepend raw bytes.
    pub fn push(&mut self, bytes: &[u8]) -> Result<()> {
        ensure!(
            self.pos >= bytes.len(),
            InvalidLength,
            "der output buffer is too small"
        );
        self.pos -= bytes.len();
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }

    fn push_u8(&mut self, byte: u8) -> Result<()> {
        self.push(&[byte])
    }

    /// Prepend a tag and a minimally encoded length.
    pub fn push_header(&mut self, tag: u8, len: usize) -> Result<()> {
        if len < 0x80 {
            self.push_u8(len as u8)?;
        } else {
            let mut tmp = [0u8; 4];
            let mut n = 0;
            let mut v = len;
            while v > 0 {
                tmp[n] = v as u8;
                v >>= 8;
                n += 1;
            }
            ensure!(n <= 4, InvalidLength, "der length is implausibly large");
            // `tmp` is little-endian and the writer prepends, so pushing it
            // in order leaves the bytes big-endian in the output.
            for byte in tmp.iter().take(n) {
                self.push_u8(*byte)?;
            }
            self.push_u8(0x80 | n as u8)?;
        }
        self.push_u8(tag)
    }

    /// Prepend a complete element: tag, length, and content.
    pub fn push_element(&mut self, tag: u8, content: &[u8]) -> Result<()> {
        self.push(content)?;
        self.push_header(tag, content.len())
    }

    /// Prepend an `OBJECT IDENTIFIER` from its content bytes.
    pub fn push_oid(&mut self, oid: &[u8]) -> Result<()> {
        self.push_element(OID, oid)
    }

    /// Prepend an `OCTET STRING`.
    pub fn push_octet_string(&mut self, content: &[u8]) -> Result<()> {
        self.push_element(OCTET_STRING, content)
    }

    /// Prepend a `NULL`.
    pub fn push_null(&mut self) -> Result<()> {
        self.push_element(NULL, &[])
    }

    /// Prepend a `BIT STRING` with no unused bits.
    pub fn push_bit_string(&mut self, content: &[u8]) -> Result<()> {
        self.push(content)?;
        self.push_u8(0)?;
        self.push_header(BIT_STRING, content.len() + 1)
    }

    /// Prepend an unsigned `INTEGER` given its big-endian bytes.
    ///
    /// Leading zero bytes are dropped, and a `0x00` sign byte is added when the
    /// top bit of the value is set — the two halves of the rule that produce a
    /// canonical encoding. Getting this wrong is the classic DER bug: a
    /// signature whose `r` happens to start with a high byte encodes
    /// differently from one that does not, so an implementation that skips the
    /// sign byte works for 255 out of 256 signatures.
    pub fn push_unsigned_integer(&mut self, value: &[u8]) -> Result<()> {
        let trimmed = match value.iter().position(|b| *b != 0) {
            Some(first) => &value[first..],
            None => &[][..],
        };
        if trimmed.is_empty() {
            // Zero is a single 0x00 content byte.
            return self.push_element(INTEGER, &[0]);
        }
        let needs_sign_byte = trimmed[0] & 0x80 != 0;
        self.push(trimmed)?;
        if needs_sign_byte {
            self.push_u8(0)?;
        }
        self.push_header(INTEGER, trimmed.len() + usize::from(needs_sign_byte))
    }

    /// Prepend a `u64` as an unsigned `INTEGER`.
    pub fn push_unsigned_u64(&mut self, value: u64) -> Result<()> {
        self.push_unsigned_integer(&value.to_be_bytes())
    }

    /// Wrap everything written since `len` was observed in a constructed tag.
    ///
    /// Record `w.len()` before emitting the content, then pass it here.
    pub fn push_wrapper(&mut self, tag: u8, len_before_content: usize) -> Result<()> {
        let content_len = self.len() - len_before_content;
        self.push_header(tag, content_len)
    }

    /// Move the encoding to the front of the buffer and return its length.
    pub fn finish(self) -> usize {
        let len = self.len();
        self.buf.copy_within(self.pos.., 0);
        len
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A DER length, encoded independently of the writer straight from X.690
    /// §8.1.3, so the two derivations have to agree.
    fn reference_length(len: usize) -> std::vec::Vec<u8> {
        if len < 0x80 {
            return std::vec![len as u8];
        }
        let be = len.to_be_bytes();
        let first = be.iter().position(|b| *b != 0).unwrap();
        let body = &be[first..];
        let mut out = std::vec![0x80 | body.len() as u8];
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn lengths_round_trip_and_match_the_reference() {
        for len in [0usize, 1, 127, 128, 255, 256, 65535, 65536, 1 << 23] {
            let mut buf = std::vec![0u8; 16];
            let mut w = Writer::new(&mut buf);
            w.push_header(SEQUENCE, len).unwrap();
            let n = w.finish();
            assert_eq!(buf[0], SEQUENCE);
            assert_eq!(&buf[1..n], &reference_length(len)[..], "length {len}");

            // And the reader agrees, given enough content to consume.
            let mut input = buf[..n].to_vec();
            input.resize(n + len, 0);
            let mut r = Reader::new(&input);
            assert_eq!(r.expect(SEQUENCE).unwrap().len(), len);
        }
    }

    #[test]
    fn non_minimal_lengths_are_rejected() {
        // 0x81 0x01: long form for a value that fits the short form.
        assert!(Reader::new(&[SEQUENCE, 0x81, 0x01, 0x00])
            .expect(SEQUENCE)
            .is_err());
        // 0x82 0x00 0x80: leading zero in the length.
        assert!(Reader::new(&[SEQUENCE, 0x82, 0x00, 0x80])
            .expect(SEQUENCE)
            .is_err());
        // 0x80: indefinite length.
        assert!(Reader::new(&[SEQUENCE, 0x80, 0x00, 0x00])
            .expect(SEQUENCE)
            .is_err());
        // Five length bytes.
        assert!(Reader::new(&[SEQUENCE, 0x85, 1, 0, 0, 0, 0])
            .expect(SEQUENCE)
            .is_err());
    }

    #[test]
    fn truncated_input_is_rejected() {
        assert!(Reader::new(&[SEQUENCE]).expect(SEQUENCE).is_err());
        assert!(Reader::new(&[SEQUENCE, 0x04, 1, 2])
            .expect(SEQUENCE)
            .is_err());
        assert!(Reader::new(&[]).expect(SEQUENCE).is_err());
    }

    #[test]
    fn a_wrong_tag_is_rejected() {
        let mut r = Reader::new(&[OCTET_STRING, 0x01, 0xff]);
        assert!(r.expect(SEQUENCE).is_err());
    }

    #[test]
    fn trailing_data_is_rejected() {
        let mut r = Reader::new(&[OCTET_STRING, 0x01, 0xff, 0x00]);
        r.octet_string().unwrap();
        assert!(r.finish().is_err());
    }

    /// The sign-byte rule, in both directions, including the case that a naive
    /// implementation gets wrong.
    #[test]
    fn unsigned_integers_round_trip_with_the_sign_byte_rule() {
        let cases: &[(&[u8], &[u8])] = &[
            // value, expected full encoding
            (&[0x00], &[INTEGER, 0x01, 0x00]),
            (&[0x01], &[INTEGER, 0x01, 0x01]),
            (&[0x7f], &[INTEGER, 0x01, 0x7f]),
            // Top bit set: a 0x00 sign byte is required.
            (&[0x80], &[INTEGER, 0x02, 0x00, 0x80]),
            (&[0xff], &[INTEGER, 0x02, 0x00, 0xff]),
            // Leading zeros in the input are not part of the number.
            (&[0x00, 0x00, 0x2a], &[INTEGER, 0x01, 0x2a]),
            (&[0x00, 0xab, 0xcd], &[INTEGER, 0x03, 0x00, 0xab, 0xcd]),
        ];
        for (value, want) in cases {
            let mut buf = std::vec![0u8; 16];
            let mut w = Writer::new(&mut buf);
            w.push_unsigned_integer(value).unwrap();
            let n = w.finish();
            assert_eq!(&buf[..n], *want, "encoding {value:02x?}");

            let mut r = Reader::new(&buf[..n]);
            let got = r.unsigned_integer().unwrap();
            let expected_value = match value.iter().position(|b| *b != 0) {
                Some(i) => &value[i..],
                None => &[0u8][..],
            };
            // Zero decodes to the single byte 0x00.
            let expected_value = if expected_value.is_empty() {
                &[0u8][..]
            } else {
                expected_value
            };
            assert_eq!(got, expected_value, "decoding {value:02x?}");
        }
    }

    #[test]
    fn malformed_integers_are_rejected() {
        // Negative: top bit set with no sign byte.
        assert!(Reader::new(&[INTEGER, 0x01, 0x80])
            .unsigned_integer()
            .is_err());
        // Non-minimal: a leading zero that is not needed.
        assert!(Reader::new(&[INTEGER, 0x02, 0x00, 0x01])
            .unsigned_integer()
            .is_err());
        // A lone 0x00 is the canonical zero and must be accepted.
        assert_eq!(
            Reader::new(&[INTEGER, 0x01, 0x00])
                .unsigned_integer()
                .unwrap(),
            &[0u8]
        );
        // Empty content.
        assert!(Reader::new(&[INTEGER, 0x00]).unsigned_integer().is_err());
        // Two leading zeros.
        assert!(Reader::new(&[INTEGER, 0x03, 0x00, 0x00, 0x80])
            .unsigned_integer()
            .is_err());
    }

    #[test]
    fn u64_integers_round_trip() {
        for v in [0u64, 1, 127, 128, 255, 65537, u32::MAX as u64, u64::MAX] {
            let mut buf = std::vec![0u8; 16];
            let mut w = Writer::new(&mut buf);
            w.push_unsigned_u64(v).unwrap();
            let n = w.finish();
            assert_eq!(Reader::new(&buf[..n]).unsigned_integer_u64().unwrap(), v);
        }
        // Nine *value* bytes will not fit a u64. The sign byte does not
        // count towards that, so this is ten content bytes.
        assert!(
            Reader::new(&[INTEGER, 0x0a, 0x00, 0xff, 0, 0, 0, 0, 0, 0, 0, 0])
                .unsigned_integer_u64()
                .is_err()
        );
        // Eight value bytes behind a sign byte still fit.
        assert_eq!(
            Reader::new(&[INTEGER, 0x09, 0x00, 0xff, 0, 0, 0, 0, 0, 0, 0])
                .unsigned_integer_u64()
                .unwrap(),
            0xff00_0000_0000_0000
        );
    }

    #[test]
    fn bit_strings_round_trip_and_reject_unused_bits() {
        let mut buf = std::vec![0u8; 16];
        let mut w = Writer::new(&mut buf);
        w.push_bit_string(&[0xde, 0xad]).unwrap();
        let n = w.finish();
        assert_eq!(&buf[..n], &[BIT_STRING, 0x03, 0x00, 0xde, 0xad]);
        assert_eq!(Reader::new(&buf[..n]).bit_string().unwrap(), &[0xde, 0xad]);

        // A non-zero unused-bit count is refused rather than silently masked.
        assert!(Reader::new(&[BIT_STRING, 0x02, 0x04, 0xf0])
            .bit_string()
            .is_err());
        assert!(Reader::new(&[BIT_STRING, 0x00]).bit_string().is_err());
    }

    #[test]
    fn nulls_must_be_empty() {
        assert!(Reader::new(&[NULL, 0x00]).null().is_ok());
        assert!(Reader::new(&[NULL, 0x01, 0x00]).null().is_err());
    }

    #[test]
    fn oids_must_not_end_mid_arc() {
        // 0x2a 0x86: the final byte still has the continuation bit set, so the
        // arc it belongs to never ends.
        assert!(Reader::new(&[OID, 0x02, 0x2a, 0x86]).oid().is_err());
        assert!(Reader::new(&[OID, 0x00]).oid().is_err());
        assert_eq!(
            Reader::new(&[OID, 0x03, 0x2a, 0x86, 0x47]).oid().unwrap(),
            &[0x2a, 0x86, 0x47]
        );
    }

    /// Nesting works in one pass because the writer runs backwards.
    #[test]
    fn nested_structures_round_trip() {
        let mut buf = std::vec![0u8; 64];
        let mut w = Writer::new(&mut buf);
        let start = w.len();
        w.push_unsigned_u64(65537).unwrap();
        w.push_octet_string(b"hi").unwrap();
        w.push_wrapper(SEQUENCE, start).unwrap();
        let n = w.finish();

        let mut outer = Reader::new(&buf[..n]);
        let mut inner = outer.sequence().unwrap();
        outer.finish().unwrap();
        assert_eq!(inner.octet_string().unwrap(), b"hi");
        assert_eq!(inner.unsigned_integer_u64().unwrap(), 65537);
        inner.finish().unwrap();
    }

    #[test]
    fn a_full_buffer_is_an_error_not_a_panic() {
        let mut buf = [0u8; 2];
        let mut w = Writer::new(&mut buf);
        assert!(w.push_octet_string(b"too long").is_err());
    }

    #[test]
    fn peek_does_not_consume() {
        let mut r = Reader::new(&[OCTET_STRING, 0x01, 0xff]);
        assert_eq!(r.peek_tag(), Some(OCTET_STRING));
        assert_eq!(r.peek_tag(), Some(OCTET_STRING));
        r.octet_string().unwrap();
        assert_eq!(r.peek_tag(), None);
    }

    #[test]
    fn context_tags_are_constructed() {
        assert_eq!(context(0), 0xA0);
        assert_eq!(context(1), 0xA1);
    }
}
