//! Conversion between fixed-width ECDSA signatures and `Ecdsa-Sig-Value` DER.
//!
//! ```text
//! Ecdsa-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
//! ```
//!
//! [`ic_ec`] produces and consumes the fixed-width form, `r || s` with each
//! half padded to the field size. X.509, CMS, and TLS carry the DER form. The
//! two are the same numbers in different clothes, and this module is the
//! changing room.
//!
//! # The sign byte
//!
//! DER integers are signed. About half of all `r` values have their top bit
//! set, and those need a leading `0x00` that is part of the encoding and not
//! part of the number. An implementation that omits it produces signatures that
//! verify correctly against itself and are rejected by everything else, roughly
//! half the time — which is exactly the kind of bug that survives a test suite
//! with one vector in it. [`der::Writer::push_unsigned_integer`] applies the
//! rule, and [`tests::the_sign_byte_appears_exactly_when_the_top_bit_is_set`]
//! checks both branches.
//!
//! [`der::Writer::push_unsigned_integer`]: crate::der::Writer::push_unsigned_integer

use crate::der::{self, Reader, Writer};
use ic_core::{ensure, Result};

/// Convert a fixed-width `r || s` signature to DER, returning the length.
///
/// `signature` must be exactly twice the field size: 64 bytes for P-256, 96 for
/// P-384.
pub fn to_der(signature: &[u8], out: &mut [u8]) -> Result<usize> {
    ensure!(
        !signature.is_empty() && signature.len() % 2 == 0,
        InvalidLength,
        "ecdsa signature must be an even number of bytes"
    );
    let (r, s) = signature.split_at(signature.len() / 2);

    let mut w = Writer::new(out);
    let start = w.len();
    w.push_unsigned_integer(s)?;
    w.push_unsigned_integer(r)?;
    w.push_wrapper(der::SEQUENCE, start)?;
    Ok(w.finish())
}

/// Convert an `Ecdsa-Sig-Value` to the fixed-width form.
///
/// `out` must be exactly twice the field size, and both halves are left-padded
/// with zeros. Rejects `r` or `s` values too large for the field, and rejects
/// trailing data.
pub fn from_der(input: &[u8], out: &mut [u8]) -> Result<()> {
    ensure!(
        !out.is_empty() && out.len() % 2 == 0,
        InvalidLength,
        "ecdsa signature buffer must be an even number of bytes"
    );
    let field_len = out.len() / 2;

    let mut outer = Reader::new(input);
    let mut seq = outer.sequence()?;
    outer.finish()?;
    let r = seq.unsigned_integer()?;
    let s = seq.unsigned_integer()?;
    seq.finish()?;

    for (value, half) in [(r, 0usize), (s, 1)] {
        ensure!(
            value.len() <= field_len,
            MalformedEncoding,
            "ecdsa signature component is too large for this curve"
        );
        let slot = &mut out[half * field_len..(half + 1) * field_len];
        for byte in slot.iter_mut() {
            *byte = 0;
        }
        slot[field_len - value.len()..].copy_from_slice(value);
    }
    Ok(())
}

/// The largest DER encoding a fixed-width signature of `signature_len` bytes
/// can produce.
///
/// Two integers, each at most `signature_len / 2 + 1` content bytes with the
/// sign byte, each with a two-byte header, inside a `SEQUENCE` with a two-byte
/// header. Use it to size a buffer without guessing.
pub const fn max_der_len(signature_len: usize) -> usize {
    let half = signature_len / 2;
    2 + 2 * (2 + half + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both halves of the sign-byte rule, with values chosen so that one `r`
    /// needs the byte and the other does not.
    #[test]
    fn the_sign_byte_appears_exactly_when_the_top_bit_is_set() {
        // Top bit clear: no sign byte.
        let mut sig = [0u8; 64];
        sig[0] = 0x7f;
        sig[32] = 0x01;
        let mut der = [0u8; 80];
        let n = to_der(&sig, &mut der).unwrap();
        assert_eq!(der[2], der::INTEGER);
        assert_eq!(der[3], 32, "r is 32 content bytes");
        assert_eq!(der[4], 0x7f, "no sign byte");

        // Top bit set: one leading zero.
        sig[0] = 0x80;
        let n2 = to_der(&sig, &mut der).unwrap();
        assert_eq!(der[3], 33, "r is 33 content bytes");
        assert_eq!(der[4], 0x00, "sign byte");
        assert_eq!(der[5], 0x80);
        assert_eq!(n2, n + 1);
    }

    /// Leading zeros in the fixed-width form are padding, not value, and must
    /// not survive into the DER.
    #[test]
    fn leading_zeros_are_stripped() {
        let mut sig = [0u8; 64];
        sig[31] = 0x09; // r = 9
        sig[63] = 0x01; // s = 1
        let mut der = [0u8; 80];
        let n = to_der(&sig, &mut der).unwrap();
        assert_eq!(
            &der[..n],
            &[0x30, 0x06, 0x02, 0x01, 0x09, 0x02, 0x01, 0x01],
            "minimal integers"
        );

        let mut back = [0u8; 64];
        from_der(&der[..n], &mut back).unwrap();
        assert_eq!(back, sig, "padding is restored on the way back");
    }

    #[test]
    fn a_zero_component_encodes_as_a_single_byte() {
        // r = 0 is not a valid signature, but it is a valid encoding, and the
        // verifier rather than the parser is what rejects it.
        let sig = [0u8; 64];
        let mut der = [0u8; 80];
        let n = to_der(&sig, &mut der).unwrap();
        assert_eq!(&der[..n], &[0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]);
        let mut back = [0u8; 64];
        from_der(&der[..n], &mut back).unwrap();
        assert_eq!(back, sig);
    }

    /// Round-trip over every combination of high and low bytes at both ends of
    /// both components, which is where the padding logic can go wrong.
    #[test]
    fn round_trips_across_the_interesting_shapes() {
        let patterns: &[[u8; 4]] = &[
            [0x00, 0x00, 0x00, 0x00],
            [0xff, 0x01, 0xff, 0x01],
            [0x80, 0x00, 0x80, 0x00],
            [0x7f, 0xff, 0x00, 0x7f],
            [0x01, 0x00, 0xff, 0xff],
        ];
        for field_len in [32usize, 48] {
            for p in patterns {
                let mut sig = std::vec![0u8; field_len * 2];
                sig[0] = p[0];
                sig[field_len - 1] = p[1];
                sig[field_len] = p[2];
                sig[2 * field_len - 1] = p[3];

                let mut der = std::vec![0u8; max_der_len(sig.len())];
                let n = to_der(&sig, &mut der).unwrap();
                assert!(n <= der.len(), "max_der_len is an upper bound");

                let mut back = std::vec![0u8; field_len * 2];
                from_der(&der[..n], &mut back).unwrap();
                assert_eq!(back, sig, "field {field_len}, pattern {p:02x?}");
            }
        }
    }

    #[test]
    fn max_der_len_is_tight() {
        // The worst case is both components 32 bytes with the top bit set.
        let mut sig = [0u8; 64];
        sig[0] = 0xff;
        sig[32] = 0xff;
        let mut der = [0u8; 128];
        let n = to_der(&sig, &mut der).unwrap();
        assert_eq!(
            n,
            max_der_len(64),
            "the bound is reached, not just respected"
        );
    }

    #[test]
    fn oversized_components_are_rejected() {
        // Encode a P-384-sized signature, then try to read it back as P-256.
        let mut wide_sig = [0xffu8; 96];
        wide_sig[0] = 0x01; // keep r below the 48-byte boundary but above 32
        let mut der = [0u8; 128];
        let n = to_der(&wide_sig, &mut der).unwrap();

        let mut narrow = [0u8; 64];
        assert!(
            from_der(&der[..n], &mut narrow).is_err(),
            "a 48-byte component does not fit a 32-byte field"
        );

        let mut wide = [0u8; 96];
        assert!(from_der(&der[..n], &mut wide).is_ok());
        assert_eq!(wide, wide_sig);
    }

    #[test]
    fn malformed_input_is_rejected() {
        let sig = [0x11u8; 64];
        let mut der = [0u8; 80];
        let n = to_der(&sig, &mut der).unwrap();
        let mut out = [0u8; 64];

        let mut extra = der[..n].to_vec();
        extra.push(0);
        assert!(from_der(&extra, &mut out).is_err(), "trailing data");
        assert!(from_der(&der[..n - 1], &mut out).is_err(), "truncated");
        assert!(from_der(&[], &mut out).is_err(), "empty");

        // A third integer in the sequence.
        let mut three = der[..n].to_vec();
        three.extend_from_slice(&[0x02, 0x01, 0x01]);
        three[1] += 3;
        assert!(from_der(&three, &mut out).is_err(), "extra field");
    }

    #[test]
    fn odd_lengths_are_rejected() {
        let mut der = [0u8; 80];
        assert!(to_der(&[0u8; 63], &mut der).is_err());
        assert!(to_der(&[], &mut der).is_err());
        let mut odd = [0u8; 63];
        assert!(from_der(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01], &mut odd).is_err());
    }

    #[test]
    fn a_small_buffer_is_an_error_not_a_panic() {
        let sig = [0xffu8; 64];
        let mut der = [0u8; 16];
        assert!(to_der(&sig, &mut der).is_err());
    }
}
