//! Hex and Base64 codecs.
//!
//! These exist so the CLI, MCP server, and ontology exports can move key
//! material and test vectors around without pulling in a dependency. The
//! decoders are constant-time with respect to the *values* they decode, which
//! matters because agents routinely paste secrets through these paths.

use crate::{ensure, Result};

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Encode `input` as lowercase hex into `out`.
///
/// `out` must be exactly `2 * input.len()` bytes.
pub fn hex_encode(input: &[u8], out: &mut [u8]) -> Result<()> {
    ensure!(
        out.len() == input.len() * 2,
        InvalidLength,
        "hex output buffer"
    );
    for (i, &b) in input.iter().enumerate() {
        out[i * 2] = HEX_LOWER[(b >> 4) as usize];
        out[i * 2 + 1] = HEX_LOWER[(b & 0x0f) as usize];
    }
    Ok(())
}

/// Decode a hex string into `out`, accepting either case.
///
/// `out` must be exactly `input.len() / 2` bytes.
pub fn hex_decode(input: &[u8], out: &mut [u8]) -> Result<()> {
    ensure!(
        input.len() % 2 == 0,
        MalformedEncoding,
        "hex length must be even"
    );
    ensure!(
        out.len() == input.len() / 2,
        InvalidLength,
        "hex output buffer"
    );
    for i in 0..out.len() {
        let hi = hex_nibble(input[i * 2])?;
        let lo = hex_nibble(input[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(())
}

#[inline]
fn hex_nibble(c: u8) -> Result<u8> {
    // Branch-free classification. Each candidate value is masked in or out, so
    // no arm can overflow on a character it does not match.
    let digit = c.wrapping_sub(b'0');
    let lower = c.wrapping_sub(b'a');
    let upper = c.wrapping_sub(b'A');
    let m_digit = ((digit < 10) as u8).wrapping_neg();
    let m_lower = ((lower < 6) as u8).wrapping_neg();
    let m_upper = ((upper < 6) as u8).wrapping_neg();
    ensure!(
        (m_digit | m_lower | m_upper) == 0xFF,
        MalformedEncoding,
        "hex digit"
    );
    Ok((digit & m_digit) | (lower.wrapping_add(10) & m_lower) | (upper.wrapping_add(10) & m_upper))
}

const B64_STD: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Length of the standard-alphabet, padded Base64 encoding of `n` bytes.
pub const fn base64_encoded_len(n: usize) -> usize {
    n.div_ceil(3) * 4
}

/// Encode `input` as padded standard Base64 into `out`.
pub fn base64_encode(input: &[u8], out: &mut [u8]) -> Result<()> {
    ensure!(
        out.len() == base64_encoded_len(input.len()),
        InvalidLength,
        "base64 output buffer"
    );
    let mut oi = 0;
    let mut chunks = input.chunks_exact(3);
    for c in &mut chunks {
        let n = ((c[0] as u32) << 16) | ((c[1] as u32) << 8) | c[2] as u32;
        out[oi] = B64_STD[(n >> 18) as usize & 63];
        out[oi + 1] = B64_STD[(n >> 12) as usize & 63];
        out[oi + 2] = B64_STD[(n >> 6) as usize & 63];
        out[oi + 3] = B64_STD[n as usize & 63];
        oi += 4;
    }
    let rem = chunks.remainder();
    match rem.len() {
        0 => {}
        1 => {
            let n = (rem[0] as u32) << 16;
            out[oi] = B64_STD[(n >> 18) as usize & 63];
            out[oi + 1] = B64_STD[(n >> 12) as usize & 63];
            out[oi + 2] = b'=';
            out[oi + 3] = b'=';
        }
        _ => {
            let n = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
            out[oi] = B64_STD[(n >> 18) as usize & 63];
            out[oi + 1] = B64_STD[(n >> 12) as usize & 63];
            out[oi + 2] = B64_STD[(n >> 6) as usize & 63];
            out[oi + 3] = b'=';
        }
    }
    Ok(())
}

/// Decode padded standard Base64, returning the number of bytes written.
pub fn base64_decode(input: &[u8], out: &mut [u8]) -> Result<usize> {
    ensure!(input.len() % 4 == 0, MalformedEncoding, "base64 length");
    if input.is_empty() {
        return Ok(0);
    }
    let pad = usize::from(input[input.len() - 1] == b'=')
        + usize::from(input.len() >= 2 && input[input.len() - 2] == b'=');
    let decoded = input.len() / 4 * 3 - pad;
    ensure!(out.len() >= decoded, InvalidLength, "base64 output buffer");

    let mut oi = 0;
    for block in input.chunks_exact(4) {
        let mut n: u32 = 0;
        for (j, &c) in block.iter().enumerate() {
            let v = if c == b'=' { 0 } else { base64_value(c)? };
            n |= (v as u32) << (18 - 6 * j);
        }
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        for &b in &bytes {
            if oi < decoded {
                out[oi] = b;
                oi += 1;
            }
        }
    }
    Ok(decoded)
}

#[inline]
fn base64_value(c: u8) -> Result<u8> {
    let upper = c.wrapping_sub(b'A');
    let lower = c.wrapping_sub(b'a');
    let digit = c.wrapping_sub(b'0');
    let m_upper = ((upper < 26) as u8).wrapping_neg();
    let m_lower = ((lower < 26) as u8).wrapping_neg();
    let m_digit = ((digit < 10) as u8).wrapping_neg();
    let m_plus = ((c == b'+') as u8).wrapping_neg();
    let m_slash = ((c == b'/') as u8).wrapping_neg();
    ensure!(
        (m_upper | m_lower | m_digit | m_plus | m_slash) == 0xFF,
        MalformedEncoding,
        "base64 character"
    );
    Ok((upper & m_upper)
        | (lower.wrapping_add(26) & m_lower)
        | (digit.wrapping_add(52) & m_digit)
        | (62 & m_plus)
        | (63 & m_slash))
}

#[cfg(feature = "std")]
mod alloc_helpers {
    use super::*;

    /// Encode `input` as a lowercase hex `String`.
    pub fn hex(input: &[u8]) -> String {
        let mut buf = vec![0u8; input.len() * 2];
        hex_encode(input, &mut buf).expect("buffer sized exactly");
        String::from_utf8(buf).expect("hex alphabet is ASCII")
    }

    /// Decode a hex string into a freshly allocated `Vec`.
    pub fn unhex(input: &str) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; input.len() / 2];
        hex_decode(input.as_bytes(), &mut buf)?;
        Ok(buf)
    }

    /// Encode `input` as a padded standard Base64 `String`.
    pub fn b64(input: &[u8]) -> String {
        let mut buf = vec![0u8; base64_encoded_len(input.len())];
        base64_encode(input, &mut buf).expect("buffer sized exactly");
        String::from_utf8(buf).expect("base64 alphabet is ASCII")
    }

    /// Decode a padded standard Base64 string into a freshly allocated `Vec`.
    pub fn unb64(input: &str) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; input.len() / 4 * 3];
        let n = base64_decode(input.as_bytes(), &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}

#[cfg(feature = "std")]
pub use alloc_helpers::{b64, hex, unb64, unhex};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let data = [0x00u8, 0x0f, 0xf0, 0xff, 0x42];
        let mut enc = [0u8; 10];
        hex_encode(&data, &mut enc).unwrap();
        assert_eq!(&enc, b"000ff0ff42");
        let mut dec = [0u8; 5];
        hex_decode(&enc, &mut dec).unwrap();
        assert_eq!(dec, data);
    }

    #[test]
    fn hex_accepts_uppercase_and_rejects_junk() {
        let mut dec = [0u8; 2];
        hex_decode(b"AbCd", &mut dec).unwrap();
        assert_eq!(dec, [0xab, 0xcd]);
        assert!(hex_decode(b"zz", &mut dec[..1]).is_err());
        assert!(hex_decode(b"abc", &mut dec).is_err());
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        for (plain, encoded) in [
            (&b""[..], ""),
            (&b"f"[..], "Zg=="),
            (&b"fo"[..], "Zm8="),
            (&b"foo"[..], "Zm9v"),
            (&b"foob"[..], "Zm9vYg=="),
            (&b"fooba"[..], "Zm9vYmE="),
            (&b"foobar"[..], "Zm9vYmFy"),
        ] {
            let mut enc = vec![0u8; base64_encoded_len(plain.len())];
            base64_encode(plain, &mut enc).unwrap();
            assert_eq!(
                core::str::from_utf8(&enc).unwrap(),
                encoded,
                "encoding {plain:?}"
            );

            let mut dec = vec![0u8; plain.len() + 3];
            let n = base64_decode(encoded.as_bytes(), &mut dec).unwrap();
            assert_eq!(&dec[..n], plain, "decoding {encoded}");
        }
    }

    #[test]
    fn string_helpers_roundtrip() {
        assert_eq!(hex(b"\xde\xad\xbe\xef"), "deadbeef");
        assert_eq!(unhex("deadbeef").unwrap(), b"\xde\xad\xbe\xef");
        assert_eq!(b64(b"foobar"), "Zm9vYmFy");
        assert_eq!(unb64("Zm9vYmE=").unwrap(), b"fooba");
    }
}
