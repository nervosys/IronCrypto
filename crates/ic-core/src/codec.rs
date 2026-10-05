//! Hex and Base64 codecs.
//!
//! These exist so the CLI, MCP server, PEM and ontology exports can move key
//! material and test vectors around without pulling in a dependency. Both
//! directions are constant time in the *values* they carry, which matters
//! because private keys pass through them: a PKCS#8 key in PEM is Base64, and
//! agents paste hex keys into the CLI.
//!
//! # How, and what went wrong before
//!
//! No character is classified by a branch and no value indexes a table.
//!
//! - **Encoding** computes each character arithmetically: the offset from the
//!   value to its character changes at the alphabet's range boundaries, and
//!   each change is a mask made from the sign of a subtraction. A table of 64
//!   or 16 characters indexed by secret bits is a cache-timing channel when it
//!   spans two lines, and the encoders used one.
//! - **Decoding** computes a value and a validity mask for every character the
//!   same way, and accumulates the validity behind [`core::hint::black_box`].
//!   The input is rejected once, at the end, if any character was invalid.
//!
//! The decoders were written branch-free before, but each character's
//! validity was tested at once with `ensure!`, an early return, and every
//! compiler this workspace targets -- x86-64, both Cortex-M cores, 32-bit
//! RISC-V -- turned the OR of the class masks feeding that test into a chain
//! of short-circuit branches: plus? slash? upper case? lower case? digit? Which
//! branch left the chain was the class of a secret character. That is the
//! channel Sieck et al. used against PEM key decoding ("Util::Lookup", USENIX
//! Security 2021), and it was found here by reading the compiled code.

use crate::{ensure, Result};
use core::hint::black_box;

/// All ones when `x` is negative, else zero: the sign of a small difference,
/// spread across a byte.
#[inline(always)]
fn neg_mask(x: i16) -> u8 {
    (x >> 8) as u8
}

/// The lowercase hex digit for `n < 16`: `'0' + n`, and 39 more from 10 up,
/// since `'a' - '0' - 10 = 39`.
#[inline(always)]
fn hex_char(n: u8) -> u8 {
    let n16 = n as i16;
    n + b'0' + (neg_mask(9 - n16) & 39)
}

/// The standard-alphabet character for `v < 64`. The offset starts at `'A'`
/// and changes by 6 at 26 (`a`), by -75 at 52 (`0`), by -15 at 62 (`+`) and
/// by 3 at 63 (`/`); each change is masked in by the sign of `boundary - v`.
#[inline(always)]
fn base64_char(v: u8) -> u8 {
    let v16 = v as i16;
    let mut d = b'A' as i16;
    d += (neg_mask(25 - v16) & 6) as i16;
    d -= (neg_mask(51 - v16) & 75) as i16;
    d -= (neg_mask(61 - v16) & 15) as i16;
    d += (neg_mask(62 - v16) & 3) as i16;
    (v16 + d) as u8
}

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
        out[i * 2] = hex_char(b >> 4);
        out[i * 2 + 1] = hex_char(b & 0x0f);
    }
    Ok(())
}

/// Decode a hex string into `out`, accepting either case.
///
/// `out` must be exactly `input.len() / 2` bytes.
pub fn hex_decode(input: &[u8], out: &mut [u8]) -> Result<()> {
    ensure!(
        input.len().is_multiple_of(2),
        MalformedEncoding,
        "hex length must be even"
    );
    ensure!(
        out.len() == input.len() / 2,
        InvalidLength,
        "hex output buffer"
    );
    // All ones while every character so far has been a hex digit.
    let mut valid = 0xFFu8;
    for i in 0..out.len() {
        let (hi, ok_hi) = hex_nibble(input[i * 2]);
        let (lo, ok_lo) = hex_nibble(input[i * 2 + 1]);
        valid = black_box(valid & ok_hi & ok_lo);
        out[i] = (hi << 4) | lo;
    }
    if valid != 0xFF {
        // Nothing decoded from invalid input is left behind.
        out.fill(0);
    }
    ensure!(valid == 0xFF, MalformedEncoding, "hex digit");
    Ok(())
}

/// A hex digit's value, and all ones if `c` is one; both without a branch.
/// Each class's candidate value is masked in or out, so no arm can overflow on
/// a character it does not match.
#[inline(always)]
fn hex_nibble(c: u8) -> (u8, u8) {
    let digit = c.wrapping_sub(b'0');
    let lower = c.wrapping_sub(b'a');
    let upper = c.wrapping_sub(b'A');
    let m_digit = neg_mask(digit as i16 - 10);
    let m_lower = neg_mask(lower as i16 - 6);
    let m_upper = neg_mask(upper as i16 - 6);
    let value =
        (digit & m_digit) | (lower.wrapping_add(10) & m_lower) | (upper.wrapping_add(10) & m_upper);
    (value, m_digit | m_lower | m_upper)
}

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
        out[oi] = base64_char((n >> 18) as u8 & 63);
        out[oi + 1] = base64_char((n >> 12) as u8 & 63);
        out[oi + 2] = base64_char((n >> 6) as u8 & 63);
        out[oi + 3] = base64_char(n as u8 & 63);
        oi += 4;
    }
    // The remainder's length is the input's length mod 3, which is public.
    let rem = chunks.remainder();
    match rem.len() {
        0 => {}
        1 => {
            let n = (rem[0] as u32) << 16;
            out[oi] = base64_char((n >> 18) as u8 & 63);
            out[oi + 1] = base64_char((n >> 12) as u8 & 63);
            out[oi + 2] = b'=';
            out[oi + 3] = b'=';
        }
        _ => {
            let n = ((rem[0] as u32) << 16) | ((rem[1] as u32) << 8);
            out[oi] = base64_char((n >> 18) as u8 & 63);
            out[oi + 1] = base64_char((n >> 12) as u8 & 63);
            out[oi + 2] = base64_char((n >> 6) as u8 & 63);
            out[oi + 3] = b'=';
        }
    }
    Ok(())
}

/// Decode padded standard Base64, returning the number of bytes written.
///
/// Strict RFC 4648: `=` is accepted only as padding, in the last one or two
/// positions, and every other character must be in the standard alphabet.
pub fn base64_decode(input: &[u8], out: &mut [u8]) -> Result<usize> {
    ensure!(
        input.len().is_multiple_of(4),
        MalformedEncoding,
        "base64 length"
    );
    if input.is_empty() {
        return Ok(0);
    }
    // How much padding there is follows from the length of what was encoded,
    // which the output length reveals anyway.
    let pad = usize::from(input[input.len() - 1] == b'=')
        + usize::from(input.len() >= 2 && input[input.len() - 2] == b'=');
    let decoded = input.len() / 4 * 3 - pad;
    ensure!(out.len() >= decoded, InvalidLength, "base64 output buffer");

    // All ones while every character so far has been valid in its place.
    let mut valid = 0xFFu8;
    let data_chars = input.len() - pad;
    let mut oi = 0;
    for (bi, block) in input.chunks_exact(4).enumerate() {
        let mut n: u32 = 0;
        for (j, &c) in block.iter().enumerate() {
            let (v, ok) = base64_value(c);
            // A padding position must hold `=` and contributes zero bits; any
            // other must hold an alphabet character. Which positions are
            // padding is public.
            let is_pad_pos = bi * 4 + j >= data_chars;
            let ok = if is_pad_pos {
                neg_mask(-i16::from(c == b'='))
            } else {
                ok
            };
            valid = black_box(valid & ok);
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
    if valid != 0xFF {
        out[..decoded].fill(0);
    }
    ensure!(valid == 0xFF, MalformedEncoding, "base64 character");
    Ok(decoded)
}

/// A standard-alphabet character's value, and all ones if `c` is one; both
/// without a branch. An invalid character's value is zero.
#[inline(always)]
fn base64_value(c: u8) -> (u8, u8) {
    let upper = c.wrapping_sub(b'A');
    let lower = c.wrapping_sub(b'a');
    let digit = c.wrapping_sub(b'0');
    let m_upper = neg_mask(upper as i16 - 26);
    let m_lower = neg_mask(lower as i16 - 26);
    let m_digit = neg_mask(digit as i16 - 10);
    // Zero exactly when c is the character: then the difference minus one is
    // negative. `c ^ x` is below 256, so no other value reaches it.
    let m_plus = neg_mask((c ^ b'+') as i16 - 1);
    let m_slash = neg_mask((c ^ b'/') as i16 - 1);
    let value = (upper & m_upper)
        | (lower.wrapping_add(26) & m_lower)
        | (digit.wrapping_add(52) & m_digit)
        | (62 & m_plus)
        | (63 & m_slash);
    (value, m_upper | m_lower | m_digit | m_plus | m_slash)
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

    /// Every byte through both decoders, against a lookup written the obvious
    /// way, and every value through both encoders against the alphabets.
    #[test]
    fn classification_agrees_with_the_alphabets_on_every_byte() {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for v in 0..16u8 {
            assert_eq!(hex_char(v), HEX[v as usize], "hex {v}");
        }
        for v in 0..64u8 {
            assert_eq!(base64_char(v), B64[v as usize], "base64 {v}");
        }
        for c in 0..=255u8 {
            let want_hex = HEX
                .iter()
                .position(|&h| h == c.to_ascii_lowercase())
                .map(|i| i as u8);
            let (v, ok) = hex_nibble(c);
            match want_hex {
                Some(w) => assert_eq!((v, ok), (w, 0xFF), "hex {c:#04x}"),
                None => assert_eq!(ok, 0, "hex {c:#04x} accepted"),
            }
            let want_b64 = B64.iter().position(|&b| b == c).map(|i| i as u8);
            let (v, ok) = base64_value(c);
            match want_b64 {
                Some(w) => assert_eq!((v, ok), (w, 0xFF), "base64 {c:#04x}"),
                None => assert_eq!((v, ok), (0, 0), "base64 {c:#04x} accepted"),
            }
        }
    }

    #[test]
    fn padding_is_accepted_only_where_it_belongs() {
        let mut out = [0u8; 6];
        assert!(base64_decode(b"Zm9vYg==", &mut out).is_ok());
        assert!(base64_decode(b"Zm9vYmE=", &mut out).is_ok());
        for bad in [
            &b"Zm=vYmFy"[..],
            b"=m9vYmFy",
            b"Zm9v=mFy",
            b"Zm9vY=E=",
            b"Zm9vYmF!",
        ] {
            let mut out = [0xAAu8; 6];
            assert!(base64_decode(bad, &mut out).is_err(), "{bad:?} accepted");
            assert!(
                out.iter().all(|&b| b == 0 || b == 0xAA),
                "{bad:?} left decoded bytes behind"
            );
        }
    }

    #[test]
    fn a_bad_digit_anywhere_is_rejected_and_nothing_is_left() {
        let mut out = [0u8; 4];
        for i in 0..8 {
            let mut text = *b"00112233";
            text[i] = b'g';
            assert!(hex_decode(&text, &mut out).is_err(), "position {i}");
            assert_eq!(out, [0; 4], "position {i} left bytes behind");
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
