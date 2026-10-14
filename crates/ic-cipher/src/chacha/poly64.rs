//! Poly1305 in radix 2^64, for the AEAD's short messages on x86-64.
//!
//! # Why a second Poly1305
//!
//! The one in [`super::Poly1305`] keeps `h` and `r` in five 26-bit limbs, the
//! form its four-way and AVX2 paths need: one block costs twenty-five 32-bit
//! products. Here `h` is two 64-bit words and a few bits more, `r` two words,
//! and a block costs four 64x64 -> 128-bit products and two small ones, on
//! `MUL`. A short message never reaches the wide paths, so for it this is the
//! cheaper form; and key setup is three masks, where the other form computes
//! `r^2`, `r^3` and `r^4` that a short message never uses.
//!
//! It serves the AEAD only, so every block is whole -- the AEAD pads the
//! associated data and the ciphertext with zeros to sixteen bytes -- and the
//! `2^128` bit is always set. There is no streaming state and no buffer: one
//! call takes the associated data, the ciphertext and the lengths.
//!
//! # The arithmetic
//!
//! The 64-bit scheme of poly1305-donna and OpenSSL, written out again from
//! RFC 8439 section 2.5. `h = h2 * 2^128 + h1 * 2^64 + h0`, with `h2` a few
//! bits; `r = r1 * 2^64 + r0`, clamped, so `r0` and `r1` are below `2^60` and
//! `r1` is a multiple of four. Then `h * r mod p` needs only
//!
//! ```text
//! d0 = h0 r0 + h1 (5 r1 / 4)
//! d1 = h0 r1 + h1 r0 + h2 (5 r1 / 4)
//! d2 = h2 r0
//! ```
//!
//! because `2^128 r1 = 2^130 (r1 / 4) = 5 (r1 / 4) mod p`, which is where the
//! clamping of `r1`'s low two bits is used. Then everything at or above
//! `2^130` -- `d2`'s bits from bit 2 up, after the carries -- folds back in
//! times five.
//!
//! Bounds, which are why nothing wraps: on entry to a block `h2 <= 4`, and
//! adding a block with its `2^128` bit makes it at most 6. Then `h2 (5 r1 /
//! 4) < 6 * 1.25 * 2^60 < 2^63` and `h2 r0 < 6 * 2^60`, so both fit in a
//! `u64`; `d0` and `d1` are under `2^126`; and the folded value `5 (d2 >>
//! 2)` is under `2^64`. After the fold `h2 <= 3` plus a carry, so at most 4,
//! and `h < 2^130 + 2^64 < 2p`: one conditional subtraction of `p` at the end
//! makes it canonical.
//!
//! # Trusting it
//!
//! `chacha::tests::the_aead_matches_the_portable_forms` compares the AEAD,
//! which takes this path for short messages, with the 26-bit Poly1305 that
//! the RFC 8439 vectors validate, at every length to 600 bytes and with
//! associated data of every length to 48; and
//! `the_short_poly1305_agrees_at_its_largest_limbs` does the same with every
//! message bit set under the largest clamped `r`, where the bounds above are
//! tightest; `the_short_poly1305_reduces_at_and_above_p` puts `h` either side
//! of `p`, where the final subtraction is decided, which no random input
//! reaches.
//!
//! # Constant-time properties
//!
//! `MUL`, `ADD`, `ADC`, shifts and masks; the carries are taken from 128-bit
//! sums, and the final subtraction selects by mask. The only branches are on
//! the lengths, which are public. `ct_poly1305_short` in `scripts/ct-audit`
//! holds the compiled code to that.

use ic_core::Zeroize;

/// The state: `h`, then `r0`, `r1` and `5 r1 / 4`, then `s`. Wiped on drop.
struct State {
    h: [u64; 3],
    r: [u64; 3],
    s: [u64; 2],
}

impl Drop for State {
    fn drop(&mut self) {
        self.h.zeroize();
        self.r.zeroize();
        self.s.zeroize();
    }
}

#[inline(always)]
fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

#[inline(always)]
fn mul(a: u64, b: u64) -> u128 {
    a as u128 * b as u128
}

impl State {
    #[inline(always)]
    fn new(key: &[u8; 32]) -> Self {
        // RFC 8439 section 2.5: clear the top four bits of bytes 3, 7, 11 and
        // 15 and the bottom two of bytes 4, 8 and 12.
        let r0 = le64(&key[0..8]) & 0x0fff_fffc_0fff_ffff;
        let r1 = le64(&key[8..16]) & 0x0fff_fffc_0fff_fffc;
        Self {
            h: [0; 3],
            r: [r0, r1, r1 + (r1 >> 2)],
            s: [le64(&key[16..24]), le64(&key[24..32])],
        }
    }

    /// `h = (h + m + 2^128) r mod p`, partly reduced.
    #[inline(always)]
    fn block(&mut self, m0: u64, m1: u64) {
        let [r0, r1, s1] = self.r;
        let [h0, h1, h2] = self.h;

        let t = h0 as u128 + m0 as u128;
        let h0 = t as u64;
        let t = h1 as u128 + m1 as u128 + (t >> 64);
        let h1 = t as u64;
        let h2 = h2 + (t >> 64) as u64 + 1;

        let d0 = mul(h0, r0) + mul(h1, s1);
        let d1 = mul(h0, r1) + mul(h1, r0) + (h2 * s1) as u128 + (d0 >> 64);
        let d2 = h2 * r0 + (d1 >> 64) as u64;

        // Fold what is at or above 2^130 back in, times five.
        let c = (d2 >> 2) + (d2 & !3);
        let t = d0 as u64 as u128 + c as u128;
        let h0 = t as u64;
        let t = d1 as u64 as u128 + (t >> 64);
        self.h = [h0, t as u64, (d2 & 3) + (t >> 64) as u64];
    }

    /// Absorb `data`, the last block zero-padded to sixteen bytes.
    #[inline(always)]
    fn padded(&mut self, data: &[u8]) {
        let mut blocks = data.chunks_exact(16);
        for b in &mut blocks {
            self.block(le64(&b[..8]), le64(&b[8..]));
        }
        let rest = blocks.remainder();
        if !rest.is_empty() {
            let mut b = [0u8; 16];
            b[..rest.len()].copy_from_slice(rest);
            self.block(le64(&b[..8]), le64(&b[8..]));
        }
    }

    /// `(h mod p + s) mod 2^128`, little-endian.
    #[inline(always)]
    fn finish(&self) -> [u8; 16] {
        let [h0, h1, h2] = self.h;
        // g = h + 5 - 2^130; if that did not borrow, h >= p and g is h mod p.
        let t = h0 as u128 + 5;
        let g0 = t as u64;
        let t = h1 as u128 + (t >> 64);
        let g1 = t as u64;
        let g2 = h2 + (t >> 64) as u64;
        let take_g = 0u64.wrapping_sub(g2 >> 2);
        let h0 = (h0 & !take_g) | (g0 & take_g);
        let h1 = (h1 & !take_g) | (g1 & take_g);

        let t = h0 as u128 + self.s[0] as u128;
        let t0 = t as u64;
        let t1 = (h1 as u128 + self.s[1] as u128 + (t >> 64)) as u64;
        let mut tag = [0u8; 16];
        tag[..8].copy_from_slice(&t0.to_le_bytes());
        tag[8..].copy_from_slice(&t1.to_le_bytes());
        tag
    }
}

/// The ChaCha20-Poly1305 tag (RFC 8439 section 2.8) under the one-time key
/// `key`: Poly1305 over `aad`, padding, `ciphertext`, padding and the two
/// lengths.
#[inline]
pub(crate) fn aead_tag(key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut st = State::new(key);
    st.padded(aad);
    st.padded(ciphertext);
    st.block(aad.len() as u64, ciphertext.len() as u64);
    st.finish()
}
