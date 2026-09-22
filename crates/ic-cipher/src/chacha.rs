//! RFC 8439 ChaCha20, Poly1305, and the ChaCha20-Poly1305 AEAD.
//!
//! **Not FIPS-approved.** These are included because they are the right answer
//! on hardware without AES acceleration, and because interoperating with TLS
//! 1.3, WireGuard, and age requires them. The ontology marks the whole family
//! `fips_status: NotApproved`, and `ic-fips` refuses to construct them while
//! the module is in approved mode.

use ic_core::traits::{Aead, Algorithm, Mac, SelfTest};
use ic_core::{ensure, Result, Zeroize};

const SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[inline(always)]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// Produce one 64-byte ChaCha20 keystream block.
fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12], out: &mut [u8; 64]) {
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&SIGMA);
    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }

    let mut working = state;
    for _ in 0..10 {
        // Column rounds.
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        // Diagonal rounds.
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }
    for i in 0..16 {
        let v = working[i].wrapping_add(state[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    working.zeroize();
    state.zeroize();
}

// Eight-way ChaCha20. `std` only, because the detection needs it.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
mod avx2;

/// Whether this CPU has AVX2. Asked once; see the SHA-256 dispatch for why.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
fn avx2() -> bool {
    use core::sync::atomic::{AtomicU8, Ordering};
    static CACHED: AtomicU8 = AtomicU8::new(0);
    match CACHED.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let have = std::is_x86_feature_detected!("avx2");
            CACHED.store(u8::from(!have) + 1, Ordering::Relaxed);
            have
        }
    }
}

/// XOR `data` with the ChaCha20 keystream, starting at `counter`.
pub fn chacha20_xor(key: &[u8], nonce: &[u8], counter: u32, data: &mut [u8]) -> Result<()> {
    ensure!(
        key.len() == 32,
        InvalidLength,
        "chacha20 key must be 32 bytes"
    );
    ensure!(
        nonce.len() == 12,
        InvalidLength,
        "chacha20 nonce must be 12 bytes"
    );
    let mut k = [0u8; 32];
    k.copy_from_slice(key);
    let mut n = [0u8; 12];
    n.copy_from_slice(nonce);

    // Eight blocks at a time where the CPU can. The tail, and every target
    // without AVX2, falls through to the block-at-a-time path below.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    let mut done = 0usize;
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    if avx2() {
        let groups = data.len() / avx2::STRIDE;
        // The counter must not wrap silently. The scalar path below reports
        // exhaustion; this has to reach the same conclusion before it starts,
        // because it advances eight at a time and would otherwise step over the
        // boundary rather than land on it.
        let needed = (groups as u64) * (avx2::LANES as u64);
        if (counter as u64).checked_add(needed).is_some() {
            for g in 0..groups {
                let ctr = counter.wrapping_add((g * avx2::LANES) as u32);
                let at = g * avx2::STRIDE;
                // SAFETY: `avx2()` confirmed the feature, and the slice is
                // exactly STRIDE bytes by construction.
                unsafe { avx2::eight_blocks(&k, &n, ctr, &mut data[at..at + avx2::STRIDE]) };
            }
            done = groups * avx2::STRIDE;
        }
    }
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    let (data, counter) = {
        let advanced = counter.wrapping_add((done / 64) as u32);
        (&mut data[done..], advanced)
    };

    let mut block = [0u8; 64];
    for (i, chunk) in data.chunks_mut(64).enumerate() {
        let ctr = counter
            .checked_add(i as u32)
            .ok_or(ic_core::err!(CounterExhausted, "chacha20 block counter"))?;
        chacha20_block(&k, ctr, &n, &mut block);
        for (d, b) in chunk.iter_mut().zip(block.iter()) {
            *d ^= b;
        }
    }
    block.zeroize();
    k.zeroize();
    Ok(())
}

/// RFC 8439 Poly1305 one-time authenticator.
///
/// Every key must be used for exactly one message. Reuse reveals the key.
#[derive(Clone)]
pub struct Poly1305 {
    r: [u32; 5],
    s: [u32; 4],
    acc: [u32; 5],
    buf: [u8; 16],
    buffered: usize,
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.r.zeroize();
        self.s.zeroize();
        self.acc.zeroize();
        self.buf.zeroize();
    }
}

impl Algorithm for Poly1305 {
    const ID: &'static str = "poly1305";
    const NAME: &'static str = "Poly1305";
}

impl Poly1305 {
    /// Absorb one block. Blocks shorter than 16 bytes are the final block and
    /// get an explicit 0x01 terminator instead of the implicit 2^128 bit.
    fn absorb_block(&mut self, block: &[u8]) {
        let mut b = [0u8; 16];
        b[..block.len()].copy_from_slice(block);
        let pad = if block.len() < 16 {
            b[block.len()] = 1;
            0
        } else {
            1 << 24
        };

        let t0 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let t1 = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
        let t2 = u32::from_le_bytes([b[8], b[9], b[10], b[11]]);
        let t3 = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);

        self.acc[0] += t0 & 0x3ff_ffff;
        self.acc[1] += ((t0 >> 26) | (t1 << 6)) & 0x3ff_ffff;
        self.acc[2] += ((t1 >> 20) | (t2 << 12)) & 0x3ff_ffff;
        self.acc[3] += ((t2 >> 14) | (t3 << 18)) & 0x3ff_ffff;
        self.acc[4] += (t3 >> 8) | pad;

        self.multiply_by_r();
    }

    fn multiply_by_r(&mut self) {
        let r = self.r;
        let s: [u32; 4] = [r[1] * 5, r[2] * 5, r[3] * 5, r[4] * 5];
        let h = self.acc;

        let d0 = h[0] as u64 * r[0] as u64
            + h[1] as u64 * s[3] as u64
            + h[2] as u64 * s[2] as u64
            + h[3] as u64 * s[1] as u64
            + h[4] as u64 * s[0] as u64;
        let d1 = h[0] as u64 * r[1] as u64
            + h[1] as u64 * r[0] as u64
            + h[2] as u64 * s[3] as u64
            + h[3] as u64 * s[2] as u64
            + h[4] as u64 * s[1] as u64;
        let d2 = h[0] as u64 * r[2] as u64
            + h[1] as u64 * r[1] as u64
            + h[2] as u64 * r[0] as u64
            + h[3] as u64 * s[3] as u64
            + h[4] as u64 * s[2] as u64;
        let d3 = h[0] as u64 * r[3] as u64
            + h[1] as u64 * r[2] as u64
            + h[2] as u64 * r[1] as u64
            + h[3] as u64 * r[0] as u64
            + h[4] as u64 * s[3] as u64;
        let d4 = h[0] as u64 * r[4] as u64
            + h[1] as u64 * r[3] as u64
            + h[2] as u64 * r[2] as u64
            + h[3] as u64 * r[1] as u64
            + h[4] as u64 * r[0] as u64;

        // Carry-propagate back into 26-bit limbs.
        let mut c = (d0 >> 26) as u32;
        self.acc[0] = d0 as u32 & 0x3ff_ffff;
        let d1 = d1 + c as u64;
        c = (d1 >> 26) as u32;
        self.acc[1] = d1 as u32 & 0x3ff_ffff;
        let d2 = d2 + c as u64;
        c = (d2 >> 26) as u32;
        self.acc[2] = d2 as u32 & 0x3ff_ffff;
        let d3 = d3 + c as u64;
        c = (d3 >> 26) as u32;
        self.acc[3] = d3 as u32 & 0x3ff_ffff;
        let d4 = d4 + c as u64;
        c = (d4 >> 26) as u32;
        self.acc[4] = d4 as u32 & 0x3ff_ffff;
        self.acc[0] += c * 5;
        c = self.acc[0] >> 26;
        self.acc[0] &= 0x3ff_ffff;
        self.acc[1] += c;
    }
}

impl Mac for Poly1305 {
    type Tag = [u8; 16];
    const TAG_LEN: usize = 16;

    fn new(key: &[u8]) -> Result<Self> {
        ensure!(
            key.len() == 32,
            InvalidLength,
            "poly1305 key must be 32 bytes"
        );
        let t0 = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
        let t1 = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);
        let t2 = u32::from_le_bytes([key[8], key[9], key[10], key[11]]);
        let t3 = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);
        // `r` is clamped per RFC 8439 §2.5.
        let r = [
            t0 & 0x3ff_ffff,
            ((t0 >> 26) | (t1 << 6)) & 0x3ff_ff03,
            ((t1 >> 20) | (t2 << 12)) & 0x3ff_c0ff,
            ((t2 >> 14) | (t3 << 18)) & 0x3f0_3fff,
            (t3 >> 8) & 0x000_fffff,
        ];
        let s = [
            u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
            u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
            u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
            u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        ];
        Ok(Self {
            r,
            s,
            acc: [0u32; 5],
            buf: [0u8; 16],
            buffered: 0,
        })
    }

    fn update(&mut self, mut data: &[u8]) {
        if self.buffered > 0 {
            let take = core::cmp::min(16 - self.buffered, data.len());
            self.buf[self.buffered..self.buffered + take].copy_from_slice(&data[..take]);
            self.buffered += take;
            data = &data[take..];
            if self.buffered < 16 {
                return;
            }
            let block = self.buf;
            self.absorb_block(&block);
            self.buffered = 0;
        }
        let mut chunks = data.chunks_exact(16);
        for block in &mut chunks {
            self.absorb_block(block);
        }
        let rest = chunks.remainder();
        self.buf[..rest.len()].copy_from_slice(rest);
        self.buffered = rest.len();
    }

    fn finalize(mut self) -> [u8; 16] {
        if self.buffered > 0 {
            let n = self.buffered;
            let block = self.buf;
            self.absorb_block(&block[..n]);
            self.buffered = 0;
        }

        // Final reduction modulo 2^130 - 5.
        let mut h = self.acc;
        let mut c = h[1] >> 26;
        h[1] &= 0x3ff_ffff;
        h[2] += c;
        c = h[2] >> 26;
        h[2] &= 0x3ff_ffff;
        h[3] += c;
        c = h[3] >> 26;
        h[3] &= 0x3ff_ffff;
        h[4] += c;
        c = h[4] >> 26;
        h[4] &= 0x3ff_ffff;
        h[0] += c * 5;
        c = h[0] >> 26;
        h[0] &= 0x3ff_ffff;
        h[1] += c;

        // g = h + 5, then select g if it did not overflow past 2^130.
        let mut g = [0u32; 5];
        let mut carry = 5u32;
        for i in 0..4 {
            let v = h[i] + carry;
            g[i] = v & 0x3ff_ffff;
            carry = v >> 26;
        }
        // The top limb is left unmasked so the borrow out of 2^130 is visible
        // in its sign bit.
        g[4] = h[4].wrapping_add(carry).wrapping_sub(1 << 26);
        let mask = ((g[4] >> 31) ^ 1).wrapping_neg();
        for i in 0..5 {
            h[i] = (h[i] & !mask) | (g[i] & mask);
        }

        // Serialize as a 128-bit little-endian value, then add `s`.
        let h0 = h[0] | (h[1] << 26);
        let h1 = (h[1] >> 6) | (h[2] << 20);
        let h2 = (h[2] >> 12) | (h[3] << 14);
        let h3 = (h[3] >> 18) | (h[4] << 8);

        let mut f = h0 as u64 + self.s[0] as u64;
        let r0 = f as u32;
        f = h1 as u64 + self.s[1] as u64 + (f >> 32);
        let r1 = f as u32;
        f = h2 as u64 + self.s[2] as u64 + (f >> 32);
        let r2 = f as u32;
        f = h3 as u64 + self.s[3] as u64 + (f >> 32);
        let r3 = f as u32;

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&r0.to_le_bytes());
        tag[4..8].copy_from_slice(&r1.to_le_bytes());
        tag[8..12].copy_from_slice(&r2.to_le_bytes());
        tag[12..16].copy_from_slice(&r3.to_le_bytes());
        tag
    }
}

impl SelfTest for Poly1305 {
    fn self_test() -> Result<()> {
        // RFC 8439 §2.5.2.
        let mut key = [0u8; 32];
        ic_core::codec::hex_decode(
            b"85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
            &mut key,
        )?;
        let tag = <Self as Mac>::mac(&key, b"Cryptographic Forum Research Group")?;
        let mut want = [0u8; 16];
        ic_core::codec::hex_decode(b"a8061dc1305136c6c22b8baf0c0127a9", &mut want)?;
        ensure!(ic_core::ct::verify(&want, &tag), SelfTestFailed, "poly1305");
        Ok(())
    }
}

/// RFC 8439 ChaCha20-Poly1305 AEAD.
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

impl Algorithm for ChaCha20Poly1305 {
    const ID: &'static str = "chacha20-poly1305";
    const NAME: &'static str = "ChaCha20-Poly1305";
}

impl ChaCha20Poly1305 {
    /// Derive the one-time Poly1305 key from block 0 of the ChaCha20 keystream.
    fn poly_key(&self, nonce: &[u8]) -> Result<[u8; 32]> {
        let mut block = [0u8; 64];
        let mut n = [0u8; 12];
        ensure!(nonce.len() == 12, InvalidLength, "chacha20-poly1305 nonce");
        n.copy_from_slice(nonce);
        chacha20_block(&self.key, 0, &n, &mut block);
        let mut k = [0u8; 32];
        k.copy_from_slice(&block[..32]);
        block.zeroize();
        Ok(k)
    }

    /// Compute the AEAD tag over `aad || pad || ciphertext || pad || lengths`.
    fn tag(&self, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> Result<[u8; 16]> {
        let mut poly_key = self.poly_key(nonce)?;
        let mut m = Poly1305::new(&poly_key)?;
        poly_key.zeroize();

        m.update(aad);
        m.update(&[0u8; 16][..(16 - aad.len() % 16) % 16]);
        m.update(ciphertext);
        m.update(&[0u8; 16][..(16 - ciphertext.len() % 16) % 16]);

        let mut lens = [0u8; 16];
        lens[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
        lens[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        m.update(&lens);
        Ok(m.finalize())
    }
}

impl Aead for ChaCha20Poly1305 {
    const KEY_LEN: usize = 32;
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;

    fn new(key: &[u8]) -> Result<Self> {
        ensure!(key.len() == 32, InvalidLength, "chacha20-poly1305 key");
        let mut k = [0u8; 32];
        k.copy_from_slice(key);
        Ok(Self { key: k })
    }

    fn seal_detached(
        &self,
        nonce: &[u8],
        aad: &[u8],
        in_out: &mut [u8],
        tag: &mut [u8],
    ) -> Result<()> {
        ensure!(
            tag.len() == 16,
            InvalidLength,
            "chacha20-poly1305 tag buffer"
        );
        // Block 0 is reserved for the Poly1305 key, so data starts at block 1.
        chacha20_xor(&self.key, nonce, 1, in_out)?;
        let t = self.tag(nonce, aad, in_out)?;
        tag.copy_from_slice(&t);
        Ok(())
    }

    fn open_detached(&self, nonce: &[u8], aad: &[u8], in_out: &mut [u8], tag: &[u8]) -> Result<()> {
        ensure!(tag.len() == 16, InvalidLength, "chacha20-poly1305 tag");
        let expected = self.tag(nonce, aad, in_out)?;
        if !ic_core::ct::verify(&expected, tag) {
            in_out.zeroize();
            return Err(ic_core::err!(AuthenticationFailed, "chacha20-poly1305"));
        }
        chacha20_xor(&self.key, nonce, 1, in_out)
    }
}

impl SelfTest for ChaCha20Poly1305 {
    fn self_test() -> Result<()> {
        let key = [0x42u8; 32];
        let nonce = [0x24u8; 12];
        let c = <Self as Aead>::new(&key)?;
        let mut buf = *b"self-test payload";
        let original = buf;
        let mut tag = [0u8; 16];
        c.seal_detached(&nonce, b"aad", &mut buf, &mut tag)?;
        ensure!(buf != original, SelfTestFailed, "chacha20-poly1305");
        c.open_detached(&nonce, b"aad", &mut buf, &tag)?;
        ensure!(buf == original, SelfTestFailed, "chacha20-poly1305");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The eight-way path must produce the same keystream as the block path.
    ///
    /// RFC 8439's vectors do not establish this. The longest of them is 114
    /// bytes and the AVX2 stride is 512, so on this machine they exercise the
    /// scalar path exclusively and would pass with the vector code producing
    /// anything at all. This builds the expected keystream one block at a time
    /// -- the function the RFC vectors do validate -- and compares.
    ///
    /// Lengths straddle the stride in both directions, including several whole
    /// groups plus a tail, because the dispatch splits there and an off-by-one
    /// in the split is the likely error rather than a wrong round function.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[test]
    fn the_avx2_keystream_matches_the_block_function() {
        if !avx2() {
            println!("no AVX2 on this CPU; the backend was not exercised");
            return;
        }

        let key = [0x5au8; 32];
        let nonce = [0x21u8; 12];

        let mut checked = 0;
        for len in [
            0usize, 1, 63, 64, 65, 127, 511, 512, 513, 575, 576, 1023, 1024, 1025, 4096, 4097,
        ] {
            for counter in [0u32, 1, 7, 8, 9, 1000] {
                let mut actual = std::vec![0u8; len];
                chacha20_xor(&key, &nonce, counter, &mut actual).unwrap();

                // The reference: one block at a time, no grouping.
                let mut expect = std::vec![0u8; len];
                let mut block = [0u8; 64];
                for (i, chunk) in expect.chunks_mut(64).enumerate() {
                    chacha20_block(&key, counter + i as u32, &nonce, &mut block);
                    for (d, b) in chunk.iter_mut().zip(block.iter()) {
                        *d ^= b;
                    }
                }

                assert_eq!(
                    actual, expect,
                    "AVX2 and scalar keystreams differ at {len} bytes, counter {counter}"
                );
                checked += 1;
            }
        }
        assert_eq!(checked, 16 * 6, "the comparison did not run");
    }

    /// Say which path this build will take.
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    #[test]
    fn the_active_chacha_path_is_reported() {
        println!(
            "chacha20 backend: {}",
            if avx2() { "AVX2 (8 blocks)" } else { "scalar" }
        );
    }
    use ic_core::codec::{hex, unhex};

    #[test]
    fn rfc8439_chacha20_keystream_vector() {
        let key: Vec<u8> = (0..32u8).collect();
        let mut nonce = [0u8; 12];
        nonce[3] = 0x09;
        nonce[7] = 0x4a;
        let mut data = [0u8; 64];
        chacha20_xor(&key, &nonce, 1, &mut data).unwrap();
        assert_eq!(
            hex(&data),
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
        );
    }

    #[test]
    fn rfc8439_chacha20_encryption_vector() {
        let key: Vec<u8> = (0..32u8).collect();
        let mut nonce = [0u8; 12];
        nonce[7] = 0x4a;
        let mut data =
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        chacha20_xor(&key, &nonce, 1, &mut data).unwrap();
        assert_eq!(
            hex(&data),
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d"
        );
    }

    #[test]
    fn rfc8439_poly1305_vector() {
        let key =
            unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b").unwrap();
        let tag = Poly1305::mac(&key, b"Cryptographic Forum Research Group").unwrap();
        assert_eq!(hex(&tag), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    #[test]
    fn poly1305_streaming_matches_one_shot() {
        let key = [0x11u8; 32];
        let data: Vec<u8> = (0..100u8).collect();
        for split in [0usize, 1, 15, 16, 17, 50, 100] {
            let mut m = Poly1305::new(&key).unwrap();
            m.update(&data[..split]);
            m.update(&data[split..]);
            assert_eq!(
                m.finalize(),
                Poly1305::mac(&key, &data).unwrap(),
                "split at {split}"
            );
        }
    }

    #[test]
    fn rfc8439_aead_vector() {
        let key =
            unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f").unwrap();
        let nonce = unhex("070000004041424344454647").unwrap();
        let aad = unhex("50515253c0c1c2c3c4c5c6c7").unwrap();
        let mut buf =
            b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();

        let c = ChaCha20Poly1305::new(&key).unwrap();
        let mut tag = [0u8; 16];
        c.seal_detached(&nonce, &aad, &mut buf, &mut tag).unwrap();
        assert_eq!(
            hex(&buf),
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
        );
        assert_eq!(hex(&tag), "1ae10b594f09e26a7e902ecbd0600691");

        c.open_detached(&nonce, &aad, &mut buf, &tag).unwrap();
        assert_eq!(
            &buf[..],
            &b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."[..]
        );
    }

    #[test]
    fn aead_rejects_tampering_and_wipes() {
        let c = ChaCha20Poly1305::new(&[1u8; 32]).unwrap();
        let mut buf = b"secret".to_vec();
        let mut tag = [0u8; 16];
        c.seal_detached(&[2u8; 12], b"", &mut buf, &mut tag)
            .unwrap();
        tag[15] ^= 0x80;
        assert!(c.open_detached(&[2u8; 12], b"", &mut buf, &tag).is_err());
        assert_eq!(buf, vec![0u8; 6]);
    }

    #[test]
    fn self_tests_pass() {
        Poly1305::self_test().unwrap();
        ChaCha20Poly1305::self_test().unwrap();
    }
}
