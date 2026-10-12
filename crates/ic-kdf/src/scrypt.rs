//! RFC 7914 scrypt, the memory-hard password-based key derivation function.
//!
//! **Not FIPS-approved.** Argon2id is the first choice for new password
//! storage; scrypt is the one to reach for where Argon2 is not available, as
//! the IETF's password-storage guidance puts it, and for interoperating with
//! systems that already use it -- cryptocurrency wallets, PKCS#8 keys
//! encrypted under PBES2-scrypt, and yescrypt, which builds on it.
//!
//! ```
//! use ic_kdf::scrypt::{scrypt, ScryptParams};
//!
//! let params = ScryptParams { log_n: 4, r: 1, p: 1 }; // RFC 7914's smallest
//! let mut key = [0u8; 64];
//! scrypt(b"", b"", &params, &mut key)?;
//! assert_eq!(key[..4], [0x77, 0xd6, 0x57, 0x62]);
//! # Ok::<(), ic_core::Error>(())
//! ```
//!
//! # Memory access depends on the password
//!
//! `ROMix` reads its table at an index taken from the state, so which memory
//! it touches depends on the password. That is the design -- it is what makes
//! scrypt expensive to attack with less memory -- and it is the same trade
//! Argon2d makes, and Argon2id after its first half-pass. An attacker who can
//! observe this process's cache from the same machine learns something about
//! the access pattern. Where that is in the threat model, prefer Argon2id.
//!
//! # Parameters
//!
//! Memory is `128 * r * N` bytes. [`ScryptParams::RECOMMENDED`] is the IETF
//! guidance's minimum, `N = 2^17`, `r = 8`, `p = 1`: 128 MiB.

use alloc::vec::Vec;

use ic_core::{ensure, Result, Zeroize};
use ic_mac::HmacSha256;

/// scrypt's cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScryptParams {
    /// `log2(N)`: the table holds `2^log_n` blocks. 1 to 63.
    pub log_n: u8,
    /// The block size factor: a block is `128 * r` bytes.
    pub r: u32,
    /// Parallelization: how many independent `ROMix` runs.
    pub p: u32,
}

impl ScryptParams {
    /// `N = 2^17`, `r = 8`, `p = 1`: the minimum the IETF password-storage
    /// guidance gives, 128 MiB.
    pub const RECOMMENDED: ScryptParams = ScryptParams {
        log_n: 17,
        r: 8,
        p: 1,
    };

    /// The limits RFC 7914 section 2 sets: `N` a power of two above one and
    /// below `2^(128 * r / 8)`, and `r * p < 2^30`.
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.log_n >= 1 && self.log_n < 64,
            InvalidParameter,
            "scrypt N must be 2^1 to 2^63"
        );
        ensure!(
            self.r >= 1 && self.p >= 1,
            InvalidParameter,
            "scrypt r and p must be at least 1"
        );
        ensure!(
            u64::from(self.log_n) < 16 * u64::from(self.r),
            InvalidParameter,
            "scrypt N must be below 2^(16 r)"
        );
        ensure!(
            u64::from(self.r) * u64::from(self.p) < 1 << 30,
            InvalidParameter,
            "scrypt r * p must be below 2^30"
        );
        Ok(())
    }

    /// Bytes of memory a run takes: `128 * r * N`.
    pub fn memory_bytes(&self) -> Option<u64> {
        128u64
            .checked_mul(u64::from(self.r))?
            .checked_mul(1u64.checked_shl(u32::from(self.log_n))?)
    }
}

/// Derive `out.len()` bytes from `password` and `salt`.
///
/// No floor is applied to the salt: RFC 7914's own vectors use an empty one.
/// For password storage use 16 random bytes, as [`phc::hash_password`]
/// does.
pub fn scrypt(password: &[u8], salt: &[u8], params: &ScryptParams, out: &mut [u8]) -> Result<()> {
    ic_core::module::operational()?;
    params.validate()?;
    ensure!(
        !out.is_empty() && (out.len() as u64) <= (u64::from(u32::MAX) * 32),
        InvalidLength,
        "scrypt output length"
    );
    let r = params.r as usize;
    let p = params.p as usize;
    let block_words = 32 * r;
    let n = 1usize
        .checked_shl(u32::from(params.log_n))
        .filter(|n| *n > 1)
        .ok_or(ic_core::err!(
            InvalidParameter,
            "scrypt N too large for this platform"
        ))?;
    let table_words = n
        .checked_mul(block_words)
        .ok_or(ic_core::err!(InvalidParameter, "scrypt memory too large"))?;
    let b_len = p
        .checked_mul(128 * r)
        .ok_or(ic_core::err!(InvalidParameter, "scrypt p * r too large"))?;

    // As for Argon2: the size can come from a stored hash, so a failed
    // allocation is an error, and the table is allocated zeroed so that the
    // operating system supplies it lazily.
    let mut probe: Vec<u32> = Vec::new();
    probe
        .try_reserve_exact(table_words)
        .map_err(|_| ic_core::err!(InvalidParameter, "scrypt memory: allocation failed"))?;
    drop(probe);
    let mut v: Vec<u32> = alloc::vec![0u32; table_words];

    let mut b = alloc::vec![0u8; b_len];
    crate::pbkdf2::derive::<HmacSha256>(password, salt, 1, &mut b)?;

    let mut x = alloc::vec![0u32; block_words];
    let mut y = alloc::vec![0u32; block_words];
    for chunk in b.chunks_exact_mut(128 * r) {
        for (w, bytes) in x.iter_mut().zip(chunk.chunks_exact(4)) {
            *w = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        }
        ro_mix(&mut x, &mut y, &mut v, n, r);
        for (bytes, w) in chunk.chunks_exact_mut(4).zip(x.iter()) {
            bytes.copy_from_slice(&w.to_le_bytes());
        }
    }

    let result = crate::pbkdf2::derive::<HmacSha256>(password, &b, 1, out);
    b.zeroize();
    x.zeroize();
    y.zeroize();
    v.zeroize();
    result
}

/// RFC 7914 section 5, `scryptROMix`, on `x` in place; `y` is scratch the
/// size of a block and `v` the table.
fn ro_mix(x: &mut [u32], y: &mut [u32], v: &mut [u32], n: usize, r: usize) {
    let block_words = 32 * r;
    for i in 0..n {
        v[i * block_words..(i + 1) * block_words].copy_from_slice(x);
        block_mix(x, y, r);
    }
    for _ in 0..n {
        // Integerify: the first word of the last 64-byte block, as a little-
        // endian integer, modulo N. N is a power of two, so the mask is the
        // modulo, and N fits in a usize, so the low 64 bits are enough.
        let last = (2 * r - 1) * 16;
        let j = ((u64::from(x[last + 1]) << 32 | u64::from(x[last])) as usize) & (n - 1);
        for (a, b) in x.iter_mut().zip(&v[j * block_words..(j + 1) * block_words]) {
            *a ^= b;
        }
        block_mix(x, y, r);
    }
}

/// RFC 7914 section 4, `scryptBlockMix`, on `b` in place.
fn block_mix(b: &mut [u32], y: &mut [u32], r: usize) {
    let mut x = [0u32; 16];
    x.copy_from_slice(&b[(2 * r - 1) * 16..2 * r * 16]);
    for i in 0..2 * r {
        for (xi, bi) in x.iter_mut().zip(&b[i * 16..(i + 1) * 16]) {
            *xi ^= bi;
        }
        salsa20_8(&mut x);
        // Even-numbered outputs to the first half, odd to the second.
        let to = (i / 2 + (i % 2) * r) * 16;
        y[to..to + 16].copy_from_slice(&x);
    }
    b.copy_from_slice(y);
    x.zeroize();
}

/// RFC 7914 section 3: Salsa20 reduced to eight rounds, with the input
/// added back.
fn salsa20_8(b: &mut [u32; 16]) {
    let mut x = *b;
    for _ in 0..4 {
        // Columns.
        x[4] ^= x[0].wrapping_add(x[12]).rotate_left(7);
        x[8] ^= x[4].wrapping_add(x[0]).rotate_left(9);
        x[12] ^= x[8].wrapping_add(x[4]).rotate_left(13);
        x[0] ^= x[12].wrapping_add(x[8]).rotate_left(18);
        x[9] ^= x[5].wrapping_add(x[1]).rotate_left(7);
        x[13] ^= x[9].wrapping_add(x[5]).rotate_left(9);
        x[1] ^= x[13].wrapping_add(x[9]).rotate_left(13);
        x[5] ^= x[1].wrapping_add(x[13]).rotate_left(18);
        x[14] ^= x[10].wrapping_add(x[6]).rotate_left(7);
        x[2] ^= x[14].wrapping_add(x[10]).rotate_left(9);
        x[6] ^= x[2].wrapping_add(x[14]).rotate_left(13);
        x[10] ^= x[6].wrapping_add(x[2]).rotate_left(18);
        x[3] ^= x[15].wrapping_add(x[11]).rotate_left(7);
        x[7] ^= x[3].wrapping_add(x[15]).rotate_left(9);
        x[11] ^= x[7].wrapping_add(x[3]).rotate_left(13);
        x[15] ^= x[11].wrapping_add(x[7]).rotate_left(18);
        // Rows.
        x[1] ^= x[0].wrapping_add(x[3]).rotate_left(7);
        x[2] ^= x[1].wrapping_add(x[0]).rotate_left(9);
        x[3] ^= x[2].wrapping_add(x[1]).rotate_left(13);
        x[0] ^= x[3].wrapping_add(x[2]).rotate_left(18);
        x[6] ^= x[5].wrapping_add(x[4]).rotate_left(7);
        x[7] ^= x[6].wrapping_add(x[5]).rotate_left(9);
        x[4] ^= x[7].wrapping_add(x[6]).rotate_left(13);
        x[5] ^= x[4].wrapping_add(x[7]).rotate_left(18);
        x[11] ^= x[10].wrapping_add(x[9]).rotate_left(7);
        x[8] ^= x[11].wrapping_add(x[10]).rotate_left(9);
        x[9] ^= x[8].wrapping_add(x[11]).rotate_left(13);
        x[10] ^= x[9].wrapping_add(x[8]).rotate_left(18);
        x[12] ^= x[15].wrapping_add(x[14]).rotate_left(7);
        x[13] ^= x[12].wrapping_add(x[15]).rotate_left(9);
        x[14] ^= x[13].wrapping_add(x[12]).rotate_left(13);
        x[15] ^= x[14].wrapping_add(x[13]).rotate_left(18);
    }
    for (bi, xi) in b.iter_mut().zip(x.iter()) {
        *bi = bi.wrapping_add(*xi);
    }
    x.zeroize();
}

/// The known-answer test: RFC 7914 section 12's first vector, the only one
/// small enough to run at start-up.
pub fn self_test() -> Result<()> {
    let mut got = [0u8; 64];
    scrypt(
        b"",
        b"",
        &ScryptParams {
            log_n: 4,
            r: 1,
            p: 1,
        },
        &mut got,
    )?;
    let mut want = [0u8; 64];
    ic_core::codec::hex_decode(
        b"77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442\
          fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906",
        &mut want,
    )?;
    ensure!(ic_core::ct::verify(&want, &got), SelfTestFailed, "scrypt");
    Ok(())
}

pub mod phc;

#[cfg(test)]
mod tests {
    use super::*;

    fn spaced_hex(s: &str) -> Vec<u8> {
        let s: alloc::string::String = s.split_whitespace().collect();
        let mut out = alloc::vec![0u8; s.len() / 2];
        ic_core::codec::hex_decode(s.as_bytes(), &mut out).unwrap();
        out
    }

    /// RFC 7914 section 8.
    #[test]
    fn salsa20_8_core_matches_the_rfc() {
        let input = spaced_hex(
            "7e 87 9a 21 4f 3e c9 86 7c a9 40 e6 41 71 8f 26
             ba ee 55 5b 8c 61 c1 b5 0d f8 46 11 6d cd 3b 1d
             ee 24 f3 19 df 9b 3d 85 14 12 1e 4b 5a c5 aa 32
             76 02 1d 29 09 c7 48 29 ed eb c6 8d b8 b8 c2 5e",
        );
        let want = spaced_hex(
            "a4 1f 85 9c 66 08 cc 99 3b 81 ca cb 02 0c ef 05
             04 4b 21 81 a2 fd 33 7d fd 7b 1c 63 96 68 2f 29
             b4 39 31 68 e3 c9 e6 bc fe 6b c5 b7 a0 6d 96 ba
             e4 24 cc 10 2c 91 74 5c 24 ad 67 3d c7 61 8f 81",
        );
        let mut b = [0u32; 16];
        for (w, c) in b.iter_mut().zip(input.chunks_exact(4)) {
            *w = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        }
        salsa20_8(&mut b);
        let got: Vec<u8> = b.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(got, want);
    }

    /// RFC 7914 section 12, the three vectors under 1 GiB. The fourth, at
    /// N = 2^20, is in `ironcrypto/tests/scrypt.rs`, which runs it in a
    /// build where it takes a second rather than minutes.
    #[test]
    fn scrypt_matches_the_rfc() {
        /// Password, salt, log2(N), r, p, and the output as the RFC prints it.
        type Case<'a> = (&'a [u8], &'a [u8], u8, u32, u32, &'a str);
        let cases: [Case; 3] = [
            (
                b"",
                b"",
                4,
                1,
                1,
                "77 d6 57 62 38 65 7b 20 3b 19 ca 42 c1 8a 04 97
                f1 6b 48 44 e3 07 4a e8 df df fa 3f ed e2 14 42
                fc d0 06 9d ed 09 48 f8 32 6a 75 3a 0f c8 1f 17
                e8 d3 e0 fb 2e 0d 36 28 cf 35 e2 0c 38 d1 89 06",
            ),
            (
                b"password",
                b"NaCl",
                10,
                8,
                16,
                "fd ba be 1c 9d 34 72 00 78 56 e7 19 0d 01 e9 fe
                7c 6a d7 cb c8 23 78 30 e7 73 76 63 4b 37 31 62
                2e af 30 d9 2e 22 a3 88 6f f1 09 27 9d 98 30 da
                c7 27 af b9 4a 83 ee 6d 83 60 cb df a2 cc 06 40",
            ),
            (
                b"pleaseletmein",
                b"SodiumChloride",
                14,
                8,
                1,
                "70 23 bd cb 3a fd 73 48 46 1c 06 cd 81 fd 38 eb
                fd a8 fb ba 90 4f 8e 3e a9 b5 43 f6 54 5d a1 f2
                d5 43 29 55 61 3f 0f cf 62 d4 97 05 24 2a 9a f9
                e6 1e 85 dc 0d 65 1e 40 df cf 01 7b 45 57 58 87",
            ),
        ];
        for (pw, salt, log_n, r, p, want) in cases {
            let mut out = [0u8; 64];
            scrypt(pw, salt, &ScryptParams { log_n, r, p }, &mut out).unwrap();
            assert_eq!(out.to_vec(), spaced_hex(want), "N=2^{log_n} r={r} p={p}");
        }
    }

    #[test]
    fn rfc_limits_are_enforced() {
        let bad = [
            ScryptParams {
                log_n: 0,
                r: 1,
                p: 1,
            },
            ScryptParams {
                log_n: 16,
                r: 1,
                p: 1,
            }, // N must be below 2^(16 r)
            ScryptParams {
                log_n: 4,
                r: 0,
                p: 1,
            },
            ScryptParams {
                log_n: 4,
                r: 1,
                p: 0,
            },
            ScryptParams {
                log_n: 4,
                r: 1 << 15,
                p: 1 << 15,
            },
        ];
        for p in bad {
            assert!(scrypt(b"pw", b"salt", &p, &mut [0u8; 32]).is_err(), "{p:?}");
        }
        assert_eq!(ScryptParams::RECOMMENDED.memory_bytes(), Some(128 << 20));
    }

    #[test]
    fn the_self_test_passes() {
        self_test().unwrap();
    }
}
