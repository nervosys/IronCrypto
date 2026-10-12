//! yescrypt, verification only: for moving `/etc/shadow`-style hashes to
//! Argon2id.
//!
//! yescrypt is the default password hash of current Debian, Ubuntu and
//! Fedora, written `$y$j9T$<salt>$<hash>` by libxcrypt's crypt(3). This
//! checks a password against such a string, or against the older `$7$`
//! scrypt form, so that the hash can be replaced at the next login:
//!
//! ```no_run
//! use ic_kdf::yescrypt;
//! # let stored = "";
//! yescrypt::verify_password(b"password", stored)?;
//! // ... and now hash the password with Argon2id and store that instead.
//! # Ok::<(), ic_core::Error>(())
//! ```
//!
//! It does not make new yescrypt hashes; this library offers Argon2id.
//!
//! # A transcription, and of what
//!
//! This follows Openwall's reference implementation, `yescrypt-ref.c` and
//! `yescrypt-common.c`, step for step, including its word shuffling, so that
//! the two can be read side by side. Supported: the default flavor (`j`,
//! YESCRYPT_RW with the 12 KiB S-box pwxform), YESCRYPT_WORM, classic scrypt
//! in `$y$` form, the `t` and `p` parameters, and `$7$`. Not supported, and
//! refused as `Unsupported`: a ROM (`NROM`), hash upgrades (`g`), and any
//! other flavor -- none of which libxcrypt writes. Checked against libxcrypt
//! itself, the crypt(3) these hashes come from.
//!
//! # Table lookups depend on the password
//!
//! pwxform reads its S-boxes, and `SMix` its memory, at indices derived from
//! the password, by design: it is what makes yescrypt hard for GPUs. A
//! process sharing this machine's cache learns something about the access
//! pattern. That is why this is offered for one verification on the way to
//! Argon2id, not as a hash to keep.

use alloc::vec::Vec;

use ic_core::traits::{Digest, Mac};
use ic_core::{ensure, Result, Zeroize};
use ic_hash::Sha256;
use ic_mac::HmacSha256;

const ITOA64: &[u8; 64] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

const YESCRYPT_WORM: u32 = 1;
const YESCRYPT_RW: u32 = 0x002;
const YESCRYPT_RW_FLAVOR_MASK: u32 = 0x3fc;
/// RW with 6 rounds, gather 4, simple 2 and the 12 KiB S-box: the only RW
/// flavor the reference implements, and what `j` encodes.
const YESCRYPT_RW_DEFAULT_FLAVOR: u32 = 0x004 | 0x010 | 0x020 | 0x080;
const YESCRYPT_PREHASH: u32 = 0x1000_0000;

const PWX_SIMPLE: usize = 2;
const PWX_GATHER: usize = 4;
const PWX_ROUNDS: usize = 6;
const S_WIDTH: usize = 8;
const PWX_BYTES: usize = PWX_GATHER * PWX_SIMPLE * 8;
const PWX_WORDS: usize = PWX_BYTES / 4;
const S_BYTES: usize = 3 * (1 << S_WIDTH) * PWX_SIMPLE * 8;
const S_WORDS: usize = S_BYTES / 4;
const S_MASK: u32 = (((1 << S_WIDTH) - 1) * PWX_SIMPLE * 8) as u32;
/// Pairs of words in one of S0, S1, S2.
const S_PAIRS: usize = (1 << S_WIDTH) * PWX_SIMPLE;

/// The most memory [`verify_password`] will use for a hash: 4 GiB.
pub const DEFAULT_MAX_MEMORY: u64 = 4 << 30;

/// salsa20(B, rounds), with the reference's SIMD shuffle.
fn salsa20(b: &mut [u32], rounds: u32) {
    let mut x = [0u32; 16];
    for i in 0..16 {
        x[i * 5 % 16] = b[i];
    }
    let mut i = 0;
    while i < rounds {
        macro_rules! r {
            ($a:expr, $n:expr) => {
                $a.rotate_left($n)
            };
        }
        x[4] ^= r!(x[0].wrapping_add(x[12]), 7);
        x[8] ^= r!(x[4].wrapping_add(x[0]), 9);
        x[12] ^= r!(x[8].wrapping_add(x[4]), 13);
        x[0] ^= r!(x[12].wrapping_add(x[8]), 18);
        x[9] ^= r!(x[5].wrapping_add(x[1]), 7);
        x[13] ^= r!(x[9].wrapping_add(x[5]), 9);
        x[1] ^= r!(x[13].wrapping_add(x[9]), 13);
        x[5] ^= r!(x[1].wrapping_add(x[13]), 18);
        x[14] ^= r!(x[10].wrapping_add(x[6]), 7);
        x[2] ^= r!(x[14].wrapping_add(x[10]), 9);
        x[6] ^= r!(x[2].wrapping_add(x[14]), 13);
        x[10] ^= r!(x[6].wrapping_add(x[2]), 18);
        x[3] ^= r!(x[15].wrapping_add(x[11]), 7);
        x[7] ^= r!(x[3].wrapping_add(x[15]), 9);
        x[11] ^= r!(x[7].wrapping_add(x[3]), 13);
        x[15] ^= r!(x[11].wrapping_add(x[7]), 18);
        x[1] ^= r!(x[0].wrapping_add(x[3]), 7);
        x[2] ^= r!(x[1].wrapping_add(x[0]), 9);
        x[3] ^= r!(x[2].wrapping_add(x[1]), 13);
        x[0] ^= r!(x[3].wrapping_add(x[2]), 18);
        x[6] ^= r!(x[5].wrapping_add(x[4]), 7);
        x[7] ^= r!(x[6].wrapping_add(x[5]), 9);
        x[4] ^= r!(x[7].wrapping_add(x[6]), 13);
        x[5] ^= r!(x[4].wrapping_add(x[7]), 18);
        x[11] ^= r!(x[10].wrapping_add(x[9]), 7);
        x[8] ^= r!(x[11].wrapping_add(x[10]), 9);
        x[9] ^= r!(x[8].wrapping_add(x[11]), 13);
        x[10] ^= r!(x[9].wrapping_add(x[8]), 18);
        x[12] ^= r!(x[15].wrapping_add(x[14]), 7);
        x[13] ^= r!(x[12].wrapping_add(x[15]), 9);
        x[14] ^= r!(x[13].wrapping_add(x[12]), 13);
        x[15] ^= r!(x[14].wrapping_add(x[13]), 18);
        i += 2;
    }
    for i in 0..16 {
        b[i] = b[i].wrapping_add(x[i * 5 % 16]);
    }
    x.zeroize();
}

fn xor_into(dst: &mut [u32], src: &[u32]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= s;
    }
}

/// blockmix_salsa8(B, Y, r).
fn blockmix_salsa8(b: &mut [u32], y: &mut [u32], r: usize) {
    let mut x = [0u32; 16];
    x.copy_from_slice(&b[(2 * r - 1) * 16..2 * r * 16]);
    for i in 0..2 * r {
        xor_into(&mut x, &b[i * 16..(i + 1) * 16]);
        salsa20(&mut x, 8);
        y[i * 16..(i + 1) * 16].copy_from_slice(&x);
    }
    for i in 0..r {
        b[i * 16..(i + 1) * 16].copy_from_slice(&y[(i * 2) * 16..(i * 2 + 1) * 16]);
    }
    for i in 0..r {
        b[(i + r) * 16..(i + r + 1) * 16].copy_from_slice(&y[(i * 2 + 1) * 16..(i * 2 + 2) * 16]);
    }
    x.zeroize();
}

/// The pwxform context: S0, S1 and S2 as pair offsets into `S`, and `w`.
struct Pwx<'a> {
    s: &'a mut [u32],
    s0: usize,
    s1: usize,
    s2: usize,
    w: usize,
}

impl Pwx<'_> {
    fn pair(&self, base: usize, index: usize) -> (u32, u32) {
        let at = (base + index) * 2;
        (self.s[at], self.s[at + 1])
    }

    /// pwxform(B, ctx) on one 16-word block.
    fn pwxform(&mut self, x: &mut [u32]) {
        for i in 0..PWX_ROUNDS {
            for j in 0..PWX_GATHER {
                let xl = x[(j * PWX_SIMPLE) * 2];
                let xh = x[(j * PWX_SIMPLE) * 2 + 1];
                let p0 = ((xl & S_MASK) / 8) as usize;
                let p1 = ((xh & S_MASK) / 8) as usize;
                for k in 0..PWX_SIMPLE {
                    let (a0, b0) = self.pair(self.s0, p0 + k);
                    let (a1, b1) = self.pair(self.s1, p1 + k);
                    let s0 = (u64::from(b0) << 32) + u64::from(a0);
                    let s1 = (u64::from(b1) << 32) + u64::from(a1);
                    let at = (j * PWX_SIMPLE + k) * 2;
                    let (xl, xh) = (x[at], x[at + 1]);
                    let v = (u64::from(xh) * u64::from(xl)).wrapping_add(s0) ^ s1;
                    x[at] = v as u32;
                    x[at + 1] = (v >> 32) as u32;
                    if i != 0 && i != PWX_ROUNDS - 1 {
                        let w = (self.s2 + self.w) * 2;
                        self.s[w] = v as u32;
                        self.s[w + 1] = (v >> 32) as u32;
                        self.w += 1;
                    }
                }
            }
        }
        let (s0, s1, s2) = (self.s0, self.s1, self.s2);
        self.s0 = s2;
        self.s1 = s0;
        self.s2 = s1;
        self.w &= S_PAIRS - 1;
    }
}

/// blockmix_pwxform(B, ctx, r).
fn blockmix_pwxform(b: &mut [u32], ctx: &mut Pwx, r: usize) {
    let r1 = 128 * r / PWX_BYTES;
    let mut x = [0u32; PWX_WORDS];
    x.copy_from_slice(&b[(r1 - 1) * PWX_WORDS..r1 * PWX_WORDS]);
    for i in 0..r1 {
        if r1 > 1 {
            xor_into(&mut x, &b[i * PWX_WORDS..(i + 1) * PWX_WORDS]);
        }
        ctx.pwxform(&mut x);
        b[i * PWX_WORDS..(i + 1) * PWX_WORDS].copy_from_slice(&x);
    }
    let mut i = (r1 - 1) * PWX_BYTES / 64;
    salsa20(&mut b[i * 16..(i + 1) * 16], 2);
    i += 1;
    while i < 2 * r {
        let (head, tail) = b.split_at_mut(i * 16);
        xor_into(&mut tail[..16], &head[(i - 1) * 16..]);
        salsa20(&mut tail[..16], 2);
        i += 1;
    }
    x.zeroize();
}

fn integerify(b: &[u32], r: usize) -> u64 {
    let x = &b[(2 * r - 1) * 16..];
    (u64::from(x[13]) << 32) + u64::from(x[0])
}

fn p2floor(mut x: u64) -> u64 {
    loop {
        let y = x & (x - 1);
        if y == 0 {
            return x;
        }
        x = y;
    }
}

fn wrap(x: u64, i: u64) -> u64 {
    let n = p2floor(i);
    (x & (n - 1)) + (i - n)
}

/// `X <-- H(X)`, by pwxform when there is a context and Salsa20/8 otherwise.
fn mix(x: &mut [u32], y: &mut [u32], ctx: &mut Option<&mut Pwx>, r: usize) {
    match ctx {
        Some(c) => blockmix_pwxform(x, c, r),
        None => blockmix_salsa8(x, y, r),
    }
}

#[allow(clippy::too_many_arguments)]
fn smix1(
    b: &mut [u32],
    r: usize,
    n: u64,
    flags: u32,
    v: &mut [u32],
    xy: &mut [u32],
    mut ctx: Option<&mut Pwx>,
) {
    let s = 32 * r;
    let (x, y) = xy.split_at_mut(s);
    for k in 0..2 * r {
        for i in 0..16 {
            x[k * 16 + i] = b[k * 16 + (i * 5 % 16)];
        }
    }
    for i in 0..n {
        let iu = i as usize;
        v[iu * s..(iu + 1) * s].copy_from_slice(x);
        if flags & YESCRYPT_RW != 0 && i > 1 {
            let j = wrap(integerify(x, r), i) as usize;
            xor_into(x, &v[j * s..(j + 1) * s]);
        }
        mix(x, y, &mut ctx, r);
    }
    for k in 0..2 * r {
        for i in 0..16 {
            b[k * 16 + (i * 5 % 16)] = x[k * 16 + i];
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn smix2(
    b: &mut [u32],
    r: usize,
    n: u64,
    nloop: u64,
    flags: u32,
    v: &mut [u32],
    xy: &mut [u32],
    mut ctx: Option<&mut Pwx>,
) {
    let s = 32 * r;
    let (x, y) = xy.split_at_mut(s);
    for k in 0..2 * r {
        for i in 0..16 {
            x[k * 16 + i] = b[k * 16 + (i * 5 % 16)];
        }
    }
    for _ in 0..nloop {
        let j = (integerify(x, r) & (n - 1)) as usize;
        xor_into(x, &v[j * s..(j + 1) * s]);
        if flags & YESCRYPT_RW != 0 {
            v[j * s..(j + 1) * s].copy_from_slice(x);
        }
        mix(x, y, &mut ctx, r);
    }
    for k in 0..2 * r {
        for i in 0..16 {
            b[k * 16 + (i * 5 % 16)] = x[k * 16 + i];
        }
    }
}

fn hmac(key: &[u8], msg: &[u8]) -> Result<[u8; 32]> {
    let mut m = HmacSha256::new(key)?;
    m.update(msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(m.finalize().as_ref());
    Ok(out)
}

fn words_to_bytes(words: &[u32], out: &mut [u8]) {
    for (c, w) in out.chunks_exact_mut(4).zip(words) {
        c.copy_from_slice(&w.to_le_bytes());
    }
}

/// smix(B, r, N, p, t, flags, V, XY, S, passwd).
#[allow(clippy::too_many_arguments)]
fn smix(
    b: &mut [u32],
    r: usize,
    n: u64,
    p: u32,
    t: u32,
    flags: u32,
    v: &mut [u32],
    xy: &mut [u32],
    s_all: &mut [u32],
    passwd: &mut [u8; 32],
) -> Result<()> {
    let s = 32 * r;
    let mut nchunk = n / u64::from(p);
    let mut nloop_all = nchunk;
    if flags & YESCRYPT_RW != 0 {
        if t <= 1 {
            if t != 0 {
                nloop_all *= 2;
            }
            nloop_all = nloop_all.div_ceil(3);
        } else {
            nloop_all *= u64::from(t - 1);
        }
    } else if t != 0 {
        if t == 1 {
            nloop_all += nloop_all.div_ceil(2);
        }
        nloop_all *= u64::from(t);
    }
    let mut nloop_rw = 0;
    if flags & YESCRYPT_RW != 0 {
        nloop_rw = nloop_all / u64::from(p);
    }
    nchunk &= !1;
    nloop_all = (nloop_all + 1) & !1;
    nloop_rw = (nloop_rw + 1) & !1;

    let mut contexts: Vec<(usize, usize, usize, usize)> = Vec::new();
    let mut vchunk = 0u64;
    for i in 0..p as usize {
        let np = if (i as u32) < p - 1 {
            nchunk
        } else {
            n - vchunk
        };
        let bp = &mut b[i * s..(i + 1) * s];
        let vp = &mut v[vchunk as usize * s..];
        if flags & YESCRYPT_RW != 0 {
            let sbox = &mut s_all[i * S_WORDS..(i + 1) * S_WORDS];
            smix1(bp, 1, (S_BYTES / 128) as u64, 0, sbox, xy, None);
            let mut ctx = Pwx {
                s: sbox,
                s2: 0,
                s1: S_PAIRS,
                s0: 2 * S_PAIRS,
                w: 0,
            };
            if i == 0 {
                let mut key = [0u8; 64];
                words_to_bytes(&bp[s - 16..], &mut key);
                *passwd = hmac(&key, passwd)?;
                key.zeroize();
            }
            smix1(bp, r, np, flags, vp, xy, Some(&mut ctx));
            smix2(bp, r, p2floor(np), nloop_rw, flags, vp, xy, Some(&mut ctx));
            contexts.push((ctx.s0, ctx.s1, ctx.s2, ctx.w));
        } else {
            smix1(bp, r, np, flags, vp, xy, None);
            smix2(bp, r, p2floor(np), nloop_rw, flags, vp, xy, None);
        }
        vchunk += nchunk;
    }
    for i in 0..p as usize {
        let bp = &mut b[i * s..(i + 1) * s];
        if flags & YESCRYPT_RW != 0 {
            let (s0, s1, s2, w) = contexts[i];
            let mut ctx = Pwx {
                s: &mut s_all[i * S_WORDS..(i + 1) * S_WORDS],
                s0,
                s1,
                s2,
                w,
            };
            smix2(
                bp,
                r,
                n,
                nloop_all - nloop_rw,
                flags & !YESCRYPT_RW,
                v,
                xy,
                Some(&mut ctx),
            );
        } else {
            smix2(bp, r, n, nloop_all - nloop_rw, flags, v, xy, None);
        }
    }
    Ok(())
}

/// The allocation a run needs, as words: `V`, `B`, `XY` and the S-boxes.
fn alloc_words(words: usize) -> Result<Vec<u32>> {
    let mut probe: Vec<u32> = Vec::new();
    probe
        .try_reserve_exact(words)
        .map_err(|_| ic_core::err!(InvalidParameter, "yescrypt memory: allocation failed"))?;
    drop(probe);
    Ok(alloc::vec![0u32; words])
}

/// yescrypt_kdf_body, for a 32-byte output.
#[allow(clippy::too_many_arguments)]
fn kdf_body(
    passwd: &[u8],
    salt: &[u8],
    flags: u32,
    n: u64,
    r: u32,
    p: u32,
    t: u32,
    out: &mut [u8; 32],
) -> Result<()> {
    // Checked throughout: a caller's ceiling may be above what a 32-bit
    // target can address.
    let too_large = || ic_core::err!(InvalidParameter, "yescrypt memory too large");
    let ru = r as usize;
    let block_words = 32usize.checked_mul(ru).ok_or_else(too_large)?;
    let v_words = usize::try_from(n)
        .ok()
        .and_then(|n| n.checked_mul(block_words))
        .ok_or_else(too_large)?;
    let b_words = block_words.checked_mul(p as usize).ok_or_else(too_large)?;
    let b_len = b_words.checked_mul(4).ok_or_else(too_large)?;
    let mut v = alloc_words(v_words)?;
    let mut b = alloc_words(b_words)?;
    let mut xy = alloc_words(block_words.checked_mul(2).ok_or_else(too_large)?)?;
    let mut s = if flags & YESCRYPT_RW != 0 {
        alloc_words(S_WORDS.checked_mul(p as usize).ok_or_else(too_large)?)?
    } else {
        Vec::new()
    };

    let mut prehashed = [0u8; 32];
    let passwd: &[u8] = if flags != 0 {
        let key: &[u8] = if flags & YESCRYPT_PREHASH != 0 {
            b"yescrypt-prehash"
        } else {
            b"yescrypt"
        };
        prehashed = hmac(key, passwd)?;
        &prehashed
    } else {
        passwd
    };
    let mut b_bytes = alloc::vec![0u8; b_len];
    crate::pbkdf2::derive::<HmacSha256>(passwd, salt, 1, &mut b_bytes)?;
    for (w, c) in b.iter_mut().zip(b_bytes.chunks_exact(4)) {
        *w = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
    }
    let mut sha256 = [0u8; 32];
    if flags != 0 {
        sha256.copy_from_slice(&b_bytes[..32]);
    }

    if flags & YESCRYPT_RW != 0 {
        smix(
            &mut b,
            ru,
            n,
            p,
            t,
            flags,
            &mut v,
            &mut xy,
            &mut s,
            &mut sha256,
        )?;
    } else {
        for i in 0..p as usize {
            let mut none: [u32; 0] = [];
            let mut unused = [0u8; 32];
            smix(
                &mut b[32 * ru * i..32 * ru * (i + 1)],
                ru,
                n,
                1,
                t,
                flags,
                &mut v,
                &mut xy,
                &mut none,
                &mut unused,
            )?;
        }
    }
    words_to_bytes(&b, &mut b_bytes);
    // After the RW smix the "password" is the HMAC chain it updated.
    let final_passwd: &[u8] = if flags != 0 { &sha256 } else { passwd };
    crate::pbkdf2::derive::<HmacSha256>(final_passwd, &b_bytes, 1, out)?;
    if flags != 0 && flags & YESCRYPT_PREHASH == 0 {
        let client_key = hmac(out, b"Client Key")?;
        let mut h = Sha256::new();
        h.update(&client_key);
        out.copy_from_slice(h.finalize().as_ref());
    }
    for x in [&mut v, &mut b, &mut xy, &mut s] {
        x.zeroize();
    }
    b_bytes.zeroize();
    sha256.zeroize();
    prehashed.zeroize();
    Ok(())
}

/// Parameters a hash string names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// The flags the flavor decodes to: 0 for classic scrypt.
    pub flags: u32,
    /// `N`, a power of two.
    pub n: u64,
    /// The block size factor.
    pub r: u32,
    /// Parallelism.
    pub p: u32,
    /// The time factor.
    pub t: u32,
}

impl Params {
    /// Bytes of memory verifying takes: `V` at `128 * r * N`, `B` at
    /// `128 * r * p`, and the S-boxes.
    pub fn memory_bytes(&self) -> Option<u64> {
        let block = 128u64.checked_mul(u64::from(self.r))?;
        let v = block.checked_mul(self.n)?;
        let b = block.checked_mul(u64::from(self.p))?;
        let s = if self.flags & YESCRYPT_RW != 0 {
            (S_BYTES as u64).checked_mul(u64::from(self.p))?
        } else {
            0
        };
        v.checked_add(b)?.checked_add(s)
    }

    /// Bytes passed through memory, a bound on the time verifying takes:
    /// `V` once per unit of `t + 1`, and once per lane where the lanes run in
    /// turn, as they do outside the read-write flavor.
    pub fn work_bytes(&self) -> Option<u64> {
        let v = 128u64.checked_mul(u64::from(self.r))?.checked_mul(self.n)?;
        let passes = u64::from(self.t) + 1;
        let lanes = if self.flags & YESCRYPT_RW != 0 {
            1
        } else {
            u64::from(self.p)
        };
        v.checked_mul(passes)?.checked_mul(lanes)
    }
}

/// How many times its memory ceiling a hash may pass through memory before
/// [`verify_password_bounded`] refuses it: what keeps a large `t`, or many
/// `$7$` lanes over a small `N`, from running for hours inside the ceiling.
pub const MAX_PASSES: u64 = 8;

fn atoi64(c: u8) -> Option<u32> {
    ITOA64.iter().position(|&a| a == c).map(|v| v as u32)
}

/// yescrypt-common.c's decode64_uint32: a variable-length integer.
fn decode_u32(src: &[u8], at: &mut usize, min: u32) -> Result<u32> {
    let bad = || ic_core::err!(MalformedEncoding, "yescrypt: parameter encoding");
    let mut c = atoi64(*src.get(*at).ok_or_else(bad)?).ok_or_else(bad)?;
    *at += 1;
    let (mut start, mut end, mut chars, mut bits) = (0u32, 47u32, 1u32, 0u32);
    let mut dst = u64::from(min);
    while c > end {
        dst += u64::from(end + 1 - start) << bits;
        start = end + 1;
        end = start + (62 - end) / 2;
        chars += 1;
        bits += 6;
    }
    dst += u64::from(c - start) << bits;
    while chars > 1 {
        chars -= 1;
        c = atoi64(*src.get(*at).ok_or_else(bad)?).ok_or_else(bad)?;
        *at += 1;
        bits -= 6;
        dst += u64::from(c) << bits;
    }
    u32::try_from(dst).map_err(|_| bad())
}

/// yescrypt-common.c's decode64: bytes, little-endian, refusing extra bits.
fn decode_bytes(src: &[u8], out: &mut Vec<u8>) -> Result<()> {
    let bad = || ic_core::err!(MalformedEncoding, "yescrypt: base64");
    for group in src.chunks(4) {
        let mut value = 0u32;
        let mut bits = 0;
        for &c in group {
            value |= atoi64(c).ok_or_else(bad)? << bits;
            bits += 6;
        }
        ensure!(bits >= 12, MalformedEncoding, "yescrypt: base64 length");
        while bits >= 8 {
            out.push(value as u8);
            value >>= 8;
            bits -= 8;
        }
        ensure!(
            value == 0,
            MalformedEncoding,
            "yescrypt: base64 not canonical"
        );
    }
    Ok(())
}

/// Parse `$y$` or `$7$` into the parameters, the salt as it is used, and the
/// 32-byte hash.
fn parse(hash: &str) -> Result<(Params, Vec<u8>, [u8; 32])> {
    let s = hash.as_bytes();
    ensure!(
        s.len() > 3 && s[0] == b'$' && s[2] == b'$' && (s[1] == b'y' || s[1] == b'7'),
        Unsupported,
        "yescrypt: not a $y$ or $7$ hash"
    );
    let mut at = 3;
    let mut params = Params {
        flags: 0,
        n: 0,
        r: 0,
        p: 1,
        t: 0,
    };
    if s[1] == b'7' {
        let n_log2 = atoi64(*s.get(at).unwrap_or(&0))
            .filter(|n| (1..=63).contains(n))
            .ok_or(ic_core::err!(MalformedEncoding, "yescrypt: $7$ N"))?;
        at += 1;
        params.n = 1 << n_log2;
        let fixed = |at: &mut usize| -> Result<u32> {
            let mut v = 0u32;
            for i in 0..5 {
                let c = atoi64(*s.get(*at).unwrap_or(&0))
                    .ok_or(ic_core::err!(MalformedEncoding, "yescrypt: $7$ field"))?;
                v |= c << (6 * i);
                *at += 1;
            }
            Ok(v)
        };
        params.r = fixed(&mut at)?;
        params.p = fixed(&mut at)?;
    } else {
        let flavor = decode_u32(s, &mut at, 0)?;
        params.flags = if flavor < YESCRYPT_RW {
            flavor
        } else if flavor <= YESCRYPT_RW + (YESCRYPT_RW_FLAVOR_MASK >> 2) {
            YESCRYPT_RW + ((flavor - YESCRYPT_RW) << 2)
        } else {
            return Err(ic_core::err!(Unsupported, "yescrypt: flavor"));
        };
        let n_log2 = decode_u32(s, &mut at, 1)?;
        ensure!(n_log2 <= 63, MalformedEncoding, "yescrypt: N");
        params.n = 1 << n_log2;
        params.r = decode_u32(s, &mut at, 1)?;
        if s.get(at) != Some(&b'$') {
            let have = decode_u32(s, &mut at, 1)?;
            ensure!(
                have & !3 == 0,
                Unsupported,
                "yescrypt: hash upgrades and ROMs"
            );
            if have & 1 != 0 {
                params.p = decode_u32(s, &mut at, 2)?;
            }
            if have & 2 != 0 {
                params.t = decode_u32(s, &mut at, 1)?;
            }
        }
        ensure!(
            s.get(at) == Some(&b'$'),
            MalformedEncoding,
            "yescrypt: parameters"
        );
        at += 1;
    }
    let rest = &s[at..];
    let dollar = rest
        .iter()
        .rposition(|&c| c == b'$')
        .ok_or(ic_core::err!(MalformedEncoding, "yescrypt: no hash"))?;
    let (salt_str, hash_str) = (&rest[..dollar], &rest[dollar + 1..]);
    let salt = if s[1] == b'7' {
        salt_str.to_vec()
    } else {
        let mut v = Vec::new();
        decode_bytes(salt_str, &mut v)?;
        ensure!(v.len() <= 64, MalformedEncoding, "yescrypt: salt too long");
        v
    };
    let mut h = Vec::new();
    decode_bytes(hash_str, &mut h)?;
    let digest: [u8; 32] = h
        .as_slice()
        .try_into()
        .map_err(|_| ic_core::err!(MalformedEncoding, "yescrypt: hash length"))?;
    check(&params)?;
    Ok((params, salt, digest))
}

/// The limits yescrypt_kdf_body enforces, and this module's.
fn check(p: &Params) -> Result<()> {
    let mode = p.flags & 3;
    let supported = match mode {
        0 => p.flags == 0 && p.t == 0,
        1 => p.flags == YESCRYPT_WORM,
        2 => {
            p.flags & YESCRYPT_RW_FLAVOR_MASK == YESCRYPT_RW_DEFAULT_FLAVOR
                && p.flags & !(YESCRYPT_RW | YESCRYPT_RW_FLAVOR_MASK) == 0
        }
        _ => false,
    };
    ensure!(supported, Unsupported, "yescrypt: flavor");
    ensure!(
        p.n > 1 && p.n.is_power_of_two() && p.r >= 1 && p.p >= 1,
        InvalidParameter,
        "yescrypt: N, r or p"
    );
    ensure!(
        u64::from(p.r) * u64::from(p.p) < 1 << 30,
        InvalidParameter,
        "yescrypt: r * p"
    );
    ensure!(
        p.n <= u64::MAX / (u64::from(p.t) + 1),
        InvalidParameter,
        "yescrypt: N * t"
    );
    if p.flags & YESCRYPT_RW != 0 {
        let rmin = PWX_BYTES.div_ceil(128) as u32;
        ensure!(
            p.n / u64::from(p.p) > 1 && p.r >= rmin,
            InvalidParameter,
            "yescrypt: N / p or r too small for pwxform"
        );
    }
    Ok(())
}

/// yescrypt_kdf: the prehash rule, then the body.
fn kdf(passwd: &[u8], salt: &[u8], p: &Params, out: &mut [u8; 32]) -> Result<()> {
    let mut pre = [0u8; 32];
    let passwd: &[u8] = if p.flags & YESCRYPT_RW != 0
        && p.n / u64::from(p.p) >= 0x100
        && p.n / u64::from(p.p) * u64::from(p.r) >= 0x20000
    {
        kdf_body(
            passwd,
            salt,
            p.flags | YESCRYPT_PREHASH,
            p.n >> 6,
            p.r,
            p.p,
            0,
            &mut pre,
        )?;
        &pre
    } else {
        passwd
    };
    let r = kdf_body(passwd, salt, p.flags, p.n, p.r, p.p, p.t, out);
    pre.zeroize();
    r
}

/// The parameters a stored hash names, read without deriving anything.
pub fn params(hash: &str) -> Result<Params> {
    Ok(parse(hash)?.0)
}

/// Whether `password` is the one `hash` was made from; `AuthenticationFailed`
/// if not, compared in constant time. Refuses a hash that would take more
/// than [`DEFAULT_MAX_MEMORY`], or pass through more than [`MAX_PASSES`]
/// times that.
pub fn verify_password(password: &[u8], hash: &str) -> Result<()> {
    verify_password_bounded(password, hash, DEFAULT_MAX_MEMORY)
}

/// [`verify_password`] with a memory ceiling of the caller's, in bytes,
/// checked before anything is allocated. The work ceiling is
/// [`MAX_PASSES`] times it.
pub fn verify_password_bounded(password: &[u8], hash: &str, max_memory: u64) -> Result<()> {
    ic_core::module::operational()?;
    let (params, salt, want) = parse(hash)?;
    ensure!(
        params.memory_bytes().is_some_and(|m| m <= max_memory),
        InvalidParameter,
        "yescrypt: memory above the ceiling"
    );
    ensure!(
        params
            .work_bytes()
            .is_some_and(|w| w <= max_memory.saturating_mul(MAX_PASSES)),
        InvalidParameter,
        "yescrypt: work above the ceiling"
    );
    let mut got = [0u8; 32];
    kdf(password, &salt, &params, &mut got)?;
    let same = ic_core::ct::verify(&got, &want);
    got.zeroize();
    ensure!(same, AuthenticationFailed, "yescrypt password");
    Ok(())
}

/// The known-answer test: the empty password under `$y$j6.`, N = 2^9 and
/// r = 1, a hash libxcrypt made (`testvectors/yescrypt-libxcrypt.json`).
pub fn self_test() -> Result<()> {
    verify_password(
        b"",
        "$y$j6.$k2XAnEHBqQ1Ct2aMXFKNa/$uRt0PX5XBXcPN8OMTEutejPUGqrWS8ZdIuU3wFAenN7",
    )
    .map_err(|_| ic_core::err!(SelfTestFailed, "yescrypt"))
}
