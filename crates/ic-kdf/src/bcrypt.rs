//! bcrypt, verification only: for moving stored hashes to Argon2id.
//!
//! bcrypt is what many existing password databases hold, as strings like
//! `$2b$12$<22-character salt><31-character hash>`. This checks a password
//! against one, so that at the user's next login the hash can be replaced:
//!
//! ```
//! use ic_kdf::bcrypt;
//! let stored = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
//! bcrypt::verify_password(b"U*U", stored)?;
//! // ... and now hash the password with Argon2id and store that instead.
//! # Ok::<(), ic_core::Error>(())
//! ```
//!
//! It does not make new bcrypt hashes. The IETF's password-storage guidance
//! advises against bcrypt for new systems, and this library offers Argon2id.
//!
//! # Table lookups depend on the password
//!
//! Blowfish's S-boxes are indexed by bytes of its state, which derives from
//! the password: an attacker who can watch this process's cache from the same
//! machine learns something about it. That is bcrypt itself, not this
//! implementation, and it is why this is offered for a single verification on
//! the way to Argon2id rather than as a scheme to keep using.
//!
//! # What is accepted
//!
//! `$2a$`, `$2b$` and `$2y$`, which compute the same function for every
//! password under 256 bytes. (`$2a$` hashes from OpenBSD before 2014 wrapped
//! the length of longer passwords; those are not reproduced.) `$2x$`, the
//! marker for crypt_blowfish's sign-extension bug, is refused. Costs 4 to 31.
//! The salt and hash must be in canonical form, with their unused bits zero,
//! as OpenBSD's own comparison of the re-encoded string requires.
//!
//! The password's first 72 bytes are all bcrypt uses; a longer one verifies
//! as its first 72.

mod tables;

use ic_core::{ensure, Result, Zeroize};

const ALPHABET: &[u8; 64] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
/// "OrpheanBeholderScryDoubt", the text bcrypt encrypts.
const CTEXT: [u32; 6] = [
    0x4f72_7068,
    0x6561_6e42,
    0x6568_6f6c,
    0x6465_7253,
    0x6372_7944,
    0x6f75_6274,
];

/// The highest cost accepted.
pub const MAX_COST: u32 = 31;
/// The lowest cost accepted.
pub const MIN_COST: u32 = 4;

struct Blowfish {
    p: [u32; 18],
    s: [[u32; 256]; 4],
}

impl Drop for Blowfish {
    fn drop(&mut self) {
        self.p.zeroize();
        for b in self.s.iter_mut() {
            b.zeroize();
        }
    }
}

impl Blowfish {
    fn new() -> Self {
        Self {
            p: tables::P,
            s: tables::S,
        }
    }

    #[inline(always)]
    fn f(&self, x: u32) -> u32 {
        let [a, b, c, d] = x.to_be_bytes();
        (self.s[0][a as usize].wrapping_add(self.s[1][b as usize]) ^ self.s[2][c as usize])
            .wrapping_add(self.s[3][d as usize])
    }

    fn encrypt(&self, l: &mut u32, r: &mut u32) {
        let (mut xl, mut xr) = (*l, *r);
        for i in 0..16 {
            xl ^= self.p[i];
            xr ^= self.f(xl);
            core::mem::swap(&mut xl, &mut xr);
        }
        core::mem::swap(&mut xl, &mut xr);
        xr ^= self.p[16];
        xl ^= self.p[17];
        *l = xl;
        *r = xr;
    }

    /// Blowfish's key schedule, with bcrypt's salt folded in when `salt` is
    /// not empty: `ExpandKey` in Provos and Mazieres' paper.
    fn expand(&mut self, salt: &[u8], key: &[u8]) {
        let mut j = 0;
        for i in 0..18 {
            self.p[i] ^= stream_word(key, &mut j);
        }
        let (mut l, mut r) = (0u32, 0u32);
        let mut k = 0;
        let mut next = |l: &mut u32, r: &mut u32| {
            if !salt.is_empty() {
                *l ^= stream_word(salt, &mut k);
                *r ^= stream_word(salt, &mut k);
            }
        };
        for i in (0..18).step_by(2) {
            next(&mut l, &mut r);
            self.encrypt(&mut l, &mut r);
            self.p[i] = l;
            self.p[i + 1] = r;
        }
        for b in 0..4 {
            for i in (0..256).step_by(2) {
                next(&mut l, &mut r);
                self.encrypt(&mut l, &mut r);
                self.s[b][i] = l;
                self.s[b][i + 1] = r;
            }
        }
    }
}

/// The next four bytes of `data`, cycling, as a big-endian word.
fn stream_word(data: &[u8], at: &mut usize) -> u32 {
    let mut w = 0u32;
    for _ in 0..4 {
        w = (w << 8) | u32::from(data[*at]);
        *at = (*at + 1) % data.len();
    }
    w
}

/// bcrypt's own base64: its alphabet, most significant bits first, no
/// padding. Decodes `chars` into `out`, refusing a character outside the
/// alphabet or nonzero bits past the end of `out`.
fn decode(chars: &[u8], out: &mut [u8]) -> Result<()> {
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut at = 0;
    for &c in chars {
        let v = ALPHABET
            .iter()
            .position(|&a| a == c)
            .ok_or(ic_core::err!(MalformedEncoding, "bcrypt: base64 character"))?;
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            ensure!(at < out.len(), MalformedEncoding, "bcrypt: base64 length");
            out[at] = (acc >> bits) as u8;
            at += 1;
        }
    }
    ensure!(
        at == out.len() && acc & ((1 << bits) - 1) == 0,
        MalformedEncoding,
        "bcrypt: base64 not canonical"
    );
    Ok(())
}

/// The cost a stored hash names, read without deriving anything.
pub fn cost(hash: &str) -> Result<u32> {
    Ok(parse(hash)?.0)
}

/// `(cost, salt, hash)` from a `$2a$`, `$2b$` or `$2y$` string.
fn parse(hash: &str) -> Result<(u32, [u8; 16], [u8; 23])> {
    let b = hash.as_bytes();
    ensure!(
        b.len() == 60,
        MalformedEncoding,
        "bcrypt: a hash is 60 characters"
    );
    ensure!(
        b[0] == b'$' && b[1] == b'2' && b[3] == b'$' && b[6] == b'$',
        MalformedEncoding,
        "bcrypt: not a bcrypt hash"
    );
    ensure!(
        matches!(b[2], b'a' | b'b' | b'y'),
        Unsupported,
        "bcrypt: only $2a$, $2b$ and $2y$"
    );
    ensure!(
        b[4].is_ascii_digit() && b[5].is_ascii_digit(),
        MalformedEncoding,
        "bcrypt: cost"
    );
    let cost = u32::from(b[4] - b'0') * 10 + u32::from(b[5] - b'0');
    ensure!(
        (MIN_COST..=MAX_COST).contains(&cost),
        InvalidParameter,
        "bcrypt: cost must be 4 to 31"
    );
    let mut salt = [0u8; 16];
    decode(&b[7..29], &mut salt)?;
    let mut digest = [0u8; 23];
    decode(&b[29..], &mut digest)?;
    Ok((cost, salt, digest))
}

/// bcrypt's 23-byte digest of `password` under `cost` and `salt`.
fn digest(password: &[u8], cost: u32, salt: &[u8; 16]) -> [u8; 23] {
    // The key is the password and a terminating zero byte, cut at 72.
    let mut key = [0u8; 73];
    let n = password.len().min(72);
    key[..n].copy_from_slice(&password[..n]);
    let key_len = (n + 1).min(72);
    let key_bytes = &key[..key_len];

    let mut state = Blowfish::new();
    state.expand(salt, key_bytes);
    for _ in 0..(1u64 << cost) {
        state.expand(&[], key_bytes);
        state.expand(&[], salt);
    }
    let mut text = CTEXT;
    for _ in 0..64 {
        for pair in text.chunks_exact_mut(2) {
            let (mut l, mut r) = (pair[0], pair[1]);
            state.encrypt(&mut l, &mut r);
            pair[0] = l;
            pair[1] = r;
        }
    }
    let mut out = [0u8; 24];
    for (chunk, w) in out.chunks_exact_mut(4).zip(text.iter()) {
        chunk.copy_from_slice(&w.to_be_bytes());
    }
    let mut d = [0u8; 23];
    d.copy_from_slice(&out[..23]);
    key.zeroize();
    out.zeroize();
    text.zeroize();
    d
}

/// Whether `password` is the one `hash` was made from; `AuthenticationFailed`
/// if not, compared in constant time.
///
/// The cost in the hash decides what this spends: `2^cost` rounds of the key
/// schedule. Above [`DEFAULT_MAX_COST`] the hash is refused, since a stored
/// cost of 31 is days of work; [`verify_password_bounded`] takes another
/// ceiling.
pub fn verify_password(password: &[u8], hash: &str) -> Result<()> {
    verify(password, hash, DEFAULT_MAX_COST)
}

/// The ceiling [`verify_password`] applies: 16, a few seconds, sixteen times
/// the cost of 12 that pyca/bcrypt and the bcrypt crate default to.
pub const DEFAULT_MAX_COST: u32 = 16;

/// [`verify_password`], refusing a hash whose cost exceeds `max_cost` before
/// computing anything, as `InvalidParameter`.
pub fn verify_password_bounded(password: &[u8], hash: &str, max_cost: u32) -> Result<()> {
    verify(password, hash, max_cost)
}

fn verify(password: &[u8], hash: &str, max_cost: u32) -> Result<()> {
    ic_core::module::operational()?;
    let (cost, salt, want) = parse(hash)?;
    ensure!(
        cost <= max_cost,
        InvalidParameter,
        "bcrypt: cost above the ceiling"
    );
    let mut got = digest(password, cost, &salt);
    let same = ic_core::ct::verify(&got, &want);
    got.zeroize();
    ensure!(same, AuthenticationFailed, "bcrypt password");
    Ok(())
}

/// The known-answer test: the classic OpenBSD vector, "U*U" at cost 5.
pub fn self_test() -> Result<()> {
    verify_password(
        b"U*U",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
    )
    .map_err(|_| ic_core::err!(SelfTestFailed, "bcrypt"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn malformed_hashes_are_refused_by_kind() {
        let good = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
        let kind = |h: &str| verify_password(b"U*U", h).unwrap_err().kind();
        use ic_core::ErrorKind::*;
        assert_eq!(kind(&good.replace("$2a$", "$2x$")), Unsupported);
        assert_eq!(kind(&good.replace("$05$", "$03$")), InvalidParameter);
        assert_eq!(kind(&good[..59]), MalformedEncoding);
        assert_eq!(kind(&good.replace("C.E5", "C!E5")), MalformedEncoding);
        // The 22nd salt character carries two bits of salt and four unused
        // ones; '.' leaves them zero and '/' does not.
        assert_eq!(kind(&good.replace("C.E5", "C/E5")), MalformedEncoding);
        assert!(verify_password_bounded(b"U*U", good, 4).is_err());
        assert_eq!(cost(good).unwrap(), 5);
    }
}
