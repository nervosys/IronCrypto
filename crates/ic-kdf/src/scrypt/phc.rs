//! scrypt password hashes as PHC strings.
//!
//! ```text
//! $scrypt$ln=17,r=8,p=1$<salt>$<hash>
//! ```
//!
//! The form the RustCrypto `scrypt` crate and passlib write: `ln` is
//! `log2(N)`, and salt and hash are base64 in the standard alphabet without
//! padding. Parsing accepts that canonical form and nothing else, as for
//! Argon2's strings.
//!
//! As for Argon2, the parameters in a hash decide what verifying it costs;
//! for a hash from elsewhere, use [`verify_password_bounded`].

use alloc::string::String;
use alloc::vec::Vec;

use super::{scrypt, ScryptParams};
use crate::argon2::phc::{b64_decode, b64_encode, decimal, push_decimal};
use ic_core::traits::RandomSource;
use ic_core::{ensure, Result, Zeroize};

/// Bytes of salt [`hash_password`] draws.
pub const SALT_LEN: usize = 16;
/// Bytes of hash [`hash_password`] writes.
pub const HASH_LEN: usize = 32;
/// The shortest hash accepted.
pub const MIN_HASH_LEN: usize = 10;
/// The longest hash accepted.
pub const MAX_HASH_LEN: usize = 1024;
/// The longest salt accepted.
pub const MAX_SALT_LEN: usize = 1024;

/// A parsed scrypt PHC string.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordHash {
    /// `log2(N)`, `r` and `p`.
    pub params: ScryptParams,
    /// The salt.
    pub salt: Vec<u8>,
    /// The hash.
    pub hash: Vec<u8>,
}

impl core::fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PasswordHash")
            .field("params", &self.params)
            .field("hash_len", &self.hash.len())
            .finish_non_exhaustive()
    }
}

impl Drop for PasswordHash {
    fn drop(&mut self) {
        self.hash.zeroize();
    }
}

impl PasswordHash {
    /// Parse a PHC string, refusing anything not in canonical form.
    pub fn parse(encoded: &str) -> Result<Self> {
        let rest = encoded
            .strip_prefix("$scrypt$")
            .ok_or(ic_core::err!(Unsupported, "phc: not an scrypt hash"))?;
        let mut fields = rest.split('$');
        let params = fields
            .next()
            .ok_or(ic_core::err!(MalformedEncoding, "phc: no parameters"))?;
        let mut parts = params.split(',');
        let mut take = |name: &str| -> Result<u32> {
            let field = parts.next().ok_or(ic_core::err!(
                MalformedEncoding,
                "phc: a parameter is missing"
            ))?;
            decimal(
                field
                    .strip_prefix(name)
                    .and_then(|v| v.strip_prefix('='))
                    .ok_or(ic_core::err!(
                        MalformedEncoding,
                        "phc: parameters out of order or unknown"
                    ))?,
            )
        };
        let log_n = take("ln")?;
        let r = take("r")?;
        let p = take("p")?;
        ensure!(
            parts.next().is_none(),
            MalformedEncoding,
            "phc: parameters out of order or unknown"
        );
        let params = ScryptParams {
            log_n: u8::try_from(log_n)
                .map_err(|_| ic_core::err!(MalformedEncoding, "phc: ln out of range"))?,
            r,
            p,
        };
        params.validate()?;
        let salt = b64_decode(
            fields
                .next()
                .ok_or(ic_core::err!(MalformedEncoding, "phc: no salt"))?,
        )?;
        let hash = b64_decode(
            fields
                .next()
                .ok_or(ic_core::err!(MalformedEncoding, "phc: no hash"))?,
        )?;
        ensure!(
            fields.next().is_none(),
            MalformedEncoding,
            "phc: fields after the hash"
        );
        ensure!(
            !salt.is_empty() && salt.len() <= MAX_SALT_LEN,
            MalformedEncoding,
            "phc: salt length"
        );
        ensure!(
            (MIN_HASH_LEN..=MAX_HASH_LEN).contains(&hash.len()),
            MalformedEncoding,
            "phc: hash length"
        );
        Ok(Self { params, salt, hash })
    }

    /// The canonical PHC string.
    pub fn encode(&self) -> String {
        let mut s = String::from("$scrypt$ln=");
        push_decimal(&mut s, u32::from(self.params.log_n));
        s.push_str(",r=");
        push_decimal(&mut s, self.params.r);
        s.push_str(",p=");
        push_decimal(&mut s, self.params.p);
        s.push('$');
        s.push_str(&b64_encode(&self.salt));
        s.push('$');
        s.push_str(&b64_encode(&self.hash));
        s
    }
}

/// Hash `password` under a salt drawn from `rng`, as a PHC string with a
/// 32-byte hash. Pass `ic_drbg::Rng`.
pub fn hash_password<R: RandomSource + ?Sized>(
    params: &ScryptParams,
    password: &[u8],
    rng: &mut R,
) -> Result<String> {
    ic_core::module::operational()?;
    params.validate()?;
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt)?;
    hash_password_with(params, password, &salt, HASH_LEN)
}

/// Hash `password` with the salt and hash length given.
pub fn hash_password_with(
    params: &ScryptParams,
    password: &[u8],
    salt: &[u8],
    hash_len: usize,
) -> Result<String> {
    ic_core::module::operational()?;
    ensure!(
        !salt.is_empty() && salt.len() <= MAX_SALT_LEN,
        InvalidParameter,
        "phc: salt length"
    );
    ensure!(
        (MIN_HASH_LEN..=MAX_HASH_LEN).contains(&hash_len),
        InvalidParameter,
        "phc: hash length"
    );
    let mut hash = alloc::vec![0u8; hash_len];
    scrypt(password, salt, params, &mut hash)?;
    Ok(PasswordHash {
        params: *params,
        salt: salt.to_vec(),
        hash,
    }
    .encode())
}

/// Whether `password` is the one `encoded` was made from;
/// `AuthenticationFailed` if not, compared in constant time.
pub fn verify_password(password: &[u8], encoded: &str) -> Result<()> {
    verify(password, encoded, None)
}

/// [`verify_password`], refusing a hash whose `ln`, `r` or `p` exceed
/// `ceiling` before deriving anything, as `InvalidParameter`.
pub fn verify_password_bounded(
    password: &[u8],
    encoded: &str,
    ceiling: &ScryptParams,
) -> Result<()> {
    verify(password, encoded, Some(ceiling))
}

/// Whether a stored hash falls short of `params` -- a smaller `N`, `r` or
/// `p`, a salt under 16 bytes or a hash under 32 -- and should be made again
/// after the password next verifies.
pub fn needs_rehash(encoded: &str, params: &ScryptParams) -> Result<bool> {
    let h = PasswordHash::parse(encoded)?;
    Ok(h.params.log_n < params.log_n
        || h.params.r < params.r
        || h.params.p < params.p
        || h.salt.len() < SALT_LEN
        || h.hash.len() < HASH_LEN)
}

fn verify(password: &[u8], encoded: &str, ceiling: Option<&ScryptParams>) -> Result<()> {
    ic_core::module::operational()?;
    let parsed = PasswordHash::parse(encoded)?;
    if let Some(max) = ceiling {
        ensure!(
            parsed.params.log_n <= max.log_n
                && parsed.params.r <= max.r
                && parsed.params.p <= max.p,
            InvalidParameter,
            "phc: parameters above the ceiling"
        );
    }
    let mut computed = alloc::vec![0u8; parsed.hash.len()];
    scrypt(password, &parsed.salt, &parsed.params, &mut computed)?;
    let same = ic_core::ct::verify(&computed, &parsed.hash);
    computed.zeroize();
    ensure!(same, AuthenticationFailed, "scrypt password");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL: ScryptParams = ScryptParams {
        log_n: 4,
        r: 1,
        p: 1,
    };

    #[test]
    fn a_hash_round_trips_and_verifies() {
        let s = hash_password_with(&SMALL, b"pw", &[7u8; 16], 32).unwrap();
        assert!(s.starts_with("$scrypt$ln=4,r=1,p=1$"));
        assert_eq!(PasswordHash::parse(&s).unwrap().encode(), s);
        verify_password(b"pw", &s).unwrap();
        let err = verify_password(b"px", &s).unwrap_err();
        assert_eq!(err.kind(), ic_core::ErrorKind::AuthenticationFailed);
        // Every byte of the hash is compared.
        let mut parsed = PasswordHash::parse(&s).unwrap();
        let last = parsed.hash.len() - 1;
        parsed.hash[last] ^= 1;
        assert!(verify_password(b"pw", &parsed.encode()).is_err());
    }

    #[test]
    fn non_canonical_and_costly_strings_are_refused() {
        let s = hash_password_with(&SMALL, b"pw", &[7u8; 16], 32).unwrap();
        let tail = s.splitn(4, '$').nth(3).unwrap();
        for bad in [
            alloc::format!("$scrypt$r=1,ln=4,p=1${tail}"),
            alloc::format!("$scrypt$ln=04,r=1,p=1${tail}"),
            alloc::format!("$scrypt$ln=4,r=1,p=1,x=1${tail}"),
            alloc::format!("$scrypt$ln=0,r=1,p=1${tail}"),
            alloc::format!("{s}$x"),
        ] {
            assert!(PasswordHash::parse(&bad).is_err(), "{bad}");
        }
        let huge = alloc::format!("$scrypt$ln=40,r=8,p=1${tail}");
        let err = verify_password_bounded(b"pw", &huge, &ScryptParams::RECOMMENDED).unwrap_err();
        assert_eq!(err.kind(), ic_core::ErrorKind::InvalidParameter);
    }

    #[test]
    fn needs_rehash_follows_the_policy() {
        let s = hash_password_with(&SMALL, b"pw", &[7u8; 16], 32).unwrap();
        assert!(!needs_rehash(&s, &SMALL).unwrap());
        assert!(needs_rehash(&s, &ScryptParams { log_n: 5, ..SMALL }).unwrap());
        assert!(needs_rehash(&s, &ScryptParams { r: 2, ..SMALL }).unwrap());
        let short = hash_password_with(&SMALL, b"pw", &[7u8; 8], 32).unwrap();
        assert!(needs_rehash(&short, &SMALL).unwrap());
    }
}
