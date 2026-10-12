//! One door for stored password hashes, whatever made them.
//!
//! A database that has lived through a few systems holds a mixture: Argon2
//! and scrypt PHC strings, bcrypt from a web framework, yescrypt copied out
//! of `/etc/shadow`. [`verify`] reads the prefix, checks the password with
//! the module that owns the format, and says whether the hash should be
//! replaced. [`verify_and_upgrade`] also makes the replacement:
//!
//! ```
//! use ic_kdf::argon2::Argon2Params;
//! use ic_kdf::password;
//! # struct Fixed;
//! # impl ic_core::traits::RandomSource for Fixed {
//! #     fn fill(&mut self, out: &mut [u8]) -> ic_core::Result<()> { out.fill(7); Ok(()) }
//! # }
//! # let mut rng = Fixed;
//! # let policy = Argon2Params { memory_kib: 64, passes: 1, lanes: 1 };
//! let stored = "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW";
//! let upgraded = password::verify_and_upgrade(b"U*U", stored, &policy, &mut rng)?;
//! // A bcrypt hash always moves: store this in its place.
//! let new = upgraded.expect("bcrypt is replaced");
//! assert!(new.starts_with("$argon2id$"));
//! assert!(password::verify(b"U*U", &new, &policy)?.needs_rehash == false);
//! # Ok::<(), ic_core::Error>(())
//! ```
//!
//! The target is Argon2id at the caller's parameters. An Argon2 hash is
//! replaced when [`argon2::phc::needs_rehash`](crate::argon2::phc::needs_rehash)
//! says it falls short of them; scrypt, bcrypt and yescrypt hashes always
//! are. To keep scrypt as the target, use [`crate::scrypt::phc`] directly.
//!
//! Each format keeps its own ceiling on what a stored hash may cost, so a
//! planted string cannot make a login run for hours.

use alloc::string::String;

use ic_core::traits::RandomSource;
use ic_core::Result;

use crate::argon2::{phc as argon2_phc, Argon2Params, Variant};

/// The format a stored hash was in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// `$argon2id$`, `$argon2i$` or `$argon2d$`.
    Argon2,
    /// `$scrypt$`.
    Scrypt,
    /// `$2a$`, `$2b$` or `$2y$`.
    Bcrypt,
    /// `$y$` or `$7$`.
    Yescrypt,
}

/// What [`verify`] found, once the password matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verified {
    /// The format the hash was in.
    pub scheme: Scheme,
    /// Whether to hash the password again with Argon2id and store that.
    pub needs_rehash: bool,
}

/// The format `stored` is in, from its prefix alone.
pub fn scheme(stored: &str) -> Result<Scheme> {
    let s = stored;
    if s.starts_with("$argon2id$") || s.starts_with("$argon2i$") || s.starts_with("$argon2d$") {
        Ok(Scheme::Argon2)
    } else if s.starts_with("$scrypt$") {
        Ok(Scheme::Scrypt)
    } else if s.starts_with("$2a$")
        || s.starts_with("$2b$")
        || s.starts_with("$2y$")
        || s.starts_with("$2x$")
    {
        Ok(Scheme::Bcrypt)
    } else if s.starts_with("$y$") || s.starts_with("$7$") {
        Ok(Scheme::Yescrypt)
    } else {
        Err(ic_core::err!(Unsupported, "password hash format"))
    }
}

/// Check `password` against `stored`, in whichever format it is, and say
/// whether to replace it with Argon2id at `policy`. `AuthenticationFailed`
/// if the password is wrong; `Unsupported` for a format not listed in
/// [`Scheme`].
pub fn verify(password: &[u8], stored: &str, policy: &Argon2Params) -> Result<Verified> {
    let scheme = scheme(stored)?;
    let needs_rehash = match scheme {
        Scheme::Argon2 => {
            argon2_phc::verify_password(password, stored)?;
            argon2_phc::needs_rehash(stored, Variant::Argon2id, policy)?
        }
        Scheme::Scrypt => {
            crate::scrypt::phc::verify_password(password, stored)?;
            true
        }
        Scheme::Bcrypt => {
            crate::bcrypt::verify_password(password, stored)?;
            true
        }
        Scheme::Yescrypt => {
            crate::yescrypt::verify_password(password, stored)?;
            true
        }
    };
    Ok(Verified {
        scheme,
        needs_rehash,
    })
}

/// [`verify`], and when the hash should be replaced, the Argon2id PHC string
/// to store in its place, under a salt drawn from `rng`. `None` when the
/// stored hash is already good enough.
pub fn verify_and_upgrade<R: RandomSource + ?Sized>(
    password: &[u8],
    stored: &str,
    policy: &Argon2Params,
    rng: &mut R,
) -> Result<Option<String>> {
    policy.validate()?;
    let verified = verify(password, stored, policy)?;
    if !verified.needs_rehash {
        return Ok(None);
    }
    argon2_phc::hash_password(Variant::Argon2id, policy, password, rng).map(Some)
}
