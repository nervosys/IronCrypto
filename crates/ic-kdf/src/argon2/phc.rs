//! Argon2 password hashes as PHC strings.
//!
//! The form a password database stores, and the one the `argon2` crate,
//! libargon2 and libsodium all read and write:
//!
//! ```text
//! $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
//! ```
//!
//! The algorithm, version and parameters travel with the hash, so a hash
//! made today still verifies after the defaults change. Salt and hash are
//! base64 in the standard alphabet without padding. Two optional parameters
//! may follow `p`: `keyid`, up to 8 bytes naming which secret (pepper) was
//! used, and `data`, up to 32 bytes of associated data that Argon2 hashes in.
//!
//! ```
//! use ic_kdf::argon2::{phc, Argon2Params, Variant};
//! # struct Fixed;
//! # impl ic_core::traits::RandomSource for Fixed {
//! #     fn fill(&mut self, out: &mut [u8]) -> ic_core::Result<()> { out.fill(7); Ok(()) }
//! # }
//! # let mut rng = Fixed;
//! # let params = Argon2Params { memory_kib: 64, passes: 1, lanes: 1 };
//! let stored = phc::hash_password(Variant::Argon2id, &params, b"hunter2", &mut rng)?;
//! phc::verify_password(b"hunter2", &stored)?;
//! assert!(phc::verify_password(b"hunter3", &stored).is_err());
//! # Ok::<(), ic_core::Error>(())
//! ```
//!
//! # Strictness
//!
//! Parsing accepts the canonical form and nothing else: parameters in the
//! order `m`, `t`, `p`, `keyid`, `data`; decimals without leading zeros;
//! base64 without padding and with its unused bits zero. Every hash
//! libargon2, libsodium and the `argon2` crate write is canonical.
//!
//! A string with no `v=` field is version 1.0, as libargon2 reads it and as
//! the PHC format defines. The `argon2` crate reads such a string as 1.3
//! instead; only hashes from before 1.3 omit the field, and they were 1.0.
//!
//! # Cost is part of the input
//!
//! The parameters in a hash say how much memory and time verifying it costs.
//! [`verify_password`] spends whatever the hash asks, which is right for hashes
//! this system wrote. For a hash from anywhere else, use
//! [`verify_password_bounded`], which refuses parameters above a ceiling
//! before deriving anything.

use alloc::string::String;
use alloc::vec::Vec;

use super::{argon2_versioned, Argon2Params, Variant, Version};
use ic_core::traits::RandomSource;
use ic_core::{ensure, Result, Zeroize};

/// Bytes of salt [`hash_password`] draws: RFC 9106's recommendation.
pub const SALT_LEN: usize = 16;
/// Bytes of hash [`hash_password`] writes.
pub const HASH_LEN: usize = 32;
/// The longest `keyid` accepted, as the `argon2` crate has it.
pub const MAX_KEYID_LEN: usize = 8;
/// The longest `data` accepted, as the `argon2` crate has it.
pub const MAX_DATA_LEN: usize = 32;
/// The shortest salt accepted: Argon2's own minimum.
pub const MIN_SALT_LEN: usize = 8;
/// The longest salt accepted.
pub const MAX_SALT_LEN: usize = 1024;
/// The shortest hash accepted: Argon2's own minimum.
pub const MIN_HASH_LEN: usize = 4;
/// The longest hash accepted.
pub const MAX_HASH_LEN: usize = 1024;

/// A parsed PHC string.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordHash {
    /// Argon2d, Argon2i or Argon2id.
    pub variant: Variant,
    /// The version; 1.0 when the string has no `v=` field.
    pub version: Version,
    /// Memory, passes and lanes.
    pub params: Argon2Params,
    /// Which secret was used, if the writer named one. Not hashed.
    pub keyid: Vec<u8>,
    /// Associated data, hashed in as Argon2's `X`.
    pub data: Vec<u8>,
    /// The salt.
    pub salt: Vec<u8>,
    /// The hash.
    pub hash: Vec<u8>,
}

impl core::fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The hash is what an attacker would brute-force; leave it out of
        // logs.
        f.debug_struct("PasswordHash")
            .field("variant", &self.variant)
            .field("version", &self.version)
            .field("params", &self.params)
            .field("keyid", &self.keyid)
            .field("hash_len", &self.hash.len())
            .finish_non_exhaustive()
    }
}

impl PasswordHash {
    /// Parse a PHC string, refusing anything not in canonical form.
    pub fn parse(encoded: &str) -> Result<Self> {
        let mut fields = encoded.split('$');
        ensure!(
            fields.next() == Some(""),
            MalformedEncoding,
            "phc: must start with '$'"
        );
        let variant = match fields.next() {
            Some("argon2d") => Variant::Argon2d,
            Some("argon2i") => Variant::Argon2i,
            Some("argon2id") => Variant::Argon2id,
            Some(_) => return Err(ic_core::err!(Unsupported, "phc: not an argon2 hash")),
            None => return Err(ic_core::err!(MalformedEncoding, "phc: no algorithm")),
        };
        let mut next = fields
            .next()
            .ok_or(ic_core::err!(MalformedEncoding, "phc: no parameters"))?;
        let version = match next.strip_prefix("v=") {
            Some(number) => {
                let v = Version::from_number(decimal(number)?)?;
                next = fields
                    .next()
                    .ok_or(ic_core::err!(MalformedEncoding, "phc: no parameters"))?;
                v
            }
            None => Version::V0x10,
        };

        let mut params = next.split(',');
        let mut take = |name: &str| -> Result<&str> {
            let field = params.next().ok_or(ic_core::err!(
                MalformedEncoding,
                "phc: a parameter is missing"
            ))?;
            field
                .strip_prefix(name)
                .and_then(|rest| rest.strip_prefix('='))
                .ok_or(ic_core::err!(
                    MalformedEncoding,
                    "phc: parameters out of order or unknown"
                ))
        };
        let memory_kib = decimal(take("m")?)?;
        let passes = decimal(take("t")?)?;
        let lanes = decimal(take("p")?)?;
        let (mut keyid, mut data) = (Vec::new(), Vec::new());
        let mut rest: Vec<&str> = params.collect();
        if let Some(field) = rest.first().and_then(|f| f.strip_prefix("keyid=")) {
            keyid = b64_decode(field)?;
            ensure!(
                !keyid.is_empty() && keyid.len() <= MAX_KEYID_LEN,
                MalformedEncoding,
                "phc: keyid must be 1 to 8 bytes"
            );
            rest.remove(0);
        }
        if let Some(field) = rest.first().and_then(|f| f.strip_prefix("data=")) {
            data = b64_decode(field)?;
            ensure!(
                !data.is_empty() && data.len() <= MAX_DATA_LEN,
                MalformedEncoding,
                "phc: data must be 1 to 32 bytes"
            );
            rest.remove(0);
        }
        ensure!(
            rest.is_empty(),
            MalformedEncoding,
            "phc: parameters out of order or unknown"
        );
        let params = Argon2Params {
            memory_kib,
            passes,
            lanes,
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
            (MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt.len()),
            MalformedEncoding,
            "phc: salt length"
        );
        ensure!(
            (MIN_HASH_LEN..=MAX_HASH_LEN).contains(&hash.len()),
            MalformedEncoding,
            "phc: hash length"
        );
        Ok(Self {
            variant,
            version,
            params,
            keyid,
            data,
            salt,
            hash,
        })
    }

    /// The canonical PHC string, with `v=` always written.
    pub fn encode(&self) -> String {
        let mut s = String::new();
        s.push('$');
        s.push_str(self.variant.id());
        s.push_str("$v=");
        push_decimal(&mut s, self.version.number());
        s.push_str("$m=");
        push_decimal(&mut s, self.params.memory_kib);
        s.push_str(",t=");
        push_decimal(&mut s, self.params.passes);
        s.push_str(",p=");
        push_decimal(&mut s, self.params.lanes);
        if !self.keyid.is_empty() {
            s.push_str(",keyid=");
            s.push_str(&b64_encode(&self.keyid));
        }
        if !self.data.is_empty() {
            s.push_str(",data=");
            s.push_str(&b64_encode(&self.data));
        }
        s.push('$');
        s.push_str(&b64_encode(&self.salt));
        s.push('$');
        s.push_str(&b64_encode(&self.hash));
        s
    }
}

impl Drop for PasswordHash {
    fn drop(&mut self) {
        self.hash.zeroize();
    }
}

/// Hash `password` under a salt drawn from `rng`, as a PHC string at version
/// 1.3 with a 32-byte hash. Pass `ic_drbg::Rng`.
pub fn hash_password<R: RandomSource + ?Sized>(
    variant: Variant,
    params: &Argon2Params,
    password: &[u8],
    rng: &mut R,
) -> Result<String> {
    ic_core::module::operational()?;
    params.validate()?;
    let mut salt = [0u8; SALT_LEN];
    rng.fill(&mut salt)?;
    hash_password_with(
        variant,
        Version::V0x13,
        params,
        password,
        &salt,
        &[],
        &[],
        &[],
        HASH_LEN,
    )
}

/// Hash `password` with everything given: the salt, a secret and the
/// `keyid` that names it, associated data, and the hash length.
///
/// The secret is hashed in and not written; `keyid` is written and not
/// hashed. A verifier needs the secret back, through
/// [`verify_password_with_secret`].
#[allow(clippy::too_many_arguments)]
pub fn hash_password_with(
    variant: Variant,
    version: Version,
    params: &Argon2Params,
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    keyid: &[u8],
    data: &[u8],
    hash_len: usize,
) -> Result<String> {
    ic_core::module::operational()?;
    ensure!(
        (MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt.len()),
        InvalidParameter,
        "phc: salt length"
    );
    ensure!(
        (MIN_HASH_LEN..=MAX_HASH_LEN).contains(&hash_len),
        InvalidParameter,
        "phc: hash length"
    );
    ensure!(
        keyid.len() <= MAX_KEYID_LEN,
        InvalidParameter,
        "phc: keyid longer than 8 bytes"
    );
    ensure!(
        data.len() <= MAX_DATA_LEN,
        InvalidParameter,
        "phc: data longer than 32 bytes"
    );
    let mut hash = alloc::vec![0u8; hash_len];
    argon2_versioned(
        variant, version, params, password, salt, secret, data, &mut hash,
    )?;
    Ok(PasswordHash {
        variant,
        version,
        params: *params,
        keyid: keyid.to_vec(),
        data: data.to_vec(),
        salt: salt.to_vec(),
        hash,
    }
    .encode())
}

/// Whether `password` is the one `encoded` was made from.
///
/// `AuthenticationFailed` if not; the comparison is constant time. Spends
/// what the hash's parameters ask: see the module documentation, and
/// [`verify_password_bounded`] for a hash from elsewhere.
pub fn verify_password(password: &[u8], encoded: &str) -> Result<()> {
    verify(password, &[], encoded, None)
}

/// [`verify_password`] for a hash made with a secret.
pub fn verify_password_with_secret(password: &[u8], secret: &[u8], encoded: &str) -> Result<()> {
    verify(password, secret, encoded, None)
}

/// [`verify_password`], refusing a hash whose memory, passes or lanes exceed
/// `ceiling` before deriving anything, as `InvalidParameter`.
pub fn verify_password_bounded(
    password: &[u8],
    encoded: &str,
    ceiling: &Argon2Params,
) -> Result<()> {
    verify(password, &[], encoded, Some(ceiling))
}

/// Whether a stored hash falls short of the current policy, so that the
/// caller should hash the password again, after it verifies, and store the
/// new hash.
///
/// Short means: another variant or version than asked for, less memory or
/// fewer passes or lanes than `params`, a salt under [`SALT_LEN`], or a hash
/// under [`HASH_LEN`]. Parameters above the policy do not count; lowering a
/// stored hash's cost is never a reason to rehash. Only the string is read,
/// so this is cheap and needs no password.
///
/// Raising the cost of stored hashes over time is what NIST SP 800-63B-4 and
/// the IETF password-storage guidance ask for, and this is how: check after
/// every successful login.
pub fn needs_rehash(encoded: &str, variant: Variant, params: &Argon2Params) -> Result<bool> {
    needs_rehash_with_keyid(encoded, variant, params, None)
}

/// [`needs_rehash`], and also when the hash names another secret than
/// `keyid`: how a rotated pepper reaches every stored hash, one login at a
/// time. `None` ignores the `keyid`.
pub fn needs_rehash_with_keyid(
    encoded: &str,
    variant: Variant,
    params: &Argon2Params,
    keyid: Option<&[u8]>,
) -> Result<bool> {
    let h = PasswordHash::parse(encoded)?;
    Ok(h.variant != variant
        || h.version != Version::V0x13
        || h.params.memory_kib < params.memory_kib
        || h.params.passes < params.passes
        || h.params.lanes < params.lanes
        || h.salt.len() < SALT_LEN
        || h.hash.len() < HASH_LEN
        || keyid.is_some_and(|k| k != h.keyid.as_slice()))
}

fn verify(
    password: &[u8],
    secret: &[u8],
    encoded: &str,
    ceiling: Option<&Argon2Params>,
) -> Result<()> {
    ic_core::module::operational()?;
    let parsed = PasswordHash::parse(encoded)?;
    if let Some(max) = ceiling {
        ensure!(
            parsed.params.memory_kib <= max.memory_kib
                && parsed.params.passes <= max.passes
                && parsed.params.lanes <= max.lanes,
            InvalidParameter,
            "phc: parameters above the ceiling"
        );
    }
    let mut computed = alloc::vec![0u8; parsed.hash.len()];
    argon2_versioned(
        parsed.variant,
        parsed.version,
        &parsed.params,
        password,
        &parsed.salt,
        secret,
        &parsed.data,
        &mut computed,
    )?;
    let same = ic_core::ct::verify(&computed, &parsed.hash);
    computed.zeroize();
    ensure!(same, AuthenticationFailed, "argon2 password");
    Ok(())
}

/// A decimal with no sign, no leading zero, and no more than fits in a `u32`.
pub(crate) fn decimal(s: &str) -> Result<u32> {
    ensure!(
        !s.is_empty()
            && s.len() <= 10
            && s.bytes().all(|b| b.is_ascii_digit())
            && !(s.len() > 1 && s.starts_with('0')),
        MalformedEncoding,
        "phc: not a canonical decimal"
    );
    s.parse::<u32>()
        .map_err(|_| ic_core::err!(MalformedEncoding, "phc: decimal out of range"))
}

pub(crate) fn push_decimal(s: &mut String, n: u32) {
    let mut digits = [0u8; 10];
    let mut i = digits.len();
    let mut n = n;
    loop {
        i -= 1;
        digits[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    for &d in &digits[i..] {
        s.push(d as char);
    }
}

/// Standard-alphabet base64 without padding.
pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    let mut padded = alloc::vec![0u8; ic_core::codec::base64_encoded_len(bytes.len())];
    // The buffer is the exact length, so this cannot fail.
    let _ = ic_core::codec::base64_encode(bytes, &mut padded);
    let end = padded.iter().rposition(|&c| c != b'=').map_or(0, |i| i + 1);
    padded[..end].iter().map(|&c| c as char).collect()
}

/// The inverse of [`b64_encode`], refusing padding, characters outside the
/// alphabet, an impossible length, and unused bits that are not zero.
pub(crate) fn b64_decode(s: &str) -> Result<Vec<u8>> {
    ensure!(
        s.len() % 4 != 1 && !s.contains('='),
        MalformedEncoding,
        "phc: base64 length or padding"
    );
    let mut padded: Vec<u8> = s.as_bytes().to_vec();
    while !padded.len().is_multiple_of(4) {
        padded.push(b'=');
    }
    let mut out = alloc::vec![0u8; padded.len() / 4 * 3];
    let n = ic_core::codec::base64_decode(&padded, &mut out)
        .map_err(|_| ic_core::err!(MalformedEncoding, "phc: base64 character"))?;
    out.truncate(n);
    ensure!(
        b64_encode(&out) == s,
        MalformedEncoding,
        "phc: base64 not canonical"
    );
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TINY: Argon2Params = Argon2Params {
        memory_kib: 64,
        passes: 1,
        lanes: 1,
    };

    #[test]
    fn a_hash_round_trips_through_its_string() {
        let s = hash_password_with(
            Variant::Argon2id,
            Version::V0x13,
            &TINY,
            b"pw",
            &[9u8; 16],
            b"pepper",
            b"k1",
            b"context",
            40,
        )
        .unwrap();
        let parsed = PasswordHash::parse(&s).unwrap();
        assert_eq!(parsed.encode(), s);
        assert_eq!(parsed.keyid, b"k1");
        assert_eq!(parsed.data, b"context");
        assert_eq!(parsed.hash.len(), 40);
        verify_password_with_secret(b"pw", b"pepper", &s).unwrap();
        // Without the secret, or with another, it does not verify.
        assert!(verify_password(b"pw", &s).is_err());
        assert!(verify_password_with_secret(b"pw", b"other", &s).is_err());
    }

    #[test]
    fn non_canonical_strings_are_refused() {
        let good = hash_password_with(
            Variant::Argon2id,
            Version::V0x13,
            &TINY,
            b"pw",
            &[9u8; 16],
            &[],
            &[],
            &[],
            32,
        )
        .unwrap();
        verify_password(b"pw", &good).unwrap();
        let salt = b64_encode(&[9u8; 16]);
        let hash = good.rsplit('$').next().unwrap();
        let bad = [
            // Parameters out of order, a leading zero, an unknown parameter.
            alloc::format!("$argon2id$v=19$t=1,m=64,p=1${salt}${hash}"),
            alloc::format!("$argon2id$v=19$m=064,t=1,p=1${salt}${hash}"),
            alloc::format!("$argon2id$v=19$m=64,t=1,p=1,x=1${salt}${hash}"),
            // Padding, and a version that does not exist.
            alloc::format!("$argon2id$v=19$m=64,t=1,p=1${salt}==${hash}"),
            alloc::format!("$argon2id$v=18$m=64,t=1,p=1${salt}${hash}"),
            // Trailing field, missing hash, not argon2.
            alloc::format!("{good}$x"),
            alloc::format!("$argon2id$v=19$m=64,t=1,p=1${salt}"),
            alloc::format!("$scrypt$v=19$m=64,t=1,p=1${salt}${hash}"),
        ];
        for s in &bad {
            assert!(PasswordHash::parse(s).is_err(), "{s}");
        }
        // Base64 whose unused bits are not zero: the salt's last character
        // moved up by one in the alphabet decodes to the same bytes.
        let mut chars: Vec<char> = salt.chars().collect();
        let last = chars.last_mut().unwrap();
        *last = (*last as u8 + 1) as char;
        let odd: String = chars.into_iter().collect();
        assert!(b64_decode(&odd).is_err(), "{odd}");
    }

    /// The whole hash is compared, not a prefix: a stored hash changed only
    /// in its last byte does not verify with the right password.
    #[test]
    fn every_byte_of_the_hash_is_compared() {
        let s = hash_password_with(
            Variant::Argon2id,
            Version::V0x13,
            &TINY,
            b"pw",
            &[9u8; 16],
            &[],
            &[],
            &[],
            32,
        )
        .unwrap();
        let mut parsed = PasswordHash::parse(&s).unwrap();
        let last = parsed.hash.len() - 1;
        parsed.hash[last] ^= 1;
        let changed = parsed.encode();
        let err = verify_password(b"pw", &changed).unwrap_err();
        assert_eq!(err.kind(), ic_core::ErrorKind::AuthenticationFailed);
    }

    /// A stored hash is read from somewhere someone else can write. Parsing
    /// any mutation of a real string, or any truncation of it, returns rather
    /// than panicking; and none of the mutants verifies.
    #[test]
    fn parsing_mutated_strings_never_panics() {
        let good = hash_password_with(
            Variant::Argon2id,
            Version::V0x13,
            &TINY,
            b"pw",
            &[9u8; 16],
            &[],
            b"k",
            b"d",
            32,
        )
        .unwrap();
        let bytes = good.as_bytes();
        for len in 0..bytes.len() {
            let _ = PasswordHash::parse(core::str::from_utf8(&bytes[..len]).unwrap());
        }
        // A fixed walk over positions and replacement characters.
        let alphabet = b"$=,0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ+/ -";
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..4000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let mut m = bytes.to_vec();
            let at = (state as usize) % m.len();
            let c = alphabet[(state >> 32) as usize % alphabet.len()];
            if (state >> 20) & 1 == 0 {
                m[at] = c;
            } else {
                m.insert(at, c);
            }
            let s = core::str::from_utf8(&m).unwrap();
            if let Ok(mut parsed) = PasswordHash::parse(s) {
                // Whatever parses must cost no more than the original, or the
                // walk would be hashing gigabytes. Only a string that differs
                // in `keyid` alone may verify: `keyid` names the secret and is
                // not hashed, which is how the format defines it.
                if parsed.params == TINY && verify_password(b"pw", s).is_ok() {
                    parsed.keyid = b"k".to_vec();
                    assert_eq!(parsed.encode(), good, "{s}");
                }
            }
        }
    }

    #[test]
    fn needs_rehash_names_every_shortfall_and_nothing_else() {
        let current = hash_password_with(
            Variant::Argon2id,
            Version::V0x13,
            &TINY,
            b"pw",
            &[9u8; 16],
            b"s",
            b"k2",
            &[],
            32,
        )
        .unwrap();
        assert!(!needs_rehash(&current, Variant::Argon2id, &TINY).unwrap());
        assert!(!needs_rehash_with_keyid(&current, Variant::Argon2id, &TINY, Some(b"k2")).unwrap());
        assert!(needs_rehash_with_keyid(&current, Variant::Argon2id, &TINY, Some(b"k3")).unwrap());
        assert!(needs_rehash(&current, Variant::Argon2i, &TINY).unwrap());
        for stronger in [
            Argon2Params {
                memory_kib: 128,
                ..TINY
            },
            Argon2Params { passes: 2, ..TINY },
            Argon2Params { lanes: 2, ..TINY },
        ] {
            assert!(
                needs_rehash(&current, Variant::Argon2id, &stronger).unwrap(),
                "{stronger:?}"
            );
        }
        // A weaker policy is not a reason to rehash.
        let weaker = Argon2Params {
            memory_kib: 32,
            ..TINY
        };
        assert!(!needs_rehash(&current, Variant::Argon2id, &weaker).unwrap());
        // Version 1.0, a short salt and a short hash each fall short.
        for (version, salt, len) in [
            (Version::V0x10, &[9u8; 16][..], 32),
            (Version::V0x13, &[9u8; 8][..], 32),
            (Version::V0x13, &[9u8; 16][..], 16),
        ] {
            let s = hash_password_with(
                Variant::Argon2id,
                version,
                &TINY,
                b"pw",
                salt,
                &[],
                &[],
                &[],
                len,
            )
            .unwrap();
            assert!(needs_rehash(&s, Variant::Argon2id, &TINY).unwrap(), "{s}");
        }
    }

    #[test]
    fn the_ceiling_refuses_before_deriving() {
        let s = "$argon2id$v=19$m=4294967295,t=4294967295,p=1$CQkJCQkJCQkJCQkJCQkJCQ$CQkJCQ";
        let err = verify_password_bounded(b"pw", s, &Argon2Params::DEFAULT).unwrap_err();
        assert_eq!(err.kind(), ic_core::ErrorKind::InvalidParameter);
    }
}
