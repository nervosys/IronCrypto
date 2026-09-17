//! The ARMv8 AES round structure, shared by the real backend and its model.
//!
//! # Why this is a macro
//!
//! The backend in [`super::aarch64`] cannot be executed on the machine it was
//! written on, so its round structure is checked instead by
//! [`super::armv8_model`], which emulates `AESE`, `AESMC`, `AESD` and `AESIMC`
//! from their FIPS 197 definitions and compares the result against the portable
//! backend. That check is only worth anything if the model and the backend
//! share *the same structure* — write them separately and the likely outcome is
//! a correct model beside an incorrect backend, with a green test.
//!
//! A macro shares it textually, with no trait, no associated types, and no
//! trouble from the fact that the real operations are `unsafe fn` carrying
//! `#[target_feature]` while the emulated ones are ordinary safe functions. The
//! expansion inherits whatever context it is written in.
//!
//! # The structure itself
//!
//! ARM divides the round differently from x86, and this is where a careless
//! translation goes wrong:
//!
//! - `AESE(state, key)` adds the round key **first**, then SubBytes and
//!   ShiftRows. x86's `AESENC` does the substitution first and adds the key
//!   last.
//! - `AESMC` is a separate instruction; x86 folds MixColumns into `AESENC`.
//! - The final round therefore needs a bare `AESE` followed by an explicit XOR
//!   of the last round key, which x86 gets for free from `AESENCLAST`.
//!
//! Decryption mirrors it, with the round keys in plain reverse order and
//! `AESIMC` applied to the **state** rather than pre-applied to the keys as the
//! x86 equivalent inverse cipher does. Doing both would invert twice.

/// Encryption rounds: `AESMC(AESE(state, rk[r]))`, then a bare `AESE`, then a
/// final XOR.
///
/// `$b` is the state, `$rk` the round keys indexed from zero, `$rounds` the
/// round count, and the last three are the operations to use.
macro_rules! armv8_encrypt_rounds {
    ($b:expr, $rk:expr, $rounds:expr, $aese:path, $aesmc:path, $xor:path) => {{
        let mut b = $b;
        for r in 0..$rounds - 1 {
            b = $aesmc($aese(b, $rk[r]));
        }
        b = $aese(b, $rk[$rounds - 1]);
        $xor(b, $rk[$rounds])
    }};
}

/// Decryption rounds, the mirror of the above.
///
/// `$dk` must be the round keys in plain reverse order: `dk[i] = rk[rounds-i]`,
/// with no `AESIMC` pre-applied.
macro_rules! armv8_decrypt_rounds {
    ($b:expr, $dk:expr, $rounds:expr, $aesd:path, $aesimc:path, $xor:path) => {{
        let mut b = $b;
        for r in 0..$rounds - 1 {
            b = $aesimc($aesd(b, $dk[r]));
        }
        b = $aesd(b, $dk[$rounds - 1]);
        $xor(b, $dk[$rounds])
    }};
}

pub(crate) use {armv8_decrypt_rounds, armv8_encrypt_rounds};
