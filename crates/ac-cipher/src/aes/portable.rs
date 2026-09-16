//! The portable, constant-time AES backend.
//!
//! Works on every target, computes its S-box algebraically rather than reading
//! a table, and is the reference against which the accelerated backends are
//! differentially tested.

use crate::gf;
use ac_core::{ensure, Result, Zeroize};

/// AES block size in bytes.
pub const BLOCK_LEN: usize = 16;

/// Round keys for the widest schedule (AES-256 has 15).
pub(crate) const MAX_ROUND_KEYS: usize = 15 * BLOCK_LEN;

/// Round-constant sequence for the key schedule, `rcon[i] = x^i` in GF(2^8).
fn rcon(i: usize) -> u8 {
    let mut c = 1u8;
    for _ in 1..i {
        c = gf::xtime(c);
    }
    c
}

/// An expanded AES key schedule.
///
/// This is the *only* key expansion in the library. The accelerated backends
/// consume its output rather than reimplementing it: expansion happens once per
/// key and is not on the hot path, so there is nothing to gain from a second
/// implementation and a subtle divergence to lose.
///
/// Dropping the schedule zeroizes it, so round keys never outlive the value.
#[derive(Clone)]
pub struct Schedule {
    round_keys: [u8; MAX_ROUND_KEYS],
    pub(crate) rounds: usize,
}

impl Drop for Schedule {
    fn drop(&mut self) {
        self.round_keys.zeroize();
    }
}

impl Schedule {
    /// Expand a 16, 24, or 32 byte key.
    pub fn expand(key: &[u8]) -> Result<Self> {
        let nk = key.len() / 4;
        let rounds = match key.len() {
            16 => 10,
            24 => 12,
            32 => 14,
            _ => {
                return Err(ac_core::err!(
                    InvalidLength,
                    "aes key must be 16, 24, or 32 bytes"
                ))
            }
        };
        let total_words = (rounds + 1) * 4;
        let mut rk = [0u8; MAX_ROUND_KEYS];
        rk[..key.len()].copy_from_slice(key);

        for i in nk..total_words {
            let mut t = [
                rk[(i - 1) * 4],
                rk[(i - 1) * 4 + 1],
                rk[(i - 1) * 4 + 2],
                rk[(i - 1) * 4 + 3],
            ];
            if i % nk == 0 {
                t.rotate_left(1);
                for b in t.iter_mut() {
                    *b = gf::sbox(*b);
                }
                t[0] ^= rcon(i / nk);
            } else if nk > 6 && i % nk == 4 {
                for b in t.iter_mut() {
                    *b = gf::sbox(*b);
                }
            }
            for j in 0..4 {
                rk[i * 4 + j] = rk[(i - nk) * 4 + j] ^ t[j];
            }
        }
        Ok(Self {
            round_keys: rk,
            rounds,
        })
    }

    /// The round key for round `round`.
    #[inline]
    pub(crate) fn round_key(&self, round: usize) -> &[u8] {
        &self.round_keys[round * BLOCK_LEN..(round + 1) * BLOCK_LEN]
    }
}

#[inline]
fn add_round_key(state: &mut [u8; BLOCK_LEN], rk: &[u8]) {
    for i in 0..BLOCK_LEN {
        state[i] ^= rk[i];
    }
}

#[inline]
fn sub_bytes(state: &mut [u8; BLOCK_LEN]) {
    for b in state.iter_mut() {
        *b = gf::sbox(*b);
    }
}

#[inline]
fn inv_sub_bytes(state: &mut [u8; BLOCK_LEN]) {
    for b in state.iter_mut() {
        *b = gf::inv_sbox(*b);
    }
}

/// ShiftRows on the column-major AES state: row `r` rotates left by `r`.
#[inline]
fn shift_rows(s: &mut [u8; BLOCK_LEN]) {
    let t = *s;
    for c in 0..4 {
        for r in 0..4 {
            s[c * 4 + r] = t[((c + r) % 4) * 4 + r];
        }
    }
}

#[inline]
fn inv_shift_rows(s: &mut [u8; BLOCK_LEN]) {
    let t = *s;
    for c in 0..4 {
        for r in 0..4 {
            s[((c + r) % 4) * 4 + r] = t[c * 4 + r];
        }
    }
}

#[inline]
fn mix_columns(s: &mut [u8; BLOCK_LEN]) {
    for c in 0..4 {
        let col = [s[c * 4], s[c * 4 + 1], s[c * 4 + 2], s[c * 4 + 3]];
        s[c * 4] = gf::xtime(col[0]) ^ (gf::xtime(col[1]) ^ col[1]) ^ col[2] ^ col[3];
        s[c * 4 + 1] = col[0] ^ gf::xtime(col[1]) ^ (gf::xtime(col[2]) ^ col[2]) ^ col[3];
        s[c * 4 + 2] = col[0] ^ col[1] ^ gf::xtime(col[2]) ^ (gf::xtime(col[3]) ^ col[3]);
        s[c * 4 + 3] = (gf::xtime(col[0]) ^ col[0]) ^ col[1] ^ col[2] ^ gf::xtime(col[3]);
    }
}

#[inline]
fn inv_mix_columns(s: &mut [u8; BLOCK_LEN]) {
    for c in 0..4 {
        let col = [s[c * 4], s[c * 4 + 1], s[c * 4 + 2], s[c * 4 + 3]];
        s[c * 4] =
            gf::mul(col[0], 14) ^ gf::mul(col[1], 11) ^ gf::mul(col[2], 13) ^ gf::mul(col[3], 9);
        s[c * 4 + 1] =
            gf::mul(col[0], 9) ^ gf::mul(col[1], 14) ^ gf::mul(col[2], 11) ^ gf::mul(col[3], 13);
        s[c * 4 + 2] =
            gf::mul(col[0], 13) ^ gf::mul(col[1], 9) ^ gf::mul(col[2], 14) ^ gf::mul(col[3], 11);
        s[c * 4 + 3] =
            gf::mul(col[0], 11) ^ gf::mul(col[1], 13) ^ gf::mul(col[2], 9) ^ gf::mul(col[3], 14);
    }
}

/// Encrypt one block in place.
pub fn encrypt_block(sched: &Schedule, block: &mut [u8]) -> Result<()> {
    ensure!(block.len() == BLOCK_LEN, InvalidLength, "aes block");
    let mut s = [0u8; BLOCK_LEN];
    s.copy_from_slice(block);
    add_round_key(&mut s, sched.round_key(0));
    for r in 1..sched.rounds {
        sub_bytes(&mut s);
        shift_rows(&mut s);
        mix_columns(&mut s);
        add_round_key(&mut s, sched.round_key(r));
    }
    sub_bytes(&mut s);
    shift_rows(&mut s);
    add_round_key(&mut s, sched.round_key(sched.rounds));
    block.copy_from_slice(&s);
    s.zeroize();
    Ok(())
}

/// Decrypt one block in place.
pub fn decrypt_block(sched: &Schedule, block: &mut [u8]) -> Result<()> {
    ensure!(block.len() == BLOCK_LEN, InvalidLength, "aes block");
    let mut s = [0u8; BLOCK_LEN];
    s.copy_from_slice(block);
    add_round_key(&mut s, sched.round_key(sched.rounds));
    for r in (1..sched.rounds).rev() {
        inv_shift_rows(&mut s);
        inv_sub_bytes(&mut s);
        add_round_key(&mut s, sched.round_key(r));
        inv_mix_columns(&mut s);
    }
    inv_shift_rows(&mut s);
    inv_sub_bytes(&mut s);
    add_round_key(&mut s, sched.round_key(0));
    block.copy_from_slice(&s);
    s.zeroize();
    Ok(())
}
