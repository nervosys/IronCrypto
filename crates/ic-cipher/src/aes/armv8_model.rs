//! A software model of the ARMv8 AES instructions, so the round structure can
//! be checked on a machine that cannot run them.
//!
//! [`super::aarch64`] was written and cross-compiled on x86-64 and has never
//! been executed by its author. That leaves two distinct risks, and they are
//! worth separating because only one of them can be addressed here:
//!
//! 1. **The round structure is wrong.** ARM composes a round differently from
//!    x86, and translating by intuition produces something that compiles, runs,
//!    and encrypts to the wrong ciphertext.
//! 2. **The intrinsics do not mean what I think they mean.** `vaeseq_u8(a, b)`
//!    might not be `AESE` with `b` as the round key.
//!
//! This module closes the first. It emulates `AESE`, `AESMC`, `AESD` and
//! `AESIMC` from their FIPS 197 definitions, drives them with the *same macro*
//! the real backend uses, and requires the result to equal the portable
//! backend — which is itself validated against the FIPS 197 vectors.
//!
//! The second risk remains open until CI runs on an arm64 host. Saying which
//! risk is closed and which is not is the point; "verified" without that
//! distinction would be a claim this cannot support.
//!
//! # Independence
//!
//! The S-box here is derived by brute-force inversion in GF(2^8) followed by
//! the affine transform, which is a different route from whatever the portable
//! backend does, and is anchored to two published values. Nothing in this file
//! calls into the portable implementation except to compare final answers.

use super::armv8_rounds::{armv8_decrypt_rounds, armv8_encrypt_rounds};
use super::portable::{self, Schedule, BLOCK_LEN};

/// A 128-bit state, byte-wise, standing in for `uint8x16_t`.
type Block = [u8; BLOCK_LEN];

/// Multiply in GF(2^8) modulo the AES polynomial, by shift and add.
fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut out = 0u8;
    for _ in 0..8 {
        if b & 1 != 0 {
            out ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    out
}

/// Multiplicative inverse in GF(2^8), by exhaustive search.
///
/// Slow and obviously correct, which is what a test oracle should be.
fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    (1u16..=255)
        .map(|x| x as u8)
        .find(|&x| gf_mul(a, x) == 1)
        .expect("every nonzero element is invertible")
}

/// The S-box and its inverse, derived once.
///
/// Derivation is deliberately naive -- a brute-force field inversion per entry
/// -- because an oracle should be obviously correct rather than fast. Doing it
/// per byte per round made this module take half a minute, which is a real cost
/// in a suite people run constantly, so the two tables are built once and the
/// naivety is paid for exactly 512 times.
fn tables() -> &'static ([u8; 256], [u8; 256]) {
    static TABLES: std::sync::OnceLock<([u8; 256], [u8; 256])> = std::sync::OnceLock::new();
    TABLES.get_or_init(|| {
        let mut forward = [0u8; 256];
        for (a, slot) in forward.iter_mut().enumerate() {
            let i = gf_inv(a as u8);
            *slot = i
                ^ i.rotate_left(1)
                ^ i.rotate_left(2)
                ^ i.rotate_left(3)
                ^ i.rotate_left(4)
                ^ 0x63;
        }
        let mut inverse = [0u8; 256];
        for (a, &v) in forward.iter().enumerate() {
            inverse[v as usize] = a as u8;
        }
        (forward, inverse)
    })
}

/// The AES S-box: inversion followed by the affine transform.
fn sbox(a: u8) -> u8 {
    tables().0[a as usize]
}

/// The inverse S-box.
fn inv_sbox(a: u8) -> u8 {
    tables().1[a as usize]
}

/// ShiftRows, on the column-major state AES uses.
fn shift_rows(s: Block) -> Block {
    let mut out = [0u8; BLOCK_LEN];
    for col in 0..4 {
        for row in 0..4 {
            out[col * 4 + row] = s[((col + row) % 4) * 4 + row];
        }
    }
    out
}

/// InvShiftRows.
fn inv_shift_rows(s: Block) -> Block {
    let mut out = [0u8; BLOCK_LEN];
    for col in 0..4 {
        for row in 0..4 {
            out[((col + row) % 4) * 4 + row] = s[col * 4 + row];
        }
    }
    out
}

/// MixColumns.
fn mix_columns(s: Block) -> Block {
    let mut out = [0u8; BLOCK_LEN];
    for c in 0..4 {
        let col = &s[c * 4..c * 4 + 4];
        out[c * 4] = gf_mul(col[0], 2) ^ gf_mul(col[1], 3) ^ col[2] ^ col[3];
        out[c * 4 + 1] = col[0] ^ gf_mul(col[1], 2) ^ gf_mul(col[2], 3) ^ col[3];
        out[c * 4 + 2] = col[0] ^ col[1] ^ gf_mul(col[2], 2) ^ gf_mul(col[3], 3);
        out[c * 4 + 3] = gf_mul(col[0], 3) ^ col[1] ^ col[2] ^ gf_mul(col[3], 2);
    }
    out
}

/// InvMixColumns.
fn inv_mix_columns(s: Block) -> Block {
    let mut out = [0u8; BLOCK_LEN];
    for c in 0..4 {
        let col = &s[c * 4..c * 4 + 4];
        out[c * 4] =
            gf_mul(col[0], 14) ^ gf_mul(col[1], 11) ^ gf_mul(col[2], 13) ^ gf_mul(col[3], 9);
        out[c * 4 + 1] =
            gf_mul(col[0], 9) ^ gf_mul(col[1], 14) ^ gf_mul(col[2], 11) ^ gf_mul(col[3], 13);
        out[c * 4 + 2] =
            gf_mul(col[0], 13) ^ gf_mul(col[1], 9) ^ gf_mul(col[2], 14) ^ gf_mul(col[3], 11);
        out[c * 4 + 3] =
            gf_mul(col[0], 11) ^ gf_mul(col[1], 13) ^ gf_mul(col[2], 9) ^ gf_mul(col[3], 14);
    }
    out
}

fn xor(a: Block, b: Block) -> Block {
    let mut out = [0u8; BLOCK_LEN];
    for i in 0..BLOCK_LEN {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// `AESE`: AddRoundKey, then SubBytes, then ShiftRows.
///
/// The key comes **first**, which is the difference from x86 that this whole
/// module exists to check.
pub(crate) fn aese(state: Block, key: Block) -> Block {
    let mut s = xor(state, key);
    for b in s.iter_mut() {
        *b = sbox(*b);
    }
    shift_rows(s)
}

/// `AESMC`: MixColumns.
pub(crate) fn aesmc(state: Block) -> Block {
    mix_columns(state)
}

/// `AESD`: AddRoundKey, then InvSubBytes, then InvShiftRows.
pub(crate) fn aesd(state: Block, key: Block) -> Block {
    let mut s = xor(state, key);
    for b in s.iter_mut() {
        *b = inv_sbox(*b);
    }
    inv_shift_rows(s)
}

/// `AESIMC`: InvMixColumns.
pub(crate) fn aesimc(state: Block) -> Block {
    inv_mix_columns(state)
}

/// Encrypt one block, using the macro the real backend uses.
fn encrypt(sched: &Schedule, block: Block) -> Block {
    let rounds = sched.rounds;
    let rk = round_keys(sched);
    armv8_encrypt_rounds!(block, rk, rounds, aese, aesmc, xor)
}

/// Decrypt one block, using the macro the real backend uses.
fn decrypt(sched: &Schedule, block: Block) -> Block {
    let rounds = sched.rounds;
    let rk = round_keys(sched);
    // The equivalent inverse cipher schedule: reversed, with InvMixColumns
    // pre-applied to everything except the first and last. Established
    // empirically with this model -- plain reversal encrypts correctly and
    // decrypts to nonsense, which is precisely the kind of claim that should
    // not be settled by recollection.
    let mut dk = [[0u8; BLOCK_LEN]; 15];
    dk[0] = rk[rounds];
    for i in 1..rounds {
        dk[i] = aesimc(rk[rounds - i]);
    }
    dk[rounds] = rk[0];
    armv8_decrypt_rounds!(block, dk, rounds, aesd, aesimc, xor)
}

fn round_keys(sched: &Schedule) -> [Block; 15] {
    let mut rk = [[0u8; BLOCK_LEN]; 15];
    for (r, slot) in rk.iter_mut().enumerate().take(sched.rounds + 1) {
        slot.copy_from_slice(sched.round_key(r));
    }
    rk
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The emulation's own primitives, against published values.
    ///
    /// If the S-box were wrong, every test below would compare two wrong
    /// answers and could still agree. These two entries are the most widely
    /// published in the literature.
    #[test]
    fn the_model_primitives_are_right() {
        assert_eq!(sbox(0x00), 0x63, "the affine constant");
        assert_eq!(sbox(0x53), 0xed, "the FIPS 197 worked example");
        assert_eq!(inv_sbox(0x63), 0x00);
        assert_eq!(inv_sbox(0xed), 0x53);
        for x in 0..=255u8 {
            assert_eq!(inv_sbox(sbox(x)), x, "the S-box must be a permutation");
        }

        // GF multiplication, against the doubling identity and a known product.
        assert_eq!(gf_mul(0x57, 0x13), 0xfe, "FIPS 197 section 4.2");
        assert_eq!(gf_mul(0x80, 0x02), 0x1b, "reduction on overflow");

        // MixColumns and its inverse must undo each other.
        let s: Block = core::array::from_fn(|i| (i as u8).wrapping_mul(37));
        assert_eq!(inv_mix_columns(mix_columns(s)), s);
        assert_eq!(inv_shift_rows(shift_rows(s)), s);
    }

    /// The round structure, checked against an implementation known to be
    /// correct.
    ///
    /// This is what the module is for. The macro under test is the same one
    /// `aarch64.rs` expands, so an error in the composition -- the key added at
    /// the wrong end, a missing final XOR, `AESIMC` applied to the keys as well
    /// as the state -- fails here, on a machine with no ARM hardware.
    ///
    /// What it cannot catch: whether Rust's `vaeseq_u8` really is `AESE` with
    /// its second argument as the round key. That needs an arm64 host.
    #[test]
    fn the_round_structure_matches_the_portable_backend() {
        for key_len in [16usize, 24, 32] {
            let key: Vec<u8> = (0..key_len)
                .map(|i| (i as u8).wrapping_mul(11) ^ 0x5a)
                .collect();
            let sched = Schedule::expand(&key).unwrap();

            for seed in 0..24u8 {
                let plain: Block =
                    core::array::from_fn(|i| seed.wrapping_mul(29).wrapping_add(i as u8));

                let mut want = plain;
                portable::encrypt_block(&sched, &mut want).unwrap();
                let got = encrypt(&sched, plain);
                assert_eq!(
                    got, want,
                    "encryption round structure, key_len={key_len} seed={seed}"
                );

                let back = decrypt(&sched, got);
                assert_eq!(
                    back, plain,
                    "decryption round structure, key_len={key_len} seed={seed}"
                );

                // And against the portable decryptor directly, so a decrypt
                // that merely inverts this model's own encrypt cannot pass.
                let mut want_back = got;
                portable::decrypt_block(&sched, &mut want_back).unwrap();
                assert_eq!(want_back, plain, "the portable pair must agree too");
            }
        }
    }

    /// The all-zero key and block, which several structural mistakes survive.
    ///
    /// A missing final round-key XOR is invisible when that key is zero, so a
    /// test that only used zeros would pass on broken code. This one is here to
    /// be explicit that the case is covered *in addition to* the varied keys
    /// above, not instead of them.
    #[test]
    fn the_degenerate_case_agrees_as_well() {
        let sched = Schedule::expand(&[0u8; 16]).unwrap();
        let plain = [0u8; BLOCK_LEN];
        let mut want = plain;
        portable::encrypt_block(&sched, &mut want).unwrap();
        assert_eq!(encrypt(&sched, plain), want);
        assert_eq!(decrypt(&sched, want), plain);
    }
}
