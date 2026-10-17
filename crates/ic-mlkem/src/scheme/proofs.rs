//! Bounded proofs of implicit rejection's selection, for Kani.
//!
//! ```text
//! scripts/kani.sh -p ic-mlkem
//! ```
//!
//! Decapsulation compares the re-encrypted ciphertext with the received one
//! (`ic_core::ct::eq`) and selects `K` or the rejection key on the result
//! (`select_key`). `ic-core` proves `eq` for every length up to 6 and
//! `select_u8` for every operand; these prove the 32-byte selection built on
//! them, and `eq` at a ciphertext length.

use super::*;
use ic_core::ct::{self, Choice};

/// `select_key` copies `k` when the choice is true and `reject` otherwise,
/// all 32 bytes, for every `k`, `reject` and choice.
#[kani::proof]
#[kani::unwind(34)]
fn select_key_is_k_when_matched_and_reject_otherwise() {
    let k: [u8; 32] = kani::any();
    let reject: [u8; 32] = kani::any();
    let matched: bool = kani::any();
    let mut out = [0u8; 32];
    select_key(Choice::from_u8(matched as u8), &k, &reject, &mut out);
    assert_eq!(out, if matched { k } else { reject });
}

/// `ct::eq` is slice equality at an ML-KEM-512 ciphertext's length, 768
/// bytes, for every pair. (`ic-core` proves it up to length 6; the loop is
/// the same at any length.)
#[kani::proof]
#[kani::unwind(770)]
fn ct_eq_is_equality_at_768_bytes() {
    let a: [u8; 768] = kani::any();
    let b: [u8; 768] = kani::any();
    assert_eq!(bool::from(ct::eq(&a, &b)), a == b);
}
