//! `verify` against hostile input.
//!
//! Verification is the only function here that parses bytes an attacker
//! chooses. Everything it touches — the challenge digest, the packed `z`, the
//! hint block — arrives in a signature, and a signature is exactly what someone
//! trying to break this would hand over.
//!
//! Two properties, and a third that exists to stop the first two being
//! vacuous:
//!
//! - **Total.** `verify` returns for every input. It never panics, never
//!   indexes out of range, never overflows. In a `no_std` deployment a panic is
//!   not an exception to catch, it is the end of the program, so "returns
//!   false" and "aborts" are very different answers to a malformed signature.
//! - **Sound.** Nothing but the signature that was produced verifies. Not a
//!   mutation of it, not a re-ordering of its hint block, not random bytes.
//! - **Deep.** Enough of the hostile input survives the cheap early rejections
//!   to actually exercise the hint reconstruction and the digest comparison.
//!   Without this, a fuzzer that was rejected on length every time would pass
//!   both properties above while testing nothing — which is precisely how the
//!   PKIX fuzzer managed to prove nothing on its first attempt.
//!
//! This says nothing about whether the scheme is *correct*; that still needs a
//! vector. It says the parser cannot be made to misbehave, which is a different
//! question and one that can be settled here.

use ac_mldsa::encode::{bit_unpack, hint_unpack, z_bits};
use ac_mldsa::poly::{Poly, N};
use ac_mldsa::sign::{
    keygen, sign_deterministic, verify, BETA, C_TILDE_LEN, GAMMA1, K, L, OMEGA, PUBLIC_KEY_LEN,
    SECRET_KEY_LEN, SIGNATURE_LEN,
};

/// SplitMix64. Deterministic, so any failure reproduces exactly.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64)) as usize
    }

    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
}

fn keypair(seed: u8) -> ([u8; PUBLIC_KEY_LEN], [u8; SECRET_KEY_LEN]) {
    let mut xi = [0u8; 32];
    for (i, b) in xi.iter_mut().enumerate() {
        *b = seed.wrapping_mul(13).wrapping_add(i as u8);
    }
    let mut pk = [0u8; PUBLIC_KEY_LEN];
    let mut sk = [0u8; SECRET_KEY_LEN];
    assert!(
        keygen(&xi, &mut pk, &mut sk),
        "keygen consistency test failed"
    );
    (pk, sk)
}

/// How far into `verify` a candidate gets before the cheap checks stop it.
///
/// This mirrors the two gates `verify` applies before doing any real work, so
/// the test can measure its own reach without the implementation having to
/// expose anything. If either of these ever stops matching `verify`, the depth
/// assertion below becomes optimistic rather than wrong — so the test also
/// checks that a genuine signature reports full depth.
fn reaches_the_expensive_part(sig: &[u8; SIGNATURE_LEN]) -> bool {
    let mut at = C_TILDE_LEN;
    for _ in 0..L {
        let mut p = Poly::ZERO;
        bit_unpack(
            &sig[at..at + 32 * z_bits(GAMMA1) as usize],
            GAMMA1,
            z_bits(GAMMA1),
            &mut p,
        );
        at += 32 * z_bits(GAMMA1) as usize;
        p.reduce();
        if p.exceeds(GAMMA1 - BETA) {
            return false;
        }
    }
    let mut hints = [[false; N]; K];
    hint_unpack(&sig[at..at + OMEGA + K], OMEGA, &mut hints)
}

/// Arbitrary bytes must be refused without incident.
#[test]
fn verification_is_total_on_random_bytes() {
    let (pk, _) = keypair(1);
    let mut rng = Rng(0xf0f0_1234);

    for _ in 0..200 {
        let mut sig = [0u8; SIGNATURE_LEN];
        for b in sig.iter_mut() {
            *b = rng.byte();
        }
        assert!(
            !verify(&pk, b"message", b"", &sig),
            "random bytes verified as a signature"
        );
    }
}

/// All-zero and all-ones inputs, which random sampling essentially never
/// produces and which sit exactly on the boundaries the decoders check.
#[test]
fn verification_is_total_on_degenerate_inputs() {
    let (pk, _) = keypair(2);
    for fill in [0x00u8, 0xff, 0x80, 0x01] {
        let sig = [fill; SIGNATURE_LEN];
        assert!(
            !verify(&pk, b"m", b"", &sig),
            "a constant signature verified"
        );
        assert!(!verify(&pk, b"", b"", &sig));
        assert!(!verify(&pk, &[fill; 300], &[fill; 255], &sig));
    }
}

/// The real test: mutations of a *valid* signature.
///
/// These get past the length and bounds checks most of the time, so they reach
/// the hint reconstruction, the matrix multiply and the digest comparison —
/// the code that random bytes never touch.
#[test]
fn no_mutation_of_a_valid_signature_verifies() {
    let (pk, sk) = keypair(3);
    let message = b"the message that was actually signed";
    let mut good = [0u8; SIGNATURE_LEN];
    assert!(sign_deterministic(&sk, message, b"", &mut good));
    assert!(verify(&pk, message, b"", &good), "the baseline must verify");
    assert!(
        reaches_the_expensive_part(&good),
        "a valid signature must report full depth, or the depth measure is wrong"
    );

    let mut rng = Rng(0x1234_5678);
    let mut deep = 0usize;
    const TRIALS: usize = 400;

    for trial in 0..TRIALS {
        let mut bad = good;
        match trial % 4 {
            // A single flipped bit, anywhere.
            0 => {
                let at = rng.below(SIGNATURE_LEN);
                bad[at] ^= 1 << rng.below(8);
            }
            // A byte replaced outright.
            1 => {
                let at = rng.below(SIGNATURE_LEN);
                bad[at] = rng.byte();
            }
            // Two bytes swapped, which preserves every byte-multiset check.
            2 => {
                let a = rng.below(SIGNATURE_LEN);
                let b = rng.below(SIGNATURE_LEN);
                bad.swap(a, b);
            }
            // A small change confined to the hint block, where the canonicity
            // rules live.
            _ => {
                let at = C_TILDE_LEN + L * 32 * z_bits(GAMMA1) as usize + rng.below(OMEGA + K);
                bad[at] = rng.byte();
            }
        }
        if bad == good {
            continue;
        }

        if reaches_the_expensive_part(&bad) {
            deep += 1;
        }
        assert!(
            !verify(&pk, message, b"", &bad),
            "a mutated signature verified, trial {trial}"
        );
    }

    // Without this the test could be passing because every mutant was thrown
    // out on a length or bounds check, having exercised nothing.
    // The measured figure with this seed is 305 of 400. The guard is set at
    // half rather than at a token ten percent: a threshold far below the real
    // value would still pass after a regression that gutted the reach, which
    // would leave this test looking healthy while testing almost nothing.
    println!("{deep} of {TRIALS} mutants reached the expensive path");
    assert!(
        deep > TRIALS / 2,
        "too few mutants reached the expensive path: {deep} of {TRIALS}"
    );
}

/// A valid signature under the wrong message, key or context must fail, and
/// must fail for the right reason: it should get all the way to the digest
/// comparison rather than being caught by a bounds check.
#[test]
fn a_valid_signature_fails_deeply_under_the_wrong_inputs() {
    let (pk, sk) = keypair(4);
    let (other_pk, _) = keypair(5);
    let mut sig = [0u8; SIGNATURE_LEN];
    assert!(sign_deterministic(&sk, b"original", b"ctx", &mut sig));

    // The signature is well-formed in all of these; only the binding is wrong.
    assert!(reaches_the_expensive_part(&sig));
    assert!(!verify(&pk, b"different", b"ctx", &sig));
    assert!(!verify(&pk, b"original", b"other", &sig));
    assert!(!verify(&other_pk, b"original", b"ctx", &sig));
    assert!(
        verify(&pk, b"original", b"ctx", &sig),
        "and the original still works"
    );
}

/// A truncated or extended context is not silently accepted.
///
/// The context is length-prefixed with a single byte, so 255 is a hard ceiling
/// and the answer at 256 must be refusal rather than a wrapped length that
/// would make two different contexts encode identically.
#[test]
fn the_context_ceiling_is_enforced_on_both_sides() {
    let (pk, sk) = keypair(6);
    let mut sig = [0u8; SIGNATURE_LEN];

    assert!(sign_deterministic(&sk, b"m", &[1u8; 255], &mut sig));
    assert!(verify(&pk, b"m", &[1u8; 255], &sig));

    let mut overlong = [0u8; SIGNATURE_LEN];
    assert!(
        !sign_deterministic(&sk, b"m", &[1u8; 256], &mut overlong),
        "signing must refuse a 256-byte context"
    );
    assert!(
        !verify(&pk, b"m", &[1u8; 256], &sig),
        "verification must refuse a 256-byte context"
    );

    // 255 and 256 must not collide through a truncated length byte.
    assert!(!verify(&pk, b"m", &[1u8; 254], &sig));
}

/// Every hint block that verification accepts must be one signing could emit.
///
/// `hint_unpack` is tested in isolation, but this checks the property survives
/// being wired into `verify`: a hint block that decodes but is not canonical
/// must not be rescued by anything downstream.
#[test]
fn verification_inherits_the_hint_canonicity_rules() {
    let (pk, sk) = keypair(7);
    let mut good = [0u8; SIGNATURE_LEN];
    assert!(sign_deterministic(&sk, b"canon", b"", &mut good));
    assert!(verify(&pk, b"canon", b"", &good));

    let hint_at = C_TILDE_LEN + L * 32 * z_bits(GAMMA1) as usize;
    let used = good[hint_at + OMEGA + K - 1] as usize;

    let mut rng = Rng(0xbeef);
    for _ in 0..100 {
        let mut bad = good;
        // Write a nonzero byte into the unused padding region, which decodes to
        // exactly the same hint vector and must still be refused.
        if used < OMEGA {
            let at = hint_at + used + rng.below(OMEGA - used);
            bad[at] = 1 + rng.byte() % 255;
            let mut hints = [[false; N]; K];
            assert!(
                !hint_unpack(&bad[hint_at..hint_at + OMEGA + K], OMEGA, &mut hints),
                "padded hint block was accepted by the decoder"
            );
            assert!(
                !verify(&pk, b"canon", b"", &bad),
                "padded hint block was accepted by verify"
            );
        }
    }
}
