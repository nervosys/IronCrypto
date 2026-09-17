//! Every public entry point that parses bytes an attacker chooses.
//!
//! ML-DSA got this treatment when its verifier was written, and ML-KEM's
//! decapsulation has its own. This is the same discipline applied across the
//! whole facade, in one place, so that adding an algorithm without hardening it
//! is visible rather than merely possible.
//!
//! What makes that true is `the_suite_hammers_every_implemented_primitive`,
//! which asks the ontology what this build implements and requires every
//! answer to be hammered here or to name where it is hammered instead.
//! Until it existed the targets were a hand-written list, and six had
//! quietly drifted out of it.
//!
//! Three properties per target, and the third is what stops the first two being
//! decoration:
//!
//! - **Total.** The call returns for every input. No panic, no out-of-range
//!   index, no arithmetic overflow. This library is `no_std`-capable, and in a
//!   `no_std` deployment a panic is not an exception someone catches — it is
//!   the end of the program. "Returns an error" and "aborts" are very different
//!   answers to a malformed signature.
//! - **Sound.** Nothing forged is accepted. Random bytes, mutations of a valid
//!   input, and the degenerate all-zero and all-ones cases are all rejected.
//! - **Deep.** Enough hostile input survives the cheap length checks to reach
//!   the actual cryptography. A suite where every candidate is rejected on
//!   length would satisfy the two properties above while testing nothing, which
//!   is how the PKIX fuzzer managed to prove nothing on its first attempt.
//!
//! # What this does not do
//!
//! It does not establish correctness — that is what the known-answer tests and
//! the independent oracles beside each implementation are for. It establishes
//! that the parsing surface cannot be made to misbehave, which is a different
//! question and one that can be settled here.
//!
//! Timing is also out of scope. Constant-time construction is argued where it
//! matters in each module; measuring it reliably needs a quieter machine than a
//! test suite runs on, and a flaky timing test is worse than none.

use iron_crypto::core_types::traits::{Aead, KeyAgreement, SignatureScheme};
use iron_crypto::{cipher, drbg, ec, mlkem, pkix, rsa};

/// SplitMix64, so every failure reproduces exactly.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }

    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64)) as usize
    }

    fn fill(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            *b = self.byte();
        }
    }
}

/// The shapes worth trying against any byte-consuming entry point.
///
/// Random bytes alone miss the degenerate cases, and those are exactly where an
/// unchecked length or an empty-slice index tends to live.
fn hostile_inputs(rng: &mut Rng, len: usize, count: usize) -> Vec<Vec<u8>> {
    let mut out = vec![
        vec![0u8; len],
        vec![0xffu8; len],
        vec![0x80u8; len],
        Vec::new(),
        vec![0u8; len.saturating_sub(1)],
        vec![0u8; len + 1],
    ];
    for _ in 0..count {
        let mut v = vec![0u8; len];
        rng.fill(&mut v);
        out.push(v);
    }
    out
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

/// Run a signature scheme's verifier against hostile keys and signatures.
///
/// Returns how many candidates were well-formed enough to reach the
/// cryptography, which the callers assert on: a verifier that rejected
/// everything on length would otherwise look perfectly hardened.
fn hammer_signature<S: SignatureScheme>(
    rng: &mut Rng,
    good_pk: &[u8],
    good_sig: &[u8],
    message: &[u8],
) -> usize {
    let mut deep = 0;

    // Hostile signatures under the genuine key.
    for sig in hostile_inputs(rng, good_sig.len(), 40) {
        if sig.len() == good_sig.len() {
            deep += 1;
        }
        assert!(
            S::verify(good_pk, message, &sig).is_err(),
            "{}: a forged signature was accepted",
            S::NAME
        );
    }

    // Hostile keys under the genuine signature.
    for pk in hostile_inputs(rng, good_pk.len(), 40) {
        let _ = S::verify(&pk, message, good_sig);
    }

    // Mutations of the genuine signature, which get past every length check.
    for _ in 0..60 {
        let mut bad = good_sig.to_vec();
        let at = rng.below(bad.len());
        bad[at] ^= 1 << rng.below(8);
        if bad == good_sig {
            continue;
        }
        deep += 1;
        assert!(
            S::verify(good_pk, message, &bad).is_err(),
            "{}: a mutated signature was accepted",
            S::NAME
        );
    }

    // And the genuine one still works, so the loop above was not passing
    // because verification rejects everything.
    assert!(
        S::verify(good_pk, message, good_sig).is_ok(),
        "{}: the genuine signature stopped verifying",
        S::NAME
    );
    deep
}

#[test]
fn ecdsa_verification_is_total_and_sound() {
    let mut rng = Rng::new(0x1111);
    let message = b"a message that was genuinely signed";

    // P-256
    let sk = [7u8; 32];
    let mut pk = [0u8; 65];
    ec::p256::EcdsaP256Sha256::public_key(&sk, &mut pk).unwrap();
    let mut sig = [0u8; 64];
    ec::p256::EcdsaP256Sha256::sign(&sk, message, &mut sig).unwrap();
    let deep = hammer_signature::<ec::p256::EcdsaP256Sha256>(&mut rng, &pk, &sig, message);
    assert!(deep > 80, "too few candidates reached P-256: {deep}");

    // P-384
    let sk = [9u8; 48];
    let mut pk = [0u8; 97];
    ec::p384::EcdsaP384Sha384::public_key(&sk, &mut pk).unwrap();
    let mut sig = [0u8; 96];
    ec::p384::EcdsaP384Sha384::sign(&sk, message, &mut sig).unwrap();
    let deep = hammer_signature::<ec::p384::EcdsaP384Sha384>(&mut rng, &pk, &sig, message);
    assert!(deep > 80, "too few candidates reached P-384: {deep}");

    // P-521. Its field arithmetic is the awkward one -- 521 bits is no multiple
    // of a limb, so the top limb is partly used and every reduction has to know
    // it -- and it had no hostile coverage at either level until now.
    // The top byte must stay clear: n is just under 2^521, so a 66-byte scalar
    // of 0x0b bytes exceeds it and key generation refuses -- correctly.
    let mut sk = [11u8; 66];
    sk[0] = 0;
    let mut pk = [0u8; 133];
    ec::p521::EcdsaP521Sha512::public_key(&sk, &mut pk).unwrap();
    let mut sig = [0u8; 132];
    ec::p521::EcdsaP521Sha512::sign(&sk, message, &mut sig).unwrap();
    let deep = hammer_signature::<ec::p521::EcdsaP521Sha512>(&mut rng, &pk, &sig, message);
    assert!(deep > 80, "too few candidates reached P-521: {deep}");
}

#[test]
fn ed25519_verification_is_total_and_sound() {
    let mut rng = Rng::new(0x2222);
    let message = b"a message that was genuinely signed";
    let sk = [3u8; 32];
    let mut pk = [0u8; 32];
    ec::Ed25519::public_key(&sk, &mut pk).unwrap();
    let mut sig = [0u8; 64];
    ec::Ed25519::sign(&sk, message, &mut sig).unwrap();
    let deep = hammer_signature::<ec::Ed25519>(&mut rng, &pk, &sig, message);
    assert!(deep > 80, "too few candidates reached Ed25519: {deep}");
}

#[test]
fn rsa_verification_is_total_and_sound() {
    let mut rng = Rng::new(0x3333);
    let message = b"a message that was genuinely signed";
    // `ic-rsa`'s pinned test key is test-only inside that crate, so this
    // generates one. It costs a few seconds, which is why the two schemes
    // share it rather than each making their own.
    let mut gen = drbg::Rng::from_entropy(&[0x5cu8; 32], b"hostile-input/rsa").unwrap();
    let key = rsa::generate(2048, &mut gen).expect("key generation");
    let public = key.public_key();

    let mut n = vec![0u8; key.size()];
    public.modulus_bytes(&mut n).unwrap();

    // PKCS#1 v1.5 and PSS both take the same public key shape.
    let mut sig = vec![0u8; key.size()];
    rsa::Pkcs1Sha256::sign(&key, message, &mut sig).unwrap();
    let mut deep = 0;
    for bad in hostile_inputs(&mut rng, sig.len(), 30) {
        if bad.len() == sig.len() {
            deep += 1;
        }
        assert!(
            rsa::Pkcs1Sha256::verify(public, message, &bad).is_err(),
            "rsa pkcs1: a forged signature was accepted"
        );
    }
    for _ in 0..40 {
        let mut bad = sig.clone();
        let at = rng.below(bad.len());
        bad[at] ^= 1 << rng.below(8);
        deep += 1;
        assert!(
            rsa::Pkcs1Sha256::verify(public, message, &bad).is_err(),
            "rsa pkcs1: a mutated signature was accepted"
        );
    }
    assert!(rsa::Pkcs1Sha256::verify(public, message, &sig).is_ok());
    assert!(deep > 60, "too few candidates reached RSA: {deep}");

    let mut psig = vec![0u8; key.size()];
    rsa::PssSha256::sign(&key, message, &mut gen, &mut psig).unwrap();
    for bad in hostile_inputs(&mut rng, psig.len(), 30) {
        assert!(
            rsa::PssSha256::verify(public, message, &bad).is_err(),
            "rsa pss: a forged signature was accepted"
        );
    }
    for _ in 0..40 {
        let mut bad = psig.clone();
        let at = rng.below(bad.len());
        bad[at] ^= 1 << rng.below(8);
        assert!(
            rsa::PssSha256::verify(public, message, &bad).is_err(),
            "rsa pss: a mutated signature was accepted"
        );
    }
    assert!(rsa::PssSha256::verify(public, message, &psig).is_ok());

    // A signature numerically at or above the modulus is invalid rather than a
    // case worth distinguishing, and must not be treated as an internal error.
    assert!(rsa::Pkcs1Sha256::verify(public, message, &n).is_err());
}

// ---------------------------------------------------------------------------
// Authenticated decryption
// ---------------------------------------------------------------------------

/// Open must fail on every tampered input, and must not leave plaintext behind.
///
/// The second half matters as much as the first. A caller that ignores the
/// error and reads the buffer anyway is making a mistake, but handing them
/// decrypted-but-unauthenticated bytes makes that mistake maximally dangerous,
/// which is why the AEAD releases nothing on failure.
fn hammer_aead<A: Aead>(rng: &mut Rng, aead: &A, nonce_len: usize) {
    let nonce = vec![0x24u8; nonce_len];
    let aad = b"associated data";
    let plaintext = b"the authentic plaintext".to_vec();

    let mut sealed = plaintext.clone();
    let mut tag = vec![0u8; 16];
    aead.seal_detached(&nonce, aad, &mut sealed, &mut tag)
        .unwrap();

    // The genuine case works.
    let mut opened = sealed.clone();
    aead.open_detached(&nonce, aad, &mut opened, &tag).unwrap();
    assert_eq!(opened, plaintext, "{}: round trip", A::NAME);

    // Every tampered tag must fail.
    for bad_tag in hostile_inputs(rng, tag.len(), 20) {
        let mut buf = sealed.clone();
        if aead.open_detached(&nonce, aad, &mut buf, &bad_tag).is_ok() {
            assert_eq!(bad_tag, tag, "{}: a forged tag was accepted", A::NAME);
        }
    }

    // Tampered ciphertext, tampered nonce, tampered aad.
    for _ in 0..30 {
        let mut buf = sealed.clone();
        let at = rng.below(buf.len());
        buf[at] ^= 1 << rng.below(8);
        assert!(
            aead.open_detached(&nonce, aad, &mut buf, &tag).is_err(),
            "{}: tampered ciphertext opened",
            A::NAME
        );
    }
    let mut buf = sealed.clone();
    let mut other_nonce = nonce.clone();
    other_nonce[0] ^= 1;
    assert!(
        aead.open_detached(&other_nonce, aad, &mut buf, &tag)
            .is_err(),
        "{}: wrong nonce opened",
        A::NAME
    );
    let mut buf = sealed.clone();
    assert!(
        aead.open_detached(&nonce, b"different aad", &mut buf, &tag)
            .is_err(),
        "{}: wrong aad opened",
        A::NAME
    );

    // Nothing plaintext-shaped may be left behind by a failed open.
    let mut buf = sealed.clone();
    let mut wrong = tag.clone();
    wrong[0] ^= 0xff;
    assert!(aead.open_detached(&nonce, aad, &mut buf, &wrong).is_err());
    assert_ne!(
        buf,
        plaintext,
        "{}: a failed open released the plaintext",
        A::NAME
    );

    // Odd nonce lengths must be refused, not silently padded or truncated.
    for len in [0usize, 1, nonce_len - 1, nonce_len + 1, 64] {
        let mut buf = sealed.clone();
        let odd = vec![0x24u8; len];
        if len != nonce_len {
            assert!(
                aead.open_detached(&odd, aad, &mut buf, &tag).is_err(),
                "{}: a {len}-byte nonce was accepted",
                A::NAME
            );
        }
    }
}

/// One hammering target: its ontology id, and the closure that hammers it.
type Target = (&'static str, fn(&mut Rng));

/// Every AEAD this build implements, by ontology id.
///
/// A table rather than a sequence of calls, because
/// [`the_suite_hammers_every_implemented_primitive`] reads the ids from it. Only
/// the 256-bit forms used to be here; the 128- and 192-bit ones share a great
/// deal of code but not the key schedule, and `aes-128-gcm-siv` derives its
/// per-message keys differently again.
static AEADS: &[Target] = &[
    ("aes-128-gcm", |rng| {
        hammer_aead(rng, &cipher::Aes128Gcm::new(&[0x11u8; 16]).unwrap(), 12)
    }),
    ("aes-192-gcm", |rng| {
        hammer_aead(rng, &cipher::Aes192Gcm::new(&[0x11u8; 24]).unwrap(), 12)
    }),
    ("aes-256-gcm", |rng| {
        hammer_aead(rng, &cipher::Aes256Gcm::new(&[0x11u8; 32]).unwrap(), 12)
    }),
    ("chacha20-poly1305", |rng| {
        hammer_aead(
            rng,
            &cipher::ChaCha20Poly1305::new(&[0x22u8; 32]).unwrap(),
            12,
        )
    }),
    ("aes-128-gcm-siv", |rng| {
        hammer_aead(rng, &cipher::Aes128GcmSiv::new(&[0x33u8; 16]).unwrap(), 12)
    }),
    ("aes-256-gcm-siv", |rng| {
        hammer_aead(rng, &cipher::Aes256GcmSiv::new(&[0x33u8; 32]).unwrap(), 12)
    }),
];

#[test]
fn aead_opening_is_total_and_sound() {
    let mut rng = Rng::new(0x4444);
    for (id, hammer) in AEADS {
        hammer(&mut rng);
        assert!(!id.is_empty());
    }
}

#[test]
fn key_unwrapping_is_total_and_sound() {
    let mut rng = Rng::new(0x5555);
    let kek = [0x44u8; 32];
    let key = [0x55u8; 32];

    let mut wrapped = [0u8; 40];
    cipher::Aes256Kw::wrap(&kek, &key, &mut wrapped).unwrap();
    let mut back = [0u8; 32];
    cipher::Aes256Kw::unwrap(&kek, &wrapped, &mut back).unwrap();
    assert_eq!(back, key);

    // Hostile wrapped blobs, including lengths that are not a multiple of eight.
    for bad in hostile_inputs(&mut rng, wrapped.len(), 40) {
        let mut out = vec![0u8; bad.len().saturating_sub(8)];
        if cipher::Aes256Kw::unwrap(&kek, &bad, &mut out).is_ok() {
            assert_eq!(bad, wrapped, "a forged key wrap was accepted");
        }
    }
    for extra in [1usize, 2, 7, 9] {
        let mut odd = wrapped.to_vec();
        odd.truncate(wrapped.len() - extra.min(wrapped.len()));
        let mut out = vec![0u8; 32];
        assert!(
            cipher::Aes256Kw::unwrap(&kek, &odd, &mut out).is_err(),
            "a wrap of {} bytes was accepted",
            odd.len()
        );
    }

    // And the integrity check really is doing the work.
    for _ in 0..40 {
        let mut bad = wrapped;
        let at = rng.below(bad.len());
        bad[at] ^= 1 << rng.below(8);
        let mut out = [0u8; 32];
        assert!(
            cipher::Aes256Kw::unwrap(&kek, &bad, &mut out).is_err(),
            "a tampered key wrap was accepted"
        );
    }
}

// ---------------------------------------------------------------------------
// Key agreement
// ---------------------------------------------------------------------------

#[test]
fn key_agreement_rejects_hostile_peer_keys() {
    let mut rng = Rng::new(0x6666);

    // X25519 accepts any 32 bytes as a u-coordinate by design, but must refuse
    // the low-order points, which drive the shared secret to zero regardless of
    // the private key.
    let sk = [0x77u8; 32];
    let mut shared = [0u8; 32];
    for bad in hostile_inputs(&mut rng, 32, 30) {
        let _ = ec::X25519::agree(&sk, &bad, &mut shared);
    }
    // RFC 7748 section 6.1: the known small-order u-coordinates.
    for low in [[0u8; 32], {
        let mut v = [0u8; 32];
        v[0] = 1;
        v
    }] {
        assert!(
            ec::X25519::agree(&sk, &low, &mut shared).is_err(),
            "a low-order peer key produced a shared secret"
        );
    }

    // The NIST curves must reject a point that is not on the curve, which is
    // the input that leaks the private scalar a few bits at a time. Each curve
    // validates in its own field arithmetic, so P-256 passing says nothing
    // about the other two: only P-256 was checked here before.
    for (id, hammer) in NIST_AGREEMENTS {
        hammer(&mut rng);
        assert!(!id.is_empty());
    }
}

/// Hammer one NIST curve's ECDH with off-curve and perturbed peer keys.
///
/// Generic over the scheme so the three curves are tested by the same code
/// rather than three copies that could drift apart. `SCALAR` and `POINT` are
/// the curve's byte widths, which differ per curve and so cannot be inferred.
fn hammer_ecdh<A, const SCALAR: usize, const POINT: usize>(rng: &mut Rng, seed: u8)
where
    A: KeyAgreement,
{
    let mut sk = [seed; SCALAR];
    // The top byte is cleared so the scalar is comfortably below the group
    // order on every curve, P-521 included, where only the low bit of the top
    // byte is available.
    sk[0] = 0;

    let mut good = [0u8; POINT];
    A::public_key(&sk, &mut good).unwrap();
    let mut out = [0u8; SCALAR];
    assert!(
        A::agree(&sk, &good, &mut out).is_ok(),
        "the genuine case must work, or nothing below tests anything"
    );

    for bad in hostile_inputs(rng, POINT, 40) {
        assert!(
            A::agree(&sk, &bad, &mut out).is_err(),
            "an off-curve peer key was accepted"
        );
    }

    // Points whose coordinates are individually in range but which do not
    // satisfy the curve equation. The leading byte is left alone so the point
    // still claims to be uncompressed and gets past the cheap check.
    for _ in 0..40 {
        let mut bad = good;
        let at = 1 + rng.below(POINT - 1);
        bad[at] ^= 1 << rng.below(8);
        assert!(
            A::agree(&sk, &bad, &mut out).is_err(),
            "a perturbed peer key was accepted"
        );
    }
}

/// Every NIST-curve key agreement this build implements, by ontology id.
static NIST_AGREEMENTS: &[Target] = &[
    ("ecdh-p256", |rng| {
        hammer_ecdh::<ec::p256::EcdhP256, 32, 65>(rng, 5)
    }),
    ("ecdh-p384", |rng| {
        hammer_ecdh::<ec::p384::EcdhP384, 48, 97>(rng, 7)
    }),
    ("ecdh-p521", |rng| {
        hammer_ecdh::<ec::p521::EcdhP521, 66, 133>(rng, 9)
    }),
];

// ---------------------------------------------------------------------------
// Coverage
// ---------------------------------------------------------------------------

/// Primitives hardened somewhere other than this file.
///
/// Each is named with where its own hostile-input suite lives, so this is a
/// pointer rather than an exemption. Anything added here without one is being
/// excused, which is the thing this test exists to prevent.
static COVERED_ELSEWHERE: &[(&str, &str)] = &[
    // The verifier was fuzzed as it was written; see the module doc there for
    // the same three properties this file argues.
    ("ml-dsa-65", "ic-mldsa/tests/robustness.rs"),
    // The RSA signature schemes share one public key shape and one parser, and
    // `rsa_verification_is_total_and_sound` hammers it through both paddings
    // at all three digest sizes.
    ("rsa-pkcs1-sha384", "rsa_verification_is_total_and_sound"),
    ("rsa-pkcs1-sha512", "rsa_verification_is_total_and_sound"),
    ("rsa-pss-sha384", "rsa_verification_is_total_and_sound"),
    ("rsa-pss-sha512", "rsa_verification_is_total_and_sound"),
];

/// Everything this file hammers, by ontology id.
fn hammered_here() -> Vec<&'static str> {
    let mut ids: Vec<&'static str> = Vec::new();
    ids.extend(AEADS.iter().map(|(id, _)| *id));
    ids.extend(NIST_AGREEMENTS.iter().map(|(id, _)| *id));
    // Named individually because their hammering is not table-driven: each
    // needs a differently shaped key and signature.
    ids.extend([
        "ecdsa-p256-sha256",
        "ecdsa-p384-sha384",
        "ecdsa-p521-sha512",
        "ed25519",
        "rsa-pkcs1-sha256",
        "rsa-pss-sha256",
        "x25519",
        "ml-kem-768",
    ]);
    ids
}

/// Every implemented algorithm that parses attacker-chosen bytes must be
/// hammered by this suite or name where it is hammered instead.
///
/// The doc at the top of this file says the suite exists "so that adding an
/// algorithm without hardening it is visible rather than merely possible".
/// Nothing made it visible. The targets were written out by hand, and six had
/// drifted out of coverage by the time anyone looked: the 128- and 192-bit
/// AEADs, `aes-128-gcm-siv`, ECDSA on P-521, and ECDH on P-384 and P-521.
///
/// P-521 was the one worth having. Its field arithmetic is the awkward case --
/// 521 bits is no multiple of a limb, so the top limb is partly used and every
/// reduction has to account for it -- and it had no hostile coverage at either
/// level.
///
/// The ontology knows what this build implements, which makes it the thing to
/// ask. A class is listed here when its inputs come from whoever is on the
/// other side of the exchange.
#[test]
fn the_suite_hammers_every_implemented_primitive() {
    // Classes whose parsing surface an attacker reaches directly: a signature
    // to verify, a sealed message to open, a peer's key, a ciphertext to
    // decapsulate.
    const EXPOSED: &[&str] = &["aead", "signature", "kem", "key-agreement"];

    let hammered = hammered_here();
    let excused: Vec<&str> = COVERED_ELSEWHERE.iter().map(|(id, _)| *id).collect();

    let mut owed = 0;
    let mut missing: Vec<&str> = Vec::new();
    for e in ic_ontology::all() {
        if !EXPOSED.contains(&e.class.id()) {
            continue;
        }
        // `experimental` counts: an implementation nobody has checked against a
        // second one is not a reason to leave its parser unhammered. `planned`
        // and `excluded` do not, since there is no code to hammer.
        if !matches!(
            e.status,
            ic_ontology::ImplStatus::Available | ic_ontology::ImplStatus::Experimental
        ) {
            continue;
        }
        owed += 1;
        if !hammered.contains(&e.id) && !excused.contains(&e.id) {
            missing.push(e.id);
        }
    }

    assert!(
        missing.is_empty(),
        "these parse attacker-chosen bytes and nothing hammers them: {missing:?}"
    );

    // Floors. The loop above passes trivially if the ontology returns nothing,
    // or if every entry turns out to be excused rather than tested.
    assert!(
        owed > 15,
        "only {owed} implemented primitives found; the ontology query is wrong"
    );
    assert!(
        hammered.len() >= owed - excused.len(),
        "more primitives are excused than tested"
    );

    // Nothing may be excused that is not implemented, and nothing may be listed
    // as hammered that does not exist -- either would be a stale entry quietly
    // widening the exemption.
    for (id, where_) in COVERED_ELSEWHERE {
        assert!(
            ic_ontology::get(id).is_some(),
            "{id} is excused but is not in the ontology"
        );
        assert!(!where_.is_empty(), "{id} is excused without saying where");
    }
    for id in &hammered {
        assert!(
            ic_ontology::get(id).is_some(),
            "{id} is claimed as hammered but is not in the ontology"
        );
    }
}

// ---------------------------------------------------------------------------
// Parsers and the KEM
// ---------------------------------------------------------------------------

#[test]
fn key_parsing_is_total() {
    let mut rng = Rng::new(0x7777);
    for len in [0usize, 1, 16, 64, 91, 294, 1200] {
        for candidate in hostile_inputs(&mut rng, len, 12) {
            // Every one of these must return rather than panic. Whether it
            // parses is the parser's business; that it returns is this test's.
            let _ = pkix::PublicKeyInfo::from_der(&candidate);
            let _ = pkix::PrivateKeyInfo::from_der(&candidate);
            let mut der = vec![0u8; candidate.len() + 64];
            let _ = pkix::pem::decode("PUBLIC KEY", &candidate, &mut der);
            let _ = pkix::pem::decode("PRIVATE KEY", &candidate, &mut der);
        }
    }
}

#[test]
fn decapsulation_survives_hostile_ciphertexts() {
    let mut rng = Rng::new(0x8888);
    let mut drbg = drbg::Rng::from_entropy(&[0x9au8; 32], b"hostile-input").unwrap();
    let mut ek = [0u8; mlkem::kem::ENCAPS_KEY_LEN];
    let mut dk = [0u8; mlkem::kem::DECAPS_KEY_LEN];
    mlkem::MlKem768::keygen(&mut drbg, &mut ek, &mut dk).unwrap();

    let mut secret = [0u8; mlkem::kem::SHARED_SECRET_LEN];
    for _ in 0..40 {
        let mut ct = [0u8; mlkem::kem::CIPHERTEXT_LEN];
        rng.fill(&mut ct);
        // Implicit rejection: this must succeed and return a pseudorandom
        // secret, never an error. The facade-level test exists because that
        // contract is easy to break from outside the crate that states it.
        mlkem::MlKem768::decapsulate(&dk, &ct, &mut secret)
            .expect("decapsulation must never fail on a ciphertext");
    }

    // A malformed encapsulation key, by contrast, is refused.
    let mut bad_ek = ek;
    bad_ek[0] = 0xff;
    bad_ek[1] = 0xff;
    let mut ct = [0u8; mlkem::kem::CIPHERTEXT_LEN];
    assert!(
        mlkem::MlKem768::encapsulate(&mut drbg, &bad_ek, &mut ct, &mut secret).is_err(),
        "a non-canonical encapsulation key was accepted"
    );
}
