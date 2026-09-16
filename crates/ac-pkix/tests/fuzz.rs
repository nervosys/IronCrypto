//! A deterministic fuzzer for the DER, PEM and key parsers.
//!
//! # Why this is a test and not a cargo-fuzz target
//!
//! `cargo-fuzz` would need nightly Rust and a `libfuzzer-sys` dependency. This
//! workspace has neither, and a fuzzer nobody runs finds nothing. So the
//! harness lives here, runs on every `cargo test`, and is reproducible: every
//! input comes from a seeded generator, so a failure prints a seed that
//! reproduces it exactly rather than a corpus file you have to be handed.
//!
//! The deep runs are `#[ignore]`d and take a seed count two orders of magnitude
//! larger. Run them with:
//!
//! ```text
//! cargo test -p ac-pkix --release --test fuzz -- --ignored --nocapture
//! ```
//!
//! # The properties
//!
//! Parsers are usually fuzzed for crashes alone, which in safe Rust means
//! panics — a real but shallow target, since the worst case is a denial of
//! service. The properties that matter for *this* parser are about ambiguity,
//! because a strict DER reader exists so that two implementations cannot
//! disagree about what a signed document says:
//!
//! - **P1, no panic.** No input, however malformed, may panic. Safe Rust rules
//!   out memory corruption; it does not rule out an index out of range.
//! - **P2, canonical fixed point.** Anything that parses must re-serialize to
//!   *exactly* the bytes it came from. This is the strong one. A parser that
//!   accepts a non-minimal length, a redundant integer sign byte, or a field it
//!   silently drops will fail it, because the re-encoding will not match. It
//!   turns "is this parser strict?" into something checkable rather than
//!   something asserted in a doc comment.
//! - **P3, prefixes are rejected.** No proper prefix of a valid encoding may
//!   parse: the outer length always claims more bytes than are present.
//! - **P4, suffixes are rejected.** No valid encoding with anything appended
//!   may parse. Trailing data is how one party is shown more than another.
//!
//! P2 is the property that would have caught the PKCS#8 attributes bug: the
//! field parsed, was dropped, and re-encoded to something shorter.

use ac_pkix::{der, ecdsa_signature, pem, PrivateKeyInfo, PublicKeyInfo};

// ---------------------------------------------------------------------------
// A small reproducible generator
// ---------------------------------------------------------------------------

/// SplitMix64. Not cryptography and not pretending to be: a fuzzer wants a fast
/// stream it can reproduce from a seed, which is the opposite of what a DRBG is
/// for. Using [`ac_drbg`] here would be slower and would make this test depend
/// on the thing it is meant to be independent of.
struct Prng(u64);

impl Prng {
    fn new(seed: u64) -> Self {
        Prng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 0xdead_beef_cafe_f00d)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn byte(&mut self) -> u8 {
        self.next_u64() as u8
    }

    /// A value in `0..n`.
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % n as u64) as usize
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.byte()).collect()
    }
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/// Emit a DER-shaped byte string.
///
/// Uniformly random bytes almost never get past the first tag check, so they
/// exercise nothing below it. This emits plausible tags and lengths — sometimes
/// deliberately malformed ones — so the generator reaches the integer, OID and
/// bit-string readers where the interesting rules live.
fn der_shaped(prng: &mut Prng, depth: usize) -> Vec<u8> {
    let tag = match prng.below(8) {
        0 => der::SEQUENCE,
        1 => der::INTEGER,
        2 => der::OCTET_STRING,
        3 => der::BIT_STRING,
        4 => der::OID,
        5 => der::NULL,
        6 => der::context(0),
        _ => prng.byte(),
    };

    let content = if depth > 0 && matches!(tag, der::SEQUENCE) {
        let mut inner = Vec::new();
        for _ in 0..prng.below(4) {
            inner.extend_from_slice(&der_shaped(prng, depth - 1));
        }
        inner
    } else {
        let len = prng.below(40);
        prng.bytes(len)
    };

    let mut out = vec![tag];
    match prng.below(10) {
        // Correct short form.
        0..=5 if content.len() < 0x80 => out.push(content.len() as u8),
        // Correct long form.
        6..=7 => {
            out.push(0x82);
            out.push((content.len() >> 8) as u8);
            out.push(content.len() as u8);
        }
        // A length that does not match the content, which must be caught.
        8 => out.push(prng.byte()),
        // Indefinite length, which DER forbids.
        _ => out.push(0x80),
    }
    out.extend_from_slice(&content);
    out
}

/// A minimal DER length header.
fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else if n < 0x100 {
        vec![0x81, n as u8]
    } else {
        vec![0x82, (n >> 8) as u8, n as u8]
    }
}

/// Wrap `content` in a tag and a minimal length.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Emit a key document built from the real grammar, with a perturbation.
///
/// The generic generator above cannot reach the key parsers at all: an SPKI has
/// to carry one of a handful of exact algorithm OIDs, and random bytes will
/// never produce one. So this builds documents that are structurally correct by
/// construction and then breaks one thing about them, which is what gets past
/// the OID comparison and into the length, parameter and range checks where the
/// rules that matter live.
fn key_shaped(prng: &mut Prng) -> Vec<u8> {
    use ac_pkix::oid;

    // 0 = params absent, 1 = NULL, 2 = named curve OID.
    let (algorithm, params_kind, key_len): (&[u8], usize, usize) = match prng.below(5) {
        0 => (oid::RSA_ENCRYPTION, 1, 0),
        1 => (oid::EC_PUBLIC_KEY, 2, 65),
        2 => (oid::EC_PUBLIC_KEY, 2, 97),
        3 => (oid::ED25519, 0, 32),
        _ => (oid::X25519, 0, 32),
    };
    let curve: &[u8] = if key_len == 97 { oid::P384 } else { oid::P256 };

    // Pick what to break. 0 means nothing, which is what produces the
    // inputs that get all the way through.
    let perturb = prng.below(8);

    let mut params = Vec::new();
    let kind = if perturb == 1 {
        (params_kind + 1) % 3
    } else {
        params_kind
    };
    match kind {
        1 => params.extend_from_slice(&tlv(der::NULL, &[])),
        2 => params.extend_from_slice(&tlv(der::OID, curve)),
        _ => {}
    }

    let mut alg_content = tlv(der::OID, algorithm);
    alg_content.extend_from_slice(&params);
    let algorithm_identifier = tlv(der::SEQUENCE, &alg_content);

    // The key material itself.
    let mut material = if algorithm == oid::RSA_ENCRYPTION {
        // RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        let size = if perturb == 2 {
            1 + prng.below(40)
        } else {
            256
        };
        let mut modulus = prng.bytes(size);
        if !modulus.is_empty() {
            modulus[0] |= 0x80; // keep it a full-width value
        }
        let mut inner = tlv(der::INTEGER, &[&[0u8][..], &modulus].concat());
        inner.extend_from_slice(&tlv(der::INTEGER, &[0x01, 0x00, 0x01]));
        tlv(der::SEQUENCE, &inner)
    } else {
        let size = if perturb == 2 {
            1 + prng.below(140)
        } else {
            key_len
        };
        let mut point = prng.bytes(size);
        if !point.is_empty() {
            point[0] = if perturb == 3 { prng.byte() } else { 0x04 };
        }
        point
    };
    if algorithm == oid::ED25519 || algorithm == oid::X25519 {
        // Curve25519 keys are raw, with no SEC1 prefix byte.
        let size = if perturb == 2 { 1 + prng.below(40) } else { 32 };
        material = prng.bytes(size);
    }

    if prng.below(2) == 0 {
        // SubjectPublicKeyInfo
        let unused = if perturb == 4 { 1 + prng.byte() % 7 } else { 0 };
        let mut bit_string = vec![unused];
        bit_string.extend_from_slice(&material);
        let mut body = algorithm_identifier;
        body.extend_from_slice(&tlv(der::BIT_STRING, &bit_string));
        if perturb == 5 {
            body.extend_from_slice(&tlv(der::context(0), &[1, 2, 3]));
        }
        tlv(der::SEQUENCE, &body)
    } else {
        // PrivateKeyInfo. The inner structure differs per family, and getting
        // it wrong is itself a useful input.
        let inner = if algorithm == oid::EC_PUBLIC_KEY {
            let mut ec = tlv(der::INTEGER, &[1]);
            ec.extend_from_slice(&tlv(
                der::OCTET_STRING,
                &prng.bytes(if key_len == 97 { 48 } else { 32 }),
            ));
            ec.extend_from_slice(&tlv(der::context(0), &tlv(der::OID, curve)));
            tlv(der::SEQUENCE, &ec)
        } else if algorithm == oid::RSA_ENCRYPTION {
            material.clone()
        } else {
            tlv(der::OCTET_STRING, &material)
        };

        let mut body = tlv(der::INTEGER, &[if perturb == 6 { 1 } else { 0 }]);
        body.extend_from_slice(&algorithm_identifier);
        body.extend_from_slice(&tlv(der::OCTET_STRING, &inner));
        if perturb == 7 {
            body.extend_from_slice(&tlv(der::context(0), &[1, 2, 3]));
        }
        tlv(der::SEQUENCE, &body)
    }
}

/// Known-good encodings to mutate. Every parser entry point is represented.
fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let mut out = Vec::new();
    let mut buf = [0u8; 2048];

    let n = PublicKeyInfo::Ed25519(&[0x42; 32])
        .to_der(&mut buf)
        .unwrap();
    out.push(("spki-ed25519", buf[..n].to_vec()));

    let n = PublicKeyInfo::X25519(&[0x11; 32]).to_der(&mut buf).unwrap();
    out.push(("spki-x25519", buf[..n].to_vec()));

    let mut point = [0u8; 65];
    point[0] = 0x04;
    for (i, b) in point[1..].iter_mut().enumerate() {
        *b = i as u8;
    }
    let n = PublicKeyInfo::Ec {
        algorithm: ac_pkix::KeyAlgorithm::EcP256,
        point: &point,
    }
    .to_der(&mut buf)
    .unwrap();
    out.push(("spki-p256", buf[..n].to_vec()));

    let mut modulus = [0xa5u8; 256];
    modulus[0] = 0xd7;
    let n = PublicKeyInfo::Rsa {
        modulus: &modulus,
        exponent: 65537,
    }
    .to_der(&mut buf)
    .unwrap();
    out.push(("spki-rsa", buf[..n].to_vec()));

    let n = PrivateKeyInfo::Ed25519(&[0x9d; 32])
        .to_der(&mut buf)
        .unwrap();
    out.push(("pkcs8-ed25519", buf[..n].to_vec()));

    let n = PrivateKeyInfo::Ec {
        algorithm: ac_pkix::KeyAlgorithm::EcP256,
        private_key: &[0x33; 32],
        public_key: Some(&point),
    }
    .to_der(&mut buf)
    .unwrap();
    out.push(("pkcs8-p256", buf[..n].to_vec()));

    let mut sig = [0u8; 64];
    sig[0] = 0x80; // forces the sign byte on r
    sig[32] = 0x01;
    let n = ecdsa_signature::to_der(&sig, &mut buf).unwrap();
    out.push(("ecdsa-sig", buf[..n].to_vec()));

    out
}

// ---------------------------------------------------------------------------
// The properties, applied to one input
// ---------------------------------------------------------------------------

/// Parse `input` every way there is, and check P1 and P2 on each.
///
/// Returns how many parsers accepted it, so the generators can report their
/// reach: a fuzzer that never produces a parseable input is testing only the
/// first branch of every function.
fn check_all_parsers(input: &[u8]) -> usize {
    let mut accepted = 0;
    let mut out = [0u8; 4096];

    if let Ok(key) = PublicKeyInfo::from_der(input) {
        accepted += 1;
        // Unsupported is excluded from P2 by construction: it deliberately
        // refuses to re-serialize, because re-emitting a structure that was
        // never validated would launder malformed input.
        if !matches!(key, PublicKeyInfo::Unsupported { .. }) {
            let n = key
                .to_der(&mut out)
                .expect("a parsed public key must re-serialize");
            assert_eq!(
                &out[..n],
                input,
                "P2 violated: SubjectPublicKeyInfo re-encoded differently\n\
                 input: {input:02x?}\n  got: {:02x?}",
                &out[..n]
            );
        }
    }

    if let Ok(key) = PrivateKeyInfo::from_der(input) {
        accepted += 1;
        if !matches!(key, PrivateKeyInfo::Unsupported { .. }) {
            let n = key
                .to_der(&mut out)
                .expect("a parsed private key must re-serialize");
            assert_eq!(
                &out[..n],
                input,
                "P2 violated: PrivateKeyInfo re-encoded differently\n\
                 input: {input:02x?}\n  got: {:02x?}",
                &out[..n]
            );
        }
    }

    // ECDSA signatures, at both field widths.
    for field in [32usize, 48, 66] {
        let mut fixed = vec![0u8; field * 2];
        if ecdsa_signature::from_der(input, &mut fixed).is_ok() {
            accepted += 1;
            let n = ecdsa_signature::to_der(&fixed, &mut out)
                .expect("a parsed signature must re-serialize");
            assert_eq!(
                &out[..n],
                input,
                "P2 violated: Ecdsa-Sig-Value re-encoded differently at field {field}"
            );
        }
    }

    // The raw DER reader, driven directly.
    let mut reader = der::Reader::new(input);
    let _ = reader.peek_tag();
    if let Ok(mut inner) = reader.sequence() {
        let _ = inner.unsigned_integer();
        let _ = inner.oid();
        let _ = inner.bit_string();
        let _ = inner.octet_string();
        let _ = inner.null();
        let _ = inner.finish();
    }

    accepted
}

// ---------------------------------------------------------------------------
// P1: nothing panics
// ---------------------------------------------------------------------------

#[test]
fn random_bytes_never_panic() {
    let mut prng = Prng::new(1);
    for _ in 0..4_000 {
        let len = prng.below(600);
        let input = prng.bytes(len);
        check_all_parsers(&input);
    }
}

/// Generic DER trees. These exercise the raw reader thoroughly and the key
/// parsers barely, since a random tree will not carry a recognized algorithm
/// OID. Reach is asserted on `key_shaped` below instead.
#[test]
fn der_shaped_input_never_panics() {
    let mut prng = Prng::new(2);
    for _ in 0..4_000 {
        let input = der_shaped(&mut prng, 3);
        check_all_parsers(&input);
    }
}

/// Grammar-aware key documents, which do reach the key parsers.
#[test]
fn key_shaped_input_reaches_the_parsers_and_stays_canonical() {
    let mut prng = Prng::new(6);
    let mut accepted = 0;
    for _ in 0..20_000 {
        let input = key_shaped(&mut prng);
        accepted += check_all_parsers(&input);
    }
    // Not a correctness assertion — an assertion that this test is testing
    // something. The first version of this generator produced zero parseable
    // inputs in four thousand tries and passed every property vacuously, which
    // is the failure mode this guard exists to catch.
    assert!(
        accepted > 1_000,
        "the grammar-aware generator only reached the parsers {accepted} times \
         out of 20000; it is not exercising them"
    );
}

#[test]
fn pem_never_panics() {
    let mut prng = Prng::new(3);
    let mut out = [0u8; 4096];
    for _ in 0..4_000 {
        let len = prng.below(400);
        let mut input = prng.bytes(len);

        // Half the time, wrap it in something PEM-shaped so the decoder gets
        // past its first check.
        if prng.below(2) == 0 {
            let mut doc = b"-----BEGIN PUBLIC KEY-----\n".to_vec();
            for chunk in input.chunks(48) {
                let mut line = vec![0u8; ac_core::codec::base64_encoded_len(chunk.len())];
                ac_core::codec::base64_encode(chunk, &mut line).unwrap();
                doc.extend_from_slice(&line);
                doc.push(b'\n');
            }
            doc.extend_from_slice(b"-----END PUBLIC KEY-----\n");
            input = doc;
        }

        let _ = pem::decode(pem::PUBLIC_KEY, &input, &mut out);
        let _ = pem::decode(pem::PRIVATE_KEY, &input, &mut out);
    }
}

// ---------------------------------------------------------------------------
// P2, P3, P4 against mutations of known-good encodings
// ---------------------------------------------------------------------------

/// Flipping any single bit of a valid encoding must leave it either rejected or
/// still canonical. This reaches deep into the parsers for very little work,
/// because the input starts valid and stays close to valid.
#[test]
fn every_single_bit_flip_is_rejected_or_canonical() {
    for (name, valid) in corpus() {
        // Sanity: the unmutated encoding must satisfy P2.
        assert!(
            check_all_parsers(&valid) > 0,
            "{name}: the corpus entry does not parse at all"
        );

        for bit in 0..valid.len() * 8 {
            let mut mutated = valid.clone();
            mutated[bit / 8] ^= 1 << (bit % 8);
            check_all_parsers(&mutated);
        }
    }
}

/// Two-bit flips, sampled. Some invariants only break when a length and its
/// content are changed together — a single flip that corrupts a length is
/// caught by the length check alone, which is the easy case.
#[test]
fn sampled_double_bit_flips_are_rejected_or_canonical() {
    let mut prng = Prng::new(4);
    for (_, valid) in corpus() {
        for _ in 0..4_000 {
            let mut mutated = valid.clone();
            let a = prng.below(valid.len() * 8);
            let b = prng.below(valid.len() * 8);
            mutated[a / 8] ^= 1 << (a % 8);
            mutated[b / 8] ^= 1 << (b % 8);
            check_all_parsers(&mutated);
        }
    }
}

/// Byte substitutions, including the values most likely to be mishandled.
#[test]
fn interesting_byte_substitutions_are_rejected_or_canonical() {
    const INTERESTING: [u8; 10] = [0x00, 0x01, 0x7f, 0x80, 0x81, 0x82, 0xa0, 0xbc, 0xfe, 0xff];
    for (_, valid) in corpus() {
        for index in 0..valid.len() {
            for value in INTERESTING {
                let mut mutated = valid.clone();
                mutated[index] = value;
                check_all_parsers(&mutated);
            }
        }
    }
}

/// P3: no proper prefix of a valid encoding may parse. The outer length always
/// claims more bytes than a prefix contains.
#[test]
fn no_prefix_of_a_valid_encoding_parses() {
    for (name, valid) in corpus() {
        for cut in 0..valid.len() {
            let prefix = &valid[..cut];
            assert!(
                PublicKeyInfo::from_der(prefix).is_err(),
                "{name}: a {cut}-byte prefix parsed as a public key"
            );
            assert!(
                PrivateKeyInfo::from_der(prefix).is_err(),
                "{name}: a {cut}-byte prefix parsed as a private key"
            );
            let mut fixed = [0u8; 64];
            assert!(
                ecdsa_signature::from_der(prefix, &mut fixed).is_err(),
                "{name}: a {cut}-byte prefix parsed as a signature"
            );
        }
    }
}

/// P4: appending anything to a valid encoding must make it invalid.
#[test]
fn no_valid_encoding_survives_a_suffix() {
    let mut prng = Prng::new(5);
    for (name, valid) in corpus() {
        for _ in 0..64 {
            let mut extended = valid.clone();
            let suffix_len = 1 + prng.below(8);
            extended.extend_from_slice(&prng.bytes(suffix_len));

            assert!(
                PublicKeyInfo::from_der(&extended).is_err(),
                "{name}: trailing data accepted by the public key parser"
            );
            assert!(
                PrivateKeyInfo::from_der(&extended).is_err(),
                "{name}: trailing data accepted by the private key parser"
            );
            let mut fixed = [0u8; 64];
            assert!(
                ecdsa_signature::from_der(&extended, &mut fixed).is_err(),
                "{name}: trailing data accepted by the signature parser"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Deep runs
// ---------------------------------------------------------------------------

/// The same properties, two orders of magnitude more input. Ignored by default
/// so `cargo test` stays fast.
#[test]
#[ignore = "deep fuzz; run with --release -- --ignored"]
fn deep_random_and_structured_run() {
    let mut prng = Prng::new(0xfeed_face);
    let mut accepted = 0usize;

    for round in 0..400_000u32 {
        let input = match round % 3 {
            0 => {
                let len = prng.below(600);
                prng.bytes(len)
            }
            1 => der_shaped(&mut prng, 4),
            _ => key_shaped(&mut prng),
        };
        accepted += check_all_parsers(&input);
    }

    println!("deep run: {accepted} inputs were accepted by at least one parser");
}

/// Exhaustive single-bit and double-bit mutation of every corpus entry.
#[test]
#[ignore = "deep fuzz; run with --release -- --ignored"]
fn deep_mutation_run() {
    for (name, valid) in corpus() {
        let bits = valid.len() * 8;
        for a in 0..bits {
            for b in a..bits {
                let mut mutated = valid.clone();
                mutated[a / 8] ^= 1 << (a % 8);
                mutated[b / 8] ^= 1 << (b % 8);
                check_all_parsers(&mutated);
            }
        }
        println!(
            "{name}: {} two-bit mutations checked",
            bits * (bits + 1) / 2
        );
    }
}
