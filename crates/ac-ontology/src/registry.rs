//! The algorithm registry: every entry the ontology knows about.
//!
//! The registry includes algorithms this library does **not** implement. That
//! is deliberate. An agent asking for post-quantum key agreement needs to learn
//! that ML-KEM is the answer *and* that it is not available here — otherwise it
//! will reach for X25519 and quietly miss the requirement. Entries carry
//! [`ImplStatus`] so the difference is never ambiguous.

use crate::types::*;

// ---------------------------------------------------------------------------
// Shared constraints
// ---------------------------------------------------------------------------

const UNIQUE_NONCE: Constraint = Constraint {
    id: "unique-nonce-per-key",
    requirement: "Never reuse a (key, nonce) pair.",
    consequence:
        "Reuse leaks the authentication subkey, allowing forgery of arbitrary messages, and XORs \
         the two plaintexts together.",
    severity: Severity::Critical,
};

const NONCE_COUNTER: Constraint = Constraint {
    id: "prefer-counter-nonce",
    requirement: "Derive the nonce from a strictly increasing counter, or draw 96 random bits and \
                  bound the number of messages per key.",
    consequence: "Random 96-bit nonces collide with meaningful probability past 2^32 messages.",
    severity: Severity::Serious,
};

const AEAD_NOT_RAW: Constraint = Constraint {
    id: "requires-separate-mac",
    requirement: "Authenticate the ciphertext with a MAC, or use an AEAD instead.",
    consequence:
        "Unauthenticated ciphertext is malleable and exposes padding and chosen-ciphertext \
                  oracles.",
    severity: Severity::Critical,
};

const ONE_TIME_KEY: Constraint = Constraint {
    id: "one-time-key",
    requirement: "Use each key for exactly one message.",
    consequence: "Two messages under one key reveal the key, permitting arbitrary forgery.",
    severity: Severity::Critical,
};

const CT_COMPARE: Constraint = Constraint {
    id: "constant-time-tag-comparison",
    requirement: "Compare tags with ac_core::ct::verify, never with ==.",
    consequence: "A byte-by-byte comparison leaks the correct tag one byte at a time.",
    severity: Severity::Critical,
};

const SALT_REQUIRED: Constraint = Constraint {
    id: "unique-salt-per-password",
    requirement: "Use at least 128 bits of fresh random salt per password.",
    consequence:
        "A shared or missing salt lets one precomputed table attack every stored password.",
    severity: Severity::Critical,
};

const NOT_FOR_PASSWORDS: Constraint = Constraint {
    id: "not-for-passwords",
    requirement: "Do not feed a low-entropy password into this function.",
    consequence:
        "It is fast by design, so a password is recovered by brute force; use a password KDF.",
    severity: Severity::Critical,
};

const RESEED_INTERVAL: Constraint = Constraint {
    id: "observe-reseed-interval",
    requirement: "Reseed from a live entropy source before the reseed interval elapses.",
    consequence: "Output past the interval is no longer backed by the claimed security strength.",
    severity: Severity::Serious,
};

const VALIDATE_PEER_KEY: Constraint = Constraint {
    id: "validate-peer-public-key",
    requirement: "Reject an all-zero shared secret, which signals a small-order peer key.",
    consequence: "A malicious peer can force a shared secret it already knows.",
    severity: Severity::Critical,
};

const HASH_TRANSCRIPT: Constraint = Constraint {
    id: "bind-shared-secret-to-transcript",
    requirement: "Run the raw shared secret through a KDF together with both public keys.",
    consequence: "Using the raw secret as a key loses contributory behaviour and key confirmation.",
    severity: Severity::Serious,
};

const NOT_COLLISION_RESISTANT: Constraint = Constraint {
    id: "no-collision-resistance",
    requirement: "Do not rely on this for collision resistance.",
    consequence:
        "Collisions are computationally feasible; signatures and commitments are forgeable.",
    severity: Severity::Critical,
};

// ---------------------------------------------------------------------------
// Shared parameter sets
// ---------------------------------------------------------------------------

const P_KEY_16: Param = Param {
    name: "key",
    unit: Unit::Bytes,
    min: 16,
    max: 16,
    recommended: 16,
    note: "AES-128 key.",
};
const P_KEY_24: Param = Param {
    name: "key",
    unit: Unit::Bytes,
    min: 24,
    max: 24,
    recommended: 24,
    note: "AES-192 key.",
};
const P_KEY_32: Param = Param {
    name: "key",
    unit: Unit::Bytes,
    min: 32,
    max: 32,
    recommended: 32,
    note: "256-bit key.",
};
const P_GCM_NONCE: Param = Param {
    name: "nonce",
    unit: Unit::Bytes,
    min: 1,
    max: 64,
    recommended: 12,
    note: "96-bit nonces are used directly as the counter block; other lengths are hashed first.",
};
const P_TAG_16: Param = Param {
    name: "tag",
    unit: Unit::Bytes,
    min: 16,
    max: 16,
    recommended: 16,
    note: "Full-length authentication tag.",
};
const P_NONCE_12: Param = Param {
    name: "nonce",
    unit: Unit::Bytes,
    min: 12,
    max: 12,
    recommended: 12,
    note: "96-bit nonce.",
};
const P_IV_16: Param = Param {
    name: "iv",
    unit: Unit::Bytes,
    min: 16,
    max: 16,
    recommended: 16,
    note: "Initialization vector, one block.",
};

const fn digest_params(out: u64, block: u64) -> [Param; 2] {
    [
        Param {
            name: "output",
            unit: Unit::Bytes,
            min: out,
            max: out,
            recommended: out,
            note: "Digest length.",
        },
        Param {
            name: "block",
            unit: Unit::Bytes,
            min: block,
            max: block,
            recommended: block,
            note: "Internal block or rate size; HMAC needs it.",
        },
    ]
}

const SHA224_P: [Param; 2] = digest_params(28, 64);
const SHA256_P: [Param; 2] = digest_params(32, 64);
const SHA384_P: [Param; 2] = digest_params(48, 128);
const SHA512_P: [Param; 2] = digest_params(64, 128);
const SHA512_224_P: [Param; 2] = digest_params(28, 128);
const SHA512_256_P: [Param; 2] = digest_params(32, 128);
const SHA3_224_P: [Param; 2] = digest_params(28, 144);
const SHA3_256_P: [Param; 2] = digest_params(32, 136);
const SHA3_384_P: [Param; 2] = digest_params(48, 104);
const SHA3_512_P: [Param; 2] = digest_params(64, 72);

const HMAC_KEY_P: [Param; 1] = [Param {
    name: "key",
    unit: Unit::Bytes,
    min: 0,
    max: u64::MAX,
    recommended: 32,
    note:
        "Any length; keys longer than the block size are hashed, shorter ones zero-padded. Use at \
           least the digest length for full strength.",
}];

const PBKDF2_P: [Param; 3] = [
    Param {
        name: "salt",
        unit: Unit::Bytes,
        min: 16,
        max: u64::MAX,
        recommended: 16,
        note: "SP 800-132 requires at least 128 bits.",
    },
    Param {
        name: "iterations",
        unit: Unit::Count,
        min: 1_000,
        max: u64::MAX,
        recommended: 600_000,
        note: "SP 800-132 floor is 1000; 600000 reflects current hardware.",
    },
    Param {
        name: "output",
        unit: Unit::Bytes,
        min: 1,
        max: u64::MAX,
        recommended: 32,
        note: "Derived key length.",
    },
];

const X25519_P: [Param; 3] = [
    Param {
        name: "private-key",
        unit: Unit::Bytes,
        min: 32,
        max: 32,
        recommended: 32,
        note: "Clamped internally per RFC 7748.",
    },
    Param {
        name: "public-key",
        unit: Unit::Bytes,
        min: 32,
        max: 32,
        recommended: 32,
        note: "Montgomery u-coordinate.",
    },
    Param {
        name: "shared-secret",
        unit: Unit::Bytes,
        min: 32,
        max: 32,
        recommended: 32,
        note: "Feed through a KDF before use.",
    },
];

const ED25519_P: [Param; 3] = [
    Param {
        name: "private-key",
        unit: Unit::Bytes,
        min: 32,
        max: 32,
        recommended: 32,
        note: "A 32-byte seed; the scalar and nonce prefix are derived from it.",
    },
    Param {
        name: "public-key",
        unit: Unit::Bytes,
        min: 32,
        max: 32,
        recommended: 32,
        note: "Compressed Edwards point.",
    },
    Param {
        name: "signature",
        unit: Unit::Bytes,
        min: 64,
        max: 64,
        recommended: 64,
        note: "R || S.",
    },
];

const P256_KA_P: [Param; 3] = [
    Param {
        name: "private-key",
        unit: Unit::Bytes,
        min: 32,
        max: 32,
        recommended: 32,
        note: "A scalar in [1, n-1]; zero and values at or above n are rejected.",
    },
    Param {
        name: "public-key",
        unit: Unit::Bytes,
        min: 33,
        max: 65,
        recommended: 65,
        note: "SEC1: 65 bytes uncompressed (0x04 || X || Y), or 33 compressed.",
    },
    Param {
        name: "shared-secret",
        unit: Unit::Bytes,
        min: 32,
        max: 32,
        recommended: 32,
        note: "The x-coordinate of the shared point. Not a key; derive from it.",
    },
];

const P256_SIG_P: [Param; 3] = [
    Param {
        name: "private-key",
        unit: Unit::Bytes,
        min: 32,
        max: 32,
        recommended: 32,
        note: "A scalar in [1, n-1].",
    },
    Param {
        name: "public-key",
        unit: Unit::Bytes,
        min: 33,
        max: 65,
        recommended: 65,
        note: "SEC1 uncompressed or compressed; both are accepted on verification.",
    },
    Param {
        name: "signature",
        unit: Unit::Bytes,
        min: 64,
        max: 64,
        recommended: 64,
        note: "Fixed-width r || s, each 32 bytes. Not DER-encoded.",
    },
];

const NO_PARAMS: [Param; 0] = [];
const NO_CONSTRAINTS: [Constraint; 0] = [];

// ---------------------------------------------------------------------------
// Entry construction helpers
// ---------------------------------------------------------------------------

/// Build a SHA-family digest entry, which differ only in their parameters.
///
/// The argument list is long because it mirrors the entry's fields; collapsing
/// it into a struct would just move the same data one level down.
#[allow(clippy::too_many_arguments)]
const fn digest_entry(
    id: &'static str,
    name: &'static str,
    aliases: &'static [&'static str],
    family: &'static str,
    bits: u16,
    fips: FipsStatus,
    standards: &'static [&'static str],
    params: &'static [Param],
    rust_path: &'static str,
    example: &'static str,
    edges: &'static [Edge],
    summary: &'static str,
) -> Entry {
    Entry {
        id,
        name,
        aliases,
        summary,
        class: Class::Hash,
        family,
        purposes: &[Purpose::Integrity, Purpose::Commitment],
        // A hash offers `bits` of collision resistance, i.e. half its output.
        strength: Strength::symmetric(bits),
        fips,
        status: ImplStatus::Available,
        standards,
        params,
        constraints: &[NOT_FOR_PASSWORDS],
        edges,
        performance: Performance::Fast,
        rust_path,
        example,
        notes: "",
    }
}

const S_FIPS_180_4: [&str; 1] = ["FIPS 180-4"];
const S_FIPS_202: [&str; 1] = ["FIPS 202"];

const SHA2_EDGE: [Edge; 1] = [Edge {
    relation: Relation::Specializes,
    target: "sha-2",
}];
const SHA3_EDGE: [Edge; 1] = [Edge {
    relation: Relation::Specializes,
    target: "sha-3",
}];

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

/// Every algorithm the ontology describes, sorted by identifier.
pub static REGISTRY: &[Entry] = &[
    // -- Hashes -------------------------------------------------------------
    digest_entry(
        "sha2-224",
        "SHA-224",
        &["sha224"],
        "SHA-2",
        112,
        FipsStatus::Approved,
        &S_FIPS_180_4,
        &SHA224_P,
        "ac_hash::Sha224",
        "let d = ac_hash::Sha224::digest(b\"message\");",
        &SHA2_EDGE,
        "Truncated SHA-256. Use only when a 28-byte digest is required by an existing format.",
    ),
    digest_entry(
        "sha2-256",
        "SHA-256",
        &["sha256", "sha-256"],
        "SHA-2",
        128,
        FipsStatus::Approved,
        &S_FIPS_180_4,
        &SHA256_P,
        "ac_hash::Sha256",
        "let d = ac_hash::Sha256::digest(b\"message\");",
        &SHA2_EDGE,
        "The default general-purpose hash: approved, fast, and universally interoperable.",
    ),
    digest_entry(
        "sha2-384",
        "SHA-384",
        &["sha384"],
        "SHA-2",
        192,
        FipsStatus::Approved,
        &S_FIPS_180_4,
        &SHA384_P,
        "ac_hash::Sha384",
        "let d = ac_hash::Sha384::digest(b\"message\");",
        &SHA2_EDGE,
        "Truncated SHA-512. Faster than SHA-256 on 64-bit targets and immune to length extension.",
    ),
    digest_entry(
        "sha2-512",
        "SHA-512",
        &["sha512"],
        "SHA-2",
        256,
        FipsStatus::Approved,
        &S_FIPS_180_4,
        &SHA512_P,
        "ac_hash::Sha512",
        "let d = ac_hash::Sha512::digest(b\"message\");",
        &SHA2_EDGE,
        "The widest SHA-2 digest; the hash underneath Ed25519.",
    ),
    digest_entry(
        "sha2-512-224",
        "SHA-512/224",
        &["sha512-224"],
        "SHA-2",
        112,
        FipsStatus::Approved,
        &S_FIPS_180_4,
        &SHA512_224_P,
        "ac_hash::Sha512_224",
        "let d = ac_hash::Sha512_224::digest(b\"message\");",
        &SHA2_EDGE,
        "SHA-512 truncated to 224 bits with a distinct IV.",
    ),
    digest_entry(
        "sha2-512-256",
        "SHA-512/256",
        &["sha512-256"],
        "SHA-2",
        128,
        FipsStatus::Approved,
        &S_FIPS_180_4,
        &SHA512_256_P,
        "ac_hash::Sha512_256",
        "let d = ac_hash::Sha512_256::digest(b\"message\");",
        &SHA2_EDGE,
        "SHA-256-strength output at SHA-512 speed on 64-bit targets, with no length extension.",
    ),
    digest_entry(
        "sha3-224",
        "SHA3-224",
        &[],
        "SHA-3",
        112,
        FipsStatus::Approved,
        &S_FIPS_202,
        &SHA3_224_P,
        "ac_hash::Sha3_224",
        "let d = ac_hash::Sha3_224::digest(b\"message\");",
        &SHA3_EDGE,
        "Keccak-based 224-bit digest.",
    ),
    digest_entry(
        "sha3-256",
        "SHA3-256",
        &[],
        "SHA-3",
        128,
        FipsStatus::Approved,
        &S_FIPS_202,
        &SHA3_256_P,
        "ac_hash::Sha3_256",
        "let d = ac_hash::Sha3_256::digest(b\"message\");",
        &SHA3_EDGE,
        "A structurally different alternative to SHA-256, for algorithm diversity.",
    ),
    digest_entry(
        "sha3-384",
        "SHA3-384",
        &[],
        "SHA-3",
        192,
        FipsStatus::Approved,
        &S_FIPS_202,
        &SHA3_384_P,
        "ac_hash::Sha3_384",
        "let d = ac_hash::Sha3_384::digest(b\"message\");",
        &SHA3_EDGE,
        "Keccak-based 384-bit digest.",
    ),
    digest_entry(
        "sha3-512",
        "SHA3-512",
        &[],
        "SHA-3",
        256,
        FipsStatus::Approved,
        &S_FIPS_202,
        &SHA3_512_P,
        "ac_hash::Sha3_512",
        "let d = ac_hash::Sha3_512::digest(b\"message\");",
        &SHA3_EDGE,
        "Keccak-based 512-bit digest.",
    ),
    Entry {
        id: "shake128",
        name: "SHAKE128",
        aliases: &[],
        summary: "Extendable-output function; squeeze any number of bytes at 128-bit strength.",
        class: Class::Xof,
        family: "SHA-3",
        purposes: &[Purpose::Integrity, Purpose::KeyDerivation],
        strength: Strength::symmetric(128),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["FIPS 202"],
        params: &NO_PARAMS,
        constraints: &[NOT_FOR_PASSWORDS],
        edges: &SHA3_EDGE,
        performance: Performance::Fast,
        rust_path: "ac_hash::Shake128",
        example: "let mut out = [0u8; 64];\nac_hash::Shake128::xof(b\"seed\", &mut out);",
        notes: "Used as the symmetric core of the FIPS 203/204 post-quantum schemes.",
    },
    Entry {
        id: "shake256",
        name: "SHAKE256",
        aliases: &[],
        summary: "Extendable-output function at 256-bit strength.",
        class: Class::Xof,
        family: "SHA-3",
        purposes: &[Purpose::Integrity, Purpose::KeyDerivation],
        strength: Strength::symmetric(256),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["FIPS 202"],
        params: &NO_PARAMS,
        constraints: &[NOT_FOR_PASSWORDS],
        edges: &SHA3_EDGE,
        performance: Performance::Fast,
        rust_path: "ac_hash::Shake256",
        example: "let mut out = [0u8; 64];\nac_hash::Shake256::xof(b\"seed\", &mut out);",
        notes: "",
    },
    Entry {
        id: "sha-1",
        name: "SHA-1",
        aliases: &["sha1"],
        summary: "Broken hash. Listed so that a request for it resolves to an explicit refusal.",
        class: Class::Hash,
        family: "SHA-1",
        purposes: &[Purpose::Integrity],
        strength: Strength { classical: 0, quantum: 0 },
        fips: FipsStatus::Disallowed,
        status: ImplStatus::Excluded,
        standards: &["FIPS 180-4"],
        params: &NO_PARAMS,
        constraints: &[NOT_COLLISION_RESISTANT],
        edges: &[Edge { relation: Relation::SupersededBy, target: "sha2-256" }],
        performance: Performance::Fast,
        rust_path: "",
        example: "",
        notes: "Chosen-prefix collisions are practical. Not implemented, and not planned. If a \
                legacy protocol requires it, that protocol needs replacing, not a SHA-1 \
                implementation.",
    },
    Entry {
        id: "md5",
        name: "MD5",
        aliases: &[],
        summary: "Broken hash, listed only to resolve requests for it to a refusal.",
        class: Class::Hash,
        family: "MD",
        purposes: &[Purpose::Integrity],
        strength: Strength { classical: 0, quantum: 0 },
        fips: FipsStatus::Disallowed,
        status: ImplStatus::Excluded,
        standards: &["RFC 1321"],
        params: &NO_PARAMS,
        constraints: &[NOT_COLLISION_RESISTANT],
        edges: &[Edge { relation: Relation::SupersededBy, target: "sha2-256" }],
        performance: Performance::Fast,
        rust_path: "",
        example: "",
        notes: "Collisions take seconds on a laptop. Not implemented, and not planned.",
    },
    // -- MACs ---------------------------------------------------------------
    Entry {
        id: "hmac-sha2-256",
        name: "HMAC-SHA-256",
        aliases: &["hmac-sha256"],
        summary: "The default keyed authenticator: approved, fast, and universally supported.",
        class: Class::Mac,
        family: "HMAC",
        purposes: &[Purpose::Authentication, Purpose::Integrity],
        strength: Strength::symmetric(256),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["FIPS 198-1", "RFC 2104"],
        params: &HMAC_KEY_P,
        constraints: &[CT_COMPARE, NOT_FOR_PASSWORDS],
        edges: &[
            Edge { relation: Relation::BuiltOn, target: "sha2-256" },
            Edge { relation: Relation::PairsWith, target: "hkdf-sha2-256" },
        ],
        performance: Performance::Fast,
        rust_path: "ac_mac::HmacSha256",
        example: "use ac_core::traits::Mac;\nlet tag = ac_mac::HmacSha256::mac(key, msg)?;",
        notes: "HMAC is secure even with a length-extendable hash, which is why it is preferred \
                over a bare keyed SHA-2.",
    },
    Entry {
        id: "hmac-sha2-384",
        name: "HMAC-SHA-384",
        aliases: &["hmac-sha384"],
        summary: "HMAC at 384-bit output, common in TLS 1.2 suites and CNSA-aligned profiles.",
        class: Class::Mac,
        family: "HMAC",
        purposes: &[Purpose::Authentication, Purpose::Integrity],
        strength: Strength::symmetric(384),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["FIPS 198-1"],
        params: &HMAC_KEY_P,
        constraints: &[CT_COMPARE, NOT_FOR_PASSWORDS],
        edges: &[Edge { relation: Relation::BuiltOn, target: "sha2-384" }],
        performance: Performance::Fast,
        rust_path: "ac_mac::HmacSha384",
        example: "use ac_core::traits::Mac;\nlet tag = ac_mac::HmacSha384::mac(key, msg)?;",
        notes: "",
    },
    Entry {
        id: "hmac-sha2-512",
        name: "HMAC-SHA-512",
        aliases: &["hmac-sha512"],
        summary: "HMAC at 512-bit output.",
        class: Class::Mac,
        family: "HMAC",
        purposes: &[Purpose::Authentication, Purpose::Integrity],
        strength: Strength::symmetric(512),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["FIPS 198-1"],
        params: &HMAC_KEY_P,
        constraints: &[CT_COMPARE, NOT_FOR_PASSWORDS],
        edges: &[Edge { relation: Relation::BuiltOn, target: "sha2-512" }],
        performance: Performance::Fast,
        rust_path: "ac_mac::HmacSha512",
        example: "use ac_core::traits::Mac;\nlet tag = ac_mac::HmacSha512::mac(key, msg)?;",
        notes: "",
    },
    Entry {
        id: "hmac-sha2-512-256",
        name: "HMAC-SHA-512/256",
        aliases: &[],
        summary: "HMAC over SHA-512/256: 32-byte tags at 64-bit-word speed.",
        class: Class::Mac,
        family: "HMAC",
        purposes: &[Purpose::Authentication, Purpose::Integrity],
        strength: Strength::symmetric(256),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["FIPS 198-1"],
        params: &HMAC_KEY_P,
        constraints: &[CT_COMPARE, NOT_FOR_PASSWORDS],
        edges: &[Edge { relation: Relation::BuiltOn, target: "sha2-512-256" }],
        performance: Performance::Fast,
        rust_path: "ac_mac::HmacSha512_256",
        example: "use ac_core::traits::Mac;\nlet tag = ac_mac::HmacSha512_256::mac(key, msg)?;",
        notes: "",
    },
    Entry {
        id: "hmac-sha3-256",
        name: "HMAC-SHA3-256",
        aliases: &[],
        summary: "HMAC over SHA3-256, for deployments wanting Keccak rather than SHA-2.",
        class: Class::Mac,
        family: "HMAC",
        purposes: &[Purpose::Authentication, Purpose::Integrity],
        strength: Strength::symmetric(256),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["FIPS 198-1", "FIPS 202"],
        params: &HMAC_KEY_P,
        constraints: &[CT_COMPARE, NOT_FOR_PASSWORDS],
        edges: &[Edge { relation: Relation::BuiltOn, target: "sha3-256" }],
        performance: Performance::Fast,
        rust_path: "ac_mac::HmacSha3_256",
        example: "use ac_core::traits::Mac;\nlet tag = ac_mac::HmacSha3_256::mac(key, msg)?;",
        notes: "KMAC is the purpose-built Keccak MAC and is generally preferable; it is not yet \
                implemented here.",
    },
    Entry {
        id: "hmac-sha3-512",
        name: "HMAC-SHA3-512",
        aliases: &[],
        summary: "HMAC over SHA3-512.",
        class: Class::Mac,
        family: "HMAC",
        purposes: &[Purpose::Authentication, Purpose::Integrity],
        strength: Strength::symmetric(512),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["FIPS 198-1", "FIPS 202"],
        params: &HMAC_KEY_P,
        constraints: &[CT_COMPARE, NOT_FOR_PASSWORDS],
        edges: &[Edge { relation: Relation::BuiltOn, target: "sha3-512" }],
        performance: Performance::Fast,
        rust_path: "ac_mac::HmacSha3_512",
        example: "use ac_core::traits::Mac;\nlet tag = ac_mac::HmacSha3_512::mac(key, msg)?;",
        notes: "",
    },
    Entry {
        id: "cmac-aes-128",
        name: "CMAC-AES-128",
        aliases: &["aes-128-cmac"],
        summary: "Block-cipher MAC, for systems that have AES hardware but no hash accelerator.",
        class: Class::Mac,
        family: "CMAC",
        purposes: &[Purpose::Authentication, Purpose::Integrity],
        strength: Strength::symmetric(128),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-38B"],
        params: &[P_KEY_16, P_TAG_16],
        constraints: &[CT_COMPARE],
        edges: &[Edge { relation: Relation::BuiltOn, target: "aes-128" }],
        performance: Performance::Slow,
        rust_path: "ac_mac::CmacAes128",
        example: "use ac_core::traits::Mac;\nlet tag = ac_mac::CmacAes128::mac(key, msg)?;",
        notes: "Slow in this build because the portable AES backend is slow; see the crate docs.",
    },
    Entry {
        id: "cmac-aes-192",
        name: "CMAC-AES-192",
        aliases: &[],
        summary: "CMAC keyed with AES-192.",
        class: Class::Mac,
        family: "CMAC",
        purposes: &[Purpose::Authentication, Purpose::Integrity],
        strength: Strength::symmetric(192),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-38B"],
        params: &[P_KEY_24, P_TAG_16],
        constraints: &[CT_COMPARE],
        edges: &[Edge { relation: Relation::BuiltOn, target: "aes-192" }],
        performance: Performance::Slow,
        rust_path: "ac_mac::CmacAes192",
        example: "use ac_core::traits::Mac;\nlet tag = ac_mac::CmacAes192::mac(key, msg)?;",
        notes: "",
    },
    Entry {
        id: "cmac-aes-256",
        name: "CMAC-AES-256",
        aliases: &[],
        summary: "CMAC keyed with AES-256.",
        class: Class::Mac,
        family: "CMAC",
        purposes: &[Purpose::Authentication, Purpose::Integrity],
        strength: Strength::symmetric(256),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-38B"],
        params: &[P_KEY_32, P_TAG_16],
        constraints: &[CT_COMPARE],
        edges: &[Edge { relation: Relation::BuiltOn, target: "aes-256" }],
        performance: Performance::Slow,
        rust_path: "ac_mac::CmacAes256",
        example: "use ac_core::traits::Mac;\nlet tag = ac_mac::CmacAes256::mac(key, msg)?;",
        notes: "",
    },
    Entry {
        id: "poly1305",
        name: "Poly1305",
        aliases: &[],
        summary: "One-time authenticator; the authentication half of ChaCha20-Poly1305.",
        class: Class::Mac,
        family: "Poly1305",
        purposes: &[Purpose::Authentication],
        strength: Strength::symmetric(128),
        fips: FipsStatus::NotApproved,
        status: ImplStatus::Available,
        standards: &["RFC 8439"],
        params: &[P_KEY_32, P_TAG_16],
        constraints: &[ONE_TIME_KEY, CT_COMPARE],
        edges: &[Edge { relation: Relation::PairsWith, target: "chacha20-poly1305" }],
        performance: Performance::Fast,
        rust_path: "ac_cipher::Poly1305",
        example: "use ac_core::traits::Mac;\nlet tag = ac_cipher::Poly1305::mac(one_time_key, msg)?;",
        notes: "Almost always the wrong thing to call directly; use the AEAD, which derives a fresh \
                one-time key per message.",
    },
    // -- Block ciphers and modes -------------------------------------------
    Entry {
        id: "aes-128",
        name: "AES-128",
        aliases: &[],
        summary: "The raw AES-128 permutation. A building block, not an encryption scheme.",
        class: Class::BlockCipher,
        family: "AES",
        purposes: &[Purpose::Confidentiality],
        strength: Strength::symmetric(128),
        fips: FipsStatus::AllowedAsComponent,
        status: ImplStatus::Available,
        standards: &["FIPS 197"],
        params: &[P_KEY_16],
        constraints: &[AEAD_NOT_RAW],
        edges: &[Edge { relation: Relation::PairsWith, target: "aes-128-gcm" }],
        performance: Performance::Slow,
        rust_path: "ac_cipher::Aes128",
        example: "use ac_core::traits::BlockCipher;\nlet c = ac_cipher::Aes128::new(key)?;",
        notes: "Encrypting more than one block with this directly is ECB, which leaks structure.",
    },
    Entry {
        id: "aes-192",
        name: "AES-192",
        aliases: &[],
        summary: "The raw AES-192 permutation.",
        class: Class::BlockCipher,
        family: "AES",
        purposes: &[Purpose::Confidentiality],
        strength: Strength::symmetric(192),
        fips: FipsStatus::AllowedAsComponent,
        status: ImplStatus::Available,
        standards: &["FIPS 197"],
        params: &[P_KEY_24],
        constraints: &[AEAD_NOT_RAW],
        edges: &[Edge { relation: Relation::PairsWith, target: "aes-192-gcm" }],
        performance: Performance::Slow,
        rust_path: "ac_cipher::Aes192",
        example: "use ac_core::traits::BlockCipher;\nlet c = ac_cipher::Aes192::new(key)?;",
        notes: "",
    },
    Entry {
        id: "aes-256",
        name: "AES-256",
        aliases: &[],
        summary: "The raw AES-256 permutation.",
        class: Class::BlockCipher,
        family: "AES",
        purposes: &[Purpose::Confidentiality],
        strength: Strength::symmetric(256),
        fips: FipsStatus::AllowedAsComponent,
        status: ImplStatus::Available,
        standards: &["FIPS 197"],
        params: &[P_KEY_32],
        constraints: &[AEAD_NOT_RAW],
        edges: &[Edge { relation: Relation::PairsWith, target: "aes-256-gcm" }],
        performance: Performance::Slow,
        rust_path: "ac_cipher::Aes256",
        example: "use ac_core::traits::BlockCipher;\nlet c = ac_cipher::Aes256::new(key)?;",
        notes: "",
    },
    Entry {
        id: "aes-cbc",
        name: "AES-CBC",
        aliases: &["cbc"],
        summary: "Unauthenticated CBC mode. Use only to interoperate with an existing format.",
        class: Class::CipherMode,
        family: "AES",
        purposes: &[Purpose::Confidentiality],
        strength: Strength::symmetric(256),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-38A"],
        params: &[P_IV_16],
        constraints: &[AEAD_NOT_RAW],
        edges: &[Edge { relation: Relation::SupersededBy, target: "aes-256-gcm" }],
        performance: Performance::Slow,
        rust_path: "ac_cipher::cbc_encrypt",
        example: "ac_cipher::cbc_encrypt(&cipher, &iv, &mut data)?;",
        notes: "The IV must be unpredictable, not merely unique. Padding oracles are the classic \
                failure; authenticate the ciphertext.",
    },
    Entry {
        id: "aes-ctr",
        name: "AES-CTR",
        aliases: &["ctr"],
        summary: "Unauthenticated counter mode; turns AES into a stream cipher.",
        class: Class::CipherMode,
        family: "AES",
        purposes: &[Purpose::Confidentiality],
        strength: Strength::symmetric(256),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-38A"],
        params: &[P_IV_16],
        constraints: &[AEAD_NOT_RAW, UNIQUE_NONCE],
        edges: &[Edge { relation: Relation::SupersededBy, target: "aes-256-gcm" }],
        performance: Performance::Slow,
        rust_path: "ac_cipher::ctr_xor",
        example: "ac_cipher::ctr_xor(&cipher, &iv, &mut data)?;",
        notes: "The counter half of GCM. Reusing a counter value under one key is fatal.",
    },
    // -- AEADs --------------------------------------------------------------
    Entry {
        id: "aes-128-gcm",
        name: "AES-128-GCM",
        aliases: &["aes128gcm"],
        summary: "Authenticated encryption at 128-bit strength; the TLS 1.3 default.",
        class: Class::Aead,
        family: "AES-GCM",
        purposes: &[Purpose::Confidentiality, Purpose::Authentication, Purpose::Integrity],
        strength: Strength::symmetric(128),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-38D"],
        params: &[P_KEY_16, P_GCM_NONCE, P_TAG_16],
        constraints: &[UNIQUE_NONCE, NONCE_COUNTER],
        edges: &[Edge { relation: Relation::BuiltOn, target: "aes-128" }],
        performance: Performance::Slow,
        rust_path: "ac_cipher::Aes128Gcm",
        example: "use ac_core::traits::Aead;\nlet c = ac_cipher::Aes128Gcm::new(key)?;\nc.seal_detached(&nonce, aad, &mut buf, &mut tag)?;",
        notes: "",
    },
    Entry {
        id: "aes-192-gcm",
        name: "AES-192-GCM",
        aliases: &[],
        summary: "Authenticated encryption at 192-bit strength.",
        class: Class::Aead,
        family: "AES-GCM",
        purposes: &[Purpose::Confidentiality, Purpose::Authentication, Purpose::Integrity],
        strength: Strength::symmetric(192),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-38D"],
        params: &[P_KEY_24, P_GCM_NONCE, P_TAG_16],
        constraints: &[UNIQUE_NONCE, NONCE_COUNTER],
        edges: &[Edge { relation: Relation::BuiltOn, target: "aes-192" }],
        performance: Performance::Slow,
        rust_path: "ac_cipher::Aes192Gcm",
        example: "use ac_core::traits::Aead;\nlet c = ac_cipher::Aes192Gcm::new(key)?;",
        notes: "Rarely used; prefer 128 or 256.",
    },
    Entry {
        id: "aes-256-gcm",
        name: "AES-256-GCM",
        aliases: &["aes256gcm"],
        summary: "The default choice for authenticated encryption under a FIPS requirement.",
        class: Class::Aead,
        family: "AES-GCM",
        purposes: &[Purpose::Confidentiality, Purpose::Authentication, Purpose::Integrity],
        strength: Strength::symmetric(256),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-38D"],
        params: &[P_KEY_32, P_GCM_NONCE, P_TAG_16],
        constraints: &[UNIQUE_NONCE, NONCE_COUNTER],
        edges: &[Edge { relation: Relation::BuiltOn, target: "aes-256" }],
        performance: Performance::Slow,
        rust_path: "ac_cipher::Aes256Gcm",
        example: "use ac_core::traits::Aead;\nlet c = ac_cipher::Aes256Gcm::new(key)?;\nc.seal_detached(&nonce, aad, &mut buf, &mut tag)?;",
        notes: "Also the choice when a single key must protect data for a long time, since the \
                256-bit key retains 128-bit strength against Grover.",
    },
    Entry {
        id: "chacha20-poly1305",
        name: "ChaCha20-Poly1305",
        aliases: &["chachapoly"],
        summary: "Authenticated encryption that is fast in software on any CPU.",
        class: Class::Aead,
        family: "ChaCha",
        purposes: &[Purpose::Confidentiality, Purpose::Authentication, Purpose::Integrity],
        strength: Strength::symmetric(256),
        fips: FipsStatus::NotApproved,
        status: ImplStatus::Available,
        standards: &["RFC 8439"],
        params: &[P_KEY_32, P_NONCE_12, P_TAG_16],
        constraints: &[UNIQUE_NONCE],
        edges: &[Edge { relation: Relation::BuiltOn, target: "poly1305" }],
        performance: Performance::Fast,
        rust_path: "ac_cipher::ChaCha20Poly1305",
        example: "use ac_core::traits::Aead;\nlet c = ac_cipher::ChaCha20Poly1305::new(key)?;\nc.seal_detached(&nonce, aad, &mut buf, &mut tag)?;",
        notes: "The right answer without AES hardware, and much faster than this build's portable \
                AES. Blocked in FIPS approved mode.",
    },
    // -- KDFs ---------------------------------------------------------------
    Entry {
        id: "hkdf-sha2-256",
        name: "HKDF-SHA-256",
        aliases: &["hkdf"],
        summary: "Extract-and-expand KDF; the default way to turn a shared secret into keys.",
        class: Class::Kdf,
        family: "HKDF",
        purposes: &[Purpose::KeyDerivation],
        strength: Strength::symmetric(256),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["RFC 5869", "SP 800-56C"],
        params: &NO_PARAMS,
        constraints: &[NOT_FOR_PASSWORDS],
        edges: &[
            Edge { relation: Relation::BuiltOn, target: "hmac-sha2-256" },
            Edge { relation: Relation::PairsWith, target: "x25519" },
        ],
        performance: Performance::Fast,
        rust_path: "ac_kdf::Hkdf::<ac_mac::HmacSha256>",
        example: "use ac_core::traits::Kdf;\nac_kdf::Hkdf::<ac_mac::HmacSha256>::derive(ikm, salt, info, &mut key)?;",
        notes: "Always pass a distinct `info` per derived key; that is what keeps two keys from the \
                same secret independent.",
    },
    Entry {
        id: "hkdf-sha2-384",
        name: "HKDF-SHA-384",
        aliases: &[],
        summary: "HKDF over HMAC-SHA-384.",
        class: Class::Kdf,
        family: "HKDF",
        purposes: &[Purpose::KeyDerivation],
        strength: Strength::symmetric(384),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["RFC 5869", "SP 800-56C"],
        params: &NO_PARAMS,
        constraints: &[NOT_FOR_PASSWORDS],
        edges: &[Edge { relation: Relation::BuiltOn, target: "hmac-sha2-384" }],
        performance: Performance::Fast,
        rust_path: "ac_kdf::Hkdf::<ac_mac::HmacSha384>",
        example: "use ac_core::traits::Kdf;\nac_kdf::Hkdf::<ac_mac::HmacSha384>::derive(ikm, salt, info, &mut key)?;",
        notes: "",
    },
    Entry {
        id: "hkdf-sha2-512",
        name: "HKDF-SHA-512",
        aliases: &[],
        summary: "HKDF over HMAC-SHA-512.",
        class: Class::Kdf,
        family: "HKDF",
        purposes: &[Purpose::KeyDerivation],
        strength: Strength::symmetric(512),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["RFC 5869", "SP 800-56C"],
        params: &NO_PARAMS,
        constraints: &[NOT_FOR_PASSWORDS],
        edges: &[Edge { relation: Relation::BuiltOn, target: "hmac-sha2-512" }],
        performance: Performance::Fast,
        rust_path: "ac_kdf::Hkdf::<ac_mac::HmacSha512>",
        example: "use ac_core::traits::Kdf;\nac_kdf::Hkdf::<ac_mac::HmacSha512>::derive(ikm, salt, info, &mut key)?;",
        notes: "",
    },
    Entry {
        id: "sp800-108-counter-hmac-sha2-256",
        name: "SP 800-108 KDF (counter mode, HMAC-SHA-256)",
        aliases: &["kbkdf", "sp800-108"],
        summary: "Expands one key-derivation key into many application keys.",
        class: Class::Kdf,
        family: "SP 800-108",
        purposes: &[Purpose::KeyDerivation],
        strength: Strength::symmetric(256),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-108r1"],
        params: &NO_PARAMS,
        constraints: &[NOT_FOR_PASSWORDS],
        edges: &[Edge { relation: Relation::BuiltOn, target: "hmac-sha2-256" }],
        performance: Performance::Fast,
        rust_path: "ac_kdf::kbkdf_counter",
        example: "ac_kdf::kbkdf_counter::<ac_mac::HmacSha256>(kdk, b\"label\", ctx, &mut key)?;",
        notes: "Use when the input is already a uniform key. Use HKDF when it is a Diffie-Hellman \
                shared secret or other non-uniform material.",
    },
    Entry {
        id: "pbkdf2-hmac-sha2-256",
        name: "PBKDF2-HMAC-SHA-256",
        aliases: &["pbkdf2"],
        summary: "Password-based key derivation. The only approved option, not the strongest one.",
        class: Class::PasswordKdf,
        family: "PBKDF2",
        purposes: &[Purpose::PasswordHashing, Purpose::KeyDerivation],
        strength: Strength::symmetric(256),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-132", "RFC 8018"],
        params: &PBKDF2_P,
        constraints: &[SALT_REQUIRED],
        edges: &[Edge { relation: Relation::BuiltOn, target: "hmac-sha2-256" }],
        performance: Performance::DeliberatelySlow,
        rust_path: "ac_kdf::pbkdf2",
        example: "ac_kdf::pbkdf2::<ac_mac::HmacSha256>(password, salt, 600_000, &mut key)?;",
        notes: "PBKDF2 is not memory-hard, so a GPU attacks it far faster than a CPU defends it. \
                Where FIPS approval is not required, Argon2id is the better choice; it is not \
                implemented here.",
    },
    Entry {
        id: "pbkdf2-hmac-sha2-512",
        name: "PBKDF2-HMAC-SHA-512",
        aliases: &[],
        summary: "PBKDF2 over HMAC-SHA-512.",
        class: Class::PasswordKdf,
        family: "PBKDF2",
        purposes: &[Purpose::PasswordHashing, Purpose::KeyDerivation],
        strength: Strength::symmetric(512),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-132"],
        params: &PBKDF2_P,
        constraints: &[SALT_REQUIRED],
        edges: &[Edge { relation: Relation::BuiltOn, target: "hmac-sha2-512" }],
        performance: Performance::DeliberatelySlow,
        rust_path: "ac_kdf::pbkdf2",
        example: "ac_kdf::pbkdf2::<ac_mac::HmacSha512>(password, salt, 600_000, &mut key)?;",
        notes: "",
    },
    Entry {
        id: "argon2id",
        name: "Argon2id",
        aliases: &["argon2"],
        summary: "Memory-hard password hashing; the best available answer outside FIPS.",
        class: Class::PasswordKdf,
        family: "Argon2",
        purposes: &[Purpose::PasswordHashing],
        strength: Strength::symmetric(256),
        fips: FipsStatus::NotApproved,
        status: ImplStatus::Planned,
        standards: &["RFC 9106"],
        params: &NO_PARAMS,
        constraints: &[SALT_REQUIRED],
        edges: &[Edge { relation: Relation::Supersedes, target: "pbkdf2-hmac-sha2-256" }],
        performance: Performance::DeliberatelySlow,
        rust_path: "",
        example: "",
        notes: "Not implemented yet. Until it lands, use PBKDF2 with a high iteration count, or an \
                external Argon2 implementation.",
    },
    // -- DRBGs --------------------------------------------------------------
    Entry {
        id: "hmac-drbg-sha2-256",
        name: "HMAC_DRBG (SHA-256)",
        aliases: &["hmac-drbg"],
        summary: "The default random bit generator; conditions its own entropy input.",
        class: Class::Drbg,
        family: "SP 800-90A",
        purposes: &[Purpose::RandomGeneration],
        strength: Strength::symmetric(256),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-90A"],
        params: &NO_PARAMS,
        constraints: &[RESEED_INTERVAL],
        edges: &[Edge { relation: Relation::BuiltOn, target: "hmac-sha2-256" }],
        performance: Performance::Fast,
        rust_path: "ac_drbg::HmacDrbgSha256",
        example: "let mut rng = ac_drbg::Rng::from_os()?;\nlet key: [u8; 32] = rng.random_array()?;",
        notes: "Prefer `ac_drbg::Rng`, which seeds this from the OS and reseeds on schedule.",
    },
    Entry {
        id: "hmac-drbg-sha2-512",
        name: "HMAC_DRBG (SHA-512)",
        aliases: &[],
        summary: "HMAC_DRBG instantiated with SHA-512.",
        class: Class::Drbg,
        family: "SP 800-90A",
        purposes: &[Purpose::RandomGeneration],
        strength: Strength::symmetric(256),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-90A"],
        params: &NO_PARAMS,
        constraints: &[RESEED_INTERVAL],
        edges: &[Edge { relation: Relation::BuiltOn, target: "hmac-sha2-512" }],
        performance: Performance::Fast,
        rust_path: "ac_drbg::HmacDrbgSha512",
        example: "use ac_core::traits::Drbg;\nlet mut d = ac_drbg::HmacDrbgSha512::instantiate(entropy, nonce, b\"app\")?;",
        notes: "",
    },
    Entry {
        id: "ctr-drbg-aes-256",
        name: "CTR_DRBG (AES-256, no df)",
        aliases: &["ctr-drbg"],
        summary: "Block-cipher DRBG, for systems whose entropy source is already conditioned.",
        class: Class::Drbg,
        family: "SP 800-90A",
        purposes: &[Purpose::RandomGeneration],
        strength: Strength::symmetric(256),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-90A"],
        params: &[Param {
            name: "entropy",
            unit: Unit::Bytes,
            min: 48,
            max: 48,
            recommended: 48,
            note: "Without a derivation function the seed must be exactly key+block bytes of \
                   full-entropy input.",
        }],
        constraints: &[RESEED_INTERVAL],
        edges: &[Edge { relation: Relation::BuiltOn, target: "aes-256" }],
        performance: Performance::Slow,
        rust_path: "ac_drbg::CtrDrbg",
        example: "use ac_core::traits::Drbg;\nlet mut d = ac_drbg::CtrDrbg::instantiate(&seed48, &[], &[])?;",
        notes: "If the entropy is not already uniform, use HMAC_DRBG instead; it conditions its \
                input.",
    },
    // -- Key establishment --------------------------------------------------
    Entry {
        id: "x25519",
        name: "X25519",
        aliases: &["curve25519", "ecdh-x25519"],
        summary: "Diffie-Hellman on Curve25519; fast, misuse-resistant, not FIPS-approved.",
        class: Class::KeyAgreement,
        family: "Curve25519",
        purposes: &[Purpose::KeyEstablishment],
        strength: Strength::classical_only(128),
        fips: FipsStatus::NotApproved,
        status: ImplStatus::Available,
        standards: &["RFC 7748"],
        params: &X25519_P,
        constraints: &[VALIDATE_PEER_KEY, HASH_TRANSCRIPT],
        edges: &[Edge { relation: Relation::PairsWith, target: "hkdf-sha2-256" }],
        performance: Performance::Moderate,
        rust_path: "ac_ec::X25519",
        example: "use ac_core::traits::KeyAgreement;\nac_ec::X25519::agree(&my_sk, &peer_pk, &mut shared)?;",
        notes: "Shor breaks this outright; pair it with ML-KEM in a hybrid once that lands.",
    },
    Entry {
        id: "ecdh-p256",
        name: "ECDH P-256",
        aliases: &["ecdh-secp256r1"],
        summary: "The FIPS-approved key agreement scheme, and the one TLS uses most.",
        class: Class::KeyAgreement,
        family: "NIST P-curves",
        purposes: &[Purpose::KeyEstablishment],
        strength: Strength::classical_only(128),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-56A", "SP 800-186"],
        params: &P256_KA_P,
        constraints: &[VALIDATE_PEER_KEY, HASH_TRANSCRIPT],
        edges: &[Edge { relation: Relation::PairsWith, target: "hkdf-sha2-256" }],
        performance: Performance::Moderate,
        rust_path: "ac_ec::p256::EcdhP256",
        example: "use ac_core::traits::KeyAgreement;\nac_ec::p256::EcdhP256::agree(&my_sk, &peer_pk, &mut shared)?;",
        notes: "Public keys are SEC1; both the 65-byte uncompressed and the 33-byte compressed \
                form are accepted, and a peer key is checked against the curve equation before \
                use. The shared secret is a coordinate, not a key: run it through a KDF.",
    },
    Entry {
        id: "ml-kem-768",
        name: "ML-KEM-768",
        aliases: &["kyber768", "kyber"],
        summary: "Post-quantum key encapsulation; the standardized successor to Kyber.",
        class: Class::Kem,
        family: "ML-KEM",
        purposes: &[Purpose::KeyEstablishment],
        strength: Strength { classical: 192, quantum: 192 },
        fips: FipsStatus::Approved,
        status: ImplStatus::Planned,
        standards: &["FIPS 203"],
        params: &NO_PARAMS,
        constraints: &NO_CONSTRAINTS,
        edges: &[Edge { relation: Relation::Supersedes, target: "x25519" }],
        performance: Performance::Fast,
        rust_path: "",
        example: "",
        notes: "Not implemented yet. Deploy it alongside X25519 in a hybrid rather than alone, so a \
                flaw in either leaves the other standing.",
    },
    // -- Signatures ---------------------------------------------------------
    Entry {
        id: "ed25519",
        name: "Ed25519",
        aliases: &["eddsa"],
        summary: "Deterministic signatures on Curve25519; fast and hard to misuse.",
        class: Class::Signature,
        family: "Curve25519",
        purposes: &[Purpose::Authentication, Purpose::NonRepudiation, Purpose::Integrity],
        strength: Strength::classical_only(128),
        fips: FipsStatus::NotApproved,
        status: ImplStatus::Available,
        standards: &["RFC 8032"],
        params: &ED25519_P,
        constraints: &[Constraint {
            id: "reject-non-canonical-s",
            requirement: "Reject signatures whose S component is not reduced modulo the group order.",
            consequence: "The signature becomes malleable, breaking any system that treats a \
                          signature as a unique identifier.",
            severity: Severity::Serious,
        }],
        edges: &[Edge { relation: Relation::BuiltOn, target: "sha2-512" }],
        performance: Performance::Moderate,
        rust_path: "ac_ec::Ed25519",
        example: "use ac_core::traits::SignatureScheme;\nac_ec::Ed25519::sign(&seed, msg, &mut sig)?;\nac_ec::Ed25519::verify(&pk, msg, &sig)?;",
        notes: "Signing needs no RNG, which removes the nonce-reuse failure that has broken ECDSA \
                deployments. FIPS 186-5 approves EdDSA, but this implementation is not validated; \
                the ontology reports it as not-approved so approved mode blocks it rather than \
                implying a validation that does not exist.",
    },
    Entry {
        id: "ecdsa-p256-sha256",
        name: "ECDSA P-256 with SHA-256",
        aliases: &["ecdsa-secp256r1"],
        summary: "The most widely deployed approved signature scheme.",
        class: Class::Signature,
        family: "NIST P-curves",
        purposes: &[Purpose::Authentication, Purpose::NonRepudiation],
        strength: Strength::classical_only(128),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["FIPS 186-5", "SP 800-186", "RFC 6979"],
        params: &P256_SIG_P,
        constraints: &[
            Constraint {
                id: "unique-signing-nonce",
                requirement: "Generate a fresh random k per signature, or derive it \
                              deterministically per RFC 6979.",
                consequence: "A repeated or predictable k reveals the private key from two \
                              signatures.",
                severity: Severity::Critical,
            },
            Constraint {
                id: "ecdsa-is-malleable",
                requirement: "Normalize to low-s, or do not treat a signature as a unique \
                              identifier.",
                consequence: "Both (r, s) and (r, n - s) verify, so a signature used as a \
                              database key or transaction id can be duplicated.",
                severity: Severity::Serious,
            },
        ],
        edges: &[
            Edge { relation: Relation::BuiltOn, target: "sha2-256" },
            Edge { relation: Relation::PairsWith, target: "ecdh-p256" },
        ],
        performance: Performance::Moderate,
        rust_path: "ac_ec::p256::EcdsaP256Sha256",
        example: "use ac_core::traits::SignatureScheme;\nac_ec::p256::EcdsaP256Sha256::sign(&sk, msg, &mut sig)?;\nac_ec::p256::EcdsaP256Sha256::verify(&pk, msg, &sig)?;",
        notes: "This implementation derives k deterministically per RFC 6979, so the \
                unique-signing-nonce constraint is satisfied by construction and there is no RNG \
                in the signing path. Signatures are fixed-width r || s, not DER.",
    },
    Entry {
        id: "ml-dsa-65",
        name: "ML-DSA-65",
        aliases: &["dilithium3", "dilithium"],
        summary: "Post-quantum signatures; the standardized successor to Dilithium.",
        class: Class::Signature,
        family: "ML-DSA",
        purposes: &[Purpose::Authentication, Purpose::NonRepudiation],
        strength: Strength { classical: 192, quantum: 192 },
        fips: FipsStatus::Approved,
        status: ImplStatus::Planned,
        standards: &["FIPS 204"],
        params: &NO_PARAMS,
        constraints: &NO_CONSTRAINTS,
        edges: &[Edge { relation: Relation::Supersedes, target: "ecdsa-p256-sha256" }],
        performance: Performance::Moderate,
        rust_path: "",
        example: "",
        notes: "Not implemented yet.",
    },
    Entry {
        id: "rsa-pkcs1-v1_5",
        name: "RSA PKCS#1 v1.5 signatures",
        aliases: &["rsassa-pkcs1"],
        summary: "Legacy RSA signature padding, kept for verification of existing artifacts.",
        class: Class::Signature,
        family: "RSA",
        purposes: &[Purpose::Authentication, Purpose::NonRepudiation],
        strength: Strength::classical_only(112),
        fips: FipsStatus::Deprecated,
        status: ImplStatus::Planned,
        standards: &["FIPS 186-5", "RFC 8017"],
        params: &NO_PARAMS,
        constraints: &[Constraint {
            id: "verify-only",
            requirement: "Use for verification of existing signatures only; sign with RSA-PSS or \
                          ECDSA.",
            consequence: "Implementation flaws in v1.5 padding checks have repeatedly allowed \
                          signature forgery.",
            severity: Severity::Serious,
        }],
        edges: &[Edge { relation: Relation::SupersededBy, target: "ecdsa-p256-sha256" }],
        performance: Performance::Slow,
        rust_path: "",
        example: "",
        notes: "Not implemented yet.",
    },
    Entry {
        id: "3des",
        name: "Triple DES",
        aliases: &["tdea", "3des-ede"],
        summary: "Withdrawn block cipher, listed so requests for it resolve to a refusal.",
        class: Class::BlockCipher,
        family: "DES",
        purposes: &[Purpose::Confidentiality],
        strength: Strength { classical: 0, quantum: 0 },
        fips: FipsStatus::Disallowed,
        status: ImplStatus::Excluded,
        standards: &["SP 800-67"],
        params: &NO_PARAMS,
        constraints: &[Constraint {
            id: "sweet32",
            requirement: "Do not use; migrate to AES.",
            consequence: "The 64-bit block allows practical collision attacks on long sessions.",
            severity: Severity::Critical,
        }],
        edges: &[Edge { relation: Relation::SupersededBy, target: "aes-256" }],
        performance: Performance::Slow,
        rust_path: "",
        example: "",
        notes: "Disallowed by SP 800-131A since 2024. Not implemented, and not planned.",
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_unique_and_sorted_within_classes() {
        for (i, a) in REGISTRY.iter().enumerate() {
            for b in REGISTRY.iter().skip(i + 1) {
                assert_ne!(a.id, b.id, "duplicate id {}", a.id);
            }
        }
    }

    #[test]
    fn every_edge_points_at_a_known_entry_or_family() {
        // Family anchors that are not themselves entries.
        let families = ["sha-2", "sha-3"];
        for e in REGISTRY {
            for edge in e.edges {
                let known =
                    REGISTRY.iter().any(|t| t.id == edge.target) || families.contains(&edge.target);
                assert!(known, "{} -> {} is dangling", e.id, edge.target);
            }
        }
    }

    #[test]
    fn available_entries_name_a_rust_path_and_example() {
        for e in REGISTRY
            .iter()
            .filter(|e| e.status == ImplStatus::Available)
        {
            assert!(!e.rust_path.is_empty(), "{} has no rust_path", e.id);
            assert!(!e.example.is_empty(), "{} has no example", e.id);
        }
    }

    #[test]
    fn unavailable_entries_explain_themselves() {
        for e in REGISTRY
            .iter()
            .filter(|e| e.status != ImplStatus::Available)
        {
            assert!(
                e.rust_path.is_empty(),
                "{} claims a path it does not have",
                e.id
            );
            assert!(!e.notes.is_empty(), "{} must explain its absence", e.id);
        }
    }

    #[test]
    fn every_entry_has_a_summary_and_purpose() {
        for e in REGISTRY {
            assert!(!e.summary.is_empty(), "{} has no summary", e.id);
            assert!(!e.purposes.is_empty(), "{} serves no purpose", e.id);
            assert!(!e.standards.is_empty(), "{} cites no standard", e.id);
        }
    }

    #[test]
    fn broken_algorithms_are_marked_and_not_implemented() {
        for id in ["sha-1", "md5", "3des"] {
            let e = REGISTRY.iter().find(|e| e.id == id).unwrap();
            assert_eq!(e.fips, FipsStatus::Disallowed, "{id}");
            assert_eq!(e.status, ImplStatus::Excluded, "{id}");
            assert_eq!(e.strength.classical, 0, "{id}");
        }
    }

    #[test]
    fn aeads_all_carry_the_nonce_constraint() {
        for e in REGISTRY.iter().filter(|e| e.class == Class::Aead) {
            assert!(
                e.constraints.iter().any(|c| c.id == "unique-nonce-per-key"),
                "{} must warn about nonce reuse",
                e.id
            );
        }
    }

    #[test]
    fn unauthenticated_modes_are_flagged() {
        for e in REGISTRY.iter().filter(|e| e.class == Class::CipherMode) {
            assert!(
                e.constraints
                    .iter()
                    .any(|c| c.id == "requires-separate-mac"),
                "{} must warn that it is unauthenticated",
                e.id
            );
        }
    }

    #[test]
    fn registry_covers_every_class() {
        for class in Class::ALL {
            assert!(
                REGISTRY.iter().any(|e| e.class == *class),
                "no entry for class {}",
                class.id()
            );
        }
    }
}
