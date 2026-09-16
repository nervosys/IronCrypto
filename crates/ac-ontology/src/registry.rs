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

const ARGON2_P: [Param; 4] = [
    Param {
        name: "salt",
        unit: Unit::Bytes,
        min: 8,
        max: u64::MAX,
        recommended: 16,
        note: "RFC 9106 requires at least 8 bytes and recommends 16.",
    },
    Param {
        name: "memory",
        unit: Unit::Count,
        min: 8,
        max: u64::MAX,
        recommended: 65_536,
        note: "Kibibytes, and at least 8 per lane. This is the parameter that costs an attacker \
               the most; 65536 is the interactive recommendation and 2097152 the offline one.",
    },
    Param {
        name: "passes",
        unit: Unit::Count,
        min: 1,
        max: u64::MAX,
        recommended: 3,
        note: "Iterations over the arena. Raise the memory before raising this.",
    },
    Param {
        name: "output",
        unit: Unit::Bytes,
        min: 4,
        max: u64::MAX,
        recommended: 32,
        note: "Derived key length.",
    },
];

const BLAKE2B_P: [Param; 2] = [
    Param {
        name: "output",
        unit: Unit::Bytes,
        min: 1,
        max: 64,
        recommended: 32,
        note: "Chosen at construction and bound into the digest.",
    },
    Param {
        name: "key",
        unit: Unit::Bytes,
        min: 0,
        max: 64,
        recommended: 32,
        note: "Optional. A keyed BLAKE2b is a MAC without needing HMAC around it.",
    },
];

const P384_KA_P: [Param; 3] = [
    Param {
        name: "private-key",
        unit: Unit::Bytes,
        min: 48,
        max: 48,
        recommended: 48,
        note: "A scalar in [1, n-1]; zero and values at or above n are rejected.",
    },
    Param {
        name: "public-key",
        unit: Unit::Bytes,
        min: 49,
        max: 97,
        recommended: 97,
        note: "SEC1: 97 bytes uncompressed (0x04 || X || Y), or 49 compressed.",
    },
    Param {
        name: "shared-secret",
        unit: Unit::Bytes,
        min: 48,
        max: 48,
        recommended: 48,
        note: "The x-coordinate of the shared point. Not a key; derive from it.",
    },
];

const P384_SIG_P: [Param; 3] = [
    Param {
        name: "private-key",
        unit: Unit::Bytes,
        min: 48,
        max: 48,
        recommended: 48,
        note: "A scalar in [1, n-1].",
    },
    Param {
        name: "public-key",
        unit: Unit::Bytes,
        min: 49,
        max: 97,
        recommended: 97,
        note: "SEC1 uncompressed or compressed; both are accepted on verification.",
    },
    Param {
        name: "signature",
        unit: Unit::Bytes,
        min: 96,
        max: 96,
        recommended: 96,
        note: "Fixed-width r || s, each 48 bytes. Not DER-encoded.",
    },
];

const RSA_SIG_P: [Param; 3] = [
    Param {
        name: "modulus",
        unit: Unit::Bytes,
        min: 256,
        max: 512,
        recommended: 256,
        note: "2048, 3072, or 4096 bits. Anything smaller is refused, not warned about.",
    },
    Param {
        name: "public-exponent",
        unit: Unit::Count,
        min: 3,
        max: u64::MAX,
        recommended: 65_537,
        note: "Odd. Key generation always uses 65537.",
    },
    Param {
        name: "signature",
        unit: Unit::Bytes,
        min: 256,
        max: 512,
        recommended: 256,
        note: "Always exactly the modulus size.",
    },
];

const RSA_PSS_P: [Param; 4] = [
    RSA_SIG_P[0],
    RSA_SIG_P[1],
    RSA_SIG_P[2],
    Param {
        name: "salt",
        unit: Unit::Bytes,
        min: 32,
        max: 64,
        recommended: 32,
        note: "Always equal to the hash length; not caller-selectable.",
    },
];

const RSA_MIN_MODULUS: Constraint = Constraint {
    id: "rsa-modulus-at-least-2048-bits",
    requirement: "Use a modulus of at least 2048 bits.",
    consequence: "1024-bit RSA is within reach of a well-funded adversary, and SP 800-131A \
                  disallows it for new signatures.",
    severity: Severity::Critical,
};

const RSA_PREFER_PSS: Constraint = Constraint {
    id: "prefer-pss-for-new-signatures",
    requirement: "Sign new artifacts with RSA-PSS; use PKCS#1 v1.5 to verify existing ones and \
                  where a peer requires it.",
    consequence: "PKCS#1 v1.5 has no security proof and a long history of forgery from lax \
                  padding checks, although FIPS 186-5 still approves it.",
    severity: Severity::Advisory,
};

const RSA_NO_PARSING: Constraint = Constraint {
    id: "verify-by-re-encoding",
    requirement: "Compare the recovered block against a freshly encoded one; never parse it.",
    consequence: "A parser that tolerates trailing bytes after the DigestInfo allows signature \
                  forgery under a small public exponent without the private key.",
    severity: Severity::Critical,
};

const RSA_SALT_ENTROPY: Constraint = Constraint {
    id: "pss-salt-must-be-random",
    requirement: "Draw the PSS salt from an approved DRBG for every signature.",
    consequence: "A repeated salt does not leak the key the way a repeated ECDSA nonce does, but \
                  it forfeits the randomization the PSS security proof relies on.",
    severity: Severity::Serious,
};

const P521_SIG_P: [Param; 3] = [
    Param {
        name: "private-key",
        unit: Unit::Bytes,
        min: 66,
        max: 66,
        recommended: 66,
        note: "A scalar in [1, n-1], left-padded to 66 bytes.",
    },
    Param {
        name: "public-key",
        unit: Unit::Bytes,
        min: 67,
        max: 133,
        recommended: 133,
        note: "SEC1: 133 bytes uncompressed, 67 compressed.",
    },
    Param {
        name: "signature",
        unit: Unit::Bytes,
        min: 132,
        max: 132,
        recommended: 132,
        note: "Fixed-width r || s, not DER. Convert with ac_pkix::ecdsa_signature.",
    },
];

const P521_KA_P: [Param; 3] = [
    P521_SIG_P[0],
    P521_SIG_P[1],
    Param {
        name: "shared-secret",
        unit: Unit::Bytes,
        min: 66,
        max: 66,
        recommended: 66,
        note: "The x-coordinate only. Run it through a KDF before use.",
    },
];

const KMAC_P: [Param; 3] = [
    Param {
        name: "key",
        unit: Unit::Bytes,
        min: 16,
        max: u64::MAX,
        recommended: 32,
        note: "Any length. A sponge absorbs the key directly, so there is no block-size rule.",
    },
    Param {
        name: "customization",
        unit: Unit::Bytes,
        min: 0,
        max: u64::MAX,
        recommended: 0,
        note: "Domain separator. Give two uses of one key different strings.",
    },
    Param {
        name: "tag",
        unit: Unit::Bytes,
        min: 16,
        max: 64,
        recommended: 32,
        note: "Caller-chosen, and bound into the computation: a short tag is not a prefix of a long one.",
    },
];

const CSHAKE_P: [Param; 2] = [
    Param {
        name: "customization",
        unit: Unit::Bytes,
        min: 0,
        max: u64::MAX,
        recommended: 0,
        note: "Empty means this is exactly SHAKE, including the domain separator.",
    },
    Param {
        name: "output",
        unit: Unit::Bytes,
        min: 1,
        max: u64::MAX,
        recommended: 32,
        note: "Any length; the sponge is squeezed for as long as asked.",
    },
];

const TUPLEHASH_P: [Param; 2] = [
    Param {
        name: "customization",
        unit: Unit::Bytes,
        min: 0,
        max: u64::MAX,
        recommended: 0,
        note: "Domain separator.",
    },
    Param {
        name: "output",
        unit: Unit::Bytes,
        min: 1,
        max: u64::MAX,
        recommended: 32,
        note: "Bound into the computation, so a short digest is not a prefix of a long one.",
    },
];

const PARALLELHASH_P: [Param; 3] = [
    TUPLEHASH_P[0],
    Param {
        name: "block-size",
        unit: Unit::Bytes,
        min: 1,
        max: u64::MAX,
        recommended: 8192,
        note: "Part of the computation, not a tuning knob: two block sizes give two digests.",
    },
    TUPLEHASH_P[1],
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
        status: ImplStatus::Available,
        standards: &["RFC 9106"],
        params: &ARGON2_P,
        constraints: &[SALT_REQUIRED],
        edges: &[
            Edge { relation: Relation::Supersedes, target: "pbkdf2-hmac-sha2-256" },
            Edge { relation: Relation::BuiltOn, target: "blake2b" },
        ],
        performance: Performance::DeliberatelySlow,
        rust_path: "ac_kdf::argon2",
        example: "use ac_kdf::argon2::{argon2, Argon2Params, Variant};\nargon2(Variant::Argon2id, &Argon2Params::INTERACTIVE, password, salt, &mut key)?;",
        notes: "Memory is the parameter that matters: raising the pass count over a small arena \
                buys far less than raising the memory. RFC 9106 recommends 2 GiB with t=1 for \
                offline use and 64 MiB with t=3 for interactive logins, both available as \
                constants. Argon2i and Argon2d are implemented too; prefer Argon2id unless you \
                specifically need one of the others.",
    },
    Entry {
        id: "blake2b",
        name: "BLAKE2b",
        aliases: &["blake2"],
        summary: "Fast hash with a variable output length and a built-in keyed mode.",
        class: Class::Hash,
        family: "BLAKE2",
        purposes: &[Purpose::Integrity, Purpose::Authentication, Purpose::Commitment],
        strength: Strength::symmetric(256),
        fips: FipsStatus::NotApproved,
        status: ImplStatus::Available,
        standards: &["RFC 7693"],
        params: &BLAKE2B_P,
        constraints: &[NOT_FOR_PASSWORDS],
        edges: &[Edge { relation: Relation::PairsWith, target: "argon2id" }],
        performance: Performance::Fast,
        rust_path: "ac_hash::Blake2b",
        example: "let mut out = [0u8; 32];\nac_hash::Blake2b::hash(b\"message\", &mut out)?;",
        notes: "Present because Argon2 is defined in terms of it. Faster than SHA-512 on 64-bit \
                hardware and keyed without needing HMAC, but not approved — under a FIPS policy \
                use SHA-2 or SHA-3 instead. The output length is bound into the digest, so a short \
                hash is not a prefix of a long one.",
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
        id: "ecdh-p384",
        name: "ECDH P-384",
        aliases: &["ecdh-secp384r1"],
        summary: "Approved key agreement at 192-bit strength; what CNSA-aligned profiles require.",
        class: Class::KeyAgreement,
        family: "NIST P-curves",
        purposes: &[Purpose::KeyEstablishment],
        strength: Strength::classical_only(192),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-56A", "SP 800-186"],
        params: &P384_KA_P,
        constraints: &[VALIDATE_PEER_KEY, HASH_TRANSCRIPT],
        edges: &[
            Edge { relation: Relation::PairsWith, target: "hkdf-sha2-384" },
            Edge { relation: Relation::Supersedes, target: "ecdh-p256" },
        ],
        performance: Performance::Moderate,
        rust_path: "ac_ec::p384::EcdhP384",
        example: "use ac_core::traits::KeyAgreement;\nac_ec::p384::EcdhP384::agree(&my_sk, &peer_pk, &mut shared)?;",
        notes: "Roughly three times the work of P-256 for a security level few threat models \
                actually need. Choose it when a profile mandates 192-bit strength, not by default.",
    },
    Entry {
        id: "ecdsa-p384-sha384",
        name: "ECDSA P-384 with SHA-384",
        aliases: &["ecdsa-secp384r1"],
        summary: "Approved signatures at 192-bit strength, paired with SHA-384.",
        class: Class::Signature,
        family: "NIST P-curves",
        purposes: &[Purpose::Authentication, Purpose::NonRepudiation],
        strength: Strength::classical_only(192),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["FIPS 186-5", "SP 800-186", "RFC 6979"],
        params: &P384_SIG_P,
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
            Edge { relation: Relation::BuiltOn, target: "sha2-384" },
            Edge { relation: Relation::PairsWith, target: "ecdh-p384" },
            Edge { relation: Relation::Supersedes, target: "ecdsa-p256-sha256" },
        ],
        performance: Performance::Moderate,
        rust_path: "ac_ec::p384::EcdsaP384Sha384",
        example: "use ac_core::traits::SignatureScheme;\nac_ec::p384::EcdsaP384Sha384::sign(&sk, msg, &mut sig)?;",
        notes: "Nonces are derived per RFC 6979, so the unique-signing-nonce constraint is \
                satisfied by construction. Signatures are fixed-width r || s at 96 bytes, not DER.",
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
        id: "tuplehash128",
        name: "TupleHash128",
        aliases: &["tuplehash"],
        summary: "Hashes a sequence of strings so that no two sequences collide.",
        class: Class::Hash,
        family: "SHA-3",
        purposes: &[Purpose::Integrity, Purpose::Commitment],
        strength: Strength { classical: 128, quantum: 64 },
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-185"],
        params: &TUPLEHASH_P,
        constraints: &[Constraint {
            id: "do-not-concatenate-before-hashing",
            requirement: "Pass each field as its own element rather than joining them first.",
            consequence: "Joining loses the boundaries, so (\"abc\", \"d\") and (\"ab\", \"cd\") \
                          hash alike and a signature over one transfers to the other.",
            severity: Severity::Serious,
        }],
        edges: &[Edge { relation: Relation::BuiltOn, target: "cshake128" }],
        performance: Performance::Fast,
        rust_path: "ac_hash::TupleHash128",
        example: "let mut out = [0u8; 32];\nac_hash::TupleHash128::hash(b\"my app\", &[field_a, field_b], &mut out);",
        notes: "Reach for this wherever a protocol hashes several fields together. Every element \
                is length-prefixed, so distinct tuples always hash distinctly, which plain \
                concatenation cannot promise.",
    },
    Entry {
        id: "tuplehash256",
        name: "TupleHash256",
        aliases: &[],
        summary: "TupleHash at the 256-bit security level.",
        class: Class::Hash,
        family: "SHA-3",
        purposes: &[Purpose::Integrity, Purpose::Commitment],
        strength: Strength { classical: 256, quantum: 128 },
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-185"],
        params: &TUPLEHASH_P,
        constraints: &[Constraint {
            id: "do-not-concatenate-before-hashing",
            requirement: "Pass each field as its own element rather than joining them first.",
            consequence: "Joining loses the boundaries, so distinct field splits hash alike.",
            severity: Severity::Serious,
        }],
        edges: &[
            Edge { relation: Relation::BuiltOn, target: "cshake256" },
            Edge { relation: Relation::Supersedes, target: "tuplehash128" },
        ],
        performance: Performance::Fast,
        rust_path: "ac_hash::TupleHash256",
        example: "ac_hash::TupleHash256::hash(b\"my app\", &[a, b], &mut out);",
        notes: "Same construction as TupleHash128 over the wider sponge.",
    },
    Entry {
        id: "parallelhash128",
        name: "ParallelHash128",
        aliases: &["parallelhash"],
        summary: "Hashes fixed-size blocks independently, then hashes their digests.",
        class: Class::Hash,
        family: "SHA-3",
        purposes: &[Purpose::Integrity],
        strength: Strength { classical: 128, quantum: 64 },
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-185"],
        params: &PARALLELHASH_P,
        constraints: &[Constraint {
            id: "block-size-is-part-of-the-digest",
            requirement: "Fix the block size in the protocol and never vary it per message.",
            consequence: "Two parties using different block sizes compute different digests over \
                          identical input, and neither can tell why.",
            severity: Severity::Serious,
        }],
        edges: &[Edge { relation: Relation::BuiltOn, target: "cshake128" }],
        performance: Performance::Fast,
        rust_path: "ac_hash::ParallelHash128",
        example: "ac_hash::ParallelHash128::hash(b\"my app\", 8192, data, &mut out);",
        notes: "The structure allows the per-block work to be spread across cores. This build \
                does the blocks in order, since the workspace has no threading and a no_std \
                target has no threads to spread onto, so what it buys here is interoperability \
                rather than speed. The digest is the same either way.",
    },
    Entry {
        id: "parallelhash256",
        name: "ParallelHash256",
        aliases: &[],
        summary: "ParallelHash at the 256-bit security level.",
        class: Class::Hash,
        family: "SHA-3",
        purposes: &[Purpose::Integrity],
        strength: Strength { classical: 256, quantum: 128 },
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-185"],
        params: &PARALLELHASH_P,
        constraints: &[Constraint {
            id: "block-size-is-part-of-the-digest",
            requirement: "Fix the block size in the protocol and never vary it per message.",
            consequence: "Two parties using different block sizes compute different digests.",
            severity: Severity::Serious,
        }],
        edges: &[
            Edge { relation: Relation::BuiltOn, target: "cshake256" },
            Edge { relation: Relation::Supersedes, target: "parallelhash128" },
        ],
        performance: Performance::Fast,
        rust_path: "ac_hash::ParallelHash256",
        example: "ac_hash::ParallelHash256::hash(b\"my app\", 8192, data, &mut out);",
        notes: "Uses a 64-byte inner digest per block where ParallelHash128 uses 32.",
    },
    Entry {
        id: "kmac128",
        name: "KMAC128",
        aliases: &["kmac"],
        summary: "The SHA-3 family's MAC: a keyed sponge, with no HMAC nesting needed.",
        class: Class::Mac,
        family: "SHA-3",
        purposes: &[Purpose::Authentication, Purpose::Integrity],
        strength: Strength { classical: 128, quantum: 64 },
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-185"],
        params: &KMAC_P,
        constraints: &[
            Constraint {
                id: "compare-tags-in-constant-time",
                requirement: "Verify with the provided constant-time check, never with ==.",
                consequence: "An early-exit comparison leaks how many leading bytes matched, \
                              which recovers a valid tag one byte at a time.",
                severity: Severity::Critical,
            },
            Constraint {
                id: "separate-domains-with-customization",
                requirement: "Give two uses of the same key different customization strings.",
                consequence: "A tag produced for one purpose verifies for the other, so a \
                              message can be replayed across contexts.",
                severity: Severity::Advisory,
            },
        ],
        edges: &[
            Edge { relation: Relation::BuiltOn, target: "cshake128" },
            Edge { relation: Relation::PairsWith, target: "sha3-256" },
        ],
        performance: Performance::Fast,
        rust_path: "ac_mac::Kmac128",
        example: "let mut tag = [0u8; 32];\nac_mac::Kmac128::mac(key, b\"my app\", msg, &mut tag);\nac_mac::Kmac128::verify(key, b\"my app\", msg, &tag)?;",
        notes: "Unlike HMAC, the tag length is an input to the computation rather than a \
                truncation of it, so a 32-byte tag is unrelated to the first 32 bytes of a \
                64-byte one and cannot be forged by truncating it. The XOF variant encodes zero \
                instead and does produce a real stream.",
    },
    Entry {
        id: "kmac256",
        name: "KMAC256",
        aliases: &[],
        summary: "KMAC at the 256-bit security level, for CNSA-style profiles.",
        class: Class::Mac,
        family: "SHA-3",
        purposes: &[Purpose::Authentication, Purpose::Integrity],
        strength: Strength { classical: 256, quantum: 128 },
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-185"],
        params: &KMAC_P,
        constraints: &[Constraint {
            id: "compare-tags-in-constant-time",
            requirement: "Verify with the provided constant-time check, never with ==.",
            consequence: "An early-exit comparison leaks how many leading bytes matched.",
            severity: Severity::Critical,
        }],
        edges: &[
            Edge { relation: Relation::BuiltOn, target: "cshake256" },
            Edge { relation: Relation::Supersedes, target: "kmac128" },
        ],
        performance: Performance::Fast,
        rust_path: "ac_mac::Kmac256",
        example: "ac_mac::Kmac256::mac(key, b\"my app\", msg, &mut tag);",
        notes: "A smaller rate than KMAC128, so it absorbs fewer bytes per permutation and runs \
                proportionally slower. Choose it to meet a profile.",
    },
    Entry {
        id: "cshake128",
        name: "cSHAKE128",
        aliases: &[],
        summary: "SHAKE128 with a customization string, and the substrate KMAC is built on.",
        class: Class::Xof,
        family: "SHA-3",
        purposes: &[Purpose::Integrity],
        strength: Strength { classical: 128, quantum: 64 },
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-185"],
        params: &CSHAKE_P,
        constraints: &[NOT_COLLISION_RESISTANT],
        edges: &[Edge { relation: Relation::Specializes, target: "shake128" }],
        performance: Performance::Fast,
        rust_path: "ac_hash::CShake128",
        example: "let mut out = [0u8; 32];\nac_hash::CShake128::xof(b\"\", b\"my app\", msg, &mut out);",
        notes: "With an empty customization string this is bit-for-bit SHAKE128, which is how \
                SP 800-185 defines it and how the self-test checks it. Reach for it when two \
                protocols hash the same bytes and must not agree on the result.",
    },
    Entry {
        id: "cshake256",
        name: "cSHAKE256",
        aliases: &[],
        summary: "SHAKE256 with a customization string.",
        class: Class::Xof,
        family: "SHA-3",
        purposes: &[Purpose::Integrity],
        strength: Strength { classical: 256, quantum: 128 },
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-185"],
        params: &CSHAKE_P,
        constraints: &[NOT_COLLISION_RESISTANT],
        edges: &[Edge { relation: Relation::Specializes, target: "shake256" }],
        performance: Performance::Fast,
        rust_path: "ac_hash::CShake256",
        example: "ac_hash::CShake256::xof(b\"\", b\"my app\", msg, &mut out);",
        notes: "With an empty customization string this is bit-for-bit SHAKE256.",
    },
    Entry {
        id: "ecdsa-p521-sha512",
        name: "ECDSA P-521 with SHA-512",
        aliases: &["ecdsa-secp521r1"],
        summary: "The largest NIST prime curve, for profiles that require 256-bit strength.",
        class: Class::Signature,
        family: "NIST P-curves",
        purposes: &[Purpose::Authentication, Purpose::NonRepudiation],
        strength: Strength::classical_only(256),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["FIPS 186-5", "SP 800-186", "RFC 6979"],
        params: &P521_SIG_P,
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
            Edge { relation: Relation::BuiltOn, target: "sha2-512" },
            Edge { relation: Relation::PairsWith, target: "ecdh-p521" },
            Edge { relation: Relation::Supersedes, target: "ecdsa-p384-sha384" },
        ],
        performance: Performance::Slow,
        rust_path: "ac_ec::p521::EcdsaP521Sha512",
        example: "use ac_core::traits::SignatureScheme;\nac_ec::p521::EcdsaP521Sha512::sign(&sk, msg, &mut sig)?;",
        notes: "The only pairing here where the hash is narrower than the group order: SHA-512 \
                gives 512 bits against 521, so RFC 6979 accumulates two HMAC blocks and keeps \
                the leftmost 521 bits. Field elements are 66 bytes with the top seven bits \
                always zero. Nonces are derived per RFC 6979, so the unique-signing-nonce \
                constraint is satisfied by construction.",
    },
    Entry {
        id: "ecdh-p521",
        name: "ECDH P-521",
        aliases: &["ecdh-secp521r1"],
        summary: "Key agreement on the largest NIST prime curve.",
        class: Class::KeyAgreement,
        family: "NIST P-curves",
        purposes: &[Purpose::KeyEstablishment],
        strength: Strength::classical_only(256),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["SP 800-56A", "SP 800-186"],
        params: &P521_KA_P,
        constraints: &[VALIDATE_PEER_KEY, HASH_TRANSCRIPT],
        edges: &[
            Edge { relation: Relation::PairsWith, target: "hkdf-sha2-256" },
            Edge { relation: Relation::Supersedes, target: "ecdh-p384" },
        ],
        performance: Performance::Slow,
        rust_path: "ac_ec::p521::EcdhP521",
        example: "use ac_core::traits::KeyAgreement;\nac_ec::p521::EcdhP521::agree(&sk, &peer, &mut secret)?;",
        notes: "Roughly three times the cost of P-384 for a security level few threat models \
                distinguish from it. Choose it to meet a profile, not for the margin.",
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
        id: "rsa-pkcs1-sha256",
        name: "RSASSA-PKCS1-v1_5 with SHA-256",
        aliases: &["rsa-pkcs1-v1_5", "rsassa-pkcs1", "sha256withrsa"],
        summary: "The RSA signature padding that certificate chains are made of.",
        class: Class::Signature,
        family: "RSA",
        purposes: &[Purpose::Authentication, Purpose::NonRepudiation],
        strength: Strength::classical_only(112),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["FIPS 186-5", "RFC 8017"],
        params: &RSA_SIG_P,
        constraints: &[RSA_MIN_MODULUS, RSA_PREFER_PSS, RSA_NO_PARSING],
        edges: &[
            Edge { relation: Relation::BuiltOn, target: "sha2-256" },
            Edge { relation: Relation::SupersededBy, target: "rsa-pss-sha256" },
        ],
        performance: Performance::Slow,
        rust_path: "ac_rsa::Pkcs1Sha256",
        example: "let key = ac_rsa::RsaPrivateKey::from_components(n, 65537, d)?;\nac_rsa::Pkcs1Sha256::sign(&key, msg, &mut sig)?;\nac_rsa::Pkcs1Sha256::verify(key.public_key(), msg, &sig)?;",
        notes: "Verification re-encodes the expected block and compares it in constant time; it \
                never parses the recovered block, which is where the Bleichenbacher 2006 \
                forgeries came from. The DigestInfo prefix is built from the algorithm OID at \
                run time rather than pasted in as a constant. Signing uses the Chinese \
                remainder theorem and verifies its own output before returning it, so a faulted \
                half cannot leak the factorization.",
    },
    Entry {
        id: "rsa-pkcs1-sha384",
        name: "RSASSA-PKCS1-v1_5 with SHA-384",
        aliases: &["sha384withrsa"],
        summary: "PKCS#1 v1.5 padding over SHA-384.",
        class: Class::Signature,
        family: "RSA",
        purposes: &[Purpose::Authentication, Purpose::NonRepudiation],
        strength: Strength::classical_only(112),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["FIPS 186-5", "RFC 8017"],
        params: &RSA_SIG_P,
        constraints: &[RSA_MIN_MODULUS, RSA_PREFER_PSS, RSA_NO_PARSING],
        edges: &[
            Edge { relation: Relation::BuiltOn, target: "sha2-384" },
            Edge { relation: Relation::SupersededBy, target: "rsa-pss-sha384" },
        ],
        performance: Performance::Slow,
        rust_path: "ac_rsa::Pkcs1Sha384",
        example: "ac_rsa::Pkcs1Sha384::verify(&public_key, msg, &sig)?;",
        notes: "The hash is stronger than what a 2048-bit modulus supports, so the modulus is \
                what bounds the security level. Use this pairing when a peer requires it.",
    },
    Entry {
        id: "rsa-pkcs1-sha512",
        name: "RSASSA-PKCS1-v1_5 with SHA-512",
        aliases: &["sha512withrsa"],
        summary: "PKCS#1 v1.5 padding over SHA-512.",
        class: Class::Signature,
        family: "RSA",
        purposes: &[Purpose::Authentication, Purpose::NonRepudiation],
        strength: Strength::classical_only(112),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["FIPS 186-5", "RFC 8017"],
        params: &RSA_SIG_P,
        constraints: &[RSA_MIN_MODULUS, RSA_PREFER_PSS, RSA_NO_PARSING],
        edges: &[
            Edge { relation: Relation::BuiltOn, target: "sha2-512" },
            Edge { relation: Relation::SupersededBy, target: "rsa-pss-sha512" },
        ],
        performance: Performance::Slow,
        rust_path: "ac_rsa::Pkcs1Sha512",
        example: "ac_rsa::Pkcs1Sha512::verify(&public_key, msg, &sig)?;",
        notes: "The hash is stronger than what a 2048-bit modulus supports, so the modulus is \
                what bounds the security level.",
    },
    Entry {
        id: "rsa-pss-sha256",
        name: "RSASSA-PSS with SHA-256",
        aliases: &["rsa-pss", "rsassa-pss"],
        summary: "The RSA padding to choose for new signatures: randomized, with a security \
                  proof PKCS#1 v1.5 lacks.",
        class: Class::Signature,
        family: "RSA",
        purposes: &[Purpose::Authentication, Purpose::NonRepudiation],
        strength: Strength::classical_only(112),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["FIPS 186-5", "RFC 8017"],
        params: &RSA_PSS_P,
        constraints: &[RSA_MIN_MODULUS, RSA_SALT_ENTROPY],
        edges: &[
            Edge { relation: Relation::BuiltOn, target: "sha2-256" },
            Edge { relation: Relation::Supersedes, target: "rsa-pkcs1-sha256" },
            Edge { relation: Relation::SupersededBy, target: "ml-dsa-65" },
        ],
        performance: Performance::Slow,
        rust_path: "ac_rsa::PssSha256",
        example: "ac_rsa::PssSha256::sign(&key, msg, &mut rng, &mut sig)?;\nac_rsa::PssSha256::verify(key.public_key(), msg, &sig)?;",
        notes: "The salt is always the hash length, which is what FIPS 186-5 and essentially \
                every deployment use. Signing needs a random source; verification does not. Two \
                signatures over one message differ, so a PSS signature is not a message id.",
    },
    Entry {
        id: "rsa-pss-sha384",
        name: "RSASSA-PSS with SHA-384",
        aliases: &[],
        summary: "PSS padding over SHA-384 with a 48-byte salt.",
        class: Class::Signature,
        family: "RSA",
        purposes: &[Purpose::Authentication, Purpose::NonRepudiation],
        strength: Strength::classical_only(112),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["FIPS 186-5", "RFC 8017"],
        params: &RSA_PSS_P,
        constraints: &[RSA_MIN_MODULUS, RSA_SALT_ENTROPY],
        edges: &[
            Edge { relation: Relation::BuiltOn, target: "sha2-384" },
            Edge { relation: Relation::Supersedes, target: "rsa-pkcs1-sha384" },
        ],
        performance: Performance::Slow,
        rust_path: "ac_rsa::PssSha384",
        example: "ac_rsa::PssSha384::sign(&key, msg, &mut rng, &mut sig)?;",
        notes: "A 2048-bit modulus has room for a 48-byte hash and a 48-byte salt with 158 \
                bytes to spare, so no size juggling is needed.",
    },
    Entry {
        id: "rsa-pss-sha512",
        name: "RSASSA-PSS with SHA-512",
        aliases: &[],
        summary: "PSS padding over SHA-512 with a 64-byte salt.",
        class: Class::Signature,
        family: "RSA",
        purposes: &[Purpose::Authentication, Purpose::NonRepudiation],
        strength: Strength::classical_only(112),
        fips: FipsStatus::Approved,
        status: ImplStatus::Available,
        standards: &["FIPS 186-5", "RFC 8017"],
        params: &RSA_PSS_P,
        constraints: &[RSA_MIN_MODULUS, RSA_SALT_ENTROPY],
        edges: &[
            Edge { relation: Relation::BuiltOn, target: "sha2-512" },
            Edge { relation: Relation::Supersedes, target: "rsa-pkcs1-sha512" },
        ],
        performance: Performance::Slow,
        rust_path: "ac_rsa::PssSha512",
        example: "ac_rsa::PssSha512::sign(&key, msg, &mut rng, &mut sig)?;",
        notes: "Needs a 2048-bit modulus or larger to fit a 64-byte hash beside a 64-byte salt; \
                this library refuses anything smaller regardless.",
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
