//! Known-answer tests for the RSA signature schemes.
//!
//! # Where the vectors come from
//!
//! NIST's ACVP RSA vectors are not reproducible offline, and inventing a
//! "known" answer would defeat the purpose of a known-answer test. So these
//! vectors are self-generated and then pinned, with their correctness
//! established by properties that a wrong value cannot satisfy:
//!
//! - the key satisfies `(m^e)^d = m (mod n)`, which holds only if `p` and `q`
//!   are genuinely prime and `d` is genuinely the inverse of `e`;
//! - the PKCS#1 encoding is checked byte-for-byte against the prefixes
//!   published in RFC 8017 §9.2, reached by an independent derivation;
//! - the signatures below are what this implementation produces, and every
//!   layer beneath them has its own oracle: the modular exponentiation against
//!   a naive reference, MGF1 against a direct transcription of RFC 8017 B.2.1,
//!   and the PSS encoder against the separately written PSS verifier.
//!
//! What a pinned signature catches is *regression*: a later change that alters
//! any byte of the output. That is what a CAST is for in a module that already
//! has correctness evidence elsewhere. docs/FIPS.md records this provenance
//! alongside the other vectors whose source is not a published test suite.
//!
//! The key here is published in a public repository and is a test fixture. It
//! must never be used for anything else.

use crate::key::{RsaPrivateKey, RsaPublicKey};
use crate::{Pkcs1Sha256, Pkcs1Sha384, Pkcs1Sha512, PssSha256, PssSha384, PssSha512};
use ac_core::traits::SelfTest;
use ac_core::{ensure, Result};

/// First prime of the known-answer-test key, big-endian hex.
///
/// The key is pinned as its two factors rather than as `n` and `d`. Everything
/// else — the modulus, the private exponent, and the three CRT parameters — is
/// derived from these by [`crate::RsaPrivateKey::from_primes`], so there is one
/// source of truth and no chance of pinning a `d` that does not match its `n`.
/// The signatures below are what that derivation produces, so a change in any
/// derived value shows up as a failed known-answer test.
pub(crate) const KAT_P: &str = concat!(
    "ebacdab5daa6a18014e9afa81e8ee48b0ecf9a12c044da47b69efaa88129332b",
    "f5b52321abd6bc90a6eb3803dacfc77550c4a3bd7762bea37e0c2544e9385c86",
    "7269d1a2f738194313299806efe1be0d29fbab167c00318c0021c615a4038d07",
    "b9358c11204162138e2cf185199304b3758447fda80c47c98c0ce3138250c453",
);

/// Second prime of the known-answer-test key, big-endian hex.
pub(crate) const KAT_Q: &str = concat!(
    "d79b690b2d3c79c895ae7e745ad060ce003c2f262a95a0e32a275805e360b869",
    "3d02754abc909e152e85393257ffd6f8f88a2d77d90f5e60f2d7971be9ccf63b",
    "587c7d126ce02434f5baf0718a6eaf08129670b01f9c71571a4d3fa71de28c19",
    "bd556af631ebd4cd0b4b4dc01a2dcce5c43b36ef589c88fd755083a2f452acc5",
);

/// Public exponent of the known-answer-test key.
pub(crate) const KAT_E: u64 = 65537;

/// The message both known-answer tests sign.
const KAT_MESSAGE: &[u8] = b"agentic-crypto rsa known answer test";

/// Expected RSASSA-PKCS1-v1_5-SHA-256 signature over [`KAT_MESSAGE`].
const KAT_PKCS1_SHA256: &str = concat!(
    "3ba68bdab5a076ce3d00a5fd4c1104d0bd8923b6fa0dab85cf8887a9cb49ae76",
    "9ef147d7fb42a95360709626f6b955c6e2bff09729d935993320f91a70ea8d3a",
    "7868a2f5f9cbc048cf2d9a9b1c68d5843e5989ab5e90e7d69099d1dd451281da",
    "fac4f292d0609125aff363db1f233c9a381d44e88ab4c61271ef0421f0b5c631",
    "f9fa9612b8977f260435ec524bc2a20e251af7a35dc5c94c8352c3063a39728a",
    "46ec59654ff913848abda4590784c8e25c0f56a898722ceaddbfe5b0fd4672ac",
    "211bf35ae73c95cae0f352442337114971e69a53aea6b462f75ffcda5d2a8896",
    "a30cbf93e9dee4148ec597646afbe0810c2a863463ef4fbd88ee5df9b472aab0",
);

/// Expected RSASSA-PKCS1-v1_5-SHA-384 signature over [`KAT_MESSAGE`].
const KAT_PKCS1_SHA384: &str = concat!(
    "56f93d706507e6648ac1bc2d7165d104f7c8c756d49b2011bcc563e2b9dfd201",
    "282da420ffe64ebd12a019e85c3dc32517c97bbd656f50bcbf8a690969f6f141",
    "8077486f90a323ec8d31512b78ec74ae3a2db2d90720c89bf46f19b15b96705f",
    "db59249c3844a406025fba2ddd8ecc51e51087278149106a13eee3db0348455b",
    "546c15459c6fe422e7204fa1fe6a99c16cbdce75e75065a743ea662060dc7f57",
    "a075add40716f5dcf71940f7230de4c886e4e91ac5a2e4a705b6d51aaef67284",
    "e7802779ba1cde8a305ed391c83e2af1c965f8637d81ab8debf52f2b9af8be75",
    "242df5de754f12bdb34ca136200a8dcfeeb972aa7b7435836e4e333bd61e5234",
);

/// Expected RSASSA-PKCS1-v1_5-SHA-512 signature over [`KAT_MESSAGE`].
const KAT_PKCS1_SHA512: &str = concat!(
    "46bac65c6abf5651c40f62929ed7898036a30eee479601622ecc63c969e16055",
    "232367cb9e485521fe570bec67d8539227d9f38011c9770ecda3b9b7c33ca208",
    "9b6c8c7f1ffdee65600d9bfade2ec3280025c9a0518a6f30be0909dc9b8a787c",
    "9a92a5d17134d9bbcb1f6c20c4f95af2cd3bd746ca544b09fba89520ca136788",
    "4d86d9a90224a8bcef1a567ea6eb87e161c8e0bda522110b80a67acfe035d1bc",
    "621da4ca9bd43ce04c55eec6ffc5b9f5aac3f4bdbdb970d6ff80a983f193ec4c",
    "c56efbca0c01cdc3c3e385b1eaccebbafc76b6448c3e04be32ad713bd858b377",
    "2d44d6e1f0928403795a569bb30018fbf7870a158af7b9601f434edffdcb63ab",
);

/// Expected RSASSA-PSS-SHA-256 signature over [`KAT_MESSAGE`].
const KAT_PSS_SHA256: &str = concat!(
    "6acf9de561e7c594205946683700e8e4d844b3b8ddeaed659ac52c88f9f839e4",
    "b539eba0e987fd833f2253c3ebce5349a72f5fe1bf615e4857023695186e6133",
    "b12ccf0d38e112faa5b5833e24b174db0548eee954939edf8bad604a87a77f59",
    "97a08b8968101e27e9e9966c493fcebf32c0b975a6899f83e270d579834265c4",
    "621dd2eb4bdb1c21f3b3c94e82c67d1e08e872f45f65e8a5fec6cadfc6d7212a",
    "e01c732ebcc4722ac61fb7b505061bd393e99797ab4387313c2aeea8568bb1ee",
    "d36e4b0a9d4cc8ac98e095c9f9355795e5d1daba280b9dc8f43d21828221ce8b",
    "4ea96132a3b1631607244d986c9ae0f1c2c3472ad3c06feabaf358c07873bdb6",
);

/// Expected RSASSA-PSS-SHA-384 signature over [`KAT_MESSAGE`].
const KAT_PSS_SHA384: &str = concat!(
    "826743e05b8cde99bb99cbd6243fe9718f04ec1ecd6fd82cf96da1798685906d",
    "238fa22362296911fc06ac2dc3e01b6f7d1753d9e3345351f435528b814d9a3a",
    "2f4c0ff46c285edfb2b37a8b867ad25f6cd70c9c607c859dbdad497eb58ae19c",
    "93e22283633153607fd0485ea241822bce0a5078332ca66a63b6d29953d12559",
    "7d7f17b8c1cfeae90431950970845cef5d289ec0c825b700c9c0e492c52dbd45",
    "386d69107e88c62ad33ccb80b23e11c5310df73272b710f5eeef37d4a32ad012",
    "f0f7c2e9bc5bda5ec91733e41647b52ad64cb5127c0d31b03b8743f35583107f",
    "b401d302f14af99d35300566be30dec54d28bb8d1d0b4c14802e0ef8c307d586",
);

/// Expected RSASSA-PSS-SHA-512 signature over [`KAT_MESSAGE`].
const KAT_PSS_SHA512: &str = concat!(
    "b6b8f150883cc3a6944dd4bda62bd5a9e89408f46c7d851e6395feb07cabd35b",
    "658c45d4292892694d8f8beb9bfc6a7244f2dbbcd9abc81c666e3246a38a137b",
    "7f9c9209055375d4932ff68b8851a33634a6375db6908983cf3230464bc66da3",
    "e6ea49b049204e2da76967aa2b44d96ff218d3a8083d5b9d7cf9aae1879f320e",
    "c6e9e01084d819541204fab34076bb0083a956c6007a337c43525cc59b388028",
    "f0a02e9521a4b6a5b7822b2286bb05bb4cb8d29f9412f8582f885d052b21bda4",
    "41d586b9c4d9e041fbdbe00f7b9a4650b07c3b945608a8aedb73d8120cac8157",
    "abc2d6645a64a1e3ac5b753e15a7f8f22ce29f38874595f862ef71d94299b4ce",
);

/// The PSS salt, fixed so the signatures are reproducible. Production signing
/// draws a fresh salt from the caller's DRBG; each scheme takes the first
/// `OUTPUT_LEN` bytes of this.
const KAT_SALT: [u8; 64] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
];

/// Decode a 512-character hex constant into 256 bytes.
fn unhex_256(hex: &str) -> Result<[u8; 256]> {
    let mut out = [0u8; 256];
    ac_core::codec::hex_decode(hex.as_bytes(), &mut out)?;
    Ok(out)
}

/// Decode a 256-character hex constant into 128 bytes.
fn unhex_128(hex: &str) -> Result<[u8; 128]> {
    let mut out = [0u8; 128];
    ac_core::codec::hex_decode(hex.as_bytes(), &mut out)?;
    Ok(out)
}

/// The known-answer-test key pair.
///
/// Built from the primes, so the self-tests run the Chinese-remainder path —
/// the one production takes for any generated key. A known-answer test that
/// exercised a path no caller uses would be worth very little.
pub(crate) fn kat_key() -> Result<RsaPrivateKey> {
    RsaPrivateKey::from_primes(&unhex_128(KAT_P)?, &unhex_128(KAT_Q)?, KAT_E)
}

/// The public half of the known-answer-test key.
fn kat_public() -> Result<RsaPublicKey> {
    Ok(*kat_key()?.public_key())
}

/// A known-answer test for one PKCS#1 v1.5 scheme.
///
/// PKCS#1 v1.5 is deterministic, so signing and comparing covers the forward
/// direction exactly; verifying the result then exercises the reverse path.
macro_rules! pkcs1_kat {
    ($scheme:ty, $expected:ident, $id:literal) => {
        impl SelfTest for $scheme {
            fn self_test() -> Result<()> {
                let mut got = [0u8; 256];
                <$scheme>::sign(&kat_key()?, KAT_MESSAGE, &mut got)?;
                ensure!(
                    ac_core::ct::verify(&unhex_256($expected)?, &got),
                    SelfTestFailed,
                    $id
                );
                <$scheme>::verify(&kat_public()?, KAT_MESSAGE, &got)
                    .map_err(|_| ac_core::err!(SelfTestFailed, $id))
            }
        }
    };
}

/// A known-answer test for one PSS scheme.
///
/// PSS signing is randomized, so the test drives the internal fixed-salt entry
/// point to get a reproducible signature, then verifies it through the ordinary
/// public one.
macro_rules! pss_kat {
    ($scheme:ty, $hash:ty, $expected:ident, $id:literal) => {
        impl SelfTest for $scheme {
            fn self_test() -> Result<()> {
                use ac_core::traits::Digest;
                let mut got = [0u8; 256];
                crate::pss::sign_with_salt::<$hash>(
                    &kat_key()?,
                    KAT_MESSAGE,
                    &KAT_SALT[..<$hash>::OUTPUT_LEN],
                    &mut got,
                )?;
                ensure!(
                    ac_core::ct::verify(&unhex_256($expected)?, &got),
                    SelfTestFailed,
                    $id
                );
                <$scheme>::verify(&kat_public()?, KAT_MESSAGE, &got)
                    .map_err(|_| ac_core::err!(SelfTestFailed, $id))
            }
        }
    };
}

pkcs1_kat!(Pkcs1Sha256, KAT_PKCS1_SHA256, "rsa-pkcs1-sha256");
pkcs1_kat!(Pkcs1Sha384, KAT_PKCS1_SHA384, "rsa-pkcs1-sha384");
pkcs1_kat!(Pkcs1Sha512, KAT_PKCS1_SHA512, "rsa-pkcs1-sha512");
pss_kat!(PssSha256, ac_hash::Sha256, KAT_PSS_SHA256, "rsa-pss-sha256");
pss_kat!(PssSha384, ac_hash::Sha384, KAT_PSS_SHA384, "rsa-pss-sha384");
pss_kat!(PssSha512, ac_hash::Sha512, KAT_PSS_SHA512, "rsa-pss-sha512");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_self_test_passes() {
        Pkcs1Sha256::self_test().expect("rsa-pkcs1-sha256");
        Pkcs1Sha384::self_test().expect("rsa-pkcs1-sha384");
        Pkcs1Sha512::self_test().expect("rsa-pkcs1-sha512");
        PssSha256::self_test().expect("rsa-pss-sha256");
        PssSha384::self_test().expect("rsa-pss-sha384");
        PssSha512::self_test().expect("rsa-pss-sha512");
    }

    /// Regenerate the pinned signatures. Ignored; run with
    /// `cargo test -p ac-rsa -- --ignored --nocapture print_kat`.
    #[test]
    #[ignore = "used to produce the pinned constants"]
    fn print_kat_signatures() {
        use ac_core::traits::Digest;
        let key = kat_key().unwrap();
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let mut sig = [0u8; 256];

        Pkcs1Sha256::sign(&key, KAT_MESSAGE, &mut sig).unwrap();
        println!("KAT_PKCS1_SHA256 {}", hex(&sig));
        Pkcs1Sha384::sign(&key, KAT_MESSAGE, &mut sig).unwrap();
        println!("KAT_PKCS1_SHA384 {}", hex(&sig));
        Pkcs1Sha512::sign(&key, KAT_MESSAGE, &mut sig).unwrap();
        println!("KAT_PKCS1_SHA512 {}", hex(&sig));

        macro_rules! pss {
            ($hash:ty, $name:literal) => {
                crate::pss::sign_with_salt::<$hash>(
                    &key,
                    KAT_MESSAGE,
                    &KAT_SALT[..<$hash>::OUTPUT_LEN],
                    &mut sig,
                )
                .unwrap();
                println!("{} {}", $name, hex(&sig));
            };
        }
        pss!(ac_hash::Sha256, "KAT_PSS_SHA256");
        pss!(ac_hash::Sha384, "KAT_PSS_SHA384");
        pss!(ac_hash::Sha512, "KAT_PSS_SHA512");
    }
}
