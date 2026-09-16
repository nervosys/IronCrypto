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

/// Modulus of the known-answer-test key, big-endian hex.
pub(crate) const KAT_N: &str = concat!(
    "9d4fdb97a4fb6ad3f667bada5130728d6032c8ed18b4df7c6d04829b0ed93d2a",
    "1144099bd1d1811b7b7eb5b4460ab6fb5ed160f259137153ab53aef230bae1b9",
    "e1820634c433535b76645075477d0264e911c8f9adb36b75ab65637e4202ebd2",
    "5e794583d18b611b4315123711e0b1278970d2361d5343e21a56c26fd41ba313",
    "9d6b9ec616e144c817f3e0751a9026afd5c250fa214af4f68189c273a723e873",
    "224c7b5338edd4fad2c827b20eaf13ac7450ff6608309feb36dd70617779bd0e",
    "c81fac0869675b99767ab0600b825868d6fb0d6b170284b812e3a954c2332aef",
    "085b6bf175e8233b164a5ff6c7c1568aca10d651748e69ed831774dcb3c3f0ab",
);

/// Private exponent of the known-answer-test key, big-endian hex.
pub(crate) const KAT_D: &str = concat!(
    "2eed49965d12daf54c05f98972babf1149671ce50d7fb74348ca15a3e7b40a38",
    "e859a17c2805153c7b847af3c2092438ac3a4d6f3dff3cc936cc89dd9987c61a",
    "4b191c7cd52272755045f0726bd6f0c5e578f6b8f48617424cd4bbef4805d30f",
    "383b78ef2fad22549d98458cc3fa811e4833ada192f1e9c8230f4a854d82c90c",
    "731f2e72822791c891f9fd48677a364fc38b3e9a422f62b8c4feced2bf8c1af9",
    "61c8e3dcf76b5eeb487983405bf1477ef88662d079e8a84c0e24d001283abda8",
    "af63aaed3a00d76074373b81d20eadf708553442cc7b1f7ebdcaec03e97b12f6",
    "41e5c711c10e1c00325c945251b91a4d58071cab6cfe5f87092c7020e6ceaac1",
);

/// Public exponent of the known-answer-test key.
pub(crate) const KAT_E: u64 = 65537;

/// The message both known-answer tests sign.
const KAT_MESSAGE: &[u8] = b"agentic-crypto rsa known answer test";

/// Expected RSASSA-PKCS1-v1_5-SHA-256 signature over [`KAT_MESSAGE`].
const KAT_PKCS1_SHA256: &str = concat!(
    "6f06ea90c42d359a3cd5c9f7888ee321234e4629a9ba4ba156274db325d74335",
    "f0eab8abbb45e18c57670eb3efc0c018161b1d5f27ce02e1ac61dbdd5e03d5f5",
    "678b5315c50e6ea91ed6f60045ab104966bb54e4e5bcca0a44c1197498852b5d",
    "4be5290102582a5ac2251f5cd0d62d18a7de61d7d12c2173e9250513fb39bf27",
    "1bedd5ea75fabeb6a6e209c60d3f2c7ebacc1f3fc017e4b808e87a56215c1877",
    "3d39616dc7f6d2463ed0fd50b988750ba6de404570a081ff4615f03445c055ee",
    "92c6401fa61e8ab3b2e9c63a8282484e91fcad779e6a7a01e1e56d7953390dde",
    "a1c8adbf3e19aea075a8f7b593f3973098178b0a926eb51795624a81779a5832",
);

/// Expected RSASSA-PKCS1-v1_5-SHA-384 signature over [`KAT_MESSAGE`].
const KAT_PKCS1_SHA384: &str = concat!(
    "0a83d64fdda467c6c8a2fb77ca738f7fe9f3acc18a1d40ea2c61264d4499bc29",
    "b1089f249a61f29a0a7fed00faa21620b78308c44edd2932273f85e7a809efd4",
    "4e1a738350666a2176d7b6e3346a1938c66870c29372837f89a62f380b6d5c8d",
    "72cf15ca8f33a0b7f018b8500287b33744ce5a1a85ee0196ea8305f83bc796e3",
    "559aa3453a4e28d9b54c015ff25fd72ffef4efb67d0522dcecf0faeb5ceae3dc",
    "b3e8399095b46d2f4ac46aaa8a6ee064cba60d03e591676c667815e17b19c52b",
    "8cbd851c34057739df881133e9a8873bd8153547493094763cde5e22f4165baa",
    "c51a4ab4e631ccd8cf55fb898b8dbad6104ca4cf8d60ae07ac606775858712a3",
);

/// Expected RSASSA-PKCS1-v1_5-SHA-512 signature over [`KAT_MESSAGE`].
const KAT_PKCS1_SHA512: &str = concat!(
    "98bdc8d17a9e7a84547076c8894c7a9aec35cf3656fe043e1ca0ae45b59ec6d6",
    "821fd6df24e254499a5796dd7151df672d4bfb9470114ddfa2d9c10378831a62",
    "eba92f2ba6a08a6ea512ead2ec96d9aa2a5f80559c5e771103bbe5c31ce154f2",
    "fa21794013333ef040506a8adb3245da3d3d8a3d8f9ddc442f95ac16af8864b1",
    "4b6ff4055c4af460a990b130493a129c7a1860b76b8e9adbddd0e871a0c919a2",
    "d76b61db1a8276b3498c76b68e21abba6fb2ff2d62991a243f09ce999a9feeff",
    "f44943a049ef636a4eba3181c63856277048f56b8a0a63602b420bf9febff876",
    "ba8039aad3b1845797a9cfc6c35188d0193427ac4f28a0f93a4a72e9a322affb",
);

/// Expected RSASSA-PSS-SHA-256 signature over [`KAT_MESSAGE`].
const KAT_PSS_SHA256: &str = concat!(
    "141617a4608a7122a8967ecb03a43ba60cde07b7b0b2c8be954b806bdaf91bf6",
    "9c9c8803b6a5ec5ab7ae54ea7120f6cad744050c85d466d2ed8c0ddeec9815a6",
    "f6ce8f67bc329e56db9cb1fc75e55fbfda4e94fb3e13cc0f76b32cc229823799",
    "f05b6065c3ee7170424dc3558a84036f51d970cdab29d77c412a03e3ffcdcf34",
    "1aa5f5f884ce409e2885e20044933ee244bad6f1f269bd7ce3ce8888a4cdf937",
    "7e8e529c785f99a89df6b5a67cbfa57d6e13cbea7fa652299cd7f1519205180f",
    "9029e9990f7109747dfc2b7e5b8bf7ba24685fe7b3ee4a141753e2fe2b7ff915",
    "9069737c482bc42a54308e8800aba0020ed39e1bbee27dd58af2794c3df48928",
);

/// Expected RSASSA-PSS-SHA-384 signature over [`KAT_MESSAGE`].
const KAT_PSS_SHA384: &str = concat!(
    "47077fc2914c4bb7c38d0161a99ba774560e7cbb5d064ed0ce9c8560c7803fe2",
    "b1223b6e45920cc82f1fa8b9072b587f5d93bc7286ab555b9faab279d0f13ca8",
    "1a8547963f648222a26cdcd5c016bd9c72e0532e1e3d2f897eba8d92b28b4367",
    "45abb5d5076a8013757b346b52117caf209b549f7c3bd6613d9355fd379c34ab",
    "fff71a79be91d082aa9fa0ddadb7526174c9a85dc088aad0d1dd4328ec646d94",
    "60359dd6faac3187c192179f248481e1abc99e529cb5348c8be36a419631ddb4",
    "ba0ef37e385c20decd80570f15a344054fc0d06163f30e987b87b9c0cacc2622",
    "6039f15b21b18518708468a579f29f5dcedf564a7c652ad9db9d767dc583e464",
);

/// Expected RSASSA-PSS-SHA-512 signature over [`KAT_MESSAGE`].
const KAT_PSS_SHA512: &str = concat!(
    "120c86884b9a05b6940ac2ac29b1e5c05b323c86f3af77bf979361081e688740",
    "25b2e97514cd6cd66749e5e59bcdc3177de78d79f5f5026c71c7862c5f782b1b",
    "bd6dfb14731fbd7eafb4d84b79d95c4a6270f83ac6ac576642b183f7e3360e88",
    "040ae57ba68088c7e6c3119f61477f6fd937a1e47ef1edd4fa5c2b72916a1305",
    "b78969a65803e5d1c8d7bec77d2ef4a67489a0714487b5c3c5b24772a346f5ff",
    "a3998029d5278551c47824a57dddd12b3cfbe16d40b1bc996c1b83fde29037fa",
    "928977f3e67d064bfd9b23ea505b1affc657c56e9fed25ebb589c48a8d5dd2b5",
    "cda4f6b6831ebea58745ea068f81f9ebed3e8d46613bf6d09373607a8744c3e5",
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

/// The known-answer-test key pair.
fn kat_key() -> Result<RsaPrivateKey> {
    RsaPrivateKey::from_components(&unhex_256(KAT_N)?, KAT_E, &unhex_256(KAT_D)?)
}

/// The public half of the known-answer-test key.
fn kat_public() -> Result<RsaPublicKey> {
    RsaPublicKey::from_components(&unhex_256(KAT_N)?, KAT_E)
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
