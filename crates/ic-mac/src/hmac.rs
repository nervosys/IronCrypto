//! FIPS 198-1 HMAC, generic over any digest.

use ic_core::traits::{Algorithm, Digest, Mac, SelfTest};
use ic_core::{ensure, Result, Zeroize};

/// The largest block size among supported digests.
///
/// SHA-512 uses 128 bytes; SHA3-224 has the widest rate at 144, so the padded
/// key buffers are sized for it.
const MAX_BLOCK_LEN: usize = 144;

/// HMAC over the digest `D`.
///
/// The key is processed per FIPS 198-1: hashed if longer than the block size,
/// zero-padded otherwise. Both padded keys are zeroized before the constructor
/// returns.
#[derive(Clone)]
pub struct Hmac<D: Digest> {
    inner: D,
    outer: D,
}

/// A digest that can name its HMAC instantiation in the ontology.
///
/// Rust cannot concatenate `&'static str` constants at compile time, so the
/// composed identifier (`"hmac-sha2-256"`) is declared explicitly per digest
/// rather than derived from [`Digest::ID`].
pub trait HmacDigest: Digest {
    /// Ontology identifier of the HMAC built on this digest.
    const HMAC_ID: &'static str;
    /// Display name of the HMAC built on this digest.
    const HMAC_NAME: &'static str;
}

impl<D: HmacDigest> Algorithm for Hmac<D> {
    const ID: &'static str = D::HMAC_ID;
    const NAME: &'static str = D::HMAC_NAME;
}

impl<D: HmacDigest> Mac for Hmac<D> {
    type Tag = D::Output;
    const TAG_LEN: usize = D::OUTPUT_LEN;

    fn new(key: &[u8]) -> Result<Self> {
        ensure!(
            D::BLOCK_LEN <= MAX_BLOCK_LEN,
            InvalidParameter,
            "digest block exceeds hmac buffer"
        );

        let mut padded = [0u8; MAX_BLOCK_LEN];
        if key.len() > D::BLOCK_LEN {
            let hashed = D::digest(key);
            padded[..D::OUTPUT_LEN].copy_from_slice(hashed.as_ref());
        } else {
            padded[..key.len()].copy_from_slice(key);
        }

        let mut inner = D::new();
        let mut outer = D::new();
        let mut pad = [0u8; MAX_BLOCK_LEN];

        for i in 0..D::BLOCK_LEN {
            pad[i] = padded[i] ^ 0x36;
        }
        inner.update(&pad[..D::BLOCK_LEN]);

        for i in 0..D::BLOCK_LEN {
            pad[i] = padded[i] ^ 0x5c;
        }
        outer.update(&pad[..D::BLOCK_LEN]);

        pad.zeroize();
        padded.zeroize();
        Ok(Self { inner, outer })
    }

    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize(mut self) -> Self::Tag {
        let inner_digest = self.inner.finalize();
        self.outer.update(inner_digest.as_ref());
        self.outer.finalize()
    }
}

macro_rules! hmac_alias {
    (
        $name:ident, $digest:ty, $id:literal, $disp:literal, $taglen:literal,
        $kat_key:expr, $kat_msg:expr, $kat_tag:literal
    ) => {
        #[doc = concat!($disp, ".")]
        pub type $name = Hmac<$digest>;

        impl HmacDigest for $digest {
            const HMAC_ID: &'static str = $id;
            const HMAC_NAME: &'static str = $disp;
        }

        impl SelfTest for Hmac<$digest> {
            fn self_test() -> Result<()> {
                let mut key = [0u8; 20];
                ic_core::codec::hex_decode($kat_key.as_bytes(), &mut key)?;
                let tag = <Self as Mac>::mac(&key, $kat_msg)?;
                let mut want = [0u8; $taglen];
                ic_core::codec::hex_decode($kat_tag.as_bytes(), &mut want)?;
                ensure!(
                    ic_core::ct::verify(&want, tag.as_ref()),
                    SelfTestFailed,
                    $id
                );
                Ok(())
            }
        }
    };
}

/// The RFC 4231 test-case-1 key: twenty `0x0b` bytes.
const KAT_KEY: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";

// Known-answer vectors, all over the RFC 4231 test-case-1 input
// (a 20-byte 0x0b key over "Hi There"):
//
// * SHA-256 / SHA-384 / SHA-512 tags are RFC 4231 test case 1.
// * SHA-512/256 and the SHA-3 tags are the corresponding NIST HMAC sample
//   values for the same input.
hmac_alias!(
    HmacSha256,
    ic_hash::Sha256,
    "hmac-sha2-256",
    "HMAC-SHA-256",
    32,
    KAT_KEY,
    b"Hi There",
    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
);
hmac_alias!(
    HmacSha384,
    ic_hash::Sha384,
    "hmac-sha2-384",
    "HMAC-SHA-384",
    48,
    KAT_KEY,
    b"Hi There",
    "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"
);
hmac_alias!(
    HmacSha512,
    ic_hash::Sha512,
    "hmac-sha2-512",
    "HMAC-SHA-512",
    64,
    KAT_KEY,
    b"Hi There",
    "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
);
hmac_alias!(
    HmacSha512_256,
    ic_hash::Sha512_256,
    "hmac-sha2-512-256",
    "HMAC-SHA-512/256",
    32,
    KAT_KEY,
    b"Hi There",
    "9f9126c3d9c3c330d760425ca8a217e31feae31bfe70196ff81642b868402eab"
);
hmac_alias!(
    HmacSha3_256,
    ic_hash::Sha3_256,
    "hmac-sha3-256",
    "HMAC-SHA3-256",
    32,
    KAT_KEY,
    b"Hi There",
    "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb"
);
hmac_alias!(
    HmacSha3_512,
    ic_hash::Sha3_512,
    "hmac-sha3-512",
    "HMAC-SHA3-512",
    64,
    KAT_KEY,
    b"Hi There",
    "eb3fbd4b2eaab8f5c504bd3a41465aacec15770a7cabac531e482f860b5ec7ba47ccb2c6f2afce8f88d22b6dc61380f23a668fd3888bb80537c0a0b86407689e"
);

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::codec::hex;

    #[test]
    fn rfc4231_case_1() {
        let key = [0x0bu8; 20];
        assert_eq!(
            hex(HmacSha256::mac(&key, b"Hi There").unwrap().as_ref()),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(HmacSha512::mac(&key, b"Hi There").unwrap().as_ref()),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
    }

    #[test]
    fn rfc4231_case_2_short_key() {
        assert_eq!(
            hex(HmacSha256::mac(b"Jefe", b"what do ya want for nothing?")
                .unwrap()
                .as_ref()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// Case 3 uses a key and message that both exceed one block.
    #[test]
    fn rfc4231_case_3_long_data() {
        let key = [0xaau8; 20];
        let data = [0xddu8; 50];
        assert_eq!(
            hex(HmacSha256::mac(&key, &data).unwrap().as_ref()),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        );
    }

    /// Case 6: a 131-byte key, longer than the SHA-256 block, so it is hashed
    /// down first.
    #[test]
    fn rfc4231_case_6_oversized_key() {
        let key = [0xaau8; 131];
        assert_eq!(
            hex(HmacSha256::mac(
                &key,
                b"Test Using Larger Than Block-Size Key - Hash Key First"
            )
            .unwrap()
            .as_ref()),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn empty_key_and_message() {
        assert_eq!(
            hex(HmacSha256::mac(b"", b"").unwrap().as_ref()),
            "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"
        );
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data: Vec<u8> = (0..200u8).collect();
        for split in [0usize, 1, 63, 64, 128, 200] {
            let mut m = HmacSha256::new(b"k").unwrap();
            m.update(&data[..split]);
            m.update(&data[split..]);
            assert_eq!(m.finalize(), HmacSha256::mac(b"k", &data).unwrap());
        }
    }

    #[test]
    fn verify_rejects_wrong_tag_and_length() {
        let tag = HmacSha256::mac(b"k", b"m").unwrap();
        HmacSha256::verify(b"k", b"m", tag.as_ref()).unwrap();
        let mut bad = tag;
        bad[0] ^= 1;
        assert!(HmacSha256::verify(b"k", b"m", bad.as_ref()).is_err());
        assert!(HmacSha256::verify(b"k", b"m", &tag.as_ref()[..31]).is_err());
    }

    #[test]
    fn self_tests_pass() {
        HmacSha256::self_test().unwrap();
        HmacSha384::self_test().unwrap();
        HmacSha512::self_test().unwrap();
        HmacSha512_256::self_test().unwrap();
        HmacSha3_256::self_test().unwrap();
        HmacSha3_512::self_test().unwrap();
    }
}
