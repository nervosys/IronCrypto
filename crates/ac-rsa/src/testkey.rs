//! Test-only handles on the pinned key from [`crate::kat`].
//!
//! Generating a key costs seconds, and the signature tests need one in every
//! case, so they share the same pinned key the known-answer tests use.
//! `the_pinned_key_is_internally_consistent` re-derives everything checkable
//! about it on every run, so a mistranscribed digit fails loudly rather than
//! quietly weakening the tests.

use crate::key::{RsaPrivateKey, RsaPublicKey};

/// The pinned 2048-bit private key.
pub fn test_private_key() -> RsaPrivateKey {
    crate::kat::kat_key().expect("the pinned test key is well formed")
}

/// The matching public key.
pub fn test_public_key() -> RsaPublicKey {
    *test_private_key().public_key()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defining RSA identity: `(m^e)^d = m (mod n)` for every m. If the
    /// pinned constants were transcribed wrongly, or if `d` does not match `n`
    /// and `e`, this fails for essentially every message.
    #[test]
    fn the_pinned_key_is_internally_consistent() {
        let private = test_private_key();
        let public = test_public_key();
        assert_eq!(public.bits(), 2048);
        assert_eq!(public.size(), 256);
        assert_eq!(public.exponent(), 65537);

        for seed in [1u8, 2, 0x5a, 0xff] {
            let mut message = [seed; 256];
            // Keep it comfortably below n by clearing the top byte.
            message[0] = 0;

            let mut encrypted = [0u8; 256];
            public.raw_public(&message, &mut encrypted).unwrap();
            let mut recovered = [0u8; 256];
            private.raw_private(&encrypted, &mut recovered).unwrap();
            assert_eq!(recovered, message, "(m^e)^d = m for seed {seed}");

            // And the other order, which is what signing does.
            let mut signed = [0u8; 256];
            private.raw_private(&message, &mut signed).unwrap();
            let mut checked = [0u8; 256];
            public.raw_public(&signed, &mut checked).unwrap();
            assert_eq!(checked, message, "(m^d)^e = m for seed {seed}");
        }
    }

    /// Regenerate the pinned key. Ignored because it takes seconds; run with
    /// `cargo test -p ac-rsa --release -- --ignored --nocapture generate_and_print`
    /// and paste the output above.
    #[test]
    #[ignore = "slow; used to produce the pinned constants"]
    fn generate_and_print_a_key() {
        let mut rng = ac_drbg::Rng::from_os().expect("system entropy");
        let key = crate::key::generate(2048, &mut rng).expect("key generation");

        let mut p = [0u8; 128];
        let mut q = [0u8; 128];
        key.prime_bytes(&mut p, &mut q).unwrap();

        let hex = |bytes: &[u8]| -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        };
        println!("KAT_P {}", hex(&p));
        println!("KAT_Q {}", hex(&q));
    }
}
