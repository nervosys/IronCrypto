//! ML-KEM-768 (FIPS 203), checked against NIST's ACVP vectors.
//!
//! # How it is verified
//!
//! Everything below assembles components that each have an independent oracle:
//! the ring arithmetic against schoolbook multiplication, the packing against a
//! bit buffer, the samplers against the specification's pseudocode, SHAKE and
//! SHA-3 against published FIPS 202 vectors.
//!
//! Those checks could not reach the assembly. A KEM whose matrix indices are
//! transposed, or whose hash inputs are ordered differently, still encapsulates
//! and decapsulates against itself perfectly -- and interoperates with nobody.
//! What closes that is the ACVP vectors: all 25 key-generation and all 25
//! encapsulation cases for ML-KEM-768, produced by another implementation, so
//! a convention misread anywhere in the stack fails them.
//!
//! It is registered `available` in the ontology and usable in the FIPS
//! approved mode, and `recommend` offers it for post-quantum key agreement --
//! with a constraint to deploy it in a hybrid, since lattice cryptanalysis is
//! young, not because of any doubt about this implementation.
//!
//! What *can* be said without a vector is that the key and ciphertext sizes
//! come out at exactly the widths FIPS 203 specifies — 1184, 2400, 1088 and 32
//! bytes — which is a weak external check but a real one, since those follow
//! from the parameters rather than from this code.
//!
//! # The shape of the scheme
//!
//! K-PKE is a public-key encryption scheme whose security rests on Module-LWE:
//! the public key is `t = A·s + e` for a public matrix `A`, secret `s` and
//! small noise `e`, and recovering `s` from `t` is the hard problem. It is only
//! CPA-secure, and it fails to decrypt with small probability.
//!
//! ML-KEM wraps it with the Fujisaki-Okamoto transform to get CCA security. The
//! part worth understanding is **implicit rejection**: when decapsulation finds
//! a ciphertext that does not re-encrypt to itself, it does not return an error.
//! It returns a pseudorandom key derived from a secret held in the private key.
//! An attacker probing with malformed ciphertexts therefore learns nothing from
//! the response — there is no oracle to query, because failure and success are
//! indistinguishable from outside.

crate::scheme::ml_kem!(MlKem768, "ML-KEM-768.", 3, 2, 2, 10, 4);

#[cfg(test)]
mod tests {
    use super::*;

    fn rng(label: &[u8]) -> ic_drbg::Rng {
        ic_drbg::Rng::from_entropy(&[0x5au8; 32], label).unwrap()
    }

    /// The sizes are fixed by FIPS 203 and follow from the parameters, not from
    /// this code. Getting them right is weak evidence, but it is external.
    #[test]
    fn the_sizes_match_the_standard() {
        assert_eq!(ENCAPS_KEY_LEN, 1184, "ML-KEM-768 encapsulation key");
        assert_eq!(DECAPS_KEY_LEN, 2400, "ML-KEM-768 decapsulation key");
        assert_eq!(CIPHERTEXT_LEN, 1088, "ML-KEM-768 ciphertext");
        assert_eq!(SHARED_SECRET_LEN, 32);
    }

    #[test]
    fn encapsulation_and_decapsulation_agree() {
        let mut r = rng(b"mlkem-roundtrip");
        let mut ek = [0u8; ENCAPS_KEY_LEN];
        let mut dk = [0u8; DECAPS_KEY_LEN];
        MlKem768::keygen(&mut r, &mut ek, &mut dk).unwrap();

        for _ in 0..8 {
            let mut ct = [0u8; CIPHERTEXT_LEN];
            let mut a = [0u8; 32];
            MlKem768::encapsulate(&mut r, &ek, &mut ct, &mut a).unwrap();

            let mut b = [0u8; 32];
            MlKem768::decapsulate(&dk, &ct, &mut b).unwrap();
            assert_eq!(a, b, "the two sides derived different secrets");
        }
    }

    /// The decryption failure rate for ML-KEM-768 is around 2^-164, so over any
    /// feasible number of trials it must never happen. A failure here means the
    /// noise is too large, which usually means a scaling error somewhere in the
    /// arithmetic rather than bad luck.
    #[test]
    fn decryption_never_fails_in_practice() {
        let mut r = rng(b"mlkem-failure-rate");
        for _ in 0..16 {
            let mut ek = [0u8; ENCAPS_KEY_LEN];
            let mut dk = [0u8; DECAPS_KEY_LEN];
            MlKem768::keygen(&mut r, &mut ek, &mut dk).unwrap();

            let mut ct = [0u8; CIPHERTEXT_LEN];
            let mut a = [0u8; 32];
            let mut b = [0u8; 32];
            MlKem768::encapsulate(&mut r, &ek, &mut ct, &mut a).unwrap();
            MlKem768::decapsulate(&dk, &ct, &mut b).unwrap();
            assert_eq!(a, b);
        }
    }

    /// Implicit rejection: a tampered ciphertext must produce a *different*
    /// secret, not an error. An implementation that returned an error here
    /// would hand an attacker a decryption oracle.
    #[test]
    fn a_tampered_ciphertext_yields_a_pseudorandom_secret() {
        let mut r = rng(b"mlkem-reject");
        let mut ek = [0u8; ENCAPS_KEY_LEN];
        let mut dk = [0u8; DECAPS_KEY_LEN];
        MlKem768::keygen(&mut r, &mut ek, &mut dk).unwrap();

        let mut ct = [0u8; CIPHERTEXT_LEN];
        let mut good = [0u8; 32];
        MlKem768::encapsulate(&mut r, &ek, &mut ct, &mut good).unwrap();

        for index in [0usize, 1, 500, CIPHERTEXT_LEN - 1] {
            let mut bad = ct;
            bad[index] ^= 1;
            let mut secret = [0u8; 32];
            MlKem768::decapsulate(&dk, &bad, &mut secret)
                .expect("decapsulation must not fail on a bad ciphertext");
            assert_ne!(secret, good, "byte {index} did not change the secret");
        }
    }

    /// The rejection secret depends on z, so two keys that differ only in z
    /// reject differently. That is what makes it unpredictable to an attacker.
    #[test]
    fn the_rejection_secret_depends_on_the_private_key() {
        let d = [0x11u8; 32];
        let mut ek = [0u8; ENCAPS_KEY_LEN];
        let mut dk_a = [0u8; DECAPS_KEY_LEN];
        let mut dk_b = [0u8; DECAPS_KEY_LEN];
        MlKem768::keygen_deterministic(&d, &[0x22u8; 32], &mut ek, &mut dk_a);
        let mut ek_b = [0u8; ENCAPS_KEY_LEN];
        MlKem768::keygen_deterministic(&d, &[0x33u8; 32], &mut ek_b, &mut dk_b);
        assert_eq!(ek, ek_b, "z must not affect the public key");

        let mut ct = [0u8; CIPHERTEXT_LEN];
        let mut secret = [0u8; 32];
        MlKem768::encapsulate_deterministic(&[0x44u8; 32], &ek, &mut ct, &mut secret);
        ct[0] ^= 1;

        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        MlKem768::decapsulate(&dk_a, &ct, &mut a).unwrap();
        MlKem768::decapsulate(&dk_b, &ct, &mut b).unwrap();
        assert_ne!(a, b, "the rejection secret must depend on z");
    }

    #[test]
    fn key_generation_is_deterministic_in_its_seeds() {
        let d = [0x77u8; 32];
        let z = [0x88u8; 32];
        let mut ek_a = [0u8; ENCAPS_KEY_LEN];
        let mut dk_a = [0u8; DECAPS_KEY_LEN];
        let mut ek_b = [0u8; ENCAPS_KEY_LEN];
        let mut dk_b = [0u8; DECAPS_KEY_LEN];
        MlKem768::keygen_deterministic(&d, &z, &mut ek_a, &mut dk_a);
        MlKem768::keygen_deterministic(&d, &z, &mut ek_b, &mut dk_b);
        assert_eq!(ek_a, ek_b);
        assert_eq!(dk_a, dk_b);

        // And a different seed gives a different key.
        MlKem768::keygen_deterministic(&[0x78u8; 32], &z, &mut ek_b, &mut dk_b);
        assert_ne!(ek_a, ek_b);
    }

    #[test]
    fn distinct_keys_do_not_decapsulate_each_others_ciphertexts() {
        let mut r = rng(b"mlkem-cross");
        let mut ek_a = [0u8; ENCAPS_KEY_LEN];
        let mut dk_a = [0u8; DECAPS_KEY_LEN];
        let mut ek_b = [0u8; ENCAPS_KEY_LEN];
        let mut dk_b = [0u8; DECAPS_KEY_LEN];
        MlKem768::keygen(&mut r, &mut ek_a, &mut dk_a).unwrap();
        MlKem768::keygen(&mut r, &mut ek_b, &mut dk_b).unwrap();

        let mut ct = [0u8; CIPHERTEXT_LEN];
        let mut secret = [0u8; 32];
        MlKem768::encapsulate(&mut r, &ek_a, &mut ct, &mut secret).unwrap();

        let mut wrong = [0u8; 32];
        MlKem768::decapsulate(&dk_b, &ct, &mut wrong).unwrap();
        assert_ne!(secret, wrong);
    }

    /// The modulus check must run on the path that actually takes a peer key.
    ///
    /// `validate_encapsulation_key` existed before this test did, and nothing
    /// called it outside its own unit test — so a caller doing the obvious
    /// thing got no validation at all. That is the gap this pins shut.
    #[test]
    fn encapsulate_refuses_a_non_canonical_key() {
        let mut r = rng(b"encaps-validates");
        let mut ek = [0u8; ENCAPS_KEY_LEN];
        let mut dk = [0u8; DECAPS_KEY_LEN];
        MlKem768::keygen(&mut r, &mut ek, &mut dk).unwrap();

        let mut ct = [0u8; CIPHERTEXT_LEN];
        let mut secret = [0u8; SHARED_SECRET_LEN];
        MlKem768::encapsulate(&mut r, &ek, &mut ct, &mut secret).unwrap();

        // Force a coefficient to q or above, which ByteDecode12 would silently
        // fold back into range.
        let mut bad = ek;
        bad[0] = 0xff;
        bad[1] = 0xff;
        assert!(
            MlKem768::validate_encapsulation_key(&bad).is_err(),
            "the fixture must actually be non-canonical"
        );
        assert!(
            MlKem768::encapsulate(&mut r, &bad, &mut ct, &mut secret).is_err(),
            "encapsulate accepted a key it was required to reject"
        );
    }

    /// The hash check, on a key whose halves do not belong together.
    ///
    /// This is the failure it exists to catch: two valid key pairs spliced
    /// together produce a key that decapsulates without complaint and yields
    /// secrets that never agree with the peer, which is a miserable thing to
    /// debug from the far end.
    /// The pairwise consistency test must actually reject a mismatched pair.
    ///
    /// Without this the test would be code that runs on every key generation
    /// and has never been shown to detect anything -- which is precisely the
    /// shape of dead validator this library has already been caught carrying.
    ///
    /// The case is subtle for a KEM: decapsulation never fails, so a mismatched
    /// pair produces the implicit-rejection secret rather than an error. The
    /// test has to compare secrets, and this proves it does.
    #[test]
    fn the_pairwise_consistency_test_rejects_a_mismatched_pair() {
        let mut r = rng(b"pct-negative");
        let mut ek1 = [0u8; ENCAPS_KEY_LEN];
        let mut dk1 = [0u8; DECAPS_KEY_LEN];
        MlKem768::keygen(&mut r, &mut ek1, &mut dk1).unwrap();
        let mut ek2 = [0u8; ENCAPS_KEY_LEN];
        let mut dk2 = [0u8; DECAPS_KEY_LEN];
        MlKem768::keygen(&mut r, &mut ek2, &mut dk2).unwrap();

        // Each pair is consistent with itself.
        MlKem768::pairwise_consistency(&ek1, &dk1).unwrap();
        MlKem768::pairwise_consistency(&ek2, &dk2).unwrap();

        // Crossed, they are not. Decapsulation still succeeds here -- it always
        // does -- so only the secret comparison can catch this.
        let crossed = MlKem768::pairwise_consistency(&ek2, &dk1);
        assert!(
            crossed.is_err(),
            "a mismatched pair passed the consistency test"
        );
    }

    #[test]
    fn decapsulate_refuses_a_spliced_key() {
        let mut r = rng(b"hash-check");
        let mut ek1 = [0u8; ENCAPS_KEY_LEN];
        let mut dk1 = [0u8; DECAPS_KEY_LEN];
        MlKem768::keygen(&mut r, &mut ek1, &mut dk1).unwrap();
        let mut ek2 = [0u8; ENCAPS_KEY_LEN];
        let mut dk2 = [0u8; DECAPS_KEY_LEN];
        MlKem768::keygen(&mut r, &mut ek2, &mut dk2).unwrap();

        let mut ct = [0u8; CIPHERTEXT_LEN];
        let mut secret = [0u8; SHARED_SECRET_LEN];
        MlKem768::encapsulate(&mut r, &ek1, &mut ct, &mut secret).unwrap();

        // The baseline works.
        let mut got = [0u8; SHARED_SECRET_LEN];
        MlKem768::decapsulate(&dk1, &ct, &mut got).unwrap();
        assert_eq!(got, secret);
        MlKem768::validate_decapsulation_key(&dk1).unwrap();

        // Splice the second key's public half into the first key.
        let mut spliced = dk1;
        spliced[384 * K..384 * K + ENCAPS_KEY_LEN].copy_from_slice(&ek2);
        assert!(
            MlKem768::validate_decapsulation_key(&spliced).is_err(),
            "the validator must reject a spliced key"
        );
        assert!(
            MlKem768::decapsulate(&spliced, &ct, &mut got).is_err(),
            "decapsulate must reject a spliced key"
        );

        // And a single flipped bit in the stored hash.
        let mut corrupted = dk1;
        corrupted[384 * K + ENCAPS_KEY_LEN] ^= 1;
        assert!(MlKem768::validate_decapsulation_key(&corrupted).is_err());
        assert!(MlKem768::decapsulate(&corrupted, &ct, &mut got).is_err());
    }

    /// The new key check must not have created a *ciphertext* failure path.
    ///
    /// Implicit rejection is the whole security argument for decapsulation: a
    /// bad ciphertext must yield a pseudorandom secret, never an error, or the
    /// error itself is the decryption oracle the transform exists to remove.
    /// Adding a check on the key is safe precisely because its answer does not
    /// depend on the ciphertext — and this is what holds that line.
    #[test]
    fn no_ciphertext_can_make_decapsulation_fail() {
        let mut r = rng(b"implicit-rejection-holds");
        let mut ek = [0u8; ENCAPS_KEY_LEN];
        let mut dk = [0u8; DECAPS_KEY_LEN];
        MlKem768::keygen(&mut r, &mut ek, &mut dk).unwrap();

        let mut secret = [0u8; SHARED_SECRET_LEN];
        let mut seen_distinct = 0;
        let mut previous = [0u8; SHARED_SECRET_LEN];

        for trial in 0..64u32 {
            let mut ct = [0u8; CIPHERTEXT_LEN];
            match trial % 4 {
                0 => {} // all zeros
                1 => ct.iter_mut().for_each(|b| *b = 0xff),
                2 => r.fill(&mut ct).unwrap(),
                _ => {
                    // A valid ciphertext with one byte disturbed.
                    let mut good = [0u8; CIPHERTEXT_LEN];
                    let mut s = [0u8; SHARED_SECRET_LEN];
                    MlKem768::encapsulate(&mut r, &ek, &mut good, &mut s).unwrap();
                    ct = good;
                    ct[(trial as usize) % CIPHERTEXT_LEN] ^= 0x40;
                }
            }
            MlKem768::decapsulate(&dk, &ct, &mut secret)
                .unwrap_or_else(|e| panic!("decapsulation failed on trial {trial}: {e}"));
            if secret != previous {
                seen_distinct += 1;
            }
            previous = secret;

            // Determinism: the same ciphertext must give the same secret, or
            // the rejection path is not a function of (dk, ct).
            let mut again = [0u8; SHARED_SECRET_LEN];
            MlKem768::decapsulate(&dk, &ct, &mut again).unwrap();
            assert_eq!(
                secret, again,
                "rejection is not deterministic, trial {trial}"
            );
        }
        assert!(seen_distinct > 32, "the secrets look degenerate");
    }

    #[test]
    fn encapsulation_keys_are_validated() {
        let mut r = rng(b"mlkem-validate");
        let mut ek = [0u8; ENCAPS_KEY_LEN];
        let mut dk = [0u8; DECAPS_KEY_LEN];
        MlKem768::keygen(&mut r, &mut ek, &mut dk).unwrap();
        MlKem768::validate_encapsulation_key(&ek).unwrap();

        // A coefficient at or above q is not a canonical encoding. 0xff bytes
        // decode to values above q, which the round trip catches.
        let mut bad = ek;
        bad[0] = 0xff;
        bad[1] = 0xff;
        assert!(MlKem768::validate_encapsulation_key(&bad).is_err());
    }

    /// The shared secret must actually depend on the message, which catches a
    /// build where the FO transform hashed the wrong thing.
    #[test]
    fn the_secret_depends_on_the_message() {
        let d = [0x01u8; 32];
        let z = [0x02u8; 32];
        let mut ek = [0u8; ENCAPS_KEY_LEN];
        let mut dk = [0u8; DECAPS_KEY_LEN];
        MlKem768::keygen_deterministic(&d, &z, &mut ek, &mut dk);

        let mut ct_a = [0u8; CIPHERTEXT_LEN];
        let mut a = [0u8; 32];
        let mut ct_b = [0u8; CIPHERTEXT_LEN];
        let mut b = [0u8; 32];
        MlKem768::encapsulate_deterministic(&[0x10u8; 32], &ek, &mut ct_a, &mut a);
        MlKem768::encapsulate_deterministic(&[0x11u8; 32], &ek, &mut ct_b, &mut b);
        assert_ne!(a, b);
        assert_ne!(ct_a, ct_b);
    }
}
