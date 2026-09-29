//! ML-DSA-65 (FIPS 204 algorithms 1 through 8), checked against NIST's ACVP
//! vectors.
//!
//! # How it is verified
//!
//! The assembled scheme produces the same bytes as NIST's ACVP vectors for
//! ML-DSA-65: all 25 key-generation cases and all 30 signature cases, 15
//! deterministic and 15 hedged. Every layer beneath it is also independently
//! checked — the NTT against schoolbook multiplication, the packing against a
//! bit-at-a-time reference, the rounding against its defining equations, the
//! samplers against the specification's pseudocode.
//!
//! Before the vectors, this module was checked only against itself, by signing
//! and verifying. That was a weaker argument than it sounds, and it is worth
//! keeping the reasoning for why. A sign/verify round trip is not vacuous here: signing computes
//! `w = A*y` while verification computes `w' = A*z - c*t1*2^d` and rebuilds the
//! high bits through the hints, so the two are different computations that must
//! agree through the rounding machinery. What the round trip cannot catch is a
//! convention misread *consistently* — a byte order in a hash input, a domain
//! separator, the order of `s` and `r` in `ExpandA`. Those produce a scheme
//! that is internally perfect and interoperates with nobody.
//!
//! That is the case the ACVP vectors close, and why the module was registered
//! `experimental` until they arrived. They were produced by another
//! implementation, so a consistent misread anywhere in the stack fails them.
//! It is now `available` in the ontology, usable in the approved mode, and
//! offered by `recommend` for post-quantum signatures -- alongside a constraint
//! to sign in a hybrid with a classical scheme, which is about the youth of
//! lattice cryptanalysis rather than about this code.
//!
//! # What is deliberately not here
//!
//! Nothing parameter-specific: ML-DSA-44 and ML-DSA-87 are [`crate::sign44`]
//! and [`crate::sign87`], this code at their parameters. They were kept out
//! until each could be checked against its own ACVP cases rather than ship
//! unchecked beside one that was, and they arrived with those cases.
//!
//! The hedged variant takes its 32 bytes of randomness as an argument rather
//! than reaching for a DRBG, so the deterministic variant is the same code path
//! with zeros — and so a caller cannot get a silently non-random signature from
//! a failed entropy source they never saw.

crate::scheme::ml_dsa!(6, 5, 4, ETA4_BITS, 49, 1 << 19, GAMMA2_32, 55, 48);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poly::Q;

    fn key(seed: u8) -> ([u8; PUBLIC_KEY_LEN], [u8; SECRET_KEY_LEN]) {
        let mut xi = [0u8; 32];
        for (i, b) in xi.iter_mut().enumerate() {
            *b = seed.wrapping_mul(7).wrapping_add(i as u8);
        }
        let mut pk = [0u8; PUBLIC_KEY_LEN];
        let mut sk = [0u8; SECRET_KEY_LEN];
        assert!(
            keygen(&xi, &mut pk, &mut sk),
            "keygen consistency test failed"
        );
        (pk, sk)
    }

    /// HashML-DSA round-trips for every approved pre-hash.
    #[test]
    fn prehash_signatures_verify() {
        let (pk, sk) = key(20);
        for ph in [PreHash::Sha256, PreHash::Sha384, PreHash::Sha512] {
            for message in [&b""[..], &b"short"[..], &[0xa5u8; 5000][..]] {
                for ctx in [&b""[..], &b"ctx"[..]] {
                    let mut sig = [0u8; SIGNATURE_LEN];
                    assert!(
                        sign_prehash(&sk, message, ctx, ph, &[0u8; 32], &mut sig),
                        "signing failed for {ph:?}"
                    );
                    assert!(
                        verify_prehash(&pk, message, ctx, ph, &sig),
                        "verification failed for {ph:?}"
                    );
                }
            }
        }
    }

    /// The two variants must not be interchangeable, in either direction.
    ///
    /// This is the property the whole pre-hash variant turns on. The domain
    /// separator byte is 0 for pure and 1 for pre-hash, so a signature made one
    /// way must be rejected the other way -- otherwise a caller could "support"
    /// HashML-DSA by hashing the message themselves and calling `sign`, and the
    /// result would interoperate with nothing while appearing to work in any
    /// test that only signs and verifies with the same code.
    #[test]
    fn the_pure_and_prehash_variants_are_separated() {
        let (pk, sk) = key(21);
        let message = b"the message";
        let ph = PreHash::Sha512;

        let mut pure_sig = [0u8; SIGNATURE_LEN];
        assert!(sign_deterministic(&sk, message, b"", &mut pure_sig));
        let mut ph_sig = [0u8; SIGNATURE_LEN];
        assert!(sign_prehash(&sk, message, b"", ph, &[0u8; 32], &mut ph_sig));

        assert_ne!(
            pure_sig.to_vec(),
            ph_sig.to_vec(),
            "the two variants must not produce the same signature"
        );
        assert!(
            !verify_prehash(&pk, message, b"", ph, &pure_sig),
            "a pure signature was accepted as a pre-hash one"
        );
        assert!(
            !verify(&pk, message, b"", &ph_sig),
            "a pre-hash signature was accepted as a pure one"
        );

        // And the workaround the documentation warns against: hashing the
        // message yourself and calling the pure variant produces something the
        // pre-hash verifier rejects.
        use ic_core::traits::Digest;
        let digest = ic_hash::Sha512::digest(message);
        let mut hand_rolled = [0u8; SIGNATURE_LEN];
        assert!(sign_deterministic(
            &sk,
            digest.as_ref(),
            b"",
            &mut hand_rolled
        ));
        assert!(
            !verify_prehash(&pk, message, b"", ph, &hand_rolled),
            "hashing by hand and signing pure must not pass as HashML-DSA"
        );
    }

    /// The hash choice is bound into the signature by its OID.
    ///
    /// Without the OID in `M'`, a verifier told the wrong hash would still have
    /// to be wrong about the digest to fail. With it, presenting the wrong hash
    /// fails on the framing alone.
    #[test]
    fn the_prehash_choice_is_bound_to_the_signature() {
        let (pk, sk) = key(22);
        let message = b"bind the hash";

        let mut sig = [0u8; SIGNATURE_LEN];
        assert!(sign_prehash(
            &sk,
            message,
            b"",
            PreHash::Sha256,
            &[0u8; 32],
            &mut sig
        ));
        assert!(verify_prehash(&pk, message, b"", PreHash::Sha256, &sig));

        for wrong in [PreHash::Sha384, PreHash::Sha512] {
            assert!(
                !verify_prehash(&pk, message, b"", wrong, &sig),
                "a signature made with SHA-256 verified under {wrong:?}"
            );
        }
    }

    /// The OID bytes, rebuilt from their arcs rather than trusted.
    ///
    /// These are transcribed constants in a file that otherwise derives its
    /// numbers, so the test encodes the object identifiers itself and compares.
    /// A single wrong trailing byte would make every signature interoperate
    /// with nothing, and would be invisible to a round-trip test.
    #[test]
    fn the_hash_oids_match_their_arcs() {
        /// Minimal DER encoder for an OID, from its arcs.
        fn der(arcs: &[u32]) -> Vec<u8> {
            let mut content = vec![(arcs[0] * 40 + arcs[1]) as u8];
            for &arc in &arcs[2..] {
                let mut stack = Vec::new();
                let mut v = arc;
                loop {
                    stack.push((v & 0x7f) as u8);
                    v >>= 7;
                    if v == 0 {
                        break;
                    }
                }
                for (i, byte) in stack.iter().rev().enumerate() {
                    let last = i + 1 == stack.len();
                    content.push(if last { *byte } else { *byte | 0x80 });
                }
            }
            let mut out = vec![0x06, content.len() as u8];
            out.extend_from_slice(&content);
            out
        }

        // Sanity: the encoder reproduces a well-known OID.
        assert_eq!(
            der(&[1, 2, 840, 113549]),
            vec![0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d],
            "the test's own OID encoder is wrong"
        );

        assert_eq!(
            PreHash::Sha256.oid_der().to_vec(),
            der(&[2, 16, 840, 1, 101, 3, 4, 2, 1])
        );
        assert_eq!(
            PreHash::Sha384.oid_der().to_vec(),
            der(&[2, 16, 840, 1, 101, 3, 4, 2, 2])
        );
        assert_eq!(
            PreHash::Sha512.oid_der().to_vec(),
            der(&[2, 16, 840, 1, 101, 3, 4, 2, 3])
        );

        // And the digest lengths, which the framing depends on.
        assert_eq!(PreHash::Sha256.digest_len(), 32);
        assert_eq!(PreHash::Sha384.digest_len(), 48);
        assert_eq!(PreHash::Sha512.digest_len(), 64);
    }

    /// Pre-hash signing honours the same context rules as the pure variant.
    #[test]
    fn prehash_binds_the_context_and_refuses_an_overlong_one() {
        let (pk, sk) = key(23);
        let ph = PreHash::Sha256;
        let mut sig = [0u8; SIGNATURE_LEN];
        assert!(sign_prehash(&sk, b"m", b"one", ph, &[0u8; 32], &mut sig));
        assert!(verify_prehash(&pk, b"m", b"one", ph, &sig));
        assert!(!verify_prehash(&pk, b"m", b"two", ph, &sig));
        assert!(!verify_prehash(&pk, b"m", b"", ph, &sig));

        let long = [0u8; 256];
        let mut unused = [0u8; SIGNATURE_LEN];
        assert!(!sign_prehash(&sk, b"m", &long, ph, &[0u8; 32], &mut unused));
        assert!(!verify_prehash(&pk, b"m", &long, ph, &sig));
    }

    /// The sizes FIPS 204 publishes for ML-DSA-65.
    ///
    /// These are computed here from the parameters rather than written down,
    /// and then checked against the numbers in the standard. It is one of the
    /// few genuinely external cross-checks available without a vector file: if
    /// a width or a count were wrong, these would almost certainly not land on
    /// the published values.
    #[test]
    fn the_encoded_sizes_match_the_standard() {
        assert_eq!(PUBLIC_KEY_LEN, 1952, "ML-DSA-65 verification key");
        assert_eq!(SECRET_KEY_LEN, 4032, "ML-DSA-65 signing key");
        assert_eq!(SIGNATURE_LEN, 3309, "ML-DSA-65 signature");
        assert_eq!(BETA, 196, "beta = tau * eta");
        assert_eq!(GAMMA2, 261_888, "gamma2 = (q-1)/32");
    }

    #[test]
    fn a_signature_verifies() {
        let (pk, sk) = key(1);
        let mut sig = [0u8; SIGNATURE_LEN];
        assert!(sign_deterministic(&sk, b"hello world", b"", &mut sig));
        assert!(verify(&pk, b"hello world", b"", &sig));
    }

    /// The round trip must work for messages of every awkward shape, since the
    /// message goes through a length-prefixed framing.
    #[test]
    fn signatures_verify_for_many_messages_and_keys() {
        for seed in 0..4u8 {
            let (pk, sk) = key(seed);
            for message in [
                &b""[..],
                &b"a"[..],
                &b"the quick brown fox"[..],
                &[0xffu8; 1000][..],
            ] {
                for ctx in [&b""[..], &b"ctx"[..], &[7u8; 255][..]] {
                    let mut sig = [0u8; SIGNATURE_LEN];
                    assert!(
                        sign_deterministic(&sk, message, ctx, &mut sig),
                        "signing failed, seed={seed} len={}",
                        message.len()
                    );
                    assert!(
                        verify(&pk, message, ctx, &sig),
                        "verification failed, seed={seed} len={}",
                        message.len()
                    );
                }
            }
        }
    }

    /// Determinism, which is also what makes a future vector able to check
    /// this at all.
    #[test]
    fn deterministic_signing_is_deterministic() {
        let (_, sk) = key(2);
        let mut a = [0u8; SIGNATURE_LEN];
        let mut b = [0u8; SIGNATURE_LEN];
        assert!(sign_deterministic(&sk, b"same", b"", &mut a));
        assert!(sign_deterministic(&sk, b"same", b"", &mut b));
        assert_eq!(a.to_vec(), b.to_vec());

        // And keygen too.
        let (pk1, sk1) = key(9);
        let (pk2, sk2) = key(9);
        assert_eq!(pk1.to_vec(), pk2.to_vec());
        assert_eq!(sk1.to_vec(), sk2.to_vec());
    }

    /// Hedging must change the signature but not its validity.
    #[test]
    fn hedged_signing_differs_and_still_verifies() {
        let (pk, sk) = key(3);
        let mut a = [0u8; SIGNATURE_LEN];
        let mut b = [0u8; SIGNATURE_LEN];
        assert!(sign(&sk, b"msg", b"", &[0u8; 32], &mut a));
        assert!(sign(&sk, b"msg", b"", &[9u8; 32], &mut b));
        assert_ne!(a.to_vec(), b.to_vec(), "randomness must reach the output");
        assert!(verify(&pk, b"msg", b"", &a));
        assert!(verify(&pk, b"msg", b"", &b));
    }

    /// The message, the context and the key must each be bound into the
    /// signature.
    ///
    /// The context one matters most: if `ctx` were not covered, a signature
    /// made in one application's context would verify in another's, which is
    /// the entire reason the field exists.
    #[test]
    fn a_signature_does_not_transfer() {
        let (pk, sk) = key(4);
        let (other_pk, _) = key(5);
        let mut sig = [0u8; SIGNATURE_LEN];
        assert!(sign_deterministic(&sk, b"message", b"ctx", &mut sig));

        assert!(verify(&pk, b"message", b"ctx", &sig), "the baseline");
        assert!(!verify(&pk, b"messagf", b"ctx", &sig), "wrong message");
        assert!(!verify(&pk, b"message", b"ctY", &sig), "wrong context");
        assert!(!verify(&pk, b"message", b"", &sig), "absent context");
        assert!(!verify(&other_pk, b"message", b"ctx", &sig), "wrong key");
    }

    /// Every single-byte change to a signature must be rejected.
    ///
    /// Sampled rather than exhaustive, but across all three regions: the
    /// challenge digest, the packed `z`, and the hint block.
    #[test]
    fn tampered_signatures_are_rejected() {
        let (pk, sk) = key(6);
        let mut sig = [0u8; SIGNATURE_LEN];
        assert!(sign_deterministic(&sk, b"tamper", b"", &mut sig));
        assert!(verify(&pk, b"tamper", b"", &sig));

        let spots = [
            0usize,
            C_TILDE_LEN - 1,
            C_TILDE_LEN,
            C_TILDE_LEN + Z_LEN / 2,
            C_TILDE_LEN + L * Z_LEN - 1,
            C_TILDE_LEN + L * Z_LEN,
            SIGNATURE_LEN - 1,
        ];
        for at in spots {
            let mut bad = sig;
            bad[at] ^= 0x01;
            assert!(
                !verify(&pk, b"tamper", b"", &bad),
                "a flipped bit at offset {at} was accepted"
            );
        }
    }

    /// A signature whose `z` is out of bounds must be refused even if the rest
    /// is consistent.
    ///
    /// This is the check that stops a forger from using an oversized `z`, and
    /// it is easy to omit because nothing else fails without it.
    #[test]
    fn an_oversized_z_is_refused() {
        let (pk, sk) = key(7);
        let mut sig = [0u8; SIGNATURE_LEN];
        assert!(sign_deterministic(&sk, b"bounds", b"", &mut sig));

        // Re-pack the first z polynomial with a coefficient at the bound.
        let mut p = Poly::ZERO;
        bit_unpack(
            &sig[C_TILDE_LEN..C_TILDE_LEN + Z_LEN],
            GAMMA1,
            z_bits(GAMMA1),
            &mut p,
        );
        p.c[0] = GAMMA1 - BETA;
        let mut repacked = [0u8; Z_LEN];
        bit_pack(&p, GAMMA1, z_bits(GAMMA1), &mut repacked);
        sig[C_TILDE_LEN..C_TILDE_LEN + Z_LEN].copy_from_slice(&repacked);

        assert!(
            !verify(&pk, b"bounds", b"", &sig),
            "z at the bound was accepted"
        );
    }

    /// A non-canonical hint block must be refused by verification, not merely
    /// by `hint_unpack` in isolation.
    #[test]
    fn verification_refuses_a_non_canonical_hint_block() {
        let (pk, sk) = key(8);
        let mut sig = [0u8; SIGNATURE_LEN];
        assert!(sign_deterministic(&sk, b"canon", b"", &mut sig));
        assert!(verify(&pk, b"canon", b"", &sig));

        let hint_at = C_TILDE_LEN + L * Z_LEN;
        let total = sig[hint_at + OMEGA + K - 1] as usize;
        assert!(total >= 2, "the fixture needs at least two hints");

        // Nonzero padding past the last index.
        let mut bad = sig;
        bad[hint_at + total] = 0xff;
        assert!(
            !verify(&pk, b"canon", b"", &bad),
            "padded hint block accepted"
        );

        // A count past omega.
        let mut bad = sig;
        bad[hint_at + OMEGA + K - 1] = (OMEGA + 1) as u8;
        assert!(!verify(&pk, b"canon", b"", &bad), "overlong count accepted");
    }

    /// The secret key must round-trip through its encoding.
    ///
    /// Signing decodes the key it was given, so if the encoding lost anything
    /// every signature would fail; this isolates the encoding so a failure says
    /// which layer broke.
    #[test]
    fn the_signing_key_survives_its_encoding() {
        let (_, sk) = key(11);
        let decoded = sk_decode(&sk);
        for p in decoded.s1.iter().chain(decoded.s2.iter()) {
            for &c in p.c.iter() {
                assert!((-ETA..=ETA).contains(&c), "secret out of range: {c}");
            }
        }
        for p in decoded.t0.iter() {
            for &c in p.c.iter() {
                let half = 1i32 << (D - 1);
                assert!(c > -half && c <= half, "t0 out of range: {c}");
            }
        }
    }

    /// `t1` from the public key must reconstruct `t` together with `t0`.
    ///
    /// This is the link between key generation and verification: verification
    /// uses `t1 * 2^d` as a stand-in for `t`, and the difference it ignores is
    /// exactly what the hints cover.
    #[test]
    fn the_public_key_and_t0_reconstruct_t() {
        let (pk, sk) = key(12);
        let decoded = sk_decode(&sk);
        let mut t1 = [Poly::ZERO; K];
        for (p, chunk) in t1.iter_mut().zip(pk[32..].chunks(T1_LEN)) {
            simple_bit_unpack(chunk, T1_BITS, p);
        }

        // Rebuild t the way keygen did, and check the split matches.
        let mut rho = [0u8; 32];
        rho.copy_from_slice(&pk[..32]);
        let a = expand_a(&rho);
        let mut t = matrix_apply(&a, &ntt_vec(&decoded.s1));
        for (ti, s) in t.iter_mut().zip(decoded.s2.iter()) {
            *ti = ti.add(s);
            ti.normalize();
        }
        for i in 0..K {
            for j in 0..N {
                assert_eq!(
                    (t1[i].c[j] * (1 << D) + decoded.t0[i].c[j]).rem_euclid(Q),
                    t[i].c[j],
                    "t does not reconstruct at ({i},{j})"
                );
            }
        }
    }

    /// A context longer than 255 bytes has no encoding, so it must be refused
    /// rather than silently truncated.
    #[test]
    fn an_overlong_context_is_refused() {
        let (pk, sk) = key(13);
        let ctx = [0u8; 256];
        let mut sig = [0u8; SIGNATURE_LEN];
        assert!(!sign_deterministic(&sk, b"m", &ctx, &mut sig));
        assert!(!verify(&pk, b"m", &ctx, &sig));
    }
}
