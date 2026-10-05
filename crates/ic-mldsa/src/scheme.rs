//! The ML-DSA scheme, once, for every parameter set.
//!
//! FIPS 204's three parameter sets differ only in their numbers: the matrix
//! shape `k` by `l`, the secret bound `eta`, the challenge weight `tau`, the
//! mask bound `gamma1`, the rounding range `gamma2`, the hint budget `omega`,
//! and the challenge digest length. So the scheme is written here once, as a
//! macro over those, and each set is one invocation: [`crate::sign`] for
//! ML-DSA-65, [`crate::sign44`] and [`crate::sign87`] for the others. What
//! does not depend on the set -- the hash, the message framing, the pre-hash
//! choice -- is written once below, so every set shares one [`PreHash`].
//!
//! A macro rather than generics for the same reason as ML-KEM's: each set
//! wants fixed-size key and signature arrays, and their lengths are
//! arithmetic on the parameters, which stable Rust cannot express over a
//! generic parameter.
//!
//! ML-DSA-65 was written first and on its own; this is that code with its
//! constants lifted out, not a rewrite. Each set is checked against its own
//! NIST ACVP vectors.

use ic_core::traits::Xof;
use ic_hash::Shake256;

/// How many times signing will retry before giving up.
///
/// Rejection is expected — the parameters aim for a handful of iterations — so
/// a cap this high is only ever reached by a bug or by a caller feeding a
/// broken key. Looping forever would turn that into a hang instead of an error.
pub(crate) const MAX_ATTEMPTS: usize = 1000;

/// `H`: SHAKE-256 over the concatenation of `parts`.
pub(crate) fn h(parts: &[&[u8]], out: &mut [u8]) {
    let mut x = Shake256::default();
    for part in parts {
        <Shake256 as Xof>::update(&mut x, part);
    }
    x.finalize_xof(out);
}

/// `M'` for the pure variant: a domain byte, the context length, the context,
/// then the message.
///
/// The two leading bytes are what keep a pure signature from colliding with a
/// pre-hashed one over the same message, so they are not optional framing.
pub(crate) fn message_prefix(domain: u8, ctx: &[u8]) -> ([u8; 2], bool) {
    ([domain, ctx.len() as u8], ctx.len() <= 255)
}

/// The pieces of `M'`, assembled without allocating.
///
/// `mu` is hashed over `tr`, the two framing bytes, the context and then
/// whatever the variant contributes. There is no `Vec` here, so the parts are
/// gathered into a fixed array; four is the most any variant needs, and the
/// assertion says so rather than silently truncating a fifth.
pub(crate) struct Framed<'a> {
    parts: [&'a [u8]; 5],
    len: usize,
}

impl<'a> Framed<'a> {
    pub(crate) fn new(tr: &'a [u8], prefix: &'a [u8], ctx: &'a [u8], rest: &[&'a [u8]]) -> Self {
        assert!(rest.len() <= 2, "M' has at most two trailing parts");
        let mut parts: [&[u8]; 5] = [&[]; 5];
        parts[0] = tr;
        parts[1] = prefix;
        parts[2] = ctx;
        for (slot, part) in parts[3..].iter_mut().zip(rest.iter()) {
            *slot = part;
        }
        Framed {
            parts,
            len: 3 + rest.len(),
        }
    }

    pub(crate) fn as_slice(&self) -> &[&'a [u8]] {
        &self.parts[..self.len]
    }
}

/// The domain byte for the pure variant, which signs the message itself.
pub(crate) const DOMAIN_PURE: u8 = 0;

/// The domain byte for the pre-hash variant.
pub(crate) const DOMAIN_PREHASH: u8 = 1;

/// Approved pre-hash functions for HashML-DSA.
///
/// The digest alone is not what gets signed: FIPS 204 places the DER encoding
/// of the hash function's object identifier in front of it. That is what binds
/// a signature to *which* hash produced the digest, and without it a signature
/// over SHA-256(m) would also verify as one over a SHA-512 digest that happened
/// to collide with it in its first 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreHash {
    /// SHA-256, OID 2.16.840.1.101.3.4.2.1.
    Sha256,
    /// SHA-384, OID 2.16.840.1.101.3.4.2.2.
    Sha384,
    /// SHA-512, OID 2.16.840.1.101.3.4.2.3.
    Sha512,
}

/// The longest digest any [`PreHash`] produces.
pub(crate) const MAX_DIGEST: usize = 64;

impl PreHash {
    /// The DER encoding of the hash function's object identifier.
    ///
    /// Tag and length included, which is what FIPS 204 concatenates. The
    /// trailing byte is the only difference between the three, and the tests
    /// rebuild these from the OID arcs rather than trusting the transcription.
    pub const fn oid_der(self) -> &'static [u8] {
        match self {
            Self::Sha256 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            ],
            Self::Sha384 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
            ],
            Self::Sha512 => &[
                0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
            ],
        }
    }

    /// Digest length in bytes.
    pub const fn digest_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }

    /// Hash `message`, returning the digest and its length.
    pub(crate) fn digest(self, message: &[u8]) -> ([u8; MAX_DIGEST], usize) {
        use ic_core::traits::Digest;
        let mut out = [0u8; MAX_DIGEST];
        match self {
            Self::Sha256 => out[..32].copy_from_slice(ic_hash::Sha256::digest(message).as_ref()),
            Self::Sha384 => out[..48].copy_from_slice(ic_hash::Sha384::digest(message).as_ref()),
            Self::Sha512 => out[..64].copy_from_slice(ic_hash::Sha512::digest(message).as_ref()),
        }
        (out, self.digest_len())
    }
}

/// Instantiate ML-DSA for one parameter set, in the module that invokes it.
macro_rules! ml_dsa {
    ($k:literal, $l:literal, $eta:literal, $eta_bits:ident, $tau:literal, $gamma1:expr, $gamma2:ident, $omega:literal, $c_tilde:literal) => {
        use $crate::encode::{
            bit_pack, bit_unpack, hint_bools, hint_pack_bits, hint_row, hint_unpack_bits,
            packed_len, simple_bit_pack, simple_bit_unpack, w1_bits, z_bits, HintRow, T0_BITS,
            T1_BITS,
        };
        #[cfg(test)]
        use $crate::encode::{hint_pack, hint_unpack};
        use $crate::poly::{Poly, N};
        use $crate::rounding::{decompose_poly, make_hint_poly, power2round_poly, use_hint_poly, D};
        use $crate::sample::{expand_mask_poly, rej_bounded_poly, rej_ntt_poly, sample_in_ball};
        use $crate::scheme::{h, message_prefix, Framed, DOMAIN_PREHASH, DOMAIN_PURE, MAX_ATTEMPTS};
        pub use $crate::scheme::PreHash;
        use ic_core::Zeroize;

        /// Bits per packed secret coefficient, for this set's `eta`.
        const ETA_BITS: u32 = $crate::encode::$eta_bits;
        /// Low-order rounding range, for this set.
        const GAMMA2: i32 = $crate::rounding::$gamma2;

        /// Rows of `A`, and the length of `t`, `s2` and `w`.
        pub const K: usize = $k;
        /// Columns of `A`, and the length of `s1`, `y` and `z`.
        pub const L: usize = $l;
        /// Secret coefficient bound.
        pub const ETA: i32 = $eta;
        /// Nonzero coefficients in the challenge.
        pub const TAU: usize = $tau;
        /// `tau * eta`, the bound on `c*s`.
        pub const BETA: i32 = (TAU as i32) * ETA;
        /// Mask bound.
        pub const GAMMA1: i32 = $gamma1;
        /// Maximum total hint weight.
        pub const OMEGA: usize = $omega;
        /// Bytes of challenge digest, `lambda / 4`.
        pub const C_TILDE_LEN: usize = $c_tilde;

        /// Bytes in a seed.
        pub const SEED_LEN: usize = 32;

        const T1_LEN: usize = packed_len(T1_BITS);
        const T0_LEN: usize = packed_len(T0_BITS);
        const S_LEN: usize = packed_len(ETA_BITS);
        const Z_LEN: usize = packed_len(z_bits(GAMMA1));
        const W1_LEN: usize = packed_len(w1_bits(GAMMA2));

        /// Encoded verification key length.
        pub const PUBLIC_KEY_LEN: usize = SEED_LEN + K * T1_LEN;
        /// Encoded signing key length.
        pub const SECRET_KEY_LEN: usize = SEED_LEN + SEED_LEN + 64 + L * S_LEN + K * S_LEN + K * T0_LEN;
        /// Encoded signature length.
        pub const SIGNATURE_LEN: usize = C_TILDE_LEN + L * Z_LEN + OMEGA + K;

        /// Where `s1`, `s2` and `t0` start in an encoded signing key.
        const SK_S1_AT: usize = 128;
        const SK_S2_AT: usize = SK_S1_AT + L * S_LEN;
        const SK_T0_AT: usize = SK_S2_AT + K * S_LEN;
        const _: () = assert!(SK_T0_AT + K * T0_LEN == SECRET_KEY_LEN);

        // # Why `A` is never held
        //
        // `A` is `k * l` polynomials of a kilobyte each: 56 KiB for ML-DSA-87,
        // and with the vectors around it signing peaked at 243 KiB of stack, more
        // RAM than most Cortex-M parts have. Each entry of `A` is a pure function
        // of `rho` and its two indices, so sampling it where it is used and then
        // dropping it gives the same values as sampling the whole matrix first,
        // and the ACVP vectors confirm the outputs are unchanged. `rho` is public,
        // so regenerating an entry changes nothing the timing depends on.
        //
        // The cost is time. Key generation and verification use each entry
        // once whether it is stored or not, so they lose nothing. Signing uses
        // all of `A` once per attempt, and so samples it once per attempt
        // instead of once per signature. `bench/src/stack.rs` measures both
        // stack use and time.

        /// `A[r][s]`, generated on demand, in the index order FIPS 204 specifies.
        ///
        /// It comes from `rho || s || r`, column byte first. See
        /// [`crate::sample::rej_ntt_poly`] for why this is called out rather than
        /// assumed.
        fn a_entry(rho: &[u8; 32], r: usize, s: usize) -> Poly {
            rej_ntt_poly(rho, s as u8, r as u8)
        }

        /// Row `r` of `A * v`, with `v` given in the transform domain.
        ///
        /// The sum is accumulated in the transform domain and inverted once, which is
        /// both faster and the only arrangement where the Montgomery bookkeeping works
        /// out: `pointwise` contributes `R^-1` and `inv_ntt` contributes `R`, so a
        /// product needs no correction but a bare round trip does.
        fn a_row_times(rho: &[u8; 32], r: usize, v_hat: &[Poly; L]) -> Poly {
            let mut acc = Poly::ZERO;
            for (s, v) in v_hat.iter().enumerate() {
                acc.pointwise_acc(&a_entry(rho, r, s), v);
            }
            acc.inv_ntt();
            acc
        }

        /// `c * v`, with both `c` and `v` already in the transform domain.
        ///
        /// Taking `v` pre-transformed is not a micro-optimisation. The signing loop
        /// multiplies by `s1`, `s2` and `t0` on every attempt, and they never change,
        /// so transforming inside would redo the same work on every rejection — and,
        /// worse, would make it easy to pass a plain-domain polynomial by mistake and
        /// get a result that is wrong by a Montgomery factor rather than obviously
        /// broken.
        fn scale(c_hat: &Poly, v_hat: &Poly) -> Poly {
            let mut product = c_hat.pointwise(v_hat);
            product.inv_ntt();
            product
        }

        /// `ExpandA` in full: the reference the on-demand entries are tested against.
        #[cfg(test)]
        fn expand_a(rho: &[u8; 32]) -> [[Poly; L]; K] {
            let mut a = [[Poly::ZERO; L]; K];
            for (r, row) in a.iter_mut().enumerate() {
                for (s, cell) in row.iter_mut().enumerate() {
                    *cell = rej_ntt_poly(rho, s as u8, r as u8);
                }
            }
            a
        }

        /// `A * v` over a held matrix: the reference for [`a_row_times`].
        #[cfg(test)]
        fn matrix_apply(a: &[[Poly; L]; K], v_hat: &[Poly; L]) -> [Poly; K] {
            let mut out = [Poly::ZERO; K];
            for (row, dest) in a.iter().zip(out.iter_mut()) {
                let mut acc = Poly::ZERO;
                for (cell, v) in row.iter().zip(v_hat.iter()) {
                    acc = acc.add(&cell.pointwise(v));
                }
                acc.inv_ntt();
                *dest = acc;
            }
            out
        }

        #[cfg(test)]
        fn ntt_vec<const M: usize>(v: &[Poly; M]) -> [Poly; M] {
            let mut out = *v;
            for p in out.iter_mut() {
                p.ntt();
            }
            out
        }

        #[cfg(test)]
        mod streaming {
            use super::*;

            /// Every row generated on demand equals that row of the held product.
            ///
            /// The ACVP vectors already pin the scheme's output; this says where a
            /// break is when one appears, and checks the on-demand path for every
            /// parameter set against the held-matrix form signing used to compute.
            #[test]
            fn on_demand_rows_match_the_held_matrix() {
                let rho: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(29) ^ 0x5c);
                let mut v = [Poly::ZERO; L];
                for (s, p) in v.iter_mut().enumerate() {
                    for (j, c) in p.c.iter_mut().enumerate() {
                        *c = ((s * 7919 + j * 104_729) % 8_380_417) as i32;
                    }
                }
                let v_hat = ntt_vec(&v);
                let held = matrix_apply(&expand_a(&rho), &v_hat);
                for (r, expected) in held.iter().enumerate() {
                    assert_eq!(&a_row_times(&rho, r, &v_hat), expected, "row {r}");
                }
            }

            /// Signing and verification agree with the forms that held the key
            /// and the hints whole, for this parameter set.
            ///
            /// Signatures must be byte-identical, deterministic and hedged, over
            /// several keys and messages, so every attempt count that occurs is
            /// covered. Verification must give the same answer on valid
            /// signatures and on each kind of damage: a flipped bit in the
            /// challenge, in `z`, in the hint indices and in the hint counts,
            /// and the wrong message.
            #[test]
            fn signing_and_verification_match_the_held_forms() {
                let mut checked = 0;
                for key_seed in 0..4u8 {
                    let mut pk = [0u8; PUBLIC_KEY_LEN];
                    let mut sk = [0u8; SECRET_KEY_LEN];
                    assert!(keygen(&[key_seed.wrapping_mul(41) ^ 0x6d; 32], &mut pk, &mut sk));
                    for msg_seed in 0..6u8 {
                        let msg = [msg_seed; 19];
                        let rnd = [msg_seed.wrapping_mul(3) ^ key_seed; 32];
                        for rnd in [[0u8; 32], rnd] {
                            let mut a = [0u8; SIGNATURE_LEN];
                            let mut b = [0u8; SIGNATURE_LEN];
                            let ok_a = sign_framed(&sk, DOMAIN_PURE, &[&msg], b"ctx", &rnd, &mut a);
                            let ok_b =
                                sign_framed_held(&sk, DOMAIN_PURE, &[&msg], b"ctx", &rnd, &mut b);
                            assert!(ok_a && ok_b);
                            assert_eq!(a[..], b[..], "key {key_seed}, message {msg_seed}");

                            let hint_at = SIGNATURE_LEN - OMEGA - K;
                            let damage = [None, Some(0), Some(C_TILDE_LEN + 5), Some(hint_at), Some(SIGNATURE_LEN - 1)];
                            for at in damage {
                                let mut s = a;
                                if let Some(at) = at {
                                    s[at] ^= 1;
                                }
                                for m in [&msg[..], b"another message"] {
                                    assert_eq!(
                                        verify_framed(&pk, DOMAIN_PURE, &[m], b"ctx", &s),
                                        verify_framed_held(&pk, DOMAIN_PURE, &[m], b"ctx", &s),
                                        "key {key_seed}, message {msg_seed}, damage {at:?}"
                                    );
                                }
                            }
                            assert!(verify_framed(&pk, DOMAIN_PURE, &[&msg], b"ctx", &a));
                            checked += 1;
                        }
                    }
                }
                assert_eq!(checked, 48, "the comparison did not run");
            }

            /// `t1` from the public key must reconstruct `t` together with `t0`.
            ///
            /// This is the link between key generation and verification:
            /// verification uses `t1 * 2^d` as a stand-in for `t`, and the
            /// difference it ignores is exactly what the hints cover. `t` is
            /// rebuilt here from the held matrix, so key generation's row-at-a-time
            /// encoding is checked against the form it replaced, for every set.
            #[test]
            fn the_public_key_and_t0_reconstruct_t() {
                let mut pk = [0u8; PUBLIC_KEY_LEN];
                let mut sk = [0u8; SECRET_KEY_LEN];
                assert!(keygen(&[0x3c; 32], &mut pk, &mut sk));
                let decoded = sk_decode(&sk);
                let mut t1 = [Poly::ZERO; K];
                for (p, chunk) in t1.iter_mut().zip(pk[32..].chunks(T1_LEN)) {
                    simple_bit_unpack(chunk, T1_BITS, p);
                }

                let mut rho = [0u8; 32];
                rho.copy_from_slice(&pk[..32]);
                assert_eq!(decoded.rho, rho, "rho is shared by both halves");
                let mut t = matrix_apply(&expand_a(&rho), &ntt_vec(&decoded.s1));
                for (ti, s) in t.iter_mut().zip(decoded.s2.iter()) {
                    *ti = ti.add(s);
                    ti.normalize();
                }
                for i in 0..K {
                    for j in 0..N {
                        assert_eq!(
                            (t1[i].c[j] * (1 << D) + decoded.t0[i].c[j]).rem_euclid($crate::poly::Q),
                            t[i].c[j],
                            "t does not reconstruct at ({i},{j})"
                        );
                    }
                }
            }
        }

        /// Generate a key pair from a 32-byte seed.
        ///
        /// Deterministic in `xi`: the same seed always gives the same key, which is
        /// what makes a future ACVP key generation vector able to check this at all.
        ///
        /// Returns `false` if the pairwise consistency test fails, in which case the
        /// buffers are cleared rather than left holding a key that does not work. That
        /// test is why this returns anything at all; FIPS 140-3 requires it on a
        /// generated asymmetric key pair, and a function that performed it but gave the
        /// caller no way to learn the answer would be performing it for nobody.
        #[must_use = "a false return means the key pair failed its consistency test"]
        pub fn keygen(
            xi: &[u8; SEED_LEN],
            pk: &mut [u8; PUBLIC_KEY_LEN],
            sk: &mut [u8; SECRET_KEY_LEN],
        ) -> bool {
            keygen_inner(xi, pk, sk);

            // Sign a fixed message and verify it. For a signature scheme that is the
            // whole meaning of "these two halves belong together", and it is the check
            // that catches a public key that does not correspond to the secret one --
            // a failure that would otherwise appear only at the far end, as signatures
            // that never verify.
            const PROBE: &[u8] = b"ic-mldsa/pairwise-consistency";
            let mut sig = [0u8; SIGNATURE_LEN];
            let ok = sign_deterministic(sk, PROBE, b"", &mut sig) && verify(pk, PROBE, b"", &sig);
            if !ok {
                pk.fill(0);
                sk.fill(0);
            }
            ok
        }

        /// Kept out of line so that its frame is gone before `keygen` signs its
        /// consistency probe, rather than sitting under the signing frame.
        #[inline(never)]
        fn keygen_inner(xi: &[u8; SEED_LEN], pk: &mut [u8; PUBLIC_KEY_LEN], sk: &mut [u8; SECRET_KEY_LEN]) {
            // The k and l bytes are part of the hash input: two parameter sets with the
            // same seed must not share an expansion.
            let mut expanded = [0u8; 128];
            h(&[xi, &[K as u8], &[L as u8]], &mut expanded);
            let mut rho = [0u8; 32];
            let mut rho_prime = [0u8; 64];
            let mut key = [0u8; 32];
            rho.copy_from_slice(&expanded[..32]);
            rho_prime.copy_from_slice(&expanded[32..96]);
            key.copy_from_slice(&expanded[96..]);
            expanded.zeroize();

            // pkEncode and skEncode are written as each piece is produced, so no
            // vector is held longer than the row that needs it. `tr` is the one
            // exception to the order: it hashes the finished public key.
            pk[..32].copy_from_slice(&rho);
            sk[..32].copy_from_slice(&rho);
            sk[32..64].copy_from_slice(&key);
            key.zeroize();

            // ExpandS, first half: s1, kept only in the transform domain, which is
            // the form every row of A*s1 needs.
            let mut s1_hat = [Poly::ZERO; L];
            for (i, (p, chunk)) in s1_hat
                .iter_mut()
                .zip(sk[SK_S1_AT..SK_S2_AT].chunks_mut(S_LEN))
                .enumerate()
            {
                *p = rej_bounded_poly(&rho_prime, i as u16, ETA);
                bit_pack(p, ETA, ETA_BITS, chunk);
                p.ntt();
            }

            // t = A*s1 + s2, a row at a time, each row split and encoded at once.
            // ExpandS's second half, s2, uses nonces l..l+k in this same order.
            for r in 0..K {
                let mut s2 = rej_bounded_poly(&rho_prime, (L + r) as u16, ETA);
                bit_pack(&s2, ETA, ETA_BITS, &mut sk[SK_S2_AT + r * S_LEN..][..S_LEN]);

                let mut t = a_row_times(&rho, r, &s1_hat).add(&s2);
                t.normalize();
                let (t1, mut t0) = power2round_poly(&t);
                simple_bit_pack(&t1, T1_BITS, &mut pk[32 + r * T1_LEN..][..T1_LEN]);
                bit_pack(&t0, 1 << (D - 1), T0_BITS, &mut sk[SK_T0_AT + r * T0_LEN..][..T0_LEN]);

                s2.zeroize();
                t.zeroize();
                t0.zeroize();
            }
            for p in s1_hat.iter_mut() {
                p.zeroize();
            }
            rho_prime.zeroize();

            let mut tr = [0u8; 64];
            h(&[&pk[..]], &mut tr);
            sk[64..128].copy_from_slice(&tr);
        }

        // # Why the secret vectors are not held either
        //
        // Holding `s1`, `s2` and `t0` decoded and transformed for the whole of
        // signing was 23 KiB for ML-DSA-87, more than half of what remained once
        // `A` went. They stay encoded in `sk`, and each row is decoded and
        // transformed where it is used, then wiped. `t0` is used only by an
        // attempt that has passed both bound checks, almost always the last one,
        // so it costs about `k` transforms per signature. `s1` and `s2` are used
        // by every attempt, and decoding them again each time is the cost of this:
        // about `l + k` decodes and transforms per attempt, against the `k * l`
        // samplings of `A` each attempt already makes.

        /// The byte-string parts of a decoded signing key.
        struct SigningKey {
            rho: [u8; 32],
            key: [u8; 32],
            tr: [u8; 64],
        }

        impl Drop for SigningKey {
            /// Wipe the secret seed and the key hash when the decoded key goes out
            /// of scope. `rho` is skipped deliberately: it is published in the
            /// verification key, and wiping public material alongside private
            /// material blurs which is which. The secret vectors are not here; each
            /// row is wiped where it is used.
            fn drop(&mut self) {
                self.key.zeroize();
                self.tr.zeroize();
            }
        }

        impl SigningKey {
            const EMPTY: SigningKey = SigningKey {
                rho: [0u8; 32],
                key: [0u8; 32],
                tr: [0u8; 64],
            };
        }

        /// `skDecode`'s byte strings, into storage the caller already holds.
        fn sk_decode_into(sk: &[u8; SECRET_KEY_LEN], out: &mut SigningKey) {
            out.rho.copy_from_slice(&sk[..32]);
            out.key.copy_from_slice(&sk[32..64]);
            out.tr.copy_from_slice(&sk[64..128]);
        }

        /// `NTT(s1[i])`, decoded from `sk` where it is used.
        fn s1_hat(sk: &[u8; SECRET_KEY_LEN], i: usize) -> Poly {
            let mut p = Poly::ZERO;
            bit_unpack(&sk[SK_S1_AT + i * S_LEN..][..S_LEN], ETA, ETA_BITS, &mut p);
            p.ntt();
            p
        }

        /// `NTT(s2[i])`, decoded from `sk` where it is used.
        fn s2_hat(sk: &[u8; SECRET_KEY_LEN], i: usize) -> Poly {
            let mut p = Poly::ZERO;
            bit_unpack(&sk[SK_S2_AT + i * S_LEN..][..S_LEN], ETA, ETA_BITS, &mut p);
            p.ntt();
            p
        }

        /// `NTT(t0[i])`, decoded from `sk` where it is used.
        fn t0_hat(sk: &[u8; SECRET_KEY_LEN], i: usize) -> Poly {
            let mut p = Poly::ZERO;
            bit_unpack(&sk[SK_T0_AT + i * T0_LEN..][..T0_LEN], 1 << (D - 1), T0_BITS, &mut p);
            p.ntt();
            p
        }

        /// `c * v` for a secret `v`, given transformed, which is wiped after use.
        fn scale_secret(c_hat: &Poly, mut v_hat: Poly) -> Poly {
            let product = scale(c_hat, &v_hat);
            v_hat.zeroize();
            product
        }

        /// The whole key decoded, as signing used to hold it: for the tests, and
        /// for the reference signer they compare against.
        #[cfg(test)]
        struct DecodedKey {
            rho: [u8; 32],
            key: [u8; 32],
            tr: [u8; 64],
            s1: [Poly; L],
            s2: [Poly; K],
            t0: [Poly; K],
        }

        #[cfg(test)]
        fn sk_decode(sk: &[u8; SECRET_KEY_LEN]) -> DecodedKey {
            let mut out = DecodedKey {
                rho: [0u8; 32],
                key: [0u8; 32],
                tr: [0u8; 64],
                s1: [Poly::ZERO; L],
                s2: [Poly::ZERO; K],
                t0: [Poly::ZERO; K],
            };
            out.rho.copy_from_slice(&sk[..32]);
            out.key.copy_from_slice(&sk[32..64]);
            out.tr.copy_from_slice(&sk[64..128]);
            for (p, chunk) in out.s1.iter_mut().zip(sk[SK_S1_AT..SK_S2_AT].chunks(S_LEN)) {
                bit_unpack(chunk, ETA, ETA_BITS, p);
            }
            for (p, chunk) in out.s2.iter_mut().zip(sk[SK_S2_AT..SK_T0_AT].chunks(S_LEN)) {
                bit_unpack(chunk, ETA, ETA_BITS, p);
            }
            for (p, chunk) in out.t0.iter_mut().zip(sk[SK_T0_AT..].chunks(T0_LEN)) {
                bit_unpack(chunk, 1 << (D - 1), T0_BITS, p);
            }
            out
        }

        /// Sign `message` under `sk`, with `rnd` supplying the hedging randomness.
        ///
        /// Pass zeros for the deterministic variant. Returns `false` only if the
        /// context is too long or the retry cap is reached; the latter means a bug or a
        /// malformed key rather than bad luck.
        #[must_use = "a false return means no signature was produced"]
        pub fn sign(
            sk: &[u8; SECRET_KEY_LEN],
            message: &[u8],
            ctx: &[u8],
            rnd: &[u8; 32],
            sig: &mut [u8; SIGNATURE_LEN],
        ) -> bool {
            sign_framed(sk, DOMAIN_PURE, &[message], ctx, rnd, sig)
        }

        /// Sign under HashML-DSA, which signs a digest rather than the message.
        ///
        /// # This is not interchangeable with [`sign`]
        ///
        /// The two variants differ in their domain separator byte, so a HashML-DSA
        /// signature never verifies as a pure one and the reverse is also false. That
        /// is deliberate, and it is why handing a digest to [`sign`] is not a
        /// substitute for this function: it produces something no conforming verifier
        /// accepts. The tests assert both directions of that separation.
        #[must_use = "a false return means no signature was produced"]
        pub fn sign_prehash(
            sk: &[u8; SECRET_KEY_LEN],
            message: &[u8],
            ctx: &[u8],
            ph: PreHash,
            rnd: &[u8; 32],
            sig: &mut [u8; SIGNATURE_LEN],
        ) -> bool {
            let (digest, len) = ph.digest(message);
            sign_framed(
                sk,
                DOMAIN_PREHASH,
                &[ph.oid_der(), &digest[..len]],
                ctx,
                rnd,
                sig,
            )
        }

        /// The signing core, shared by both variants.
        ///
        /// `parts` is what follows the context in `M'`: the message for the pure
        /// variant, the hash OID and digest for the pre-hash one. Threading it through
        /// rather than duplicating the loop means the two variants cannot drift in
        /// anything except the framing, which is the only thing that should differ.
        fn sign_framed(
            sk: &[u8; SECRET_KEY_LEN],
            domain: u8,
            parts: &[&[u8]],
            ctx: &[u8],
            rnd: &[u8; 32],
            sig: &mut [u8; SIGNATURE_LEN],
        ) -> bool {
            let (prefix, ok) = message_prefix(domain, ctx);
            if !ok {
                return false;
            }
            // The byte strings only; s1, s2 and t0 are decoded per use below.
            let mut k = SigningKey::EMPTY;
            sk_decode_into(sk, &mut k);

            let mut mu = [0u8; 64];
            let framed = Framed::new(&k.tr, &prefix, ctx, parts);
            h(framed.as_slice(), &mut mu);

            let mut rho_prime = [0u8; 64];
            h(&[&k.key, rnd, &mu], &mut rho_prime);

            let mut w1_packed = [0u8; K * W1_LEN];
            let mut c_tilde = [0u8; C_TILDE_LEN];
            // w, and from the rejection check on, w - c*s2 in its place.
            let mut w = [Poly::ZERO; K];
            let mut hints: [HintRow; K] = [[0u8; N / 8]; K];

            let mut kappa = 0u16;
            let mut signed = false;
            for _ in 0..MAX_ATTEMPTS {
                // w = A*y, a column at a time: each y[s] is drawn from ExpandMask,
                // transformed, and multiplied into every row before the next is
                // drawn, so neither y nor A is ever held whole. Every row's sum
                // still runs over s in order, exactly as a row-major product does.
                for acc in w.iter_mut() {
                    *acc = Poly::ZERO;
                }
                for s in 0..L {
                    let mut y_hat = expand_mask_poly(&rho_prime, kappa + s as u16, GAMMA1);
                    y_hat.ntt();
                    for (r, acc) in w.iter_mut().enumerate() {
                        acc.pointwise_acc(&a_entry(&k.rho, r, s), &y_hat);
                    }
                    y_hat.zeroize();
                }

                // w1 = HighBits(w), encoded as it is computed.
                for (acc, chunk) in w.iter_mut().zip(w1_packed.chunks_mut(W1_LEN)) {
                    acc.inv_ntt();
                    acc.normalize();
                    let (w1, _) = decompose_poly(acc, GAMMA2);
                    simple_bit_pack(&w1, w1_bits(GAMMA2), chunk);
                }

                h(&[&mu, &w1_packed], &mut c_tilde);
                let mut c = sample_in_ball(&c_tilde, TAU);
                c.ntt();

                // z = y + c*s1, checked here and discarded. A rejected z must
                // never leave this function, and a z that is too large does not
                // fit its encoding, so it is recomputed below once an attempt is
                // known to succeed rather than held or written out now. Its y is
                // regenerated from the same seed and index it was drawn from.
                let mut too_big = false;
                for i in 0..L {
                    let mut z = expand_mask_poly(&rho_prime, kappa + i as u16, GAMMA1);
                    let mut cs1 = scale_secret(&c, s1_hat(sk, i));
                    z.add_assign(&cs1);
                    z.reduce();
                    if z.exceeds(GAMMA1 - BETA) {
                        too_big = true;
                    }
                    z.zeroize();
                    cs1.zeroize();
                }

                // r0 = LowBits(w - c*s2)
                for (r, wi) in w.iter_mut().enumerate() {
                    let mut cs2 = scale_secret(&c, s2_hat(sk, r));
                    wi.sub_assign(&cs2);
                    cs2.zeroize();
                    let (_, r0) = decompose_poly(wi, GAMMA2);
                    if r0.exceeds(GAMMA2 - BETA) {
                        too_big = true;
                    }
                }
                if too_big {
                    kappa += L as u16;
                    continue;
                }

                // h = MakeHint(-c*t0, w - c*s2 + c*t0)
                let mut weight = 0usize;
                let mut ct0_too_big = false;
                for (r, (row, base)) in hints.iter_mut().zip(w.iter()).enumerate() {
                    let mut shift = scale_secret(&c, t0_hat(sk, r));
                    let mut probe = shift;
                    probe.reduce();
                    if probe.exceeds(GAMMA2) {
                        ct0_too_big = true;
                    }
                    // The hint answers "does subtracting c*t0 move the bucket", so the
                    // shift passed in is negated while the point it is measured at
                    // already includes it.
                    let mut negated = Poly::ZERO;
                    for (o, c) in negated.c.iter_mut().zip(shift.c.iter()) {
                        *o = -*c;
                    }
                    let mut target = *base;
                    target.add_assign(&shift);
                    let (bits, w) = make_hint_poly(&negated, &target, GAMMA2);
                    *row = hint_row(&bits);
                    weight += w;
                    shift.zeroize();
                    probe.zeroize();
                    negated.zeroize();
                    target.zeroize();
                }
                if ct0_too_big || weight > OMEGA {
                    kappa += L as u16;
                    continue;
                }

                // sigEncode, with z recomputed exactly as it was checked.
                sig[..C_TILDE_LEN].copy_from_slice(&c_tilde);
                let mut at = C_TILDE_LEN;
                for i in 0..L {
                    let mut z = expand_mask_poly(&rho_prime, kappa + i as u16, GAMMA1);
                    let mut cs1 = scale_secret(&c, s1_hat(sk, i));
                    z.add_assign(&cs1);
                    z.reduce();
                    z.reduce();
                    bit_pack(&z, GAMMA1, z_bits(GAMMA1), &mut sig[at..at + Z_LEN]);
                    at += Z_LEN;
                    z.zeroize();
                    cs1.zeroize();
                }
                kappa += L as u16;
                if !hint_pack_bits(&hints, OMEGA, &mut sig[at..at + OMEGA + K]) {
                    continue;
                }
                signed = true;
                break;
            }
            for p in w.iter_mut() {
                p.zeroize();
            }
            rho_prime.zeroize();
            signed
        }

        /// The signer b0dbcb4 left, holding the whole key decoded: the reference
        /// [`sign_framed`] is compared against. Unchanged apart from its names.
        #[cfg(test)]
        fn sign_framed_held(
            sk: &[u8; SECRET_KEY_LEN],
            domain: u8,
            parts: &[&[u8]],
            ctx: &[u8],
            rnd: &[u8; 32],
            sig: &mut [u8; SIGNATURE_LEN],
        ) -> bool {
            let (prefix, ok) = message_prefix(domain, ctx);
            if !ok {
                return false;
            }
            let mut k = sk_decode(sk);
            let mut mu = [0u8; 64];
            let framed = Framed::new(&k.tr, &prefix, ctx, parts);
            h(framed.as_slice(), &mut mu);
            let mut rho_prime = [0u8; 64];
            h(&[&k.key, rnd, &mu], &mut rho_prime);
            for p in k.s1.iter_mut().chain(k.s2.iter_mut()).chain(k.t0.iter_mut()) {
                p.ntt();
            }
            let (s1_hat, s2_hat, t0_hat) = (&k.s1, &k.s2, &k.t0);
            let mut w1_packed = [0u8; K * W1_LEN];
            let mut c_tilde = [0u8; C_TILDE_LEN];
            let mut w = [Poly::ZERO; K];
            let mut hints = [[false; N]; K];
            let mut kappa = 0u16;
            for _ in 0..MAX_ATTEMPTS {
                for acc in w.iter_mut() {
                    *acc = Poly::ZERO;
                }
                for s in 0..L {
                    let mut y_hat = expand_mask_poly(&rho_prime, kappa + s as u16, GAMMA1);
                    y_hat.ntt();
                    for (r, acc) in w.iter_mut().enumerate() {
                        *acc = acc.add(&a_entry(&k.rho, r, s).pointwise(&y_hat));
                    }
                }
                for (acc, chunk) in w.iter_mut().zip(w1_packed.chunks_mut(W1_LEN)) {
                    acc.inv_ntt();
                    acc.normalize();
                    let (w1, _) = decompose_poly(acc, GAMMA2);
                    simple_bit_pack(&w1, w1_bits(GAMMA2), chunk);
                }
                h(&[&mu, &w1_packed], &mut c_tilde);
                let mut c = sample_in_ball(&c_tilde, TAU);
                c.ntt();
                let mut too_big = false;
                for (i, s1) in s1_hat.iter().enumerate() {
                    let y = expand_mask_poly(&rho_prime, kappa + i as u16, GAMMA1);
                    let mut z = y.add(&scale(&c, s1));
                    z.reduce();
                    if z.exceeds(GAMMA1 - BETA) {
                        too_big = true;
                    }
                }
                for (wi, s2) in w.iter_mut().zip(s2_hat.iter()) {
                    *wi = wi.sub(&scale(&c, s2));
                    let (_, r0) = decompose_poly(wi, GAMMA2);
                    if r0.exceeds(GAMMA2 - BETA) {
                        too_big = true;
                    }
                }
                if too_big {
                    kappa += L as u16;
                    continue;
                }
                let mut weight = 0usize;
                let mut ct0_too_big = false;
                for ((slot, base), t0) in hints.iter_mut().zip(w.iter()).zip(t0_hat.iter()) {
                    let shift = scale(&c, t0);
                    let mut probe = shift;
                    probe.reduce();
                    if probe.exceeds(GAMMA2) {
                        ct0_too_big = true;
                    }
                    let mut negated = Poly::ZERO;
                    for (o, c) in negated.c.iter_mut().zip(shift.c.iter()) {
                        *o = -*c;
                    }
                    let target = base.add(&shift);
                    let (bits, w) = make_hint_poly(&negated, &target, GAMMA2);
                    *slot = bits;
                    weight += w;
                }
                if ct0_too_big || weight > OMEGA {
                    kappa += L as u16;
                    continue;
                }
                sig[..C_TILDE_LEN].copy_from_slice(&c_tilde);
                let mut at = C_TILDE_LEN;
                for (i, s1) in s1_hat.iter().enumerate() {
                    let y = expand_mask_poly(&rho_prime, kappa + i as u16, GAMMA1);
                    let mut z = y.add(&scale(&c, s1));
                    z.reduce();
                    z.reduce();
                    bit_pack(&z, GAMMA1, z_bits(GAMMA1), &mut sig[at..at + Z_LEN]);
                    at += Z_LEN;
                }
                kappa += L as u16;
                if !hint_pack(&hints, OMEGA, &mut sig[at..at + OMEGA + K]) {
                    continue;
                }
                return true;
            }
            false
        }

        /// Verify `sig` over `message` under `pk`.
        #[must_use = "this is the result of a cryptographic verification; discarding it accepts everything"]
        pub fn verify(
            pk: &[u8; PUBLIC_KEY_LEN],
            message: &[u8],
            ctx: &[u8],
            sig: &[u8; SIGNATURE_LEN],
        ) -> bool {
            verify_framed(pk, DOMAIN_PURE, &[message], ctx, sig)
        }

        /// Verify a HashML-DSA signature.
        ///
        /// The pre-hash function is an input rather than something recovered from the
        /// signature, because the signature does not carry it. A verifier must already
        /// know which hash the signer used; the OID inside `M'` then binds the
        /// signature to that choice, so presenting the wrong one fails rather than
        /// silently accepting.
        #[must_use = "this is the result of a cryptographic verification; discarding it accepts everything"]
        pub fn verify_prehash(
            pk: &[u8; PUBLIC_KEY_LEN],
            message: &[u8],
            ctx: &[u8],
            ph: PreHash,
            sig: &[u8; SIGNATURE_LEN],
        ) -> bool {
            let (digest, len) = ph.digest(message);
            verify_framed(
                pk,
                DOMAIN_PREHASH,
                &[ph.oid_der(), &digest[..len]],
                ctx,
                sig,
            )
        }

        /// The verification core, shared by both variants.
        fn verify_framed(
            pk: &[u8; PUBLIC_KEY_LEN],
            domain: u8,
            parts: &[&[u8]],
            ctx: &[u8],
            sig: &[u8; SIGNATURE_LEN],
        ) -> bool {
            let (prefix, ok) = message_prefix(domain, ctx);
            if !ok {
                return false;
            }

            let mut rho = [0u8; 32];
            rho.copy_from_slice(&pk[..32]);

            // sigDecode, with every rejection the encoding allows.
            let mut c_tilde = [0u8; C_TILDE_LEN];
            c_tilde.copy_from_slice(&sig[..C_TILDE_LEN]);
            let mut at = C_TILDE_LEN;
            let mut z = [Poly::ZERO; L];
            for p in z.iter_mut() {
                bit_unpack(&sig[at..at + Z_LEN], GAMMA1, z_bits(GAMMA1), p);
                at += Z_LEN;
            }
            let mut hints: [HintRow; K] = [[0u8; N / 8]; K];
            if !hint_unpack_bits(&sig[at..at + OMEGA + K], OMEGA, &mut hints) {
                return false;
            }

            // ||z||inf < gamma1 - beta. Checked before any expensive work, and before
            // the hash comparison, because it is cheap and rejects malformed input.
            for p in z.iter_mut() {
                p.reduce();
                if p.exceeds(GAMMA1 - BETA) {
                    return false;
                }
            }

            let mut tr = [0u8; 64];
            h(&[&pk[..]], &mut tr);
            let mut mu = [0u8; 64];
            let framed = Framed::new(&tr, &prefix, ctx, parts);
            h(framed.as_slice(), &mut mu);

            let mut c = sample_in_ball(&c_tilde, TAU);
            c.ntt();

            // w' = A*z - c*t1*2^d, then w1 = UseHint(h, w'), a row at a time:
            // row r needs only row r of A, t1[r] and h[r], so each is decoded,
            // used and encoded before the next.
            for p in z.iter_mut() {
                p.ntt();
            }
            let mut w1_packed = [0u8; K * W1_LEN];
            for (r, (hint, chunk)) in hints.iter().zip(w1_packed.chunks_mut(W1_LEN)).enumerate() {
                let mut t1 = Poly::ZERO;
                simple_bit_unpack(&pk[32 + r * T1_LEN..][..T1_LEN], T1_BITS, &mut t1);
                for coeff in t1.c.iter_mut() {
                    *coeff <<= D;
                }
                t1.ntt();
                let mut w_approx = a_row_times(&rho, r, &z);
                w_approx.sub_assign(&scale(&c, &t1));
                w_approx.normalize();
                let w1 = use_hint_poly(&hint_bools(hint), &w_approx, GAMMA2);
                simple_bit_pack(&w1, w1_bits(GAMMA2), chunk);
            }

            let mut expected = [0u8; C_TILDE_LEN];
            h(&[&mu, &w1_packed], &mut expected);

            // The comparison is over a public digest, but constant time costs nothing
            // here and removes the question.
            let mut diff = 0u8;
            for (a, b) in expected.iter().zip(c_tilde.iter()) {
                diff |= a ^ b;
            }
            diff == 0
        }

        /// The verifier b0dbcb4 left: the reference [`verify_framed`] is
        /// compared against. Unchanged apart from its name.
        #[cfg(test)]
        fn verify_framed_held(
            pk: &[u8; PUBLIC_KEY_LEN],
            domain: u8,
            parts: &[&[u8]],
            ctx: &[u8],
            sig: &[u8; SIGNATURE_LEN],
        ) -> bool {
            let (prefix, ok) = message_prefix(domain, ctx);
            if !ok {
                return false;
            }
            let mut rho = [0u8; 32];
            rho.copy_from_slice(&pk[..32]);
            let mut c_tilde = [0u8; C_TILDE_LEN];
            c_tilde.copy_from_slice(&sig[..C_TILDE_LEN]);
            let mut at = C_TILDE_LEN;
            let mut z = [Poly::ZERO; L];
            for p in z.iter_mut() {
                bit_unpack(&sig[at..at + Z_LEN], GAMMA1, z_bits(GAMMA1), p);
                at += Z_LEN;
            }
            let mut hints = [[false; N]; K];
            if !hint_unpack(&sig[at..at + OMEGA + K], OMEGA, &mut hints) {
                return false;
            }
            for p in z.iter_mut() {
                p.reduce();
                if p.exceeds(GAMMA1 - BETA) {
                    return false;
                }
            }
            let mut tr = [0u8; 64];
            h(&[&pk[..]], &mut tr);
            let mut mu = [0u8; 64];
            let framed = Framed::new(&tr, &prefix, ctx, parts);
            h(framed.as_slice(), &mut mu);
            let mut c = sample_in_ball(&c_tilde, TAU);
            c.ntt();
            for p in z.iter_mut() {
                p.ntt();
            }
            let mut w1_packed = [0u8; K * W1_LEN];
            for (r, (hint, chunk)) in hints.iter().zip(w1_packed.chunks_mut(W1_LEN)).enumerate() {
                let mut t1 = Poly::ZERO;
                simple_bit_unpack(&pk[32 + r * T1_LEN..][..T1_LEN], T1_BITS, &mut t1);
                for coeff in t1.c.iter_mut() {
                    *coeff <<= D;
                }
                t1.ntt();
                let mut acc = Poly::ZERO;
                for (s, v) in z.iter().enumerate() {
                    acc = acc.add(&a_entry(&rho, r, s).pointwise(v));
                }
                acc.inv_ntt();
                let mut w_approx = acc.sub(&scale(&c, &t1));
                w_approx.normalize();
                let w1 = use_hint_poly(hint, &w_approx, GAMMA2);
                simple_bit_pack(&w1, w1_bits(GAMMA2), chunk);
            }
            let mut expected = [0u8; C_TILDE_LEN];
            h(&[&mu, &w1_packed], &mut expected);
            let mut diff = 0u8;
            for (a, b) in expected.iter().zip(c_tilde.iter()) {
                diff |= a ^ b;
            }
            diff == 0
        }

        /// Deterministic signing: the hedged path with zero randomness.
        #[must_use = "a false return means no signature was produced"]
        pub fn sign_deterministic(
            sk: &[u8; SECRET_KEY_LEN],
            message: &[u8],
            ctx: &[u8],
            sig: &mut [u8; SIGNATURE_LEN],
        ) -> bool {
            sign(sk, message, ctx, &[0u8; 32], sig)
        }
    };
}
pub(crate) use ml_dsa;
