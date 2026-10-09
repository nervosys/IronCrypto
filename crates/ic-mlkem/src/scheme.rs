//! The ML-KEM scheme, once, for every parameter set.
//!
//! FIPS 203 defines three parameter sets that differ only in five numbers:
//! the module rank `k`, the two noise widths `eta1` and `eta2`, and the two
//! ciphertext compression widths `du` and `dv`. The algorithm is otherwise
//! identical. So it is written here once, as a macro over those five, and
//! each parameter set is one invocation: [`crate::kem`] for ML-KEM-768,
//! [`crate::kem512`] and [`crate::kem1024`] for the others.
//!
//! A macro rather than generics because each set wants fixed-size key and
//! ciphertext arrays, and a `[u8; 384 * K + 32]` whose `K` is a generic
//! parameter is not expressible on stable Rust. The alternative -- arrays
//! sized for the largest set and sliced -- would give every key type the
//! wrong length in its signature.
//!
//! ML-KEM-768 was written first and on its own; this is that code with the
//! five constants lifted out, not a rewrite. Each set is checked against its
//! own NIST ACVP vectors.

use ic_core::traits::{Digest, Xof};
use ic_hash::{Sha3_256, Sha3_512, Shake256};

/// `G(x) = SHA3-512(x)`, split into two 32-byte halves.
pub(crate) fn g(parts: &[&[u8]]) -> ([u8; 32], [u8; 32]) {
    let mut h = Sha3_512::new();
    for part in parts {
        h.update(part);
    }
    let out = h.finalize();
    let bytes = out.as_ref();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&bytes[..32]);
    b.copy_from_slice(&bytes[32..]);
    (a, b)
}

/// `H(x) = SHA3-256(x)`.
pub(crate) fn h(data: &[u8]) -> [u8; 32] {
    let out = Sha3_256::digest(data);
    let mut a = [0u8; 32];
    a.copy_from_slice(out.as_ref());
    a
}

/// `J(x) = SHAKE256(x, 32)`, the implicit-rejection key derivation.
pub(crate) fn j(parts: &[&[u8]]) -> [u8; 32] {
    let mut x = Shake256::default();
    for part in parts {
        <Shake256 as Xof>::update(&mut x, part);
    }
    let mut out = [0u8; 32];
    x.finalize_xof(&mut out);
    out
}

/// Instantiate ML-KEM for one parameter set, in the module that invokes it.
macro_rules! ml_kem {
    ($name:ident, $display:literal, $k:literal, $eta1:literal, $eta2:literal, $du:literal, $dv:literal) => {
        use ic_core::traits::RandomSource;
        use ic_core::{ensure, Result, Zeroize};
        use $crate::encode::{
            byte_decode, byte_encode, compress_encode, decode_decompress, encoded_len,
        };
        use $crate::poly::Poly;
        use $crate::sample::{sample_noise, sample_ntt};

        /// Module rank `k`.
        pub const K: usize = $k;
        /// Noise width for the secret and the first error term.
        const ETA1: usize = $eta1;
        /// Noise width for the second error term.
        const ETA2: usize = $eta2;
        /// Compression width for the ciphertext's vector part.
        const DU: u32 = $du;
        /// Compression width for the ciphertext's scalar part.
        const DV: u32 = $dv;

        /// Encapsulation key size: `384 * k + 32`.
        pub const ENCAPS_KEY_LEN: usize = 384 * K + 32;
        /// Decapsulation key size: `768 * k + 96`.
        pub const DECAPS_KEY_LEN: usize = 768 * K + 96;
        /// Ciphertext size: `32 * (du * k + dv)`.
        pub const CIPHERTEXT_LEN: usize = 32 * (DU as usize * K + DV as usize);
        /// Shared secret size.
        pub const SHARED_SECRET_LEN: usize = 32;

        /// A vector of `K` ring elements.
        type Vector = [Poly; K];

        fn zero_vector() -> Vector {
            [Poly::ZERO; K]
        }

        // # Why the matrix is never held
        //
        // `A` is `k * k` polynomials of 512 bytes each, 8 KiB for ML-KEM-1024,
        // and with the vectors beside it a decapsulation peaked at 27 KiB of
        // stack. Each entry is a pure function of the public `rho` and its two
        // indices, so it is sampled where it is used and dropped, and vectors
        // are carried a row or an element at a time where the algorithm allows.
        // Every K-PKE operation uses each entry of `A` exactly once, so unlike
        // ML-DSA's signing loop nothing is sampled twice and there is nothing to
        // trade. The held-matrix form is kept, under `cfg(test)`, as the
        // reference the streaming one is compared against.

        /// `A[i][j]`, or `A^T[i][j]` when `transposed`, sampled on demand.
        ///
        /// The index order is the classic place to go wrong: FIPS 203 defines
        /// `A[i][j] = SampleNTT(rho || j || i)`, with `j` *before* `i` in the seed. A
        /// build that swaps them produces a matrix that is the transpose of the
        /// intended one, key generation and encryption still agree with each other, and
        /// nothing else in the world can decrypt the result.
        fn matrix_entry(rho: &[u8; 32], i: usize, j: usize, transposed: bool) -> Poly {
            let (x, y) = if transposed { (j, i) } else { (i, j) };
            sample_ntt(rho, y as u8, x as u8)
        }

        /// Row `i` of `A o v`, or of `A^T o v`, in the transform domain.
        fn matrix_row(rho: &[u8; 32], i: usize, transposed: bool, v: &Vector) -> Poly {
            let mut acc = Poly::ZERO;
            for (jj, vj) in v.iter().enumerate() {
                acc.basemul_add(&matrix_entry(rho, i, jj, transposed), vj);
            }
            acc.reduce();
            acc
        }

        /// `ByteEncode12` of one element, normalized first.
        fn encode_poly(p: &Poly, out: &mut [u8]) {
            let mut normalized = *p;
            normalized.normalize();
            byte_encode(&normalized, 12, out);
        }

        /// K-PKE key generation from a 32-byte seed.
        ///
        /// `s` is the only vector held, in the transform domain, because every
        /// row of `A o s` needs all of it. Each row of `t` is computed, has its
        /// error term added and is encoded before the next.
        fn pke_keygen(d: &[u8; 32], ek: &mut [u8], dk: &mut [u8]) {
            // FIPS 203 appends the module rank so that the three parameter sets cannot
            // produce the same expansion from the same seed.
            let (rho, mut sigma) = $crate::scheme::g(&[d, &[K as u8]]);

            // s takes nonces 0..k and e takes k..2k, as in FIPS 203.
            let mut s = zero_vector();
            for (i, p) in s.iter_mut().enumerate() {
                *p = sample_noise(ETA1, &sigma, i as u8);
                p.ntt();
            }

            // t = A o s + e, with the Montgomery factor from basemul put back.
            for i in 0..K {
                let mut e = sample_noise(ETA1, &sigma, (K + i) as u8);
                e.ntt();
                let mut t = matrix_row(&rho, i, false, &s);
                t.to_mont();
                t.add_assign(&e);
                t.reduce();
                encode_poly(&t, &mut ek[i * 384..(i + 1) * 384]);
                e.zeroize();
            }
            ek[384 * K..].copy_from_slice(&rho);

            for (i, p) in s.iter_mut().enumerate() {
                encode_poly(p, &mut dk[i * 384..(i + 1) * 384]);
                p.zeroize();
            }
            sigma.zeroize();
        }

        /// K-PKE encryption. `m` is 32 bytes, `r` is the 32-byte coin.
        ///
        /// `y` is the only vector held. Each row of `u` is computed from `A^T`
        /// and encoded before the next, and `t` is decoded an element at a time
        /// as the inner product consumes it.
        fn pke_encrypt(ek: &[u8], m: &[u8; 32], r: &[u8; 32], out: &mut [u8]) {
            let mut rho = [0u8; 32];
            rho.copy_from_slice(&ek[384 * K..]);
            let du_len = encoded_len(DU);

            // y takes nonces 0..k, e1 takes k..2k and e2 takes 2k.
            let mut y = zero_vector();
            for (i, p) in y.iter_mut().enumerate() {
                *p = sample_noise(ETA1, r, i as u8);
                p.ntt();
            }

            // u = InvNTT(A^T o y) + e1
            for i in 0..K {
                let mut u = matrix_row(&rho, i, true, &y);
                u.inv_ntt();
                u.add_assign(&sample_noise(ETA2, r, (K + i) as u8));
                u.reduce();
                u.normalize();
                compress_encode(&u, DU, &mut out[i * du_len..(i + 1) * du_len]);
            }

            // v = InvNTT(t^T o y) + e2 + Decompress_1(m)
            let mut v = Poly::ZERO;
            for (i, yi) in y.iter().enumerate() {
                let mut t = Poly::ZERO;
                byte_decode(&ek[i * 384..(i + 1) * 384], 12, &mut t);
                v.basemul_add(&t, yi);
            }
            v.reduce();
            v.inv_ntt();
            v.add_assign(&sample_noise(ETA2, r, (2 * K) as u8));
            let mut mu = Poly::ZERO;
            decode_decompress(m, 1, &mut mu);
            v.add_assign(&mu);
            v.reduce();
            v.normalize();
            compress_encode(&v, DV, &mut out[K * du_len..]);

            for p in y.iter_mut() {
                p.zeroize();
            }
            mu.zeroize();
        }

        /// K-PKE decryption, recovering the 32-byte message.
        ///
        /// `s^T o NTT(u)` is accumulated an element at a time: each `u[i]` is
        /// decompressed and transformed, and each `s[i]` decoded, only when the
        /// sum reaches it.
        fn pke_decrypt(dk: &[u8], ct: &[u8]) -> [u8; 32] {
            let du_len = encoded_len(DU);
            let mut w = Poly::ZERO;
            for i in 0..K {
                let mut u = Poly::ZERO;
                decode_decompress(&ct[i * du_len..(i + 1) * du_len], DU, &mut u);
                u.ntt();
                let mut s = Poly::ZERO;
                byte_decode(&dk[i * 384..(i + 1) * 384], 12, &mut s);
                w.basemul_add(&s, &u);
                s.zeroize();
            }
            w.reduce();
            w.inv_ntt();

            let mut v = Poly::ZERO;
            decode_decompress(&ct[K * du_len..], DV, &mut v);
            let mut result = v.sub(&w);
            result.reduce();
            result.normalize();

            let mut out = [0u8; 32];
            compress_encode(&result, 1, &mut out);
            w.zeroize();
            result.zeroize();
            out
        }

        /// The held-matrix K-PKE these functions replaced, kept as the reference
        /// the streaming form is tested against. Unchanged apart from its names.
        #[cfg(test)]
        mod held {
            use super::*;

            #[allow(clippy::needless_range_loop)]
            fn expand_matrix(rho: &[u8; 32], transposed: bool) -> [[Poly; K]; K] {
                let mut a = [[Poly::ZERO; K]; K];
                for i in 0..K {
                    for jj in 0..K {
                        let (x, y) = if transposed { (jj, i) } else { (i, jj) };
                        a[i][jj] = sample_ntt(rho, y as u8, x as u8);
                    }
                }
                a
            }

            #[allow(clippy::needless_range_loop)]
            fn matrix_mul(a: &[[Poly; K]; K], v: &Vector) -> Vector {
                let mut out = zero_vector();
                for i in 0..K {
                    let mut acc = Poly::ZERO;
                    for jj in 0..K {
                        acc = acc.add(&a[i][jj].basemul(&v[jj]));
                    }
                    acc.reduce();
                    out[i] = acc;
                }
                out
            }

            fn dot(a: &Vector, b: &Vector) -> Poly {
                let mut acc = Poly::ZERO;
                for i in 0..K {
                    acc = acc.add(&a[i].basemul(&b[i]));
                }
                acc.reduce();
                acc
            }

            fn encode_vector(v: &Vector, out: &mut [u8]) {
                for (i, p) in v.iter().enumerate() {
                    encode_poly(p, &mut out[i * 384..(i + 1) * 384]);
                }
            }

            fn decode_vector(data: &[u8]) -> Vector {
                let mut v = zero_vector();
                for (i, p) in v.iter_mut().enumerate() {
                    byte_decode(&data[i * 384..(i + 1) * 384], 12, p);
                }
                v
            }

            pub(super) fn pke_keygen(d: &[u8; 32], ek: &mut [u8], dk: &mut [u8]) {
                let (rho, sigma) = $crate::scheme::g(&[d, &[K as u8]]);
                let a = expand_matrix(&rho, false);
                let mut s = zero_vector();
                let mut e = zero_vector();
                let mut nonce = 0u8;
                for p in s.iter_mut() {
                    *p = sample_noise(ETA1, &sigma, nonce);
                    nonce += 1;
                }
                for p in e.iter_mut() {
                    *p = sample_noise(ETA1, &sigma, nonce);
                    nonce += 1;
                }
                for p in s.iter_mut() {
                    p.ntt();
                }
                for p in e.iter_mut() {
                    p.ntt();
                }
                let mut t = matrix_mul(&a, &s);
                for (ti, ei) in t.iter_mut().zip(e.iter()) {
                    ti.to_mont();
                    *ti = ti.add(ei);
                    ti.reduce();
                }
                encode_vector(&t, &mut ek[..384 * K]);
                ek[384 * K..].copy_from_slice(&rho);
                encode_vector(&s, dk);
            }

            pub(super) fn pke_encrypt(ek: &[u8], m: &[u8; 32], r: &[u8; 32], out: &mut [u8]) {
                let t = decode_vector(&ek[..384 * K]);
                let mut rho = [0u8; 32];
                rho.copy_from_slice(&ek[384 * K..]);
                let at = expand_matrix(&rho, true);
                let mut y = zero_vector();
                let mut e1 = zero_vector();
                let mut nonce = 0u8;
                for p in y.iter_mut() {
                    *p = sample_noise(ETA1, r, nonce);
                    nonce += 1;
                }
                for p in e1.iter_mut() {
                    *p = sample_noise(ETA2, r, nonce);
                    nonce += 1;
                }
                let e2 = sample_noise(ETA2, r, nonce);
                for p in y.iter_mut() {
                    p.ntt();
                }
                let mut u = matrix_mul(&at, &y);
                for (ui, ei) in u.iter_mut().zip(e1.iter()) {
                    ui.inv_ntt();
                    *ui = ui.add(ei);
                    ui.reduce();
                }
                let mut v = dot(&t, &y);
                v.inv_ntt();
                v = v.add(&e2);
                let mut mu = Poly::ZERO;
                decode_decompress(m, 1, &mut mu);
                v = v.add(&mu);
                v.reduce();
                for (i, ui) in u.iter().enumerate() {
                    let mut n = *ui;
                    n.normalize();
                    compress_encode(
                        &n,
                        DU,
                        &mut out[i * encoded_len(DU)..(i + 1) * encoded_len(DU)],
                    );
                }
                let mut vn = v;
                vn.normalize();
                compress_encode(&vn, DV, &mut out[K * encoded_len(DU)..]);
            }

            pub(super) fn pke_decrypt(dk: &[u8], ct: &[u8]) -> [u8; 32] {
                let mut u = zero_vector();
                for (i, p) in u.iter_mut().enumerate() {
                    decode_decompress(&ct[i * encoded_len(DU)..(i + 1) * encoded_len(DU)], DU, p);
                }
                let mut v = Poly::ZERO;
                decode_decompress(&ct[K * encoded_len(DU)..], DV, &mut v);
                let s = decode_vector(dk);
                for p in u.iter_mut() {
                    p.ntt();
                }
                let mut w = dot(&s, &u);
                w.inv_ntt();
                let mut result = v.sub(&w);
                result.reduce();
                result.normalize();
                let mut out = [0u8; 32];
                compress_encode(&result, 1, &mut out);
                out
            }

            /// Bytes from a seed and a counter, for inputs no vector covers.
            fn bytes<const N: usize>(seed: u8) -> [u8; N] {
                let mut x = seed.wrapping_mul(151).wrapping_add(17);
                core::array::from_fn(|_| {
                    x = x.wrapping_mul(29).wrapping_add(11);
                    x
                })
            }

            /// Key generation, encryption and decryption agree with the held form.
            ///
            /// The ACVP vectors already pin the scheme's output; this says which
            /// K-PKE operation broke when one does, and runs every parameter set
            /// over inputs no vector file chose, including ciphertexts that are
            /// not encryptions of anything -- the input decapsulation's
            /// re-encryption check exists for.
            #[test]
            fn streaming_matches_the_held_matrix_form() {
                let mut checked = 0;
                for seed in 0..12u8 {
                    let d: [u8; 32] = bytes(seed);
                    let mut ek = [0u8; ENCAPS_KEY_LEN];
                    let mut dk = [0u8; 384 * K];
                    let mut ek_held = [0u8; ENCAPS_KEY_LEN];
                    let mut dk_held = [0u8; 384 * K];
                    super::pke_keygen(&d, &mut ek, &mut dk);
                    pke_keygen(&d, &mut ek_held, &mut dk_held);
                    assert_eq!(ek, ek_held, "encapsulation key, seed {seed}");
                    assert_eq!(dk, dk_held, "decryption key, seed {seed}");

                    let m: [u8; 32] = bytes(seed.wrapping_add(100));
                    let r: [u8; 32] = bytes(seed.wrapping_add(200));
                    let mut ct = [0u8; CIPHERTEXT_LEN];
                    let mut ct_held = [0u8; CIPHERTEXT_LEN];
                    super::pke_encrypt(&ek, &m, &r, &mut ct);
                    pke_encrypt(&ek, &m, &r, &mut ct_held);
                    assert_eq!(ct, ct_held, "ciphertext, seed {seed}");

                    assert_eq!(super::pke_decrypt(&dk, &ct), m, "round trip, seed {seed}");
                    let garbage: [u8; CIPHERTEXT_LEN] = bytes(seed.wrapping_add(50));
                    assert_eq!(
                        super::pke_decrypt(&dk, &garbage),
                        pke_decrypt(&dk, &garbage),
                        "decryption of an arbitrary ciphertext, seed {seed}"
                    );
                    checked += 1;
                }
                assert_eq!(checked, 12, "the comparison did not run");
            }

            /// Decapsulation returns `K` for a ciphertext that re-encrypts to
            /// itself and `J(z || c)` for every other one, as FIPS 203 algorithm 18
            /// specifies -- checked against the rule, not only as "different".
            ///
            /// Decapsulation's re-encryption runs through the streaming
            /// encryption, and its implicit rejection is the part no vector here
            /// pins: a tampered ciphertext must select exactly the rejection key.
            #[test]
            fn decapsulation_selects_k_or_the_rejection_key() {
                let mut ek = [0u8; ENCAPS_KEY_LEN];
                let mut dk = [0u8; DECAPS_KEY_LEN];
                $name::keygen_deterministic(&bytes(1), &bytes(2), &mut ek, &mut dk);
                let mut ct = [0u8; CIPHERTEXT_LEN];
                let mut sent = [0u8; SHARED_SECRET_LEN];
                $name::encapsulate_deterministic(&bytes(3), &ek, &mut ct, &mut sent);

                let mut received = [0u8; SHARED_SECRET_LEN];
                $name::decapsulate(&dk, &ct, &mut received).unwrap();
                assert_eq!(received, sent, "a valid ciphertext yields K");

                let z = &dk[DECAPS_KEY_LEN - 32..];
                for index in [0usize, CIPHERTEXT_LEN / 2, CIPHERTEXT_LEN - 1] {
                    let mut bad = ct;
                    bad[index] ^= 0x10;
                    let mut secret = [0u8; SHARED_SECRET_LEN];
                    $name::decapsulate(&dk, &bad, &mut secret).unwrap();
                    assert_eq!(
                        secret,
                        $crate::scheme::j(&[z, &bad]),
                        "byte {index}: a rejected ciphertext yields J(z || c)"
                    );
                }
            }
        }

        #[doc = $display]
        pub struct $name;

        impl $name {
            /// Generate a key pair.
            pub fn keygen<R: RandomSource + ?Sized>(
                rng: &mut R,
                ek: &mut [u8; ENCAPS_KEY_LEN],
                dk: &mut [u8; DECAPS_KEY_LEN],
            ) -> Result<()> {
                ic_core::module::operational()?;
                let mut d = [0u8; 32];
                let mut z = [0u8; 32];
                rng.fill(&mut d)?;
                rng.fill(&mut z)?;
                Self::keygen_deterministic(&d, &z, ek, dk);
                d.zeroize();
                z.zeroize();
                // FIPS 140-3 requires a pairwise consistency test on a generated key
                // pair. It runs here, inside generation, rather than being a function a
                // caller has to know to call.
                // A failure means this module disagrees with itself, so it ends the
                // module and not only this call.
                ic_core::module::conditional_self_test(Self::pairwise_consistency(ek, dk))
            }

            /// The pairwise consistency test for a generated key pair.
            ///
            /// Encapsulates to the public half and decapsulates with the private half,
            /// requiring the same shared secret. For a KEM that is the whole meaning of
            /// "these two belong together".
            ///
            /// The subtlety is that decapsulation *never fails*: a mismatched key pair
            /// yields the implicit-rejection secret rather than an error. So the test
            /// cannot check for an error, it must compare the secrets — which is
            /// exactly the check that distinguishes a working pair from one that will
            /// silently disagree with every peer it ever talks to.
            ///
            /// The message is derived from the public key rather than drawn from the
            /// RNG. That keeps the test deterministic, costs no entropy, and means a
            /// failure reproduces.
            fn pairwise_consistency(
                ek: &[u8; ENCAPS_KEY_LEN],
                dk: &[u8; DECAPS_KEY_LEN],
            ) -> Result<()> {
                let m = $crate::scheme::h(ek);
                let mut ct = [0u8; CIPHERTEXT_LEN];
                let mut sent = [0u8; SHARED_SECRET_LEN];
                Self::encapsulate_deterministic(&m, ek, &mut ct, &mut sent);

                let mut received = [0u8; SHARED_SECRET_LEN];
                Self::decapsulate(dk, &ct, &mut received)?;

                let matched = ic_core::ct::verify(&sent, &received);
                sent.zeroize();
                received.zeroize();
                ensure!(
                    matched,
                    SelfTestFailed,
                    "ml-kem key pair failed its pairwise consistency test; the key is withheld"
                );
                Ok(())
            }

            /// Generate a key pair from explicit seeds.
            ///
            /// Exposed because it is the only way to test the scheme reproducibly, and
            /// because ACVP vectors are specified this way. Production callers should
            /// use [`Self::keygen`].
            pub fn keygen_deterministic(
                d: &[u8; 32],
                z: &[u8; 32],
                ek: &mut [u8; ENCAPS_KEY_LEN],
                dk: &mut [u8; DECAPS_KEY_LEN],
            ) {
                pke_keygen(d, ek, &mut dk[..384 * K]);
                dk[384 * K..384 * K + ENCAPS_KEY_LEN].copy_from_slice(ek);
                let hash = $crate::scheme::h(ek);
                dk[384 * K + ENCAPS_KEY_LEN..384 * K + ENCAPS_KEY_LEN + 32].copy_from_slice(&hash);
                dk[384 * K + ENCAPS_KEY_LEN + 32..].copy_from_slice(z);
            }

            /// Encapsulate, producing a shared secret and a ciphertext.
            ///
            /// The encapsulation key is the one input here an attacker may choose, so
            /// it gets the modulus check FIPS 203 section 7.2 requires before any of it
            /// is used. Without that, a key with coefficients at or above `q` is
            /// silently reinterpreted as a different key, and the peer that supplied it
            /// controls the reinterpretation.
            pub fn encapsulate<R: RandomSource + ?Sized>(
                rng: &mut R,
                ek: &[u8; ENCAPS_KEY_LEN],
                ct: &mut [u8; CIPHERTEXT_LEN],
                shared: &mut [u8; SHARED_SECRET_LEN],
            ) -> Result<()> {
                ic_core::module::operational()?;
                Self::validate_encapsulation_key(ek)?;
                let mut m = [0u8; 32];
                rng.fill(&mut m)?;
                Self::encapsulate_deterministic(&m, ek, ct, shared);
                m.zeroize();
                Ok(())
            }

            /// Encapsulate with an explicit message, for tests and vectors.
            ///
            /// # This does not validate the encapsulation key
            ///
            /// It is the raw primitive, so that an ACVP vector can drive it with
            /// whatever bytes the vector file contains. Anything handling a key that
            /// came from a peer wants [`Self::encapsulate`], which performs the check,
            /// or must call [`Self::validate_encapsulation_key`] itself first.
            pub fn encapsulate_deterministic(
                m: &[u8; 32],
                ek: &[u8; ENCAPS_KEY_LEN],
                ct: &mut [u8; CIPHERTEXT_LEN],
                shared: &mut [u8; SHARED_SECRET_LEN],
            ) {
                let (k, r) = $crate::scheme::g(&[m, &$crate::scheme::h(ek)]);
                pke_encrypt(ek, m, &r, ct);
                shared.copy_from_slice(&k);
            }

            /// Decapsulate.
            ///
            /// Never fails on a malformed ciphertext. A ciphertext that does not
            /// re-encrypt to itself yields a pseudorandom secret derived from `z`,
            /// which is what denies an attacker a decryption oracle. The only errors
            /// here are length errors, which are a programming mistake rather than an
            /// attack signal.
            pub fn decapsulate(
                dk: &[u8; DECAPS_KEY_LEN],
                ct: &[u8; CIPHERTEXT_LEN],
                shared: &mut [u8; SHARED_SECRET_LEN],
            ) -> Result<()> {
                ic_core::module::operational()?;
                let dk_pke = &dk[..384 * K];
                let ek: &[u8; ENCAPS_KEY_LEN] = dk[384 * K..384 * K + ENCAPS_KEY_LEN]
                    .try_into()
                    .map_err(|_| ic_core::err!(Internal, "decapsulation key layout"))?;
                let hash = &dk[384 * K + ENCAPS_KEY_LEN..384 * K + ENCAPS_KEY_LEN + 32];
                let z = &dk[384 * K + ENCAPS_KEY_LEN + 32..];

                // FIPS 203 section 7.3's hash check. This is a check on the *key*, not
                // on the ciphertext, so failing it loudly is right and creates no
                // decryption oracle: the answer does not depend on `ct` at all.
                //
                // Delegated rather than inlined. Two copies of one rule drift, and a
                // drifted validator is worse than none because callers who check a key
                // once at load time would be checking something different from what
                // decapsulation enforces.
                Self::validate_decapsulation_key(dk)?;

                let mut m = pke_decrypt(dk_pke, ct);
                let (mut k, mut r) = $crate::scheme::g(&[&m, hash]);
                let mut reject = $crate::scheme::j(&[z, ct]);

                let mut recomputed = [0u8; CIPHERTEXT_LEN];
                pke_encrypt(ek, &m, &r, &mut recomputed);

                // Constant-time select: the comparison result must not be observable
                // through timing, or the implicit rejection leaks exactly what it is
                // meant to hide.
                let matched = ic_core::ct::eq(&recomputed, ct);
                for (i, out) in shared.iter_mut().enumerate() {
                    *out = ic_core::ct::select_u8(matched, k[i], reject[i]);
                }
                // Every one of these is key material. `m` is the recovered message,
                // which is the value the whole transform protects; `k` and `reject` are
                // the two candidate shared secrets, one of which was not selected and
                // is therefore still live; `r` is the encryption randomness derived
                // from `m`. Previously only `recomputed` was wiped, which is the one
                // item on the list that is a *ciphertext*.
                recomputed.zeroize();
                m.zeroize();
                k.zeroize();
                r.zeroize();
                reject.zeroize();
                Ok(())
            }

            /// Check that a decapsulation key is internally consistent.
            ///
            /// FIPS 203 section 7.3 calls this the hash check: the key carries a copy
            /// of its own public half and a hash of it, and the two must agree. It
            /// catches corruption and catches a key assembled from mismatched halves,
            /// which would otherwise fail only as secrets that never agree.
            ///
            /// [`Self::decapsulate`] performs this itself; it is public so that a
            /// caller loading a key from storage can check it once rather than on
            /// every use.
            pub fn validate_decapsulation_key(dk: &[u8; DECAPS_KEY_LEN]) -> Result<()> {
                let ek: &[u8; ENCAPS_KEY_LEN] = dk[384 * K..384 * K + ENCAPS_KEY_LEN]
                    .try_into()
                    .map_err(|_| ic_core::err!(Internal, "decapsulation key layout"))?;
                let stored = &dk[384 * K + ENCAPS_KEY_LEN..384 * K + ENCAPS_KEY_LEN + 32];
                ensure!(
                    bool::from(ic_core::ct::eq(&$crate::scheme::h(ek), stored)),
                    MalformedEncoding,
                    "decapsulation key's embedded hash does not match its public key"
                );
                Ok(())
            }

            /// Check that an encapsulation key is well formed.
            ///
            /// FIPS 203 requires that `ByteDecode12` of the key round-trips, which
            /// rejects keys whose coefficients are at or above `q`. Without this a
            /// malformed key is silently reinterpreted.
            pub fn validate_encapsulation_key(ek: &[u8; ENCAPS_KEY_LEN]) -> Result<()> {
                // An element at a time. The key is public, so stopping at the
                // first non-canonical element would reveal nothing, but every
                // element is checked anyway so the work does not depend on it.
                let mut canonical = true;
                for chunk in ek[..384 * K].chunks(384) {
                    let mut t = Poly::ZERO;
                    byte_decode(chunk, 12, &mut t);
                    let mut round = [0u8; 384];
                    encode_poly(&t, &mut round);
                    canonical &= round[..] == chunk[..];
                }
                ensure!(
                    canonical,
                    MalformedEncoding,
                    "encapsulation key is not canonically encoded"
                );
                Ok(())
            }
        }
    };
}
pub(crate) use ml_kem;
