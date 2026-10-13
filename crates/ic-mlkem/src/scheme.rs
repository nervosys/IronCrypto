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

        /// Whether the lane-scheduled form below runs: only where the four-way
        /// Keccak is a vector permutation, since elsewhere it is four scalar
        /// ones and holding the matrix would buy nothing. A `no_std` build has
        /// no way to detect the instructions, and compiles only the streaming
        /// form.
        #[cfg(feature = "std")]
        fn parallel() -> bool {
            ic_hash::KeccakX4::is_parallel()
        }

        /// K-PKE and the KEM's hashing with every Keccak call run through
        /// [`crate::lanes`], four lanes at a time.
        ///
        /// # Why this one holds the matrix
        ///
        /// The streaming functions above sample each entry of `A` where it is
        /// used and drop it, to keep an embedded stack small. Here the entries
        /// are sampled together, in the same permutations as the hashes, so
        /// they must be held until the arithmetic reaches them: `k * k`
        /// polynomials, 8 KiB for ML-KEM-1024. That is only taken on a CPU with
        /// the vector permutation, which is to say a hosted `std` build, and
        /// the streaming form stays the only one a `no_std` build compiles.
        ///
        /// Each function computes exactly what its streaming counterpart
        /// does, with the same reductions in the same order; the tests in
        /// `held` compare both against the held-matrix reference.
        #[cfg(feature = "std")]
        mod fast {
            use super::*;
            use $crate::lanes::{run, Task};

            /// `k * k`.
            pub(super) const KK: usize = K * K;

            /// The task that samples `A[i][j]`, or `A^T[i][j]`, into `slot`.
            ///
            /// The same index order as `matrix_entry`: FIPS 203 seeds
            /// `A[i][j]` with `rho || j || i`.
            fn uniform(
                rho: &[u8; 32],
                i: usize,
                jj: usize,
                transposed: bool,
                slot: usize,
            ) -> Task<'_> {
                let index = if transposed {
                    [i as u8, jj as u8]
                } else {
                    [jj as u8, i as u8]
                };
                Task::Uniform { rho, index, slot }
            }

            /// Row `i` of a held matrix times `v`, reduced: `matrix_row`'s sums.
            fn row(m: &[Poly], i: usize, v: &[Poly]) -> Poly {
                let mut acc = Poly::ZERO;
                for (jj, vj) in v.iter().enumerate() {
                    acc.basemul_add(&m[i * K + jj], vj);
                }
                acc.reduce();
                acc
            }

            pub(super) fn pke_keygen(d: &[u8; 32], ek: &mut [u8], dk: &mut [u8]) {
                let (rho, mut sigma) = $crate::scheme::g(&[d, &[K as u8]]);

                // A, then s (nonces 0..k) and e (k..2k), in one schedule.
                let mut polys = [Poly::ZERO; KK + 2 * K];
                {
                    let tasks: [Task<'_>; KK + 2 * K] = core::array::from_fn(|n| {
                        if n < KK {
                            uniform(&rho, n / K, n % K, false, n)
                        } else {
                            Task::Noise {
                                seed: &sigma,
                                nonce: (n - KK) as u8,
                                eta: ETA1,
                                slot: n,
                            }
                        }
                    });
                    run(&tasks, &mut polys, &mut []);
                }
                sigma.zeroize();

                let (a, se) = polys.split_at_mut(KK);
                for p in se.iter_mut() {
                    p.ntt();
                }
                let (s, e) = se.split_at(K);
                for (i, ei) in e.iter().enumerate() {
                    let mut t = row(a, i, s);
                    t.to_mont();
                    t.add_assign(ei);
                    t.reduce();
                    encode_poly(&t, &mut ek[i * 384..(i + 1) * 384]);
                }
                ek[384 * K..].copy_from_slice(&rho);
                for (i, p) in s.iter().enumerate() {
                    encode_poly(p, &mut dk[i * 384..(i + 1) * 384]);
                }
                for p in se.iter_mut() {
                    p.zeroize();
                }
            }

            // These write into storage the caller holds, rather than
            // returning arrays of polynomials: a returned array was built and
            // then copied, and the copy was kilobytes of stack.

            /// `y` (nonces 0..k, `eta1`), `e1` (k..2k, `eta2`) and `e2` (2k).
            pub(super) fn encryption_noise(r: &[u8; 32], noise: &mut [Poly; 2 * K + 1]) {
                let tasks: [Task<'_>; 2 * K + 1] = core::array::from_fn(|n| Task::Noise {
                    seed: r,
                    nonce: n as u8,
                    eta: if n < K { ETA1 } else { ETA2 },
                    slot: n,
                });
                run(&tasks, noise, &mut []);
            }

            /// `A^T` and up to two 32-byte hashes, in one schedule. The hashes
            /// go first, being the longest tasks.
            pub(super) fn transposed_matrix_and_hashes(
                rho: &[u8; 32],
                hash_tasks: &[Task<'_>],
                hashes: &mut [[u8; 32]],
                at: &mut [Poly; KK],
            ) {
                let mut tasks = [Task::Hash {
                    parts: [&[], &[]],
                    domain: 0,
                    slot: usize::MAX,
                }; KK + 2];
                let n = hash_tasks.len().min(2);
                tasks[..n].copy_from_slice(&hash_tasks[..n]);
                for f in 0..KK {
                    tasks[n + f] = uniform(rho, f / K, f % K, true, f);
                }
                run(&tasks[..n + KK], at, hashes);
            }

            /// `A^T` in slots `0..k*k` and the encryption noise for coins `r`
            /// in the `2k + 1` after, with up to two 32-byte hashes, in one
            /// schedule.
            pub(super) fn matrix_noise_and_hashes(
                rho: &[u8; 32],
                r: &[u8; 32],
                hash_tasks: &[Task<'_>],
                hashes: &mut [[u8; 32]],
                polys: &mut [Poly; KK + 2 * K + 1],
            ) {
                let mut tasks = [Task::Hash {
                    parts: [&[], &[]],
                    domain: 0,
                    slot: usize::MAX,
                }; 2 + KK + 2 * K + 1];
                let n = hash_tasks.len().min(2);
                tasks[..n].copy_from_slice(&hash_tasks[..n]);
                for f in 0..KK {
                    tasks[n + f] = uniform(rho, f / K, f % K, true, f);
                }
                for e in 0..2 * K + 1 {
                    tasks[n + KK + e] = Task::Noise {
                        seed: r,
                        nonce: e as u8,
                        eta: if e < K { ETA1 } else { ETA2 },
                        slot: KK + e,
                    };
                }
                run(&tasks[..n + KK + 2 * K + 1], polys, hashes);
            }

            /// K-PKE encryption, given `A^T` (`k * k` entries) and the
            /// `2k + 1` noise polynomials already drawn: `pke_encrypt`'s
            /// arithmetic, in its order. Clears `noise`.
            pub(super) fn pke_encrypt(
                ek: &[u8],
                m: &[u8; 32],
                at: &[Poly],
                noise: &mut [Poly],
                out: &mut [u8],
            ) {
                let du_len = encoded_len(DU);
                let (y, errors) = noise.split_at_mut(K);
                for p in y.iter_mut() {
                    p.ntt();
                }

                // u = InvNTT(A^T o y) + e1
                for (i, e1) in errors[..K].iter().enumerate() {
                    let mut u = row(at, i, y);
                    u.inv_ntt();
                    u.add_assign(e1);
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
                v.add_assign(&errors[K]);
                let mut mu = Poly::ZERO;
                decode_decompress(m, 1, &mut mu);
                v.add_assign(&mu);
                v.reduce();
                v.normalize();
                compress_encode(&v, DV, &mut out[K * du_len..]);

                for p in noise.iter_mut() {
                    p.zeroize();
                }
                mu.zeroize();
            }
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

            /// The lane-scheduled form against the streaming one, operation by
            /// operation and through the whole KEM, over inputs no vector file
            /// chose -- including a ciphertext that is not an encryption of
            /// anything, and a key whose embedded hash is wrong.
            ///
            /// Both forms run here whatever the CPU: without the vector
            /// permutation the scheduled form runs over four scalar ones, which
            /// is slower and computes the same thing. Which one the public
            /// functions select is checked separately below.
            #[cfg(feature = "std")]
            #[test]
            fn the_lane_scheduled_form_matches_the_streaming_one() {
                let mut checked = 0;
                for seed in 0..12u8 {
                    let d: [u8; 32] = bytes(seed);
                    let mut ek = [0u8; ENCAPS_KEY_LEN];
                    let mut dk = [0u8; 384 * K];
                    let mut ek_lanes = [0u8; ENCAPS_KEY_LEN];
                    let mut dk_lanes = [0u8; 384 * K];
                    super::pke_keygen(&d, &mut ek, &mut dk);
                    super::fast::pke_keygen(&d, &mut ek_lanes, &mut dk_lanes);
                    assert_eq!(ek, ek_lanes, "encapsulation key, seed {seed}");
                    assert_eq!(dk, dk_lanes, "decryption key, seed {seed}");

                    let z: [u8; 32] = bytes(seed.wrapping_add(30));
                    let mut full_ek = [0u8; ENCAPS_KEY_LEN];
                    let mut full_dk = [0u8; DECAPS_KEY_LEN];
                    $name::keygen_deterministic(&d, &z, &mut full_ek, &mut full_dk);

                    let m: [u8; 32] = bytes(seed.wrapping_add(100));
                    let mut ct = [0u8; CIPHERTEXT_LEN];
                    let mut ct_lanes = [0u8; CIPHERTEXT_LEN];
                    let mut sent = [0u8; SHARED_SECRET_LEN];
                    let mut sent_lanes = [0u8; SHARED_SECRET_LEN];
                    $name::encapsulate_streaming(&m, &full_ek, &mut ct, &mut sent);
                    $name::encapsulate_lanes(&m, &full_ek, &mut ct_lanes, &mut sent_lanes);
                    assert_eq!(ct, ct_lanes, "ciphertext, seed {seed}");
                    assert_eq!(sent, sent_lanes, "shared secret, seed {seed}");

                    let garbage: [u8; CIPHERTEXT_LEN] = bytes(seed.wrapping_add(50));
                    for (what, c) in [("valid", ct), ("arbitrary", garbage)] {
                        let mut a = [0u8; SHARED_SECRET_LEN];
                        let mut b = [0u8; SHARED_SECRET_LEN];
                        $name::decapsulate_streaming(&full_dk, &c, &mut a).unwrap();
                        $name::decapsulate_lanes(&full_dk, &c, &mut b).unwrap();
                        assert_eq!(a, b, "decapsulation of a {what} ciphertext, seed {seed}");
                    }
                    assert_eq!(sent, {
                        let mut s = [0u8; SHARED_SECRET_LEN];
                        $name::decapsulate_lanes(&full_dk, &ct, &mut s).unwrap();
                        s
                    });

                    // The hash check refuses a key whose embedded hash, or whose
                    // embedded public key, has been altered -- on both paths.
                    for at in [384 * K + ENCAPS_KEY_LEN, 384 * K + 5] {
                        let mut bad = full_dk;
                        bad[at] ^= 1;
                        let mut s = [0u8; SHARED_SECRET_LEN];
                        assert!($name::decapsulate_streaming(&bad, &ct, &mut s).is_err());
                        assert!($name::decapsulate_lanes(&bad, &ct, &mut s).is_err());
                    }
                    checked += 1;
                }
                assert_eq!(checked, 12, "the comparison did not run");
            }

            /// Where encapsulation and decapsulation spend their time, stage by
            /// stage, on the scheduled path. A diagnostic, not a test: run it
            /// with `--release -- --ignored --nocapture`.
            #[cfg(feature = "std")]
            #[test]
            #[ignore = "diagnostic, not a test"]
            fn where_the_time_goes() {
                use std::time::Instant;
                fn time(label: &str, mut f: impl FnMut()) {
                    let mut best = f64::INFINITY;
                    for _ in 0..7 {
                        let t = Instant::now();
                        for _ in 0..2000 {
                            f();
                        }
                        best = best.min(t.elapsed().as_secs_f64() / 2000.0 * 1e6);
                    }
                    println!("  {label:<44} {best:>7.2} us");
                }
                let mut ek = [0u8; ENCAPS_KEY_LEN];
                let mut dk = [0u8; DECAPS_KEY_LEN];
                $name::keygen_deterministic(&bytes(1), &bytes(2), &mut ek, &mut dk);
                let mut ct = [0u8; CIPHERTEXT_LEN];
                let mut ss = [0u8; SHARED_SECRET_LEN];
                let m: [u8; 32] = bytes(3);
                let mut rho = [0u8; 32];
                rho.copy_from_slice(&ek[384 * K..]);
                println!("{}", $display);
                time("encapsulate_lanes", || {
                    $name::encapsulate_lanes(&m, &ek, &mut ct, &mut ss)
                });
                let mut at = [Poly::ZERO; super::fast::KK];
                let mut noise = [Poly::ZERO; 2 * K + 1];
                time("  H(ek) and A^T, scheduled", || {
                    let mut h = [[0u8; 32]];
                    let task = $crate::lanes::Task::Hash {
                        parts: [&ek[..], &[]],
                        domain: 0x06,
                        slot: 0,
                    };
                    super::fast::transposed_matrix_and_hashes(&rho, &[task], &mut h, &mut at);
                    std::hint::black_box(&at);
                });
                time("  A^T alone, scheduled", || {
                    super::fast::transposed_matrix_and_hashes(&rho, &[], &mut [], &mut at);
                    std::hint::black_box(&at);
                });
                time("  H(ek) alone, scalar", || {
                    std::hint::black_box($crate::scheme::h(&ek));
                });
                time("  G", || {
                    std::hint::black_box($crate::scheme::g(&[&m, &m]));
                });
                time("  noise, scheduled", || {
                    super::fast::encryption_noise(&m, &mut noise);
                    std::hint::black_box(&noise);
                });
                super::fast::transposed_matrix_and_hashes(&rho, &[], &mut [], &mut at);
                time("  K-PKE arithmetic and encoding", || {
                    super::fast::encryption_noise(&m, &mut noise);
                    super::fast::pke_encrypt(&ek, &m, &at, &mut noise, &mut ct);
                });
                time("validate_encapsulation_key", || {
                    $name::validate_encapsulation_key(&ek).unwrap()
                });
                time("decapsulate_lanes", || {
                    $name::decapsulate_lanes(&dk, &ct, &mut ss).unwrap()
                });
                time("  K-PKE decryption", || {
                    std::hint::black_box(super::pke_decrypt(&dk[..384 * K], &ct));
                });
                println!("per polynomial");
                let mut p = at[1];
                let q = at[2];
                time("  ntt", || {
                    let mut x = std::hint::black_box(p);
                    x.ntt();
                    std::hint::black_box(x);
                });
                time("  inv_ntt", || {
                    let mut x = std::hint::black_box(p);
                    x.inv_ntt();
                    std::hint::black_box(x);
                });
                time("  basemul_add", || {
                    let mut x = std::hint::black_box(p);
                    x.basemul_add(&q, &q);
                    std::hint::black_box(x);
                });
                time("  reduce", || {
                    let mut x = std::hint::black_box(p);
                    x.reduce();
                    std::hint::black_box(x);
                });
                time("  normalize", || {
                    let mut x = std::hint::black_box(p);
                    x.normalize();
                    std::hint::black_box(x);
                });
                time("  to_mont", || {
                    let mut x = std::hint::black_box(p);
                    x.to_mont();
                    std::hint::black_box(x);
                });
                time("  add_assign", || {
                    let mut x = std::hint::black_box(p);
                    x.add_assign(&q);
                    std::hint::black_box(x);
                });
                p.normalize();
                let mut b12 = [0u8; 384];
                time("  encode_poly (normalize, ByteEncode12)", || {
                    encode_poly(std::hint::black_box(&p), &mut b12);
                });
                time("  ByteDecode12", || {
                    byte_decode(std::hint::black_box(&b12), 12, &mut p);
                });
                let mut b10 = [0u8; 320];
                time("  compress_encode 10", || {
                    compress_encode(std::hint::black_box(&p), 10, &mut b10);
                });
                time("  decode_decompress 10", || {
                    decode_decompress(std::hint::black_box(&b10), 10, &mut p);
                });
                time("  decode_decompress 1", || {
                    decode_decompress(std::hint::black_box(&m), 1, &mut p);
                });
                let prf = [0x5au8; 192];
                time("  SamplePolyCBD eta 2", || {
                    $crate::sample::sample_poly_cbd(2, std::hint::black_box(&prf[..128]), &mut p);
                });
            }

            /// On a CPU with the vector permutation, the public functions take
            /// the scheduled form; say which, so a vector run is not silently
            /// testing the other.
            #[cfg(feature = "std")]
            #[test]
            fn the_scheduled_form_is_selected_where_it_pays() {
                assert_eq!(parallel(), ic_hash::KeccakX4::is_parallel());
                #[cfg(target_arch = "x86_64")]
                if std::is_x86_feature_detected!("avx2") {
                    assert!(
                        parallel(),
                        "AVX2 is present but the scheduled form is not selected"
                    );
                }
                println!(
                    "{}: {}",
                    $display,
                    if parallel() {
                        "lane-scheduled"
                    } else {
                        "streaming"
                    }
                );
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
                // `H(ek)`, as key generation stored it in `dk`. Recomputing it
                // here was a fourth hash of the same 1 KiB key per generation;
                // the decapsulation below checks the stored copy against `ek`
                // in any case.
                let mut m = [0u8; 32];
                m.copy_from_slice(&dk[384 * K + ENCAPS_KEY_LEN..384 * K + ENCAPS_KEY_LEN + 32]);
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
                #[cfg(feature = "std")]
                if parallel() {
                    fast::pke_keygen(d, ek, &mut dk[..384 * K]);
                } else {
                    pke_keygen(d, ek, &mut dk[..384 * K]);
                }
                #[cfg(not(feature = "std"))]
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
                #[cfg(feature = "std")]
                if parallel() {
                    Self::encapsulate_lanes(m, ek, ct, shared);
                    return;
                }
                Self::encapsulate_streaming(m, ek, ct, shared);
            }

            /// [`Self::encapsulate_deterministic`], one Keccak call at a time.
            fn encapsulate_streaming(
                m: &[u8; 32],
                ek: &[u8; ENCAPS_KEY_LEN],
                ct: &mut [u8; CIPHERTEXT_LEN],
                shared: &mut [u8; SHARED_SECRET_LEN],
            ) {
                let (mut k, mut r) = $crate::scheme::g(&[m, &$crate::scheme::h(ek)]);
                pke_encrypt(ek, m, &r, ct);
                shared.copy_from_slice(&k);
                k.zeroize();
                r.zeroize();
            }

            /// [`Self::encapsulate_deterministic`] with its Keccak calls
            /// scheduled four lanes at a time: `H(ek)` on one lane while the
            /// other three expand `A^T`, then the noise.
            #[cfg(feature = "std")]
            fn encapsulate_lanes(
                m: &[u8; 32],
                ek: &[u8; ENCAPS_KEY_LEN],
                ct: &mut [u8; CIPHERTEXT_LEN],
                shared: &mut [u8; SHARED_SECRET_LEN],
            ) {
                let mut rho = [0u8; 32];
                rho.copy_from_slice(&ek[384 * K..]);
                let mut hashes = [[0u8; 32]];
                let hash = $crate::lanes::Task::Hash {
                    parts: [&ek[..], &[]],
                    domain: 0x06,
                    slot: 0,
                };
                let mut at = [Poly::ZERO; fast::KK];
                fast::transposed_matrix_and_hashes(&rho, &[hash], &mut hashes, &mut at);
                let (mut k, mut r) = $crate::scheme::g(&[m, &hashes[0]]);
                let mut noise = [Poly::ZERO; 2 * K + 1];
                fast::encryption_noise(&r, &mut noise);
                fast::pke_encrypt(ek, m, &at, &mut noise, ct);
                shared.copy_from_slice(&k);
                k.zeroize();
                r.zeroize();
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
                // Where the four-way Keccak runs in hardware, the hash check's
                // hash is computed alongside `J(z || c)` and the matrix, and
                // compared by the same function `validate_decapsulation_key` uses.
                #[cfg(feature = "std")]
                if parallel() {
                    return Self::decapsulate_lanes(dk, ct, shared);
                }
                Self::decapsulate_streaming(dk, ct, shared)
            }

            /// [`Self::decapsulate`], one Keccak call at a time.
            fn decapsulate_streaming(
                dk: &[u8; DECAPS_KEY_LEN],
                ct: &[u8; CIPHERTEXT_LEN],
                shared: &mut [u8; SHARED_SECRET_LEN],
            ) -> Result<()> {
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

                Self::select_shared_secret(ct, &recomputed, &k, &reject, shared);
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

            /// `K` if the re-encryption reproduced `ct`, otherwise the rejection
            /// key, into `shared`.
            ///
            /// Constant-time select: the comparison result must not be observable
            /// through timing, or the implicit rejection leaks exactly what it is
            /// meant to hide.
            fn select_shared_secret(
                ct: &[u8; CIPHERTEXT_LEN],
                recomputed: &[u8; CIPHERTEXT_LEN],
                k: &[u8; 32],
                reject: &[u8; 32],
                shared: &mut [u8; SHARED_SECRET_LEN],
            ) {
                let matched = ic_core::ct::eq(recomputed, ct);
                for (i, out) in shared.iter_mut().enumerate() {
                    *out = ic_core::ct::select_u8(matched, k[i], reject[i]);
                }
            }

            /// [`Self::decapsulate`] with its Keccak calls scheduled four lanes
            /// at a time: the hash check's `H(ek)`, `J(z || c)` and `A^T` in one
            /// schedule, then the re-encryption's noise.
            #[cfg(feature = "std")]
            fn decapsulate_lanes(
                dk: &[u8; DECAPS_KEY_LEN],
                ct: &[u8; CIPHERTEXT_LEN],
                shared: &mut [u8; SHARED_SECRET_LEN],
            ) -> Result<()> {
                let dk_pke = &dk[..384 * K];
                let ek: &[u8; ENCAPS_KEY_LEN] = dk[384 * K..384 * K + ENCAPS_KEY_LEN]
                    .try_into()
                    .map_err(|_| ic_core::err!(Internal, "decapsulation key layout"))?;
                let hash = &dk[384 * K + ENCAPS_KEY_LEN..384 * K + ENCAPS_KEY_LEN + 32];
                let z = &dk[384 * K + ENCAPS_KEY_LEN + 32..];
                let mut rho = [0u8; 32];
                rho.copy_from_slice(&ek[384 * K..]);

                // Decryption, and the re-encryption's coins, need no Keccak
                // that depends on the checks, so they come first and the
                // re-encryption noise joins `H(ek)`, `J(z || c)` and `A^T` in
                // one schedule. Nothing computed here is returned, or
                // influences what is returned, unless the hash check passes;
                // on failure all of it is wiped.
                let mut m = pke_decrypt(dk_pke, ct);
                let (mut k, mut r) = $crate::scheme::g(&[&m, hash]);

                use $crate::lanes::Task;
                let tasks = [
                    Task::Hash {
                        parts: [&ek[..], &[]],
                        domain: 0x06,
                        slot: 0,
                    },
                    Task::Hash {
                        parts: [z, &ct[..]],
                        domain: 0x1f,
                        slot: 1,
                    },
                ];
                let mut hashes = [[0u8; 32]; 2];
                let mut polys = [Poly::ZERO; fast::KK + 2 * K + 1];
                fast::matrix_noise_and_hashes(&rho, &r, &tasks, &mut hashes, &mut polys);
                let [computed, mut reject] = hashes;
                let (at, noise) = polys.split_at_mut(fast::KK);
                if let Err(e) = Self::check_embedded_hash(dk, &computed) {
                    for p in noise.iter_mut() {
                        p.zeroize();
                    }
                    m.zeroize();
                    k.zeroize();
                    r.zeroize();
                    reject.zeroize();
                    return Err(e);
                }

                let mut recomputed = [0u8; CIPHERTEXT_LEN];
                fast::pke_encrypt(ek, &m, at, noise, &mut recomputed);

                Self::select_shared_secret(ct, &recomputed, &k, &reject, shared);
                // As in `decapsulate`: all key material, `noise` cleared by
                // `pke_encrypt`.
                recomputed.zeroize();
                m.zeroize();
                k.zeroize();
                r.zeroize();
                reject.zeroize();
                Ok(())
            }

            /// FIPS 203's hash check, given `H(ek)` however it was computed:
            /// the one comparison both [`Self::validate_decapsulation_key`] and
            /// the scheduled decapsulation make.
            fn check_embedded_hash(dk: &[u8; DECAPS_KEY_LEN], computed: &[u8; 32]) -> Result<()> {
                let stored = &dk[384 * K + ENCAPS_KEY_LEN..384 * K + ENCAPS_KEY_LEN + 32];
                ensure!(
                    bool::from(ic_core::ct::eq(computed, stored)),
                    MalformedEncoding,
                    "decapsulation key's embedded hash does not match its public key"
                );
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
                Self::check_embedded_hash(dk, &$crate::scheme::h(ek))
            }

            /// Check that an encapsulation key is well formed.
            ///
            /// FIPS 203 requires that `ByteDecode12` of the key round-trips, which
            /// rejects keys whose coefficients are at or above `q`. Without this a
            /// malformed key is silently reinterpreted.
            pub fn validate_encapsulation_key(ek: &[u8; ENCAPS_KEY_LEN]) -> Result<()> {
                // The round trip reproduces its input exactly when no twelve-bit
                // field reaches q, which is what this tests, every field of
                // every element; `the_modulus_check_is_the_round_trip` holds the
                // two forms to each other.
                ensure!(
                    $crate::encode::all_below_q_12(&ek[..384 * K]),
                    MalformedEncoding,
                    "encapsulation key is not canonically encoded"
                );
                Ok(())
            }
        }
    };
}
pub(crate) use ml_kem;
