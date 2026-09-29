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
            bit_pack, bit_unpack, hint_pack, hint_unpack, packed_len, simple_bit_pack,
            simple_bit_unpack, w1_bits, z_bits, T0_BITS, T1_BITS,
        };
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

        /// `ExpandA`, in the index order FIPS 204 specifies.
        ///
        /// `A[r][s]` comes from `rho || s || r` — column byte first. See
        /// [`crate::sample::rej_ntt_poly`] for why this is called out rather than
        /// assumed.
        fn expand_a(rho: &[u8; 32]) -> [[Poly; L]; K] {
            let mut a = [[Poly::ZERO; L]; K];
            for (r, row) in a.iter_mut().enumerate() {
                for (s, cell) in row.iter_mut().enumerate() {
                    *cell = rej_ntt_poly(rho, s as u8, r as u8);
                }
            }
            a
        }

        /// `A * v`, with `A` already in the transform domain and `v` given in it too.
        ///
        /// The sum is accumulated in the transform domain and inverted once, which is
        /// both faster and the only arrangement where the Montgomery bookkeeping works
        /// out: `pointwise` contributes `R^-1` and `inv_ntt` contributes `R`, so a
        /// product needs no correction but a bare round trip does.
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

        /// `c * v`, with both `c` and `v` already in the transform domain.
        ///
        /// Taking `v` pre-transformed is not a micro-optimisation. The signing loop
        /// runs this three times per attempt against vectors that never change, so
        /// transforming inside would redo the same work on every rejection — and, worse,
        /// would make it easy to pass a plain-domain vector by mistake and get a result
        /// that is wrong by a Montgomery factor rather than obviously broken.
        fn scale_vec<const M: usize>(c_hat: &Poly, v_hat: &[Poly; M]) -> [Poly; M] {
            let mut out = [Poly::ZERO; M];
            for (o, p) in out.iter_mut().zip(v_hat.iter()) {
                let mut product = c_hat.pointwise(p);
                product.inv_ntt();
                *o = product;
            }
            out
        }

        fn ntt_vec<const M: usize>(v: &[Poly; M]) -> [Poly; M] {
            let mut out = *v;
            for p in out.iter_mut() {
                p.ntt();
            }
            out
        }

        /// `ExpandS`: `s1` then `s2`, from one seed with a running nonce.
        fn expand_s(rho_prime: &[u8; 64]) -> ([Poly; L], [Poly; K]) {
            let mut s1 = [Poly::ZERO; L];
            let mut s2 = [Poly::ZERO; K];
            for (i, p) in s1.iter_mut().enumerate() {
                *p = rej_bounded_poly(rho_prime, i as u16, ETA);
            }
            for (i, p) in s2.iter_mut().enumerate() {
                *p = rej_bounded_poly(rho_prime, (L + i) as u16, ETA);
            }
            (s1, s2)
        }

        /// `w1Encode`: the high bits, four bits per coefficient.
        fn w1_encode(w1: &[Poly; K], out: &mut [u8]) {
            for (p, chunk) in w1.iter().zip(out.chunks_mut(W1_LEN)) {
                simple_bit_pack(p, w1_bits(GAMMA2), chunk);
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

            let a = expand_a(&rho);
            let (s1, s2) = expand_s(&rho_prime);

            // t = A*s1 + s2
            let mut t = matrix_apply(&a, &ntt_vec(&s1));
            for (ti, s) in t.iter_mut().zip(s2.iter()) {
                *ti = ti.add(s);
                ti.normalize();
            }

            let mut t1 = [Poly::ZERO; K];
            let mut t0 = [Poly::ZERO; K];
            for i in 0..K {
                let (hi, lo) = power2round_poly(&t[i]);
                t1[i] = hi;
                t0[i] = lo;
            }

            // pkEncode
            pk[..32].copy_from_slice(&rho);
            for (p, chunk) in t1.iter().zip(pk[32..].chunks_mut(T1_LEN)) {
                simple_bit_pack(p, T1_BITS, chunk);
            }

            let mut tr = [0u8; 64];
            h(&[&pk[..]], &mut tr);

            // skEncode
            let mut at = 0;
            sk[at..at + 32].copy_from_slice(&rho);
            at += 32;
            sk[at..at + 32].copy_from_slice(&key);
            at += 32;
            sk[at..at + 64].copy_from_slice(&tr);
            at += 64;
            for p in s1.iter() {
                bit_pack(p, ETA, ETA_BITS, &mut sk[at..at + S_LEN]);
                at += S_LEN;
            }
            for p in s2.iter() {
                bit_pack(p, ETA, ETA_BITS, &mut sk[at..at + S_LEN]);
                at += S_LEN;
            }
            for p in t0.iter() {
                bit_pack(p, 1 << (D - 1), T0_BITS, &mut sk[at..at + T0_LEN]);
                at += T0_LEN;
            }
            debug_assert_eq!(at, SECRET_KEY_LEN);
        }

        struct SigningKey {
            rho: [u8; 32],
            key: [u8; 32],
            tr: [u8; 64],
            s1: [Poly; L],
            s2: [Poly; K],
            t0: [Poly; K],
        }

        impl Drop for SigningKey {
            /// Wipe the secret halves when the decoded key goes out of scope.
            ///
            /// `sk_decode` runs on every signature, so without this each one leaves a
            /// copy of `s1`, `s2` and `t0` on the stack. `rho` is skipped deliberately:
            /// it is published in the verification key, and wiping public material
            /// alongside private material blurs which is which.
            ///
            /// This crate had no `Drop` anywhere before, while `impl Zeroize for Poly`
            /// sat unused -- the trait existed, the application did not, which is the
            /// same shape as a validator nothing calls.
            fn drop(&mut self) {
                self.key.zeroize();
                self.tr.zeroize();
                for p in self.s1.iter_mut() {
                    p.zeroize();
                }
                for p in self.s2.iter_mut() {
                    p.zeroize();
                }
                for p in self.t0.iter_mut() {
                    p.zeroize();
                }
            }
        }

        fn sk_decode(sk: &[u8; SECRET_KEY_LEN]) -> SigningKey {
            let mut out = SigningKey {
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
            let mut at = 128;
            for p in out.s1.iter_mut() {
                bit_unpack(&sk[at..at + S_LEN], ETA, ETA_BITS, p);
                at += S_LEN;
            }
            for p in out.s2.iter_mut() {
                bit_unpack(&sk[at..at + S_LEN], ETA, ETA_BITS, p);
                at += S_LEN;
            }
            for p in out.t0.iter_mut() {
                bit_unpack(&sk[at..at + T0_LEN], 1 << (D - 1), T0_BITS, p);
                at += T0_LEN;
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
            let k = sk_decode(sk);

            let mut mu = [0u8; 64];
            let framed = Framed::new(&k.tr, &prefix, ctx, parts);
            h(framed.as_slice(), &mut mu);

            let mut rho_prime = [0u8; 64];
            h(&[&k.key, rnd, &mu], &mut rho_prime);

            let a = expand_a(&k.rho);
            let s1_hat = ntt_vec(&k.s1);
            let s2_hat = ntt_vec(&k.s2);
            let t0_hat = ntt_vec(&k.t0);

            let mut w1_packed = [0u8; K * W1_LEN];
            let mut c_tilde = [0u8; C_TILDE_LEN];

            let mut kappa = 0u16;
            for _ in 0..MAX_ATTEMPTS {
                // y <- ExpandMask
                let mut y = [Poly::ZERO; L];
                for (i, p) in y.iter_mut().enumerate() {
                    *p = expand_mask_poly(&rho_prime, kappa + i as u16, GAMMA1);
                }
                kappa += L as u16;

                // w = A*y, and its high bits.
                let mut w = matrix_apply(&a, &ntt_vec(&y));
                for p in w.iter_mut() {
                    p.normalize();
                }
                let mut w1 = [Poly::ZERO; K];
                let mut w0 = [Poly::ZERO; K];
                for i in 0..K {
                    let (hi, lo) = decompose_poly(&w[i], GAMMA2);
                    w1[i] = hi;
                    w0[i] = lo;
                }

                w1_encode(&w1, &mut w1_packed);
                h(&[&mu, &w1_packed], &mut c_tilde);
                let mut c = sample_in_ball(&c_tilde, TAU);
                c.ntt();

                // z = y + c*s1
                let cs1 = scale_vec(&c, &s1_hat);
                let mut z = [Poly::ZERO; L];
                let mut too_big = false;
                for i in 0..L {
                    z[i] = y[i].add(&cs1[i]);
                    z[i].reduce();
                    if z[i].exceeds(GAMMA1 - BETA) {
                        too_big = true;
                    }
                }

                // r0 = LowBits(w - c*s2)
                let cs2 = scale_vec(&c, &s2_hat);
                let mut r0 = [Poly::ZERO; K];
                let mut w_minus_cs2 = [Poly::ZERO; K];
                for i in 0..K {
                    w_minus_cs2[i] = w[i].sub(&cs2[i]);
                    let (_, lo) = decompose_poly(&w_minus_cs2[i], GAMMA2);
                    r0[i] = lo;
                    if r0[i].exceeds(GAMMA2 - BETA) {
                        too_big = true;
                    }
                }
                if too_big {
                    continue;
                }

                // h = MakeHint(-c*t0, w - c*s2 + c*t0)
                let ct0 = scale_vec(&c, &t0_hat);
                let mut hints = [[false; N]; K];
                let mut weight = 0usize;
                let mut ct0_too_big = false;
                for ((slot, base), shift) in hints.iter_mut().zip(w_minus_cs2.iter()).zip(ct0.iter()) {
                    let mut probe = *shift;
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
                    let target = base.add(shift);
                    let (bits, w) = make_hint_poly(&negated, &target, GAMMA2);
                    *slot = bits;
                    weight += w;
                }
                if ct0_too_big || weight > OMEGA {
                    continue;
                }

                // sigEncode
                sig[..C_TILDE_LEN].copy_from_slice(&c_tilde);
                let mut at = C_TILDE_LEN;
                for p in z.iter_mut() {
                    p.reduce();
                    bit_pack(p, GAMMA1, z_bits(GAMMA1), &mut sig[at..at + Z_LEN]);
                    at += Z_LEN;
                }
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
            let mut t1 = [Poly::ZERO; K];
            for (p, chunk) in t1.iter_mut().zip(pk[32..].chunks(T1_LEN)) {
                simple_bit_unpack(chunk, T1_BITS, p);
            }

            // sigDecode, with every rejection the encoding allows.
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

            // w' = A*z - c*t1*2^d
            let a = expand_a(&rho);
            let az = matrix_apply(&a, &ntt_vec(&z));

            let mut shifted = [Poly::ZERO; K];
            for (o, p) in shifted.iter_mut().zip(t1.iter()) {
                for (oc, pc) in o.c.iter_mut().zip(p.c.iter()) {
                    *oc = pc << D;
                }
            }
            let ct1 = scale_vec(&c, &ntt_vec(&shifted));

            let mut w_approx = [Poly::ZERO; K];
            for i in 0..K {
                w_approx[i] = az[i].sub(&ct1[i]);
                w_approx[i].normalize();
            }

            let mut w1 = [Poly::ZERO; K];
            for i in 0..K {
                w1[i] = use_hint_poly(&hints[i], &w_approx[i], GAMMA2);
            }

            let mut w1_packed = [0u8; K * W1_LEN];
            w1_encode(&w1, &mut w1_packed);
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
