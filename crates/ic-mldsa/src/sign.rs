//! ML-DSA-65 (FIPS 204 algorithms 1 through 8) — **experimental**.
//!
//! # Read this before using it
//!
//! No ACVP vector is wired in, so **nothing here has been confirmed to produce
//! the same bytes as any other ML-DSA implementation**. Every layer beneath it
//! is independently checked — the NTT against schoolbook multiplication, the
//! packing against a bit-at-a-time reference, the rounding against its defining
//! equations, the samplers against the specification's pseudocode — and this
//! module is checked only against itself, by signing and verifying.
//!
//! That is a weaker argument than it sounds, and it is worth being precise
//! about why. A sign/verify round trip is not vacuous here: signing computes
//! `w = A*y` while verification computes `w' = A*z - c*t1*2^d` and rebuilds the
//! high bits through the hints, so the two are different computations that must
//! agree through the rounding machinery. What the round trip cannot catch is a
//! convention misread *consistently* — a byte order in a hash input, a domain
//! separator, the order of `s` and `r` in `ExpandA`. Those produce a scheme
//! that is internally perfect and interoperates with nobody.
//!
//! So this is registered `experimental` in the ontology, alongside ML-KEM-768
//! and for the same reason, carrying a `not-interoperability-tested` constraint
//! at `Critical` severity. It is excluded from the approved-mode policy and
//! from `recommend`. Being discoverable and being recommended are different
//! things, and the registry is where that difference gets stated rather than
//! left to whoever reads the source. `testvectors/README.md` says what file
//! would promote it.
//!
//! # What is deliberately not here
//!
//! Only ML-DSA-65. The other two parameter sets are a table change away, but
//! shipping three unverified variants is worse than shipping one: it triples
//! what a future vector has to confirm while adding nothing that can be checked
//! today.
//!
//! The hedged variant takes its 32 bytes of randomness as an argument rather
//! than reaching for a DRBG, so the deterministic variant is the same code path
//! with zeros — and so a caller cannot get a silently non-random signature from
//! a failed entropy source they never saw.

use crate::encode::{
    bit_pack, bit_unpack, hint_pack, hint_unpack, packed_len, simple_bit_pack, simple_bit_unpack,
    w1_bits, z_bits, ETA4_BITS, T0_BITS, T1_BITS,
};
use crate::poly::{Poly, N};
use crate::rounding::{
    decompose_poly, make_hint_poly, power2round_poly, use_hint_poly, D, GAMMA2_32 as GAMMA2,
};
use crate::sample::{expand_mask_poly, rej_bounded_poly, rej_ntt_poly, sample_in_ball};
use ic_core::traits::Xof;
use ic_hash::Shake256;

/// Rows of `A`, and the length of `t`, `s2` and `w`.
pub const K: usize = 6;
/// Columns of `A`, and the length of `s1`, `y` and `z`.
pub const L: usize = 5;
/// Secret coefficient bound.
pub const ETA: i32 = 4;
/// Nonzero coefficients in the challenge.
pub const TAU: usize = 49;
/// `tau * eta`, the bound on `c*s`.
pub const BETA: i32 = (TAU as i32) * ETA;
/// Mask bound.
pub const GAMMA1: i32 = 1 << 19;
/// Maximum total hint weight.
pub const OMEGA: usize = 55;
/// Bytes of challenge digest, `lambda / 4` with `lambda = 192`.
pub const C_TILDE_LEN: usize = 48;

/// Bytes in a seed.
pub const SEED_LEN: usize = 32;

const T1_LEN: usize = packed_len(T1_BITS);
const T0_LEN: usize = packed_len(T0_BITS);
const S_LEN: usize = packed_len(ETA4_BITS);
const Z_LEN: usize = packed_len(z_bits(GAMMA1));
const W1_LEN: usize = packed_len(w1_bits(GAMMA2));

/// Encoded verification key length.
pub const PUBLIC_KEY_LEN: usize = SEED_LEN + K * T1_LEN;
/// Encoded signing key length.
pub const SECRET_KEY_LEN: usize = SEED_LEN + SEED_LEN + 64 + L * S_LEN + K * S_LEN + K * T0_LEN;
/// Encoded signature length.
pub const SIGNATURE_LEN: usize = C_TILDE_LEN + L * Z_LEN + OMEGA + K;

/// How many times signing will retry before giving up.
///
/// Rejection is expected — the parameters aim for a handful of iterations — so
/// a cap this high is only ever reached by a bug or by a caller feeding a
/// broken key. Looping forever would turn that into a hang instead of an error.
const MAX_ATTEMPTS: usize = 1000;

/// `H`: SHAKE-256 over the concatenation of `parts`.
fn h(parts: &[&[u8]], out: &mut [u8]) {
    let mut x = Shake256::default();
    for part in parts {
        <Shake256 as Xof>::update(&mut x, part);
    }
    x.finalize_xof(out);
}

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

/// `M'` for the pure variant: a domain byte, the context length, the context,
/// then the message.
///
/// The two leading bytes are what keep a pure signature from colliding with a
/// pre-hashed one over the same message, so they are not optional framing.
fn message_prefix(domain: u8, ctx: &[u8]) -> ([u8; 2], bool) {
    ([domain, ctx.len() as u8], ctx.len() <= 255)
}

/// The pieces of `M'`, assembled without allocating.
///
/// `mu` is hashed over `tr`, the two framing bytes, the context and then
/// whatever the variant contributes. There is no `Vec` here, so the parts are
/// gathered into a fixed array; four is the most any variant needs, and the
/// assertion says so rather than silently truncating a fifth.
struct Framed<'a> {
    parts: [&'a [u8]; 5],
    len: usize,
}

impl<'a> Framed<'a> {
    fn new(tr: &'a [u8], prefix: &'a [u8], ctx: &'a [u8], rest: &[&'a [u8]]) -> Self {
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

    fn as_slice(&self) -> &[&'a [u8]] {
        &self.parts[..self.len]
    }
}

/// The domain byte for the pure variant, which signs the message itself.
const DOMAIN_PURE: u8 = 0;

/// The domain byte for the pre-hash variant.
const DOMAIN_PREHASH: u8 = 1;

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
const MAX_DIGEST: usize = 64;

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
    fn digest(self, message: &[u8]) -> ([u8; MAX_DIGEST], usize) {
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
        bit_pack(p, ETA, ETA4_BITS, &mut sk[at..at + S_LEN]);
        at += S_LEN;
    }
    for p in s2.iter() {
        bit_pack(p, ETA, ETA4_BITS, &mut sk[at..at + S_LEN]);
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
        bit_unpack(&sk[at..at + S_LEN], ETA, ETA4_BITS, p);
        at += S_LEN;
    }
    for p in out.s2.iter_mut() {
        bit_unpack(&sk[at..at + S_LEN], ETA, ETA4_BITS, p);
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
pub fn sign_deterministic(
    sk: &[u8; SECRET_KEY_LEN],
    message: &[u8],
    ctx: &[u8],
    sig: &mut [u8; SIGNATURE_LEN],
) -> bool {
    sign(sk, message, ctx, &[0u8; 32], sig)
}

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
