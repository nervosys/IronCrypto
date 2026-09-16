//! ML-KEM-768 (FIPS 203) — **experimental, not interoperability-tested**.
//!
//! # Read this first
//!
//! Everything below assembles components that each have an independent oracle:
//! the ring arithmetic against schoolbook multiplication, the packing against a
//! bit buffer, the samplers against the specification's pseudocode, SHAKE and
//! SHA-3 against published FIPS 202 vectors. The assembly itself has none. No
//! ACVP vector is wired in, and a KEM whose matrix indices are transposed, or
//! whose hash inputs are ordered differently, still encapsulates and
//! decapsulates against itself perfectly.
//!
//! So this is registered as `Experimental` in the ontology, excluded from the
//! FIPS approved mode, and absent from `recommend()`. Do not use it to talk to
//! another implementation. Wire in an ACVP vector first; the components are in
//! place, so that is a short job for whoever has one.
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

use crate::encode::{byte_decode, byte_encode, compress_encode, decode_decompress, encoded_len};
use crate::poly::Poly;
use crate::sample::{sample_noise, sample_ntt};
use ac_core::traits::{Digest, RandomSource, Xof};
use ac_core::{ensure, Result, Zeroize};
use ac_hash::{Sha3_256, Sha3_512, Shake256};

/// Module rank. Three is ML-KEM-768.
pub const K: usize = 3;
/// Noise width for the secret and the first error term.
const ETA1: usize = 2;
/// Noise width for the second error term.
const ETA2: usize = 2;
/// Compression width for the ciphertext's vector part.
const DU: u32 = 10;
/// Compression width for the ciphertext's scalar part.
const DV: u32 = 4;

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

/// `G(x) = SHA3-512(x)`, split into two 32-byte halves.
fn g(parts: &[&[u8]]) -> ([u8; 32], [u8; 32]) {
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
fn h(data: &[u8]) -> [u8; 32] {
    let out = Sha3_256::digest(data);
    let mut a = [0u8; 32];
    a.copy_from_slice(out.as_ref());
    a
}

/// `J(x) = SHAKE256(x, 32)`, the implicit-rejection key derivation.
fn j(parts: &[&[u8]]) -> [u8; 32] {
    let mut x = Shake256::default();
    for part in parts {
        <Shake256 as Xof>::update(&mut x, part);
    }
    let mut out = [0u8; 32];
    x.finalize_xof(&mut out);
    out
}

/// Build the public matrix. `transposed` selects `A` or `A^T`.
///
/// The index order is the classic place to go wrong: FIPS 203 defines
/// `A[i][j] = SampleNTT(rho || j || i)`, with `j` *before* `i` in the seed. A
/// build that swaps them produces a matrix that is the transpose of the
/// intended one, key generation and encryption still agree with each other, and
/// nothing else in the world can decrypt the result.
///
/// The loops are written with explicit indices precisely because of that: the
/// whole correctness question here is which index goes where, and iterator form
/// would hide it.
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

/// Multiply a matrix by a vector in the transform domain.
///
/// Indexed rather than iterated, to keep the row/column roles visible.
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

/// Inner product of two transform-domain vectors.
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
        let mut normalized = *p;
        normalized.normalize();
        byte_encode(&normalized, 12, &mut out[i * 384..(i + 1) * 384]);
    }
}

fn decode_vector(data: &[u8]) -> Vector {
    let mut v = zero_vector();
    for (i, p) in v.iter_mut().enumerate() {
        byte_decode(&data[i * 384..(i + 1) * 384], 12, p);
    }
    v
}

/// K-PKE key generation from a 32-byte seed.
fn pke_keygen(d: &[u8; 32], ek: &mut [u8], dk: &mut [u8]) {
    // FIPS 203 appends the module rank so that the three parameter sets cannot
    // produce the same expansion from the same seed.
    let (rho, sigma) = g(&[d, &[K as u8]]);

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

    // t = A o s + e, with the Montgomery factor from basemul put back.
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

/// K-PKE encryption. `m` is 32 bytes, `r` is the 32-byte coin.
fn pke_encrypt(ek: &[u8], m: &[u8; 32], r: &[u8; 32], out: &mut [u8]) {
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

    // u = InvNTT(A^T o y) + e1
    let mut u = matrix_mul(&at, &y);
    for (ui, ei) in u.iter_mut().zip(e1.iter()) {
        ui.inv_ntt();
        *ui = ui.add(ei);
        ui.reduce();
    }

    // v = InvNTT(t^T o y) + e2 + Decompress_1(m)
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

/// K-PKE decryption, recovering the 32-byte message.
fn pke_decrypt(dk: &[u8], ct: &[u8]) -> [u8; 32] {
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

/// ML-KEM-768.
pub struct MlKem768;

impl MlKem768 {
    /// Generate a key pair.
    pub fn keygen<R: RandomSource + ?Sized>(
        rng: &mut R,
        ek: &mut [u8; ENCAPS_KEY_LEN],
        dk: &mut [u8; DECAPS_KEY_LEN],
    ) -> Result<()> {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        rng.fill(&mut d)?;
        rng.fill(&mut z)?;
        Self::keygen_deterministic(&d, &z, ek, dk);
        d.zeroize();
        z.zeroize();
        Ok(())
    }

    /// Generate a key pair from explicit seeds.
    ///
    /// Exposed because it is the only way to test the scheme reproducibly, and
    /// because ACVP vectors are specified this way. Production callers should
    /// use [`MlKem768::keygen`].
    pub fn keygen_deterministic(
        d: &[u8; 32],
        z: &[u8; 32],
        ek: &mut [u8; ENCAPS_KEY_LEN],
        dk: &mut [u8; DECAPS_KEY_LEN],
    ) {
        pke_keygen(d, ek, &mut dk[..384 * K]);
        dk[384 * K..384 * K + ENCAPS_KEY_LEN].copy_from_slice(ek);
        let hash = h(ek);
        dk[384 * K + ENCAPS_KEY_LEN..384 * K + ENCAPS_KEY_LEN + 32].copy_from_slice(&hash);
        dk[384 * K + ENCAPS_KEY_LEN + 32..].copy_from_slice(z);
    }

    /// Encapsulate, producing a shared secret and a ciphertext.
    pub fn encapsulate<R: RandomSource + ?Sized>(
        rng: &mut R,
        ek: &[u8; ENCAPS_KEY_LEN],
        ct: &mut [u8; CIPHERTEXT_LEN],
        shared: &mut [u8; SHARED_SECRET_LEN],
    ) -> Result<()> {
        let mut m = [0u8; 32];
        rng.fill(&mut m)?;
        Self::encapsulate_deterministic(&m, ek, ct, shared);
        m.zeroize();
        Ok(())
    }

    /// Encapsulate with an explicit message, for tests and vectors.
    pub fn encapsulate_deterministic(
        m: &[u8; 32],
        ek: &[u8; ENCAPS_KEY_LEN],
        ct: &mut [u8; CIPHERTEXT_LEN],
        shared: &mut [u8; SHARED_SECRET_LEN],
    ) {
        let (k, r) = g(&[m, &h(ek)]);
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
        let dk_pke = &dk[..384 * K];
        let ek: &[u8; ENCAPS_KEY_LEN] = dk[384 * K..384 * K + ENCAPS_KEY_LEN]
            .try_into()
            .map_err(|_| ac_core::err!(Internal, "decapsulation key layout"))?;
        let hash = &dk[384 * K + ENCAPS_KEY_LEN..384 * K + ENCAPS_KEY_LEN + 32];
        let z = &dk[384 * K + ENCAPS_KEY_LEN + 32..];

        let m = pke_decrypt(dk_pke, ct);
        let (k, r) = g(&[&m, hash]);
        let reject = j(&[z, ct]);

        let mut recomputed = [0u8; CIPHERTEXT_LEN];
        pke_encrypt(ek, &m, &r, &mut recomputed);

        // Constant-time select: the comparison result must not be observable
        // through timing, or the implicit rejection leaks exactly what it is
        // meant to hide.
        let matched = ac_core::ct::eq(&recomputed, ct);
        for (i, out) in shared.iter_mut().enumerate() {
            *out = ac_core::ct::select_u8(matched, k[i], reject[i]);
        }
        recomputed.zeroize();
        Ok(())
    }

    /// Check that an encapsulation key is well formed.
    ///
    /// FIPS 203 requires that `ByteDecode12` of the key round-trips, which
    /// rejects keys whose coefficients are at or above `q`. Without this a
    /// malformed key is silently reinterpreted.
    pub fn validate_encapsulation_key(ek: &[u8; ENCAPS_KEY_LEN]) -> Result<()> {
        let t = decode_vector(&ek[..384 * K]);
        let mut round = [0u8; 384 * K];
        encode_vector(&t, &mut round);
        ensure!(
            round == ek[..384 * K],
            MalformedEncoding,
            "encapsulation key is not canonically encoded"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rng(label: &[u8]) -> ac_drbg::Rng {
        ac_drbg::Rng::from_entropy(&[0x5au8; 32], label).unwrap()
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
