//! FIPS 186-5 ECDSA over the NIST prime curves, with RFC 6979 nonces.
//!
//! # Deterministic nonces
//!
//! ECDSA's notorious failure mode is the signing nonce `k`: reuse it across two
//! signatures, or let an attacker predict a few bits, and the private key falls
//! out by simple algebra. This has broken real systems repeatedly (the PS3, and
//! several Bitcoin wallets).
//!
//! Signing here derives `k` deterministically from the private key and the
//! message, per [RFC 6979](https://www.rfc-editor.org/rfc/rfc6979). There is no
//! RNG in the signing path, so there is no entropy failure that can produce a
//! repeated nonce — the same class of protection Ed25519 gets by construction.
//! It also makes signatures reproducible, which is why the RFC's published
//! vectors serve as known-answer tests for the whole stack beneath.
//!
//! # Pairing a curve with a hash
//!
//! Each instantiation fixes the hash at the curve's security level: SHA-256
//! with P-256, SHA-384 with P-384. For both, the hash output and the group
//! order are the same width, so RFC 6979's bit-length juggling collapses to a
//! straight reduction.

use super::arith::Field;
use super::point::{AffinePoint, Curve, Point};
use ic_core::traits::internal::Digest;
use ic_core::traits::internal::Mac;
use ic_core::{ensure, Result, Zeroize};

/// A curve paired with the hash and MAC its signatures use.
pub trait EcdsaCurve: Curve + crate::nist::gentable::HasGeneratorTable {
    /// The message digest, at the curve's security level.
    type Digest: Digest;
    /// HMAC over the same digest, for RFC 6979. `Clone`, so a key set up
    /// once serves the two MACs RFC 6979 computes under each `K`.
    type Hmac: Mac + Clone;

    /// `s^-1 mod n` for verification's public `s`. The ring's own inversion
    /// unless the curve has a faster one; P-384's ring inverts by Fermat,
    /// and verification uses divsteps instead. Signing's `k^-1` does not
    /// come here.
    fn invert_public_scalar(s: &Self::Scalar) -> Self::Scalar {
        s.invert()
    }
}

/// Widest scalar this module handles, for stack buffers.
const MAX_SCALAR: usize = 66;

/// Widest `T` accumulator RFC 6979 can need, in bytes.
///
/// `T` grows by one HMAC output per round until it covers `qlen` bits. The
/// worst case here is P-521: HMAC-SHA-512 gives 512 bits a round and the order
/// is 521, so it takes two rounds and 128 bytes.
const MAX_T: usize = 128;

/// RFC 6979 `bits2int`: keep the leftmost `order_bits` bits of `t`.
///
/// When `t` is at least as wide as the order, that means taking the first
/// `ceil(order_bits / 8)` bytes and shifting right by however many bits the
/// byte boundary overshot. For P-256 and P-384 the overshoot is zero and this
/// is a straight copy; for P-521 it is seven bits, and skipping the shift would
/// produce nonces that are wrong by a factor of 128 — which still verifies
/// against itself and against nothing else.
fn bits2int(t: &[u8], order_bits: usize, out: &mut [u8]) {
    let m = order_bits.div_ceil(8);
    let shift = m * 8 - order_bits;
    for i in 0..m {
        let hi = if i == 0 { 0 } else { t[i - 1] };
        let carry = if shift == 0 { 0 } else { hi << (8 - shift) };
        out[i] = (t[i] >> shift) | carry;
    }
}

/// Derive the RFC 6979 nonce for a given attempt.
///
/// The `K`/`V` state machine is run from scratch and advanced `attempt` times,
/// so a rejected candidate (`r == 0` or `s == 0`) moves to the next one exactly
/// as the RFC specifies. Those rejections have negligible probability, so the
/// loop exists for correctness rather than speed.
fn rfc6979_nonce<C: EcdsaCurve>(
    private_key: &[u8],
    h1: &[u8],
    attempt: usize,
) -> Result<C::Scalar> {
    let n = C::SCALAR_BYTES;
    ensure!(n <= MAX_SCALAR, InvalidParameter, "scalar too wide");

    // bits2octets(h1): reduce the hash modulo n, then re-encode.
    let e = C::scalar_reduce_slice(h1);
    let e_octets = e.to_bytes();
    let e_octets = e_octets.as_ref();

    let tag_len = <C::Hmac as Mac>::TAG_LEN;
    let mut v_buf = [0x01u8; MAX_SCALAR];
    let mut k_buf = [0x00u8; MAX_SCALAR];
    let v = &mut v_buf[..tag_len];
    let k = &mut k_buf[..tag_len];

    // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    let mut mac = C::Hmac::new(k)?;
    mac.update(v);
    mac.update(&[0x00]);
    mac.update(private_key);
    mac.update(e_octets);
    k.copy_from_slice(mac.finalize().as_ref());
    // Each K is used for two MACs in a row: V = HMAC_K(V), then the next K
    // or a block of T. Its key setup -- two compressions -- is done once
    // and the keyed state cloned for each.
    let mut keyed = C::Hmac::new(k)?;
    let mut mac = keyed.clone();
    mac.update(v);
    v.copy_from_slice(mac.finalize().as_ref());

    // K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    let mut mac = keyed.clone();
    mac.update(v);
    mac.update(&[0x01]);
    mac.update(private_key);
    mac.update(e_octets);
    k.copy_from_slice(mac.finalize().as_ref());
    keyed = C::Hmac::new(k)?;
    let mut mac = keyed.clone();
    mac.update(v);
    v.copy_from_slice(mac.finalize().as_ref());

    let mut found = 0usize;
    let mut t_buf = [0u8; MAX_T];
    let mut candidate_buf = [0u8; MAX_SCALAR];

    // Bounded so a pathological key cannot spin forever.
    for _ in 0..(attempt + 1) * 8 + 16 {
        // RFC 6979 3.2 step h: T = T || HMAC_K(V) until T covers qlen bits,
        // then k = bits2int(T). One round is enough for P-256 and P-384, where
        // the HMAC output is exactly the order width; P-521 needs two, because
        // SHA-512 gives 512 bits against a 521-bit order.
        let mut tlen = 0usize;
        while tlen * 8 < C::ORDER_BITS {
            let mut mac = keyed.clone();
            mac.update(v);
            v.copy_from_slice(mac.finalize().as_ref());
            let take = core::cmp::min(tag_len, MAX_T - tlen);
            t_buf[tlen..tlen + take].copy_from_slice(&v[..take]);
            tlen += take;
        }
        bits2int(&t_buf[..tlen], C::ORDER_BITS, &mut candidate_buf);

        // Accept only a canonical, non-zero scalar.
        if let Some(candidate) = C::scalar_from_slice(&candidate_buf[..n]) {
            if !bool::from(candidate.is_zero()) {
                if found == attempt {
                    k_buf.zeroize();
                    v_buf.zeroize();
                    t_buf.zeroize();
                    candidate_buf.zeroize();
                    return Ok(candidate);
                }
                found += 1;
            }
        }

        // K = HMAC_K(V || 0x00); V = HMAC_K(V)
        let mut mac = keyed.clone();
        mac.update(v);
        mac.update(&[0x00]);
        k.copy_from_slice(mac.finalize().as_ref());
        keyed = C::Hmac::new(k)?;
        let mut mac = keyed.clone();
        mac.update(v);
        v.copy_from_slice(mac.finalize().as_ref());
    }

    k_buf.zeroize();
    v_buf.zeroize();
    t_buf.zeroize();
    candidate_buf.zeroize();
    Err(ic_core::err!(
        Internal,
        "rfc6979 nonce generation did not converge"
    ))
}

/// Load a private key, rejecting zero and anything at or above `n`.
fn load_private_key<C: Curve>(bytes: &[u8]) -> Result<C::Scalar> {
    ensure!(
        bytes.len() == C::SCALAR_BYTES,
        InvalidLength,
        "ecdsa private key"
    );
    let d = C::scalar_from_slice(bytes).ok_or(ic_core::err!(
        InvalidParameter,
        "ecdsa private key is not less than n"
    ))?;
    ensure!(
        !bool::from(d.is_zero()),
        InvalidParameter,
        "ecdsa private key must not be zero"
    );
    Ok(d)
}

/// Compute the public key, SEC1 uncompressed.
pub fn public_key<C: EcdsaCurve>(private_key: &[u8], out: &mut [u8]) -> Result<()> {
    ic_core::module::operational()?;
    ensure!(
        out.len() == 1 + 2 * C::FIELD_BYTES,
        InvalidLength,
        "ecdsa public key buffer"
    );
    let d = load_private_key::<C>(private_key)?;
    let q = Point::<C>::mul_generator(&d)
        .to_affine()
        .ok_or(ic_core::err!(Internal, "public key is the identity"))?;
    // See the note in `ecdh::public_key`: the length check above and the
    // encoder must agree, and this is what says so if they stop.
    ensure!(
        q.write_uncompressed(out),
        Internal,
        "public key buffer length disagrees with the encoder"
    );
    Ok(())
}

/// Compute the public key, SEC1 compressed.
pub fn public_key_compressed<C: EcdsaCurve>(private_key: &[u8], out: &mut [u8]) -> Result<()> {
    ic_core::module::operational()?;
    ensure!(
        out.len() == 1 + C::FIELD_BYTES,
        InvalidLength,
        "ecdsa compressed key buffer"
    );
    let d = load_private_key::<C>(private_key)?;
    let q = Point::<C>::mul_generator(&d)
        .to_affine()
        .ok_or(ic_core::err!(Internal, "public key is the identity"))?;
    ensure!(
        q.write_compressed(out),
        Internal,
        "compressed key buffer length disagrees with the encoder"
    );
    Ok(())
}

/// Sign `message`, writing fixed-width `r || s`.
pub fn sign<C: EcdsaCurve>(private_key: &[u8], message: &[u8], signature: &mut [u8]) -> Result<()> {
    ic_core::module::operational()?;
    let n = C::SCALAR_BYTES;
    ensure!(
        signature.len() == 2 * n,
        InvalidLength,
        "ecdsa signature buffer"
    );
    let d = load_private_key::<C>(private_key)?;

    let digest = C::Digest::digest(message);
    let h1 = digest.as_ref();
    let e = C::scalar_reduce_slice(h1);

    // Both rejections below have negligible probability; the loop is here so
    // that "negligible" never becomes "silently wrong".
    for attempt in 0..8 {
        let k = rfc6979_nonce::<C>(private_key, h1, attempt)?;

        let x = Point::<C>::mul_generator(&k)
            .to_affine_x()
            .ok_or(ic_core::err!(Internal, "kG is the identity"))?;
        let r = C::scalar_reduce_slice(x.to_bytes().as_ref());
        if bool::from(r.is_zero()) {
            continue;
        }

        // s = k^-1 (e + r*d)
        let s = k.invert().mul(&e.add(&r.mul(&d)));
        if bool::from(s.is_zero()) {
            continue;
        }

        signature[..n].copy_from_slice(r.to_bytes().as_ref());
        signature[n..].copy_from_slice(s.to_bytes().as_ref());
        return Ok(());
    }

    Err(ic_core::err!(Internal, "ecdsa signing did not converge"))
}

/// Verify a fixed-width `r || s` signature.
pub fn verify<C: EcdsaCurve>(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    ic_core::module::operational()?;
    let digest = C::Digest::digest(message);
    verify_digest::<C>(public_key, digest.as_ref(), signature)
}

/// Digest widths `verify_prehash` accepts, on every curve (for instance
/// [`crate::p256::EcdsaP256Sha256::verify_prehash`]): those of SHA-224, SHA-256,
/// SHA-384 and SHA-512, and of SHA-3 and SHA-512/t at the same widths.
///
/// SHA-1's 20 bytes are not among them. This library implements no SHA-1 and
/// registers it as excluded, and accepting its width here would make this the
/// one way to verify a signature over it.
pub const PREHASH_LENS: [usize; 4] = [28, 32, 48, 64];

/// Verify a fixed-width `r || s` signature over a digest the caller computed.
///
/// For signatures made with a hash other than the curve's own, which X.509 and
/// other protocols allow: P-384 with SHA-512, P-256 with SHA-384. The digest is
/// turned into the scalar `e` as FIPS 186-5 section 6.4.2 specifies, by taking
/// its leftmost bits up to the width of the group order; for every width in
/// [`PREHASH_LENS`] that is the leftmost bytes, which `scalar_reduce_slice`
/// takes.
///
/// The digest must also be at least as wide as the curve's strength demands:
/// 32 bytes on P-256, 48 on P-384, 64 on P-521. A narrower one would make the
/// hash the weakest part of the signature -- SHA-224 under P-521 is 112-bit
/// collision resistance under a 256-bit key -- and SP 800-57 asks for a hash at
/// least as strong as the key. That rule is enforced here rather than left to
/// the caller, because the digest's width is the one thing about it this
/// function can see.
///
/// Which hash produced the digest is still the caller's to establish: a
/// 64-byte BLAKE2b digest is as wide as SHA-512's, and nothing here can tell
/// them apart.
pub fn verify_prehash<C: EcdsaCurve>(
    public_key: &[u8],
    digest: &[u8],
    signature: &[u8],
) -> Result<()> {
    ic_core::module::operational()?;
    ensure!(
        PREHASH_LENS.contains(&digest.len()),
        InvalidLength,
        "ecdsa digest must be 28, 32, 48 or 64 bytes"
    );
    ensure!(
        digest.len() >= min_prehash_len::<C>(),
        InvalidLength,
        "ecdsa digest narrower than the curve's strength"
    );
    verify_digest::<C>(public_key, digest, signature)
}

/// The narrowest digest `verify_prehash` accepts on `C`: as wide as the
/// order, or SHA-512's 64 bytes where the order is wider (P-521).
pub fn min_prehash_len<C: EcdsaCurve>() -> usize {
    core::cmp::min(C::SCALAR_BYTES, 64)
}

/// The verification both entry points share, from the digest onwards.
fn verify_digest<C: EcdsaCurve>(public_key: &[u8], digest: &[u8], signature: &[u8]) -> Result<()> {
    let n = C::SCALAR_BYTES;
    ensure!(signature.len() == 2 * n, InvalidLength, "ecdsa signature");

    let q = AffinePoint::<C>::from_sec1(public_key).ok_or(ic_core::err!(
        MalformedEncoding,
        "ecdsa public key is not a curve point"
    ))?;

    // r and s must both be canonical and non-zero. A non-canonical encoding is
    // rejected rather than reduced, so a signature has exactly one valid byte
    // representation.
    let r = C::scalar_from_slice(&signature[..n]).ok_or(ic_core::err!(
        MalformedEncoding,
        "ecdsa r is not less than n"
    ))?;
    let s = C::scalar_from_slice(&signature[n..]).ok_or(ic_core::err!(
        MalformedEncoding,
        "ecdsa s is not less than n"
    ))?;
    ensure!(
        !bool::from(r.is_zero()) && !bool::from(s.is_zero()),
        MalformedEncoding,
        "ecdsa r and s must be non-zero"
    );

    let e = C::scalar_reduce_slice(digest);

    let w = C::invert_public_scalar(&s);
    let u1 = e.mul(&w);
    let u2 = r.mul(&w);

    let point = Point::<C>::mul_double(&u1, &Point::<C>::from_affine(&q), &u2);

    // The signature is valid when x(point) mod n = r, x in [0, p). Every
    // curve here has n < p < 2n, so that is x = r, or x = r + n where r + n
    // is below p; both are checked against the Jacobian X as x * Z^2 = X,
    // which saves the inversion to affine. Everything here is public.
    let r_bytes = r.to_bytes();
    let mut xs = [C::Field::ZERO; 2];
    let mut count = 0;
    if let Some(x) = C::field_from_slice(r_bytes.as_ref()) {
        xs[count] = x;
        count += 1;
    }
    if let Some(x) = r_plus_n::<C>(r_bytes.as_ref()).and_then(|b| C::field_from_slice(&b[..n])) {
        xs[count] = x;
        count += 1;
    }
    if point.x_is_one_of_vartime(&xs[..count]) {
        Ok(())
    } else {
        Err(ic_core::err!(AuthenticationFailed, "ecdsa"))
    }
}

/// `r + n` as big-endian bytes of the scalar width, or `None` if it does not
/// fit. `n` is `-1 + 1` in the scalar ring's encoding, added back by hand.
fn r_plus_n<C: Curve>(r: &[u8]) -> Option<[u8; MAX_SCALAR]> {
    let len = r.len();
    let n_minus_1 = C::Scalar::ZERO.sub(&C::Scalar::ONE).to_bytes();
    let n_minus_1 = n_minus_1.as_ref();
    let mut out = [0u8; MAX_SCALAR];
    // r + (n - 1) + 1, least significant byte first.
    let mut carry = 1u16;
    for i in (0..len).rev() {
        let s = r[i] as u16 + n_minus_1[i] as u16 + carry;
        out[i] = s as u8;
        carry = s >> 8;
    }
    (carry == 0).then_some(out)
}

/// Whether `s` is above `n/2`.
fn is_high_s<C: Curve>(s: &C::Scalar) -> bool {
    let bytes = s.to_bytes();
    let bytes = bytes.as_ref();

    // n/2, by shifting the modulus encoding right one bit.
    let n_bytes = C::Scalar::ZERO.sub(&C::Scalar::ONE).to_bytes();
    let n_bytes = n_bytes.as_ref();
    // `n - 1` encoded; adding one back gives n, but the top bit of n/2 is what
    // matters and n is odd, so (n-1)/2 == n/2 rounded down.
    let mut half = [0u8; MAX_SCALAR];
    let len = n_bytes.len();
    let mut carry = 0u8;
    for i in 0..len {
        let v = n_bytes[i];
        half[i] = (v >> 1) | (carry << 7);
        carry = v & 1;
    }

    // Compare big-endian, most significant byte first. Both operands are public
    // wherever this is called.
    for i in 0..len {
        if bytes[i] != half[i] {
            return bytes[i] > half[i];
        }
    }
    false
}

/// Rewrite a signature to its low-`s` form, if it is not already.
///
/// ECDSA is malleable: `(r, s)` and `(r, n - s)` are both valid for the same
/// message, so a signature is not a unique identifier unless one form is
/// chosen. FIPS 186-5 and RFC 6979 accept both, and this library signs and
/// verifies per the standard, so normalization is offered rather than imposed —
/// apply it when a signature doubles as a database key or a transaction id.
pub fn normalize_s<C: EcdsaCurve>(signature: &mut [u8]) -> Result<()> {
    let n = C::SCALAR_BYTES;
    ensure!(signature.len() == 2 * n, InvalidLength, "ecdsa signature");
    let s = C::scalar_from_slice(&signature[n..]).ok_or(ic_core::err!(
        MalformedEncoding,
        "ecdsa s is not less than n"
    ))?;
    if is_high_s::<C>(&s) {
        let flipped = C::Scalar::ZERO.sub(&s);
        signature[n..].copy_from_slice(flipped.to_bytes().as_ref());
    }
    Ok(())
}

/// Whether a signature is already in low-`s` form.
pub fn has_low_s<C: EcdsaCurve>(signature: &[u8]) -> Result<bool> {
    let n = C::SCALAR_BYTES;
    ensure!(signature.len() == 2 * n, InvalidLength, "ecdsa signature");
    let s = C::scalar_from_slice(&signature[n..]).ok_or(ic_core::err!(
        MalformedEncoding,
        "ecdsa s is not less than n"
    ))?;
    Ok(!is_high_s::<C>(&s))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::p256::P256;
    use crate::p384::P384;

    /// RFC 6979 section 3.2, steps b to h, transcribed for widths where the
    /// HMAC output is the order's (P-256, P-384): every MAC set up from its
    /// key afresh, as the text reads, and the candidate after `attempt`
    /// rejections returned as bytes. It shares nothing with `rfc6979_nonce`
    /// but the HMAC.
    fn reference<C: EcdsaCurve>(x: &[u8], h1: &[u8], attempt: usize) -> std::vec::Vec<u8> {
        let mac = |key: &[u8], parts: &[&[u8]]| -> std::vec::Vec<u8> {
            let mut m = C::Hmac::new(key).unwrap();
            for p in parts {
                m.update(p);
            }
            m.finalize().as_ref().to_vec()
        };
        let hlen = <C::Hmac as Mac>::TAG_LEN;
        let e = C::scalar_reduce_slice(h1).to_bytes();
        let mut v = std::vec![0x01u8; hlen];
        let mut k = std::vec![0x00u8; hlen];
        k = mac(&k, &[&v, &[0x00], x, e.as_ref()]);
        v = mac(&k, &[&v]);
        k = mac(&k, &[&v, &[0x01], x, e.as_ref()]);
        v = mac(&k, &[&v]);
        let mut seen = 0;
        loop {
            v = mac(&k, &[&v]);
            let candidate = v.clone();
            let ok = C::scalar_from_slice(&candidate).is_some_and(|c| !bool::from(c.is_zero()));
            if ok {
                if seen == attempt {
                    return candidate;
                }
                seen += 1;
            }
            k = mac(&k, &[&v, &[0x00]]);
            v = mac(&k, &[&v]);
        }
    }

    /// The nonce, and the nonces after one, two and three rejections --
    /// which signing asks for only when `r` or `s` is zero, and so which no
    /// published vector reaches -- against the transcription.
    fn nonces_agree<C: EcdsaCurve>() {
        let x = std::vec![0x5au8; C::SCALAR_BYTES];
        for msg in [&b"sample"[..], b"test", b""] {
            let h1 = C::Digest::digest(msg);
            for attempt in 0..4 {
                let got = rfc6979_nonce::<C>(&x, h1.as_ref(), attempt).unwrap();
                let want = reference::<C>(&x, h1.as_ref(), attempt);
                assert_eq!(got.to_bytes().as_ref(), &want[..], "attempt {attempt}");
            }
        }
    }

    #[test]
    fn nonces_after_rejection_follow_rfc_6979() {
        nonces_agree::<P256>();
        nonces_agree::<P384>();
    }

    /// Where a verification's time goes, piece by piece, on whichever
    /// backend this CPU and build select. A measurement, not a check: run
    /// with `cargo test --release -p ic-ec -- --ignored --nocapture
    /// where_verification_spends_its_time`, and with `RUSTFLAGS="--cfg
    /// ic_no_avx512"` for the MULX/ADX path on a CPU with AVX-512.
    #[test]
    #[ignore = "timing; run manually with --release"]
    fn where_verification_spends_its_time() {
        fn ns(label: &str, iters: u32, mut f: impl FnMut()) {
            use std::time::Instant;
            let mut best = f64::INFINITY;
            for _ in 0..9 {
                let t = Instant::now();
                for _ in 0..iters {
                    f();
                }
                best = best.min(t.elapsed().as_secs_f64() * 1e9 / iters as f64);
            }
            std::println!("{label:40} {best:10.1} ns");
        }
        fn curve<C: EcdsaCurve>() {
            use core::hint::black_box;
            std::println!("{}", C::NAME);
            let n = C::SCALAR_BYTES;
            let key = std::vec![0x5au8; n];
            let mut pk = std::vec![0u8; 1 + 2 * C::FIELD_BYTES];
            public_key::<C>(&key, &mut pk).unwrap();
            let mut sig = std::vec![0u8; 2 * n];
            sign::<C>(&key, b"message", &mut sig).unwrap();
            C::prepare_generator_table();
            ns("verify", 300, || {
                verify::<C>(black_box(&pk), b"message", black_box(&sig)).unwrap();
            });
            ns("digest", 3000, || {
                black_box(C::Digest::digest(black_box(b"message")));
            });
            ns("decode public key", 3000, || {
                black_box(AffinePoint::<C>::from_sec1(black_box(&pk)));
            });
            let s = C::scalar_from_slice(&sig[n..]).unwrap();
            let r = C::scalar_from_slice(&sig[..n]).unwrap();
            ns("s^-1 mod n", 3000, || {
                black_box(C::invert_public_scalar(&black_box(s)));
            });
            let w = s.invert();
            let u1 = r.mul(&w).mul(&w);
            let u2 = r.mul(&w);
            ns("u1, u2", 30000, || {
                black_box(black_box(r).mul(&black_box(w)));
            });
            let q = Point::<C>::from_affine(&AffinePoint::<C>::from_sec1(&pk).unwrap());
            ns("mul_double", 300, || {
                black_box(Point::<C>::mul_double(&black_box(u1), &q, &black_box(u2)));
            });
            {
                use super::super::point::wnaf_vartime;
                use super::super::verify::{
                    joint_vartime, odd_multiples_affine_vartime, G_WIDTH, Q_ODD, Q_WIDTH,
                };
                ns("  Q's odd multiples, affine", 3000, || {
                    black_box(odd_multiples_affine_vartime::<C, Q_ODD>(&black_box(q)));
                });
                let qt: [AffinePoint<C>; Q_ODD] = odd_multiples_affine_vartime(&q);
                let gt = C::odd_generator_multiples();
                let (ab, bb) = (u1.to_bytes(), u2.to_bytes());
                ns("  both non-adjacent forms", 3000, || {
                    black_box(wnaf_vartime(black_box(ab.as_ref()), G_WIDTH));
                    black_box(wnaf_vartime(black_box(bb.as_ref()), Q_WIDTH));
                });
                let (gn, gl) = wnaf_vartime(ab.as_ref(), G_WIDTH);
                let (qn, ql) = wnaf_vartime(bb.as_ref(), Q_WIDTH);
                let len = gl.max(ql);
                let adds = gn[..len]
                    .iter()
                    .chain(&qn[..len])
                    .filter(|d| **d != 0)
                    .count();
                std::println!("  {len} doublings, {adds} additions");
                ns("  the chain, fast where there is one", 300, || {
                    black_box(
                        C::mul_double_vartime_fast(gt, &qt, &gn[..len], &qn[..len])
                            .unwrap_or_else(Point::identity),
                    );
                });
                ns("  the chain, field operations", 300, || {
                    black_box(joint_vartime(gt, &qt, &gn[..len], &qn[..len]));
                });
            }
            ns("  u1 * G, table, vartime", 1000, || {
                black_box(Point::<C>::mul_generator_vartime(&black_box(u1)));
            });
            ns("  u2 * Q, wNAF 5", 300, || {
                black_box(black_box(q).mul_scalar_vartime(&black_box(u2)));
            });
            let p = q.double();
            ns("  double", 30000, || {
                black_box(black_box(p).double());
            });
            ns("  add_vartime", 30000, || {
                black_box(black_box(p).add_vartime(&black_box(q)));
            });
            let qa = AffinePoint::<C>::from_sec1(&pk).unwrap();
            ns("  add_affine_vartime", 30000, || {
                black_box(black_box(p).add_affine_vartime(&black_box(qa.x), &black_box(qa.y)));
            });
            ns("  field inversion", 3000, || {
                black_box(black_box(qa.x).invert());
            });
            let x = qa.x;
            ns("x_is_one_of_vartime", 30000, || {
                black_box(black_box(p).x_is_one_of_vartime(&[black_box(x), black_box(x)]));
            });
        }
        curve::<P256>();
        curve::<P384>();
    }
}
