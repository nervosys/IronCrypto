//! SP 800-56A elliptic-curve Diffie-Hellman over the NIST prime curves.
//!
//! The shared secret is the x-coordinate of `[d]Q`, as SP 800-56A §5.7.1.2
//! specifies. It is **not** a key: it is a field element that must go through a
//! KDF before use. The ontology records that as a `serious` constraint.

use super::arith::Field;
use super::gentable::{Comb, HasGeneratorTable};
use super::point::{AffinePoint, Curve, Point};
use ic_core::{ensure, Result};

/// Load and validate a private scalar.
fn load_scalar<C: Curve>(bytes: &[u8]) -> Result<C::Scalar> {
    ensure!(
        bytes.len() == C::SCALAR_BYTES,
        InvalidLength,
        "ecdh private key"
    );
    let d = C::scalar_from_slice(bytes).ok_or(ic_core::err!(
        InvalidParameter,
        "ecdh private key is not less than n"
    ))?;
    ensure!(
        !bool::from(d.is_zero()),
        InvalidParameter,
        "ecdh private key must not be zero"
    );
    Ok(d)
}

/// Compute the public key, SEC1 uncompressed.
pub fn public_key<C: HasGeneratorTable>(private_key: &[u8], out: &mut [u8]) -> Result<()> {
    ic_core::module::operational()?;
    ensure!(
        out.len() == 1 + 2 * C::FIELD_BYTES,
        InvalidLength,
        "ecdh public key buffer"
    );
    let d = load_scalar::<C>(private_key)?;
    let q = Point::<C>::mul_generator(&d)
        .to_affine()
        .ok_or(ic_core::err!(Internal, "public key is the identity"))?;
    // The length was checked above, so this can only fail if that check
    // and the encoder disagree. Propagating it keeps such a drift loud
    // rather than silently returning success with nothing written.
    ensure!(
        q.write_uncompressed(out),
        Internal,
        "public key buffer length disagrees with the encoder"
    );
    Ok(())
}

/// Compute the public key, SEC1 compressed.
pub fn public_key_compressed<C: HasGeneratorTable>(
    private_key: &[u8],
    out: &mut [u8],
) -> Result<()> {
    ic_core::module::operational()?;
    ensure!(
        out.len() == 1 + C::FIELD_BYTES,
        InvalidLength,
        "ecdh compressed key buffer"
    );
    let d = load_scalar::<C>(private_key)?;
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

/// Compute the shared secret: the x-coordinate of `[d]Q`.
pub fn agree<C: Curve>(private_key: &[u8], peer_public_key: &[u8], out: &mut [u8]) -> Result<()> {
    ic_core::module::operational()?;
    ensure!(
        out.len() == C::FIELD_BYTES,
        InvalidLength,
        "ecdh shared secret buffer"
    );
    let d = load_scalar::<C>(private_key)?;
    let q = load_peer::<C>(peer_public_key)?;
    finish(Point::<C>::from_affine(&q).mul_scalar(&d), out)
}

/// Decode and validate a peer's public key.
///
/// SP 800-56A full public-key validation: the decoder checks that each
/// coordinate is below `p` and the point is on the curve, and refuses the
/// identity, which has no encoding; every NIST prime curve has cofactor 1, so
/// there is no small subgroup left to land in.
fn load_peer<C: Curve>(peer_public_key: &[u8]) -> Result<AffinePoint<C>> {
    AffinePoint::<C>::from_sec1(peer_public_key).ok_or(ic_core::err!(
        InvalidParameter,
        "ecdh peer public key is not a valid curve point"
    ))
}

/// Write the shared secret, the affine x-coordinate of `shared`, into `out`,
/// whose length the caller has checked.
fn finish<C: Curve>(shared: Point<C>, out: &mut [u8]) -> Result<()> {
    let x = shared.to_affine_x().ok_or(ic_core::err!(
        InvalidParameter,
        "ecdh key agreement produced the identity"
    ))?;
    out.copy_from_slice(x.to_bytes().as_ref());
    Ok(())
}

/// A peer's public key, decoded, validated and expanded once, for key
/// agreement with it many times.
///
/// `agree` decodes and validates the peer's SEC1 encoding and builds a
/// window of its multiples on every call. This does that once, in
/// [`Self::new`], and keeps more than one window: the multiples of the point
/// at four spacings across the scalar, which [`Self::agree`] combines so that
/// it needs a quarter of the doublings. Each agreement through it took about
/// 40 percent of the time of one through `agree` on P-256, P-384 and P-521
/// alike (x86-64); building it costs about one agreement. It pays for a key
/// that is used more than once: a server's static key, a peer's certificate
/// key, a long-lived session.
///
/// It holds only the public key's multiples, and nothing secret, so nothing
/// is wiped. The private key, the scalar and the shared secret are handled as
/// in `agree`: the same decoding, the same selection without indexing, the
/// same affine conversion. Nothing is allocated; it is 64 affine points, about
/// 4 KiB for P-256, 6 KiB for P-384 and 9 KiB for P-521.
pub struct PreparedPublicKey<C: Curve> {
    comb: Comb<C>,
}

impl<C: Curve> PreparedPublicKey<C> {
    /// Decode, validate and expand a peer's public key, SEC1 compressed or
    /// uncompressed.
    ///
    /// Refuses, with `InvalidParameter`, an encoding `agree` would refuse:
    /// the wrong length or tag, a coordinate not below `p`, or a point not on
    /// the curve. Refuses with `ModuleErrorState` once the module has failed.
    pub fn new(peer_public_key: &[u8]) -> Result<Self> {
        ic_core::module::operational()?;
        let q = load_peer::<C>(peer_public_key)?;
        Ok(Self {
            comb: Comb::new(&Point::from_affine(&q)),
        })
    }

    /// The shared secret with this peer: the x-coordinate of `[d]Q`, as
    /// `agree` computes it, written into `out`.
    ///
    /// `out` must be the field's width. The private key is checked as
    /// `agree` checks it. Refuses with `ModuleErrorState` once the module
    /// has failed, even for a key prepared before.
    pub fn agree(&self, private_key: &[u8], out: &mut [u8]) -> Result<()> {
        ic_core::module::operational()?;
        ensure!(
            out.len() == C::FIELD_BYTES,
            InvalidLength,
            "ecdh shared secret buffer"
        );
        let d = load_scalar::<C>(private_key)?;
        finish(self.comb.mul(&d), out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nist::gentable::{comb_span, TEETH};
    use crate::p256::P256;
    use crate::p384::P384;
    use crate::p521::P521;
    use std::vec::Vec;

    /// A byte stream from a 64-bit state: enough to vary every digit.
    struct Stream(u64);

    impl Stream {
        fn fill(&mut self, out: &mut [u8]) {
            for b in out {
                self.0 = self
                    .0
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (self.0 >> 56) as u8;
            }
        }
    }

    /// A valid private key: random bytes, reduced, never zero.
    fn private_key<C: HasGeneratorTable>(s: &mut Stream) -> Vec<u8> {
        let mut bytes = C::Scalar::zero_bytes();
        loop {
            s.fill(bytes.as_mut());
            if C::scalar_from_slice(bytes.as_ref()).is_some_and(|k| !bool::from(k.is_zero())) {
                return bytes.as_ref().to_vec();
            }
        }
    }

    fn public<C: HasGeneratorTable>(sk: &[u8], compressed: bool) -> Vec<u8> {
        let f = C::FIELD_BYTES;
        if compressed {
            let mut pk = std::vec![0u8; 1 + f];
            public_key_compressed::<C>(sk, &mut pk).unwrap();
            pk
        } else {
            let mut pk = std::vec![0u8; 1 + 2 * f];
            public_key::<C>(sk, &mut pk).unwrap();
            pk
        }
    }

    /// Scalars at the edges of the recoding and of the range: `1..=40` and
    /// `n - 40..=n - 1`, where the last steps' additions meet their
    /// exceptional cases if they are going to; and fills that make every
    /// digit carry, or none, or alternate.
    fn edge_scalars<C: Curve>() -> Vec<C::Scalar> {
        let mut out = Vec::new();
        let (mut small, mut minus) = (C::Scalar::ZERO, C::Scalar::ZERO);
        for _ in 0..40 {
            small = small.add(&C::Scalar::ONE);
            minus = minus.sub(&C::Scalar::ONE);
            out.push(small);
            out.push(minus);
        }
        for fill in [0x88u8, 0x77, 0x99, 0xff, 0x0f, 0xf0, 0x5a, 0x84, 0x10] {
            let mut bytes = C::Scalar::zero_bytes();
            for b in bytes.as_mut() {
                *b = fill;
            }
            out.push(C::Scalar::from_bytes_reduced(&bytes));
        }
        // One digit set in each window and nothing else, and the largest
        // window boundary minus one: 32^(c*m) and 32^(c*m) - 1.
        let m = comb_span::<C>();
        for c in 1..TEETH {
            let mut p = C::Scalar::ONE;
            for _ in 0..5 * c * m {
                p = p.add(&p);
            }
            out.push(p);
            out.push(p.sub(&C::Scalar::ONE));
            out.push(p.neg());
        }
        out
    }

    /// The comb against the ladder, which shares nothing with it but the
    /// group law, on the generator and another point, for every edge scalar.
    fn comb_agrees_with_the_ladder<C: HasGeneratorTable>() -> usize {
        let mut checked = 0;
        let g = Point::<C>::generator();
        let other = g.mul_scalar_ladder(&C::Scalar::ONE.add(&C::Scalar::ONE).neg());
        for p in [g, other] {
            let comb = Comb::new(&p);
            for k in edge_scalars::<C>() {
                let want = p.mul_scalar_ladder(&k);
                assert!(bool::from(comb.mul(&k).ct_eq(&want)), "{}", C::NAME);
                checked += 1;
            }
        }
        checked
    }

    /// Scalars on which an addition at the last position meets its
    /// exceptional case, so that only the complete addition gets them right.
    ///
    /// At the last position the accumulator before window `c`'s digit is
    /// `k - sum_(c' >= c) d_(c'm) 32^(c'm)` and the entry is `d_(cm) 32^(cm)`,
    /// so they are the same point when `k = 2 d_(cm) 32^(cm) +
    /// sum_(c' > c) d_(c'm) 32^(c'm) mod n` and the recoding of that `k`
    /// really has those digits. This searches window 1 for them, over every
    /// digit and every pair of digits above, keeps the ones the recoding
    /// confirms, and returns up to `max`.
    fn exceptional_scalars<C: Curve>(max: usize) -> Vec<C::Scalar> {
        use crate::nist::gentable::{digit_count, signed_digits_w};
        let m = comb_span::<C>();
        let n = digit_count(C::SCALAR_BYTES, 5);
        // 32^(c*m) for each window, and its multiples by -16..=16.
        let mut base = Vec::new();
        let mut p = C::Scalar::ONE;
        for _ in 0..TEETH {
            base.push(p);
            for _ in 0..5 * m {
                p = p.add(&p);
            }
        }
        let multiples = |b: C::Scalar| {
            let mut out = Vec::new();
            let mut acc = b.neg().add(&b.neg()).add(&b.neg()).add(&b.neg());
            for _ in 0..2 {
                acc = acc.add(&acc);
            }
            // acc = -16 b; step up by b to +16 b.
            for _ in 0..33 {
                out.push(acc);
                acc = acc.add(&b);
            }
            out
        };
        let (b1, b2, b3) = (multiples(base[1]), multiples(base[2]), multiples(base[3]));
        let mut found = Vec::new();
        for (di, d) in (-16i8..=16).enumerate() {
            if d == 0 {
                continue;
            }
            for (r2i, r2) in (-16i8..=16).enumerate() {
                for (r3i, r3) in (-16i8..=16).enumerate() {
                    let k = b1[di].add(&b1[di]).add(&b2[r2i]).add(&b3[r3i]);
                    let digits = signed_digits_w(k.to_bytes().as_ref(), 5);
                    let top = |c: usize| if c * m < n { digits[c * m] } else { 0 };
                    if top(1) == d && top(2) == r2 && top(3) == r3 && !bool::from(k.is_zero()) {
                        found.push(k);
                        if found.len() == max {
                            return found;
                        }
                    }
                }
            }
        }
        found
    }

    #[test]
    fn the_comb_is_right_where_only_the_complete_addition_is() {
        fn run<C: HasGeneratorTable>() -> usize {
            let g = Point::<C>::generator();
            let comb = Comb::new(&g);
            let scalars = exceptional_scalars::<C>(8);
            for k in &scalars {
                let want = g.mul_scalar_ladder(k);
                assert!(bool::from(comb.mul(k).ct_eq(&want)), "{}", C::NAME);
            }
            scalars.len()
        }
        assert_eq!(run::<P256>(), 8);
        assert_eq!(run::<P384>(), 8);
        assert_eq!(run::<P521>(), 8);
    }

    #[test]
    fn the_comb_agrees_with_the_ladder_on_edge_scalars() {
        let checked = comb_agrees_with_the_ladder::<P256>()
            + comb_agrees_with_the_ladder::<P384>()
            + comb_agrees_with_the_ladder::<P521>();
        assert_eq!(checked, 2 * 3 * (80 + 9 + 3 * (TEETH - 1)));
    }

    /// The bound `Comb::mul`'s incomplete additions rest on: every entry is
    /// below `2^(ORDER_BITS - 3)` in magnitude, `16 * 32^((TEETH - 1) * m)`,
    /// and the complete additions fall exactly on the steps the comment
    /// there names.
    fn entries_are_small<C: Curve>() -> usize {
        let m = comb_span::<C>();
        assert!(5 * (TEETH - 1) * m + 4 <= C::ORDER_BITS - 3, "{}", C::NAME);
        let n = super::super::gentable::digit_count(C::SCALAR_BYTES, 5);
        (0..m).filter(|j| 5 * (n - j) >= C::ORDER_BITS).count()
    }

    #[test]
    fn comb_entries_are_small_against_the_order() {
        assert_eq!(entries_are_small::<P256>(), 1);
        assert_eq!(entries_are_small::<P384>(), 1);
        assert_eq!(entries_are_small::<P521>(), 2);
    }

    /// The prepared key against `agree`, byte for byte, for random keys on
    /// both sides, each peer given compressed and uncompressed.
    fn prepared_matches_unprepared<C: HasGeneratorTable>(seed: u64, rounds: usize) -> usize {
        let mut s = Stream(seed);
        let f = C::FIELD_BYTES;
        let mut checked = 0;
        for _ in 0..rounds {
            let peer = public::<C>(&private_key::<C>(&mut s), false);
            let peer_c = public::<C>(&private_key::<C>(&mut s), true);
            for pk in [&peer, &peer_c] {
                let prepared = PreparedPublicKey::<C>::new(pk).unwrap();
                for _ in 0..3 {
                    let sk = private_key::<C>(&mut s);
                    let (mut want, mut got) = (std::vec![0u8; f], std::vec![0u8; f]);
                    agree::<C>(&sk, pk, &mut want).unwrap();
                    prepared.agree(&sk, &mut got).unwrap();
                    assert_eq!(want, got, "{}", C::NAME);
                    checked += 1;
                }
            }
        }
        checked
    }

    #[test]
    fn prepared_agreement_matches_unprepared_on_random_keys() {
        let checked = prepared_matches_unprepared::<P256>(1, 40)
            + prepared_matches_unprepared::<P384>(2, 40)
            + prepared_matches_unprepared::<P521>(3, 10);
        assert_eq!(checked, 6 * 90);
    }

    /// Both sides of an exchange, one prepared and one not, and the edge
    /// private keys, `1` and `n - 1`, against the peer's own public key.
    fn prepared_edges<C: HasGeneratorTable>() {
        let f = C::FIELD_BYTES;
        let mut s = Stream(7);
        let peer_sk = private_key::<C>(&mut s);
        let peer = public::<C>(&peer_sk, false);
        let prepared = PreparedPublicKey::<C>::new(&peer).unwrap();
        for k in edge_scalars::<C>() {
            let sk = k.to_bytes();
            let (mut want, mut got) = (std::vec![0u8; f], std::vec![0u8; f]);
            agree::<C>(sk.as_ref(), &peer, &mut want).unwrap();
            prepared.agree(sk.as_ref(), &mut got).unwrap();
            assert_eq!(want, got, "{}", C::NAME);
            // The other direction, from the private key's own public key.
            let mut back = std::vec![0u8; f];
            agree::<C>(&peer_sk, &public::<C>(sk.as_ref(), false), &mut back).unwrap();
            assert_eq!(back, got, "{}", C::NAME);
        }
        // `[1]Q` is `Q`: the secret is the peer's own x-coordinate.
        let mut one = C::Scalar::zero_bytes();
        let last = one.as_ref().len() - 1;
        one.as_mut()[last] = 1;
        let mut got = std::vec![0u8; f];
        prepared.agree(one.as_ref(), &mut got).unwrap();
        assert_eq!(got, peer[1..1 + f]);
    }

    #[test]
    fn prepared_agreement_handles_edge_private_keys() {
        prepared_edges::<P256>();
        prepared_edges::<P384>();
        prepared_edges::<P521>();
    }

    /// Everything `agree` refuses in a public key, `new` refuses; and
    /// `agree` on a prepared key refuses what `agree` refuses in a private
    /// key and an output buffer.
    fn prepared_refusals<C: HasGeneratorTable>() {
        let f = C::FIELD_BYTES;
        let mut s = Stream(11);
        let sk = private_key::<C>(&mut s);
        let good = public::<C>(&private_key::<C>(&mut s), false);
        let good_c = public::<C>(&private_key::<C>(&mut s), true);

        let mut bad: Vec<Vec<u8>> = std::vec![
            Vec::new(),
            std::vec![0u8],
            std::vec![0u8; 1 + 2 * f],
            good[..good.len() - 1].to_vec(),
        ];
        let mut longer = good.clone();
        longer.push(0);
        bad.push(longer);
        for tag in [0x00u8, 0x01, 0x05, 0x06, 0x07] {
            let mut b = good.clone();
            b[0] = tag;
            bad.push(b);
        }
        // Off the curve: y changed.
        let mut b = good.clone();
        b[2 * f] ^= 1;
        bad.push(b);
        // A coordinate equal to p, and all ones: not below p.
        let p_bytes = {
            let mut bytes = C::Field::ZERO.sub(&C::Field::ONE).to_bytes();
            // p - 1, plus one, as big-endian bytes.
            let raw = bytes.as_mut();
            let mut i = raw.len();
            loop {
                i -= 1;
                let (v, carry) = raw[i].overflowing_add(1);
                raw[i] = v;
                if !carry {
                    break;
                }
            }
            raw.to_vec()
        };
        for coord in [p_bytes.clone(), std::vec![0xffu8; f]] {
            let mut x = good.clone();
            x[1..1 + f].copy_from_slice(&coord);
            bad.push(x);
            let mut y = good.clone();
            y[1 + f..].copy_from_slice(&coord);
            bad.push(y);
            let mut c = good_c.clone();
            c[1..].copy_from_slice(&coord);
            bad.push(c);
        }
        // A compressed x with no point on the curve: some x in 1.. whose
        // right-hand side is a non-residue.
        let mut x = C::Field::ONE;
        loop {
            let rhs = x.square().mul(&x).sub(&x.triple()).add(&C::B);
            let root = C::sqrt(&rhs);
            if root.square() != rhs {
                break;
            }
            x = x.add(&C::Field::ONE);
        }
        let mut c = std::vec![0x02u8];
        c.extend_from_slice(x.to_bytes().as_ref());
        bad.push(c);

        let mut out = std::vec![0u8; f];
        for b in &bad {
            assert!(
                agree::<C>(&sk, b, &mut out).is_err(),
                "{}: agree accepted {b:02x?}",
                C::NAME
            );
            assert!(
                PreparedPublicKey::<C>::new(b).is_err(),
                "{}: new accepted {b:02x?}",
                C::NAME
            );
        }

        let prepared = PreparedPublicKey::<C>::new(&good).unwrap();
        let zero = std::vec![0u8; C::SCALAR_BYTES];
        let n_bytes = {
            // n itself: n - 1, plus one.
            let mut bytes = C::Scalar::ONE.neg().to_bytes();
            let raw = bytes.as_mut();
            let mut i = raw.len();
            loop {
                i -= 1;
                let (v, carry) = raw[i].overflowing_add(1);
                raw[i] = v;
                if !carry {
                    break;
                }
            }
            raw.to_vec()
        };
        for k in [
            zero,
            n_bytes,
            std::vec![0xffu8; C::SCALAR_BYTES],
            sk[1..].to_vec(),
        ] {
            assert!(prepared.agree(&k, &mut out).is_err(), "{}", C::NAME);
            assert!(agree::<C>(&k, &good, &mut out).is_err(), "{}", C::NAME);
        }
        assert!(prepared.agree(&sk, &mut std::vec![0u8; f - 1]).is_err());
        assert!(prepared.agree(&sk, &mut std::vec![0u8; f + 1]).is_err());
    }

    #[test]
    fn prepared_keys_refuse_what_agree_refuses() {
        prepared_refusals::<P256>();
        prepared_refusals::<P384>();
        prepared_refusals::<P521>();
    }
}
