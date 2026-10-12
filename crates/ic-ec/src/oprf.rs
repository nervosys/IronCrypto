//! Oblivious pseudorandom functions, RFC 9497, with the P256-SHA256 suite.
//!
//! An OPRF lets a client learn `F(k, input)` for a server's key `k` without
//! the server learning the input or the client learning the key. The client
//! blinds its input, the server evaluates the blinded value, and the client
//! removes the blind. It is the building block of OPAQUE, of password
//! hardening services that hold a pepper the database never sees, and of
//! privacy-preserving tokens.
//!
//! All three of RFC 9497's modes:
//!
//! - [`Mode::Oprf`]: the base protocol.
//! - [`Mode::Voprf`]: the server also proves, with a discrete-logarithm
//!   equality proof, that it used the key whose public half the client
//!   holds, so it cannot single a client out with a different key.
//! - [`Mode::Poprf`]: as VOPRF, with a public `info` string both sides see
//!   bound into the evaluation -- a per-user or per-epoch tweak, which is
//!   how a hardening service can rate-limit or rotate by tweak.
//!
//! ```
//! use ic_ec::oprf::{blind, finalize, Mode, ServerKey};
//! # struct Fixed(u8);
//! # impl ic_core::traits::RandomSource for Fixed {
//! #     fn fill(&mut self, out: &mut [u8]) -> ic_core::Result<()> { self.0 += 1; out.fill(self.0); Ok(()) }
//! # }
//! # let mut rng = Fixed(0);
//! let server = ServerKey::generate(Mode::Oprf, &mut rng)?;
//! let (state, blinded) = blind(Mode::Oprf, b"password", b"", None, &mut rng)?;
//! let (evaluated, _) = server.blind_evaluate(&blinded, b"", &mut rng)?;
//! let output = finalize(b"password", b"", &state, &blinded, &evaluated, None)?;
//! assert_eq!(output, server.evaluate(b"password", b"")?);
//! # Ok::<(), ic_core::Error>(())
//! ```
//!
//! Elements are 33-byte compressed SEC1 points, scalars 32 bytes big-endian,
//! a proof two scalars, and an output 32 bytes. Checked against every P-256
//! vector in RFC 9497 appendix A.3.

use crate::hash_to_curve::{hash_to_curve_point, hash_to_scalar};
use crate::nist::arith::Field;
use crate::nist::point::{AffinePoint, Point};
use crate::p256::{Fn as Scalar, P256};
use ic_core::traits::{Digest, RandomSource};
use ic_core::{ensure, Result, Zeroize};
use ic_hash::Sha256;

/// Bytes in a serialized element.
pub const ELEMENT_LEN: usize = 33;
/// Bytes in a serialized scalar.
pub const SCALAR_LEN: usize = 32;
/// Bytes in a serialized proof.
pub const PROOF_LEN: usize = 64;
/// Bytes in an output.
pub const OUTPUT_LEN: usize = 32;
/// The most elements one batch may hold. Batches are worked on the stack,
/// a point is 96 bytes, and this crate builds for targets with a few
/// kilobytes of it.
pub const MAX_BATCH: usize = 64;

/// The suite's identifier, as the context string names it.
const IDENTIFIER: &[u8] = b"P256-SHA256";

/// Which of RFC 9497's three protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The base OPRF.
    Oprf,
    /// Verifiable: the server proves which key it used.
    Voprf,
    /// Partially oblivious: verifiable, with a public `info` bound in.
    Poprf,
}

impl Mode {
    const fn id(self) -> u8 {
        match self {
            Self::Oprf => 0,
            Self::Voprf => 1,
            Self::Poprf => 2,
        }
    }
}

/// `"OPRFV1-" || I2OSP(mode, 1) || "-" || "P256-SHA256"`.
fn context(mode: Mode) -> [u8; 20] {
    let mut c = [0u8; 20];
    c[..7].copy_from_slice(b"OPRFV1-");
    c[7] = mode.id();
    c[8] = b'-';
    c[9..].copy_from_slice(IDENTIFIER);
    c
}

/// A domain separation tag: `prefix || contextString`.
fn dst(prefix: &[u8], mode: Mode, out: &mut [u8; 40]) -> usize {
    let ctx = context(mode);
    out[..prefix.len()].copy_from_slice(prefix);
    out[prefix.len()..prefix.len() + ctx.len()].copy_from_slice(&ctx);
    prefix.len() + ctx.len()
}

fn hash_to_group(mode: Mode, input: &[u8]) -> Result<Point<P256>> {
    let mut d = [0u8; 40];
    let n = dst(b"HashToGroup-", mode, &mut d);
    let p = hash_to_curve_point(&[input], &d[..n])?;
    ensure!(
        !bool::from(p.is_identity()),
        InvalidParameter,
        "oprf input hashes to the identity"
    );
    Ok(p)
}

fn hash_to_scalar_ctx(mode: Mode, parts: &[&[u8]]) -> Result<Scalar> {
    let mut d = [0u8; 40];
    let n = dst(b"HashToScalar-", mode, &mut d);
    hash_to_scalar(parts, &d[..n])
}

fn serialize(p: &Point<P256>) -> Result<[u8; ELEMENT_LEN]> {
    let affine = p.to_affine().ok_or(ic_core::err!(
        InvalidParameter,
        "oprf element is the identity"
    ))?;
    let mut out = [0u8; ELEMENT_LEN];
    let _ = affine.write_compressed(&mut out);
    Ok(out)
}

/// A compressed point on the curve, never the identity: RFC 9497 section
/// 4.3's `DeserializeElement`.
fn deserialize(bytes: &[u8]) -> Result<Point<P256>> {
    ensure!(
        bytes.len() == ELEMENT_LEN && (bytes[0] == 0x02 || bytes[0] == 0x03),
        MalformedEncoding,
        "oprf element must be a 33-byte compressed point"
    );
    let a = AffinePoint::<P256>::from_sec1(bytes).ok_or(ic_core::err!(
        MalformedEncoding,
        "oprf element is not on the curve"
    ))?;
    Ok(Point::from_affine(&a))
}

fn scalar_from(bytes: &[u8]) -> Result<Scalar> {
    let mut b = [0u8; SCALAR_LEN];
    ensure!(
        bytes.len() == SCALAR_LEN,
        InvalidLength,
        "oprf scalar length"
    );
    b.copy_from_slice(bytes);
    let s = Scalar::from_bytes(&b).ok_or(ic_core::err!(
        MalformedEncoding,
        "oprf scalar is not below the group order"
    ));
    b.zeroize();
    s
}

/// A uniform nonzero scalar by rejection sampling, RFC 9497 section 4.7.1.
fn random_scalar<R: RandomSource + ?Sized>(rng: &mut R) -> Result<Scalar> {
    let mut b = [0u8; SCALAR_LEN];
    for _ in 0..64 {
        rng.fill(&mut b)?;
        if let Some(s) = Scalar::from_bytes(&b) {
            if !bool::from(s.is_zero()) {
                b.zeroize();
                return Ok(s);
            }
        }
    }
    b.zeroize();
    Err(ic_core::err!(EntropyFailure, "oprf: no scalar in 64 draws"))
}

fn length_prefixed(h: &mut Sha256, bytes: &[u8]) {
    h.update(&(bytes.len() as u16).to_be_bytes());
    h.update(bytes);
}

/// The POPRF tweak `m = HashToScalar("Info" || I2OSP(len(info), 2) || info)`.
fn tweak(info: &[u8]) -> Result<Scalar> {
    ensure!(
        info.len() <= u16::MAX as usize,
        InvalidLength,
        "oprf info too long"
    );
    hash_to_scalar_ctx(
        Mode::Poprf,
        &[b"Info", &(info.len() as u16).to_be_bytes(), info],
    )
}

/// `ComputeComposites`: with the key, `Z = k * M`; without it, the sum of
/// `d_i * D[i]`.
fn composites(
    mode: Mode,
    k: Option<&Scalar>,
    b: &Point<P256>,
    c: &[Point<P256>],
    d: &[Point<P256>],
) -> Result<(Point<P256>, Point<P256>)> {
    let bm = serialize(b)?;
    let mut seed_dst = [0u8; 40];
    let n = dst(b"Seed-", mode, &mut seed_dst);
    let mut h = Sha256::new();
    length_prefixed(&mut h, &bm);
    length_prefixed(&mut h, &seed_dst[..n]);
    let seed = h.finalize();
    let mut m = Point::<P256>::identity();
    let mut z = Point::<P256>::identity();
    for (i, (ci, di)) in c.iter().zip(d.iter()).enumerate() {
        let (cs, ds) = (serialize(ci)?, serialize(di)?);
        let weight = hash_to_scalar_ctx(
            mode,
            &[
                &(seed.as_ref().len() as u16).to_be_bytes(),
                seed.as_ref(),
                &(i as u16).to_be_bytes(),
                &(cs.len() as u16).to_be_bytes(),
                &cs,
                &(ds.len() as u16).to_be_bytes(),
                &ds,
                b"Composite",
            ],
        )?;
        m = ci.mul_scalar_vartime(&weight).add(&m);
        if k.is_none() {
            z = di.mul_scalar_vartime(&weight).add(&z);
        }
    }
    if let Some(k) = k {
        z = m.mul_scalar(k);
    }
    Ok((m, z))
}

fn challenge(
    mode: Mode,
    b: &Point<P256>,
    m: &Point<P256>,
    z: &Point<P256>,
    t2: &Point<P256>,
    t3: &Point<P256>,
) -> Result<Scalar> {
    let (bm, a0, a1, a2, a3) = (
        serialize(b)?,
        serialize(m)?,
        serialize(z)?,
        serialize(t2)?,
        serialize(t3)?,
    );
    let len = (ELEMENT_LEN as u16).to_be_bytes();
    hash_to_scalar_ctx(
        mode,
        &[
            &len,
            &bm,
            &len,
            &a0,
            &len,
            &a1,
            &len,
            &a2,
            &len,
            &a3,
            b"Challenge",
        ],
    )
}

/// `GenerateProof(k, A, B, C, D)` with `A` the generator.
fn generate_proof<R: RandomSource + ?Sized>(
    mode: Mode,
    k: &Scalar,
    b: &Point<P256>,
    c: &[Point<P256>],
    d: &[Point<P256>],
    rng: &mut R,
) -> Result<[u8; PROOF_LEN]> {
    let (m, z) = composites(mode, Some(k), b, c, d)?;
    let r = random_scalar(rng)?;
    let t2 = Point::<P256>::mul_generator(&r);
    let t3 = m.mul_scalar(&r);
    let ch = challenge(mode, b, &m, &z, &t2, &t3)?;
    let s = r.sub(&ch.mul(k));
    let mut proof = [0u8; PROOF_LEN];
    proof[..32].copy_from_slice(&ch.to_bytes());
    proof[32..].copy_from_slice(&s.to_bytes());
    Ok(proof)
}

/// `VerifyProof(A, B, C, D, proof)` with `A` the generator.
fn verify_proof(
    mode: Mode,
    b: &Point<P256>,
    c: &[Point<P256>],
    d: &[Point<P256>],
    proof: &[u8; PROOF_LEN],
) -> Result<()> {
    let (m, z) = composites(mode, None, b, c, d)?;
    let ch = scalar_from(&proof[..32])?;
    let s = scalar_from(&proof[32..])?;
    let t2 = Point::<P256>::mul_generator(&s).add(&b.mul_scalar_vartime(&ch));
    let t3 = m.mul_scalar_vartime(&s).add(&z.mul_scalar_vartime(&ch));
    let expected = challenge(mode, b, &m, &z, &t2, &t3)?;
    ensure!(
        bool::from(expected.ct_eq(&ch)),
        AuthenticationFailed,
        "oprf proof"
    );
    Ok(())
}

fn finalize_hash(input: &[u8], info: Option<&[u8]>, n: &Point<P256>) -> Result<[u8; OUTPUT_LEN]> {
    ensure!(
        input.len() <= u16::MAX as usize,
        InvalidLength,
        "oprf input too long"
    );
    let unblinded = serialize(n)?;
    let mut h = Sha256::new();
    length_prefixed(&mut h, input);
    if let Some(info) = info {
        length_prefixed(&mut h, info);
    }
    length_prefixed(&mut h, &unblinded);
    h.update(b"Finalize");
    let mut out = [0u8; OUTPUT_LEN];
    out.copy_from_slice(h.finalize().as_ref());
    Ok(out)
}

/// A server's key for one mode.
pub struct ServerKey {
    mode: Mode,
    secret: [u8; SCALAR_LEN],
    public: [u8; ELEMENT_LEN],
}

impl Drop for ServerKey {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl ServerKey {
    fn from_scalar(mode: Mode, sk: &Scalar) -> Result<Self> {
        ensure!(
            !bool::from(sk.is_zero()),
            InvalidParameter,
            "oprf key is zero"
        );
        let public = serialize(&Point::<P256>::mul_generator(sk))?;
        Ok(Self {
            mode,
            secret: sk.to_bytes(),
            public,
        })
    }

    fn scalar(&self) -> Result<Scalar> {
        scalar_from(&self.secret)
    }

    /// A fresh key from `rng`. Pass `ic_drbg::Rng`.
    pub fn generate<R: RandomSource + ?Sized>(mode: Mode, rng: &mut R) -> Result<Self> {
        ic_core::module::operational()?;
        Self::from_scalar(mode, &random_scalar(rng)?)
    }

    /// RFC 9497 section 3.2.1's `DeriveKeyPair`: a key from a 32-byte secret
    /// seed and a public `info`.
    pub fn derive(mode: Mode, seed: &[u8; 32], info: &[u8]) -> Result<Self> {
        ic_core::module::operational()?;
        ensure!(
            info.len() <= u16::MAX as usize,
            InvalidLength,
            "oprf info too long"
        );
        let mut d = [0u8; 40];
        let n = dst(b"DeriveKeyPair", mode, &mut d);
        for counter in 0u8..=255 {
            let sk = hash_to_scalar(
                &[seed, &(info.len() as u16).to_be_bytes(), info, &[counter]],
                &d[..n],
            )?;
            if !bool::from(sk.is_zero()) {
                return Self::from_scalar(mode, &sk);
            }
        }
        Err(ic_core::err!(
            InvalidParameter,
            "oprf DeriveKeyPair found no key"
        ))
    }

    /// A key from its 32-byte scalar.
    pub fn from_bytes(mode: Mode, secret: &[u8]) -> Result<Self> {
        ic_core::module::operational()?;
        Self::from_scalar(mode, &scalar_from(secret)?)
    }

    /// The 32-byte scalar, for storing the key.
    pub fn to_bytes(&self) -> ic_core::Zeroizing<[u8; SCALAR_LEN]> {
        ic_core::Zeroizing::new(self.secret)
    }

    /// The public key, which a VOPRF or POPRF client needs.
    pub fn public_key(&self) -> [u8; ELEMENT_LEN] {
        self.public
    }

    /// The mode this key serves.
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Evaluate one blinded element; see [`ServerKey::blind_evaluate_batch`].
    pub fn blind_evaluate<R: RandomSource + ?Sized>(
        &self,
        blinded: &[u8; ELEMENT_LEN],
        info: &[u8],
        rng: &mut R,
    ) -> Result<([u8; ELEMENT_LEN], Option<[u8; PROOF_LEN]>)> {
        let mut evaluated = [[0u8; ELEMENT_LEN]; 1];
        let proof = self.blind_evaluate_batch(&[*blinded], info, rng, &mut evaluated)?;
        Ok((evaluated[0], proof))
    }

    /// Evaluate blinded elements, writing one evaluated element for each, and
    /// return the batched proof in the verifiable modes.
    ///
    /// `info` is the POPRF's public input and must be empty in the other two
    /// modes. A POPRF `info` that hashes to the negated key -- which only
    /// someone who knows the key can find -- is refused, as RFC 9497 says,
    /// and is a sign the key is known.
    pub fn blind_evaluate_batch<R: RandomSource + ?Sized>(
        &self,
        blinded: &[[u8; ELEMENT_LEN]],
        info: &[u8],
        rng: &mut R,
        evaluated: &mut [[u8; ELEMENT_LEN]],
    ) -> Result<Option<[u8; PROOF_LEN]>> {
        ic_core::module::operational()?;
        ensure!(
            !blinded.is_empty() && blinded.len() == evaluated.len() && blinded.len() <= MAX_BATCH,
            InvalidLength,
            "oprf batch: 1 to MAX_BATCH elements, one output each"
        );
        ensure!(
            self.mode == Mode::Poprf || info.is_empty(),
            InvalidParameter,
            "oprf info is only for the POPRF mode"
        );
        let sk = self.scalar()?;
        // The POPRF evaluates under t = skS + m, inverted.
        let k = if self.mode == Mode::Poprf {
            let t = sk.add(&tweak(info)?);
            ensure!(
                !bool::from(t.is_zero()),
                InvalidParameter,
                "oprf: info maps to the key"
            );
            t.invert()
        } else {
            sk
        };
        for (b, e) in blinded.iter().zip(evaluated.iter_mut()) {
            *e = serialize(&deserialize(b)?.mul_scalar(&k))?;
        }
        if self.mode == Mode::Oprf {
            return Ok(None);
        }
        // In the POPRF the proof runs the other way: blinded = t * evaluated,
        // under the tweaked key t * G.
        let c_list = decode_all(if self.mode == Mode::Poprf {
            evaluated
        } else {
            blinded
        })?;
        let d_list = decode_all(if self.mode == Mode::Poprf {
            blinded
        } else {
            evaluated
        })?;
        let (proof_key, b) = if self.mode == Mode::Poprf {
            let t = sk.add(&tweak(info)?);
            (t, Point::<P256>::mul_generator(&t))
        } else {
            (sk, deserialize(&self.public)?)
        };
        let proof = generate_proof(
            self.mode,
            &proof_key,
            &b,
            &c_list[..blinded.len()],
            &d_list[..blinded.len()],
            rng,
        )?;
        Ok(Some(proof))
    }

    /// RFC 9497's `Evaluate`: the PRF output for `input` computed directly
    /// with the key, as the client would arrive at it. `info` is the POPRF's
    /// and must be empty otherwise.
    pub fn evaluate(&self, input: &[u8], info: &[u8]) -> Result<[u8; OUTPUT_LEN]> {
        ic_core::module::operational()?;
        ensure!(
            self.mode == Mode::Poprf || info.is_empty(),
            InvalidParameter,
            "oprf info is only for the POPRF mode"
        );
        let element = hash_to_group(self.mode, input)?;
        let sk = self.scalar()?;
        if self.mode == Mode::Poprf {
            let t = sk.add(&tweak(info)?);
            ensure!(
                !bool::from(t.is_zero()),
                InvalidParameter,
                "oprf: info maps to the key"
            );
            finalize_hash(input, Some(info), &element.mul_scalar(&t.invert()))
        } else {
            finalize_hash(input, None, &element.mul_scalar(&sk))
        }
    }
}

/// Decode up to [`MAX_BATCH`] elements into a fixed array.
fn decode_all(elements: &[[u8; ELEMENT_LEN]]) -> Result<[Point<P256>; MAX_BATCH]> {
    ensure!(
        elements.len() <= MAX_BATCH,
        InvalidLength,
        "oprf batch too large"
    );
    let mut out: [Point<P256>; MAX_BATCH] = core::array::from_fn(|_| Point::identity());
    for (slot, e) in out.iter_mut().zip(elements.iter()) {
        *slot = deserialize(e)?;
    }
    Ok(out)
}

/// What a client keeps between blinding and finalizing.
pub struct BlindState {
    mode: Mode,
    blind: [u8; SCALAR_LEN],
    /// The server's public key in the VOPRF, the tweaked key in the POPRF.
    key: Option<[u8; ELEMENT_LEN]>,
}

impl Drop for BlindState {
    fn drop(&mut self) {
        self.blind.zeroize();
    }
}

/// Blind `input` for evaluation.
///
/// The VOPRF and POPRF need the server's public key, to verify its proof
/// later; the POPRF also binds the public `info`, which must be empty in the
/// other modes. Returns the state to keep and the blinded element to send.
pub fn blind<R: RandomSource + ?Sized>(
    mode: Mode,
    input: &[u8],
    info: &[u8],
    server_public_key: Option<&[u8; ELEMENT_LEN]>,
    rng: &mut R,
) -> Result<(BlindState, [u8; ELEMENT_LEN])> {
    ic_core::module::operational()?;
    ensure!(
        mode == Mode::Poprf || info.is_empty(),
        InvalidParameter,
        "oprf info is only for the POPRF mode"
    );
    let key = match mode {
        Mode::Oprf => None,
        Mode::Voprf | Mode::Poprf => {
            let pk = server_public_key.ok_or(ic_core::err!(
                InvalidParameter,
                "the verifiable modes need the server's public key"
            ))?;
            let pk_point = deserialize(pk)?;
            if mode == Mode::Poprf {
                let tweaked = Point::<P256>::mul_generator(&tweak(info)?).add(&pk_point);
                ensure!(
                    !bool::from(tweaked.is_identity()),
                    InvalidParameter,
                    "oprf: info maps to the negated key"
                );
                Some(serialize(&tweaked)?)
            } else {
                Some(*pk)
            }
        }
    };
    let r = random_scalar(rng)?;
    let element = hash_to_group(mode, input)?;
    let blinded = serialize(&element.mul_scalar(&r))?;
    Ok((
        BlindState {
            mode,
            blind: r.to_bytes(),
            key,
        },
        blinded,
    ))
}

/// Finish one evaluation; see [`finalize_batch`].
pub fn finalize(
    input: &[u8],
    info: &[u8],
    state: &BlindState,
    blinded: &[u8; ELEMENT_LEN],
    evaluated: &[u8; ELEMENT_LEN],
    proof: Option<&[u8; PROOF_LEN]>,
) -> Result<[u8; OUTPUT_LEN]> {
    let mut out = [[0u8; OUTPUT_LEN]; 1];
    finalize_batch(
        &[input],
        info,
        core::slice::from_ref(state),
        &[*blinded],
        &[*evaluated],
        proof,
        &mut out,
    )?;
    Ok(out[0])
}

/// Unblind a batch of evaluations, writing one output for each input.
///
/// In the verifiable modes the server's proof is checked first, over the
/// whole batch, and a bad proof is `AuthenticationFailed` with nothing
/// written. Every state must come from [`blind`] in the same mode with the
/// same key and `info`.
pub fn finalize_batch(
    inputs: &[&[u8]],
    info: &[u8],
    states: &[BlindState],
    blinded: &[[u8; ELEMENT_LEN]],
    evaluated: &[[u8; ELEMENT_LEN]],
    proof: Option<&[u8; PROOF_LEN]>,
    out: &mut [[u8; OUTPUT_LEN]],
) -> Result<()> {
    ic_core::module::operational()?;
    let n = inputs.len();
    ensure!(
        (1..=MAX_BATCH).contains(&n)
            && states.len() == n
            && blinded.len() == n
            && evaluated.len() == n
            && out.len() == n,
        InvalidLength,
        "oprf batch: 1 to MAX_BATCH of each, equal in number"
    );
    let mode = states[0].mode;
    ensure!(
        states
            .iter()
            .all(|s| s.mode == mode && s.key == states[0].key),
        InvalidParameter,
        "oprf batch mixes modes or keys"
    );
    ensure!(
        mode == Mode::Poprf || info.is_empty(),
        InvalidParameter,
        "oprf info is only for the POPRF mode"
    );
    if mode != Mode::Oprf {
        let proof = proof.ok_or(ic_core::err!(
            InvalidParameter,
            "the verifiable modes need the server's proof"
        ))?;
        let key = deserialize(&states[0].key.ok_or(ic_core::err!(
            InvalidParameter,
            "the verifiable modes need the server's public key"
        ))?)?;
        let blinded_points = decode_all(blinded)?;
        let evaluated_points = decode_all(evaluated)?;
        let (c, d) = if mode == Mode::Poprf {
            (&evaluated_points[..n], &blinded_points[..n])
        } else {
            (&blinded_points[..n], &evaluated_points[..n])
        };
        verify_proof(mode, &key, c, d, proof)?;
    }
    for i in 0..n {
        let r = scalar_from(&states[i].blind)?;
        let unblinded = deserialize(&evaluated[i])?.mul_scalar(&r.invert());
        out[i] = finalize_hash(inputs[i], (mode == Mode::Poprf).then_some(info), &unblinded)?;
    }
    Ok(())
}

/// The known-answer test: RFC 9497 appendix A.3.1.1, the OPRF mode's first
/// vector, evaluated with the derived key.
pub fn self_test() -> Result<()> {
    let seed = [0xa3u8; 32];
    let key = ServerKey::derive(Mode::Oprf, &seed, b"test key")?;
    let mut want_sk = [0u8; 32];
    ic_core::codec::hex_decode(
        b"159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf",
        &mut want_sk,
    )?;
    ensure!(
        ic_core::ct::verify(key.to_bytes().as_ref(), &want_sk),
        SelfTestFailed,
        "oprf"
    );
    let mut want = [0u8; 32];
    ic_core::codec::hex_decode(
        b"a0b34de5fa4c5b6da07e72af73cc507cceeb48981b97b7285fc375345fe495dd",
        &mut want,
    )?;
    ensure!(
        ic_core::ct::verify(&key.evaluate(&[0x00], b"")?, &want),
        SelfTestFailed,
        "oprf"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_self_test_passes() {
        self_test().unwrap();
    }

    #[test]
    fn the_context_string_is_rfc_9497_s() {
        assert_eq!(&context(Mode::Poprf), b"OPRFV1-\x02-P256-SHA256");
    }

    /// Not the identity, not uncompressed, not off the curve.
    #[test]
    fn elements_are_validated() {
        assert!(deserialize(&[0u8; 33]).is_err());
        let mut uncompressed = [0u8; 65];
        uncompressed[0] = 4;
        assert!(deserialize(&uncompressed).is_err());
        let mut off = [0u8; 33];
        off[0] = 2;
        off[32] = 7; // x = 7 is not: x^3 - 3x + b is a non-residue, checked by Euler's criterion
        assert!(deserialize(&off).is_err());
    }
}
