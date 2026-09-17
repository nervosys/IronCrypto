//! RSA key types, primality testing, and key generation.
//!
//! # What is and is not constant-time
//!
//! The private operation ([`RsaPrivateKey::raw_private`]) is constant-time in
//! the exponent. Key *generation* is not, and deliberately so: the binary GCD
//! and the trial divisions branch on candidate values. That matches every
//! mainstream implementation — generation is a one-time operation, typically
//! offline, and making it constant-time would cost far more than it buys.
//! Generate keys somewhere an attacker is not measuring.
//!
//! # CRT, and the check that makes it safe
//!
//! The private operation runs the Chinese-remainder pair modulo `p` and `q`
//! when the key carries them, which is roughly four times faster than a single
//! exponentiation modulo `n`: two half-width exponentiations cost about a
//! quarter of one full-width exponentiation, because modular multiplication is
//! quadratic in the operand size.
//!
//! CRT is also where RSA fault attacks land. If a glitch corrupts exactly one
//! of the two halves, the difference between the faulty output and the correct
//! one shares a factor with `n`, and one `gcd` recovers the private key from a
//! single bad signature. So this implementation never returns a CRT result it
//! has not checked: [`RsaPrivateKey::raw_private`] raises the output back to
//! the public exponent and compares it against the input, and on a mismatch
//! returns an error and no data at all. The check costs one exponentiation by
//! 65537 — seventeen squarings — against the thousands the private operation
//! took, so it is under one percent.
//!
//! That makes the CRT path strictly safer than the non-CRT one, which has no
//! output check to make. A key built from `n`, `e`, and `d` alone still uses
//! the slow path, because there is nothing to recombine.

use crate::uint::{Modulus, Uint, MAX_BYTES, MAX_LIMBS};
use ic_core::traits::RandomSource;
use ic_core::{ensure, Result, Zeroize};

/// The smallest modulus this accepts, in bits.
///
/// SP 800-131A disallows RSA below 2048 bits for new signatures.
pub const MIN_MODULUS_BITS: usize = 2048;

/// The largest modulus this accepts, in bits.
pub const MAX_MODULUS_BITS: usize = 4096;

/// The only public exponent this generates, and the one essentially everything
/// uses.
///
/// FIPS 186-5 requires an odd public exponent between 2^16 and 2^256. Small
/// exponents like 3 are legal but leave less margin against implementation
/// mistakes, so generation always uses this one.
pub const PUBLIC_EXPONENT: u64 = 65537;

/// An RSA public key.
#[derive(Clone, Copy)]
pub struct RsaPublicKey {
    n: Modulus,
    e: u64,
}

impl RsaPublicKey {
    /// Build from a big-endian modulus and a public exponent.
    pub fn from_components(n: &[u8], e: u64) -> Result<Self> {
        let n_uint =
            Uint::from_be_bytes(n).ok_or(ic_core::err!(InvalidLength, "rsa modulus too large"))?;
        let bits = n_uint.bits();
        ensure!(
            (MIN_MODULUS_BITS..=MAX_MODULUS_BITS).contains(&bits),
            InvalidParameter,
            "rsa modulus must be 2048..=4096 bits"
        );
        ensure!(
            e >= 3 && e % 2 == 1,
            InvalidParameter,
            "rsa exponent must be odd and >= 3"
        );
        let n = Modulus::new(n_uint)
            .ok_or(ic_core::err!(InvalidParameter, "rsa modulus must be odd"))?;
        Ok(RsaPublicKey { n, e })
    }

    /// The modulus size in bytes, which is also the signature size.
    pub fn size(&self) -> usize {
        self.n.byte_len()
    }

    /// The modulus size in bits.
    pub fn bits(&self) -> usize {
        self.n.value().bits()
    }

    /// The public exponent.
    pub fn exponent(&self) -> u64 {
        self.e
    }

    /// The modulus, big-endian, written into `out` (which must be [`Self::size`]).
    pub fn modulus_bytes(&self, out: &mut [u8]) -> Result<()> {
        ensure!(
            out.len() == self.size(),
            InvalidLength,
            "rsa modulus buffer"
        );
        self.n.value().to_be_bytes(out);
        Ok(())
    }

    /// The raw public operation, `m^e mod n`.
    ///
    /// Both the input and the output are big-endian and exactly [`Self::size`]
    /// bytes. Rejects `m >= n`, which has no valid representative.
    pub fn raw_public(&self, m: &[u8], out: &mut [u8]) -> Result<()> {
        let size = self.size();
        ensure!(
            m.len() == size && out.len() == size,
            InvalidLength,
            "rsa block"
        );
        let value = Uint::from_be_bytes(m)
            .ok_or(ic_core::err!(MalformedEncoding, "rsa block too large"))?;
        ensure!(
            value.cmp_vartime(self.n.value()) == core::cmp::Ordering::Less,
            MalformedEncoding,
            "rsa block is not less than the modulus"
        );
        self.n.pow_public(&value, self.e).to_be_bytes(out);
        Ok(())
    }
}

/// The Chinese-remainder parameters, when a key has them.
///
/// Held as prepared [`Modulus`] values rather than raw integers, since every
/// use needs the Montgomery constants anyway and deriving them once per key is
/// the whole point.
struct CrtParams {
    p: Modulus,
    q: Modulus,
    /// `e^-1 mod (p-1)`, so `m^dp = m^d mod p`.
    dp: Uint,
    /// `e^-1 mod (q-1)`.
    dq: Uint,
    /// `q^-1 mod p`, for the recombination.
    qinv: Uint,
    /// Bit width of the half-size exponentiations.
    half_bits: usize,
}

impl Zeroize for CrtParams {
    fn zeroize(&mut self) {
        self.p.zeroize();
        self.q.zeroize();
        self.dp.zeroize();
        self.dq.zeroize();
        self.qinv.zeroize();
    }
}

/// An RSA private key.
///
/// # Size
///
/// Every integer inside is a fixed-capacity 4096-bit buffer regardless of the
/// key, so this is around five kilobytes whether it holds a 2048-bit key or a
/// 4096-bit one. That is deliberate — it is what keeps the crate allocation
/// free — but it is too large for a small stack. Box it on an embedded target.
pub struct RsaPrivateKey {
    public: RsaPublicKey,
    d: Uint,
    /// Bit length of `d`, which bounds the exponentiation loop. This is a
    /// property of the key rather than of any message, so it is not secret in
    /// the way `d` itself is.
    d_bits: usize,
    /// Present when the key was generated here or imported with its primes.
    crt: Option<CrtParams>,
}

impl Drop for RsaPrivateKey {
    fn drop(&mut self) {
        self.d.zeroize();
        if let Some(crt) = self.crt.as_mut() {
            crt.zeroize();
        }
    }
}

impl RsaPrivateKey {
    /// Build from a big-endian modulus, public exponent, and private exponent.
    pub fn from_components(n: &[u8], e: u64, d: &[u8]) -> Result<Self> {
        let public = RsaPublicKey::from_components(n, e)?;
        let d_uint =
            Uint::from_be_bytes(d).ok_or(ic_core::err!(InvalidLength, "rsa exponent too large"))?;
        ensure!(
            d_uint.cmp_vartime(public.n.value()) == core::cmp::Ordering::Less,
            InvalidParameter,
            "rsa private exponent must be less than the modulus"
        );
        // The loop runs over the full modulus width rather than d's own bit
        // length, so the timing does not reveal how large d happens to be.
        let d_bits = public.bits();
        Ok(RsaPrivateKey {
            public,
            d: d_uint,
            d_bits,
            crt: None,
        })
    }

    /// Build from the two primes, deriving everything else.
    ///
    /// This is the constructor to prefer when the primes are available: it
    /// yields a key that uses the CRT path, and it recomputes `d` and the CRT
    /// parameters rather than trusting values that may not be consistent with
    /// `p` and `q`.
    ///
    /// `p` and `q` must be distinct primes of the same bit length, and that
    /// length must be a whole number of 64-bit words. Primality is *not*
    /// rechecked: that is the caller's guarantee, and it is what
    /// [`generate`] provides.
    pub fn from_primes(p: &[u8], q: &[u8], e: u64) -> Result<Self> {
        ensure!(e >= 3 && e % 2 == 1, InvalidParameter, "rsa exponent");
        let p_uint =
            Uint::from_be_bytes(p).ok_or(ic_core::err!(InvalidLength, "rsa prime too large"))?;
        let q_uint =
            Uint::from_be_bytes(q).ok_or(ic_core::err!(InvalidLength, "rsa prime too large"))?;
        ensure!(
            p_uint.bits() == q_uint.bits(),
            InvalidParameter,
            "rsa primes must be the same size"
        );
        ensure!(
            p_uint.cmp_vartime(&q_uint) != core::cmp::Ordering::Equal,
            InvalidParameter,
            "rsa primes must be distinct"
        );
        // PKCS#1 defines qInv as q^-1 mod p, and implementations conventionally
        // store the larger factor as p. Normalizing here means an exported key
        // matches what other tools expect, and costs nothing: the two primes
        // are interchangeable up to this choice.
        let (p_uint, q_uint) = if p_uint.cmp_vartime(&q_uint) == core::cmp::Ordering::Less {
            (q_uint, p_uint)
        } else {
            (p_uint, q_uint)
        };

        let half_bits = p_uint.bits();
        ensure!(
            half_bits % 64 == 0,
            Unsupported,
            "rsa primes must be a whole number of words"
        );
        let half_limbs = half_bits / 64;

        let n = mul_vartime(&p_uint, &q_uint, half_limbs, half_limbs);
        let mut n_bytes = [0u8; MAX_BYTES];
        let size = n.bits().div_ceil(8);
        n.to_be_bytes(&mut n_bytes[..size]);
        let public = RsaPublicKey::from_components(&n_bytes[..size], e)?;

        let one = Uint::one();
        let mut p1 = p_uint;
        p1.sub_assign(&one, half_limbs);
        let mut q1 = q_uint;
        q1.sub_assign(&one, half_limbs);

        let full_limbs = public.n.limbs();
        let phi = mul_vartime(&p1, &q1, half_limbs, half_limbs);
        let e_uint = Uint::from_u64(e);
        let d = modinv_even_modulus(&e_uint, &phi, full_limbs).ok_or(ic_core::err!(
            InvalidParameter,
            "rsa exponent is not coprime to phi(n)"
        ))?;

        // dp and dq are e^-1 modulo p-1 and q-1. Deriving them this way rather
        // than as d mod (p-1) avoids needing a general big-integer division,
        // and gives the same answer: both satisfy e * dp = 1 mod (p-1).
        let dp = modinv_even_modulus(&e_uint, &p1, half_limbs).ok_or(ic_core::err!(
            InvalidParameter,
            "rsa exponent is not coprime to p-1"
        ))?;
        let dq = modinv_even_modulus(&e_uint, &q1, half_limbs).ok_or(ic_core::err!(
            InvalidParameter,
            "rsa exponent is not coprime to q-1"
        ))?;

        let p_mod = Modulus::new(p_uint).ok_or(ic_core::err!(InvalidParameter, "p must be odd"))?;
        let q_mod = Modulus::new(q_uint).ok_or(ic_core::err!(InvalidParameter, "q must be odd"))?;
        let qinv = p_mod
            .invert_vartime(&q_uint)
            .ok_or(ic_core::err!(InvalidParameter, "q has no inverse modulo p"))?;

        let crt = crt_params_if_usable(p_mod, q_mod, dp, dq, qinv, half_bits, full_limbs);

        Ok(RsaPrivateKey {
            public,
            d,
            d_bits: public.bits(),
            crt,
        })
    }

    /// The primes, big-endian, when the key has them.
    ///
    /// Each buffer must be half the modulus size. Returns
    /// `Err(Unsupported)` for a key built from `n`, `e`, and `d` alone. The
    /// caller is responsible for erasing the output.
    pub fn prime_bytes(&self, p_out: &mut [u8], q_out: &mut [u8]) -> Result<()> {
        let crt = self.crt.as_ref().ok_or(ic_core::err!(
            Unsupported,
            "this key does not carry its primes"
        ))?;
        let half = self.size() / 2;
        ensure!(
            p_out.len() == half && q_out.len() == half,
            InvalidLength,
            "rsa prime buffer"
        );
        crt.p.value().to_be_bytes(p_out);
        crt.q.value().to_be_bytes(q_out);
        Ok(())
    }

    /// The three CRT exponents — `dP`, `dQ`, and `qInv` — big-endian.
    ///
    /// Each buffer must be half the modulus size. These are what PKCS#1
    /// `RSAPrivateKey` carries beyond the primes. The caller is responsible for
    /// erasing the output.
    pub fn crt_exponent_bytes(
        &self,
        dp_out: &mut [u8],
        dq_out: &mut [u8],
        qinv_out: &mut [u8],
    ) -> Result<()> {
        let crt = self.crt.as_ref().ok_or(ic_core::err!(
            Unsupported,
            "this key does not carry crt parameters"
        ))?;
        let half = self.size() / 2;
        ensure!(
            dp_out.len() == half && dq_out.len() == half && qinv_out.len() == half,
            InvalidLength,
            "rsa crt buffer"
        );
        crt.dp.to_be_bytes(dp_out);
        crt.dq.to_be_bytes(dq_out);
        crt.qinv.to_be_bytes(qinv_out);
        Ok(())
    }

    /// Whether the private operation will take the CRT path.
    ///
    /// Reported so a caller can tell a fast key from a slow one, and so the
    /// tests can assert which path they exercised.
    #[must_use]
    pub fn uses_crt(&self) -> bool {
        self.crt.is_some()
    }

    /// The matching public key.
    pub fn public_key(&self) -> &RsaPublicKey {
        &self.public
    }

    /// The modulus size in bytes.
    pub fn size(&self) -> usize {
        self.public.size()
    }

    /// The raw private operation, `c^d mod n`, constant-time in `d`.
    pub fn raw_private(&self, c: &[u8], out: &mut [u8]) -> Result<()> {
        let size = self.size();
        ensure!(
            c.len() == size && out.len() == size,
            InvalidLength,
            "rsa block"
        );
        let value = Uint::from_be_bytes(c)
            .ok_or(ic_core::err!(MalformedEncoding, "rsa block too large"))?;
        ensure!(
            value.cmp_vartime(self.public.n.value()) == core::cmp::Ordering::Less,
            MalformedEncoding,
            "rsa block is not less than the modulus"
        );
        let mut result = match self.crt.as_ref() {
            Some(crt) => self.crt_private(crt, &value)?,
            None => self.public.n.pow(&value, &self.d, self.d_bits),
        };
        result.to_be_bytes(out);
        result.zeroize();
        Ok(())
    }

    /// `c^d mod n` by the Chinese remainder theorem, with the result verified
    /// before it is returned.
    ///
    /// ```text
    /// m1 = c^dp mod p
    /// m2 = c^dq mod q
    /// h  = qInv * (m1 - m2) mod p
    /// m  = m2 + q * h
    /// ```
    ///
    /// The verification at the end is not optional and not a debug assertion.
    /// See the module docs: without it, one faulted half-exponentiation hands
    /// an attacker the factorization of `n`.
    fn crt_private(&self, crt: &CrtParams, c: &Uint) -> Result<Uint> {
        let half_limbs = crt.p.limbs();

        let cp = crt.p.reduce_wide(c);
        let cq = crt.q.reduce_wide(c);
        let m1 = crt.p.pow(&cp, &crt.dp, crt.half_bits);
        let m2 = crt.q.pow(&cq, &crt.dq, crt.half_bits);

        // h = qInv * (m1 - m2) mod p. The subtraction is modulo p, so m2 is
        // first brought into p's range; it is already below q, and p and q are
        // the same width.
        let m2_mod_p = crt.p.reduce_once(&m2);
        let diff = crt.p.sub_mod(&m1, &m2_mod_p);
        let h = crt.p.mul_mod(&crt.qinv, &diff);

        // m = m2 + q * h, computed at full width. Both q and h are below 2^half,
        // so the product fits the modulus width and the sum cannot overflow it.
        let mut m = mul_vartime(crt.q.value(), &h, half_limbs, half_limbs);
        m.add_assign(&m2, self.public.n.limbs());

        // Raise it back to the public exponent and compare. A fault in either
        // half changes `m`, and then this comparison fails.
        let check = self.public.n.pow_public(&m, self.public.e);
        ensure!(
            bool::from(check.ct_eq(c, self.public.n.limbs())),
            Internal,
            "rsa crt result failed its verification; the output is withheld"
        );
        Ok(m)
    }

    /// The private exponent, big-endian, written into `out`.
    ///
    /// For serializing a key. The caller is responsible for erasing `out`.
    pub fn exponent_bytes(&self, out: &mut [u8]) -> Result<()> {
        ensure!(
            out.len() == self.size(),
            InvalidLength,
            "rsa exponent buffer"
        );
        self.d.to_be_bytes(out);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/// Primes below 256, for trial division.
///
/// Rejecting candidates with a small factor before the first Miller-Rabin round
/// removes around 80% of them for a tiny fraction of the cost.
const SMALL_PRIMES: [u64; 54] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
    101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
    197, 199, 211, 223, 227, 229, 233, 239, 241, 251,
];

/// Full-width multiplication, `a * b`, variable time.
///
/// Used only during key generation, on values that are secret but processed
/// once in an offline setting. See the module note on generation timing.
fn mul_vartime(a: &Uint, b: &Uint, a_limbs: usize, b_limbs: usize) -> Uint {
    let mut out = Uint::ZERO;
    for i in 0..a_limbs {
        let mut carry = 0u128;
        for j in 0..b_limbs {
            if i + j >= crate::uint::MAX_LIMBS {
                break;
            }
            let sum = (out.0[i + j] as u128) + (a.0[i] as u128) * (b.0[j] as u128) + carry;
            out.0[i + j] = sum as u64;
            carry = sum >> 64;
        }
        if i + b_limbs < crate::uint::MAX_LIMBS {
            out.0[i + b_limbs] = out.0[i + b_limbs].wrapping_add(carry as u64);
        }
    }
    out
}

/// Miller-Rabin probable-primality test against the first `rounds` prime bases.
///
/// # Why fixed bases rather than random ones
///
/// FIPS 186-5 C.3.1 draws each base at random, which matters when the candidate
/// might have been chosen adversarially to fool a known base set. Here the
/// candidate always comes from this library's own DRBG a few lines earlier, so
/// there is no adversary in a position to choose it, and fixed bases make the
/// test deterministic and therefore testable. A key arriving from outside is
/// never run through this function — [`RsaPublicKey::from_components`] does not
/// attempt to factor what it is given.
///
/// Composites survive a single round with probability at most 1/4, so `rounds`
/// prime bases put the failure probability below 4^-rounds for a random
/// candidate — far below the 2^-100 that FIPS 186-5 Table B.1 asks for by the
/// time `rounds` reaches 8, and in practice much lower still, since no
/// composite is known that fools even the first twelve prime bases.
fn is_probable_prime(candidate: &Uint, limbs: usize, rounds: usize) -> bool {
    if !candidate.is_odd() {
        return false;
    }
    for p in SMALL_PRIMES {
        if candidate.rem_u64(p) == 0 {
            // Divisible: prime only if the candidate *is* that small prime.
            return candidate.cmp_vartime(&Uint::from_u64(p)) == core::cmp::Ordering::Equal;
        }
    }

    let modulus = match Modulus::new(*candidate) {
        Some(m) => m,
        None => return false,
    };
    let one = Uint::one();
    let mut n_minus_1 = *candidate;
    n_minus_1.sub_assign(&one, limbs);

    // n - 1 = 2^s * d with d odd.
    let mut d = n_minus_1;
    let mut s = 0usize;
    while !d.is_odd() {
        d.shr1(limbs);
        s += 1;
    }
    let d_bits = d.bits();

    for &p in SMALL_PRIMES.iter().take(rounds) {
        let base = Uint::from_u64(p);
        // Trial division already established `candidate > p` for every small
        // prime, so the base is in range.
        let mut x = modulus.pow(&base, &d, d_bits);
        if x.cmp_vartime(&one) == core::cmp::Ordering::Equal
            || x.cmp_vartime(&n_minus_1) == core::cmp::Ordering::Equal
        {
            continue;
        }

        let mut witnessed = false;
        for _ in 1..s {
            x = modulus.pow_public(&x, 2);
            if x.cmp_vartime(&n_minus_1) == core::cmp::Ordering::Equal {
                witnessed = true;
                break;
            }
        }
        if !witnessed {
            return false;
        }
    }
    true
}

/// Draw a random odd candidate of exactly `bits` bits.
///
/// The top two bits are set, which is what guarantees that a product of two
/// such primes has exactly `2 * bits` bits — otherwise the modulus could come
/// out a bit short.
fn random_candidate<R: RandomSource + ?Sized>(bits: usize, rng: &mut R) -> Result<Uint> {
    let byte_len = bits / 8;
    let mut buf = [0u8; MAX_BYTES];
    rng.fill(&mut buf[..byte_len])?;
    buf[0] |= 0xC0;
    buf[byte_len - 1] |= 0x01;
    Uint::from_be_bytes(&buf[..byte_len]).ok_or(ic_core::err!(Internal, "candidate did not fit"))
}

/// Generate an RSA key pair of `bits` bits.
///
/// `bits` must be 2048, 3072, or 4096. Expect this to take seconds: the search
/// tries on the order of `ln(2^(bits/2))/2` candidates, most rejected by trial
/// division, and each survivor costs several modular exponentiations.
///
/// The public exponent is always [`PUBLIC_EXPONENT`].
///
/// # Standards note
///
/// The private exponent is derived modulo `phi(n) = (p-1)(q-1)`. FIPS 186-5
/// B.3 specifies `lambda(n) = lcm(p-1, q-1)`, which yields a smaller `d`. Both
/// satisfy `m^(ed) = m mod n`, so signatures and ciphertexts interoperate
/// either way, but a validator would want the `lambda` form.
pub fn generate<R: RandomSource + ?Sized>(bits: usize, rng: &mut R) -> Result<RsaPrivateKey> {
    ensure!(
        matches!(bits, 2048 | 3072 | 4096),
        InvalidParameter,
        "rsa key size must be 2048, 3072, or 4096 bits"
    );

    let half = bits / 2;
    let half_limbs = half / 64;
    let full_limbs = bits / 64;
    let rounds = 8;
    let one = Uint::one();
    let e = Uint::from_u64(PUBLIC_EXPONENT);

    // Bounded so a broken RNG cannot hang the caller.
    for _ in 0..(half * 40) {
        let p = random_candidate(half, rng)?;
        if !is_probable_prime(&p, half_limbs, rounds) {
            continue;
        }

        for _ in 0..(half * 40) {
            let q = random_candidate(half, rng)?;
            if q.cmp_vartime(&p) == core::cmp::Ordering::Equal {
                continue;
            }
            if !is_probable_prime(&q, half_limbs, rounds) {
                continue;
            }

            let n = mul_vartime(&p, &q, half_limbs, half_limbs);
            if n.bits() != bits {
                continue;
            }

            // phi = (p-1)(q-1)
            let mut p1 = p;
            p1.sub_assign(&one, half_limbs);
            let mut q1 = q;
            q1.sub_assign(&one, half_limbs);
            let phi = mul_vartime(&p1, &q1, half_limbs, half_limbs);

            // d = e^-1 mod phi. phi is even, and the binary extended GCD needs
            // an odd modulus, so invert the other way round: solve for d with
            // the roles swapped by inverting phi mod e is not possible here, so
            // fall back to rejecting the rare case where the inverse does not
            // exist (gcd(e, phi) != 1).
            let d = match modinv_even_modulus(&e, &phi, full_limbs) {
                Some(d) => d,
                None => continue,
            };

            // `d` above is not used directly: computing it proves that e is
            // coprime to phi(n), which is what makes this prime pair usable,
            // and then the key is rebuilt from the primes so that d and the CRT
            // parameters are derived in exactly one place.
            let _ = d;
            let half_bytes = half / 8;
            let mut p_bytes = [0u8; MAX_BYTES];
            p.to_be_bytes(&mut p_bytes[..half_bytes]);
            let mut q_bytes = [0u8; MAX_BYTES];
            q.to_be_bytes(&mut q_bytes[..half_bytes]);

            let key = RsaPrivateKey::from_primes(
                &p_bytes[..half_bytes],
                &q_bytes[..half_bytes],
                PUBLIC_EXPONENT,
            );
            p_bytes.zeroize();
            q_bytes.zeroize();
            // FIPS 140-3 requires a pairwise consistency test on a generated
            // key pair before it is used. It runs here rather than being
            // offered as a separate function a caller has to know to invoke.
            return key.and_then(|k| pairwise_consistency(&k).map(|()| k));
        }
    }

    Err(ic_core::err!(
        Internal,
        "rsa key generation did not converge"
    ))
}

/// The pairwise consistency test FIPS 140-3 requires on a generated key pair.
///
/// Applies the private operation to a fixed value and the public operation to
/// the result, and requires the original back. That is the whole content of
/// "these two halves are each other's inverse", and it is the check that
/// catches a keygen corrupted after the primality tests passed — a faulted
/// exponent, a mis-assembled CRT parameter, a bit flipped in memory.
///
/// It is not redundant with the per-operation CRT verification. That one proves
/// a single private operation was computed correctly; this proves the public
/// key published alongside it is the matching one. A key whose `d` does not
/// correspond to its `n` and `e` would pass the former on every operation and
/// still be useless, and the failure would appear at the far end as signatures
/// that never verify.
///
/// The test value is `2`, which is a valid input in `[0, n)` and is not a
/// fixed point of exponentiation the way `0` and `1` are. Those two satisfy
/// `m^(ed) = m` for *any* exponents at all, so a test using them would pass for
/// a completely broken key.
fn pairwise_consistency(key: &RsaPrivateKey) -> Result<()> {
    let size = key.size();
    let mut m = [0u8; MAX_BYTES];
    m[size - 1] = 2;

    let mut signed = [0u8; MAX_BYTES];
    key.raw_private(&m[..size], &mut signed[..size])?;

    let mut recovered = [0u8; MAX_BYTES];
    key.public_key()
        .raw_public(&signed[..size], &mut recovered[..size])?;

    let matched = ic_core::ct::verify(&m[..size], &recovered[..size]);
    signed.zeroize();
    recovered.zeroize();
    ensure!(
        matched,
        SelfTestFailed,
        "rsa key failed its pairwise consistency test; the key is withheld"
    );
    Ok(())
}

/// Modular inverse of a small odd `a` modulo an even `m`.
///
/// The binary extended GCD needs an odd modulus, which `phi(n)` never is. This
/// solves `a * d = 1 (mod m)` by inverting in the other direction: it finds
/// `t = m^-1 mod a` (a small modulus, since `a` is the public exponent) and
/// then reconstructs `d = (1 + m * (a - t)) / a` exactly.
fn modinv_even_modulus(a: &Uint, m: &Uint, limbs: usize) -> Option<Uint> {
    // `a` is the public exponent and fits in a u64.
    let a_small = a.0[0];
    if a_small == 0 || a.bits() > 64 {
        return None;
    }
    let m_mod_a = m.rem_u64(a_small);
    if m_mod_a == 0 {
        return None; // not coprime
    }
    // t = m^-1 mod a, by extended Euclid on two small integers.
    let t = small_modinv(m_mod_a, a_small)?;
    // k = a - t, so that (1 + m*k) is divisible by a.
    let k = a_small - t;

    // d = (1 + m*k) / a
    let mut product = mul_small(m, k, limbs);
    product.add_assign(&Uint::one(), limbs + 1);
    div_small(&mut product, a_small, limbs + 1)?;
    Some(product)
}

/// Assemble the CRT parameters, or decline them.
///
/// The CRT path reduces a full-width value modulo a half-width prime by
/// splitting it at the halfway word, which needs the prime to fill its top limb
/// and to be exactly half the modulus width. Primes from [`generate`] always
/// satisfy both, since the candidate search forces the top two bits. A prime
/// from elsewhere might not, and then the key falls back to the plain
/// exponentiation rather than taking a shortcut that does not hold.
fn crt_params_if_usable(
    p: Modulus,
    q: Modulus,
    dp: Uint,
    dq: Uint,
    qinv: Uint,
    half_bits: usize,
    full_limbs: usize,
) -> Option<CrtParams> {
    let usable = p.is_full_width()
        && q.is_full_width()
        && p.limbs() == q.limbs()
        && p.limbs() * 2 == full_limbs
        && full_limbs <= MAX_LIMBS;
    usable.then_some(CrtParams {
        p,
        q,
        dp,
        dq,
        qinv,
        half_bits,
    })
}

/// Extended Euclid on two `u64`s.
fn small_modinv(a: u64, m: u64) -> Option<u64> {
    let (mut old_r, mut r) = (a as i128, m as i128);
    let (mut old_s, mut s) = (1i128, 0i128);
    while r != 0 {
        let q = old_r / r;
        (old_r, r) = (r, old_r - q * r);
        (old_s, s) = (s, old_s - q * s);
    }
    if old_r != 1 {
        return None;
    }
    Some(old_s.rem_euclid(m as i128) as u64)
}

/// `a * b` for a small `b`.
fn mul_small(a: &Uint, b: u64, limbs: usize) -> Uint {
    let mut out = Uint::ZERO;
    let mut carry = 0u128;
    for i in 0..limbs {
        let sum = (a.0[i] as u128) * (b as u128) + carry;
        out.0[i] = sum as u64;
        carry = sum >> 64;
    }
    if limbs < crate::uint::MAX_LIMBS {
        out.0[limbs] = carry as u64;
    }
    out
}

/// Divide in place by a small integer, returning `None` if it does not divide
/// exactly.
fn div_small(a: &mut Uint, b: u64, limbs: usize) -> Option<()> {
    let mut rem = 0u128;
    for i in (0..limbs).rev() {
        let cur = (rem << 64) | (a.0[i] as u128);
        a.0[i] = (cur / b as u128) as u64;
        rem = cur % b as u128;
    }
    if rem != 0 {
        return None;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pairwise consistency test must reject a key whose halves disagree.
    ///
    /// Built by taking a real key and replacing `d` with a value that is not
    /// the inverse of `e`. Every structural check still passes -- the modulus
    /// is the right size, the exponent is right, nothing is malformed -- and
    /// only applying both operations in turn reveals it. That is the failure
    /// mode the test exists for, and it would otherwise surface at the far end
    /// as signatures nobody can verify.
    #[test]
    fn the_pairwise_consistency_test_rejects_a_mismatched_key() {
        let good = crate::testkey::test_private_key();
        let size = good.size();
        let mut n = vec![0u8; size];
        good.public_key().modulus_bytes(&mut n).unwrap();
        let mut d = vec![0u8; size];
        good.exponent_bytes(&mut d).unwrap();

        // The genuine key passes, including when rebuilt from its components
        // (which takes the non-CRT path, so both paths are covered).
        pairwise_consistency(&good).expect("a real key must pass");
        let rebuilt = RsaPrivateKey::from_components(&n, good.public_key().exponent(), &d).unwrap();
        pairwise_consistency(&rebuilt).expect("the rebuilt key must pass too");

        // Disturb d, leaving every structural property intact.
        let last = d.len() - 1;
        d[last] ^= 0x02;
        let bad = RsaPrivateKey::from_components(&n, good.public_key().exponent(), &d).unwrap();
        assert!(
            pairwise_consistency(&bad).is_err(),
            "a key whose d does not match e passed the consistency test"
        );
    }

    #[test]
    fn small_modular_inverse() {
        assert_eq!(small_modinv(3, 7), Some(5)); // 3*5 = 15 = 1 mod 7
        assert_eq!(
            small_modinv(65537, 11),
            Some(small_modinv(65537 % 11, 11).unwrap())
        );
        assert_eq!(small_modinv(2, 4), None, "not coprime");
    }

    #[test]
    fn small_multiply_and_divide_round_trip() {
        let a = Uint::from_u64(123_456_789);
        let mut p = mul_small(&a, 65537, 4);
        assert_eq!(p.0[0], 123_456_789u64 * 65537);
        div_small(&mut p, 65537, 4).unwrap();
        assert_eq!(p.0[0], 123_456_789);

        let mut q = Uint::from_u64(10);
        assert!(div_small(&mut q, 3, 4).is_none(), "inexact division");
    }

    #[test]
    fn full_multiply_matches_u128() {
        let a = Uint::from_u64(0xffff_ffff_ffff_fffb);
        let b = Uint::from_u64(0xffff_ffff_ffff_fff9);
        let p = mul_vartime(&a, &b, 1, 1);
        let want = (a.0[0] as u128) * (b.0[0] as u128);
        assert_eq!(p.0[0], want as u64);
        assert_eq!(p.0[1], (want >> 64) as u64);
    }

    #[test]
    fn primality_recognizes_known_values() {
        for p in [3u64, 5, 7, 65537, 2_147_483_647, 1_000_000_007] {
            assert!(is_probable_prime(&Uint::from_u64(p), 1, 8), "{p} is prime");
        }
        for c in [9u64, 15, 21, 65535, 2_147_483_645, 1_000_000_009 * 3] {
            assert!(
                !is_probable_prime(&Uint::from_u64(c), 1, 8),
                "{c} is composite"
            );
        }
    }

    /// A Carmichael number passes a naive Fermat test but must fail
    /// Miller-Rabin, which is the whole reason for using the latter.
    #[test]
    fn primality_rejects_carmichael_numbers() {
        for c in [561u64, 1105, 1729, 2465, 6601, 8911, 41041, 62745] {
            assert!(
                !is_probable_prime(&Uint::from_u64(c), 1, 8),
                "{c} is a Carmichael number, not a prime"
            );
        }
    }

    #[test]
    fn generation_rejects_unsupported_sizes() {
        let mut rng = ic_drbg::Rng::from_entropy(&[0x33u8; 32], b"sizes").unwrap();
        for bits in [512usize, 1024, 2047, 2049, 8192] {
            assert!(generate(bits, &mut rng).is_err(), "{bits} bits");
        }
    }

    /// The one property that matters for a generated key: it is a working RSA
    /// key, meaning `(m^e)^d = m (mod n)`. That holds only if `p` and `q` really
    /// are prime and `d` really is the inverse of `e` modulo `phi(n)`, so a
    /// broken primality test or a broken inversion shows up here.
    ///
    /// This generates three 2048-bit keys, which costs a couple of seconds even
    /// in a debug build — worth paying on every run for the only test that
    /// exercises key generation end to end.
    #[test]
    fn generated_keys_satisfy_the_rsa_identity() {
        let mut rng = ic_drbg::Rng::from_entropy(&[0x44u8; 32], b"generate").unwrap();
        let key = generate(2048, &mut rng).unwrap();
        assert_eq!(key.public_key().bits(), 2048);
        assert_eq!(key.size(), 256);

        for seed in [1u8, 0x5a, 0xfe] {
            let mut message = [seed; 256];
            message[0] = 0;
            let mut encrypted = [0u8; 256];
            key.public_key()
                .raw_public(&message, &mut encrypted)
                .unwrap();
            let mut recovered = [0u8; 256];
            key.raw_private(&encrypted, &mut recovered).unwrap();
            assert_eq!(recovered, message, "seed {seed}");
        }

        // Two generations from different seeds must not collide.
        let mut other_rng = ic_drbg::Rng::from_entropy(&[0x55u8; 32], b"generate").unwrap();
        let other = generate(2048, &mut other_rng).unwrap();
        let mut a = [0u8; 256];
        let mut b = [0u8; 256];
        key.public_key().modulus_bytes(&mut a).unwrap();
        other.public_key().modulus_bytes(&mut b).unwrap();
        assert_ne!(a, b, "distinct seeds give distinct keys");
    }

    /// The strongest oracle available for the CRT path: the same key, both
    /// ways, must produce identical output. The plain path is already checked
    /// against a naive reference in `uint`, so agreement here transfers that
    /// evidence to the fast path.
    #[test]
    fn the_crt_path_agrees_with_the_plain_path() {
        let mut rng = ic_drbg::Rng::from_entropy(&[0x66u8; 32], b"crt-diff").unwrap();
        let crt_key = generate(2048, &mut rng).unwrap();
        assert!(crt_key.uses_crt(), "a generated key carries its primes");

        // The same key without the primes, which forces the slow path.
        let mut n = [0u8; 256];
        crt_key.public_key().modulus_bytes(&mut n).unwrap();
        let mut d = [0u8; 256];
        crt_key.exponent_bytes(&mut d).unwrap();
        let plain_key = RsaPrivateKey::from_components(&n, PUBLIC_EXPONENT, &d).unwrap();
        assert!(!plain_key.uses_crt());

        for seed in [0u8, 1, 2, 0x5a, 0x7f, 0x80, 0xfe] {
            let mut message = [seed; 256];
            message[0] = 0; // keep it below the modulus

            let mut via_crt = [0u8; 256];
            crt_key.raw_private(&message, &mut via_crt).unwrap();
            let mut via_plain = [0u8; 256];
            plain_key.raw_private(&message, &mut via_plain).unwrap();
            assert_eq!(via_crt, via_plain, "seed {seed}");

            // And both invert under the public operation.
            let mut back = [0u8; 256];
            crt_key
                .public_key()
                .raw_public(&via_crt, &mut back)
                .unwrap();
            assert_eq!(back, message, "seed {seed}");
        }
    }

    /// `from_primes` must reproduce a key bit for bit from its factors alone.
    #[test]
    fn a_key_can_be_rebuilt_from_its_primes() {
        let mut rng = ic_drbg::Rng::from_entropy(&[0x77u8; 32], b"from-primes").unwrap();
        let original = generate(2048, &mut rng).unwrap();

        let mut p = [0u8; 128];
        let mut q = [0u8; 128];
        original.prime_bytes(&mut p, &mut q).unwrap();
        let rebuilt = RsaPrivateKey::from_primes(&p, &q, PUBLIC_EXPONENT).unwrap();

        let mut a = [0u8; 256];
        original.public_key().modulus_bytes(&mut a).unwrap();
        let mut b = [0u8; 256];
        rebuilt.public_key().modulus_bytes(&mut b).unwrap();
        assert_eq!(a, b, "same modulus");

        let mut da = [0u8; 256];
        original.exponent_bytes(&mut da).unwrap();
        let mut db = [0u8; 256];
        rebuilt.exponent_bytes(&mut db).unwrap();
        assert_eq!(da, db, "same private exponent");

        // n = p * q, checked against the modulus the key reports.
        let p_uint = Uint::from_be_bytes(&p).unwrap();
        let q_uint = Uint::from_be_bytes(&q).unwrap();
        let product = mul_vartime(&p_uint, &q_uint, 16, 16);
        let mut product_bytes = [0u8; 256];
        product.to_be_bytes(&mut product_bytes);
        assert_eq!(product_bytes, a, "n is the product of the primes");
    }

    /// The CRT exponents must satisfy their defining congruences.
    #[test]
    fn the_crt_exponents_satisfy_their_congruences() {
        let mut rng = ic_drbg::Rng::from_entropy(&[0x88u8; 32], b"crt-params").unwrap();
        let key = generate(2048, &mut rng).unwrap();

        let mut p = [0u8; 128];
        let mut q = [0u8; 128];
        key.prime_bytes(&mut p, &mut q).unwrap();
        let mut dp = [0u8; 128];
        let mut dq = [0u8; 128];
        let mut qinv = [0u8; 128];
        key.crt_exponent_bytes(&mut dp, &mut dq, &mut qinv).unwrap();

        let p_uint = Uint::from_be_bytes(&p).unwrap();
        let q_uint = Uint::from_be_bytes(&q).unwrap();
        let one = Uint::one();

        // e * dP = 1 mod (p - 1), and likewise for q.
        for (prime, exponent, name) in [(p_uint, dp, "p"), (q_uint, dq, "q")] {
            let mut minus_one = prime;
            minus_one.sub_assign(&one, 16);
            // p-1 is even, so use the same inversion the derivation used and
            // check it lands on the same value.
            let recomputed =
                modinv_even_modulus(&Uint::from_u64(PUBLIC_EXPONENT), &minus_one, 16).unwrap();
            let mut expected = [0u8; 128];
            recomputed.to_be_bytes(&mut expected);
            assert_eq!(expected, exponent, "e^-1 mod ({name} - 1)");
        }

        // qInv * q = 1 mod p.
        let p_mod = Modulus::new(p_uint).unwrap();
        let qinv_uint = Uint::from_be_bytes(&qinv).unwrap();
        let product = p_mod.mul_mod(&qinv_uint, &p_mod.reduce_once(&q_uint));
        assert_eq!(product, one, "q * q^-1 = 1 mod p");
    }

    /// A key without its primes still works; it simply takes the slow path and
    /// says so rather than pretending to have parameters it does not.
    #[test]
    fn a_key_without_primes_declines_the_crt_accessors() {
        let mut n = [0u8; 256];
        n[0] = 0x80;
        n[255] = 1;
        let mut d = [0u8; 256];
        d[255] = 3;
        let key = RsaPrivateKey::from_components(&n, 65537, &d).unwrap();
        assert!(!key.uses_crt());

        let mut p = [0u8; 128];
        let mut q = [0u8; 128];
        assert!(key.prime_bytes(&mut p, &mut q).is_err());
        let mut a = [0u8; 128];
        let mut b = [0u8; 128];
        let mut c = [0u8; 128];
        assert!(key.crt_exponent_bytes(&mut a, &mut b, &mut c).is_err());
    }

    #[test]
    fn from_primes_validates_its_inputs() {
        let p = [0xc1u8; 128];
        assert!(
            RsaPrivateKey::from_primes(&p, &p, 65537).is_err(),
            "the primes must differ"
        );
        let short = [0xc1u8; 64];
        assert!(
            RsaPrivateKey::from_primes(&p, &short, 65537).is_err(),
            "the primes must be the same size"
        );
        assert!(
            RsaPrivateKey::from_primes(&p, &p, 4).is_err(),
            "the exponent must be odd"
        );
    }

    /// Report the actual CRT speedup rather than asserting a claimed one.
    ///
    /// Ignored, because a timing assertion on a shared machine is a flaky test.
    /// Run it with `--release -- --ignored --nocapture` when the number in the
    /// documentation needs checking.
    #[test]
    #[ignore = "timing; run manually with --release"]
    fn report_the_crt_speedup() {
        use std::time::Instant;

        let mut rng = ic_drbg::Rng::from_entropy(&[0x99u8; 32], b"bench").unwrap();
        let crt_key = generate(2048, &mut rng).unwrap();
        let mut n = [0u8; 256];
        crt_key.public_key().modulus_bytes(&mut n).unwrap();
        let mut d = [0u8; 256];
        crt_key.exponent_bytes(&mut d).unwrap();
        let plain_key = RsaPrivateKey::from_components(&n, PUBLIC_EXPONENT, &d).unwrap();

        let mut message = [0x5au8; 256];
        message[0] = 0;
        let mut out = [0u8; 256];
        let rounds = 20;

        let start = Instant::now();
        for _ in 0..rounds {
            crt_key.raw_private(&message, &mut out).unwrap();
        }
        let with_crt = start.elapsed();

        let start = Instant::now();
        for _ in 0..rounds {
            plain_key.raw_private(&message, &mut out).unwrap();
        }
        let without = start.elapsed();

        println!(
            "2048-bit private operation: {:?} with CRT, {:?} without, {:.2}x",
            with_crt / rounds,
            without / rounds,
            without.as_secs_f64() / with_crt.as_secs_f64()
        );
    }

    #[test]
    fn public_key_validates_its_parameters() {
        let mut n = [0u8; 256];
        n[0] = 0x80;
        n[255] = 1;
        assert!(RsaPublicKey::from_components(&n, 65537).is_ok());
        assert!(
            RsaPublicKey::from_components(&n, 4).is_err(),
            "even exponent"
        );
        assert!(
            RsaPublicKey::from_components(&n, 1).is_err(),
            "exponent too small"
        );

        // Too small a modulus.
        let mut small = [0u8; 128];
        small[0] = 0x80;
        small[127] = 1;
        assert!(RsaPublicKey::from_components(&small, 65537).is_err());

        // Even modulus.
        let mut even = [0u8; 256];
        even[0] = 0x80;
        assert!(RsaPublicKey::from_components(&even, 65537).is_err());
    }
}
