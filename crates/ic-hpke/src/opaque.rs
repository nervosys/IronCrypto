//! OPAQUE, RFC 9807: password authentication in which the server never sees
//! the password.
//!
//! A client registers once and then logs in with a password, as with any
//! password scheme, but the server stores no password hash it could attack
//! offline without first doing the expensive work for each guess against
//! its own OPRF key, and nothing it receives during a login reveals the
//! password. A successful login also leaves both sides with a shared session
//! key, and the client with an `export_key` for encrypting data only it can
//! later recover.
//!
//! This is the OPAQUE-3DH configuration over P-256: the OPRF is RFC 9497's
//! P256-SHA256, the key exchange is three Diffie-Hellman operations on
//! P-256, and the KDF, MAC and hash are HKDF, HMAC and SHA-256 -- the second
//! of RFC 9807 section 7's recommended configurations, with the key
//! stretching function the caller's choice of [`Ksf`].
//!
//! ```
//! use ic_hpke::opaque::{self, Argon2idKsf, ServerSetup};
//! # struct Fixed(u8);
//! # impl ic_core::traits::RandomSource for Fixed {
//! #     fn fill(&mut self, out: &mut [u8]) -> ic_core::Result<()> { self.0 = self.0.wrapping_add(1); out.fill(self.0); Ok(()) }
//! # }
//! # let mut rng = Fixed(0);
//! let ksf = Argon2idKsf::small_for_tests();
//! # let ksf = &ksf;
//! let server = ServerSetup::generate(&mut rng)?;
//!
//! // Registration.
//! let (state, request) = opaque::registration_start(b"hunter2", &mut rng)?;
//! let response = server.registration_response(&request, b"alice")?;
//! let (record, _export_key) = opaque::registration_finish(
//!     ksf, &state, b"hunter2", &response, None, None, &mut rng)?;
//!
//! // Login.
//! let (client, ke1) = opaque::login_start(b"hunter2", &mut rng)?;
//! let (pending, ke2) = server.login_respond(
//!     &record, b"alice", &ke1, None, None, b"my app v1", &mut rng)?;
//! let (ke3, client_key, _) = client.finish(ksf, b"hunter2", &ke2, None, None, b"my app v1")?;
//! let server_key = pending.finish(&ke3)?;
//! assert_eq!(*client_key, *server_key);
//! # Ok::<(), ic_core::Error>(())
//! ```
//!
//! # What the server keeps
//!
//! A [`ServerSetup`] -- an OPRF seed and an AKE key pair -- for all clients,
//! and per client its 129-byte [`RECORD_LEN`] record under a credential
//! identifier the server chooses. When a login names a client with no
//! record, answer with [`ServerSetup::fake_record`] so the response looks
//! like any other; RFC 9807 section 10.9 explains why.
//!
//! Checked against RFC 9807 appendix C.1.5, C.1.6 and C.2.3, the P-256
//! vectors, byte for byte.

use ic_core::traits::{Mac, RandomSource};
use ic_core::{ensure, Result, Zeroize, Zeroizing};
use ic_ec::oprf::{self, Mode, ServerKey, ELEMENT_LEN};
use ic_kdf::Hkdf;
use ic_mac::HmacSha256;

/// `Nn`, `Nseed`: nonces and seeds.
const NN: usize = 32;
/// `Nh`, `Nm`, `Nx`: hash, MAC and extract output.
const NH: usize = 32;
/// `Npk`: an encoded public key.
const NPK: usize = ELEMENT_LEN;
/// `Nsk`: an encoded private key.
const NSK: usize = 32;

/// Bytes in an envelope: nonce and tag.
pub const ENVELOPE_LEN: usize = NN + NH;
/// Bytes in a registration request.
pub const REGISTRATION_REQUEST_LEN: usize = ELEMENT_LEN;
/// Bytes in a registration response: evaluated element and server key.
pub const REGISTRATION_RESPONSE_LEN: usize = ELEMENT_LEN + NPK;
/// Bytes in the record the server stores: client key, masking key, envelope.
pub const RECORD_LEN: usize = NPK + NH + ENVELOPE_LEN;
/// Bytes in KE1: blinded element, client nonce, client key share.
pub const KE1_LEN: usize = ELEMENT_LEN + NN + NPK;
/// Bytes in a credential response: evaluated element, masking nonce, and the
/// masked server key and envelope.
const CREDENTIAL_RESPONSE_LEN: usize = ELEMENT_LEN + NN + NPK + ENVELOPE_LEN;
/// Bytes in KE2: credential response, server nonce, server key share, MAC.
pub const KE2_LEN: usize = CREDENTIAL_RESPONSE_LEN + NN + NPK + NH;
/// Bytes in KE3: the client's MAC.
pub const KE3_LEN: usize = NH;
/// Bytes in a session key and an export key.
pub const KEY_LEN: usize = NH;

/// A key stretching function: what makes each password guess against a
/// stolen record expensive. RFC 9807 section 7 recommends Argon2id or
/// scrypt with fixed parameters; both sides must use the same one.
pub trait Ksf {
    /// Stretch the OPRF output into `NH` bytes.
    fn stretch(&self, input: &[u8; NH], out: &mut [u8; NH]) -> Result<()>;
}

/// Argon2id as RFC 9807 section 7 configures it: a zero salt of 16 bytes,
/// version 1.3, a 32-byte tag, and the parameters given.
pub struct Argon2idKsf(pub ic_kdf::Argon2Params);

impl Argon2idKsf {
    /// RFC 9807's recommended parameters: 2 GiB, one pass, four lanes.
    pub const RECOMMENDED: Argon2idKsf = Argon2idKsf(ic_kdf::Argon2Params {
        memory_kib: 1 << 21,
        passes: 1,
        lanes: 4,
    });

    /// 64 KiB and one pass: fast, and fit for tests and examples only.
    pub const fn small_for_tests() -> Argon2idKsf {
        Argon2idKsf(ic_kdf::Argon2Params {
            memory_kib: 64,
            passes: 1,
            lanes: 1,
        })
    }
}

impl Ksf for Argon2idKsf {
    fn stretch(&self, input: &[u8; NH], out: &mut [u8; NH]) -> Result<()> {
        ic_kdf::argon2(ic_kdf::Variant::Argon2id, &self.0, input, &[0u8; 16], out)
    }
}

/// scrypt as RFC 9807 section 7 configures it: a zero salt of 16 bytes and
/// a 32-byte output; the recommendation is `N = 2^15`, `r = 8`, `p = 1`.
pub struct ScryptKsf(pub ic_kdf::scrypt::ScryptParams);

impl ScryptKsf {
    /// RFC 9807's recommended parameters.
    pub const RECOMMENDED: ScryptKsf = ScryptKsf(ic_kdf::scrypt::ScryptParams {
        log_n: 15,
        r: 8,
        p: 1,
    });
}

impl Ksf for ScryptKsf {
    fn stretch(&self, input: &[u8; NH], out: &mut [u8; NH]) -> Result<()> {
        ic_kdf::scrypt::scrypt(input, &[0u8; 16], &self.0, out)
    }
}

/// No stretching: `Stretch(x) = x`. RFC 9807's test vectors use it. It
/// leaves a stolen record open to fast guessing, so it is for tests only.
pub struct IdentityKsf;

impl Ksf for IdentityKsf {
    fn stretch(&self, input: &[u8; NH], out: &mut [u8; NH]) -> Result<()> {
        out.copy_from_slice(input);
        Ok(())
    }
}

/// HKDF-Expand with SHA-256.
fn expand(prk: &[u8], info: &[&[u8]], out: &mut [u8]) -> Result<()> {
    let mut joined = [0u8; 256];
    let total: usize = info.iter().map(|p| p.len()).sum();
    ensure!(total <= joined.len(), InvalidLength, "opaque expand info");
    let mut at = 0;
    for part in info {
        joined[at..at + part.len()].copy_from_slice(part);
        at += part.len();
    }
    Hkdf::<HmacSha256>::expand(prk, &joined[..total], out)
}

/// `Expand-Label(secret, label, context, NH)`, section 6.4.2.
fn expand_label(secret: &[u8], label: &[u8], context: &[u8], out: &mut [u8; NH]) -> Result<()> {
    let full = 7 + label.len();
    expand(
        secret,
        &[
            &(NH as u16).to_be_bytes(),
            &[full as u8],
            b"OPAQUE-",
            label,
            &[context.len() as u8],
            context,
        ],
        out,
    )
}

fn mac(key: &[u8], parts: &[&[u8]]) -> Result<[u8; NH]> {
    let mut m = HmacSha256::new(key)?;
    for p in parts {
        m.update(p);
    }
    let mut out = [0u8; NH];
    out.copy_from_slice(m.finalize().as_ref());
    Ok(out)
}

fn sha256(parts: &[&[u8]]) -> [u8; NH] {
    use ic_core::traits::Digest;
    let mut h = ic_hash::Sha256::new();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; NH];
    out.copy_from_slice(h.finalize().as_ref());
    out
}

fn random<R: RandomSource + ?Sized, const N: usize>(rng: &mut R) -> Result<[u8; N]> {
    let mut out = [0u8; N];
    rng.fill(&mut out)?;
    Ok(out)
}

/// `DeriveDiffieHellmanKeyPair(seed)`: RFC 9497's `DeriveKeyPair` under the
/// OPRF mode's context, with the info OPAQUE names.
fn derive_dh_key_pair(seed: &[u8; NN]) -> Result<ServerKey> {
    ServerKey::derive(Mode::Oprf, seed, b"OPAQUE-DeriveDiffieHellmanKeyPair")
}

/// The per-client OPRF key, from the global seed and the credential
/// identifier.
fn oprf_key(oprf_seed: &[u8; NH], credential_identifier: &[u8]) -> Result<ServerKey> {
    let mut seed = Zeroizing::new([0u8; NN]);
    expand(
        oprf_seed,
        &[credential_identifier, b"OprfKey"],
        seed.get_mut(),
    )?;
    ServerKey::derive(Mode::Oprf, &seed, b"OPAQUE-DeriveKeyPair")
}

/// The identities as `CreateCleartextCredentials` defaults them: each to its
/// party's public key when absent.
fn identities<'a>(
    server_public_key: &'a [u8; NPK],
    client_public_key: &'a [u8; NPK],
    server_identity: Option<&'a [u8]>,
    client_identity: Option<&'a [u8]>,
) -> Result<(&'a [u8], &'a [u8])> {
    let s = server_identity.unwrap_or(server_public_key);
    let c = client_identity.unwrap_or(client_public_key);
    ensure!(
        !s.is_empty()
            && !c.is_empty()
            && s.len() <= u16::MAX as usize
            && c.len() <= u16::MAX as usize,
        InvalidLength,
        "opaque identity must be 1 to 65535 bytes"
    );
    Ok((s, c))
}

/// The envelope's MAC input after the nonce: the server key and both
/// identities, length-prefixed.
fn envelope_tag(
    auth_key: &[u8; NH],
    nonce: &[u8],
    server_public_key: &[u8; NPK],
    server_identity: &[u8],
    client_identity: &[u8],
) -> Result<[u8; NH]> {
    mac(
        auth_key,
        &[
            nonce,
            server_public_key,
            &(server_identity.len() as u16).to_be_bytes(),
            server_identity,
            &(client_identity.len() as u16).to_be_bytes(),
            client_identity,
        ],
    )
}

/// The OPRF output stretched and extracted: `randomized_password`.
fn randomized_password<K: Ksf + ?Sized>(
    ksf: &K,
    oprf_output: &[u8; NH],
) -> Result<Zeroizing<[u8; NH]>> {
    let mut stretched = Zeroizing::new([0u8; NH]);
    ksf.stretch(oprf_output, stretched.get_mut())?;
    let mut ikm = Zeroizing::new([0u8; 2 * NH]);
    ikm.get_mut()[..NH].copy_from_slice(oprf_output);
    ikm.get_mut()[NH..].copy_from_slice(&stretched[..]);
    let mut out = Zeroizing::new([0u8; NH]);
    Hkdf::<HmacSha256>::extract(&[], &ikm[..], out.get_mut())?;
    Ok(out)
}

/// The keys an envelope nonce and a randomized password give.
struct EnvelopeKeys {
    auth_key: Zeroizing<[u8; NH]>,
    export_key: Zeroizing<[u8; NH]>,
    client: ServerKey,
}

fn envelope_keys(rwd: &[u8; NH], nonce: &[u8]) -> Result<EnvelopeKeys> {
    let mut auth_key = Zeroizing::new([0u8; NH]);
    expand(rwd, &[nonce, b"AuthKey"], auth_key.get_mut())?;
    let mut export_key = Zeroizing::new([0u8; NH]);
    expand(rwd, &[nonce, b"ExportKey"], export_key.get_mut())?;
    let mut seed = Zeroizing::new([0u8; NN]);
    expand(rwd, &[nonce, b"PrivateKey"], seed.get_mut())?;
    Ok(EnvelopeKeys {
        auth_key,
        export_key,
        client: derive_dh_key_pair(&seed)?,
    })
}

/// What the server holds for all clients: the OPRF seed and its AKE key pair.
pub struct ServerSetup {
    oprf_seed: [u8; NH],
    key: ServerKey,
}

impl Drop for ServerSetup {
    fn drop(&mut self) {
        self.oprf_seed.zeroize();
    }
}

impl ServerSetup {
    /// A fresh setup. Pass `ic_drbg::Rng`.
    pub fn generate<R: RandomSource + ?Sized>(rng: &mut R) -> Result<Self> {
        ic_core::module::operational()?;
        let oprf_seed = random::<_, NH>(rng)?;
        let mut seed = Zeroizing::new(random::<_, NN>(rng)?);
        let key = derive_dh_key_pair(&seed)?;
        seed.get_mut().zeroize();
        Ok(Self { oprf_seed, key })
    }

    /// A setup from its stored parts: the OPRF seed and the AKE private key.
    pub fn from_parts(oprf_seed: &[u8; NH], server_private_key: &[u8; NSK]) -> Result<Self> {
        ic_core::module::operational()?;
        Ok(Self {
            oprf_seed: *oprf_seed,
            key: ServerKey::from_bytes(Mode::Oprf, server_private_key)?,
        })
    }

    /// The stored parts, for persisting the setup.
    pub fn to_parts(&self) -> (Zeroizing<[u8; NH]>, Zeroizing<[u8; NSK]>) {
        (Zeroizing::new(self.oprf_seed), self.key.to_bytes())
    }

    /// The server's AKE public key.
    pub fn public_key(&self) -> [u8; NPK] {
        self.key.public_key()
    }

    /// `CreateRegistrationResponse`: evaluate a client's registration request
    /// under its credential identifier's OPRF key.
    pub fn registration_response(
        &self,
        request: &[u8; REGISTRATION_REQUEST_LEN],
        credential_identifier: &[u8],
    ) -> Result<[u8; REGISTRATION_RESPONSE_LEN]> {
        ic_core::module::operational()?;
        let key = oprf_key(&self.oprf_seed, credential_identifier)?;
        let (evaluated, _) = key.blind_evaluate(request, b"", &mut NoRandom)?;
        let mut out = [0u8; REGISTRATION_RESPONSE_LEN];
        out[..ELEMENT_LEN].copy_from_slice(&evaluated);
        out[ELEMENT_LEN..].copy_from_slice(&self.key.public_key());
        Ok(out)
    }

    /// A record for a client that does not exist, so that a login attempt
    /// against an unknown identifier gets a response indistinguishable from
    /// a real one. Make one per identifier and keep it, or derive it
    /// deterministically, so that two attempts see the same.
    pub fn fake_record<R: RandomSource + ?Sized>(rng: &mut R) -> Result<[u8; RECORD_LEN]> {
        ic_core::module::operational()?;
        let mut seed = Zeroizing::new(random::<_, NN>(rng)?);
        let client = derive_dh_key_pair(&seed)?;
        seed.get_mut().zeroize();
        let mut record = [0u8; RECORD_LEN];
        record[..NPK].copy_from_slice(&client.public_key());
        rng.fill(&mut record[NPK..NPK + NH])?;
        Ok(record)
    }

    /// `GenerateKE2`: answer a login.
    ///
    /// `record` is what [`registration_finish`] produced for this
    /// `credential_identifier`, or a [`ServerSetup::fake_record`].
    /// `context` binds the application; both sides must give the same.
    #[allow(clippy::too_many_arguments)]
    pub fn login_respond<R: RandomSource + ?Sized>(
        &self,
        record: &[u8; RECORD_LEN],
        credential_identifier: &[u8],
        ke1: &[u8; KE1_LEN],
        client_identity: Option<&[u8]>,
        server_identity: Option<&[u8]>,
        context: &[u8],
        rng: &mut R,
    ) -> Result<(ServerLogin, [u8; KE2_LEN])> {
        ic_core::module::operational()?;
        let client_public_key: [u8; NPK] = record[..NPK].try_into().map_err(|_| bad_record())?;
        oprf::validate_element(&client_public_key)?;
        let masking_key = &record[NPK..NPK + NH];
        let envelope = &record[NPK + NH..];

        // CreateCredentialResponse.
        let key = oprf_key(&self.oprf_seed, credential_identifier)?;
        let blinded: [u8; ELEMENT_LEN] = ke1[..ELEMENT_LEN].try_into().map_err(|_| bad_record())?;
        let (evaluated, _) = key.blind_evaluate(&blinded, b"", &mut NoRandom)?;
        let masking_nonce = random::<_, NN>(rng)?;
        let mut pad = [0u8; NPK + ENVELOPE_LEN];
        expand(
            masking_key,
            &[&masking_nonce, b"CredentialResponsePad"],
            &mut pad,
        )?;
        let mut ke2 = [0u8; KE2_LEN];
        ke2[..ELEMENT_LEN].copy_from_slice(&evaluated);
        ke2[ELEMENT_LEN..ELEMENT_LEN + NN].copy_from_slice(&masking_nonce);
        let server_public_key = self.key.public_key();
        let masked = &mut ke2[ELEMENT_LEN + NN..CREDENTIAL_RESPONSE_LEN];
        for (i, m) in masked.iter_mut().enumerate() {
            let plain = if i < NPK {
                server_public_key[i]
            } else {
                envelope[i - NPK]
            };
            *m = plain ^ pad[i];
        }
        pad.zeroize();

        // AuthServerRespond.
        let (s_id, c_id) = identities(
            &server_public_key,
            &client_public_key,
            server_identity,
            client_identity,
        )?;
        let server_nonce = random::<_, NN>(rng)?;
        let mut keyshare_seed = Zeroizing::new(random::<_, NN>(rng)?);
        let keyshare = derive_dh_key_pair(&keyshare_seed)?;
        keyshare_seed.get_mut().zeroize();
        let at = CREDENTIAL_RESPONSE_LEN;
        ke2[at..at + NN].copy_from_slice(&server_nonce);
        ke2[at + NN..at + NN + NPK].copy_from_slice(&keyshare.public_key());

        let client_keyshare: [u8; NPK] = ke1[ELEMENT_LEN + NN..]
            .try_into()
            .map_err(|_| bad_record())?;
        let mut ikm = Zeroizing::new([0u8; 3 * NPK]);
        ikm.get_mut()[..NPK].copy_from_slice(&oprf::diffie_hellman(
            &keyshare.to_bytes(),
            &client_keyshare,
        )?);
        ikm.get_mut()[NPK..2 * NPK].copy_from_slice(&oprf::diffie_hellman(
            &self.key.to_bytes(),
            &client_keyshare,
        )?);
        ikm.get_mut()[2 * NPK..].copy_from_slice(&oprf::diffie_hellman(
            &keyshare.to_bytes(),
            &client_public_key,
        )?);
        let preamble_hash = preamble_hash(context, c_id, ke1, s_id, &ke2[..at + NN + NPK])?;
        let keys = derive_keys(&ikm[..], &preamble_hash)?;
        let server_mac = mac(&keys.km2[..], &[&preamble_hash])?;
        ke2[at + NN + NPK..].copy_from_slice(&server_mac);
        let expected = mac(
            &keys.km3[..],
            &[&sha256_preamble_mac(context, c_id, ke1, s_id, &ke2)?],
        )?;
        Ok((
            ServerLogin {
                expected_client_mac: expected,
                session_key: keys.session_key,
            },
            ke2,
        ))
    }
}

fn bad_record() -> ic_core::Error {
    ic_core::err!(MalformedEncoding, "opaque message")
}

/// A random source for the OPRF's base mode, which draws nothing when it
/// evaluates; anything that asks is a bug, refused rather than answered.
struct NoRandom;

impl RandomSource for NoRandom {
    fn fill(&mut self, _: &mut [u8]) -> Result<()> {
        Err(ic_core::err!(
            Internal,
            "opaque: the base OPRF drew randomness"
        ))
    }
}

/// The preamble of section 6.4.2.1, hashed. `ke2_prefix` is the credential
/// response, the server nonce and the server key share.
fn preamble_hash(
    context: &[u8],
    client_identity: &[u8],
    ke1: &[u8; KE1_LEN],
    server_identity: &[u8],
    ke2_prefix: &[u8],
) -> Result<[u8; NH]> {
    ensure!(
        context.len() <= u16::MAX as usize,
        InvalidLength,
        "opaque context too long"
    );
    Ok(sha256(&[
        b"OPAQUEv1-",
        &(context.len() as u16).to_be_bytes(),
        context,
        &(client_identity.len() as u16).to_be_bytes(),
        client_identity,
        ke1,
        &(server_identity.len() as u16).to_be_bytes(),
        server_identity,
        ke2_prefix,
    ]))
}

/// `Hash(preamble || server_mac)`, which the client's MAC covers.
fn sha256_preamble_mac(
    context: &[u8],
    client_identity: &[u8],
    ke1: &[u8; KE1_LEN],
    server_identity: &[u8],
    ke2: &[u8; KE2_LEN],
) -> Result<[u8; NH]> {
    ensure!(
        context.len() <= u16::MAX as usize,
        InvalidLength,
        "opaque context too long"
    );
    Ok(sha256(&[
        b"OPAQUEv1-",
        &(context.len() as u16).to_be_bytes(),
        context,
        &(client_identity.len() as u16).to_be_bytes(),
        client_identity,
        ke1,
        &(server_identity.len() as u16).to_be_bytes(),
        server_identity,
        &ke2[..CREDENTIAL_RESPONSE_LEN + NN + NPK],
        &ke2[CREDENTIAL_RESPONSE_LEN + NN + NPK..],
    ]))
}

struct Keys {
    km2: Zeroizing<[u8; NH]>,
    km3: Zeroizing<[u8; NH]>,
    session_key: Zeroizing<[u8; NH]>,
}

/// `DeriveKeys(ikm, preamble)`, section 6.4.2.2.
fn derive_keys(ikm: &[u8], preamble_hash: &[u8; NH]) -> Result<Keys> {
    let mut prk = Zeroizing::new([0u8; NH]);
    Hkdf::<HmacSha256>::extract(&[], ikm, prk.get_mut())?;
    let mut handshake = Zeroizing::new([0u8; NH]);
    expand_label(
        &prk[..],
        b"HandshakeSecret",
        preamble_hash,
        handshake.get_mut(),
    )?;
    let mut session_key = Zeroizing::new([0u8; NH]);
    expand_label(
        &prk[..],
        b"SessionKey",
        preamble_hash,
        session_key.get_mut(),
    )?;
    let mut km2 = Zeroizing::new([0u8; NH]);
    expand_label(&handshake[..], b"ServerMAC", b"", km2.get_mut())?;
    let mut km3 = Zeroizing::new([0u8; NH]);
    expand_label(&handshake[..], b"ClientMAC", b"", km3.get_mut())?;
    Ok(Keys {
        km2,
        km3,
        session_key,
    })
}

/// The server's half of a login between KE2 and KE3.
pub struct ServerLogin {
    expected_client_mac: [u8; NH],
    session_key: Zeroizing<[u8; NH]>,
}

impl ServerLogin {
    /// `ServerFinish`: check the client's KE3 and return the session key.
    /// A wrong password, or anything changed in transit, is
    /// `AuthenticationFailed`.
    pub fn finish(self, ke3: &[u8; KE3_LEN]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        ic_core::module::operational()?;
        ensure!(
            ic_core::ct::verify(&self.expected_client_mac, ke3),
            AuthenticationFailed,
            "opaque client"
        );
        Ok(Zeroizing::new(*self.session_key))
    }
}

/// The client's state between starting and finishing registration.
pub struct RegistrationState(oprf::BlindState);

/// `CreateRegistrationRequest`.
pub fn registration_start<R: RandomSource + ?Sized>(
    password: &[u8],
    rng: &mut R,
) -> Result<(RegistrationState, [u8; REGISTRATION_REQUEST_LEN])> {
    ic_core::module::operational()?;
    let (state, blinded) = oprf::blind(Mode::Oprf, password, b"", None, rng)?;
    Ok((RegistrationState(state), blinded))
}

/// `FinalizeRegistrationRequest`: the record to send the server, and the
/// export key.
pub fn registration_finish<K: Ksf + ?Sized, R: RandomSource + ?Sized>(
    ksf: &K,
    state: &RegistrationState,
    password: &[u8],
    response: &[u8; REGISTRATION_RESPONSE_LEN],
    server_identity: Option<&[u8]>,
    client_identity: Option<&[u8]>,
    rng: &mut R,
) -> Result<([u8; RECORD_LEN], Zeroizing<[u8; KEY_LEN]>)> {
    ic_core::module::operational()?;
    let evaluated: [u8; ELEMENT_LEN] = response[..ELEMENT_LEN]
        .try_into()
        .map_err(|_| bad_record())?;
    let server_public_key: [u8; NPK] = response[ELEMENT_LEN..]
        .try_into()
        .map_err(|_| bad_record())?;
    oprf::validate_element(&server_public_key)?;
    let blinded = [0u8; ELEMENT_LEN];
    let mut output = Zeroizing::new(oprf::finalize(
        password, b"", &state.0, &blinded, &evaluated, None,
    )?);
    let rwd = randomized_password(ksf, &output)?;
    output.get_mut().zeroize();

    // Store.
    let nonce = random::<_, NN>(rng)?;
    let mut masking_key = Zeroizing::new([0u8; NH]);
    expand(&rwd[..], &[b"MaskingKey"], masking_key.get_mut())?;
    let keys = envelope_keys(&rwd, &nonce)?;
    let client_public_key = keys.client.public_key();
    let (s_id, c_id) = identities(
        &server_public_key,
        &client_public_key,
        server_identity,
        client_identity,
    )?;
    let tag = envelope_tag(&keys.auth_key, &nonce, &server_public_key, s_id, c_id)?;

    let mut record = [0u8; RECORD_LEN];
    record[..NPK].copy_from_slice(&client_public_key);
    record[NPK..NPK + NH].copy_from_slice(&masking_key[..]);
    record[NPK + NH..NPK + NH + NN].copy_from_slice(&nonce);
    record[NPK + NH + NN..].copy_from_slice(&tag);
    Ok((record, keys.export_key))
}

/// The client's state between KE1 and KE3.
pub struct ClientLogin {
    blind: oprf::BlindState,
    keyshare: ServerKey,
    ke1: [u8; KE1_LEN],
}

/// `GenerateKE1`: start a login.
pub fn login_start<R: RandomSource + ?Sized>(
    password: &[u8],
    rng: &mut R,
) -> Result<(ClientLogin, [u8; KE1_LEN])> {
    ic_core::module::operational()?;
    let (blind, blinded) = oprf::blind(Mode::Oprf, password, b"", None, rng)?;
    let nonce = random::<_, NN>(rng)?;
    let mut seed = Zeroizing::new(random::<_, NN>(rng)?);
    let keyshare = derive_dh_key_pair(&seed)?;
    seed.get_mut().zeroize();
    let mut ke1 = [0u8; KE1_LEN];
    ke1[..ELEMENT_LEN].copy_from_slice(&blinded);
    ke1[ELEMENT_LEN..ELEMENT_LEN + NN].copy_from_slice(&nonce);
    ke1[ELEMENT_LEN + NN..].copy_from_slice(&keyshare.public_key());
    Ok((
        ClientLogin {
            blind,
            keyshare,
            ke1,
        },
        ke1,
    ))
}

impl ClientLogin {
    /// `GenerateKE3`: recover the credentials, authenticate the server, and
    /// return KE3, the session key and the export key.
    ///
    /// A wrong password, a server that does not hold the record, or any
    /// change in transit is `AuthenticationFailed`.
    #[allow(clippy::type_complexity)]
    pub fn finish<K: Ksf + ?Sized>(
        self,
        ksf: &K,
        password: &[u8],
        ke2: &[u8; KE2_LEN],
        client_identity: Option<&[u8]>,
        server_identity: Option<&[u8]>,
        context: &[u8],
    ) -> Result<(
        [u8; KE3_LEN],
        Zeroizing<[u8; KEY_LEN]>,
        Zeroizing<[u8; KEY_LEN]>,
    )> {
        ic_core::module::operational()?;
        // RecoverCredentials.
        let evaluated: [u8; ELEMENT_LEN] =
            ke2[..ELEMENT_LEN].try_into().map_err(|_| bad_record())?;
        let blinded: [u8; ELEMENT_LEN] = self.ke1[..ELEMENT_LEN]
            .try_into()
            .map_err(|_| bad_record())?;
        let mut output = Zeroizing::new(oprf::finalize(
            password,
            b"",
            &self.blind,
            &blinded,
            &evaluated,
            None,
        )?);
        let rwd = randomized_password(ksf, &output)?;
        output.get_mut().zeroize();
        let mut masking_key = Zeroizing::new([0u8; NH]);
        expand(&rwd[..], &[b"MaskingKey"], masking_key.get_mut())?;
        let masking_nonce = &ke2[ELEMENT_LEN..ELEMENT_LEN + NN];
        let mut pad = [0u8; NPK + ENVELOPE_LEN];
        expand(
            &masking_key[..],
            &[masking_nonce, b"CredentialResponsePad"],
            &mut pad,
        )?;
        let mut unmasked = [0u8; NPK + ENVELOPE_LEN];
        for ((u, m), p) in unmasked
            .iter_mut()
            .zip(&ke2[ELEMENT_LEN + NN..CREDENTIAL_RESPONSE_LEN])
            .zip(pad.iter())
        {
            *u = m ^ p;
        }
        pad.zeroize();
        let server_public_key: [u8; NPK] = unmasked[..NPK].try_into().map_err(|_| bad_record())?;
        // A wrong password unmasks to garbage, which is refused below as an
        // authentication failure rather than here as a bad encoding.
        let keys = envelope_keys(&rwd, &unmasked[NPK..NPK + NN])?;
        let client_public_key = keys.client.public_key();
        let (s_id, c_id) = identities(
            &server_public_key,
            &client_public_key,
            server_identity,
            client_identity,
        )?;
        let tag = envelope_tag(
            &keys.auth_key,
            &unmasked[NPK..NPK + NN],
            &server_public_key,
            s_id,
            c_id,
        )?;
        ensure!(
            ic_core::ct::verify(&tag, &unmasked[NPK + NN..]),
            AuthenticationFailed,
            "opaque envelope"
        );
        oprf::validate_element(&server_public_key)?;

        // AuthClientFinalize.
        let at = CREDENTIAL_RESPONSE_LEN;
        let server_keyshare: [u8; NPK] = ke2[at + NN..at + NN + NPK]
            .try_into()
            .map_err(|_| bad_record())?;
        let mut ikm = Zeroizing::new([0u8; 3 * NPK]);
        ikm.get_mut()[..NPK].copy_from_slice(&oprf::diffie_hellman(
            &self.keyshare.to_bytes(),
            &server_keyshare,
        )?);
        ikm.get_mut()[NPK..2 * NPK].copy_from_slice(&oprf::diffie_hellman(
            &self.keyshare.to_bytes(),
            &server_public_key,
        )?);
        ikm.get_mut()[2 * NPK..].copy_from_slice(&oprf::diffie_hellman(
            &keys.client.to_bytes(),
            &server_keyshare,
        )?);
        let preamble = preamble_hash(context, c_id, &self.ke1, s_id, &ke2[..at + NN + NPK])?;
        let derived = derive_keys(&ikm[..], &preamble)?;
        let expected_server_mac = mac(&derived.km2[..], &[&preamble])?;
        ensure!(
            ic_core::ct::verify(&expected_server_mac, &ke2[at + NN + NPK..]),
            AuthenticationFailed,
            "opaque server"
        );
        let client_mac = mac(
            &derived.km3[..],
            &[&sha256_preamble_mac(context, c_id, &self.ke1, s_id, ke2)?],
        )?;
        Ok((client_mac, derived.session_key, keys.export_key))
    }
}

/// Hands out fixed values, one per draw; for the known-answer test.
struct Fixed<'a> {
    values: &'a [&'a [u8; 32]],
    at: usize,
}

impl RandomSource for Fixed<'_> {
    fn fill(&mut self, out: &mut [u8]) -> Result<()> {
        let next = self
            .values
            .get(self.at)
            .ok_or(ic_core::err!(SelfTestFailed, "opaque"))?;
        ensure!(out.len() == next.len(), SelfTestFailed, "opaque");
        out.copy_from_slice(&next[..]);
        self.at += 1;
        Ok(())
    }
}

/// The known-answer test: RFC 9807 appendix C.1.5's registration, from the
/// request through the record the client uploads, with the identity KSF
/// its vectors use.
pub fn self_test() -> Result<()> {
    let hex32 = |s: &[u8]| -> Result<[u8; 32]> {
        let mut out = [0u8; 32];
        ic_core::codec::hex_decode(s, &mut out)?;
        Ok(out)
    };
    let setup = ServerSetup::from_parts(
        &hex32(b"62f60b286d20ce4fd1d64809b0021dad6ed5d52a2c8cf27ae6582543a0a8dce2")?,
        &hex32(b"c36139381df63bfc91c850db0b9cfbec7a62e86d80040a41aa7725bf0e79d5e5")?,
    )?;
    let password = b"CorrectHorseBatteryStaple";
    let blind = hex32(b"411bf1a62d119afe30df682b91a0a33d777972d4f2daa4b34ca527d597078153")?;
    let nonce = hex32(b"a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f")?;
    let (state, request) = registration_start(
        password,
        &mut Fixed {
            values: &[&blind],
            at: 0,
        },
    )?;
    let response = setup.registration_response(&request, b"1234")?;
    let (record, _) = registration_finish(
        &IdentityKsf,
        &state,
        password,
        &response,
        None,
        None,
        &mut Fixed {
            values: &[&nonce],
            at: 0,
        },
    )?;
    let mut want = [0u8; RECORD_LEN];
    ic_core::codec::hex_decode(
        b"03b218507d978c3db570ca994aaf36695a731ddb2db272c817f79746fc37ae5214\
          7f0ed53532d3ae8e505ecc70d42d2b814b6b0e48156def71ea029148b2803aaf\
          a921f2a014513bd8a90e477a629794e89fec12d12206dde662ebdcf65670e51f\
          ad30bbcfc1f8eda0211553ab9aaf26345ad59a128e80188f035fe4924fad67b8",
        &mut want,
    )?;
    ensure!(
        ic_core::ct::verify(&want, &record),
        SelfTestFailed,
        "opaque"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_self_test_passes() {
        super::self_test().unwrap();
    }
}
