//! OPAQUE against RFC 9807's P-256 test vectors.
//!
//! `testvectors/rfc9807-p256.json`, from `scripts/gen_opaque_vectors.py`:
//! appendix C.1.5 and C.1.6, a registration and a login each, the second
//! with client and server identities, and C.2.3, a login against a client
//! with no record answered from a fake one. Each vector's random draws --
//! blinds, nonces, key-share seeds -- are handed out by a scripted source in
//! the order the protocol makes them, so every message and every key is
//! compared byte for byte.

// Every algorithm here is one approved mode does not permit.
#![cfg(not(ic_approved_only))]

use ic_core::traits::RandomSource;
use ic_core::ErrorKind;
use ic_vectors::{hex, hex_field, VectorFile};
use ironcrypto::hpke::opaque::{
    self, IdentityKsf, ServerSetup, ENVELOPE_LEN, KE1_LEN, KE3_LEN, RECORD_LEN,
};

/// Hands out given values, one per draw, in order.
struct Script(Vec<Vec<u8>>);

impl RandomSource for Script {
    fn fill(&mut self, out: &mut [u8]) -> ic_core::Result<()> {
        assert!(
            !self.0.is_empty(),
            "the protocol drew more than the vector gives"
        );
        let next = self.0.remove(0);
        assert_eq!(next.len(), out.len());
        out.copy_from_slice(&next);
        Ok(())
    }
}

fn arr<const N: usize>(v: Vec<u8>) -> [u8; N] {
    v.try_into().unwrap()
}

#[test]
fn opaque_matches_rfc_9807() {
    let Some(file) = VectorFile::load_or_report("rfc9807-p256") else {
        return;
    };
    let mut checked = 0;
    for case in &file.cases {
        let name = &case["name"];
        let field = |k: &str| hex_field(case, k);
        let context = field("Context");
        let client_identity = case
            .get("client_identity")
            .map(|_| field("client_identity"));
        let server_identity = case
            .get("server_identity")
            .map(|_| field("server_identity"));
        let (c_id, s_id) = (client_identity.as_deref(), server_identity.as_deref());
        let credential_identifier = field("credential_identifier");
        let setup =
            ServerSetup::from_parts(&arr(field("oprf_seed")), &arr(field("server_private_key")))
                .unwrap();
        assert_eq!(
            hex(&setup.public_key()),
            case["server_public_key"],
            "{name}"
        );

        let record: [u8; RECORD_LEN] = if case["kind"] == "real" {
            let password = field("password");
            let mut rng = Script(vec![field("blind_registration")]);
            let (state, request) = opaque::registration_start(&password, &mut rng).unwrap();
            assert_eq!(hex(&request), case["registration_request"], "{name}");
            let response = setup
                .registration_response(&request, &credential_identifier)
                .unwrap();
            assert_eq!(hex(&response), case["registration_response"], "{name}");
            let mut rng = Script(vec![field("envelope_nonce")]);
            let (record, export_key) = opaque::registration_finish(
                &IdentityKsf,
                &state,
                &password,
                &response,
                s_id,
                c_id,
                &mut rng,
            )
            .unwrap();
            assert_eq!(hex(&record), case["registration_upload"], "{name}");
            assert_eq!(hex(&export_key[..]), case["export_key"], "{name}");
            record
        } else {
            // C.2.3: the fake record RFC 9807 section 6.3.2.2 describes.
            let mut r = [0u8; RECORD_LEN];
            r[..33].copy_from_slice(&field("client_public_key"));
            r[33..65].copy_from_slice(&field("masking_key"));
            assert_eq!(r[65..], [0u8; ENVELOPE_LEN]);
            r
        };

        let ke1: [u8; KE1_LEN] = if case["kind"] == "real" {
            let mut rng = Script(vec![
                field("blind_login"),
                field("client_nonce"),
                field("client_keyshare_seed"),
            ]);
            let (client, ke1) = opaque::login_start(&field("password"), &mut rng).unwrap();
            assert_eq!(hex(&ke1), case["KE1"], "{name}");
            let mut rng = Script(vec![
                field("masking_nonce"),
                field("server_nonce"),
                field("server_keyshare_seed"),
            ]);
            let (pending, ke2) = setup
                .login_respond(
                    &record,
                    &credential_identifier,
                    &ke1,
                    c_id,
                    s_id,
                    &context,
                    &mut rng,
                )
                .unwrap();
            assert_eq!(hex(&ke2), case["KE2"], "{name}");
            let (ke3, session_key, export_key) = client
                .finish(&IdentityKsf, &field("password"), &ke2, c_id, s_id, &context)
                .unwrap();
            assert_eq!(hex(&ke3), case["KE3"], "{name}");
            assert_eq!(hex(&session_key[..]), case["session_key"], "{name}");
            assert_eq!(hex(&export_key[..]), case["export_key"], "{name}");

            // A KE3 with one bit changed is refused.
            let mut bad = ke3;
            bad[KE3_LEN - 1] ^= 1;
            let err = pending.finish(&bad).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::AuthenticationFailed);
            ke1
        } else {
            arr(field("KE1"))
        };

        // Respond again, for the fake vector and to check the server's side
        // of the real ones on its own.
        let mut rng = Script(vec![
            field("masking_nonce"),
            field("server_nonce"),
            field("server_keyshare_seed"),
        ]);
        let (pending, ke2) = setup
            .login_respond(
                &record,
                &credential_identifier,
                &ke1,
                c_id,
                s_id,
                &context,
                &mut rng,
            )
            .unwrap();
        assert_eq!(hex(&ke2), case["KE2"], "{name}");
        if case["kind"] == "real" {
            let ke3: [u8; KE3_LEN] = arr(field("KE3"));
            let key = pending.finish(&ke3).unwrap();
            assert_eq!(hex(&key[..]), case["session_key"], "{name}");
        }
        checked += 1;
    }
    assert_eq!(checked, 3);
}

/// A wrong password, a different context, or a changed KE2 each end the
/// login on the client's side as an authentication failure.
#[test]
fn a_login_fails_closed() {
    let mut rng = ironcrypto::drbg::Rng::from_entropy(&[0x0au8; 32], b"opaque test").unwrap();
    let setup = ServerSetup::generate(&mut rng).unwrap();
    let (state, request) = opaque::registration_start(b"right", &mut rng).unwrap();
    let response = setup.registration_response(&request, b"id").unwrap();
    let (record, _) = opaque::registration_finish(
        &IdentityKsf,
        &state,
        b"right",
        &response,
        None,
        None,
        &mut rng,
    )
    .unwrap();

    let attempt = |password: &[u8], client_context: &[u8], flip: Option<usize>| {
        let mut rng = ironcrypto::drbg::Rng::from_entropy(&[0x0bu8; 32], b"login").unwrap();
        let (client, ke1) = opaque::login_start(password, &mut rng).unwrap();
        let (_, mut ke2) = setup
            .login_respond(&record, b"id", &ke1, None, None, b"ctx", &mut rng)
            .unwrap();
        if let Some(i) = flip {
            ke2[i] ^= 1;
        }
        client
            .finish(&IdentityKsf, password, &ke2, None, None, client_context)
            .map(|_| ())
    };
    attempt(b"right", b"ctx", None).unwrap();
    for (password, ctx, flip) in [
        (&b"wrong"[..], &b"ctx"[..], None),
        (b"right", b"other", None),
        (b"right", b"ctx", Some(40)),  // the masking nonce
        (b"right", b"ctx", Some(200)), // the server key share
        (b"right", b"ctx", Some(258)), // the server MAC
    ] {
        let err = attempt(password, ctx, flip).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                ErrorKind::AuthenticationFailed | ErrorKind::MalformedEncoding
            ),
            "{:?} {:?} {flip:?}: {err:?}",
            password,
            ctx
        );
    }
}
