//! The operations shared by the CLI and the MCP server.
//!
//! Both front ends call into this module, so `acrypto ontology show sha2-256`
//! and the MCP `ontology_show` tool return the same data from the same code.
//! That is deliberate: a human debugging an agent's behaviour should be able to
//! reproduce it from a shell.

use crate::json::Json;
use ac_core::traits::{Aead, Digest, Mac};
use ac_ontology::select::{recommend, Intent, NoRecommendation, Policy};
use ac_ontology::{Entry, ImplStatus};

/// Render an ontology entry as JSON.
pub fn entry_json(e: &Entry) -> Json {
    Json::object([
        ("id", Json::str(e.id)),
        ("name", Json::str(e.name)),
        ("summary", Json::str(e.summary)),
        ("class", Json::str(e.class.id())),
        ("family", Json::str(e.family)),
        (
            "purposes",
            Json::Array(e.purposes.iter().map(|p| Json::str(p.id())).collect()),
        ),
        (
            "aliases",
            Json::Array(e.aliases.iter().map(|a| Json::str(*a)).collect()),
        ),
        (
            "standards",
            Json::Array(e.standards.iter().map(|s| Json::str(*s)).collect()),
        ),
        (
            "strength",
            Json::object([
                ("classicalBits", Json::num(e.strength.classical)),
                ("quantumBits", Json::num(e.strength.quantum)),
            ]),
        ),
        ("fipsStatus", Json::str(e.fips.id())),
        ("implementationStatus", Json::str(e.status.id())),
        ("approvedModeUsable", Json::Bool(e.approved_mode_ok())),
        ("performance", Json::str(e.performance.id())),
        (
            "parameters",
            Json::Array(
                e.params
                    .iter()
                    .map(|p| {
                        Json::object([
                            ("name", Json::str(p.name)),
                            ("unit", Json::str(p.unit.id())),
                            ("min", Json::num(p.min as f64)),
                            ("max", Json::num(p.max as f64)),
                            ("recommended", Json::num(p.recommended as f64)),
                            ("note", Json::str(p.note)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "constraints",
            Json::Array(
                e.constraints
                    .iter()
                    .map(|c| {
                        Json::object([
                            ("id", Json::str(c.id)),
                            ("severity", Json::str(c.severity.id())),
                            ("requirement", Json::str(c.requirement)),
                            ("consequence", Json::str(c.consequence)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "relations",
            Json::Array(
                e.edges
                    .iter()
                    .map(|edge| {
                        Json::object([
                            ("relation", Json::str(edge.relation.id())),
                            ("target", Json::str(edge.target)),
                        ])
                    })
                    .collect(),
            ),
        ),
        ("rustPath", Json::str(e.rust_path)),
        ("example", Json::str(e.example)),
        ("notes", Json::str(e.notes)),
    ])
}

/// Build a query from optional string filters and run it.
pub fn list(
    class: Option<&str>,
    purpose: Option<&str>,
    fips_only: bool,
    available_only: bool,
) -> Result<Vec<&'static Entry>, String> {
    let mut q = ac_ontology::Query::new();
    if let Some(c) = class {
        let parsed = ac_ontology::Class::from_id(c)
            .ok_or_else(|| format!("unknown class '{c}'; try one of {}", class_list()))?;
        q = q.class(parsed);
    }
    if let Some(p) = purpose {
        let parsed = ac_ontology::Purpose::from_id(p)
            .ok_or_else(|| format!("unknown purpose '{p}'; try one of {}", purpose_list()))?;
        q = q.purpose(parsed);
    }
    if fips_only {
        q = q.fips_approved_only();
    }
    if available_only {
        q = q.available_only();
    }
    Ok(q.run().collect())
}

/// The class vocabulary, comma-separated.
pub fn class_list() -> String {
    ac_ontology::Class::ALL
        .iter()
        .map(|c| c.id())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The purpose vocabulary, comma-separated.
pub fn purpose_list() -> String {
    ac_ontology::Purpose::ALL
        .iter()
        .map(|p| p.id())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The intent vocabulary, comma-separated.
pub fn intent_list() -> String {
    Intent::ALL
        .iter()
        .map(|i| i.id())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Produce a recommendation as JSON, including the honest failure cases.
pub fn recommend_json(
    intent: &str,
    fips: bool,
    post_quantum: bool,
    aes_hardware: bool,
) -> Result<Json, String> {
    let parsed = Intent::from_id(intent)
        .ok_or_else(|| format!("unknown intent '{intent}'; try one of {}", intent_list()))?;

    // `--aes-hardware` forces the assumption on; otherwise it is detected, so
    // the recommendation reflects the machine the command is running on.
    let policy = Policy {
        require_fips: fips,
        min_classical_bits: 128,
        min_quantum_bits: if post_quantum { 128 } else { 0 },
        aes_hardware: aes_hardware || ac_ontology::runtime::backend().fast_bulk_symmetric(),
    };

    match recommend(parsed, policy) {
        Ok(r) => Ok(Json::object([
            ("intent", Json::str(r.intent.id())),
            ("status", Json::str("ok")),
            ("recommended", Json::str(r.primary.id)),
            ("rustPath", Json::str(r.primary.rust_path)),
            ("example", Json::str(r.primary.example)),
            ("rationale", Json::str(r.rationale)),
            (
                "alternative",
                match r.alternative {
                    Some(a) => Json::str(a.id),
                    None => Json::Null,
                },
            ),
            (
                "rejected",
                Json::Array(
                    r.rejected()
                        .map(|x| {
                            Json::object([("id", Json::str(x.id)), ("reason", Json::str(x.reason))])
                        })
                        .collect(),
                ),
            ),
            (
                "mustObserve",
                Json::Array(
                    r.must_observe
                        .iter()
                        .map(|c| {
                            Json::object([
                                ("id", Json::str(c.id)),
                                ("severity", Json::str(c.severity.id())),
                                ("requirement", Json::str(c.requirement)),
                                ("consequence", Json::str(c.consequence)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])),
        Err(NoRecommendation::KnownButUnavailable { id }) => {
            let e = ac_ontology::get(id);
            Ok(Json::object([
                ("intent", Json::str(parsed.id())),
                ("status", Json::str("unavailable")),
                ("recommended", Json::Null),
                ("correctAnswer", Json::str(id)),
                (
                    "explanation",
                    Json::str(format!(
                        "{id} satisfies this request, but it is not implemented in this build. Do \
                         not substitute a different algorithm to work around this."
                    )),
                ),
                ("notes", Json::str(e.map(|e| e.notes).unwrap_or_default())),
            ]))
        }
        Err(NoRecommendation::NothingSatisfiesPolicy) => Ok(Json::object([
            ("intent", Json::str(parsed.id())),
            ("status", Json::str("impossible")),
            ("recommended", Json::Null),
            (
                "explanation",
                Json::str(
                    "No algorithm in the ontology satisfies this combination of intent and policy.",
                ),
            ),
        ])),
    }
}

/// Run self-tests and render the report as JSON.
pub fn selftest_json(only: Option<&str>) -> Result<Json, String> {
    if let Some(id) = only {
        let ok = ac_fips::selftest::run_self_test(id)
            .map(|_| true)
            .map_err(|e| format!("{id}: {e}"))?;
        return Ok(Json::object([
            ("algorithm", Json::str(id)),
            ("passed", Json::Bool(ok)),
        ]));
    }

    let report = ac_fips::run_all_self_tests();
    Ok(Json::object([
        ("passed", Json::num(report.passed as f64)),
        ("failed", Json::num(report.failed as f64)),
        ("allPassed", Json::Bool(report.all_passed())),
        (
            "outcomes",
            Json::Array(
                report
                    .outcomes
                    .iter()
                    .map(|o| {
                        Json::object([
                            ("algorithm", Json::str(o.algorithm)),
                            ("passed", Json::Bool(o.passed)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "integrityCheck",
            Json::Bool(ac_fips::selftest::integrity_check().is_ok()),
        ),
    ]))
}

/// Describe this build: backend, capabilities, and validation status.
pub fn capabilities_json() -> Json {
    Json::object([
        ("version", Json::str(agentic_crypto::VERSION)),
        ("ontologyVersion", Json::str(ac_ontology::ONTOLOGY_VERSION)),
        ("backend", Json::str(ac_ontology::runtime::backend().id())),
        (
            "fastBulkSymmetric",
            Json::Bool(ac_ontology::runtime::backend().fast_bulk_symmetric()),
        ),
        ("moduleState", Json::str(ac_fips::state().id())),
        (
            "validationStatement",
            Json::str(ac_fips::VALIDATION_STATEMENT),
        ),
        (
            "capabilities",
            Json::Array(
                ac_ontology::runtime::capabilities()
                    .map(|c| {
                        Json::object([
                            ("id", Json::str(c.id)),
                            ("present", Json::Bool(c.present)),
                            ("note", Json::str(c.note)),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "algorithmCounts",
            Json::object([
                ("total", Json::num(ac_ontology::all().len() as f64)),
                (
                    "available",
                    Json::num(
                        ac_ontology::all()
                            .iter()
                            .filter(|e| e.status == ImplStatus::Available)
                            .count() as f64,
                    ),
                ),
                (
                    "planned",
                    Json::num(
                        ac_ontology::all()
                            .iter()
                            .filter(|e| e.status == ImplStatus::Planned)
                            .count() as f64,
                    ),
                ),
            ]),
        ),
    ])
}

/// The error catalog as JSON.
pub fn errors_json() -> Json {
    Json::Array(
        ac_ontology::errors::catalog()
            .map(|d| {
                Json::object([
                    ("id", Json::str(d.id)),
                    ("meaning", Json::str(d.meaning)),
                    ("recovery", Json::str(d.recovery)),
                    ("retryable", Json::Bool(d.retryable)),
                    ("callerCorrectable", Json::Bool(d.caller_correctable)),
                ])
            })
            .collect(),
    )
}

/// Hash `data` with the named digest, returning lowercase hex.
pub fn digest_hex(algorithm: &str, data: &[u8]) -> Result<String, String> {
    use ac_hash::*;
    let hex = |b: &[u8]| ac_core::codec::hex(b);
    Ok(match algorithm {
        "sha2-224" | "sha224" => hex(Sha224::digest(data).as_ref()),
        "sha2-256" | "sha256" => hex(Sha256::digest(data).as_ref()),
        "sha2-384" | "sha384" => hex(Sha384::digest(data).as_ref()),
        "sha2-512" | "sha512" => hex(Sha512::digest(data).as_ref()),
        "sha2-512-224" => hex(Sha512_224::digest(data).as_ref()),
        "sha2-512-256" => hex(Sha512_256::digest(data).as_ref()),
        "sha3-224" => hex(Sha3_224::digest(data).as_ref()),
        "sha3-256" => hex(Sha3_256::digest(data).as_ref()),
        "sha3-384" => hex(Sha3_384::digest(data).as_ref()),
        "sha3-512" => hex(Sha3_512::digest(data).as_ref()),
        other => {
            return Err(match ac_ontology::get(other) {
                Some(e) if e.class != ac_ontology::Class::Hash => {
                    format!("'{other}' is a {}, not a hash", e.class.id())
                }
                Some(e) => format!("'{}' is known but not available here", e.id),
                None => format!("unknown digest '{other}'; try sha2-256 or sha3-256"),
            })
        }
    })
}

/// Compute an HMAC tag, returning lowercase hex.
pub fn hmac_hex(algorithm: &str, key: &[u8], data: &[u8]) -> Result<String, String> {
    use ac_mac::*;
    Ok(match algorithm {
        "hmac-sha2-256" | "hmac-sha256" => ac_core::codec::hex(
            HmacSha256::mac(key, data)
                .map_err(|e| e.to_string())?
                .as_ref(),
        ),
        "hmac-sha2-384" | "hmac-sha384" => ac_core::codec::hex(
            HmacSha384::mac(key, data)
                .map_err(|e| e.to_string())?
                .as_ref(),
        ),
        "hmac-sha2-512" | "hmac-sha512" => ac_core::codec::hex(
            HmacSha512::mac(key, data)
                .map_err(|e| e.to_string())?
                .as_ref(),
        ),
        "hmac-sha3-256" => ac_core::codec::hex(
            HmacSha3_256::mac(key, data)
                .map_err(|e| e.to_string())?
                .as_ref(),
        ),
        "hmac-sha3-512" => ac_core::codec::hex(
            HmacSha3_512::mac(key, data)
                .map_err(|e| e.to_string())?
                .as_ref(),
        ),
        other => return Err(format!("unknown MAC '{other}'; try hmac-sha2-256")),
    })
}

/// Encrypt with an AEAD, returning `(ciphertext_hex, tag_hex)`.
pub fn seal_hex(
    algorithm: &str,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(String, String), String> {
    let mut buf = plaintext.to_vec();
    let mut tag = [0u8; 16];
    match algorithm {
        "aes-128-gcm" => ac_cipher::Aes128Gcm::new(key)
            .and_then(|c| c.seal_detached(nonce, aad, &mut buf, &mut tag)),
        "aes-192-gcm" => ac_cipher::Aes192Gcm::new(key)
            .and_then(|c| c.seal_detached(nonce, aad, &mut buf, &mut tag)),
        "aes-256-gcm" => ac_cipher::Aes256Gcm::new(key)
            .and_then(|c| c.seal_detached(nonce, aad, &mut buf, &mut tag)),
        "chacha20-poly1305" => ac_cipher::ChaCha20Poly1305::new(key)
            .and_then(|c| c.seal_detached(nonce, aad, &mut buf, &mut tag)),
        other => return Err(format!("unknown AEAD '{other}'; try aes-256-gcm")),
    }
    .map_err(|e| e.to_string())?;
    Ok((ac_core::codec::hex(&buf), ac_core::codec::hex(&tag)))
}

/// Generate `n` random bytes from the OS-seeded DRBG, as hex.
use std::collections::BTreeMap;

/// Describe a key given as DER or PEM, without doing anything with it.
///
/// This is the first question anyone has about a key file, human or agent:
/// what is it? Answering it needs no private material and no cryptography, so
/// it is safe to run on anything.
pub fn key_json(input: &[u8]) -> Result<Json, String> {
    let (der, container, label) = unwrap_pem(input)?;

    // Try the public form first, then the private one. A file is one or the
    // other, and the two structures are distinguishable: PrivateKeyInfo starts
    // with a version INTEGER where SubjectPublicKeyInfo starts with a SEQUENCE.
    if let Ok(key) = ac_pkix::PublicKeyInfo::from_der(&der) {
        return Ok(public_key_json(&key, container, label.as_deref()));
    }
    match ac_pkix::PrivateKeyInfo::from_der(&der) {
        Ok(key) => Ok(private_key_json(&key, container, label.as_deref())),
        Err(e) => Err(format!("not a recognizable key: {}", e.kind().id())),
    }
}

/// Strip a PEM wrapper if there is one, returning the DER plus what was around
/// it.
fn unwrap_pem(input: &[u8]) -> Result<(Vec<u8>, &'static str, Option<String>), String> {
    let text = core::str::from_utf8(input).unwrap_or("");
    let Some(begin) = text.find("-----BEGIN ") else {
        return Ok((input.to_vec(), "der", None));
    };
    let rest = &text[begin + 11..];
    let end = rest.find("-----").ok_or("malformed pem header")?;
    let label = rest[..end].to_string();

    let mut out = vec![0u8; input.len()];
    let n = ac_pkix::pem::decode(&label, input, &mut out)
        .map_err(|e| format!("pem: {}", e.kind().id()))?;
    out.truncate(n);
    Ok((out, "pem", Some(label)))
}

fn key_common(
    algorithm: ac_pkix::KeyAlgorithm,
    container: &str,
    label: Option<&str>,
) -> BTreeMap<String, Json> {
    let mut fields = BTreeMap::new();
    fields.insert("algorithm".to_string(), Json::str(algorithm.id()));
    fields.insert("container".to_string(), Json::str(container));
    if let Some(label) = label {
        fields.insert("pem_label".to_string(), Json::str(label));
    }
    fields
}

fn public_key_json(key: &ac_pkix::PublicKeyInfo<'_>, container: &str, label: Option<&str>) -> Json {
    let mut fields = key_common(key.algorithm(), container, label);
    fields.insert("kind".to_string(), Json::str("public"));
    match key {
        ac_pkix::PublicKeyInfo::Rsa { modulus, exponent } => {
            fields.insert("bits".to_string(), Json::num(modulus_bits(modulus) as f64));
            fields.insert("public_exponent".to_string(), Json::num(*exponent as f64));
        }
        ac_pkix::PublicKeyInfo::Ec { point, .. } => {
            fields.insert("point_bytes".to_string(), Json::num(point.len() as f64));
        }
        ac_pkix::PublicKeyInfo::Unsupported { oid } => {
            fields.insert("oid".to_string(), Json::str(dotted_oid(oid)));
        }
        _ => {}
    }
    if let Some(entry) = ontology_entry(key.algorithm()) {
        fields.insert("ontology_id".to_string(), Json::str(entry));
    }
    Json::Object(fields)
}

fn private_key_json(
    key: &ac_pkix::PrivateKeyInfo<'_>,
    container: &str,
    label: Option<&str>,
) -> Json {
    let mut fields = key_common(key.algorithm(), container, label);
    fields.insert("kind".to_string(), Json::str("private"));
    match key {
        ac_pkix::PrivateKeyInfo::Rsa {
            modulus,
            public_exponent,
            ..
        } => {
            fields.insert("bits".to_string(), Json::num(modulus_bits(modulus) as f64));
            fields.insert(
                "public_exponent".to_string(),
                Json::num(*public_exponent as f64),
            );
        }
        ac_pkix::PrivateKeyInfo::Ec { public_key, .. } => {
            fields.insert(
                "has_public_key".to_string(),
                Json::Bool(public_key.is_some()),
            );
        }
        ac_pkix::PrivateKeyInfo::Unsupported { oid } => {
            fields.insert("oid".to_string(), Json::str(dotted_oid(oid)));
        }
        _ => {}
    }
    if let Some(entry) = ontology_entry(key.algorithm()) {
        fields.insert("ontology_id".to_string(), Json::str(entry));
    }
    Json::Object(fields)
}

/// Bit length of a minimal big-endian integer.
fn modulus_bits(modulus: &[u8]) -> usize {
    match modulus.iter().position(|b| *b != 0) {
        Some(first) => (modulus.len() - first) * 8 - modulus[first].leading_zeros() as usize,
        None => 0,
    }
}

/// Render OID content bytes as a dotted string, so an unrecognized algorithm
/// can be looked up rather than merely reported as unknown.
fn dotted_oid(oid: &[u8]) -> String {
    let mut arcs: Vec<u64> = Vec::new();
    let mut value = 0u64;
    for (i, byte) in oid.iter().enumerate() {
        value = (value << 7) | (*byte & 0x7f) as u64;
        if byte & 0x80 == 0 {
            if i == 0 || arcs.is_empty() {
                // The first byte encodes two arcs: 40 * first + second.
                let first = core::cmp::min(value / 40, 2);
                arcs.push(first);
                arcs.push(value - first * 40);
            } else {
                arcs.push(value);
            }
            value = 0;
        }
    }
    arcs.iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// The ontology entry a key algorithm points at, where there is exactly one.
///
/// RSA deliberately has none: a key does not fix the padding, so `rsa-pss-*`
/// and `rsa-pkcs1-*` are both reachable from the same key and the caller has to
/// choose.
fn ontology_entry(algorithm: ac_pkix::KeyAlgorithm) -> Option<&'static str> {
    match algorithm {
        ac_pkix::KeyAlgorithm::EcP256 => Some("ecdsa-p256-sha256"),
        ac_pkix::KeyAlgorithm::EcP384 => Some("ecdsa-p384-sha384"),
        ac_pkix::KeyAlgorithm::Ed25519 => Some("ed25519"),
        ac_pkix::KeyAlgorithm::X25519 => Some("x25519"),
        ac_pkix::KeyAlgorithm::Rsa | ac_pkix::KeyAlgorithm::Unknown => None,
    }
}

pub fn random_hex(n: usize) -> Result<String, String> {
    if n == 0 || n > 1024 {
        return Err("request between 1 and 1024 bytes".to_string());
    }
    let mut rng = ac_drbg::Rng::from_os().map_err(|e| e.to_string())?;
    let mut out = vec![0u8; n];
    rng.fill(&mut out).map_err(|e| e.to_string())?;
    Ok(ac_core::codec::hex(&out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_json_round_trips_through_the_parser() {
        for e in ac_ontology::all() {
            let text = entry_json(e).to_string();
            let parsed = crate::json::parse(&text)
                .unwrap_or_else(|err| panic!("{} produced invalid JSON: {err}", e.id));
            assert_eq!(parsed.get("id").unwrap().as_str(), Some(e.id));
        }
    }

    #[test]
    fn list_filters_and_rejects_unknown_vocabulary() {
        let aeads = list(Some("aead"), None, false, true).unwrap();
        assert!(aeads.iter().any(|e| e.id == "aes-256-gcm"));
        assert!(list(Some("not-a-class"), None, false, false).is_err());
        assert!(list(None, Some("not-a-purpose"), false, false).is_err());

        let fips_aeads = list(Some("aead"), None, true, true).unwrap();
        assert!(!fips_aeads.iter().any(|e| e.id == "chacha20-poly1305"));
    }

    #[test]
    fn recommend_json_reports_availability_honestly() {
        let ok = recommend_json("encrypt-message", true, false, false).unwrap();
        assert_eq!(ok.get("status").unwrap().as_str(), Some("ok"));
        assert_eq!(ok.get("recommended").unwrap().as_str(), Some("aes-256-gcm"));

        // Under a FIPS policy the approved scheme is chosen, never the
        // available-but-unapproved Ed25519.
        let signing = recommend_json("sign-data", true, false, false).unwrap();
        assert_eq!(signing.get("status").unwrap().as_str(), Some("ok"));
        assert_eq!(
            signing.get("recommended").unwrap().as_str(),
            Some("ecdsa-p256-sha256")
        );

        // Post-quantum key agreement has no implementation here, so the
        // selector declines rather than offering X25519.
        let unavailable = recommend_json("agree-key", false, true, false).unwrap();
        assert_eq!(
            unavailable.get("status").unwrap().as_str(),
            Some("unavailable")
        );
        assert_eq!(
            unavailable.get("correctAnswer").unwrap().as_str(),
            Some("ml-kem-768")
        );
        assert_eq!(unavailable.get("recommended"), Some(&Json::Null));

        assert!(recommend_json("do-magic", false, false, false).is_err());
    }

    #[test]
    fn digest_matches_the_library() {
        assert_eq!(
            digest_hex("sha2-256", b"abc").unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            digest_hex("sha256", b"abc").unwrap(),
            digest_hex("sha2-256", b"abc").unwrap()
        );
    }

    /// Asking for a hash by the name of a cipher should explain the category
    /// error rather than just saying "unknown".
    #[test]
    fn digest_rejects_non_hashes_with_a_useful_message() {
        let err = digest_hex("aes-256-gcm", b"abc").unwrap_err();
        assert!(err.contains("aead"), "got: {err}");
        let err = digest_hex("sha-1", b"abc").unwrap_err();
        assert!(err.contains("not available"), "got: {err}");
    }

    #[test]
    fn hmac_matches_the_library() {
        assert_eq!(
            hmac_hex("hmac-sha2-256", &[0x0b; 20], b"Hi There").unwrap(),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert!(hmac_hex("hmac-md5", b"k", b"m").is_err());
    }

    #[test]
    fn seal_produces_a_ciphertext_and_tag() {
        let (ct, tag) = seal_hex("aes-256-gcm", &[0u8; 32], &[0u8; 12], b"", b"data").unwrap();
        assert_eq!(ct.len(), 8, "4 bytes of ciphertext in hex");
        assert_eq!(tag.len(), 32);
        assert!(seal_hex("aes-256-gcm", &[0u8; 16], &[0u8; 12], b"", b"x").is_err());
    }

    #[test]
    fn selftest_report_is_complete() {
        let report = selftest_json(None).unwrap();
        assert_eq!(report.get("failed").unwrap().as_i64(), Some(0));
        assert_eq!(report.get("allPassed").unwrap().as_bool(), Some(true));
        assert_eq!(report.get("integrityCheck").unwrap().as_bool(), Some(true));

        let one = selftest_json(Some("sha2-256")).unwrap();
        assert_eq!(one.get("passed").unwrap().as_bool(), Some(true));
        assert!(selftest_json(Some("nope")).is_err());
    }

    #[test]
    fn capabilities_do_not_overclaim() {
        let caps = capabilities_json();
        let text = caps.to_string();
        assert!(text.contains("NOT been submitted"));
        let list = caps.get("capabilities").unwrap();
        match list {
            Json::Array(items) => {
                let fips = items
                    .iter()
                    .find(|c| c.get("id").unwrap().as_str() == Some("fips-validated"))
                    .unwrap();
                assert_eq!(fips.get("present").unwrap().as_bool(), Some(false));
            }
            _ => panic!("expected an array"),
        }
    }

    #[test]
    fn random_respects_its_bounds() {
        assert_eq!(random_hex(16).unwrap().len(), 32);
        assert!(random_hex(0).is_err());
        assert!(random_hex(4096).is_err());
        assert_ne!(random_hex(32).unwrap(), random_hex(32).unwrap());
    }

    #[test]
    fn error_catalog_is_exported() {
        match errors_json() {
            Json::Array(items) => {
                assert!(!items.is_empty());
                assert!(items
                    .iter()
                    .any(|d| d.get("id").unwrap().as_str() == Some("authentication-failed")));
            }
            _ => panic!("expected an array"),
        }
    }
}

#[cfg(test)]
mod key_tests {
    use super::*;

    /// An Ed25519 public key in SPKI form. The base64 prefix `MCowBQYDK2Vw` is
    /// what every Ed25519 public key starts with, which makes this vector
    /// checkable against any other implementation's output.
    const ED25519_PUB: &str = "-----BEGIN PUBLIC KEY-----
        MCowBQYDK2VwAyEAyFOtDwzSthmuqSzuxP1Wok1kmdWEznklfkXP2BObYKc=
        -----END PUBLIC KEY-----
";

    fn field(json: &Json, key: &str) -> String {
        json.get(key)
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string()
    }

    #[test]
    fn a_pem_public_key_is_identified() {
        let json = key_json(ED25519_PUB.as_bytes()).unwrap();
        assert_eq!(field(&json, "algorithm"), "ed25519");
        assert_eq!(field(&json, "kind"), "public");
        assert_eq!(field(&json, "container"), "pem");
        assert_eq!(field(&json, "pem_label"), "PUBLIC KEY");
        assert_eq!(field(&json, "ontology_id"), "ed25519");
    }

    /// The same key without its PEM wrapper must identify the same way.
    #[test]
    fn a_bare_der_key_is_identified() {
        let mut der = vec![0u8; 256];
        let n = ac_pkix::pem::decode("PUBLIC KEY", ED25519_PUB.as_bytes(), &mut der).unwrap();
        let json = key_json(&der[..n]).unwrap();
        assert_eq!(field(&json, "algorithm"), "ed25519");
        assert_eq!(field(&json, "container"), "der");
        assert!(json.get("pem_label").is_none());
    }

    #[test]
    fn a_private_key_is_reported_as_private() {
        let seed = [0x42u8; 32];
        let mut der = [0u8; 128];
        let n = ac_pkix::PrivateKeyInfo::Ed25519(&seed)
            .to_der(&mut der)
            .unwrap();
        let json = key_json(&der[..n]).unwrap();
        assert_eq!(field(&json, "kind"), "private");
        assert_eq!(field(&json, "algorithm"), "ed25519");
    }

    /// RSA reports its size, and deliberately reports no single ontology entry:
    /// the key does not choose between PSS and PKCS#1 v1.5.
    #[test]
    fn an_rsa_key_reports_its_size_but_not_a_padding() {
        let mut modulus = [0xa7u8; 256];
        modulus[0] = 0xd1;
        let mut der = [0u8; 512];
        let n = ac_pkix::PublicKeyInfo::Rsa {
            modulus: &modulus,
            exponent: 65537,
        }
        .to_der(&mut der)
        .unwrap();

        let json = key_json(&der[..n]).unwrap();
        assert_eq!(field(&json, "algorithm"), "rsa");
        assert_eq!(json.get("bits").unwrap().as_i64(), Some(2048));
        assert_eq!(json.get("public_exponent").unwrap().as_i64(), Some(65537));
        assert!(
            json.get("ontology_id").is_none(),
            "an rsa key does not name a padding"
        );
    }

    #[test]
    fn modulus_bits_counts_from_the_top_set_bit() {
        assert_eq!(modulus_bits(&[0x80]), 8);
        assert_eq!(modulus_bits(&[0x01]), 1);
        assert_eq!(modulus_bits(&[0x00, 0x01]), 1);
        assert_eq!(modulus_bits(&[0xff, 0xff]), 16);
        assert_eq!(modulus_bits(&[]), 0);
        assert_eq!(modulus_bits(&[0x00, 0x00]), 0);
    }

    /// The dotted form is what makes an unrecognized algorithm actionable: the
    /// caller can look the number up. Checked against arcs whose encoding is
    /// documented in X.690 and RFC 5480.
    #[test]
    fn unknown_algorithms_report_a_dotted_oid() {
        // DSA, 1.2.840.10040.4.1.
        let dsa: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01];
        assert_eq!(dotted_oid(dsa), "1.2.840.10040.4.1");
        assert_eq!(dotted_oid(&[0x2b, 0x65, 0x70]), "1.3.101.112");
        assert_eq!(dotted_oid(&[0x88, 0x37, 0x03]), "2.999.3");

        let spki: &[u8] = &[
            0x30, 0x10, 0x30, 0x09, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01, 0x03,
            0x03, 0x00, 0x01, 0x02,
        ];
        let json = key_json(spki).unwrap();
        assert_eq!(field(&json, "algorithm"), "unknown");
        assert_eq!(field(&json, "oid"), "1.2.840.10040.4.1");
    }

    #[test]
    fn rubbish_is_an_error_not_a_guess() {
        assert!(key_json(b"not a key at all").is_err());
        assert!(key_json(&[]).is_err());
        assert!(key_json(
            b"-----BEGIN PUBLIC KEY-----
zzzz
-----END PUBLIC KEY-----
"
        )
        .is_err());
    }
}
