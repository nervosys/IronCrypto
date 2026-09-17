//! Software bill of materials, in CycloneDX form.
//!
//! An SBOM is the artifact a supply-chain audit asks for, and for this project
//! it is unusually short: every component is first-party. That is the whole
//! claim, and emitting it in a standard format is what makes the claim
//! checkable by a tool the auditor already runs rather than by reading a README
//! and taking its word.
//!
//! # Deterministic on purpose
//!
//! There is no timestamp and no random serial number. Both fields are optional
//! in CycloneDX, and both would make two runs over identical source produce
//! different documents — which defeats the one thing an SBOM is good for in a
//! supply-chain context, namely that anyone can regenerate it and compare.
//! A document you cannot reproduce is a document you have to trust.
//!
//! The consequence is that this SBOM describes *the source*, not a particular
//! build of it. It does not establish that a given binary came from this
//! source; that needs a reproducible build pipeline, which the ATT&CK entry
//! `T1195.001` records as an open gap rather than papering over.
//!
//! # Where the component list comes from
//!
//! A table in this file, checked against the workspace manifest by a test. The
//! alternative — parsing `Cargo.toml` at run time — would put a manifest parser
//! in the shipping binary to restate something the build already knows. The
//! test closes the gap that a table would otherwise open: add a crate without
//! listing it here and the build fails.

use ic_json::Json;

/// The workspace version, shared by every crate.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// SPDX identifier for the licence every crate is published under.
const LICENSE: &str = "AGPL-3.0-or-later";

/// The project's canonical location.
const REPOSITORY: &str = "https://github.com/nervosys/IronCrypto";

/// One component of the bill of materials.
struct Component {
    /// Crate name, as published.
    name: &'static str,
    /// What it contributes, for a reader who is not going to open the source.
    description: &'static str,
}

/// Every crate in the workspace.
///
/// Kept in the order the workspace manifest lists them, which runs roughly from
/// primitives upward, so the document reads as a dependency order even though
/// CycloneDX does not require one.
const COMPONENTS: &[Component] = &[
    Component {
        name: "ic-core",
        description: "Traits, error types, constant-time helpers, zeroization and entropy.",
    },
    Component {
        name: "ic-hash",
        description: "SHA-2, SHA-3, SHAKE, the SP 800-185 derived functions, and BLAKE2.",
    },
    Component {
        name: "ic-mac",
        description: "HMAC over SHA-2 and SHA-3, CMAC over AES, and KMAC.",
    },
    Component {
        name: "ic-kdf",
        description: "HKDF, KBKDF, PBKDF2 and Argon2.",
    },
    Component {
        name: "ic-cipher",
        description: "AES, ChaCha20, the AEAD modes, POLYVAL and key wrapping.",
    },
    Component {
        name: "ic-drbg",
        description: "CTR_DRBG and HMAC_DRBG, with the random source callers hold.",
    },
    Component {
        name: "ic-ec",
        description: "The NIST prime curves, X25519 and Ed25519.",
    },
    Component {
        name: "ic-rsa",
        description: "RSA keys, PKCS#1 v1.5 and PSS.",
    },
    Component {
        name: "ic-pkix",
        description: "A strict DER reader and writer, SubjectPublicKeyInfo, PKCS#8 and PEM.",
    },
    Component {
        name: "ic-mlkem",
        description: "ML-KEM-768. Experimental: no interoperability vector is wired in.",
    },
    Component {
        name: "ic-mldsa",
        description: "ML-DSA-65. Experimental: no interoperability vector is wired in.",
    },
    Component {
        name: "ic-json",
        description: "A small JSON reader and writer, so the tooling needs no dependency.",
    },
    Component {
        name: "ic-vectors",
        description: "Loading test vectors that are not in the repository.",
    },
    Component {
        name: "ic-fips",
        description: "Approved-mode policy, self-tests, error state and service indicators.",
    },
    Component {
        name: "ic-ontology",
        description: "The algorithm registry, the standards knowledgebase and the frameworks.",
    },
    Component {
        name: "iron-crypto",
        description: "The facade crate that re-exports everything above.",
    },
    Component {
        name: "ic-cli",
        description: "The icrypto command line tool and its MCP server.",
    },
];

/// A package URL for a crate, in the form tooling expects.
fn purl(name: &str) -> String {
    format!("pkg:cargo/{name}@{VERSION}")
}

/// Render the bill of materials as CycloneDX 1.5 JSON.
pub fn cyclonedx() -> Json {
    let components: Vec<Json> = COMPONENTS
        .iter()
        .map(|c| {
            Json::object([
                ("type", Json::str("library")),
                ("bom-ref", Json::str(purl(c.name))),
                ("name", Json::str(c.name)),
                ("version", Json::str(VERSION)),
                ("description", Json::str(c.description)),
                ("purl", Json::str(purl(c.name))),
                ("scope", Json::str("required")),
                (
                    "licenses",
                    Json::Array(vec![Json::object([(
                        "license",
                        Json::object([("id", Json::str(LICENSE))]),
                    )])]),
                ),
            ])
        })
        .collect();

    Json::object([
        ("bomFormat", Json::str("CycloneDX")),
        ("specVersion", Json::str("1.5")),
        ("version", Json::Number(1.0)),
        (
            "metadata",
            Json::object([
                (
                    "component",
                    Json::object([
                        ("type", Json::str("library")),
                        ("bom-ref", Json::str(purl("iron-crypto"))),
                        ("name", Json::str("iron-crypto")),
                        ("version", Json::str(VERSION)),
                        ("purl", Json::str(purl("iron-crypto"))),
                        (
                            "description",
                            Json::str(
                                "A FIPS-disciplined cryptography library in pure Rust with \
                                 zero third-party dependencies. Not FIPS-validated.",
                            ),
                        ),
                        (
                            "licenses",
                            Json::Array(vec![Json::object([(
                                "license",
                                Json::object([("id", Json::str(LICENSE))]),
                            )])]),
                        ),
                        (
                            "externalReferences",
                            Json::Array(vec![Json::object([
                                ("type", Json::str("vcs")),
                                ("url", Json::str(REPOSITORY)),
                            ])]),
                        ),
                    ]),
                ),
                (
                    "properties",
                    Json::Array(vec![
                        Json::object([
                            ("name", Json::str("ironcrypto:third-party-dependencies")),
                            ("value", Json::str("0")),
                        ]),
                        Json::object([
                            ("name", Json::str("ironcrypto:fips-validated")),
                            ("value", Json::str("false")),
                        ]),
                        Json::object([
                            ("name", Json::str("ironcrypto:deterministic")),
                            (
                                "value",
                                Json::str(
                                    "true; no timestamp or serial number, so the document \
                                     can be regenerated and compared",
                                ),
                            ),
                        ]),
                    ]),
                ),
            ]),
        ),
        ("components", Json::Array(components)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn workspace_root() -> PathBuf {
        let mut here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        for _ in 0..4 {
            if here.join("Cargo.toml").is_file() && here.join("crates").is_dir() {
                return here;
            }
            if !here.pop() {
                break;
            }
        }
        panic!("could not find the workspace root");
    }

    /// The crates listed in the workspace manifest.
    fn manifest_members() -> Vec<String> {
        let text = std::fs::read_to_string(workspace_root().join("Cargo.toml")).unwrap();
        let start = text.find("members = [").expect("a members list");
        let end = text[start..].find(']').expect("a closing bracket") + start;
        text[start..end]
            .lines()
            .filter_map(|l| {
                let l = l.trim().trim_end_matches(',').trim_matches('"');
                l.strip_prefix("crates/").map(str::to_string)
            })
            .collect()
    }

    /// A `key = "value"` from the workspace manifest's `[workspace.package]`.
    fn manifest_field(key: &str) -> String {
        let text = std::fs::read_to_string(workspace_root().join("Cargo.toml")).unwrap();
        let section = text
            .split_once("[workspace.package]")
            .expect("a [workspace.package] section")
            .1;
        // Stop at the next section, so a key of the same name elsewhere in the
        // manifest cannot be picked up instead.
        let section = section.split("\n[").next().unwrap();
        for line in section.lines() {
            if let Some((k, v)) = line.split_once('=') {
                if k.trim() == key {
                    return v.trim().trim_matches('"').to_string();
                }
            }
        }
        panic!("the manifest has no {key} in [workspace.package]");
    }

    /// The licence and repository the document asserts must be the ones the
    /// workspace actually sets.
    ///
    /// `VERSION` comes from `CARGO_PKG_VERSION`, so it cannot drift. `LICENSE`
    /// and `REPOSITORY` are strings in this file, and the test below them
    /// compares the rendered document against those same constants -- which
    /// holds whatever they happen to say.
    ///
    /// A licence in an SBOM is the field downstream consumers scan for.
    /// Relicensing the workspace without touching this file would leave every
    /// component in the document claiming terms the code is no longer under,
    /// and the document would still pass every other test here.
    #[test]
    fn the_declared_licence_is_the_workspace_licence() {
        assert_eq!(
            LICENSE,
            manifest_field("license"),
            "the SBOM claims a licence the workspace does not set"
        );
        assert_eq!(
            REPOSITORY,
            manifest_field("repository"),
            "the SBOM points somewhere the workspace does not"
        );

        // And the rendered document must carry them, not merely agree in
        // principle: every component states the licence, so an omission in one
        // is an unlicensed component to a consumer reading it.
        let bom = cyclonedx();
        let components = bom.get("components").unwrap().as_array().unwrap();
        let mut stated = 0;
        for c in components {
            let id = c
                .get("licenses")
                .and_then(|l| l.as_array())
                .and_then(|l| l.first())
                .and_then(|l| l.get("license"))
                .and_then(|l| l.get("id"))
                .and_then(Json::as_str)
                .unwrap_or_else(|| {
                    panic!(
                        "{} states no licence",
                        c.get("name")
                            .and_then(Json::as_str)
                            .unwrap_or("a component")
                    )
                });
            assert_eq!(id, LICENSE);
            stated += 1;
        }
        assert_eq!(stated, components.len(), "not every component was examined");
        assert!(stated > 10, "only {stated} components in the document");
    }

    /// The bill of materials must list exactly the workspace, no more and no
    /// less.
    ///
    /// This is the check that makes a hand-written table safe. Add a crate and
    /// forget to list it and the build fails, which is the only way a document
    /// like this stays true — an SBOM that quietly omits a component is worse
    /// than none, because its whole purpose is completeness.
    #[test]
    fn the_bill_of_materials_matches_the_workspace() {
        let mut expected = manifest_members();
        let mut listed: Vec<String> = COMPONENTS.iter().map(|c| c.name.to_string()).collect();
        assert!(
            expected.len() >= 15,
            "the manifest parse found only {} members, which suggests it broke rather than \
             that the workspace shrank",
            expected.len()
        );
        expected.sort();
        listed.sort();
        assert_eq!(
            listed, expected,
            "the SBOM component list and the workspace manifest disagree"
        );
    }

    /// Every component must describe itself and carry a licence.
    #[test]
    fn components_are_complete() {
        let bom = cyclonedx();
        let components = bom.get("components").unwrap().as_array().unwrap();
        assert_eq!(components.len(), COMPONENTS.len());
        for c in components {
            let name = c.get("name").unwrap().as_str().unwrap();
            assert!(!name.is_empty());
            assert_eq!(c.get("version").unwrap().as_str(), Some(VERSION));
            assert_eq!(
                c.get("purl").unwrap().as_str(),
                Some(format!("pkg:cargo/{name}@{VERSION}").as_str())
            );
            let desc = c.get("description").unwrap().as_str().unwrap();
            assert!(desc.len() > 20, "{name} has a thin description");
            let licenses = c.get("licenses").unwrap().as_array().unwrap();
            assert_eq!(
                licenses[0]
                    .get("license")
                    .unwrap()
                    .get("id")
                    .unwrap()
                    .as_str(),
                Some(LICENSE)
            );
        }
    }

    /// The document must state what it is not.
    ///
    /// An SBOM is read by people deciding whether they may deploy something.
    /// The two facts that decide it here are that there are no third-party
    /// components and that this is not FIPS-validated, so both travel in the
    /// document rather than only in a README nobody attaches to a ticket.
    #[test]
    fn the_document_carries_its_own_caveats() {
        let bom = cyclonedx();
        let props = bom
            .get("metadata")
            .unwrap()
            .get("properties")
            .unwrap()
            .as_array()
            .unwrap();
        let find = |name: &str| {
            props
                .iter()
                .find(|p| p.get("name").and_then(|v| v.as_str()) == Some(name))
                .and_then(|p| p.get("value"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
        };
        assert_eq!(find("ironcrypto:third-party-dependencies"), "0");
        assert_eq!(find("ironcrypto:fips-validated"), "false");
        assert!(find("ironcrypto:deterministic").starts_with("true"));

        let desc = bom
            .get("metadata")
            .unwrap()
            .get("component")
            .unwrap()
            .get("description")
            .unwrap()
            .as_str()
            .unwrap();
        assert!(
            desc.contains("Not FIPS-validated"),
            "the top-level description must say so: {desc}"
        );
    }

    /// Two runs must produce byte-identical output.
    ///
    /// The point of omitting the timestamp and serial number, asserted rather
    /// than left as an intention someone later "fixes" by adding them back.
    #[test]
    fn the_document_is_reproducible() {
        assert_eq!(cyclonedx().to_string(), cyclonedx().to_string());
        // Check for the *fields*, not the words. The caveat property mentions
        // both by name, and a test that could not tell a field from prose about
        // that field would have to be worked around rather than satisfied.
        let text = cyclonedx().to_string();
        assert!(
            !text.contains("\"timestamp\":"),
            "a timestamp field would break reproducibility"
        );
        assert!(
            !text.contains("\"serialNumber\":"),
            "a random serial number would break reproducibility"
        );
    }

    /// It must parse as JSON and be recognisable as CycloneDX.
    #[test]
    fn the_document_is_well_formed_cyclonedx() {
        let text = cyclonedx().to_string();
        let parsed = ic_json::parse(&text).expect("valid JSON");
        assert_eq!(parsed.get("bomFormat").unwrap().as_str(), Some("CycloneDX"));
        assert_eq!(parsed.get("specVersion").unwrap().as_str(), Some("1.5"));
        assert_eq!(parsed.get("version").unwrap().as_f64(), Some(1.0));
        assert!(parsed.get("components").unwrap().as_array().is_some());
    }
}
