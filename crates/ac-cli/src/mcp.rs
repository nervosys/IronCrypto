//! A Model Context Protocol server over stdio.
//!
//! This is the door an agent walks through. It speaks newline-delimited
//! JSON-RPC 2.0 on stdin/stdout and exposes the ontology, the selector, the
//! self-tests, and a few primitive operations as MCP tools.
//!
//! Run it with `acrypto mcp`, or wire it into a client config:
//!
//! ```jsonc
//! {
//!   "mcpServers": {
//!     "agentic-crypto": { "command": "acrypto", "args": ["mcp"] }
//!   }
//! }
//! ```
//!
//! Every tool schema is generated from the same vocabulary the library uses, so
//! the enum of valid `class` values an agent sees is the enum the query engine
//! actually accepts.

use crate::ops;
use ac_json::{parse, Json};
use std::io::{BufRead, Write};

/// The MCP protocol revision this server implements.
const PROTOCOL_VERSION: &str = "2024-11-05";

/// One exposed tool.
struct Tool {
    name: &'static str,
    description: &'static str,
    schema: fn() -> Json,
    call: fn(&Json) -> Result<Json, String>,
}

fn string_prop(desc: &str) -> Json {
    Json::object([
        ("type", Json::str("string")),
        ("description", Json::str(desc)),
    ])
}

fn bool_prop(desc: &str) -> Json {
    Json::object([
        ("type", Json::str("boolean")),
        ("description", Json::str(desc)),
    ])
}

fn enum_prop(desc: &str, values: &str) -> Json {
    Json::object([
        ("type", Json::str("string")),
        ("description", Json::str(desc)),
        (
            "enum",
            Json::Array(values.split(", ").map(Json::str).collect()),
        ),
    ])
}

fn schema(props: Vec<(&str, Json)>, required: &[&str]) -> Json {
    let mut map = std::collections::BTreeMap::new();
    for (k, v) in props {
        map.insert(k.to_string(), v);
    }
    Json::object([
        ("type", Json::str("object")),
        ("properties", Json::Object(map)),
        (
            "required",
            Json::Array(required.iter().map(|r| Json::str(*r)).collect()),
        ),
    ])
}

fn arg<'a>(args: &'a Json, name: &str) -> Option<&'a str> {
    args.get(name).and_then(|v| v.as_str())
}

fn flag(args: &Json, name: &str) -> bool {
    args.get(name).and_then(|v| v.as_bool()).unwrap_or(false)
}

fn required<'a>(args: &'a Json, name: &str) -> Result<&'a str, String> {
    arg(args, name).ok_or_else(|| format!("missing required argument '{name}'"))
}

fn hex_arg(args: &Json, name: &str) -> Result<Vec<u8>, String> {
    let text = required(args, name)?;
    ac_core::codec::unhex(text).map_err(|e| format!("'{name}' must be hex: {e}"))
}

/// The tools this server exposes.
fn tools() -> Vec<Tool> {
    vec![
        Tool {
            name: "crypto_recommend",
            description:
                "Choose a cryptographic algorithm for a task. Returns the recommendation, the \
                 reasoning, rejected alternatives with reasons, the exact Rust path to call, and \
                 the constraints that must be honoured. If the correct algorithm is not \
                 implemented here, says so instead of substituting a different one.",
            schema: || {
                schema(
                    vec![
                        ("intent", enum_prop("What you are trying to do.", &ops::intent_list())),
                        ("fips", bool_prop("Require FIPS-approved algorithms only.")),
                        ("post_quantum", bool_prop("Require resistance to a quantum adversary.")),
                        ("aes_hardware", bool_prop("The target has AES hardware acceleration.")),
                    ],
                    &["intent"],
                )
            },
            call: |args| {
                ops::recommend_json(
                    required(args, "intent")?,
                    flag(args, "fips"),
                    flag(args, "post_quantum"),
                    flag(args, "aes_hardware"),
                )
            },
        },
        Tool {
            name: "key_inspect",
            description:
                "Identify a cryptographic key. Give it the contents of a PEM or DER key file and \
                 it reports the algorithm, whether the key is public or private, the size, and \
                 the ontology entry to look up next. It parses structure only — no private \
                 material is used and nothing is signed or decrypted — so it is safe to run on \
                 an unknown file.",
            schema: || {
                schema(
                    vec![(
                        "key",
                        string_prop(
                            "The key file's contents. PEM text, or DER as a hex string.",
                        ),
                    )],
                    &["key"],
                )
            },
            call: |args| {
                let text = required(args, "key")?;
                // A PEM document is text; a DER file has to arrive as hex,
                // since JSON has no byte string.
                let bytes = if text.contains("-----BEGIN ") {
                    text.as_bytes().to_vec()
                } else {
                    let trimmed: String =
                        text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
                    let mut out = vec![0u8; trimmed.len() / 2];
                    ac_core::codec::hex_decode(trimmed.as_bytes(), &mut out)
                        .map_err(|_| "key must be PEM text or a hex-encoded DER file".to_string())?;
                    out
                };
                ops::key_json(&bytes)
            },
        },
        Tool {
            name: "ontology_list",
            description:
                "List algorithms, optionally filtered by class, purpose, FIPS approval, and \
                 whether they are implemented in this build.",
            schema: || {
                schema(
                    vec![
                        ("class", enum_prop("Kind of algorithm.", &ops::class_list())),
                        ("purpose", enum_prop("Security goal it must serve.", &ops::purpose_list())),
                        ("fips_only", bool_prop("Only algorithms usable in FIPS approved mode.")),
                        ("available_only", bool_prop("Only algorithms implemented in this build.")),
                    ],
                    &[],
                )
            },
            call: |args| {
                let entries = ops::list(
                    arg(args, "class"),
                    arg(args, "purpose"),
                    flag(args, "fips_only"),
                    flag(args, "available_only"),
                )?;
                Ok(Json::object([
                    ("count", Json::num(entries.len() as f64)),
                    (
                        "algorithms",
                        Json::Array(
                            entries
                                .iter()
                                .map(|e| {
                                    Json::object([
                                        ("id", Json::str(e.id)),
                                        ("name", Json::str(e.name)),
                                        ("class", Json::str(e.class.id())),
                                        ("summary", Json::str(e.summary)),
                                        ("fipsStatus", Json::str(e.fips.id())),
                                        ("implementationStatus", Json::str(e.status.id())),
                                    ])
                                })
                                .collect(),
                        ),
                    ),
                ]))
            },
        },
        Tool {
            name: "ontology_show",
            description:
                "Full ontology record for one algorithm: strength, FIPS standing, parameter \
                 bounds, usage constraints with severities, related algorithms, Rust path, and a \
                 usage example. Accepts ids, names, and aliases.",
            schema: || {
                schema(
                    vec![("algorithm", string_prop("Algorithm id, name, or alias."))],
                    &["algorithm"],
                )
            },
            call: |args| {
                let name = required(args, "algorithm")?;
                let e = ac_ontology::get(name)
                    .ok_or_else(|| format!("unknown algorithm '{name}'"))?;
                Ok(ops::entry_json(e))
            },
        },
        Tool {
            name: "ontology_errors",
            description:
                "The library's complete error vocabulary, with what each failure means, how to \
                 recover, and whether retrying could help.",
            schema: || schema(vec![], &[]),
            call: |_| Ok(ops::errors_json()),
        },
        Tool {
            name: "crypto_standard",
            description:
                "Look up the standards that define an algorithm, or one document by its                  citation. Returns the title, publisher, year, whether it is still current,                  what it covers, and the obligations it imposes on an implementation -- each                  with whether this library meets it and the file that evidences it. Use this                  to answer 'what does FIPS 203 require here' without guessing.",
            schema: || {
                schema(
                    vec![
                        (
                            "standard",
                            string_prop("A citation such as 'FIPS 203' or 'RFC 8439'."),
                        ),
                        (
                            "algorithm",
                            string_prop(
                                "An algorithm id; returns every document that defines it.",
                            ),
                        ),
                    ],
                    &[],
                )
            },
            call: |args| match arg(args, "standard") {
                Some(id) => ops::standard_lookup_json(id),
                None => ops::standards_json(arg(args, "algorithm")),
            },
        },
        Tool {
            name: "crypto_requirements",
            description:
                "The conformance view: every normative obligation drawn from the standards,                  with whether this library meets it, does not, or is not bound by it -- and                  why. Filter by state or algorithm. Nothing here asserts FIPS validation; a                  met requirement means the code does what the document asks, not that a                  laboratory has agreed.",
            schema: || {
                schema(
                    vec![
                        (
                            "state",
                            enum_prop(
                                "Narrow to one compliance state.",
                                "met, unmet, not-applicable",
                            ),
                        ),
                        (
                            "algorithm",
                            string_prop(
                                "Narrow to obligations bearing on this algorithm id.                                  Library-wide obligations always match.",
                            ),
                        ),
                    ],
                    &[],
                )
            },
            call: |args| ops::requirements_json(arg(args, "state"), arg(args, "algorithm")),
        },
        Tool {
            name: "crypto_capabilities",
            description:
                "What this build can and cannot do: backend, module state, algorithm counts, and \
                 an explicit statement of FIPS validation status.",
            schema: || schema(vec![], &[]),
            call: |_| Ok(ops::capabilities_json()),
        },
        Tool {
            name: "crypto_selftest",
            description:
                "Run the FIPS known-answer tests, for one algorithm or for all of them.",
            schema: || {
                schema(
                    vec![("algorithm", string_prop("Optional: test just this algorithm."))],
                    &[],
                )
            },
            call: |args| ops::selftest_json(arg(args, "algorithm")),
        },
        Tool {
            name: "crypto_digest",
            description: "Hash a UTF-8 string and return the digest as hex.",
            schema: || {
                schema(
                    vec![
                        ("algorithm", string_prop("Digest id, e.g. sha2-256.")),
                        ("data", string_prop("The text to hash.")),
                    ],
                    &["algorithm", "data"],
                )
            },
            call: |args| {
                let hex = ops::digest_hex(
                    required(args, "algorithm")?,
                    required(args, "data")?.as_bytes(),
                )?;
                Ok(Json::object([("digest", Json::str(hex))]))
            },
        },
        Tool {
            name: "crypto_hmac",
            description: "Compute an HMAC tag over a UTF-8 string with a hex key.",
            schema: || {
                schema(
                    vec![
                        ("algorithm", string_prop("MAC id, e.g. hmac-sha2-256.")),
                        ("key", string_prop("Hex-encoded key.")),
                        ("data", string_prop("The text to authenticate.")),
                    ],
                    &["algorithm", "key", "data"],
                )
            },
            call: |args| {
                let key = hex_arg(args, "key")?;
                let hex = ops::hmac_hex(
                    required(args, "algorithm")?,
                    &key,
                    required(args, "data")?.as_bytes(),
                )?;
                Ok(Json::object([("tag", Json::str(hex))]))
            },
        },
        Tool {
            name: "crypto_seal",
            description:
                "Encrypt with an AEAD and return the ciphertext and tag as hex. Key, nonce, and                  associated data are hex; the plaintext is a UTF-8 string.",
            schema: || {
                schema(
                    vec![
                        ("algorithm", string_prop("AEAD id, e.g. aes-256-gcm.")),
                        ("key", string_prop("Hex-encoded key.")),
                        ("nonce", string_prop("Hex-encoded nonce; never reuse one under a key.")),
                        ("aad", string_prop("Optional hex-encoded associated data.")),
                        ("plaintext", string_prop("The text to encrypt.")),
                    ],
                    &["algorithm", "key", "nonce", "plaintext"],
                )
            },
            call: |args| {
                let key = hex_arg(args, "key")?;
                let nonce = hex_arg(args, "nonce")?;
                let aad = match arg(args, "aad") {
                    Some(text) if !text.is_empty() => ac_core::codec::unhex(text)
                        .map_err(|e| format!("'aad' must be hex: {e}"))?,
                    _ => Vec::new(),
                };
                let (ct, tag) = ops::seal_hex(
                    required(args, "algorithm")?,
                    &key,
                    &nonce,
                    &aad,
                    required(args, "plaintext")?.as_bytes(),
                )?;
                Ok(Json::object([
                    ("ciphertext", Json::str(ct)),
                    ("tag", Json::str(tag)),
                ]))
            },
        },
        Tool {
            name: "crypto_random",
            description:
                "Generate random bytes from the OS-seeded SP 800-90A DRBG, returned as hex.",
            schema: || {
                schema(
                    vec![(
                        "bytes",
                        Json::object([
                            ("type", Json::str("integer")),
                            ("minimum", Json::num(1)),
                            ("maximum", Json::num(1024)),
                            ("description", Json::str("How many bytes to generate.")),
                        ]),
                    )],
                    &["bytes"],
                )
            },
            call: |args| {
                let n = args
                    .get("bytes")
                    .and_then(|v| v.as_i64())
                    .ok_or("missing required argument 'bytes'")?;
                let hex = ops::random_hex(n.max(0) as usize)?;
                Ok(Json::object([("hex", Json::str(hex))]))
            },
        },
    ]
}

fn error_response(id: Json, code: i64, message: &str) -> Json {
    Json::object([
        ("jsonrpc", Json::str("2.0")),
        ("id", id),
        (
            "error",
            Json::object([
                ("code", Json::num(code as f64)),
                ("message", Json::str(message)),
            ]),
        ),
    ])
}

fn result_response(id: Json, result: Json) -> Json {
    Json::object([
        ("jsonrpc", Json::str("2.0")),
        ("id", id),
        ("result", result),
    ])
}

/// Wrap a tool result in the MCP content envelope.
fn tool_content(body: Json, is_error: bool) -> Json {
    Json::object([
        (
            "content",
            Json::Array(vec![Json::object([
                ("type", Json::str("text")),
                ("text", Json::str(body.to_string())),
            ])]),
        ),
        ("isError", Json::Bool(is_error)),
    ])
}

/// Handle one JSON-RPC request, returning the response, or `None` for a
/// notification (which JSON-RPC says must not be answered).
pub fn handle(request: &Json) -> Option<Json> {
    let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = request.get("id").cloned();
    let params = request.get("params").cloned().unwrap_or(Json::Null);

    // A request without an id is a notification.
    let id = id?;

    let response = match method {
        "initialize" => result_response(
            id,
            Json::object([
                ("protocolVersion", Json::str(PROTOCOL_VERSION)),
                ("capabilities", Json::object([("tools", Json::object([]))])),
                (
                    "serverInfo",
                    Json::object([
                        ("name", Json::str("agentic-crypto")),
                        ("version", Json::str(agentic_crypto::VERSION)),
                    ]),
                ),
                (
                    "instructions",
                    Json::str(
                        "Call crypto_recommend before choosing an algorithm. It reports the \
                         correct choice for your constraints, and says plainly when the correct \
                         choice is not implemented here rather than offering a substitute. Use \
                         ontology_show to read parameter bounds and usage constraints before \
                         writing a call.",
                    ),
                ),
            ]),
        ),
        "tools/list" => result_response(
            id,
            Json::object([(
                "tools",
                Json::Array(
                    tools()
                        .iter()
                        .map(|t| {
                            Json::object([
                                ("name", Json::str(t.name)),
                                ("description", Json::str(t.description)),
                                ("inputSchema", (t.schema)()),
                            ])
                        })
                        .collect(),
                ),
            )]),
        ),
        "tools/call" => {
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or(Json::Object(Default::default()));
            match tools().iter().find(|t| t.name == name) {
                Some(tool) => match (tool.call)(&args) {
                    Ok(body) => result_response(id, tool_content(body, false)),
                    // A tool-level failure is reported inside the result with
                    // `isError`, not as a protocol error: the agent needs to see
                    // the message and try again, not treat the server as broken.
                    Err(message) => result_response(
                        id,
                        tool_content(Json::object([("error", Json::str(message))]), true),
                    ),
                },
                None => error_response(id, -32601, &format!("unknown tool '{name}'")),
            }
        }
        "ping" => result_response(id, Json::object([])),
        other => error_response(id, -32601, &format!("unknown method '{other}'")),
    };

    Some(response)
}

/// Serve MCP over stdin/stdout until end of input.
pub fn serve() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = match parse(&line) {
            Ok(request) => handle(&request),
            Err(message) => Some(error_response(
                Json::Null,
                -32700,
                &format!("parse error: {message}"),
            )),
        };
        if let Some(response) = response {
            writeln!(stdout, "{response}")?;
            stdout.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str, params: Json) -> Json {
        Json::object([
            ("jsonrpc", Json::str("2.0")),
            ("id", Json::num(1)),
            ("method", Json::str(method)),
            ("params", params),
        ])
    }

    fn call(name: &str, args: Json) -> Json {
        let req = request(
            "tools/call",
            Json::object([("name", Json::str(name)), ("arguments", args)]),
        );
        handle(&req).expect("a request with an id must be answered")
    }

    /// The text body a tool returns, parsed back into JSON.
    fn body(response: &Json) -> Json {
        let content = response.get("result").unwrap().get("content").unwrap();
        match content {
            Json::Array(items) => parse(items[0].get("text").unwrap().as_str().unwrap()).unwrap(),
            _ => panic!("expected content array"),
        }
    }

    fn is_error(response: &Json) -> bool {
        response
            .get("result")
            .and_then(|r| r.get("isError"))
            .and_then(|b| b.as_bool())
            .unwrap_or(false)
    }

    #[test]
    fn initialize_reports_protocol_and_server_info() {
        let r = handle(&request("initialize", Json::Null)).unwrap();
        let result = r.get("result").unwrap();
        assert_eq!(
            result.get("protocolVersion").unwrap().as_str(),
            Some(PROTOCOL_VERSION)
        );
        assert_eq!(
            result
                .get("serverInfo")
                .unwrap()
                .get("name")
                .unwrap()
                .as_str(),
            Some("agentic-crypto")
        );
        assert!(result.get("instructions").is_some());
    }

    #[test]
    fn tools_list_is_complete_and_well_formed() {
        let r = handle(&request("tools/list", Json::Null)).unwrap();
        let listed = r.get("result").unwrap().get("tools").unwrap();
        match listed {
            Json::Array(items) => {
                assert_eq!(items.len(), tools().len());
                for t in items {
                    assert!(!t.get("name").unwrap().as_str().unwrap().is_empty());
                    assert!(t.get("description").unwrap().as_str().unwrap().len() > 20);
                    let s = t.get("inputSchema").unwrap();
                    assert_eq!(s.get("type").unwrap().as_str(), Some("object"));
                    assert!(s.get("properties").is_some());
                    assert!(s.get("required").is_some());
                }
            }
            _ => panic!("expected an array"),
        }
    }

    #[test]
    fn recommend_tool_returns_a_choice() {
        let r = call(
            "crypto_recommend",
            Json::object([
                ("intent", Json::str("encrypt-message")),
                ("fips", Json::Bool(true)),
            ]),
        );
        assert!(!is_error(&r));
        assert_eq!(
            body(&r).get("recommended").unwrap().as_str(),
            Some("aes-256-gcm")
        );
    }

    /// The behaviour this whole project exists for: under a FIPS policy, the
    /// tool must decline rather than hand back Ed25519.
    #[test]
    fn recommend_tool_declines_rather_than_substituting() {
        // A FIPS policy must yield the approved scheme, not the convenient one.
        let r = call(
            "crypto_recommend",
            Json::object([
                ("intent", Json::str("sign-data")),
                ("fips", Json::Bool(true)),
            ]),
        );
        let b = body(&r);
        assert_eq!(b.get("status").unwrap().as_str(), Some("ok"));
        assert_eq!(
            b.get("recommended").unwrap().as_str(),
            Some("ecdsa-p256-sha256")
        );

        // And where nothing suitable is implemented, it declines outright.
        let r = call(
            "crypto_recommend",
            Json::object([
                ("intent", Json::str("agree-key")),
                ("post_quantum", Json::Bool(true)),
            ]),
        );
        let b = body(&r);
        assert_eq!(b.get("status").unwrap().as_str(), Some("unavailable"));
        assert_eq!(b.get("recommended"), Some(&Json::Null));
        assert_eq!(b.get("correctAnswer").unwrap().as_str(), Some("ml-kem-768"));
    }

    #[test]
    fn ontology_tools_work() {
        let r = call(
            "ontology_list",
            Json::object([("class", Json::str("aead"))]),
        );
        assert!(body(&r).get("count").unwrap().as_i64().unwrap() >= 4);

        let r = call(
            "ontology_show",
            Json::object([("algorithm", Json::str("SHA-256"))]),
        );
        assert_eq!(body(&r).get("id").unwrap().as_str(), Some("sha2-256"));

        let r = call("ontology_errors", Json::object([]));
        assert!(!is_error(&r));
    }

    #[test]
    fn primitive_tools_produce_correct_values() {
        let r = call(
            "crypto_digest",
            Json::object([
                ("algorithm", Json::str("sha2-256")),
                ("data", Json::str("abc")),
            ]),
        );
        assert_eq!(
            body(&r).get("digest").unwrap().as_str(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );

        let r = call(
            "crypto_hmac",
            Json::object([
                ("algorithm", Json::str("hmac-sha2-256")),
                ("key", Json::str("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")),
                ("data", Json::str("Hi There")),
            ]),
        );
        assert_eq!(
            body(&r).get("tag").unwrap().as_str(),
            Some("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
        );

        let r = call("crypto_random", Json::object([("bytes", Json::num(16))]));
        assert_eq!(body(&r).get("hex").unwrap().as_str().unwrap().len(), 32);
    }

    #[test]
    fn seal_tool_encrypts_and_authenticates() {
        let r = call(
            "crypto_seal",
            Json::object([
                ("algorithm", Json::str("aes-256-gcm")),
                ("key", Json::str("00".repeat(32))),
                ("nonce", Json::str("00".repeat(12))),
                ("plaintext", Json::str("data")),
            ]),
        );
        assert!(!is_error(&r));
        let b = body(&r);
        assert_eq!(b.get("ciphertext").unwrap().as_str().unwrap().len(), 8);
        assert_eq!(b.get("tag").unwrap().as_str().unwrap().len(), 32);

        // A wrong-sized key is a tool error the agent can correct.
        let r = call(
            "crypto_seal",
            Json::object([
                ("algorithm", Json::str("aes-256-gcm")),
                ("key", Json::str("00".repeat(16))),
                ("nonce", Json::str("00".repeat(12))),
                ("plaintext", Json::str("data")),
            ]),
        );
        assert!(is_error(&r));
    }

    #[test]
    fn selftest_tool_reports_all_passing() {
        let r = call("crypto_selftest", Json::object([]));
        assert_eq!(body(&r).get("failed").unwrap().as_i64(), Some(0));
    }

    #[test]
    fn capabilities_tool_denies_validation() {
        let r = call("crypto_capabilities", Json::object([]));
        assert!(body(&r)
            .get("validationStatement")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("NOT been submitted"));
    }

    /// The knowledgebase is reachable over MCP, with the evidence attached.
    ///
    /// An agent asking "what does FIPS 203 require of this" should get the
    /// obligations *and* where to look, otherwise it has to take the server's
    /// word for it.
    #[test]
    fn the_standards_tool_returns_obligations_with_evidence() {
        let r = call(
            "crypto_standard",
            Json::object([("standard", Json::str("FIPS 203"))]),
        );
        assert!(!is_error(&r));
        let b = body(&r);
        assert_eq!(b.get("id").unwrap().as_str(), Some("FIPS 203"));
        assert_eq!(b.get("status").unwrap().as_str(), Some("current"));

        let reqs = b.get("requirements").unwrap().as_array().unwrap();
        assert!(!reqs.is_empty(), "FIPS 203 must carry requirements");
        let met = reqs
            .iter()
            .find(|r| r.get("id").unwrap().as_str() == Some("fips-203-encaps-key-check"))
            .expect("the section 7.2 check must be listed");
        let c = met.get("compliance").unwrap();
        assert_eq!(c.get("state").unwrap().as_str(), Some("met"));
        assert!(
            c.get("file").unwrap().as_str().unwrap().contains("kem.rs"),
            "a met requirement must say where to look"
        );

        // By algorithm rather than by citation.
        let r = call(
            "crypto_standard",
            Json::object([("algorithm", Json::str("ml-kem-768"))]),
        );
        assert!(!is_error(&r));
        let docs = body(&r).get("standards").unwrap().as_array().unwrap().len();
        assert!(docs >= 1, "ml-kem-768 must cite at least one document");

        // An unknown citation is a tool error the agent can correct.
        let r = call(
            "crypto_standard",
            Json::object([("standard", Json::str("FIPS 999"))]),
        );
        assert!(is_error(&r));
    }

    /// The conformance view totals, and the filter.
    #[test]
    fn the_requirements_tool_reports_totals_and_filters() {
        let r = call("crypto_requirements", Json::object([]));
        assert!(!is_error(&r));
        let b = body(&r);
        let totals = b.get("totals").unwrap();
        let met = totals.get("met").unwrap().as_f64().unwrap();
        assert!(
            met >= 12.0,
            "most requirements should be wired to code: {met}"
        );

        // Filtering must actually narrow, not silently return everything.
        let all = b.get("count").unwrap().as_f64().unwrap();
        let r = call(
            "crypto_requirements",
            Json::object([("algorithm", Json::str("ml-kem-768"))]),
        );
        let narrowed = body(&r).get("count").unwrap().as_f64().unwrap();
        assert!(narrowed < all, "a filter must narrow: {narrowed} vs {all}");
        assert!(narrowed > 0.0, "and must not narrow to nothing");

        // Library-wide obligations match every algorithm, which is the case a
        // naive filter gets wrong by dropping them.
        let r = call(
            "crypto_requirements",
            Json::object([("algorithm", Json::str("ml-kem-768"))]),
        );
        let scoped = body(&r);
        let ids: Vec<&str> = scoped
            .get("requirements")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|x| x.get("id").and_then(|v| v.as_str()))
            .collect();
        assert!(
            ids.iter().any(|i| i.starts_with("fips-140-3")),
            "module-wide obligations must match too, got {ids:?}"
        );

        // A bad state is correctable, not a crash.
        let r = call(
            "crypto_requirements",
            Json::object([("state", Json::str("nonsense"))]),
        );
        assert!(is_error(&r));
    }

    #[test]
    fn tool_failures_are_reported_in_band() {
        // A bad argument is a tool error the agent can correct, not a protocol
        // error that suggests the server is broken.
        let r = call(
            "crypto_digest",
            Json::object([("algorithm", Json::str("sha2-256"))]),
        );
        assert!(is_error(&r));
        assert!(body(&r)
            .get("error")
            .unwrap()
            .as_str()
            .unwrap()
            .contains("data"));

        let r = call(
            "crypto_hmac",
            Json::object([
                ("algorithm", Json::str("hmac-sha2-256")),
                ("key", Json::str("not-hex")),
                ("data", Json::str("x")),
            ]),
        );
        assert!(is_error(&r));
    }

    #[test]
    fn unknown_methods_and_tools_produce_protocol_errors() {
        let r = handle(&request("does/not/exist", Json::Null)).unwrap();
        assert_eq!(
            r.get("error").unwrap().get("code").unwrap().as_i64(),
            Some(-32601)
        );

        let r = call("no_such_tool", Json::object([]));
        assert_eq!(
            r.get("error").unwrap().get("code").unwrap().as_i64(),
            Some(-32601)
        );
    }

    #[test]
    fn notifications_are_not_answered() {
        let notification = Json::object([
            ("jsonrpc", Json::str("2.0")),
            ("method", Json::str("notifications/initialized")),
        ]);
        assert!(handle(&notification).is_none());
    }

    #[test]
    fn every_response_is_valid_json() {
        for r in [
            handle(&request("initialize", Json::Null)).unwrap(),
            handle(&request("tools/list", Json::Null)).unwrap(),
            call("crypto_capabilities", Json::object([])),
        ] {
            let text = r.to_string();
            parse(&text).unwrap_or_else(|e| panic!("invalid response JSON: {e}\n{text}"));
        }
    }
}
