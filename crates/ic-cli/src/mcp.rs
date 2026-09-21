//! A Model Context Protocol server over stdio.
//!
//! This is the door an agent walks through. It speaks newline-delimited
//! JSON-RPC 2.0 on stdin/stdout and exposes the ontology, the selector, the
//! self-tests, and a few primitive operations as MCP tools.
//!
//! Run it with `icrypto mcp`, or wire it into a client config:
//!
//! ```jsonc
//! {
//!   "mcpServers": {
//!     "iron-crypto": { "command": "icrypto", "args": ["mcp"] }
//!   }
//! }
//! ```
//!
//! Every tool schema is generated from the same vocabulary the library uses, so
//! the enum of valid `class` values an agent sees is the enum the query engine
//! actually accepts.

use crate::ops;
use ic_json::{parse, Json};
use std::io::{BufRead, Read, Write};

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
    ic_core::codec::unhex(text).map_err(|e| format!("'{name}' must be hex: {e}"))
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
                    ic_core::codec::hex_decode(trimmed.as_bytes(), &mut out)
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
                let e = ic_ontology::get(name)
                    .ok_or_else(|| format!("unknown algorithm '{name}'"))?;
                Ok(ops::entry_detail_json(e))
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
            name: "crypto_controls",
            description:
                "Security framework coverage: MITRE CWE weakness classes, MITRE ATT&CK \
                 techniques, and CMMC 2.0 practices, each with whether IronCrypto satisfies it \
                 and the file that evidences it. Filter by framework, algorithm or compliance \
                 state. IMPORTANT: IronCrypto is NOT FIPS-validated, so CMMC SC.L2-3.13.11 is \
                 reported as unmet; any answer about FIPS-validated cryptography must say so \
                 rather than inferring satisfaction from the other entries.",
            schema: || {
                schema(
                    vec![
                        (
                            "framework",
                            enum_prop("Narrow to one framework.", "cwe, attack, cmmc"),
                        ),
                        (
                            "algorithm",
                            string_prop(
                                "Narrow to controls bearing on this algorithm id. \
                                 Library-wide controls always match.",
                            ),
                        ),
                        (
                            "state",
                            enum_prop(
                                "Narrow to one compliance state.",
                                "met, partial, unmet, not-applicable",
                            ),
                        ),
                        (
                            "control",
                            string_prop("A single control id, e.g. CWE-327 or SC.L2-3.13.11."),
                        ),
                    ],
                    &[],
                )
            },
            call: |args| match arg(args, "control") {
                Some(id) => ops::control_lookup_json(id),
                None => ops::controls_json(
                    arg(args, "framework"),
                    arg(args, "algorithm"),
                    arg(args, "state"),
                ),
            },
        },
        Tool {
            name: "crypto_standard",
            description:
                "Look up the standards that define an algorithm, or one document by its citation. \
                 Returns the title, publisher, year, whether it is still current, what it covers, \
                 and the obligations it imposes on an implementation -- each with whether this \
                 library meets it and the file that evidences it. Use this to answer 'what does \
                 FIPS 203 require here' without guessing.",
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
                "The conformance view: every normative obligation drawn from the standards, with \
                 whether this library meets it, meets it partially, does not, or is not bound by it \
                 -- and why. A partial answer names the gap, which is the one a binary yes/no would \
                 misreport in either direction. Filter by state or algorithm. Nothing here asserts \
                 FIPS validation; a met requirement means the code does what the document asks, not \
                 that a laboratory has agreed.",
            schema: || {
                schema(
                    vec![
                        (
                            "state",
                            enum_prop(
                                "Narrow to one compliance state.",
                                "met, partial, unmet, not-applicable",
                            ),
                        ),
                        (
                            "algorithm",
                            string_prop(
                                "Narrow to obligations bearing on this algorithm id. Library-wide \
                                 obligations always match.",
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
                "Encrypt with an AEAD and return the ciphertext and tag as hex. Key, nonce, and \
                 associated data are hex; the plaintext is a UTF-8 string.",
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
                    Some(text) if !text.is_empty() => ic_core::codec::unhex(text)
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
                        ("name", Json::str("iron-crypto")),
                        ("version", Json::str(iron_crypto::VERSION)),
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

/// The largest JSON-RPC message this server will hold in memory.
///
/// `lines()` grows a buffer until it meets a newline, so without a bound a peer
/// that never sends one exhausts memory -- and `ic_json::parse` then multiplies
/// whatever arrived by four, because it collects into `Vec<char>` and a char is
/// four bytes.
///
/// 16 MiB is far above anything real. The largest calls here carry a
/// hex-encoded payload for `crypto_digest` or a PEM file for `key_inspect`, and
/// both are kilobytes.
const MAX_MESSAGE: usize = 16 * 1024 * 1024;

/// Serve MCP over stdin/stdout until end of input.
pub fn serve() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    serve_on(stdin.lock(), &mut stdout)
}

/// [`serve`], over any reader and writer.
///
/// Split out so the message bound and its recovery can be tested without a
/// real stdin. The behaviour that matters there is not the refusal but what
/// happens next: a peer that sends one oversized message must still be served
/// the one after it.
pub fn serve_on(mut input: impl BufRead, stdout: &mut impl Write) -> std::io::Result<()> {
    loop {
        let mut line = Vec::new();
        // One byte past the limit, so an oversized message is recognised rather
        // than silently truncated into something that might still parse.
        let read = (&mut input)
            .take(MAX_MESSAGE as u64 + 1)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }

        if line.len() > MAX_MESSAGE {
            // The rest of this message is still in the stream. Discard it
            // without buffering, so recovering from an oversized message does
            // not itself hold it in memory, then carry on: one bad message is
            // not a reason to stop serving.
            // `read_until` rather than `read`: it stops *at* the newline, so
            // it cannot consume the start of the next message. A plain `read`
            // takes a fixed chunk wherever the boundary falls and swallows
            // whatever follows -- which loses the message after this one, the
            // opposite of carrying on. Three messages in, two responses out.
            let mut sink = Vec::new();
            while !line.ends_with(b"\n") {
                sink.clear();
                let n = (&mut input).take(65536).read_until(b'\n', &mut sink)?;
                if n == 0 || sink.ends_with(b"\n") {
                    break;
                }
            }
            let response = error_response(
                Json::Null,
                -32700,
                &format!("message larger than {MAX_MESSAGE} bytes"),
            );
            writeln!(stdout, "{response}")?;
            stdout.flush()?;
            continue;
        }

        let line = String::from_utf8_lossy(&line);
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
mod totality_tests {
    use super::*;

    /// A JSON-RPC envelope around one call.
    fn envelope(method: &str, params: Json) -> Json {
        Json::object([
            ("jsonrpc", Json::str("2.0")),
            ("id", Json::num(1)),
            ("method", Json::str(method)),
            ("params", params),
        ])
    }

    /// Hostile values for a string argument, including the shapes that have
    /// broken parsers elsewhere in this workspace.
    fn hostile_strings() -> Vec<String> {
        let mut out = vec![
            String::new(),
            "0".into(),
            "zz".into(),       // not hex
            "0z".into(),       // half hex
            "00".repeat(1000), // long but valid hex
            "ff".repeat(1000),
            "\u{0}\u{1}\u{7f}".into(),           // control characters
            "\u{1f600}".into(),                  // outside the basic plane
            "-----BEGIN PUBLIC KEY-----".into(), // a truncated PEM header
            "-".repeat(500),
            "a".repeat(100_000),
        ];
        // Every odd length up to a block, since hex decoding and key lengths
        // both care about parity and boundaries.
        for n in [1usize, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 65] {
            out.push("a".repeat(n));
            out.push("0".repeat(n));
        }
        out
    }

    /// The handler must return for every request, however malformed.
    ///
    /// Not "must succeed": a bad argument should come back as `isError` inside
    /// the result, which is where the protocol puts a failure the agent is
    /// meant to read and retry. What must not happen is a panic, because that
    /// ends the server rather than the call.
    #[test]
    fn every_tool_returns_on_hostile_arguments() {
        let tools = tools();
        assert!(tools.len() >= 10, "only {} tools found", tools.len());

        let mut calls = 0;
        let mut reached_the_tool = 0;

        for tool in &tools {
            // The argument names this tool declares, from its own schema, so a
            // tool gaining an argument is covered without editing this.
            let schema = (tool.schema)();
            let Some(Json::Object(props)) = schema.get("properties") else {
                panic!("{} has no properties", tool.name)
            };
            let names: Vec<String> = props.keys().cloned().collect();

            for value in hostile_strings() {
                // Every argument set to the same hostile value, so required
                // ones are present and the call gets past the argument check
                // into the code that interprets them.
                let mut args = std::collections::BTreeMap::new();
                for name in &names {
                    args.insert(name.clone(), Json::str(value.clone()));
                }
                let call = envelope(
                    "tools/call",
                    Json::object([
                        ("name", Json::str(tool.name)),
                        ("arguments", Json::Object(args.clone())),
                    ]),
                );

                let response = handle(&call).expect("a request with an id gets a response");
                calls += 1;

                // Depth means the tool examined the value it was handed and
                // objected to *it* -- not that the call returned. Two things
                // are excluded, and both fooled the first version of this:
                //
                //   - "missing required argument", which is the call stopping
                //     at the argument check before any value is read;
                //   - a plain success, because six of these tools require no
                //     arguments and answer happily when sent none. A fuzzer
                //     supplying nothing at all passed the old guard on those.
                let text = response.to_string();
                let objected = text.contains("\"isError\":true");
                if objected && !text.contains("missing required argument") {
                    reached_the_tool += 1;
                }
            }

            // Each argument dropped in turn, once. What this exercises is the
            // absence rather than the value that was absent, so repeating it
            // per hostile value only costs time -- 29 seconds of it, almost all
            // in `crypto_selftest`, which runs all 64 known-answer tests when
            // its argument is missing.
            for dropped in &names {
                let mut short = std::collections::BTreeMap::new();
                for name in &names {
                    if name != dropped {
                        short.insert(name.clone(), Json::str("00"));
                    }
                }
                let call = envelope(
                    "tools/call",
                    Json::object([
                        ("name", Json::str(tool.name)),
                        ("arguments", Json::Object(short)),
                    ]),
                );
                assert!(handle(&call).is_some(), "{} without {dropped}", tool.name);
                calls += 1;
            }

            // Wrong types, which the accessors turn into None rather than a
            // panic -- worth asserting, since that is the behaviour being
            // relied on.
            for wrong in [
                Json::Null,
                Json::Bool(true),
                Json::Number(-1.0),
                Json::Number(f64::MAX),
                Json::Array(vec![Json::Null; 3]),
            ] {
                let mut args = std::collections::BTreeMap::new();
                for name in &names {
                    args.insert(name.clone(), wrong.clone());
                }
                let call = envelope(
                    "tools/call",
                    Json::object([
                        ("name", Json::str(tool.name)),
                        ("arguments", Json::Object(args)),
                    ]),
                );
                assert!(handle(&call).is_some(), "{} on {wrong:?}", tool.name);
                calls += 1;
            }
        }

        // Floors. Without these the loop passes having tried nothing, and the
        // second is the one that matters: arguments all rejected for being
        // absent would never reach a cipher, a hex decoder or a key parser.
        assert!(calls > 250, "only {calls} calls made");
        assert!(
            reached_the_tool > calls / 4,
            "only {reached_the_tool} of {calls} calls reached a tool that then \
             objected to the value it was given; the rest either stopped at the \
             argument check or succeeded without reading anything, so the hostile \
             values never got near the code that interprets them"
        );
    }

    /// The protocol layer must return for malformed envelopes too.
    #[test]
    fn the_protocol_layer_returns_on_anything() {
        let shapes = [
            Json::Null,
            Json::Bool(false),
            Json::Number(0.0),
            Json::str("not an object"),
            Json::Array(vec![]),
            Json::object([]),
            Json::object([("method", Json::Null)]),
            Json::object([("id", Json::Null), ("method", Json::Number(7.0))]),
            Json::object([("id", Json::str("x")), ("method", Json::str("tools/call"))]),
            Json::object([
                ("id", Json::Number(1.0)),
                ("method", Json::str("tools/call")),
                ("params", Json::str("not an object")),
            ]),
            Json::object([
                ("id", Json::Number(1.0)),
                ("method", Json::str("tools/call")),
                ("params", Json::object([("name", Json::Number(3.0))])),
            ]),
        ];

        let mut tried = 0;
        for shape in shapes {
            // Returning None is allowed -- that is a notification -- but it
            // must return rather than panic.
            let _ = handle(&shape);
            tried += 1;
        }
        assert_eq!(tried, 11);
    }
}

#[cfg(test)]
mod serve_tests {
    use super::*;

    /// A message larger than the bound is refused, and the next one is served.
    ///
    /// The refusal is the easy half. The half that goes wrong is the recovery:
    /// the rest of the oversized message is still in the stream and has to be
    /// discarded without crossing into the message behind it. The first attempt
    /// used `read`, which takes a fixed chunk wherever the boundary falls, and
    /// ate the following request -- three messages in, two responses out.
    #[test]
    fn an_oversized_message_is_refused_and_the_next_one_still_answered() {
        let huge = "x".repeat(MAX_MESSAGE + 1024);
        let input = format!(
            concat!(
                r#"{{"jsonrpc":"2.0","id":1,"method":"tools/list"}}"#,
                "\n",
                r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"crypto_digest","arguments":{{"algorithm":"sha2-256","data":"{}"}}}}}}"#,
                "\n",
                r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"crypto_random","arguments":{{"bytes":4}}}}}}"#,
                "\n"
            ),
            huge
        );

        let mut out = Vec::new();
        serve_on(input.as_bytes(), &mut out).expect("serving should not fail");
        let out = String::from_utf8(out).expect("responses are utf-8");
        let responses: Vec<&str> = out.lines().filter(|l| !l.trim().is_empty()).collect();

        assert_eq!(
            responses.len(),
            3,
            "one response per message, including the refusal: {responses:#?}"
        );
        assert!(responses[0].contains("\"tools\""), "{}", responses[0]);
        assert!(
            responses[1].contains("-32700") && responses[1].contains("larger than"),
            "the oversized message should be refused with a reason: {}",
            responses[1]
        );
        assert!(
            responses[2].contains("hex") && responses[2].contains("\"id\":3"),
            "the message after the oversized one must still be served: {}",
            responses[2]
        );
    }

    /// A message at the bound is accepted, so the limit is where it says.
    #[test]
    fn a_message_within_the_bound_is_served() {
        // Comfortably inside, and far larger than any real call.
        let data = "ab".repeat(100_000);
        let input = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"crypto_digest","arguments":{{"algorithm":"sha2-256","data":"{data}"}}}}}}"#
        ) + "\n";
        assert!(input.len() < MAX_MESSAGE);

        let mut out = Vec::new();
        serve_on(input.as_bytes(), &mut out).unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.contains("digest") && !out.contains("larger than"),
            "a large but permitted message should be served: {out}"
        );
    }

    /// End of input ends the loop rather than spinning.
    #[test]
    fn empty_input_terminates() {
        let mut out = Vec::new();
        serve_on(&b""[..], &mut out).unwrap();
        assert!(out.is_empty());

        // And a message with no trailing newline is still served.
        let one = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        let mut out = Vec::new();
        serve_on(&one[..], &mut out).unwrap();
        assert!(String::from_utf8_lossy(&out).contains("tools"));
    }
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
            Some("iron-crypto")
        );
        assert!(result.get("instructions").is_some());
    }

    #[test]
    fn tools_list_is_complete_and_well_formed() {
        let r = handle(&request("tools/list", Json::Null)).unwrap();
        let listed = r.get("result").unwrap().get("tools").unwrap();
        let Json::Array(items) = listed else {
            panic!("expected an array")
        };
        assert_eq!(items.len(), tools().len());

        for t in items {
            let name = t.get("name").unwrap().as_str().unwrap();
            assert!(!name.is_empty());
            assert!(t.get("description").unwrap().as_str().unwrap().len() > 20);

            let s = t.get("inputSchema").unwrap();
            assert_eq!(s.get("type").unwrap().as_str(), Some("object"));
            let Some(Json::Object(props)) = s.get("properties") else {
                panic!("{name} has no properties object")
            };
            let Some(Json::Array(required)) = s.get("required") else {
                panic!("{name} has no required list")
            };

            // A required argument that is not a declared property cannot be
            // supplied: `inputSchema` is the whole of what an agent is given,
            // so an argument absent from `properties` does not exist to it.
            for r in required {
                let r = r.as_str().expect("required entries are strings");
                assert!(
                    props.contains_key(r),
                    "{name} requires {r:?}, which it never declares"
                );
            }

            // An undescribed or untyped property is one an agent has to guess
            // at, which is the failure mode this whole server exists to avoid.
            for (prop, def) in props {
                let Json::Object(def) = def else {
                    panic!("{name}.{prop} is not a schema object")
                };
                assert!(
                    def.get("description")
                        .and_then(Json::as_str)
                        .is_some_and(|d| d.len() > 10),
                    "{name}.{prop} has no useful description"
                );
                assert!(
                    def.contains_key("type") || def.contains_key("enum"),
                    "{name}.{prop} declares neither a type nor an enum"
                );
            }
        }
    }

    /// Every word an agent reads must be prose, not a source listing.
    ///
    /// A Rust string broken across lines needs a trailing backslash, which eats
    /// the newline and the next line's indentation. Without it the indentation
    /// stays in the string, and four descriptions reached agents with runs of
    /// eighteen and thirty-four spaces in mid-sentence. The ontology already
    /// tests its own prose this way; the tool descriptions were not covered,
    /// which is the only reason it went unnoticed.
    #[test]
    fn descriptions_read_as_prose() {
        let Json::Array(items) = handle(&request("tools/list", Json::Null))
            .unwrap()
            .get("result")
            .unwrap()
            .get("tools")
            .unwrap()
            .clone()
        else {
            panic!("expected an array")
        };

        let mut checked = 0;
        for t in &items {
            let name = t.get("name").unwrap().as_str().unwrap();
            let schema = t.get("inputSchema").unwrap();
            let Some(Json::Object(props)) = schema.get("properties") else {
                panic!("{name} has no properties")
            };

            let mut prose = vec![(
                name.to_string(),
                t.get("description").unwrap().as_str().unwrap(),
            )];
            for (prop, def) in props {
                if let Some(d) = def.get("description").and_then(Json::as_str) {
                    prose.push((format!("{name}.{prop}"), d));
                }
            }

            for (what, text) in prose {
                assert!(
                    !text.contains("  "),
                    "{what} contains a run of spaces, so a line continuation is \
                     missing: {text:?}"
                );
                assert!(
                    !text.contains('\n') && !text.contains('\t'),
                    "{what} contains a literal newline or tab"
                );
                assert!(text.trim() == text, "{what} is padded at one end");
                checked += 1;
            }
        }

        // Well past the fourteen descriptions alone, so this cannot pass by
        // examining the tools and skipping their arguments.
        assert!(checked > 30, "only {checked} pieces of prose examined");
    }

    /// A tool's `required` list must be the one its handler enforces.
    ///
    /// The two are written in different places -- the schema in the `schema`
    /// field, the demand in the `call` closure -- and nothing but this holds
    /// them together. An agent that trusts an empty `required` and gets an
    /// error, or supplies everything listed and is told something else is
    /// missing, has been misled by the description it was handed.
    ///
    /// Calling with no arguments at all separates the two cases: a tool that
    /// requires something must refuse, and a tool that requires nothing must
    /// work.
    #[test]
    fn the_required_list_is_the_one_the_handler_enforces() {
        let Json::Array(items) = handle(&request("tools/list", Json::Null))
            .unwrap()
            .get("result")
            .unwrap()
            .get("tools")
            .unwrap()
            .clone()
        else {
            panic!("expected an array")
        };

        let mut with_required = 0;
        let mut without = 0;

        for t in &items {
            let name = t.get("name").unwrap().as_str().unwrap();
            let Some(Json::Array(required)) = t.get("inputSchema").unwrap().get("required") else {
                panic!("{name} has no required list")
            };

            let response = call(name, Json::object([]));
            let refused = is_error(&response);

            if required.is_empty() {
                assert!(
                    !refused,
                    "{name} requires nothing but refused a call with no arguments: {response}"
                );
                without += 1;
            } else {
                assert!(
                    refused,
                    "{name} lists {} required argument(s) and accepted a call with none",
                    required.len()
                );
                with_required += 1;
            }
        }

        // Both branches must have been taken, or the test proves only that one
        // kind of tool exists.
        assert!(
            with_required > 0 && without > 0,
            "{with_required} tools with required arguments, {without} without"
        );
        assert_eq!(with_required + without, items.len());
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

        // Post-quantum key agreement used to be the example of declining, since
        // ML-KEM-768 was implemented but not vector-tested. It is checked
        // against ACVP now, so the honest answer is the algorithm.
        let r = call(
            "crypto_recommend",
            Json::object([
                ("intent", Json::str("agree-key")),
                ("post_quantum", Json::Bool(true)),
            ]),
        );
        let b = body(&r);
        assert_eq!(b.get("status").unwrap().as_str(), Some("ok"));
        assert_eq!(b.get("recommended").unwrap().as_str(), Some("ml-kem-768"));
        // And it still carries the advice that matters more than the choice.
        assert!(
            b.get("mustObserve")
                .and_then(|c| c.as_array())
                .is_some_and(|cs| cs.iter().any(|c| c.get("id").and_then(Json::as_str)
                    == Some("deploy-post-quantum-in-a-hybrid"))),
            "the hybrid constraint is missing from the recommendation"
        );
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

    /// The detail view must carry the relations that point *at* an entry.
    ///
    /// The registry stores each relation once, in the direction that helps the
    /// reader, so the outgoing edges alone are half the graph. This tool's
    /// description promises "related algorithms", and before the inbound half
    /// was added an agent asking about HKDF-SHA-256 was told it pairs with
    /// X25519 while three ECDH curves and HMAC-SHA-256 pointed at it unseen.
    ///
    /// SHA-256 is the clearest case: it declares one edge and is named by six
    /// other entries, so without this it reads as a leaf.
    #[test]
    fn the_detail_view_shows_both_directions() {
        let r = call(
            "ontology_show",
            Json::object([("algorithm", Json::str("sha2-256"))]),
        );
        assert!(!is_error(&r));
        let b = body(&r);

        let inbound = b
            .get("relatedBy")
            .and_then(|v| v.as_array())
            .expect("the detail view must carry relatedBy");
        let sources: Vec<&str> = inbound
            .iter()
            .filter_map(|x| x.get("source").and_then(|v| v.as_str()))
            .collect();

        assert!(
            sources.len() >= 5,
            "sha2-256 is named by several entries; got {sources:?}"
        );
        for expected in ["md5", "sha-1", "hmac-sha2-256"] {
            assert!(
                sources.contains(&expected),
                "{expected} points at sha2-256 but is not listed: {sources:?}"
            );
        }
        // Every inbound record names the relation, not just the source: an
        // agent needs to know whether it is being superseded or built upon.
        for item in inbound {
            assert!(item.get("relation").and_then(|v| v.as_str()).is_some());
        }

        // And the outgoing half is still there.
        assert!(b.get("relations").and_then(|v| v.as_array()).is_some());

        // The list view stays lean; the inbound half is detail. Checked over
        // the serialized response rather than by indexing into a shape this
        // test would otherwise be asserting by assumption.
        let listed = body(&call("ontology_list", Json::object([]))).to_string();
        assert!(
            listed.contains("sha2-256"),
            "the list response should contain entries"
        );
        assert!(
            !listed.contains("relatedBy"),
            "ontology_list should not carry the inbound half for every entry"
        );
    }

    /// The CLI and this server must return the same data.
    ///
    /// `ops.rs` opens by saying they do, and that a human debugging an agent's
    /// behaviour should be able to reproduce it from a shell. That is a promise
    /// about two front ends staying in step, and nothing checked it — they
    /// share an ops layer today, and the way that decays is a field added to
    /// one path and not the other.
    ///
    /// Comparing the parsed JSON rather than the strings, since key order is
    /// not part of the promise.
    #[test]
    fn the_cli_and_this_server_agree() {
        let cases = [
            (
                vec!["ontology", "show", "sha2-256", "--json"],
                "ontology_show",
                Json::object([("algorithm", Json::str("sha2-256"))]),
            ),
            (
                vec!["recommend", "encrypt-message", "--json"],
                "crypto_recommend",
                Json::object([("intent", Json::str("encrypt-message"))]),
            ),
            (
                vec!["ontology", "standard", "FIPS 203", "--json"],
                "crypto_standard",
                Json::object([("standard", Json::str("FIPS 203"))]),
            ),
            (
                vec!["ontology", "controls", "--json"],
                "crypto_controls",
                Json::object([]),
            ),
        ];

        for (argv, tool, args) in cases {
            let from_cli = crate::run(&argv).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
            let from_cli = ic_json::parse(&from_cli).expect("the CLI emits valid JSON");
            let from_mcp = body(&call(tool, args));
            assert_eq!(
                from_cli,
                from_mcp,
                "`icrypto {}` and the {tool} tool returned different data",
                argv.join(" ")
            );
        }
    }

    /// Every key in every tool response is camelCase.
    ///
    /// The responses used to mix twelve camelCase keys with fifteen
    /// snake_case ones, so an agent parsing across tools had to handle both
    /// with no rule for which applied where. The ontology's exports are
    /// uniformly camelCase, so that is the convention.
    ///
    /// Tool *names* and input *parameters* stay snake_case and are not checked
    /// here: that is the MCP convention for both, they were already consistent,
    /// and they are the part callers have written down.
    #[test]
    fn response_keys_are_camel_case() {
        fn walk(value: &Json, path: &str, bad: &mut Vec<String>) {
            match value {
                Json::Object(fields) => {
                    for (k, v) in fields {
                        if k.contains('_') {
                            bad.push(format!("{path}.{k}"));
                        }
                        walk(v, &format!("{path}.{k}"), bad);
                    }
                }
                Json::Array(items) => {
                    for (i, v) in items.iter().enumerate() {
                        walk(v, &format!("{path}[{i}]"), bad);
                    }
                }
                _ => {}
            }
        }

        // One representative call per tool that returns a structured body.
        let calls = [
            (
                "crypto_recommend",
                Json::object([("intent", Json::str("encrypt-message"))]),
            ),
            ("crypto_capabilities", Json::object([])),
            (
                "crypto_standard",
                Json::object([("standard", Json::str("FIPS 203"))]),
            ),
            ("crypto_requirements", Json::object([])),
            ("crypto_controls", Json::object([])),
            ("ontology_list", Json::object([])),
            (
                "ontology_show",
                Json::object([("algorithm", Json::str("sha2-256"))]),
            ),
            ("ontology_errors", Json::object([])),
        ];

        let mut bad = Vec::new();
        let mut checked = 0;
        for (name, args) in calls {
            let r = call(name, args);
            assert!(!is_error(&r), "{name} returned an error");
            checked += 1;
            walk(&body(&r), name, &mut bad);
        }

        assert_eq!(checked, 8, "a tool stopped responding");
        assert!(
            bad.is_empty(),
            "these response keys are not camelCase: {bad:?}"
        );
    }

    /// The compliance view must lead with what is *not* satisfied.
    ///
    /// An agent asked "is this CMMC compliant" will quote whatever comes back.
    /// If the unmet practice were merely one row among several, it would be
    /// summarised away. So the response names it separately and carries the
    /// validation status as its own field.
    #[test]
    fn the_controls_tool_surfaces_what_is_not_satisfied() {
        let r = call("crypto_controls", Json::object([]));
        assert!(!is_error(&r));
        let b = body(&r);

        assert_eq!(
            b.get("fipsValidated").unwrap().as_bool(),
            Some(false),
            "the response must state plainly that this is not validated"
        );

        let unmet: Vec<&str> = b
            .get("unmet")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|v| v.as_str())
            .collect();
        assert!(
            unmet.contains(&"SC.L2-3.13.11"),
            "the FIPS-validation practice must be named as unmet, got {unmet:?}"
        );

        // And looking it up directly gives the reason, not just a state.
        let r = call(
            "crypto_controls",
            Json::object([("control", Json::str("SC.L2-3.13.11"))]),
        );
        let b = body(&r);
        let why = b
            .get("compliance")
            .unwrap()
            .get("reason")
            .unwrap()
            .as_str()
            .unwrap();
        assert!(why.contains("no CMVP certificate"), "got {why}");

        // Filtering by framework narrows, and an unknown one is correctable.
        let r = call(
            "crypto_controls",
            Json::object([("framework", Json::str("cwe"))]),
        );
        let n = body(&r).get("count").unwrap().as_f64().unwrap();
        assert!(n >= 5.0, "cwe should have several controls: {n}");
        let r = call(
            "crypto_controls",
            Json::object([("framework", Json::str("nonsense"))]),
        );
        assert!(is_error(&r));
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
