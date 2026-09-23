//! `ic` — the command-line and MCP front end for IronCrypto.
//!
//! Every subcommand takes `--json`, because the same tool serves a human
//! reading a terminal and an agent parsing output. `ic mcp` turns the
//! binary into a Model Context Protocol server.

#![forbid(unsafe_code)]

mod mcp;
mod ops;
mod sbom;
mod timing;

use ic_json::Json;
use std::io::Read;
use std::process::ExitCode;

const USAGE: &str = "\
ic — agentic-first cryptography

USAGE:
    ic <COMMAND> [OPTIONS]

DISCOVERY
    recommend <intent>          Choose an algorithm for a task
        --fips                      Require FIPS-approved algorithms
        --post-quantum              Require quantum resistance
        --aes-hardware              Target has AES acceleration
    ontology list               List algorithms
        --class <class>             Filter by kind
        --purpose <purpose>         Filter by security goal
        --fips                      Only approved-mode algorithms
        --available                 Only algorithms built in
    ontology show <algorithm>   Full record for one algorithm
    ontology export <format>    json | jsonld | turtle | schema | markdown
    ontology errors             The error vocabulary
    capabilities                What this build can and cannot do

OPERATIONS
    selftest [algorithm]        Run FIPS known-answer tests
    digest <algorithm>          Hash stdin, print hex
    hmac <algorithm> <hexkey>   Authenticate stdin, print hex
    seal <algorithm> <hexkey> <hexnonce>
                                Encrypt stdin, print ciphertext and tag
    random <bytes>              Random bytes from the DRBG, as hex

KEYS
    key inspect                 Identify a DER or PEM key on stdin

INTEGRATION
    mcp                         Serve the Model Context Protocol on stdio

GLOBAL
    --json                      Machine-readable output
    --help                      This message
    --version                   Version information
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();

    match run(&refs) {
        Ok(output) => {
            if !output.is_empty() {
                println!("{output}");
            }
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("ic: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Whether a flag is present.
fn has_flag(args: &[&str], flag: &str) -> bool {
    args.contains(&flag)
}

/// The value following `--name`, if present.
fn opt<'a>(args: &[&'a str], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| *a == name)
        .and_then(|i| args.get(i + 1))
        .copied()
        .filter(|v| !v.starts_with("--"))
}

/// Flags that take a following value.
///
/// A flag missing from this list still *works* through `opt`, but its value
/// also leaks into the positional arguments, where it is read as a subcommand
/// or an identifier. That is how `--iterations 60000` came to be parsed as a
/// timing target. The list is checked against the source by a test, so adding
/// a valued flag and forgetting to list it fails the build rather than
/// producing a confusing error at run time.
const VALUED_FLAGS: &[&str] = &[
    "--algorithm",
    "--class",
    "--framework",
    "--iterations",
    "--purpose",
    "--state",
];

/// Positional arguments, in order, excluding flags and their values.
#[allow(clippy::manual_pattern_char_comparison)]
fn positionals<'a>(args: &[&'a str]) -> Vec<&'a str> {
    let valued = VALUED_FLAGS;
    let mut out = Vec::new();
    let mut skip_next = false;
    for a in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if valued.contains(a) {
            skip_next = true;
            continue;
        }
        if a.starts_with("--") {
            continue;
        }
        out.push(*a);
    }
    out
}

fn read_stdin() -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    std::io::stdin()
        .read_to_end(&mut buf)
        .map_err(|e| format!("reading stdin: {e}"))?;
    Ok(buf)
}

/// Execute a command line, returning the text to print.
pub fn run(args: &[&str]) -> Result<String, String> {
    if args.is_empty() || has_flag(args, "--help") || args[0] == "help" {
        return Ok(USAGE.to_string());
    }
    if has_flag(args, "--version") || args[0] == "version" {
        return Ok(format!(
            "ic {} (ontology {}, backend {})",
            iron_crypto::VERSION,
            ic_ontology::ONTOLOGY_VERSION,
            ic_ontology::runtime::backend().id()
        ));
    }

    let want_json = has_flag(args, "--json");
    let pos = positionals(args);

    match pos.first().copied().unwrap_or("") {
        "recommend" => {
            let intent = pos
                .get(1)
                .copied()
                .ok_or_else(|| format!("recommend needs an intent: {}", ops::intent_list()))?;
            let result = ops::recommend_json(
                intent,
                has_flag(args, "--fips"),
                has_flag(args, "--post-quantum"),
                has_flag(args, "--aes-hardware"),
            )?;
            Ok(if want_json {
                result.to_string()
            } else {
                render_recommendation(&result)
            })
        }

        "timing" => {
            let iterations = opt(args, "--iterations")
                .map(|s| {
                    s.parse::<usize>()
                        .map_err(|_| "--iterations wants a number".to_string())
                })
                .transpose()?
                .unwrap_or(100_000);
            let json = timing::run(pos.get(1).copied(), iterations)?;
            if want_json {
                return Ok(json.to_string());
            }
            let mut out = String::new();
            for r in json.get("results").and_then(|v| v.as_array()).unwrap() {
                let g = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("");
                let t = r.get("t").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let flag = if r.get("asExpected").and_then(|v| v.as_bool()) == Some(true) {
                    " "
                } else {
                    "!"
                };
                out.push_str(&format!(
                    "{} {:<16} t = {:>10.2}   {:<24} {}
",
                    flag,
                    g("target"),
                    t,
                    g("verdict"),
                    g("classes")
                ));
            }
            out.push_str(&format!(
                "
{}
",
                json.get("interpretation")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
            ));
            Ok(out)
        }

        "sbom" => {
            // Always JSON: an SBOM is consumed by tooling, and a human-readable
            // variant would be a second document that could disagree with it.
            Ok(sbom::cyclonedx().to_string())
        }

        "ontology" => match pos.get(1).copied().unwrap_or("") {
            "list" => {
                let entries = ops::list(
                    opt(args, "--class"),
                    opt(args, "--purpose"),
                    has_flag(args, "--fips"),
                    has_flag(args, "--available"),
                )?;
                if want_json {
                    return Ok(
                        Json::Array(entries.iter().map(|e| ops::entry_json(e)).collect())
                            .to_string(),
                    );
                }
                let mut out = String::new();
                for e in &entries {
                    out.push_str(&format!(
                        "{:<32} {:<14} {:<22} {}\n",
                        e.id,
                        e.class.id(),
                        format!("{} / {}", e.fips.id(), e.status.id()),
                        e.summary
                    ));
                }
                out.push_str(&format!("\n{} algorithm(s)", entries.len()));
                Ok(out)
            }
            "show" => {
                let name = pos
                    .get(2)
                    .copied()
                    .ok_or("ontology show needs an algorithm")?;
                let e = ic_ontology::get(name)
                    .ok_or_else(|| format!("unknown algorithm '{name}'; try `ic ontology list`"))?;
                Ok(if want_json {
                    ops::entry_detail_json(e).to_string()
                } else {
                    render_entry(e)
                })
            }
            "controls" => {
                let json = ops::controls_json(
                    opt(args, "--framework"),
                    opt(args, "--algorithm"),
                    opt(args, "--state"),
                )?;
                if want_json {
                    return Ok(json.to_string());
                }
                let mut out = String::new();
                for c in json.get("controls").and_then(|v| v.as_array()).unwrap() {
                    let g = |k: &str| c.get(k).and_then(|v| v.as_str()).unwrap_or("");
                    let state = c
                        .get("compliance")
                        .and_then(|x| x.get("state"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    out.push_str(&format!(
                        "{:<18} {:<8} {:<16} {}\n",
                        g("id"),
                        g("framework"),
                        state,
                        g("title")
                    ));
                }
                let t = json.get("totals").unwrap();
                let num = |k: &str| t.get(k).and_then(|v| v.as_f64()).unwrap_or(0.0);
                out.push_str(&format!(
                    "\n{} met, {} partial, {} unmet, {} not applicable",
                    num("met"),
                    num("partial"),
                    num("unmet"),
                    num("notApplicable")
                ));
                // The unmet list is printed rather than left to a filter. A
                // compliance summary quoted without its gaps is worse than none.
                if let Some(unmet) = json.get("unmet").and_then(|v| v.as_array()) {
                    if !unmet.is_empty() {
                        let ids: Vec<&str> = unmet.iter().filter_map(|v| v.as_str()).collect();
                        out.push_str(&format!("\nNOT SATISFIED: {}", ids.join(", ")));
                    }
                }
                if json.get("fipsValidated").and_then(|v| v.as_bool()) != Some(true) {
                    out.push_str(
                        "\nIronCrypto is NOT FIPS-validated. Practices requiring validated \
                         cryptography are not satisfied.",
                    );
                }
                Ok(out)
            }
            "control" => {
                let name = pos
                    .get(2)
                    .copied()
                    .ok_or("ontology control needs an id, e.g. CWE-327 or SC.L2-3.13.11")?;
                let json = ops::control_lookup_json(name)?;
                if want_json {
                    return Ok(json.to_string());
                }
                Ok(render_control(&json))
            }
            "standards" => {
                let json = ops::standards_json(opt(args, "--algorithm"))?;
                if want_json {
                    return Ok(json.to_string());
                }
                let mut out = String::new();
                let docs = json.get("standards").and_then(|d| d.as_array()).unwrap();
                for d in docs {
                    let status = d.get("status").and_then(|v| v.as_str()).unwrap_or("");
                    let reqs = d
                        .get("requirements")
                        .and_then(|v| v.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    out.push_str(&format!(
                        "{:<14} {:<14} {}  ({} requirement(s))
",
                        d.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                        status,
                        d.get("title").and_then(|v| v.as_str()).unwrap_or(""),
                        reqs
                    ));
                }
                out.push_str(&format!(
                    "
{} document(s)",
                    docs.len()
                ));
                Ok(out)
            }
            "standard" => {
                let name = pos
                    .get(2)
                    .copied()
                    .ok_or("ontology standard needs a citation, e.g. 'FIPS 203'")?;
                let json = ops::standard_lookup_json(name)?;
                if want_json {
                    return Ok(json.to_string());
                }
                Ok(render_standard(&json))
            }
            "requirements" => {
                let json = ops::requirements_json(opt(args, "--state"), opt(args, "--algorithm"))?;
                if want_json {
                    return Ok(json.to_string());
                }
                let mut out = String::new();
                for r in json.get("requirements").and_then(|v| v.as_array()).unwrap() {
                    let c = r.get("compliance").unwrap();
                    out.push_str(&format!(
                        "{:<36} {:<10} {:<16} {}
",
                        r.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                        r.get("obligation").and_then(|v| v.as_str()).unwrap_or(""),
                        c.get("state").and_then(|v| v.as_str()).unwrap_or(""),
                        r.get("statement").and_then(|v| v.as_str()).unwrap_or("")
                    ));
                }
                let t = json.get("totals").unwrap();
                out.push_str(&format!(
                    "
{} met, {} partial, {} unmet, {} not applicable",
                    t.get("met").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    t.get("partial").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    t.get("unmet").and_then(|v| v.as_f64()).unwrap_or(0.0),
                    t.get("notApplicable")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(0.0),
                ));
                Ok(out)
            }
            "export" => {
                let format = pos.get(2).copied().unwrap_or("json");
                match format {
                    "json" => Ok(ic_ontology::export::to_json()),
                    "jsonld" | "json-ld" => Ok(ic_ontology::export::to_json_ld()),
                    "turtle" | "ttl" => Ok(ic_ontology::export::to_turtle()),
                    "schema" => Ok(ic_ontology::export::to_json_schema()),
                    "markdown" | "md" => Ok(ic_ontology::export::to_markdown()),
                    "standards" => Ok(ops::standards_json(None)?.to_string()),
                    other => Err(format!(
                        "unknown format '{other}'; try json, jsonld, turtle, schema, markdown,                          or standards"
                    )),
                }
            }
            "errors" => {
                if want_json {
                    return Ok(ops::errors_json().to_string());
                }
                let mut out = String::new();
                for d in ic_ontology::errors::catalog() {
                    out.push_str(&format!(
                        "{}\n  {}\n  → {}\n\n",
                        d.id, d.meaning, d.recovery
                    ));
                }
                Ok(out.trim_end().to_string())
            }
            other => Err(format!(
                "unknown ontology subcommand '{other}'; try list, show, export, or errors"
            )),
        },

        "capabilities" => {
            let caps = ops::capabilities_json();
            if want_json {
                return Ok(caps.to_string());
            }
            let mut out = format!(
                "IronCrypto {}\n  backend:       {}\n  ontology:      {} ({} algorithms, {} available)\n  module state:  {}\n\n",
                iron_crypto::VERSION,
                ic_ontology::runtime::backend().id(),
                ic_ontology::ONTOLOGY_VERSION,
                ic_ontology::all().len(),
                ic_ontology::all()
                    .iter()
                    .filter(|e| e.status == ic_ontology::ImplStatus::Available)
                    .count(),
                ic_fips::state().id(),
            );
            for c in ic_ontology::runtime::capabilities() {
                out.push_str(&format!(
                    "  [{}] {}\n      {}\n",
                    if c.present { "x" } else { " " },
                    c.id,
                    c.note
                ));
            }
            out.push_str(&format!("\n{}", ic_fips::VALIDATION_STATEMENT));
            Ok(out)
        }

        "selftest" => {
            let report = ops::selftest_json(pos.get(1).copied())?;
            if want_json {
                return Ok(report.to_string());
            }
            match report.get("outcomes") {
                Some(Json::Array(outcomes)) => {
                    let mut out = String::new();
                    for o in outcomes {
                        out.push_str(&format!(
                            "  {} {}\n",
                            if o.get("passed").and_then(|p| p.as_bool()).unwrap_or(false) {
                                "PASS"
                            } else {
                                "FAIL"
                            },
                            o.get("algorithm").and_then(|a| a.as_str()).unwrap_or("?")
                        ));
                    }
                    out.push_str(&format!(
                        "\n{} passed, {} failed; integrity check {}",
                        report.get("passed").and_then(|p| p.as_i64()).unwrap_or(0),
                        report.get("failed").and_then(|f| f.as_i64()).unwrap_or(0),
                        if report
                            .get("integrityCheck")
                            .and_then(|i| i.as_bool())
                            .unwrap_or(false)
                        {
                            "passed"
                        } else {
                            "FAILED"
                        }
                    ));
                    Ok(out)
                }
                _ => Ok(report.to_string()),
            }
        }

        "key" => {
            let sub = pos.get(1).copied().unwrap_or("");
            if sub != "inspect" {
                return Err("usage: ic key inspect".to_string());
            }
            let data = read_stdin()?;
            let json = ops::key_json(&data)?;
            Ok(if want_json {
                json.to_string()
            } else {
                let get = |k: &str| {
                    json.get(k)
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string()
                };
                let mut out = String::new();
                out.push_str(&format!("{} {} key\n", get("algorithm"), get("kind")));
                out.push_str(&format!("  container:  {}\n", get("container")));
                if let Some(label) = json.get("pemLabel").and_then(|v| v.as_str()) {
                    out.push_str(&format!("  pem label:  {label}\n"));
                }
                if let Some(bits) = json.get("bits").and_then(|v| v.as_i64()) {
                    out.push_str(&format!("  size:       {bits} bits\n"));
                }
                if let Some(e) = json.get("publicExponent").and_then(|v| v.as_i64()) {
                    out.push_str(&format!("  exponent:   {e}\n"));
                }
                if let Some(oid) = json.get("oid").and_then(|v| v.as_str()) {
                    out.push_str(&format!("  oid:        {oid}\n"));
                }
                if let Some(id) = json.get("ontologyId").and_then(|v| v.as_str()) {
                    out.push_str(&format!("  ontology:   {id}\n"));
                    out.push_str(&format!("  explain:    ic ontology show {id}\n"));
                }
                out.trim_end().to_string()
            })
        }

        "digest" => {
            let algorithm = pos.get(1).copied().ok_or("digest needs an algorithm")?;
            let data = read_stdin()?;
            let hex = ops::digest_hex(algorithm, &data)?;
            Ok(if want_json {
                Json::object([
                    ("algorithm", Json::str(algorithm)),
                    ("digest", Json::str(hex)),
                ])
                .to_string()
            } else {
                hex
            })
        }

        "hmac" => {
            let algorithm = pos.get(1).copied().ok_or("hmac needs an algorithm")?;
            let key_hex = pos.get(2).copied().ok_or("hmac needs a hex key")?;
            let key =
                ic_core::codec::unhex(key_hex).map_err(|e| format!("key must be hex: {e}"))?;
            let data = read_stdin()?;
            let hex = ops::hmac_hex(algorithm, &key, &data)?;
            Ok(if want_json {
                Json::object([("algorithm", Json::str(algorithm)), ("tag", Json::str(hex))])
                    .to_string()
            } else {
                hex
            })
        }

        "seal" => {
            let algorithm = pos.get(1).copied().ok_or("seal needs an algorithm")?;
            let key = ic_core::codec::unhex(pos.get(2).copied().ok_or("seal needs a hex key")?)
                .map_err(|e| format!("key must be hex: {e}"))?;
            let nonce = ic_core::codec::unhex(pos.get(3).copied().ok_or("seal needs a hex nonce")?)
                .map_err(|e| format!("nonce must be hex: {e}"))?;
            let aad = match pos.get(4).copied() {
                Some(text) => {
                    ic_core::codec::unhex(text).map_err(|e| format!("aad must be hex: {e}"))?
                }
                None => Vec::new(),
            };
            let plaintext = read_stdin()?;
            let (ct, tag) = ops::seal_hex(algorithm, &key, &nonce, &aad, &plaintext)?;
            Ok(if want_json {
                Json::object([
                    ("algorithm", Json::str(algorithm)),
                    ("ciphertext", Json::str(ct)),
                    ("tag", Json::str(tag)),
                ])
                .to_string()
            } else {
                format!(
                    "{ct}
{tag}"
                )
            })
        }

        "random" => {
            let n: usize = pos
                .get(1)
                .copied()
                .ok_or("random needs a byte count")?
                .parse()
                .map_err(|_| "byte count must be a number".to_string())?;
            let hex = ops::random_hex(n)?;
            Ok(if want_json {
                Json::object([("bytes", Json::num(n as f64)), ("hex", Json::str(hex))]).to_string()
            } else {
                hex
            })
        }

        "mcp" => {
            mcp::serve().map_err(|e| format!("mcp server: {e}"))?;
            Ok(String::new())
        }

        other => Err(format!("unknown command '{other}'\n\n{USAGE}")),
    }
}

fn render_recommendation(r: &Json) -> String {
    let s = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("");
    match s("status") {
        "ok" => {
            let mut out = format!("use: {}\n  {}\n", s("recommended"), s("rationale"));
            out.push_str(&format!("  call: {}\n", s("rustPath")));
            if let Some(Json::Array(items)) = r.get("mustObserve") {
                if !items.is_empty() {
                    out.push_str("\nmust observe:\n");
                    for c in items {
                        out.push_str(&format!(
                            "  [{}] {}\n      {}\n",
                            c.get("severity").and_then(|v| v.as_str()).unwrap_or(""),
                            c.get("requirement").and_then(|v| v.as_str()).unwrap_or(""),
                            c.get("consequence").and_then(|v| v.as_str()).unwrap_or("")
                        ));
                    }
                }
            }
            if let Some(Json::Array(items)) = r.get("rejected") {
                if !items.is_empty() {
                    out.push_str("\nconsidered and rejected:\n");
                    for x in items {
                        out.push_str(&format!(
                            "  {}: {}\n",
                            x.get("id").and_then(|v| v.as_str()).unwrap_or(""),
                            x.get("reason").and_then(|v| v.as_str()).unwrap_or("")
                        ));
                    }
                }
            }
            out
        }
        "unavailable" => format!(
            "no recommendation.\n\nThe correct algorithm for this request is {}, which is not \
             implemented in this build.\n{}\n\n{}",
            s("correctAnswer"),
            s("explanation"),
            s("notes")
        ),
        _ => format!("no recommendation.\n{}", s("explanation")),
    }
}

/// Render one framework control for a human.
fn render_control(c: &Json) -> String {
    let g = |k: &str| c.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let mut out = String::new();
    out.push_str(&format!("{}  {}\n", g("id"), g("title")));
    out.push_str(&format!("  {}\n\n", g("frameworkName")));
    out.push_str(&format!("{}\n\n", g("description")));
    out.push_str(&format!("Bearing on this library\n  {}\n", g("bearing")));

    let comp = c.get("compliance").unwrap();
    let cg = |k: &str| comp.get(k).and_then(|v| v.as_str()).unwrap_or("");
    out.push_str(&format!("\nStatus: {}\n", cg("state")));
    match cg("state") {
        "met" => out.push_str(&format!(
            "  Evidence: {} in {}\n",
            cg("evidence"),
            cg("file")
        )),
        "partial" => out.push_str(&format!(
            "  Evidence: {} in {}\n  Gap: {}\n",
            cg("evidence"),
            cg("file"),
            cg("gap")
        )),
        _ => out.push_str(&format!("  Reason: {}\n", cg("reason"))),
    }

    for (label, key) in [("Algorithms", "algorithms"), ("Standards", "standards")] {
        if let Some(items) = c.get(key).and_then(|v| v.as_array()) {
            if !items.is_empty() {
                let names: Vec<&str> = items.iter().filter_map(|v| v.as_str()).collect();
                out.push_str(&format!("\n{label}: {}\n", names.join(", ")));
            }
        }
    }
    out
}

/// Render one standard for a human.
///
/// Requirements are shown with their compliance state and, where met, the file
/// that evidences it — so a reader can go and look rather than take the word of
/// this tool.
fn render_standard(d: &Json) -> String {
    let get = |k: &str| d.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let mut out = String::new();
    out.push_str(&format!(
        "{}  {}
",
        get("id"),
        get("title")
    ));
    out.push_str(&format!(
        "  {} / {} / {}
  {}

",
        get("body"),
        d.get("year")
            .and_then(|v| v.as_f64())
            .map(|y| (y as u32).to_string())
            .unwrap_or_default(),
        get("status"),
        get("url")
    ));
    out.push_str(&format!(
        "{}
",
        get("summary")
    ));

    if let Some(algs) = d.get("algorithms").and_then(|v| v.as_array()) {
        if !algs.is_empty() {
            let names: Vec<&str> = algs.iter().filter_map(|a| a.as_str()).collect();
            out.push_str(&format!(
                "
Defines: {}
",
                names.join(", ")
            ));
        }
    }

    if let Some(reqs) = d.get("requirements").and_then(|v| v.as_array()) {
        if !reqs.is_empty() {
            out.push_str(
                "
Requirements
",
            );
            for r in reqs {
                let rg = |k: &str| r.get(k).and_then(|v| v.as_str()).unwrap_or("");
                let c = r.get("compliance").unwrap();
                let cg = |k: &str| c.get(k).and_then(|v| v.as_str()).unwrap_or("");
                out.push_str(&format!(
                    "
  [{}] {} ({} {})
    {}
    Why: {}
",
                    cg("state"),
                    rg("id"),
                    rg("obligation"),
                    format_args!("§{}", rg("section")),
                    rg("statement"),
                    rg("rationale"),
                ));
                match cg("state") {
                    "met" => out.push_str(&format!(
                        "    Evidence: {} in {}\n",
                        cg("evidence"),
                        cg("file")
                    )),
                    // A partial answer is the one worth reading closely, so it
                    // shows both what is there and what is not.
                    "partial" => out.push_str(&format!(
                        "    Evidence: {} in {}\n    Gap: {}\n",
                        cg("evidence"),
                        cg("file"),
                        cg("gap")
                    )),
                    _ => out.push_str(&format!("    Reason: {}\n", cg("reason"))),
                }
            }
        }
    }
    out
}

fn render_entry(e: &ic_ontology::Entry) -> String {
    let mut out = format!("{} ({})\n{}\n\n", e.name, e.id, e.summary);
    out.push_str(&format!("  class:      {}\n", e.class.id()));
    out.push_str(&format!("  family:     {}\n", e.family));
    out.push_str(&format!(
        "  purposes:   {}\n",
        e.purposes
            .iter()
            .map(|p| p.id())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    out.push_str(&format!(
        "  strength:   {} bits classical, {} bits quantum\n",
        e.strength.classical, e.strength.quantum
    ));
    out.push_str(&format!("  fips:       {}\n", e.fips.id()));
    out.push_str(&format!("  status:     {}\n", e.status.id()));
    out.push_str(&format!("  standards:  {}\n", e.standards.join(", ")));
    if !e.rust_path.is_empty() {
        out.push_str(&format!("  call:       {}\n", e.rust_path));
    }

    if !e.params.is_empty() {
        out.push_str("\nparameters:\n");
        for p in e.params {
            out.push_str(&format!(
                "  {:<14} {}..{} {} (recommended {})\n      {}\n",
                p.name,
                p.min,
                if p.max == u64::MAX {
                    "unbounded".to_string()
                } else {
                    p.max.to_string()
                },
                p.unit.id(),
                p.recommended,
                p.note
            ));
        }
    }

    if !e.constraints.is_empty() {
        out.push_str("\nconstraints:\n");
        for c in e.constraints {
            out.push_str(&format!(
                "  [{}] {}\n      {}\n",
                c.severity.id(),
                c.requirement,
                c.consequence
            ));
        }
    }

    if !e.edges.is_empty() {
        out.push_str("\nrelations:\n");
        for edge in e.edges {
            out.push_str(&format!("  {} {}\n", edge.relation.id(), edge.target));
        }
    }

    if !e.example.is_empty() {
        out.push_str(&format!(
            "\nexample:\n  {}\n",
            e.example.replace('\n', "\n  ")
        ));
    }
    if !e.notes.is_empty() {
        out.push_str(&format!("\nnotes:\n  {}\n", e.notes));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_and_version_are_available() {
        assert!(run(&[]).unwrap().contains("USAGE"));
        assert!(run(&["--help"]).unwrap().contains("USAGE"));
        assert!(run(&["version"]).unwrap().contains("ic"));
        assert!(run(&["--version"]).unwrap().contains("ontology"));
    }

    #[test]
    fn unknown_commands_fail_with_guidance() {
        let err = run(&["frobnicate"]).unwrap_err();
        assert!(err.contains("unknown command"));
        assert!(err.contains("USAGE"));
    }

    #[test]
    fn recommend_renders_both_shapes() {
        let human = run(&["recommend", "encrypt-message", "--fips"]).unwrap();
        assert!(human.contains("aes-256-gcm"));
        assert!(human.contains("must observe"));

        let machine = run(&["recommend", "encrypt-message", "--fips", "--json"]).unwrap();
        let parsed = ic_json::parse(&machine).unwrap();
        assert_eq!(
            parsed.get("recommended").unwrap().as_str(),
            Some("aes-256-gcm")
        );
    }

    #[test]
    fn recommend_declines_rather_than_substituting() {
        // With an approved implementation present, the FIPS policy selects it.
        let out = run(&["recommend", "sign-data", "--fips"]).unwrap();
        assert!(out.contains("use: ecdsa-p256-sha256"));
        assert!(!out.contains("use: ed25519"));

        // Post-quantum key agreement now answers, rather than declining: this
        // used to assert "no recommendation" because ML-KEM-768 was not
        // vector-tested, and it is checked against ACVP now.
        let out = run(&["recommend", "agree-key", "--post-quantum"]).unwrap();
        assert!(out.contains("use: ml-kem-768"), "{out}");
        assert!(!out.contains("use: x25519"), "{out}");
        // The hybrid advice has to come with it.
        assert!(out.contains("hybrid"), "{out}");
    }

    #[test]
    fn ontology_list_filters() {
        let all = run(&["ontology", "list"]).unwrap();
        assert!(all.contains("aes-256-gcm"));
        assert!(
            all.contains("sha-1"),
            "the registry lists broken algorithms too"
        );

        let approved = run(&["ontology", "list", "--class", "aead", "--fips"]).unwrap();
        assert!(approved.contains("aes-256-gcm"));
        assert!(!approved.contains("chacha20-poly1305"));

        assert!(run(&["ontology", "list", "--class", "bogus"]).is_err());
    }

    #[test]
    fn ontology_show_renders_constraints_and_examples() {
        let out = run(&["ontology", "show", "aes-256-gcm"]).unwrap();
        assert!(out.contains("critical"));
        assert!(out.contains("Never reuse"));
        assert!(out.contains("ic_cipher::Aes256Gcm"));

        // Aliases resolve too.
        assert!(run(&["ontology", "show", "SHA-256"])
            .unwrap()
            .contains("sha2-256"));
        assert!(run(&["ontology", "show", "nope"]).is_err());
    }

    #[test]
    fn ontology_export_produces_every_format() {
        assert!(run(&["ontology", "export", "json"])
            .unwrap()
            .starts_with('{'));
        assert!(run(&["ontology", "export", "jsonld"])
            .unwrap()
            .contains("@context"));
        assert!(run(&["ontology", "export", "turtle"])
            .unwrap()
            .starts_with("@prefix"));
        assert!(run(&["ontology", "export", "schema"])
            .unwrap()
            .contains("$schema"));
        assert!(run(&["ontology", "export", "markdown"])
            .unwrap()
            .contains('|'));
        assert!(run(&["ontology", "export", "yaml"]).is_err());
    }

    /// The schema the ontology publishes must accept the JSON it publishes.
    ///
    /// Not a tautology: the two are generated by different functions, and for a
    /// while they disagreed. `ImplStatus::Experimental` was added, the schema's
    /// `implementationStatus` enum was a string literal nobody updated, and the
    /// published schema rejected the four entries carrying that status -- the
    /// unverified ones, which are precisely the entries a consumer validating
    /// against the schema most needs to see.
    ///
    /// The validator below covers only the keywords this schema uses. It
    /// *reports* any keyword it does not recognise rather than passing over it,
    /// because a validator that silently skips the interesting construct is the
    /// same failure in a new place.
    #[test]
    fn the_published_schema_accepts_the_published_json() {
        use std::collections::BTreeMap;

        let schema = ic_json::parse(&run(&["ontology", "export", "schema"]).unwrap()).unwrap();
        let data = ic_json::parse(&run(&["ontology", "export", "json"]).unwrap()).unwrap();

        let defs: &BTreeMap<String, Json> = match schema.get("$defs") {
            Some(Json::Object(m)) => m,
            _ => panic!("the schema has no $defs"),
        };

        // Counted so the assertions at the end can tell "everything passed"
        // apart from "nothing was looked at".
        struct Check<'a> {
            defs: &'a BTreeMap<String, Json>,
            errors: Vec<String>,
            unknown: Vec<String>,
            enums_checked: usize,
            values_checked: usize,
            patterns_checked: usize,
            bounds_checked: usize,
        }

        impl Check<'_> {
            fn visit(&mut self, node: &Json, value: &Json, path: &str) {
                // Free function rather than a method: resolving borrows the
                // `$defs` map, and a method would hold a borrow of `self` for
                // as long as the resolved node lives.
                fn resolve<'b>(defs: &'b BTreeMap<String, Json>, node: &'b Json) -> &'b Json {
                    match node.get("$ref").and_then(Json::as_str) {
                        Some(r) => {
                            let name = r.strip_prefix("#/$defs/").expect("unsupported $ref form");
                            defs.get(name).expect("dangling $ref")
                        }
                        None => node,
                    }
                }
                let node = resolve(self.defs, node);
                let Json::Object(keywords) = node else {
                    self.errors
                        .push(format!("{path}: schema node is not an object"));
                    return;
                };
                self.values_checked += 1;

                for key in keywords.keys() {
                    const KNOWN: &[&str] = &[
                        "type",
                        "properties",
                        "required",
                        "items",
                        "enum",
                        "minItems",
                        "$ref",
                        "$schema",
                        "$id",
                        "title",
                        "description",
                        "additionalProperties",
                        "pattern",
                        "minimum",
                        "format",
                        // Where the subschemas live, not a constraint on the
                        // instance; `$ref` above is what consumes it.
                        "$defs",
                    ];
                    if !KNOWN.contains(&key.as_str()) && !self.unknown.contains(key) {
                        self.unknown.push(key.clone());
                    }
                }

                if let Some(t) = node.get("type").and_then(Json::as_str) {
                    let ok = match t {
                        "object" => matches!(value, Json::Object(_)),
                        "array" => matches!(value, Json::Array(_)),
                        "string" => matches!(value, Json::String(_)),
                        "boolean" => matches!(value, Json::Bool(_)),
                        // This parser holds every number as f64; "integer"
                        // means the value must have no fractional part.
                        "integer" => matches!(value, Json::Number(n) if n.fract() == 0.0),
                        "number" => matches!(value, Json::Number(_)),
                        other => {
                            self.errors
                                .push(format!("{path}: unsupported type {other:?}"));
                            return;
                        }
                    };
                    if !ok {
                        self.errors
                            .push(format!("{path}: value does not match type {t:?}"));
                        return;
                    }
                }

                if let Some(pattern) = node.get("pattern").and_then(Json::as_str) {
                    self.patterns_checked += 1;
                    let text = value.as_str().unwrap_or_default();
                    if !matches_pattern(pattern, text) {
                        self.errors
                            .push(format!("{path}: {text:?} does not match /{pattern}/"));
                    }
                }

                if let Some(min) = node.get("minimum").and_then(Json::as_i64) {
                    self.bounds_checked += 1;
                    if let Json::Number(n) = value {
                        if *n < min as f64 {
                            self.errors
                                .push(format!("{path}: {n} is below minimum {min}"));
                        }
                    }
                }

                if let Some(fmt) = node.get("format").and_then(Json::as_str) {
                    let text = value.as_str().unwrap_or_default();
                    match fmt {
                        // Enough to catch a relative reference or empty string
                        // where an absolute IRI was promised, which is what a
                        // consumer resolving the vocabulary would trip over.
                        "uri" => {
                            let absolute = text.split_once(':').is_some_and(|(scheme, rest)| {
                                !scheme.is_empty()
                                    && scheme
                                        .chars()
                                        .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c))
                                    && scheme
                                        .chars()
                                        .next()
                                        .is_some_and(|c| c.is_ascii_alphabetic())
                                    && !rest.is_empty()
                            });
                            if !absolute {
                                self.errors
                                    .push(format!("{path}: {text:?} is not an absolute URI"));
                            }
                        }
                        other => self
                            .errors
                            .push(format!("{path}: unsupported format {other:?}")),
                    }
                }

                if let Some(Json::Array(allowed)) = node.get("enum") {
                    self.enums_checked += 1;
                    if !allowed.iter().any(|a| a == value) {
                        let names: Vec<&str> = allowed.iter().filter_map(Json::as_str).collect();
                        let got = value.as_str().unwrap_or("<non-string>");
                        self.errors
                            .push(format!("{path}: {got:?} is not one of {names:?}"));
                    }
                }

                if let Json::Object(fields) = value {
                    if let Some(Json::Array(required)) = node.get("required") {
                        for name in required.iter().filter_map(Json::as_str) {
                            if !fields.contains_key(name) {
                                self.errors
                                    .push(format!("{path}: missing required {name:?}"));
                            }
                        }
                    }
                    if let Some(Json::Object(props)) = node.get("properties") {
                        for (name, sub) in props {
                            if let Some(v) = fields.get(name) {
                                self.visit(sub, v, &format!("{path}.{name}"));
                            }
                        }
                    }
                }

                if let Json::Array(items) = value {
                    if let Some(min) = node.get("minItems").and_then(Json::as_i64) {
                        if (items.len() as i64) < min {
                            self.errors
                                .push(format!("{path}: {} items, minimum {min}", items.len()));
                        }
                    }
                    if let Some(item) = node.get("items") {
                        for (i, v) in items.iter().enumerate() {
                            self.visit(item, v, &format!("{path}[{i}]"));
                        }
                    }
                }
            }
        }

        /// Just enough regular expression for the one pattern this schema
        /// uses: anchors, character classes with ranges, and `*`.
        ///
        /// Anything outside that grammar panics rather than returning `false`,
        /// so a future pattern gets a loud failure instead of a silent pass.
        fn matches_pattern(pattern: &str, text: &str) -> bool {
            let pattern = pattern
                .strip_prefix('^')
                .and_then(|p| p.strip_suffix('$'))
                .expect("only fully anchored patterns are supported");

            // Parse into (class, repeated) terms.
            let mut terms: Vec<(Vec<(char, char)>, bool)> = Vec::new();
            let mut chars = pattern.chars().peekable();
            while let Some(c) = chars.next() {
                let class = if c == '[' {
                    // The body is collected before it is parsed, because `-`
                    // is a range only between two members: in `[a-z0-9._-]` the
                    // last one is a literal hyphen, and deciding that needs to
                    // see what follows it.
                    let mut body = Vec::new();
                    loop {
                        let ch = chars.next().expect("unterminated character class");
                        if ch == ']' {
                            break;
                        }
                        assert!(ch != '^', "negated classes are not supported");
                        assert!(ch != '\\', "escapes in classes are not supported");
                        body.push(ch);
                    }
                    let mut ranges = Vec::new();
                    let mut i = 0;
                    while i < body.len() {
                        if i + 2 < body.len() && body[i + 1] == '-' {
                            ranges.push((body[i], body[i + 2]));
                            i += 3;
                        } else {
                            ranges.push((body[i], body[i]));
                            i += 1;
                        }
                    }
                    ranges
                } else {
                    assert!(
                        !"()|+?{}\\.".contains(c),
                        "pattern uses unsupported syntax: {c:?}"
                    );
                    vec![(c, c)]
                };
                let repeated = chars.peek() == Some(&'*');
                if repeated {
                    chars.next();
                }
                terms.push((class, repeated));
            }

            fn matches(terms: &[(Vec<(char, char)>, bool)], text: &[char]) -> bool {
                let Some(((class, repeated), rest)) = terms.split_first() else {
                    return text.is_empty();
                };
                let hit = |c: char| class.iter().any(|(lo, hi)| c >= *lo && c <= *hi);
                if *repeated {
                    // Backtracking: try every prefix this term could consume.
                    let mut taken = 0;
                    loop {
                        if matches(rest, &text[taken..]) {
                            return true;
                        }
                        if taken < text.len() && hit(text[taken]) {
                            taken += 1;
                        } else {
                            return false;
                        }
                    }
                } else {
                    !text.is_empty() && hit(text[0]) && matches(rest, &text[1..])
                }
            }

            matches(&terms, &text.chars().collect::<Vec<_>>())
        }

        // The matcher is small enough to be wrong quietly, so it is pinned to
        // cases with known answers before anything is validated with it.
        assert!(matches_pattern("^[a-z0-9][a-z0-9._-]*$", "aes-256-gcm"));
        assert!(matches_pattern("^[a-z0-9][a-z0-9._-]*$", "a"));
        assert!(!matches_pattern("^[a-z0-9][a-z0-9._-]*$", ""));
        assert!(!matches_pattern("^[a-z0-9][a-z0-9._-]*$", "-leading"));
        assert!(!matches_pattern("^[a-z0-9][a-z0-9._-]*$", "Upper"));
        assert!(!matches_pattern("^[a-z0-9][a-z0-9._-]*$", "has space"));

        let mut check = Check {
            defs,
            errors: Vec::new(),
            unknown: Vec::new(),
            enums_checked: 0,
            values_checked: 0,
            patterns_checked: 0,
            bounds_checked: 0,
        };
        check.visit(&schema, &data, "$");

        assert!(
            check.errors.is_empty(),
            "the published schema rejects the published JSON:\n  {}",
            check.errors.join("\n  ")
        );
        assert!(
            check.unknown.is_empty(),
            "the schema uses keywords this validator ignores, so it proved less \
             than it appears to: {:?}",
            check.unknown
        );

        // Floors. Without these the test passes just as happily against an
        // empty registry or a schema that constrains nothing, which is the
        // failure it exists to catch.
        assert!(
            check.values_checked > 500,
            "only {} values validated; the walk did not reach the entries",
            check.values_checked
        );
        assert!(
            check.enums_checked > 200,
            "only {} enum values checked; the stale-enum case is what this is for",
            check.enums_checked
        );
        assert!(
            check.patterns_checked > 50,
            "only {} identifiers matched against the id pattern",
            check.patterns_checked
        );
        assert!(
            check.bounds_checked > 50,
            "only {} numeric bounds checked",
            check.bounds_checked
        );
    }

    #[test]
    fn exported_json_parses() {
        let text = run(&["ontology", "export", "json"]).unwrap();
        let parsed = ic_json::parse(&text).unwrap();
        match parsed.get("algorithms").unwrap() {
            Json::Array(items) => assert_eq!(items.len(), ic_ontology::all().len()),
            _ => panic!("expected an array"),
        }
    }

    #[test]
    fn selftest_reports_results() {
        let out = run(&["selftest"]).unwrap();
        assert!(out.contains("PASS sha2-256"));
        assert!(out.contains("0 failed"));
        assert!(out.contains("integrity check passed"));

        let one = run(&["selftest", "aes-256-gcm", "--json"]).unwrap();
        assert!(ic_json::parse(&one)
            .unwrap()
            .get("passed")
            .unwrap()
            .as_bool()
            .unwrap());
    }

    #[test]
    fn capabilities_is_honest_in_both_shapes() {
        let human = run(&["capabilities"]).unwrap();
        assert!(human.contains("[ ] fips-validated"));
        assert!(human.contains("[x] zero-dependencies"));
        assert!(human.contains("NOT been submitted"));

        let machine = run(&["capabilities", "--json"]).unwrap();
        assert!(ic_json::parse(&machine).is_ok());
    }

    #[test]
    fn errors_command_lists_the_vocabulary() {
        let out = run(&["ontology", "errors"]).unwrap();
        assert!(out.contains("authentication-failed"));
        assert!(out.contains("→"));
    }

    #[test]
    fn seal_requires_its_arguments() {
        assert!(run(&["seal"]).is_err());
        assert!(run(&["seal", "aes-256-gcm"]).is_err());
        assert!(run(&["seal", "aes-256-gcm", "not-hex", "00"]).is_err());
    }

    #[test]
    fn random_produces_the_requested_length() {
        let out = run(&["random", "16"]).unwrap();
        assert_eq!(out.len(), 32);
        assert!(run(&["random", "abc"]).is_err());
        assert!(run(&["random"]).is_err());
    }

    /// Every flag read with `opt` must be listed as value-taking.
    ///
    /// Reads this file's own source, because the failure it prevents is one of
    /// omission: the code compiles, the flag works, and only the positional
    /// parsing quietly goes wrong. That is exactly what happened when
    /// `--iterations` was added, and `--iterations 60000` reported "unknown
    /// target '60000'".
    #[test]
    fn every_valued_flag_is_declared() {
        let source = include_str!("main.rs");
        let mut found: Vec<&str> = Vec::new();
        let needle = "opt(args, \"";
        let mut rest = source;
        while let Some(at) = rest.find(needle) {
            rest = &rest[at + needle.len()..];
            if let Some(end) = rest.find('"') {
                let flag = &rest[..end];
                if flag.starts_with("--") && !found.contains(&flag) {
                    found.push(flag);
                }
            }
        }
        assert!(
            found.len() >= 5,
            "the scan found only {} flags, which suggests it stopped matching: {found:?}",
            found.len()
        );
        for flag in &found {
            assert!(
                VALUED_FLAGS.contains(flag),
                "{flag} takes a value but is not in VALUED_FLAGS, so its value will be parsed                  as a positional argument"
            );
        }
        // And nothing declared that is never read, which would be dead config.
        for flag in VALUED_FLAGS {
            assert!(
                found.contains(flag),
                "{flag} is declared value-taking but nothing reads it"
            );
        }
    }

    #[test]
    fn option_parsing_handles_flags_and_values() {
        let args = ["ontology", "list", "--class", "aead", "--fips", "--json"];
        assert_eq!(opt(&args, "--class"), Some("aead"));
        assert_eq!(opt(&args, "--purpose"), None);
        assert!(has_flag(&args, "--fips"));
        assert!(!has_flag(&args, "--available"));
        assert_eq!(positionals(&args), vec!["ontology", "list"]);
    }

    /// A flag immediately followed by another flag must not swallow it as a
    /// value.
    #[test]
    fn a_flag_is_not_mistaken_for_an_option_value() {
        let args = ["ontology", "list", "--class", "--fips"];
        assert_eq!(opt(&args, "--class"), None);
    }
}
