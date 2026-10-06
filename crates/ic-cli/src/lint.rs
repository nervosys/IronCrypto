//! `ic lint`: find the known ways of misusing this library in Rust source.
//!
//! Each check is a pattern for one rule in `ic_ontology::RULES`, and every
//! finding names its rule. The checks read source text a line at a time; they
//! do not parse Rust or follow values between lines. So a finding is a place to
//! look, which can be wrong, and an empty report means only that none of these
//! patterns matched. The report says so, and lists the rules it cannot check.

use ic_json::Json;
use ic_ontology::{Severity, RULES};

/// One place in the source that matches a misuse pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// 1-based line number.
    pub line: usize,
    /// The `ic_ontology::RULES` id this pattern belongs to.
    pub rule: &'static str,
    /// What was matched, specifically.
    pub message: String,
    /// The line, trimmed.
    pub excerpt: String,
}

/// The rules these checks cover. The rest are listed as unchecked.
pub const CHECKED: &[&str] = &[
    "no-nonce-reuse",
    "no-unauthenticated-mode",
    "no-tag-equality",
    "no-plain-password-hash",
    "no-literal-key",
    "no-raw-os-bytes",
    "no-raw-shared-secret",
];

/// The iteration floor `no-plain-password-hash` names for PBKDF2.
const PBKDF2_MIN_ITERATIONS: u64 = 600_000;

/// The line without a trailing `//` comment. Naive about `//` inside string
/// literals, which costs a missed finding on that line rather than a false one.
fn code_of(line: &str) -> &str {
    match line.find("//") {
        Some(i) => &line[..i],
        None => line,
    }
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The words of an identifier path: `self.expected_tag[..]` gives `self`,
/// `expected`, `tag`.
fn words(expr: &str) -> impl Iterator<Item = String> + '_ {
    expr.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(|w| w.to_ascii_lowercase())
}

fn has_word(expr: &str, any: &[&str]) -> bool {
    words(expr).any(|w| any.contains(&w.as_str()))
}

/// The operand ending just before byte `end`: identifiers, paths, field
/// access, indexing, references and calls, back to the first character that
/// cannot be part of one.
fn operand_before(code: &str, end: usize) -> &str {
    let bytes = code.as_bytes();
    let mut i = end;
    while i > 0 && bytes[i - 1] == b' ' {
        i -= 1;
    }
    let stop = i;
    let mut depth = 0i32;
    while i > 0 {
        let c = bytes[i - 1] as char;
        match c {
            ')' | ']' => depth += 1,
            '(' | '[' if depth > 0 => depth -= 1,
            _ if depth > 0 => {}
            c if is_ident_char(c) || c == '.' || c == ':' || c == '&' || c == '*' => {}
            _ => break,
        }
        i -= 1;
    }
    &code[i..stop]
}

/// The operand starting just after byte `start`.
fn operand_after(code: &str, start: usize) -> &str {
    let bytes = code.as_bytes();
    let mut i = start;
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    let begin = i;
    let mut depth = 0i32;
    while i < bytes.len() {
        let c = bytes[i] as char;
        match c {
            '(' | '[' => depth += 1,
            ')' | ']' if depth > 0 => depth -= 1,
            _ if depth > 0 => {}
            c if is_ident_char(c) || c == '.' || c == ':' || c == '&' || c == '*' => {}
            _ => break,
        }
        i += 1;
    }
    &code[begin..i]
}

/// The arguments of the call whose `(` is at byte `open`, split at depth zero,
/// or `None` if the call does not close on this line.
fn call_args(code: &str, open: usize) -> Option<Vec<&str>> {
    let bytes = code.as_bytes();
    let mut depth = 0i32;
    let mut start = open + 1;
    let mut args = Vec::new();
    for (i, &b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' => {
                depth -= 1;
                if depth == 0 {
                    args.push(code[start..i].trim());
                    return Some(args);
                }
            }
            b',' if depth == 1 => {
                args.push(code[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    None
}

/// A byte-array or byte-string literal: `[0u8; 12]`, `&[1, 2]`, `*b"..."`.
fn is_literal_bytes(expr: &str) -> bool {
    let e = expr.trim().trim_start_matches(['&', '*']).trim_start();
    e.starts_with('[') || e.starts_with("b\"") || e.starts_with("b'")
}

/// The integer a literal like `1_000u32` denotes.
fn integer_literal(expr: &str) -> Option<u64> {
    let e = expr.trim();
    let consumed = e
        .find(|c: char| !(c.is_ascii_digit() || c == '_'))
        .unwrap_or(e.len());
    let digits: String = e[..consumed].chars().filter(|c| *c != '_').collect();
    let rest = &e[consumed..];
    if digits.is_empty() || !(rest.is_empty() || rest.starts_with('u') || rest.starts_with('i')) {
        return None;
    }
    digits.parse().ok()
}

/// Types whose `new` takes a key.
fn is_keyed_type(path: &str) -> bool {
    [
        "Gcm",
        "GcmSiv",
        "ChaCha20Poly1305",
        "Sealer",
        "Opener",
        "Hmac",
        "Cmac",
        "Kmac",
    ]
    .iter()
    .any(|t| path.contains(t))
}

// Not signatures: they are public, so comparing one with == leaks nothing.
const TAG_WORDS: &[&str] = &["tag", "mac", "hmac", "cmac", "digest"];

/// Names that mean a MAC or AEAD is in use in a file.
const MAC_CONTEXT: &[&str] = &[
    "Hmac",
    "Cmac",
    "Kmac",
    "Mac",
    "Aead",
    "Gcm",
    "Poly1305",
    "open_detached",
    "seal_detached",
    "ct::verify",
];

/// Names that mean a file parses an encoding, where "tag" is a type tag. A bare
/// `tag` operand is not reported in such a file unless a MAC is also in use;
/// `mac`, `hmac` and `digest` are reported regardless.
const ENCODING_CONTEXT: &[&str] = &["der::", "Der", "asn1", "Asn1", "peek_tag", "Tag::", "tlv"];
const PASSWORD_WORDS: &[&str] = &["password", "passwd", "pwd", "passphrase", "pin"];
const PLAIN_HASHES: &[&str] = &[
    "Sha224", "Sha256", "Sha384", "Sha512", "Sha3_", "Blake2b", "Shake",
];
const RAW_ENTROPY: &[(&str, &str)] = &[
    ("getrandom", "the getrandom crate or call"),
    ("OsRng", "OsRng"),
    ("/dev/urandom", "/dev/urandom"),
    ("/dev/random", "/dev/random"),
    ("BCryptGenRandom", "BCryptGenRandom"),
    ("ic_core::entropy::fill", "ic_core::entropy::fill"),
    ("thread_rng", "rand::thread_rng"),
];
const SECRET_WORDS: &[&str] = &["shared", "dh", "ecdh", "secret", "premaster"];

/// Check one source text, skipping test code.
///
/// Literal keys and fixed nonces are what known-answer tests are made of, so
/// a `#[cfg(test)]` module -- from its attribute to the end of the file, which
/// is where Rust puts one -- is not checked. [`lint_with`] includes it.
#[cfg(test)]
pub fn lint(source: &str) -> Vec<Finding> {
    lint_with(source, false)
}

/// Check one source text, including test code when `tests` is set.
pub fn lint_with(source: &str, tests: bool) -> Vec<Finding> {
    let mut out = Vec::new();
    let has_mac = ["Hmac", "Cmac", "Kmac", "::verify(", "Mac"]
        .iter()
        .any(|m| source.contains(m));
    let bare_tag_is_a_tag = MAC_CONTEXT.iter().any(|m| source.contains(m))
        || !ENCODING_CONTEXT.iter().any(|m| source.contains(m));

    for (n, raw) in source.lines().enumerate() {
        if !tests && raw.trim_start().starts_with("#[cfg(test)]") {
            break;
        }
        let code = code_of(raw);
        let line = n + 1;
        let mut push = |rule: &'static str, message: String| {
            // One finding per rule per line is enough to send someone there.
            if out
                .last()
                .is_some_and(|f: &Finding| f.line == line && f.rule == rule)
            {
                return;
            }
            out.push(Finding {
                line,
                rule,
                message,
                excerpt: raw.trim().to_string(),
            })
        };

        // no-nonce-reuse: a literal nonce, the first argument of
        // `seal_detached`. (HPKE's `seal_in_place` takes associated data
        // first; its context chooses the nonce.)
        for call in ["seal_detached("] {
            let mut from = 0;
            while let Some(at) = code[from..].find(call) {
                let open = from + at + call.len() - 1;
                if let Some(args) = call_args(code, open) {
                    if args.first().is_some_and(|a| is_literal_bytes(a)) {
                        push(
                            "no-nonce-reuse",
                            format!(
                                "the nonce passed to {} is a literal, so every run reuses it",
                                &call[..call.len() - 1]
                            ),
                        );
                    }
                }
                from = open + 1;
            }
        }

        // no-unauthenticated-mode: CBC or CTR with no MAC anywhere in the file.
        if !has_mac {
            for mode in ["cbc_encrypt", "cbc_decrypt", "ctr_xor"] {
                // A call, not the definition or a re-export.
                let called =
                    code.contains(&format!("{mode}(")) && !code.contains(&format!("fn {mode}"));
                if called {
                    push(
                        "no-unauthenticated-mode",
                        format!("{mode} with no MAC anywhere in this file"),
                    );
                }
            }
        }

        // no-tag-equality: == or != with a tag-like operand.
        let mut from = 0;
        while let Some(at) = code[from..].find(['=', '!']) {
            let i = from + at;
            let op = code.get(i..i + 2);
            let is_cmp = matches!(op, Some("==") | Some("!="))
                && code.get(i + 2..i + 3) != Some("=")
                && (i == 0 || !matches!(code.as_bytes()[i - 1], b'=' | b'<' | b'>' | b'!'));
            if is_cmp {
                let left = operand_before(code, i);
                let right = operand_after(code, i + 2);
                let tagged = |e: &str| {
                    let words: &[&str] = if bare_tag_is_a_tag {
                        TAG_WORDS
                    } else {
                        &TAG_WORDS[1..]
                    };
                    // `peek_tag()` and `der::...` are a parser's type tags.
                    has_word(e, words) && !has_word(e, &["len", "is_empty", "peek", "der", "asn1"])
                };
                if tagged(left) || tagged(right) {
                    push(
                        "no-tag-equality",
                        format!(
                            "'{}' compares a tag with {}; that exits at the first differing byte",
                            format!("{left} {} {right}", op.unwrap_or("==")).trim(),
                            op.unwrap_or("==")
                        ),
                    );
                }
                from = i + 2;
            } else {
                from = i + 1;
            }
        }

        // no-plain-password-hash: a plain hash on a password, or PBKDF2 below
        // the floor.
        let slow_hash = ["pbkdf2", "argon2", "Argon2"]
            .iter()
            .any(|k| code.contains(k));
        if has_word(code, PASSWORD_WORDS)
            && PLAIN_HASHES.iter().any(|h| code.contains(h))
            && !slow_hash
        {
            push(
                "no-plain-password-hash",
                "a password goes through a plain hash".to_string(),
            );
        }
        if let Some(at) = code.find("pbkdf2") {
            if let Some(open) = code[at..].find('(').map(|o| at + o) {
                if let Some(args) = call_args(code, open) {
                    if let Some(n) = args.get(2).and_then(|a| integer_literal(a)) {
                        if n < PBKDF2_MIN_ITERATIONS {
                            push(
                                "no-plain-password-hash",
                                format!("PBKDF2 at {n} iterations, below {PBKDF2_MIN_ITERATIONS}"),
                            );
                        }
                    }
                }
            }
        }

        // no-literal-key: a literal passed where a key goes, or bound to a
        // name that says it is one.
        let mut from = 0;
        while let Some(at) = code[from..].find("::new(") {
            let i = from + at;
            let path = operand_before(code, i);
            if is_keyed_type(path) {
                if let Some(args) = call_args(code, i + "::new".len()) {
                    if args.first().is_some_and(|a| is_literal_bytes(a)) {
                        push(
                            "no-literal-key",
                            format!("the key passed to {path}::new is a literal"),
                        );
                    }
                    // no-raw-shared-secret: a shared secret straight into a
                    // keyed type.
                    if args.first().is_some_and(|a| has_word(a, SECRET_WORDS)) {
                        push(
                            "no-raw-shared-secret",
                            format!(
                                "'{}' looks like a shared secret used directly as the key of {path}",
                                args[0]
                            ),
                        );
                    }
                }
            }
            from = i + 1;
        }
        if let Some(rest) = code.trim_start().strip_prefix("let ") {
            if let Some(eq) = rest.find('=') {
                let (name, value) = (&rest[..eq], &rest[eq + 1..]);
                let name = name.split(':').next().unwrap_or(name);
                if has_word(name, &["key", "secret"])
                    && !has_word(name, &["public", "pk", "pub", "len", "id", "size", "name"])
                    && is_literal_bytes(value)
                    && !is_zero_buffer(value)
                {
                    push(
                        "no-literal-key",
                        format!("'{}' is bound to a literal", name.trim()),
                    );
                }
            }
        }

        // no-raw-os-bytes.
        for (needle, what) in RAW_ENTROPY {
            if code.contains(needle) {
                push(
                    "no-raw-os-bytes",
                    format!("{what} read directly rather than through the DRBG"),
                );
            }
        }
    }
    out
}

/// `[0u8; 32]` and the like: an output buffer about to be filled, which is
/// how a key is drawn or derived, not a literal key.
fn is_zero_buffer(value: &str) -> bool {
    let v = value.trim().trim_end_matches(';').trim();
    let inner = v
        .trim_start_matches("Zeroizing::new(")
        .trim_start_matches("ic_core::Zeroizing::new(")
        .trim_end_matches(')');
    inner.starts_with("[0u8;") || inner.starts_with("[0; ") || inner.starts_with("[0u8 ;")
}

fn severity_of(rule: &str) -> Severity {
    RULES
        .iter()
        .find(|r| r.id == rule)
        .map(|r| r.severity)
        .unwrap_or(Severity::Advisory)
}

/// The report as JSON: findings, what was checked, and what was not.
pub fn report_json(findings: &[(String, Finding)]) -> Json {
    let unchecked: Vec<Json> = RULES
        .iter()
        .filter(|r| !CHECKED.contains(&r.id))
        .map(|r| Json::str(r.id))
        .collect();
    Json::object([
        (
            "findings",
            Json::Array(
                findings
                    .iter()
                    .map(|(file, f)| {
                        Json::object([
                            ("file", Json::str(file.as_str())),
                            ("line", Json::num(f.line as f64)),
                            ("rule", Json::str(f.rule)),
                            ("severity", Json::str(severity_of(f.rule).id())),
                            ("message", Json::str(f.message.as_str())),
                            ("excerpt", Json::str(f.excerpt.as_str())),
                        ])
                    })
                    .collect(),
            ),
        ),
        (
            "checked",
            Json::Array(CHECKED.iter().map(|r| Json::str(*r)).collect()),
        ),
        ("unchecked", Json::Array(unchecked)),
        ("caveat", Json::str(CAVEAT)),
    ])
}

/// What a clean report does and does not mean.
pub const CAVEAT: &str = "These checks match source text a line at a time. A finding is a place \
     to look and can be wrong; no findings means none of these patterns matched, not that the \
     code is correct.";

/// The report as text.
pub fn report_text(findings: &[(String, Finding)]) -> String {
    let mut out = String::new();
    for (file, f) in findings {
        out.push_str(&format!(
            "{file}:{}: [{}] {}: {}\n    {}\n",
            f.line,
            severity_of(f.rule).id(),
            f.rule,
            f.message,
            f.excerpt
        ));
    }
    let unchecked: Vec<&str> = RULES
        .iter()
        .filter(|r| !CHECKED.contains(&r.id))
        .map(|r| r.id)
        .collect();
    out.push_str(&format!(
        "{} finding{}. Not checked: {}.\n{CAVEAT}",
        findings.len(),
        if findings.len() == 1 { "" } else { "s" },
        if unchecked.is_empty() {
            "none".to_string()
        } else {
            unchecked.join(", ")
        }
    ));
    out
}

/// Lint every `.rs` file under `path`, skipping `tests/` and `benches/`
/// directories and `#[cfg(test)]` modules unless `tests` is set.
pub fn lint_path(path: &std::path::Path, tests: bool) -> Result<Vec<(String, Finding)>, String> {
    let mut files = Vec::new();
    collect(path, tests, &mut files)?;
    if files.is_empty() {
        return Err(format!("no .rs files under {}", path.display()));
    }
    let mut out = Vec::new();
    for file in files {
        let text =
            std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
        for f in lint_with(&text, tests) {
            out.push((file.display().to_string(), f));
        }
    }
    Ok(out)
}

fn collect(
    path: &std::path::Path,
    tests: bool,
    out: &mut Vec<std::path::PathBuf>,
) -> Result<(), String> {
    if path.is_file() {
        out.push(path.to_path_buf());
        return Ok(());
    }
    let entries = std::fs::read_dir(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut entries: Vec<_> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    entries.sort();
    for p in entries {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let skipped = name.starts_with('.')
            || name == "target"
            || (!tests && (name == "tests" || name == "benches"));
        if p.is_dir() && !skipped {
            collect(&p, tests, out)?;
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules_hit(src: &str) -> Vec<&'static str> {
        lint(src).into_iter().map(|f| f.rule).collect()
    }

    /// Every pattern, on code that commits it.
    #[test]
    fn each_misuse_is_found() {
        let cases: &[(&str, &str)] = &[
            ("c.seal_detached(&[0u8; 12], aad, &mut buf, &mut tag)?;", "no-nonce-reuse"),
            ("c.seal_detached(b\"fixed nonce!\", aad, &mut buf, &mut tag)?;", "no-nonce-reuse"),
            ("let ct = ic_cipher::cbc_encrypt(&aes, &iv, &mut buf)?;", "no-unauthenticated-mode"),
            ("if tag == expected { return true; }", "no-tag-equality"),
            ("if computed_mac != mac { bail!() }", "no-tag-equality"),
            ("return &self.expected_tag[..] == &received[..];", "no-tag-equality"),
            ("let h = Sha256::digest(password.as_bytes());", "no-plain-password-hash"),
            ("ic_kdf::pbkdf2::<HmacSha256>(pw, &salt, 10_000, &mut out)?;", "no-plain-password-hash"),
            ("let c = Aes256Gcm::new(&[0x2a; 32])?;", "no-literal-key"),
            ("let key = *b\"0123456789abcdef0123456789abcdef\";", "no-literal-key"),
            ("let secret_key: [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];", "no-literal-key"),
            ("getrandom::getrandom(&mut key)?;", "no-raw-os-bytes"),
            ("let mut rng = OsRng;", "no-raw-os-bytes"),
            ("ic_core::entropy::fill(&mut key)?;", "no-raw-os-bytes"),
            ("let c = ChaCha20Poly1305::new(&shared_secret)?;", "no-raw-shared-secret"),
        ];
        for (src, rule) in cases {
            assert!(
                rules_hit(src).contains(rule),
                "'{src}' should be found as {rule}; found {:?}",
                rules_hit(src)
            );
        }
    }

    /// The correct forms of the same operations, and things that look alike.
    #[test]
    fn correct_code_is_left_alone() {
        let clean = r#"
use ironcrypto::prelude::*;
fn session(shared: &[u8], our_pk: &[u8], their_pk: &[u8]) -> Result<()> {
    let mut rng = Rng::from_os()?;
    let mut key = Zeroizing::new([0u8; 32]);
    rng.fill(&mut *key)?;
    let mut derived = [0u8; 32];
    Hkdf::<HmacSha256>::derive(shared, b"salt", their_pk, &mut derived)?;
    let mut tx = Sealer::<Aes256Gcm>::new(&*key, *b"c->s")?;
    let nonce = tx.seal(b"aad", &mut buf, &mut tag)?;
    ic_core::ct::verify(&expected_tag, &tag)?;
    if tag.len() == 16 { }
    if tags_seen == 3 { }
    let stage = 2; if stage == 2 { }
    let message = b"x"; if message == b"x" { }
    ic_kdf::pbkdf2::<HmacSha256>(password, &salt, 600_000, &mut out)?;
    let public_key = [4u8; 65];
    let key_len = 32;
    c.seal_detached(&nonce, aad, &mut buf, &mut tag)?; // a literal nonce here: &[0u8; 12]
    let hash = Sha256::digest(document);
    Ok(())
}
"#;
        let found = lint(clean);
        assert!(found.is_empty(), "false positives: {found:#?}");
    }

    /// The false positives a run over this repository turned up.
    #[test]
    fn lookalikes_from_real_code_are_left_alone() {
        // HPKE's first argument is associated data.
        assert!(rules_hit("tx.seal_in_place(b\"\", &mut m, &mut tag)?;").is_empty());
        // A DER tag, in a file that parses DER and has no MAC in it.
        assert!(
            rules_hit("use crate::der::Reader;\nensure!(actual == tag, Malformed, \"x\");")
                .is_empty()
        );
        // The same comparison with a MAC in the file is reported.
        assert!(!rules_hit("use crate::der::Reader; use Hmac;\nif actual == tag {}").is_empty());
        // A DER peek, even where the file also uses a MAC.
        assert!(rules_hit("use Hmac;\nif seq.peek_tag() == Some(der::context(0)) {}").is_empty());
        // A re-export or definition of an unauthenticated mode is not a use.
        assert!(rules_hit("pub use modes::{cbc_encrypt, ctr_xor};").is_empty());
        assert!(rules_hit("pub fn ctr_xor<C>(c: &C, iv: &[u8], d: &mut [u8]) {}").is_empty());
        // Signatures are public.
        assert!(rules_hit("let c = Hmac::new(k)?; if bad == good_sig {}").is_empty());
    }

    #[test]
    fn a_line_reports_each_rule_once() {
        let f = lint("let c = cbc_encrypt(a, b, c)?; let d = cbc_decrypt(a, b, c)?;");
        assert_eq!(f.len(), 1, "{f:#?}");
    }

    #[test]
    fn test_code_is_skipped_unless_asked_for() {
        let src = "fn f() {}\n#[cfg(test)]\nmod tests { let c = Aes256Gcm::new(&[1; 32]); }";
        assert!(lint(src).is_empty());
        assert_eq!(lint_with(src, true).len(), 1);
    }

    #[test]
    fn cbc_is_accepted_where_the_file_authenticates() {
        let src =
            "let ct = cbc_encrypt(&aes, &iv, &mut buf)?;\nlet t = HmacSha256::mac(&mk, &ct)?;";
        assert!(rules_hit(src).is_empty());
    }

    #[test]
    fn every_checked_id_is_a_rule_and_findings_name_them() {
        for id in CHECKED {
            assert!(RULES.iter().any(|r| r.id == *id), "{id} is not in RULES");
        }
    }

    #[test]
    fn the_report_states_its_limits() {
        let text = report_text(&[]);
        assert!(
            text.contains("0 findings") && text.contains("wrap-secrets") && text.contains(CAVEAT)
        );
        let json = report_json(&[]);
        assert!(json.get("caveat").is_some());
        assert_eq!(
            json.get("unchecked")
                .and_then(|u| u.as_array())
                .map(|a| a.len()),
            Some(RULES.len() - CHECKED.len())
        );
    }
}
