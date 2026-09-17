//! Source-level guards on the shape of the public API.
//!
//! These read the crates' own source rather than calling into them, which is
//! unusual for a test and is the point: some properties are about how an API
//! can be *misused*, and a test that only calls it correctly will never notice.
//!
//! The one that matters is `#[must_use]`. Before this existed the whole library
//! had exactly one, and `ic_core::ct::verify` — the constant-time comparison
//! every tag and signature check funnels through — was not it. Writing
//! `ct::verify(expected, actual);` compiled cleanly and discarded the answer.
//! Nothing in a conventional test suite catches that, because the bug is in
//! code nobody has written yet.
//!
//! There was a second guard here, grepping for `std::` outside a feature gate
//! to protect the `no_std` builds. It is gone, and deliberately so: CI already
//! cross-compiles the facade for three embedded targets, which is a compiler
//! proving the property rather than a regular expression approximating it. The
//! grep's first act was to report a false positive on a correctly gated
//! `/dev/urandom` reader. A weaker check that also cries wolf earns nothing.

use std::path::{Path, PathBuf};

/// The crates that implement cryptography, as opposed to describing it.
///
/// The ontology and CLI crates are excluded on purpose: their predicates are
/// metadata questions, and a discarded answer there is a nuisance rather than a
/// vulnerability.
const CRYPTO_CRATES: &[&str] = &[
    "ic-core",
    "ic-cipher",
    "ic-mac",
    "ic-ec",
    "ic-rsa",
    "ic-mldsa",
    "ic-mlkem",
    "ic-pkix",
    "ic-kdf",
    "ic-drbg",
    "ic-hash",
];

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

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Every public function returning a bare `bool` must be `#[must_use]`.
///
/// A discarded predicate is always a bug. A discarded *security decision* is a
/// vulnerability, and the two are not distinguishable by looking at the type,
/// which is why the rule is universal rather than a judgement call made once
/// per function and then forgotten.
///
/// Only the code before `#[cfg(test)]` is examined: test helpers are not API.
#[test]
fn public_predicates_cannot_be_ignored() {
    let root = workspace_root();
    let mut offenders: Vec<String> = Vec::new();
    let mut checked = 0;

    for crate_name in CRYPTO_CRATES {
        let src = root.join("crates").join(crate_name).join("src");
        assert!(src.is_dir(), "{crate_name} has no src directory");
        let mut files = Vec::new();
        rust_files(&src, &mut files);
        assert!(!files.is_empty(), "{crate_name} has no Rust files");

        for file in files {
            let text = std::fs::read_to_string(&file).expect("readable source");
            let lines: Vec<&str> = text.lines().collect();
            // Anything from the first `#[cfg(test)]` onwards is not API.
            let cut = lines
                .iter()
                .position(|l| l.trim() == "#[cfg(test)]")
                .unwrap_or(lines.len());

            for (i, line) in lines.iter().enumerate().take(cut) {
                let trimmed = line.trim_start();
                if !trimmed.starts_with("pub fn ") && !trimmed.starts_with("pub const fn ") {
                    continue;
                }
                // Gather the signature: keep going until a line ends the
                // declaration. Testing for a bare ';' stops early on `[u8; N]`,
                // which is most of this library's signatures.
                let mut blob = String::from(*line);
                let mut j = i;
                while !blob.trim_end().ends_with('{')
                    && !blob.trim_end().ends_with(';')
                    && j + 1 < lines.len()
                {
                    j += 1;
                    blob.push('\n');
                    blob.push_str(lines[j]);
                }
                let returns_bool = blob.contains("-> bool {") || blob.contains("-> bool;");
                if !returns_bool {
                    continue;
                }
                checked += 1;

                let has_attr = (i.saturating_sub(3)..i)
                    .any(|k| lines.get(k).is_some_and(|l| l.contains("must_use")));
                if !has_attr {
                    let name = trimmed
                        .trim_start_matches("pub const fn ")
                        .trim_start_matches("pub fn ")
                        .split('(')
                        .next()
                        .unwrap_or("?");
                    offenders.push(format!(
                        "{}:{} {}",
                        file.strip_prefix(&root).unwrap_or(&file).display(),
                        i + 1,
                        name
                    ));
                }
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "these public predicates can be silently ignored; add #[must_use]:\n  {}",
        offenders.join("\n  ")
    );
    // If the scanner ever stops finding signatures — a formatting change, a
    // refactor — it would pass by examining nothing.
    assert!(
        checked >= 15,
        "the scanner found only {checked} bool-returning functions, which suggests it \
         has stopped matching rather than that they have gone away"
    );
}
