//! `docs/FIPS.md` must agree with the registry about what is verified.
//!
//! That document is where `SECURITY.md` sends anyone asking "what is checked,
//! and against what oracle". It is the project's evidence record, and until
//! this test existed it was the last compliance surface with nothing tying it
//! to the code — prose beside an implementation, free to drift.
//!
//! It had already drifted. ML-DSA-65 was registered `experimental` and shipped
//! without a provenance row, so the document quietly described a library with
//! two unverified algorithms when there were three. Nothing failed, because
//! nothing was checking.
//!
//! # What is checked, and why only this
//!
//! Every entry the registry marks `Experimental` must appear in the provenance
//! table, in a row that says it is not vector-tested.
//!
//! That is deliberately narrower than "every algorithm has a row". The table is
//! organised by family — one row covers SHA-2, SHA-3 and SHAKE together — so a
//! per-entry rule would either produce fifty false failures or need matching
//! loose enough to pass on anything. `Experimental` is the status that makes
//! the strongest claim about *missing* verification, there are only a handful,
//! and they are exactly what a reader opening this document needs to find.
//!
//! The converse is checked too: a row may not describe something as not
//! vector-tested when the registry says it is available. Promote an algorithm
//! and forget the document, or vice versa, and this fails either way round.

use ic_ontology::{ImplStatus, REGISTRY};
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

/// One row of the provenance table: its label and its evidence cell.
struct Row {
    label: String,
    evidence: String,
}

fn provenance_rows() -> Vec<Row> {
    let text = std::fs::read_to_string(workspace_root().join("docs/FIPS.md"))
        .expect("docs/FIPS.md must be readable");
    let mut rows = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if !line.starts_with('|') || line.matches('|').count() < 3 {
            continue;
        }
        let cells: Vec<&str> = line.split('|').map(str::trim).collect();
        let (label, evidence) = (cells[1], cells[2]);
        // Skip the header and the `|---|---|` separator.
        if label.is_empty()
            || label.chars().all(|c| c == '-' || c == ':' || c == ' ')
            || label.eq_ignore_ascii_case("algorithm family")
        {
            continue;
        }
        rows.push(Row {
            label: label.to_ascii_lowercase(),
            evidence: evidence.to_ascii_lowercase(),
        });
    }
    rows
}

/// Reduce a label to letters, dropping key sizes and separators.
///
/// `AES-256-GCM-SIV` and the table's `AES-GCM-SIV` are the same thing with a
/// key size inserted in the middle, so neither contains the other as a
/// substring. Stripping the digits and punctuation makes both `aesgcmsiv`, and
/// comparing the results for equality keeps `AES-256-GCM-SIV` from matching the
/// bare `AES` row — which is what a substring test does, and how the first
/// version of this got the wrong answer.
fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Whether a row's label names this entry.
///
/// A label may list several algorithms, so it is split on commas first.
fn names(row: &Row, name: &str) -> bool {
    let wanted = normalize(name);
    row.label.split(',').any(|part| normalize(part) == wanted)
}

/// Every experimental algorithm must be recorded as not vector-tested.
#[test]
fn experimental_algorithms_are_recorded_as_unverified() {
    let rows = provenance_rows();
    assert!(
        rows.len() >= 25,
        "only {} provenance rows parsed, which suggests the parser broke rather than that \
         the table shrank",
        rows.len()
    );

    // The registry has to have been read at all, which is what an empty
    // `experimental` list below cannot tell us on its own.
    assert!(
        REGISTRY.len() > 50,
        "only {} registry entries; the registry did not load",
        REGISTRY.len()
    );

    let experimental: Vec<_> = REGISTRY
        .iter()
        .filter(|e| e.status == ImplStatus::Experimental)
        .collect();

    // Currently none, and that is the goal state rather than a broken query:
    // every algorithm here has been checked against values produced by
    // something other than itself. This used to assert the list was non-empty,
    // which was right while three entries carried the status and became wrong
    // when the last one was promoted.
    //
    // The loop below is what matters, and it starts working again the moment an
    // entry is registered experimental.
    if experimental.is_empty() {
        return;
    }

    for e in experimental {
        let matched: Vec<&Row> = rows.iter().filter(|r| names(r, e.name)).collect();
        assert!(
            !matched.is_empty(),
            "{} is registered experimental but has no row in docs/FIPS.md. That document is \
             where SECURITY.md sends people to find out what is verified; an unverified \
             algorithm missing from it is the one case that matters most.",
            e.id
        );
        assert!(
            matched
                .iter()
                .any(|r| r.evidence.contains("not vector-tested")
                    || r.evidence.contains("no published vector")),
            "{} is registered experimental, but its row in docs/FIPS.md does not say it is \
             not vector-tested",
            e.id
        );
    }
}

/// Nothing available may be described as unverified, or the reverse.
#[test]
fn available_algorithms_are_not_described_as_unverified() {
    let rows = provenance_rows();
    for row in rows
        .iter()
        .filter(|r| r.evidence.contains("not vector-tested"))
    {
        for e in REGISTRY
            .iter()
            .filter(|e| e.status == ImplStatus::Available)
        {
            // Normalized equality, not substring: `AES-256-GCM-SIV` and
            // `AES-256-GCM` differ by three letters, and a substring test would
            // report the first being unverified as a claim about the second.
            let label_names_it = names(row, e.name);
            assert!(
                !label_names_it,
                "docs/FIPS.md describes {} as not vector-tested, but the registry marks it \
                 available. One of the two is wrong.",
                e.id
            );
        }
    }
}

/// The document must keep saying the module is not validated.
///
/// The same rule the ontology and the frameworks knowledgebase are held to,
/// applied to the document a reader is most likely to quote from.
#[test]
fn the_document_does_not_claim_validation() {
    let text = std::fs::read_to_string(workspace_root().join("docs/FIPS.md"))
        .expect("docs/FIPS.md must be readable");
    let lower = text.to_ascii_lowercase();
    assert!(
        lower.contains("not a fips-validated cryptographic module"),
        "the document must state plainly that this is not a validated module"
    );
    assert!(
        lower.contains("holds no certificate number"),
        "it must say there is no certificate"
    );
    assert!(
        !ic_ontology::runtime::has("fips-validated"),
        "the runtime capability must agree with the document"
    );
}
