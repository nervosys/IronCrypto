//! The always-in-force rules, held in agreement wherever they are written.
//!
//! `ic_ontology::RULES` is the list that ships: the MCP server and `ic rules`
//! serve it. `AGENTS.md` is what an agent working in this repository reads, and
//! the `ironcrypto` crate documentation is what one using it from crates.io
//! reads. Three copies drift unless something compares them.

use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    let mut here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    while !(here.join("Cargo.toml").is_file() && here.join("crates").is_dir()) {
        assert!(here.pop(), "workspace root not found");
    }
    here
}

/// Markdown with the emphasis and code marks removed, so `**Never use
/// `==`.**` compares equal to the plain sentence.
fn plain(text: &str) -> String {
    text.replace("**", "").replace('`', "")
}

/// The bulleted list under `heading`, each bullet's lines joined.
fn bullets_under(text: &str, heading: &str, bullet: &str) -> Vec<String> {
    let start = text
        .find(heading)
        .unwrap_or_else(|| panic!("no '{heading}'"));
    let mut out: Vec<String> = Vec::new();
    let mut started = false;
    for line in text[start + heading.len()..].lines() {
        let line = line.trim_start_matches("//!").trim();
        if let Some(rest) = line.strip_prefix(bullet) {
            out.push(rest.to_string());
            started = true;
        } else if started && (line.is_empty() || line.starts_with('#')) {
            break;
        } else if let Some(last) = out.last_mut() {
            last.push(' ');
            last.push_str(line);
        }
    }
    out
}

fn check(name: &str, bullets: &[String]) {
    assert_eq!(
        bullets.len(),
        ic_ontology::RULES.len(),
        "{name} lists {} rules, ic_ontology::RULES has {}: {bullets:#?}",
        bullets.len(),
        ic_ontology::RULES.len()
    );
    for (bullet, rule) in bullets.iter().zip(ic_ontology::RULES) {
        assert!(
            plain(bullet).starts_with(rule.rule),
            "{name}: '{}' should open with the rule '{}', in RULES's order",
            plain(bullet),
            rule.rule
        );
    }
}

#[test]
fn agents_md_lists_the_shipped_rules() {
    let text = std::fs::read_to_string(workspace_root().join("AGENTS.md")).expect("AGENTS.md");
    check(
        "AGENTS.md",
        &bullets_under(&text, "## Rules that are always in force", "- "),
    );
}

#[test]
fn the_crate_documentation_lists_the_shipped_rules() {
    let text = std::fs::read_to_string(workspace_root().join("crates/ironcrypto/src/lib.rs"))
        .expect("lib.rs");
    check(
        "ironcrypto's documentation",
        &bullets_under(&text, "## Rules that hold for every algorithm", "* "),
    );
}
