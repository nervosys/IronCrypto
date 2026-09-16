//! Serializing the ontology for consumption outside Rust.
//!
//! Four formats, because agents arrive through different doors:
//!
//! | format | consumer |
//! |---|---|
//! | [`to_json`] | an LLM tool call, a CI check, `jq` |
//! | [`to_json_ld`] | a knowledge graph or RDF triple store |
//! | [`to_turtle`] | a SPARQL endpoint or an OWL reasoner |
//! | [`to_json_schema`] | a validator, or a tool-use schema generator |
//!
//! The writers are hand-rolled rather than derived from `serde`, which keeps
//! the whole workspace dependency-free. They are only ever fed static registry
//! data, but they still escape properly — [`escape_json`] is exercised directly
//! by the tests so that a future entry containing a quote or newline cannot
//! produce malformed output.

use crate::registry::REGISTRY;
use crate::types::{Class, Entry, Purpose};

/// The vocabulary IRI that JSON-LD and Turtle exports resolve terms against.
pub const VOCAB: &str = "https://nervosys.github.io/AgenticCrypto/ontology#";

/// Escape a string for inclusion in a JSON document.
pub fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

fn json_string_array(items: impl Iterator<Item = String>) -> String {
    let mut out = String::from("[");
    for (i, item) in items.enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('"');
        out.push_str(&item);
        out.push('"');
    }
    out.push(']');
    out
}

/// Render one entry as a JSON object.
pub fn entry_to_json(e: &Entry) -> String {
    let mut out = String::new();
    out.push('{');
    out.push_str(&format!(r#""id":"{}","#, escape_json(e.id)));
    out.push_str(&format!(r#""name":"{}","#, escape_json(e.name)));
    out.push_str(&format!(r#""summary":"{}","#, escape_json(e.summary)));
    out.push_str(&format!(r#""class":"{}","#, e.class.id()));
    out.push_str(&format!(r#""family":"{}","#, escape_json(e.family)));
    out.push_str(&format!(r#""fipsStatus":"{}","#, e.fips.id()));
    out.push_str(&format!(r#""implementationStatus":"{}","#, e.status.id()));
    out.push_str(&format!(r#""performance":"{}","#, e.performance.id()));
    out.push_str(&format!(
        r#""approvedModeUsable":{},"#,
        e.approved_mode_ok()
    ));
    out.push_str(&format!(
        r#""strength":{{"classicalBits":{},"quantumBits":{}}},"#,
        e.strength.classical, e.strength.quantum
    ));
    out.push_str(&format!(
        r#""aliases":{},"#,
        json_string_array(e.aliases.iter().map(|a| escape_json(a)))
    ));
    out.push_str(&format!(
        r#""purposes":{},"#,
        json_string_array(e.purposes.iter().map(|p| p.id().to_string()))
    ));
    out.push_str(&format!(
        r#""standards":{},"#,
        json_string_array(e.standards.iter().map(|s| escape_json(s)))
    ));

    out.push_str(r#""parameters":["#);
    for (i, p) in e.params.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            r#"{{"name":"{}","unit":"{}","min":{},"max":{},"recommended":{},"note":"{}"}}"#,
            escape_json(p.name),
            p.unit.id(),
            p.min,
            p.max,
            p.recommended,
            escape_json(p.note)
        ));
    }
    out.push_str("],");

    out.push_str(r#""constraints":["#);
    for (i, c) in e.constraints.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            r#"{{"id":"{}","severity":"{}","requirement":"{}","consequence":"{}"}}"#,
            escape_json(c.id),
            c.severity.id(),
            escape_json(c.requirement),
            escape_json(c.consequence)
        ));
    }
    out.push_str("],");

    out.push_str(r#""relations":["#);
    for (i, edge) in e.edges.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            r#"{{"relation":"{}","target":"{}"}}"#,
            edge.relation.id(),
            escape_json(edge.target)
        ));
    }
    out.push_str("],");

    out.push_str(&format!(r#""rustPath":"{}","#, escape_json(e.rust_path)));
    out.push_str(&format!(r#""example":"{}","#, escape_json(e.example)));
    out.push_str(&format!(r#""notes":"{}""#, escape_json(e.notes)));
    out.push('}');
    out
}

/// The whole registry as a JSON document.
pub fn to_json() -> String {
    let mut out = String::from("{\"version\":\"");
    out.push_str(env!("CARGO_PKG_VERSION"));
    out.push_str("\",\"vocabulary\":\"");
    out.push_str(VOCAB);
    out.push_str("\",\"algorithms\":[");
    for (i, e) in REGISTRY.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&entry_to_json(e));
    }
    out.push_str("]}");
    out
}

/// The registry as JSON-LD, for loading into a knowledge graph.
///
/// The `@context` maps every ontology term onto the [`VOCAB`] IRI and declares
/// the relation properties as `@id` references, so a triple store resolves
/// `built-on` into a real edge rather than a literal string.
pub fn to_json_ld() -> String {
    let mut out = String::from("{\"@context\":{");
    out.push_str(&format!(r#""@vocab":"{VOCAB}","#));
    out.push_str(r#""id":"@id","#);
    out.push_str(r#""algorithms":{"@id":"member","@container":"@set"},"#);
    out.push_str(r#""target":{"@type":"@id"},"#);
    out.push_str(r#""class":{"@type":"@vocab"},"#);
    out.push_str(r#""purposes":{"@type":"@vocab","@container":"@set"},"#);
    out.push_str(r#""fipsStatus":{"@type":"@vocab"}"#);
    out.push_str("},\"@type\":\"AlgorithmRegistry\",\"algorithms\":[");
    for (i, e) in REGISTRY.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let body = entry_to_json(e);
        // Splice in the node type after the opening brace.
        out.push('{');
        out.push_str("\"@type\":\"Algorithm\",");
        out.push_str(&body[1..]);
    }
    out.push_str("]}");
    out
}

/// The registry as RDF 1.1 Turtle.
///
/// Emitted so the ontology can be loaded into a SPARQL endpoint or reasoned
/// over with OWL tooling, which is the usual meaning of "ontology" outside the
/// Rust world.
pub fn to_turtle() -> String {
    let mut out = String::new();
    out.push_str(&format!("@prefix ac: <{VOCAB}> .\n"));
    out.push_str("@prefix rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> .\n");
    out.push_str("@prefix rdfs: <http://www.w3.org/2000/01/rdf-schema#> .\n");
    out.push_str("@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n\n");

    // Class hierarchy.
    out.push_str("ac:Algorithm a rdfs:Class ;\n    rdfs:label \"Cryptographic algorithm\" .\n\n");
    for c in Class::ALL {
        out.push_str(&format!(
            "ac:{} a rdfs:Class ;\n    rdfs:subClassOf ac:Algorithm .\n",
            term(c.id())
        ));
    }
    out.push('\n');
    for p in Purpose::ALL {
        out.push_str(&format!(
            "ac:{} a ac:Purpose ;\n    rdfs:label \"{}\" .\n",
            term(p.id()),
            p.id()
        ));
    }
    out.push('\n');

    for e in REGISTRY {
        out.push_str(&format!(
            "ac:{} a ac:{} ;\n",
            term(e.id),
            term(e.class.id())
        ));
        out.push_str(&format!("    rdfs:label \"{}\" ;\n", escape_json(e.name)));
        out.push_str(&format!(
            "    rdfs:comment \"{}\" ;\n",
            escape_json(e.summary)
        ));
        out.push_str(&format!("    ac:family \"{}\" ;\n", escape_json(e.family)));
        out.push_str(&format!("    ac:fipsStatus ac:{} ;\n", term(e.fips.id())));
        out.push_str(&format!(
            "    ac:implementationStatus ac:{} ;\n",
            term(e.status.id())
        ));
        out.push_str(&format!(
            "    ac:classicalBits \"{}\"^^xsd:integer ;\n",
            e.strength.classical
        ));
        out.push_str(&format!(
            "    ac:quantumBits \"{}\"^^xsd:integer ",
            e.strength.quantum
        ));
        for p in e.purposes {
            out.push_str(&format!(";\n    ac:servesPurpose ac:{} ", term(p.id())));
        }
        for edge in e.edges {
            out.push_str(&format!(
                ";\n    ac:{} ac:{} ",
                term(edge.relation.id()),
                term(edge.target)
            ));
        }
        out.push_str(".\n\n");
    }
    out
}

/// Convert a kebab-case identifier into a Turtle-safe camel-ish local name.
fn term(id: &str) -> String {
    let mut out = String::with_capacity(id.len());
    let mut upper_next = false;
    for c in id.chars() {
        match c {
            '-' | '.' | '/' => upper_next = true,
            c if upper_next => {
                out.extend(c.to_uppercase());
                upper_next = false;
            }
            c => out.push(c),
        }
    }
    out
}

/// A JSON Schema describing the shape of [`to_json`] output.
///
/// Emitted so an agent framework can validate ontology documents, and so a
/// tool-use schema can be generated from the same source of truth the library
/// uses at runtime.
pub fn to_json_schema() -> String {
    let classes = json_string_array(Class::ALL.iter().map(|c| c.id().to_string()));
    let purposes = json_string_array(Purpose::ALL.iter().map(|p| p.id().to_string()));
    format!(
        r##"{{"$schema":"https://json-schema.org/draft/2020-12/schema",
"$id":"{VOCAB}schema.json",
"title":"AgenticCrypto algorithm registry",
"type":"object",
"required":["version","algorithms"],
"properties":{{
 "version":{{"type":"string"}},
 "vocabulary":{{"type":"string","format":"uri"}},
 "algorithms":{{"type":"array","items":{{"$ref":"#/$defs/algorithm"}}}}
}},
"$defs":{{
 "algorithm":{{
  "type":"object",
  "required":["id","name","class","purposes","fipsStatus","implementationStatus","strength"],
  "properties":{{
   "id":{{"type":"string","pattern":"^[a-z0-9][a-z0-9._-]*$"}},
   "name":{{"type":"string"}},
   "summary":{{"type":"string"}},
   "class":{{"enum":{classes}}},
   "family":{{"type":"string"}},
   "purposes":{{"type":"array","items":{{"enum":{purposes}}},"minItems":1}},
   "strength":{{"type":"object","required":["classicalBits","quantumBits"],
     "properties":{{"classicalBits":{{"type":"integer","minimum":0}},
                   "quantumBits":{{"type":"integer","minimum":0}}}}}},
   "fipsStatus":{{"enum":["approved","allowed-as-component","not-approved","deprecated","disallowed"]}},
   "implementationStatus":{{"enum":["available","planned","excluded"]}},
   "approvedModeUsable":{{"type":"boolean"}},
   "performance":{{"enum":["fast","moderate","slow","deliberately-slow"]}},
   "aliases":{{"type":"array","items":{{"type":"string"}}}},
   "standards":{{"type":"array","items":{{"type":"string"}}}},
   "parameters":{{"type":"array","items":{{"$ref":"#/$defs/parameter"}}}},
   "constraints":{{"type":"array","items":{{"$ref":"#/$defs/constraint"}}}},
   "relations":{{"type":"array","items":{{"$ref":"#/$defs/relation"}}}},
   "rustPath":{{"type":"string"}},
   "example":{{"type":"string"}},
   "notes":{{"type":"string"}}
  }}
 }},
 "parameter":{{"type":"object","required":["name","unit","min","max"],
  "properties":{{"name":{{"type":"string"}},"unit":{{"enum":["bytes","count"]}},
   "min":{{"type":"integer"}},"max":{{"type":"integer"}},
   "recommended":{{"type":"integer"}},"note":{{"type":"string"}}}}}},
 "constraint":{{"type":"object","required":["id","severity","requirement","consequence"],
  "properties":{{"id":{{"type":"string"}},
   "severity":{{"enum":["critical","serious","advisory"]}},
   "requirement":{{"type":"string"}},"consequence":{{"type":"string"}}}}}},
 "relation":{{"type":"object","required":["relation","target"],
  "properties":{{"relation":{{"enum":["built-on","supersedes","superseded-by","pairs-with","specializes"]}},
   "target":{{"type":"string"}}}}}}
}}}}"##
    )
}

/// A human-readable Markdown table of the registry.
pub fn to_markdown() -> String {
    let mut out = String::from("# AgenticCrypto algorithm registry\n\n");
    out.push_str("| ID | Class | Strength (classical/quantum) | FIPS | Status | Rust path |\n");
    out.push_str("|---|---|---|---|---|---|\n");
    for e in REGISTRY {
        out.push_str(&format!(
            "| `{}` | {} | {}/{} | {} | {} | {} |\n",
            e.id,
            e.class.id(),
            e.strength.classical,
            e.strength.quantum,
            e.fips.id(),
            e.status.id(),
            if e.rust_path.is_empty() {
                "—".to_string()
            } else {
                format!("`{}`", e.rust_path)
            }
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal structural JSON check: balanced braces and brackets outside of
    /// strings, and no unescaped control characters inside them.
    fn json_is_well_formed(s: &str) -> bool {
        let mut depth_obj = 0i32;
        let mut depth_arr = 0i32;
        let mut in_string = false;
        let mut escaped = false;
        for c in s.chars() {
            if in_string {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_string = false;
                } else if (c as u32) < 0x20 {
                    return false;
                }
                continue;
            }
            match c {
                '"' => in_string = true,
                '{' => depth_obj += 1,
                '}' => depth_obj -= 1,
                '[' => depth_arr += 1,
                ']' => depth_arr -= 1,
                _ => {}
            }
            if depth_obj < 0 || depth_arr < 0 {
                return false;
            }
        }
        !in_string && depth_obj == 0 && depth_arr == 0
    }

    #[test]
    fn json_export_is_well_formed() {
        let json = to_json();
        assert!(json_is_well_formed(&json), "malformed JSON");
        assert!(json.contains(r#""id":"aes-256-gcm""#));
        assert!(json.contains(r#""fipsStatus":"approved""#));
    }

    #[test]
    fn json_ld_export_is_well_formed_and_typed() {
        let jsonld = to_json_ld();
        assert!(json_is_well_formed(&jsonld), "malformed JSON-LD");
        assert!(jsonld.contains("\"@context\""));
        assert!(jsonld.contains("\"@type\":\"Algorithm\""));
        assert!(jsonld.contains(VOCAB));
    }

    #[test]
    fn json_schema_is_well_formed() {
        let schema = to_json_schema();
        assert!(json_is_well_formed(&schema), "malformed JSON Schema");
        assert!(schema.contains("\"$defs\""));
        assert!(schema.contains("aead"));
    }

    #[test]
    fn schema_enumerates_every_vocabulary_term() {
        let schema = to_json_schema();
        for c in Class::ALL {
            assert!(schema.contains(c.id()), "schema omits class {}", c.id());
        }
        for p in Purpose::ALL {
            assert!(schema.contains(p.id()), "schema omits purpose {}", p.id());
        }
    }

    #[test]
    fn turtle_export_declares_every_entry() {
        let ttl = to_turtle();
        assert!(ttl.starts_with("@prefix ac:"));
        for e in REGISTRY {
            assert!(
                ttl.contains(&format!("ac:{} a ac:", term(e.id))),
                "turtle omits {}",
                e.id
            );
        }
        // Every statement block must terminate.
        assert!(ttl.matches(" .\n").count() + ttl.matches(".\n\n").count() > 0);
    }

    #[test]
    fn turtle_terms_are_valid_local_names() {
        assert_eq!(term("aes-256-gcm"), "aes256Gcm");
        assert_eq!(term("sha2-512-256"), "sha2512256");
        assert_eq!(term("hash"), "hash");
        for e in REGISTRY {
            let t = term(e.id);
            assert!(
                t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "{} produced an invalid local name {t}",
                e.id
            );
        }
    }

    #[test]
    fn escaping_handles_the_characters_that_break_json() {
        assert_eq!(escape_json(r#"a"b"#), r#"a\"b"#);
        assert_eq!(escape_json("a\\b"), "a\\\\b");
        assert_eq!(escape_json("a\nb"), "a\\nb");
        assert_eq!(escape_json("a\tb"), "a\\tb");
        assert_eq!(escape_json("a\u{1}b"), "a\\u0001b");
        assert_eq!(escape_json("plain"), "plain");
    }

    /// Entries contain newlines in their examples; the export must survive them.
    #[test]
    fn multiline_examples_do_not_break_the_json() {
        let e = crate::query::get("aes-256-gcm").unwrap();
        assert!(e.example.contains('\n'), "test needs a multi-line example");
        let json = entry_to_json(e);
        assert!(json_is_well_formed(&json));
        assert!(!json.contains("\n"), "raw newline leaked into JSON");
    }

    #[test]
    fn markdown_lists_every_entry() {
        let md = to_markdown();
        for e in REGISTRY {
            assert!(md.contains(e.id), "markdown omits {}", e.id);
        }
    }
}
