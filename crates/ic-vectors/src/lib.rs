//! Loading test vectors that are not in the repository.
//!
//! Two algorithms here are registered `experimental` rather than `available`
//! for one reason: nobody has checked them against values produced by something
//! other than themselves. ML-KEM-768 and AES-GCM-SIV have every component
//! verified against an independent oracle and their assembly verified against
//! nothing, because no ACVP or RFC vector is wired in.
//!
//! That gap is not a code problem. It is a *files* problem, and this crate
//! exists so that closing it needs no code at all: drop a vector file in the
//! right place and the tests start checking against it. Without one they skip,
//! loudly enough to be visible and quietly enough not to fail a build that was
//! never promised the file.
//!
//! # Where the files go
//!
//! `testvectors/<name>.json`, relative to the workspace root, or wherever
//! `IC_TEST_VECTORS` points. The format is deliberately not raw ACVP:
//!
//! ```json
//! {
//!   "algorithm": "aes-kw",
//!   "source": "RFC 3394 section 4.1",
//!   "cases": [
//!     { "key": "000102...", "pt": "001122...", "ct": "1fa68b..." }
//!   ]
//! }
//! ```
//!
//! Every field is a hex string, and which fields a case needs is up to the test
//! reading it. ACVP's own files nest differently per algorithm and carry a
//! great deal that is irrelevant here, so converting is a few lines of `jq`
//! rather than a parser this crate has to keep up with. `testvectors/README.md`
//! records the mapping for each algorithm that wants one.
//!
//! # Why the skip is loud
//!
//! A test that silently passes when its input is missing is worse than no test:
//! it reports success for work nobody did. [`VectorFile::load`] returns `None`
//! and the callers print what they were looking for, so an absent file shows up
//! in the output rather than in nothing at all.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

use ic_json::Json;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// A loaded vector file.
pub struct VectorFile {
    /// What the file says it is for.
    pub algorithm: String,
    /// Where the vectors came from, for the record.
    pub source: String,
    /// The cases, each a map of field name to raw hex string.
    pub cases: Vec<BTreeMap<String, String>>,
    /// Where the file was found.
    pub path: PathBuf,
}

/// The directory vector files are read from.
///
/// `IC_TEST_VECTORS` if set, otherwise `testvectors/` beside the workspace
/// manifest. Tests run with the crate directory as the working directory, so
/// the fallback walks up until it finds the workspace root.
pub fn vectors_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("IC_TEST_VECTORS") {
        return PathBuf::from(dir);
    }
    // CARGO_MANIFEST_DIR is the crate being tested; the workspace root is one
    // or two levels up depending on layout, so look for the marker.
    let mut here = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    for _ in 0..4 {
        let candidate = here.join("testvectors");
        if candidate.is_dir() {
            return candidate;
        }
        if !here.pop() {
            break;
        }
    }
    PathBuf::from("testvectors")
}

impl VectorFile {
    /// Load `testvectors/<name>.json`, or `None` if it is not there.
    ///
    /// A malformed file is an error rather than a miss: someone went to the
    /// trouble of providing it, and silently ignoring it would waste their
    /// effort in the most confusing way available.
    pub fn load(name: &str) -> Option<VectorFile> {
        Self::load_from(&vectors_dir(), name)
    }

    /// [`load`](Self::load), reading from a directory the caller names.
    ///
    /// Exists so the tests can point at a directory of their own rather than
    /// setting `IC_TEST_VECTORS` -- cargo runs a crate's tests as threads in
    /// one process, so mutating the environment races every sibling that reads
    /// it.
    pub fn load_from(dir: &std::path::Path, name: &str) -> Option<VectorFile> {
        let path = dir.join(format!("{name}.json"));
        let text = std::fs::read_to_string(&path).ok()?;
        let parsed = ic_json::parse(&text)
            .unwrap_or_else(|e| panic!("{} is present but not valid JSON: {e}", path.display()));

        // Both are required of a file that exists. `source` used to fall back to
        // the string "unrecorded", so a file with no provenance loaded and its
        // values went on to validate an implementation, with the report
        // printing "unrecorded" where the citation belongs.
        //
        // The point of this crate is that ML-KEM-768 and AES-GCM-SIV stop being
        // `experimental` when someone drops a file in here. `experimental`
        // means nothing has checked them against values produced by something
        // other than themselves, and a file of unknown origin does not close
        // that -- it hides it. A missing citation belongs with the other ways a
        // present file can be malformed, all of which already panic.
        let algorithm = parsed
            .get("algorithm")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| panic!("{} does not say which algorithm it is for", path.display()))
            .to_string();
        let source = parsed
            .get("source")
            .and_then(|v| v.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| {
                panic!(
                    "{} does not cite where its values came from. A vector whose \
                     provenance is unknown cannot establish that an implementation \
                     interoperates, which is the only reason to have one.",
                    path.display()
                )
            })
            .to_string();

        let raw = match parsed.get("cases") {
            Some(Json::Array(items)) => items.clone(),
            _ => panic!("{} has no \"cases\" array", path.display()),
        };

        let mut cases = Vec::new();
        for (index, item) in raw.iter().enumerate() {
            let Json::Object(fields) = item else {
                panic!("{}: case {index} is not an object", path.display());
            };
            let mut case = BTreeMap::new();
            for (key, value) in fields {
                if let Some(text) = value.as_str() {
                    case.insert(key.clone(), text.to_string());
                }
            }
            cases.push(case);
        }

        Some(VectorFile {
            algorithm,
            source,
            cases,
            path,
        })
    }

    /// Load, or print why nothing was checked and return `None`.
    ///
    /// The message is the point. A skipped vector test should be visible in the
    /// output of `cargo test -- --nocapture`, not inferred from its absence.
    pub fn load_or_report(name: &str) -> Option<VectorFile> {
        match Self::load(name) {
            Some(file) => {
                println!(
                    "vectors: {} cases for {} from {} ({})",
                    file.cases.len(),
                    file.algorithm,
                    file.source,
                    file.path.display()
                );
                Some(file)
            }
            None => {
                println!(
                    "vectors: SKIPPED {name} -- no file at {}. \
                     See testvectors/README.md.",
                    vectors_dir().join(format!("{name}.json")).display()
                );
                None
            }
        }
    }
}

/// Decode a hex field from a case, panicking with the field name on failure.
///
/// Tests are the caller, so a bad field is a broken input file and should stop
/// the run with something readable rather than return an error nobody handles.
pub fn hex_field(case: &BTreeMap<String, String>, name: &str) -> Vec<u8> {
    let text = case
        .get(name)
        .unwrap_or_else(|| panic!("a case is missing the field {name:?}"));
    unhex(text).unwrap_or_else(|| panic!("field {name:?} is not valid hex: {text:?}"))
}

/// An optional hex field.
pub fn optional_hex_field(case: &BTreeMap<String, String>, name: &str) -> Option<Vec<u8>> {
    case.get(name).map(|text| {
        unhex(text).unwrap_or_else(|| panic!("field {name:?} is not valid hex: {text:?}"))
    })
}

/// Decode a hex string, tolerating whitespace and either case.
fn unhex(text: &str) -> Option<Vec<u8>> {
    let cleaned: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if cleaned.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for pair in cleaned.chunks(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Render bytes as lowercase hex, for comparison messages.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decoding_is_forgiving_about_layout_and_strict_about_content() {
        assert_eq!(unhex("00ff").unwrap(), vec![0x00, 0xff]);
        assert_eq!(unhex("00FF").unwrap(), vec![0x00, 0xff]);
        assert_eq!(unhex("00 ff\n").unwrap(), vec![0x00, 0xff]);
        assert_eq!(unhex("").unwrap(), Vec::<u8>::new());
        assert!(unhex("0").is_none(), "odd length");
        assert!(unhex("zz").is_none(), "not hex");
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00u8, 0x0f, 0xa5, 0xff];
        assert_eq!(unhex(&hex(&bytes)).unwrap(), bytes);
    }

    /// A missing file is a miss, not a failure. This is the behaviour the whole
    /// design rests on, so it is asserted rather than assumed.
    /// A file that is present must cite its source, and one that does not must
    /// fail loudly rather than load.
    ///
    /// `source` used to fall back to the string "unrecorded", so a file with no
    /// provenance loaded and its values went on to validate an implementation.
    /// That matters here more than it would elsewhere: this crate is how
    /// ML-KEM-768 and AES-GCM-SIV are meant to stop being `experimental`, and
    /// `experimental` means exactly that nothing has checked them against
    /// values produced by something other than themselves. A file of unknown
    /// origin does not close that gap, it conceals it.
    ///
    /// Absent stays `None`: skipping loudly is the documented behaviour and is
    /// a different situation from a file that is there and incomplete.
    #[test]
    fn a_vector_file_without_provenance_is_refused() {
        // Under the workspace's own target directory, not the system temp
        // directory. cargo already requires target/ to be writable, and
        // .gitignore already covers it.
        //
        // This test has been flaky three times, each from depending on
        // something outside itself: a process-wide environment variable that
        // raced its sibling tests, a name built from the process id that
        // collided with leftovers after Windows recycled it, and a subdirectory
        // of %LOCALAPPDATA%\Temp that the user could create and then not write
        // to, because that directory grants the user no inheritable rights on
        // this machine. Nothing ambient is left.
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        // `vectors_dir()` already locates the workspace root by looking for
        // the `testvectors` marker, so its parent is the root.
        let root = vectors_dir()
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        let dir = root
            .join("target")
            .join("ic-vectors-tests")
            .join(format!("{}-{unique}", std::process::id()));

        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)
            .unwrap_or_else(|e| panic!("could not create {}: {e}", dir.display()));

        let write = |name: &str, body: &str| {
            let path = dir.join(format!("{name}.json"));
            std::fs::write(&path, body)
                .unwrap_or_else(|e| panic!("could not write {}: {e}", path.display()));
        };

        // Present and properly cited: loads, and carries the citation through.
        write(
            "cited",
            r#"{"algorithm":"aes-kw","source":"RFC 3394 section 4.1",
                "cases":[{"key":"00","pt":"11","ct":"22"}]}"#,
        );
        let file = VectorFile::load_from(&dir, "cited").expect("a cited file must load");
        assert_eq!(file.source, "RFC 3394 section 4.1");
        assert_eq!(file.algorithm, "aes-kw");
        assert_eq!(file.cases.len(), 1);

        // Absent: none, and no panic. This is the skip path.
        assert!(VectorFile::load_from(&dir, "no-such-file").is_none());

        // Present with no source, and present with an empty one. Both are a
        // file someone meant to be used, without the one thing that makes it
        // usable.
        for (name, body) in [
            (
                "uncited",
                r#"{"algorithm":"aes-kw","cases":[{"key":"00"}]}"#,
            ),
            (
                "blank-source",
                r#"{"algorithm":"aes-kw","source":"   ","cases":[{"key":"00"}]}"#,
            ),
            ("unnamed", r#"{"source":"RFC 3394","cases":[{"key":"00"}]}"#),
        ] {
            write(name, body);
            let outcome = std::panic::catch_unwind(|| VectorFile::load_from(&dir, name));
            assert!(
                outcome.is_err(),
                "{name} loaded despite not saying where its values came from"
            );
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_absent_file_is_none() {
        assert!(VectorFile::load("a-name-no-file-will-ever-have").is_none());
    }

    /// The bundled RFC 3394 file must load, which is what proves the plumbing
    /// works rather than merely compiling.
    #[test]
    fn the_bundled_key_wrap_vectors_load() {
        let file =
            VectorFile::load("aes-kw").expect("testvectors/aes-kw.json is in the repository");
        assert_eq!(file.algorithm, "aes-kw");
        assert!(
            file.source.contains("3394"),
            "the source should be recorded"
        );
        assert_eq!(file.cases.len(), 6, "RFC 3394 publishes six");
        for case in &file.cases {
            assert!(!hex_field(case, "key").is_empty());
            assert!(!hex_field(case, "pt").is_empty());
            assert!(!hex_field(case, "ct").is_empty());
        }
    }
}
