//! A minimal JSON reader and writer.
//!
//! The MCP server speaks JSON-RPC, which means something in this workspace has
//! to *parse* JSON, not merely emit it. Rather than take a dependency and break
//! the zero-dependency property at the last mile, this is a complete
//! [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259) parser in a few hundred
//! lines, exercised by round-trip and malformed-input tests.
//!
//! It lived inside the CLI binary until the test-vector harness needed it too.
//! Parsing JSON is not a command-line concern, and a binary crate is a place
//! code goes to become unreachable.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![warn(clippy::all)]

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// A JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    /// `null`
    Null,
    /// `true` or `false`
    Bool(bool),
    /// Any JSON number, held as `f64`.
    Number(f64),
    /// A string, already unescaped.
    String(String),
    /// An array.
    Array(Vec<Json>),
    /// An object. Ordered so that output is deterministic.
    Object(BTreeMap<String, Json>),
}

impl Json {
    /// Look up a key, if this is an object.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(m) => m.get(key),
            _ => None,
        }
    }

    /// Borrow as a string, if this is one.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    /// Read as an `i64`, if this is a number.
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Number(n) => Some(*n as i64),
            _ => None,
        }
    }

    /// Read as a slice of elements, if this is an array.
    ///
    /// Returns `None` for a non-array rather than an empty slice, so a caller
    /// can tell "not an array" from "an array with nothing in it" — a
    /// distinction that matters when the value came from somewhere else.
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Read as an `f64`, if this is a number.
    ///
    /// [`Json::as_i64`] truncates; this does not, so a caller that needs the
    /// value as written has somewhere to get it.
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Number(n) => Some(*n),
            _ => None,
        }
    }

    /// Read as a bool, if this is one.
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Build an object from key-value pairs.
    pub fn object<const N: usize>(pairs: [(&str, Json); N]) -> Json {
        let mut m = BTreeMap::new();
        for (k, v) in pairs {
            m.insert(k.to_string(), v);
        }
        Json::Object(m)
    }

    /// Convenience constructor for a string value.
    pub fn str(s: impl Into<String>) -> Json {
        Json::String(s.into())
    }

    /// Convenience constructor for a numeric value.
    pub fn num(n: impl Into<f64>) -> Json {
        Json::Number(n.into())
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Number(n) => {
                if n.fract() == 0.0 && n.is_finite() && n.abs() < 9e15 {
                    let _ = write!(out, "{}", *n as i64);
                } else {
                    let _ = write!(out, "{n}");
                }
            }
            Json::String(s) => write_string(s, out),
            Json::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Object(map) => {
                out.push('{');
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }
}

impl std::fmt::Display for Json {
    /// Serialize to compact JSON text.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = String::new();
        self.write(&mut out);
        f.write_str(&out)
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// How deeply arrays and objects may nest before parsing is refused.
///
/// Recursive descent uses stack in proportion to nesting, and a stack overflow
/// in Rust is an abort rather than an error: nothing unwinds and no caller can
/// recover. Before this limit existed, two kilobytes of `[[[[...]]]]` ended the
/// process -- which matters because `ic mcp` parses JSON-RPC from whatever
/// is on the other end of its stdin.
///
/// 64 is chosen against measurement rather than taste. The deepest document this
/// project produces is the JSON Schema export, at 7; JSON-LD reaches 5 and the
/// SBOM 6. That is an order of magnitude of headroom, and far below the roughly
/// one thousand that exhausts the stack.
pub const MAX_DEPTH: usize = 64;

/// Parse a JSON document.
///
/// Nesting deeper than [`MAX_DEPTH`] is an error rather than a crash.
pub fn parse(input: &str) -> Result<Json, String> {
    let bytes: Vec<char> = input.chars().collect();
    let mut p = Parser {
        input: &bytes,
        pos: 0,
        depth: 0,
    };
    p.skip_ws();
    let value = p.value()?;
    p.skip_ws();
    if p.pos != p.input.len() {
        return Err(format!("trailing input at position {}", p.pos));
    }
    Ok(value)
}

struct Parser<'a> {
    input: &'a [char],
    pos: usize,
    /// How many arrays and objects are open at this point.
    depth: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.input.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<char> {
        let c = self.peek();
        if c.is_some() {
            self.pos += 1;
        }
        c
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(' ' | '\t' | '\n' | '\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, c: char) -> Result<(), String> {
        if self.bump() == Some(c) {
            Ok(())
        } else {
            Err(format!("expected '{c}' at position {}", self.pos))
        }
    }

    fn literal(&mut self, word: &str) -> Result<(), String> {
        for c in word.chars() {
            if self.bump() != Some(c) {
                return Err(format!("invalid literal near position {}", self.pos));
            }
        }
        Ok(())
    }

    fn value(&mut self) -> Result<Json, String> {
        self.skip_ws();
        match self.peek() {
            Some('n') => {
                self.literal("null")?;
                Ok(Json::Null)
            }
            Some('t') => {
                self.literal("true")?;
                Ok(Json::Bool(true))
            }
            Some('f') => {
                self.literal("false")?;
                Ok(Json::Bool(false))
            }
            Some('"') => Ok(Json::String(self.string()?)),
            Some('[') => self.array(),
            Some('{') => self.object(),
            Some(c) if c == '-' || c.is_ascii_digit() => self.number(),
            Some(c) => Err(format!("unexpected '{c}' at position {}", self.pos)),
            None => Err("unexpected end of input".to_string()),
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect('"')?;
        let mut out = String::new();
        loop {
            match self.bump() {
                None => return Err("unterminated string".to_string()),
                Some('"') => return Ok(out),
                Some('\\') => match self.bump() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('/') => out.push('/'),
                    Some('b') => out.push('\u{8}'),
                    Some('f') => out.push('\u{c}'),
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some('u') => {
                        let mut code = 0u32;
                        for _ in 0..4 {
                            let c = self.bump().ok_or("truncated \\u escape")?;
                            let d = c.to_digit(16).ok_or("invalid \\u escape")?;
                            code = code * 16 + d;
                        }
                        // Surrogate pairs are joined; a lone surrogate becomes
                        // the replacement character rather than an error, which
                        // matches what lenient JSON consumers do.
                        if (0xD800..0xDC00).contains(&code) && self.peek() == Some('\\') {
                            self.pos += 1;
                            self.expect('u')?;
                            let mut low = 0u32;
                            for _ in 0..4 {
                                let c = self.bump().ok_or("truncated \\u escape")?;
                                let d = c.to_digit(16).ok_or("invalid \\u escape")?;
                                low = low * 16 + d;
                            }
                            code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                        }
                        out.push(char::from_u32(code).unwrap_or('\u{FFFD}'));
                    }
                    _ => return Err("invalid escape".to_string()),
                },
                Some(c) if (c as u32) < 0x20 => {
                    return Err("unescaped control character in string".to_string())
                }
                Some(c) => out.push(c),
            }
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some('-') {
            self.pos += 1;
        }
        while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
            self.pos += 1;
        }
        if self.peek() == Some('.') {
            self.pos += 1;
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some('e' | 'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some('+' | '-')) {
                self.pos += 1;
            }
            while matches!(self.peek(), Some(c) if c.is_ascii_digit()) {
                self.pos += 1;
            }
        }
        let text: String = self.input[start..self.pos].iter().collect();
        text.parse::<f64>()
            .map(Json::Number)
            .map_err(|_| format!("invalid number '{text}'"))
    }

    /// Parse an array, counting the nesting.
    ///
    /// The counter is taken and released here rather than inside
    /// `array_inner`, which returns from several places: a decrement missed on
    /// one of them would leak depth and start rejecting long documents that are
    /// not deep at all, which is worse than what this guards against and far
    /// harder to notice.
    fn array(&mut self) -> Result<Json, String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(format!(
                "nesting deeper than {MAX_DEPTH} at position {}",
                self.pos
            ));
        }
        let parsed = self.array_inner();
        self.depth -= 1;
        parsed
    }

    fn array_inner(&mut self) -> Result<Json, String> {
        self.expect('[')?;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            items.push(self.value()?);
            self.skip_ws();
            match self.bump() {
                Some(',') => continue,
                Some(']') => return Ok(Json::Array(items)),
                _ => return Err("expected ',' or ']'".to_string()),
            }
        }
    }

    /// Parse an object, counting the nesting.
    ///
    /// The counter is taken and released here rather than inside
    /// `object_inner`, which returns from several places: a decrement missed on
    /// one of them would leak depth and start rejecting long documents that are
    /// not deep at all, which is worse than what this guards against and far
    /// harder to notice.
    fn object(&mut self) -> Result<Json, String> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(format!(
                "nesting deeper than {MAX_DEPTH} at position {}",
                self.pos
            ));
        }
        let parsed = self.object_inner();
        self.depth -= 1;
        parsed
    }

    fn object_inner(&mut self) -> Result<Json, String> {
        self.expect('{')?;
        let mut map = BTreeMap::new();
        self.skip_ws();
        if self.peek() == Some('}') {
            self.pos += 1;
            return Ok(Json::Object(map));
        }
        loop {
            self.skip_ws();
            let key = self.string()?;
            self.skip_ws();
            self.expect(':')?;
            let value = self.value()?;
            map.insert(key, value);
            self.skip_ws();
            match self.bump() {
                Some(',') => continue,
                Some('}') => return Ok(Json::Object(map)),
                _ => return Err("expected ',' or '}'".to_string()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The new accessors, including the distinction that motivates them.
    #[test]
    fn array_and_number_accessors_report_the_right_shape() {
        let v = parse(r#"{"xs":[1,2],"empty":[],"n":1.5,"s":"t"}"#).unwrap();

        assert_eq!(
            v.get("xs").and_then(|x| x.as_array()).map(|a| a.len()),
            Some(2)
        );
        // An empty array is still an array, and must not read as absent.
        assert_eq!(
            v.get("empty").and_then(|x| x.as_array()).map(|a| a.len()),
            Some(0)
        );
        assert!(
            v.get("s").unwrap().as_array().is_none(),
            "a string is not an array"
        );

        assert_eq!(v.get("n").and_then(|x| x.as_f64()), Some(1.5));
        // as_i64 truncates where as_f64 does not; both are offered for that reason.
        assert_eq!(v.get("n").and_then(|x| x.as_i64()), Some(1));
        assert!(v.get("s").unwrap().as_f64().is_none());
    }

    /// `n` copies of `unit`, comma separated.
    fn alloc_join(n: usize, unit: &str) -> String {
        vec![unit; n].join(",")
    }

    /// `n` copies of `unit`, comma separated, for units too large to repeat
    /// cheaply by value.
    fn alloc_join_with(n: usize, unit: &str) -> String {
        (0..n).map(|_| unit).collect::<Vec<_>>().join(",")
    }

    #[test]
    fn parses_scalars() {
        assert_eq!(parse("null").unwrap(), Json::Null);
        assert_eq!(parse("true").unwrap(), Json::Bool(true));
        assert_eq!(parse("false").unwrap(), Json::Bool(false));
        assert_eq!(parse("42").unwrap(), Json::Number(42.0));
        assert_eq!(parse("-1.5e2").unwrap(), Json::Number(-150.0));
        assert_eq!(parse(r#""hi""#).unwrap(), Json::str("hi"));
    }

    #[test]
    fn parses_nested_structures() {
        let v = parse(r#"{"a":[1,2,{"b":null}],"c":"d"}"#).unwrap();
        assert_eq!(v.get("c").unwrap().as_str(), Some("d"));
        let a = v.get("a").unwrap();
        match a {
            Json::Array(items) => {
                assert_eq!(items.len(), 3);
                assert_eq!(items[2].get("b"), Some(&Json::Null));
            }
            _ => panic!("expected an array"),
        }
    }

    #[test]
    fn handles_escapes() {
        assert_eq!(parse(r#""a\nb""#).unwrap(), Json::str("a\nb"));
        assert_eq!(parse(r#""a\\b""#).unwrap(), Json::str("a\\b"));
        assert_eq!(parse(r#""a\"b""#).unwrap(), Json::str("a\"b"));
        assert_eq!(parse(r#""A""#).unwrap(), Json::str("A"));
        // A surrogate pair for U+1F600.
        assert_eq!(parse(r#""😀""#).unwrap(), Json::str("\u{1F600}"));
    }

    /// Deep nesting is refused, not fatal.
    ///
    /// Before the limit existed, `"[" * 1000` overflowed the stack, and a stack
    /// overflow in Rust aborts: nothing unwinds and no caller can recover. This
    /// is the case that motivated it, and `ic mcp` is why it matters --
    /// that server parses JSON-RPC from whatever is on the other end of its
    /// stdin.
    #[test]
    fn deep_nesting_is_refused_rather_than_fatal() {
        for depth in [MAX_DEPTH + 1, 1_000, 100_000] {
            let deep = "[".repeat(depth) + &"]".repeat(depth);
            let err = parse(&deep).expect_err("{depth} deep should be refused");
            assert!(
                err.contains("nesting"),
                "the error should say what was wrong: {err}"
            );

            let deep = "{\"a\":".repeat(depth) + "1" + &"}".repeat(depth);
            assert!(
                parse(&deep).is_err(),
                "{depth} deep objects should be refused"
            );
        }
    }

    /// The boundary is where it says it is.
    ///
    /// Off by one here is either a document refused that should parse or a
    /// limit that is not the documented one.
    #[test]
    fn the_limit_is_exactly_where_it_claims() {
        let at = "[".repeat(MAX_DEPTH) + &"]".repeat(MAX_DEPTH);
        assert!(parse(&at).is_ok(), "{MAX_DEPTH} deep should parse");

        let over = "[".repeat(MAX_DEPTH + 1) + &"]".repeat(MAX_DEPTH + 1);
        assert!(parse(&over).is_err(), "{} deep should not", MAX_DEPTH + 1);
    }

    /// Depth is not length: a wide document is not a deep one.
    ///
    /// The easy mistake in a limit like this is to count the wrong thing and
    /// start refusing large inputs, which would break the ontology exports --
    /// 75 algorithms with their parameters and constraints, all of it shallow.
    #[test]
    fn a_wide_document_is_not_a_deep_one() {
        let wide = format!("[{}]", vec!["1"; 50_000].join(","));
        let parsed = parse(&wide).expect("a flat array of 50,000 items is not deep");
        match parsed {
            Json::Array(items) => assert_eq!(items.len(), 50_000),
            other => panic!("expected an array, got {other:?}"),
        }

        // And the real thing: whatever this project emits must still parse.
        // The deepest is the JSON Schema export at 7.
        let nested = r#"{"a":{"b":{"c":{"d":{"e":{"f":{"g":[1,2,3]}}}}}}}"#;
        assert!(parse(nested).is_ok());
    }

    /// The counter must be released, or siblings exhaust it.
    ///
    /// This is the bug a depth limit introduces rather than fixes, and it hides
    /// from the obvious test. A single deep chain enters each level once, so a
    /// missing decrement never shows; and `parse` builds a fresh parser every
    /// call, so nothing leaks between documents either. The first version of
    /// this test did both of those and stayed green when the release was
    /// deleted.
    ///
    /// It shows up across siblings, where the counter should fall between one
    /// value and the next. That shape is not contrived: the ontology export is
    /// an object holding an array of seventy-five algorithm objects, every one
    /// of them a sibling at depth 3.
    #[test]
    fn depth_is_released_between_siblings() {
        // Far more siblings than MAX_DEPTH, and only two deep. This parses if
        // and only if the counter comes back down between them.
        let siblings = alloc_join(MAX_DEPTH * 8, "[]");
        let doc = format!("[{siblings}]");
        let parsed = parse(&doc).expect("wide and shallow should parse");
        match parsed {
            Json::Array(items) => assert_eq!(items.len(), MAX_DEPTH * 8),
            other => panic!("expected an array, got {other:?}"),
        }

        // Objects too, which use the other wrapper.
        let siblings = alloc_join(MAX_DEPTH * 8, "{}");
        assert!(parse(&format!("[{siblings}]")).is_ok());

        // And nested siblings: each branch goes deep, returns, and the next one
        // starts from the same level rather than from where the last finished.
        let branch = "[".repeat(MAX_DEPTH - 2) + &"]".repeat(MAX_DEPTH - 2);
        let many = alloc_join_with(8, &branch);
        assert!(
            parse(&format!("[{many}]")).is_ok(),
            "deep branches side by side should parse; the counter is not falling"
        );

        // A refusal must not leave the counter raised either: the early return
        // on the limit is the exit most likely to skip a decrement.
        let over = "[".repeat(MAX_DEPTH + 10) + &"]".repeat(MAX_DEPTH + 10);
        assert!(parse(&over).is_err());
        assert!(parse(&doc).is_ok(), "a refusal poisoned the next parse");
    }

    #[test]
    fn rejects_malformed_input() {
        for bad in [
            "",
            "{",
            "[1,]",
            r#"{"a"}"#,
            r#"{"a":}"#,
            "tru",
            "{} {}",
            "\"unterminated",
            "01x",
        ] {
            assert!(parse(bad).is_err(), "{bad:?} should not parse");
        }
    }

    #[test]
    fn roundtrips_through_serialization() {
        let cases = [
            r#"{"a":1,"b":[true,false,null],"c":"x"}"#,
            r#"[]"#,
            r#"{}"#,
            r#"{"nested":{"deep":{"value":-3}}}"#,
        ];
        for case in cases {
            let v = parse(case).unwrap();
            let text = v.to_string();
            assert_eq!(parse(&text).unwrap(), v, "round trip of {case}");
        }
    }

    #[test]
    fn serialization_escapes_control_characters() {
        let v = Json::str("tab\there\u{1}");
        let text = v.to_string();
        assert!(text.contains("\\t"));
        assert!(text.contains("\\u0001"));
        assert_eq!(parse(&text).unwrap(), v);
    }

    #[test]
    fn integers_serialize_without_a_decimal_point() {
        assert_eq!(Json::num(42.0).to_string(), "42");
        assert_eq!(Json::num(-7.0).to_string(), "-7");
        assert_eq!(Json::num(0.5).to_string(), "0.5");
    }

    #[test]
    fn object_keys_are_ordered_deterministically() {
        let a = Json::object([("z", Json::num(1)), ("a", Json::num(2))]);
        assert_eq!(a.to_string(), r#"{"a":2,"z":1}"#);
    }

    #[test]
    fn accessors_return_none_on_type_mismatch() {
        let v = Json::str("text");
        assert_eq!(v.as_i64(), None);
        assert_eq!(v.as_bool(), None);
        assert_eq!(v.get("key"), None);
    }
}
