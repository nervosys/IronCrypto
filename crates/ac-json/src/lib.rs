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

/// Parse a JSON document.
pub fn parse(input: &str) -> Result<Json, String> {
    let bytes: Vec<char> = input.chars().collect();
    let mut p = Parser {
        input: &bytes,
        pos: 0,
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

    fn array(&mut self) -> Result<Json, String> {
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

    fn object(&mut self) -> Result<Json, String> {
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
