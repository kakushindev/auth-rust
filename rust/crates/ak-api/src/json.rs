//! A `jsonb` column as Django returns it through orjson.
//!
//! Django reads `jsonb` with `json.loads` on `PostgreSQL`'s text output
//! (key order kept, a number with `.`/exponent becomes a `float`, any other
//! an `int`) and DRF's `JSONField` hands the value to orjson unchanged.
//! This rewrites that text the same way: no insignificant whitespace,
//! strings re-escaped, floats in `ryu`'s shortest form (orjson's).

use crate::Decline;

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    out: String,
}

fn bad() -> Decline {
    Decline("jsonb rendering")
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self
            .s
            .get(self.i)
            .is_some_and(|b| matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        {
            self.i += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn value(&mut self) -> Result<(), Decline> {
        self.ws();
        match self.peek().ok_or_else(bad)? {
            b'{' => self.container(b'{', b'}', true),
            b'[' => self.container(b'[', b']', false),
            b'"' => {
                let text = self.string()?;
                self.out
                    .push_str(&serde_json::to_string(&text).map_err(|_| bad())?);
                Ok(())
            }
            b't' => self.literal("true"),
            b'f' => self.literal("false"),
            b'n' => self.literal("null"),
            _ => self.number(),
        }
    }

    fn literal(&mut self, word: &str) -> Result<(), Decline> {
        if self.s[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            self.out.push_str(word);
            Ok(())
        } else {
            Err(bad())
        }
    }

    fn container(&mut self, open: u8, close: u8, object: bool) -> Result<(), Decline> {
        self.i += 1;
        self.out.push(char::from(open));
        self.ws();
        if self.peek() == Some(close) {
            self.i += 1;
            self.out.push(char::from(close));
            return Ok(());
        }
        loop {
            if object {
                self.ws();
                let key = self.string()?;
                self.out
                    .push_str(&serde_json::to_string(&key).map_err(|_| bad())?);
                self.ws();
                if self.peek() != Some(b':') {
                    return Err(bad());
                }
                self.i += 1;
                self.out.push(':');
            }
            self.value()?;
            self.ws();
            match self.peek() {
                Some(b',') => {
                    self.i += 1;
                    self.out.push(',');
                }
                Some(c) if c == close => {
                    self.i += 1;
                    self.out.push(char::from(close));
                    return Ok(());
                }
                _ => return Err(bad()),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, Decline> {
        let digits = self.s.get(self.i..self.i + 4).ok_or_else(bad)?;
        let text = std::str::from_utf8(digits).map_err(|_| bad())?;
        self.i += 4;
        u32::from_str_radix(text, 16).map_err(|_| bad())
    }

    fn string(&mut self) -> Result<String, Decline> {
        if self.peek() != Some(b'"') {
            return Err(bad());
        }
        self.i += 1;
        let mut out = String::new();
        loop {
            let start = self.i;
            while self.peek().is_some_and(|b| b != b'"' && b != b'\\') {
                self.i += 1;
            }
            out.push_str(std::str::from_utf8(&self.s[start..self.i]).map_err(|_| bad())?);
            if self.peek().ok_or_else(bad)? == b'"' {
                self.i += 1;
                return Ok(out);
            }
            // A backslash escape.
            self.i += 1;
            let escape = self.peek().ok_or_else(bad)?;
            self.i += 1;
            match escape {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'b' => out.push('\u{8}'),
                b'f' => out.push('\u{c}'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'u' => {
                    let high = self.hex4()?;
                    let code = if (0xd800..0xdc00).contains(&high) {
                        // jsonb only stores valid surrogate pairs.
                        if self.s.get(self.i..self.i + 2) != Some(b"\\u") {
                            return Err(bad());
                        }
                        self.i += 2;
                        let low = self.hex4()?;
                        0x10000 + ((high - 0xd800) << 10) + (low.wrapping_sub(0xdc00))
                    } else {
                        high
                    };
                    out.push(char::from_u32(code).ok_or_else(bad)?);
                }
                _ => return Err(bad()),
            }
        }
    }

    fn number(&mut self) -> Result<(), Decline> {
        let start = self.i;
        while self
            .peek()
            .is_some_and(|b| b.is_ascii_digit() || matches!(b, b'-' | b'+' | b'.' | b'e' | b'E'))
        {
            self.i += 1;
        }
        let token = std::str::from_utf8(&self.s[start..self.i]).map_err(|_| bad())?;
        if token.contains(['.', 'e', 'E']) {
            // `float(token)`; orjson cannot serialize a non-finite float.
            let value: f64 = token.parse().map_err(|_| bad())?;
            if !value.is_finite() {
                return Err(bad());
            }
            self.out.push_str(ryu::Buffer::new().format_finite(value));
        } else {
            // `int(token)`; orjson rejects anything outside i64/u64.
            let value: i128 = token.parse().map_err(|_| bad())?;
            if value < i128::from(i64::MIN) || value > i128::from(u64::MAX) {
                return Err(bad());
            }
            self.out.push_str(&value.to_string());
        }
        Ok(())
    }
}

/// `orjson.dumps(json.loads(jsonb_text))`, as raw JSON text.
///
/// # Errors
///
/// [`Decline`] for text that is not JSON, or values orjson would raise on.
pub fn render_jsonb(text: &str) -> Result<String, Decline> {
    let mut parser = Parser {
        s: text.as_bytes(),
        i: 0,
        out: String::with_capacity(text.len()),
    };
    parser.value()?;
    parser.ws();
    if parser.i != parser.s.len() {
        return Err(bad());
    }
    Ok(parser.out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_like_json_loads_then_orjson() {
        let r = |s| render_jsonb(s).expect("json");
        assert_eq!(
            r(r#"{"b": 1, "a": [1.50, 1e2, -0, "xé\n"]}"#),
            r#"{"b":1,"a":[1.5,100.0,0,"xé\n"]}"#
        );
        assert_eq!(r("{}"), "{}");
        assert_eq!(r(r#"{"k": 1e20}"#), r#"{"k":1e20}"#);
        assert_eq!(r(r#""😀""#), "\"\u{1f600}\"");
        assert_eq!(r("18446744073709551615"), "18446744073709551615");
        assert_eq!(render_jsonb("18446744073709551616"), Err(bad()));
        assert_eq!(render_jsonb("1e400"), Err(bad()));
        // orjson's float forms, checked in the reference image.
        assert_eq!(
            r("[1e-7, 0.00001, 1e15, 1e16, -0.0, 1.2345678901234568e17]"),
            "[1e-7,0.00001,1000000000000000.0,1e16,-0.0,1.2345678901234568e17]"
        );
    }
}
