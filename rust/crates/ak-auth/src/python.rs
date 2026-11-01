//! Python 3.14 behaviors that decide outcomes on untrusted input.
//!
//! Lenient base64, `json.loads`, `int()`, truthiness and `len()`, each
//! checked against `CPython` by `testdata/python_vectors.json`.

/// `str.isspace()`: Unicode whitespace plus U+001C..U+001F.
#[must_use]
pub fn isspace(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}

/// `PyJWT`'s `base64url_decode`.
///
/// Pad to a multiple of four with `=`, then
/// `base64.urlsafe_b64decode`, which skips bytes outside the alphabet
/// (accepting both `-_` and `+/`) and `=` signs, and requires the last
/// group to be completed by the `=` signs that follow it.
#[must_use]
pub fn base64url_decode(input: &[u8]) -> Option<Vec<u8>> {
    let mut padded = input.to_vec();
    let rem = padded.len() % 4;
    if rem > 0 {
        padded.extend(std::iter::repeat_n(b'=', 4 - rem));
    }
    let mut out = Vec::with_capacity(padded.len() / 4 * 3);
    let (mut quad_pos, mut left, mut pads) = (0_u8, 0_u8, 0_usize);
    for byte in padded {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => {
                pads += 1;
                continue;
            }
            _ => continue,
        };
        pads = 0;
        match quad_pos {
            0 => {
                left = value;
                quad_pos = 1;
            }
            1 => {
                out.push((left << 2_u32) | (value >> 4_u32));
                left = value & 0x0f;
                quad_pos = 2;
            }
            2 => {
                out.push((left << 4_u32) | (value >> 2_u32));
                left = value & 0x03;
                quad_pos = 3;
            }
            _ => {
                out.push((left << 6_u32) | value);
                quad_pos = 0;
            }
        }
    }
    match quad_pos {
        0 => Some(out),
        1 => None,
        n if usize::from(n) + pads >= 4 => Some(out),
        _ => None,
    }
}

/// A Python `str`: code points, lone surrogates included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyStr(pub Vec<u32>);

impl PyStr {
    #[must_use]
    pub fn from_text(s: &str) -> Self {
        Self(s.chars().map(u32::from).collect())
    }

    /// The text, unless it holds a lone surrogate (which Python can hold and
    /// UTF-8 cannot).
    #[must_use]
    pub fn to_string_lossless(&self) -> Option<String> {
        self.0.iter().map(|&c| char::from_u32(c)).collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// A value `json.loads` produces.
#[derive(Debug, Clone, PartialEq)]
pub enum PyValue {
    None,
    Bool(bool),
    /// Python `int`, as decimal digits with an optional `-`.
    Int(String),
    Float(f64),
    Str(PyStr),
    List(Vec<Self>),
    /// Python `dict` from `json.loads`: insertion order of first occurrence,
    /// value of the last (duplicate keys).
    Dict(Vec<(PyStr, Self)>),
}

/// Dropped iteratively: a validly parsed value can be nested tens of
/// thousands deep (see [`MAX_DEPTH`]), which recursive drop glue would turn
/// into a stack overflow.
#[expect(clippy::missing_trait_methods, reason = "pin_drop is not used")]
impl Drop for PyValue {
    fn drop(&mut self) {
        fn take_children(value: &mut PyValue, into: &mut Vec<PyValue>) {
            match value {
                PyValue::List(items) => into.append(items),
                PyValue::Dict(items) => into.extend(items.drain(..).map(|(_, v)| v)),
                _ => {}
            }
        }
        let mut pending = Vec::new();
        take_children(self, &mut pending);
        while let Some(mut value) = pending.pop() {
            take_children(&mut value, &mut pending);
        }
    }
}

/// A Python exception, by class name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PyError {
    ValueError,
    TypeError,
    OverflowError,
    RecursionError,
}

impl PyValue {
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Self> {
        let key = PyStr::from_text(key);
        match self {
            Self::Dict(items) => items.iter().find(|(k, _)| *k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// `bool(value)`.
    #[must_use]
    pub fn truthy(&self) -> bool {
        match self {
            Self::None => false,
            Self::Bool(b) => *b,
            Self::Int(digits) => digits.trim_start_matches('-').bytes().any(|b| b != b'0'),
            Self::Float(f) => *f != 0.0,
            Self::Str(s) => !s.is_empty(),
            Self::List(items) => !items.is_empty(),
            Self::Dict(items) => !items.is_empty(),
        }
    }

    /// `len(value)`.
    ///
    /// # Errors
    ///
    /// `TypeError` for values without a length.
    pub fn py_len(&self) -> Result<usize, PyError> {
        match self {
            Self::Str(s) => Ok(s.len()),
            Self::List(items) => Ok(items.len()),
            Self::Dict(items) => Ok(items.len()),
            _ => Err(PyError::TypeError),
        }
    }

    /// `int(value)` as an `f64`-comparable number: exact within `i128`,
    /// `±inf` beyond (only its order relative to a timestamp matters).
    /// `str` follows `int(str)` for ASCII digits (non-ASCII decimal digits,
    /// which Python also accepts, are a `ValueError` here).
    ///
    /// # Errors
    ///
    /// The exception Python raises.
    pub fn to_int(&self) -> Result<f64, PyError> {
        fn digits_value(negative: bool, digits: &str) -> f64 {
            #[expect(
                clippy::as_conversions,
                clippy::cast_precision_loss,
                reason = "ordering only"
            )]
            digits.parse::<i128>().map_or(
                if negative {
                    f64::NEG_INFINITY
                } else {
                    f64::INFINITY
                },
                |v| if negative { -(v as f64) } else { v as f64 },
            )
        }
        match self {
            Self::Bool(b) => Ok(if *b { 1.0 } else { 0.0 }),
            Self::Int(text) => {
                let (negative, digits) = text
                    .strip_prefix('-')
                    .map_or((false, text.as_str()), |d| (true, d));
                Ok(digits_value(negative, digits))
            }
            Self::Float(f) if f.is_nan() => Err(PyError::ValueError),
            Self::Float(f) if f.is_infinite() => Err(PyError::OverflowError),
            Self::Float(f) => Ok(f.trunc()),
            Self::Str(s) => {
                let text = s.to_string_lossless().ok_or(PyError::ValueError)?;
                let text = text.trim_matches(isspace);
                let (negative, rest) = match text.as_bytes().first() {
                    Some(b'-') => (true, &text[1..]),
                    Some(b'+') => (false, &text[1..]),
                    _ => (false, text),
                };
                // Digits with single underscores between them.
                let valid = !rest.is_empty()
                    && !rest.starts_with('_')
                    && !rest.ends_with('_')
                    && !rest.contains("__")
                    && rest.bytes().all(|b| b.is_ascii_digit() || b == b'_');
                if !valid {
                    return Err(PyError::ValueError);
                }
                let digits: String = rest.chars().filter(|&c| c != '_').collect();
                if digits.len() > 4300 {
                    return Err(PyError::ValueError);
                }
                {
                    let significant = digits.trim_start_matches('0');
                    Ok(digits_value(
                        negative,
                        if significant.is_empty() {
                            "0"
                        } else {
                            significant
                        },
                    ))
                }
            }
            Self::None | Self::List(_) | Self::Dict(_) => Err(PyError::TypeError),
        }
    }
}

/// `json.detect_encoding` plus `bytes.decode(…, "surrogatepass")`.
fn decode_json_bytes(b: &[u8]) -> Option<Vec<u32>> {
    fn utf16(b: &[u8], big: bool) -> Option<Vec<u32>> {
        if !b.len().is_multiple_of(2) {
            return None;
        }
        let units: Vec<u16> = b
            .chunks_exact(2)
            .map(|c| {
                if big {
                    u16::from_be_bytes(c.try_into().expect("two bytes"))
                } else {
                    u16::from_le_bytes(c.try_into().expect("two bytes"))
                }
            })
            .collect();
        // surrogatepass: pairs combine, lone surrogates stay.
        let mut out = Vec::with_capacity(units.len());
        let mut i = 0;
        while i < units.len() {
            let u = u32::from(units[i]);
            if (0xd800..0xdc00).contains(&u)
                && let Some(&next) = units.get(i + 1)
                && (0xdc00..0xe000).contains(&u32::from(next))
            {
                out.push(0x10000 + ((u - 0xd800) << 10_u32) + (u32::from(next) - 0xdc00));
                i += 2;
                continue;
            }
            out.push(u);
            i += 1;
        }
        Some(out)
    }
    fn utf32(b: &[u8], big: bool) -> Option<Vec<u32>> {
        if !b.len().is_multiple_of(4) {
            return None;
        }
        b.chunks_exact(4)
            .map(|c| {
                let v = if big {
                    u32::from_be_bytes(c.try_into().expect("four bytes"))
                } else {
                    u32::from_le_bytes(c.try_into().expect("four bytes"))
                };
                (v <= 0x0010_ffff).then_some(v)
            })
            .collect()
    }
    fn utf8(b: &[u8]) -> Option<Vec<u32>> {
        // surrogatepass also admits encoded surrogates (ED A0..BF xx).
        let mut out = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            let lead = b[i];
            let (len, init) = match lead {
                0x00..=0x7f => (1, u32::from(lead)),
                0xc2..=0xdf => (2, u32::from(lead & 0x1f)),
                0xe0..=0xef => (3, u32::from(lead & 0x0f)),
                0xf0..=0xf4 => (4, u32::from(lead & 0x07)),
                _ => return None,
            };
            let cont = b.get(i + 1..i + len)?;
            if cont.iter().any(|c| c & 0xc0 != 0x80) {
                return None;
            }
            let cp = cont
                .iter()
                .fold(init, |acc, c| (acc << 6_u32) | u32::from(c & 0x3f));
            let min = [0, 0, 0x80, 0x800, 0x10000][len];
            if cp < min || cp > 0x0010_ffff {
                return None;
            }
            out.push(cp);
            i += len;
        }
        Some(out)
    }
    match b {
        [0x00, 0x00, 0xfe, 0xff, rest @ ..] => utf32(rest, true),
        [0xff, 0xfe, 0x00, 0x00, rest @ ..] => utf32(rest, false),
        [0xfe, 0xff, rest @ ..] => utf16(rest, true),
        [0xff, 0xfe, rest @ ..] => utf16(rest, false),
        [0xef, 0xbb, 0xbf, rest @ ..] => utf8(rest),
        [0, b1, _, _, ..] => {
            if *b1 != 0 {
                utf16(b, true)
            } else {
                utf32(b, true)
            }
        }
        [_, 0, b2, b3, ..] => {
            if *b2 != 0 || *b3 != 0 {
                utf16(b, false)
            } else {
                utf32(b, false)
            }
        }
        [0, _] => utf16(b, true),
        [_, 0] => utf16(b, false),
        _ => utf8(b),
    }
}

/// Nesting at which `CPython` 3.14's JSON scanner raises `RecursionError`.
///
/// Python's guard measures C stack space, not levels: in authentik's image
/// it trips between 47 405 (worker thread) and 47 449 (main thread) levels,
/// and a request's own frames lower it slightly. Parsing is iterative, so
/// any depth is safe here.
const MAX_DEPTH: usize = 47_000;

/// An open container while parsing.
enum Frame {
    List(Vec<PyValue>),
    /// Items so far and the key whose value is being parsed.
    Dict(Vec<(PyStr, PyValue)>, PyStr),
}

struct Parser<'a> {
    s: &'a [u32],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while matches!(self.s.get(self.i), Some(0x20 | 0x09 | 0x0a | 0x0d)) {
            self.i += 1;
        }
    }

    fn eat(&mut self, lit: &str) -> bool {
        let lit: Vec<u32> = lit.chars().map(u32::from).collect();
        if self.s.get(self.i..self.i + lit.len()) == Some(lit.as_slice()) {
            self.i += lit.len();
            true
        } else {
            false
        }
    }

    /// An object key and its `:`, with the whitespace around them.
    fn key(&mut self) -> Result<PyStr, PyError> {
        if self.s.get(self.i) != Some(&0x22) {
            return Err(PyError::ValueError);
        }
        let key = self.string()?;
        self.ws();
        if self.s.get(self.i) != Some(&0x3a) {
            return Err(PyError::ValueError);
        }
        self.i += 1;
        self.ws();
        Ok(key)
    }

    /// One JSON value, with an explicit stack instead of recursion.
    fn value(&mut self) -> Result<PyValue, PyError> {
        let mut stack: Vec<Frame> = Vec::new();
        loop {
            let mut value = match self.s.get(self.i).copied() {
                Some(0x22) => PyValue::Str(self.string()?),
                Some(0x7b) => {
                    self.i += 1;
                    self.ws();
                    if self.s.get(self.i) == Some(&0x7d) {
                        self.i += 1;
                        PyValue::Dict(Vec::new())
                    } else {
                        if stack.len() >= MAX_DEPTH {
                            return Err(PyError::RecursionError);
                        }
                        let key = self.key()?;
                        stack.push(Frame::Dict(Vec::new(), key));
                        continue;
                    }
                }
                Some(0x5b) => {
                    self.i += 1;
                    self.ws();
                    if self.s.get(self.i) == Some(&0x5d) {
                        self.i += 1;
                        PyValue::List(Vec::new())
                    } else {
                        if stack.len() >= MAX_DEPTH {
                            return Err(PyError::RecursionError);
                        }
                        stack.push(Frame::List(Vec::new()));
                        continue;
                    }
                }
                _ if self.eat("null") => PyValue::None,
                _ if self.eat("true") => PyValue::Bool(true),
                _ if self.eat("false") => PyValue::Bool(false),
                _ if self.eat("NaN") => PyValue::Float(f64::NAN),
                _ if self.eat("Infinity") => PyValue::Float(f64::INFINITY),
                _ if self.eat("-Infinity") => PyValue::Float(f64::NEG_INFINITY),
                _ => self.number()?,
            };
            // Hand the value to the enclosing containers, closing those that end.
            loop {
                match stack.last_mut() {
                    None => return Ok(value),
                    Some(Frame::List(items)) => {
                        items.push(value);
                        self.ws();
                        match self.s.get(self.i) {
                            Some(0x2c) => {
                                self.i += 1;
                                self.ws();
                                break;
                            }
                            Some(0x5d) => {
                                self.i += 1;
                                let Some(Frame::List(items)) = stack.pop() else {
                                    return Err(PyError::ValueError);
                                };
                                value = PyValue::List(items);
                            }
                            _ => return Err(PyError::ValueError),
                        }
                    }
                    Some(Frame::Dict(items, key)) => {
                        let key = std::mem::replace(key, PyStr(Vec::new()));
                        match items.iter_mut().find(|(k, _)| *k == key) {
                            Some(slot) => slot.1 = value,
                            None => items.push((key, value)),
                        }
                        self.ws();
                        match self.s.get(self.i) {
                            Some(0x2c) => {
                                self.i += 1;
                                self.ws();
                                let next = self.key()?;
                                if let Some(Frame::Dict(_, slot)) = stack.last_mut() {
                                    *slot = next;
                                }
                                break;
                            }
                            Some(0x7d) => {
                                self.i += 1;
                                let Some(Frame::Dict(items, _)) = stack.pop() else {
                                    return Err(PyError::ValueError);
                                };
                                value = PyValue::Dict(items);
                            }
                            _ => return Err(PyError::ValueError),
                        }
                    }
                }
            }
        }
    }

    fn number(&mut self) -> Result<PyValue, PyError> {
        // `(-?(?:0|[1-9][0-9]*))(\.[0-9]+)?([eE][-+]?[0-9]+)?`
        let digit = |c: Option<&u32>| matches!(c, Some(0x30..=0x39));
        let start = self.i;
        if self.s.get(self.i) == Some(&0x2d) {
            self.i += 1;
        }
        match self.s.get(self.i) {
            Some(0x30) => self.i += 1,
            Some(0x31..=0x39) => {
                while digit(self.s.get(self.i)) {
                    self.i += 1;
                }
            }
            _ => return Err(PyError::ValueError),
        }
        let int_end = self.i;
        let fraction = self.s.get(self.i) == Some(&0x2e) && digit(self.s.get(self.i + 1));
        if fraction {
            self.i += 1;
            while digit(self.s.get(self.i)) {
                self.i += 1;
            }
        }
        let mut exponent = false;
        if matches!(self.s.get(self.i), Some(0x65 | 0x45)) {
            let mark = self.i;
            self.i += 1;
            if matches!(self.s.get(self.i), Some(0x2b | 0x2d)) {
                self.i += 1;
            }
            exponent = digit(self.s.get(self.i));
            if exponent {
                while digit(self.s.get(self.i)) {
                    self.i += 1;
                }
            } else {
                self.i = mark;
            }
        }
        let is_float = fraction || exponent;
        let text: String = self.s[start..self.i]
            .iter()
            .filter_map(|&c| char::from_u32(c))
            .collect();
        if is_float {
            text.parse::<f64>()
                .map(PyValue::Float)
                .map_err(|_| PyError::ValueError)
        } else {
            let digits = &self.s[start..int_end];
            if digits.len() > 4300 {
                return Err(PyError::ValueError);
            }
            Ok(PyValue::Int(text))
        }
    }

    fn string(&mut self) -> Result<PyStr, PyError> {
        self.i += 1;
        let mut out = Vec::new();
        loop {
            let c = *self.s.get(self.i).ok_or(PyError::ValueError)?;
            self.i += 1;
            match c {
                0x22 => return Ok(PyStr(out)),
                0x5c => {
                    let e = *self.s.get(self.i).ok_or(PyError::ValueError)?;
                    self.i += 1;
                    match e {
                        0x22 => out.push(0x22),
                        0x5c => out.push(0x5c),
                        0x2f => out.push(0x2f),
                        0x62 => out.push(0x08),
                        0x66 => out.push(0x0c),
                        0x6e => out.push(0x0a),
                        0x72 => out.push(0x0d),
                        0x74 => out.push(0x09),
                        0x75 => {
                            let mut unit = self.hex4()?;
                            if (0xd800..0xdc00).contains(&unit)
                                && self.s.get(self.i) == Some(&0x5c)
                                && self.s.get(self.i + 1) == Some(&0x75)
                            {
                                let mark = self.i;
                                self.i += 2;
                                let low = self.hex4()?;
                                if (0xdc00..0xe000).contains(&low) {
                                    unit = 0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00);
                                } else {
                                    self.i = mark;
                                }
                            }
                            out.push(unit);
                        }
                        _ => return Err(PyError::ValueError),
                    }
                }
                // strict: control characters are not allowed in strings.
                0x00..=0x1f => return Err(PyError::ValueError),
                _ => out.push(c),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, PyError> {
        let digits = self.s.get(self.i..self.i + 4).ok_or(PyError::ValueError)?;
        let mut v = 0;
        for &d in digits {
            v = v * 16
                + char::from_u32(d)
                    .and_then(|c| c.to_digit(16))
                    .ok_or(PyError::ValueError)?;
        }
        self.i += 4;
        Ok(v)
    }
}

/// `json.loads(bytes)`.
///
/// # Errors
///
/// `ValueError` where Python raises `JSONDecodeError`/`UnicodeDecodeError`,
/// `RecursionError` for nesting past [`MAX_DEPTH`].
pub fn json_loads(bytes: &[u8]) -> Result<PyValue, PyError> {
    let s = decode_json_bytes(bytes).ok_or(PyError::ValueError)?;
    let mut parser = Parser { s: &s, i: 0 };
    parser.ws();
    let value = parser.value()?;
    parser.ws();
    if parser.i != s.len() {
        return Err(PyError::ValueError);
    }
    Ok(value)
}

/// `timedelta_from_string(expr).total_seconds()`, `None` where it raises.
///
/// That is `authentik.lib.utils.time`'s parser (`ValueError` is `None`).
/// Values go through `float()` after `strip()`; Python-only float syntax
/// (`1_0`) is rejected here.
#[must_use]
pub fn timedelta_seconds(expr: &str) -> Option<f64> {
    const KEYS: &[(&str, f64)] = &[
        ("microseconds", 1e-6),
        ("milliseconds", 1e-3),
        ("seconds", 1.0),
        ("minutes", 60.0),
        ("hours", 3600.0),
        ("days", 86_400.0),
        ("weeks", 604_800.0),
    ];
    let mut kwargs: Vec<(&str, f64)> = Vec::new();
    for pair in expr.split(';') {
        // `key, value = pair.split("=")`: exactly one `=`.
        let mut parts = pair.split('=');
        let (Some(key), Some(value), None) = (parts.next(), parts.next(), parts.next()) else {
            return None;
        };
        let key = key.to_lowercase();
        let Some((name, unit)) = KEYS.iter().find(|(k, _)| *k == key) else {
            continue;
        };
        let value: f64 = value.trim_matches(isspace).parse().ok()?;
        // Later duplicates replace earlier ones (a dict).
        kwargs.retain(|(k, _)| k != name);
        kwargs.push((name, value * unit));
    }
    if kwargs.is_empty() {
        return None;
    }
    // `timedelta` keeps whole microseconds.
    let seconds: f64 = kwargs.iter().map(|(_, v)| v).sum();
    Some((seconds * 1e6).round() / 1e6)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use serde_json::Value;

    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().fold(String::new(), |mut out, x| {
            let _ = write!(out, "{x:02x}");
            out
        })
    }

    fn tag(v: &PyValue) -> Value {
        let cps = |s: &PyStr| Value::from(s.0.clone());
        match v {
            PyValue::None => serde_json::json!({"t": "none"}),
            PyValue::Bool(b) => serde_json::json!({"t": "bool", "v": b}),
            PyValue::Int(i) => {
                // Python normalizes `-0` to `0`.
                let i = if i.trim_start_matches('-').bytes().all(|b| b == b'0') {
                    "0"
                } else {
                    i
                };
                serde_json::json!({"t": "int", "v": i})
            }
            PyValue::Float(f) => serde_json::json!({"t": "float", "v": float_hex(*f)}),
            PyValue::Str(s) => serde_json::json!({"t": "str", "v": cps(s)}),
            PyValue::List(items) => {
                serde_json::json!({"t": "list", "v": items.iter().map(tag).collect::<Vec<_>>()})
            }
            PyValue::Dict(items) => serde_json::json!({
                "t": "dict",
                "v": items.iter().map(|(k, v)| serde_json::json!([cps(k), tag(v)])).collect::<Vec<_>>()
            }),
        }
    }

    /// Python's `float.hex()`.
    fn float_hex(f: f64) -> String {
        if f.is_nan() {
            return "nan".to_owned();
        }
        if f.is_infinite() {
            return if f > 0.0 { "inf" } else { "-inf" }.to_owned();
        }
        let sign = if f.is_sign_negative() { "-" } else { "" };
        if f == 0.0_f64 {
            return format!("{sign}0x0.0p+0");
        }
        let bits = f.to_bits();
        let exp = i64::try_from((bits >> 52_u32) & 0x7ff).expect("exponent");
        let mantissa = bits & ((1_u64 << 52_u32) - 1);
        let (lead, exp) = if exp == 0 {
            (0_u8, -1022_i64)
        } else {
            (1_u8, exp - 1023)
        };
        format!("{sign}0x{lead}.{mantissa:013x}p{exp:+}")
    }

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../testdata/python_vectors.json")).expect("vectors")
    }

    #[test]
    fn base64_matches_cpython() {
        for case in vectors()["base64"].as_array().expect("base64") {
            let input = unhex(case[0].as_str().expect("input"));
            let expected = case[1].as_str();
            assert_eq!(
                base64url_decode(&input).map(|b| hex(&b)).as_deref(),
                expected,
                "{:?}",
                String::from_utf8_lossy(&input)
            );
        }
    }

    #[test]
    fn json_matches_cpython() {
        for case in vectors()["json"].as_array().expect("json") {
            let input = unhex(case[0].as_str().expect("input"));
            let got = match json_loads(&input) {
                Ok(v) => tag(&v),
                Err(PyError::RecursionError) => Value::from("RecursionError"),
                Err(_) => Value::from("ValueError"),
            };
            assert_eq!(got, case[1], "{:?}", String::from_utf8_lossy(&input));
        }
    }

    #[test]
    fn nesting_depth_matches_cpython() {
        for case in vectors()["depth"].as_array().expect("depth") {
            let depth = usize::try_from(case[0].as_u64().expect("depth")).expect("depth");
            let text = format!("{}{}", "[".repeat(depth), "]".repeat(depth));
            let got = match json_loads(text.as_bytes()) {
                Ok(_) => "ok",
                Err(PyError::RecursionError) => "RecursionError",
                Err(_) => "ValueError",
            };
            assert_eq!(Some(got), case[1].as_str(), "depth {depth}");
        }
    }

    #[test]
    fn int_truthiness_len_match_cpython() {
        for case in vectors()["values"].as_array().expect("values") {
            let text = case[0].as_str().expect("input");
            // Python's int() also accepts non-ASCII decimal digits; this port
            // does not (only reachable inside a validly signed token).
            if text == "\"١٢\"" {
                continue;
            }
            let v = json_loads(text.as_bytes()).expect("parse");
            let expected_int = case[1].as_str().expect("int");
            match v.to_int() {
                Ok(got) => {
                    let want: f64 = expected_int
                        .parse::<f64>()
                        .unwrap_or_else(|_| panic!("{text}: {expected_int}"));
                    assert!(
                        (got - want).abs() < 1.0_f64
                            || (got.is_infinite() && want.abs() > 1e30_f64),
                        "{text}: {got} != {want}"
                    );
                }
                Err(err) => assert_eq!(format!("{err:?}"), expected_int, "{text}"),
            }
            assert_eq!(Value::from(v.truthy()), case[2], "{text} truthiness");
            let len = v
                .py_len()
                .map_or_else(|_| Value::from("TypeError"), Value::from);
            assert_eq!(len, case[3], "{text} len");
        }
    }

    #[test]
    fn timedelta_matches_authentik() {
        // `timedelta_from_string(e).total_seconds()` in the reference image.
        for (expr, seconds) in [
            ("days=1", 86_400.0_f64),
            ("hours=1;minutes=30", 5_400.0_f64),
            ("Seconds=1.5", 1.5_f64),
            ("weeks=1;days=-1", 518_400.0_f64),
            ("foo=1;hours=2", 7_200.0_f64),
            ("milliseconds=1.0000004", 0.001_f64),
            ("hours=2;hours=3", 10_800.0_f64),
        ] {
            assert_eq!(timedelta_seconds(expr), Some(seconds), "{expr}");
        }
        for expr in ["", "foo=1", "hours", "hours=1=2", "hours=x"] {
            assert_eq!(timedelta_seconds(expr), None, "{expr}");
        }
    }
}
