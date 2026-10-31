//! The `CPython` and Django text semantics the read API depends on.
//!
//! Query string parsing (`QueryDict`), `str.strip()`, `int(str)`,
//! `Decimal(str)` truncated by `int()`, `uuid.UUID(hex=…)` and
//! `smart_split`.
//!
//! Where Python accepts input these ports do not model (non-ASCII digits,
//! `int()`'s underscores inside a UUID), they return [`Unsupported`] so the
//! request is left to Django instead of being answered differently.

use ak_auth::python::isspace;
use uuid::Uuid;

/// Input Python accepts in a way not reproduced here: decline the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unsupported;

/// Django's `QueryDict(query_string)`.
///
/// That is `parse_qsl(keep_blank_values=True, encoding="utf-8",
/// errors="replace")`, `&` as the only separator, `+` as space, and the
/// `DATA_UPLOAD_MAX_NUMBER_FIELDS` (1000) limit.
#[derive(Debug, Clone, Default)]
pub struct QueryDict {
    items: Vec<(String, String)>,
}

/// More fields than `DATA_UPLOAD_MAX_NUMBER_FIELDS`: Django raises
/// `TooManyFieldsSent` (a 400 the read API leaves to Django).
const MAX_NUMBER_FIELDS: usize = 1000;

fn unquote_plus(s: &str) -> String {
    let replaced = s.replace('+', " ");
    percent_encoding::percent_decode_str(&replaced)
        .decode_utf8_lossy()
        .into_owned()
}

impl QueryDict {
    /// # Errors
    ///
    /// [`Unsupported`] past Django's field limit.
    pub fn parse(query: &str) -> Result<Self, Unsupported> {
        // `parse_qsl` counts `1 + qs.count("&")` before splitting.
        if 1 + query.matches('&').count() > MAX_NUMBER_FIELDS {
            return Err(Unsupported);
        }
        let mut items = Vec::new();
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            items.push((unquote_plus(name), unquote_plus(value)));
        }
        Ok(Self { items })
    }

    /// `QueryDict.get(key)`: the last value.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.items
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    /// `QueryDict.getlist(key)`.
    pub fn getlist(&self, key: &str) -> Vec<&str> {
        self.items
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn contains(&self, key: &str) -> bool {
        self.items.iter().any(|(k, _)| k == key)
    }
}

/// `str.strip()`.
pub fn strip(s: &str) -> &str {
    s.trim_matches(isspace)
}

/// An `int` that may not fit: `Big` keeps its sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PyInt {
    Small(i64),
    Big { negative: bool },
}

impl PyInt {
    pub fn is_negative(self) -> bool {
        match self {
            Self::Small(v) => v < 0,
            Self::Big { negative } => negative,
        }
    }
}

/// Digits with PEP 515 underscores (only between digits).
fn digits_with_underscores(s: &str) -> Option<String> {
    if s.is_empty() || s.starts_with('_') || s.ends_with('_') || s.contains("__") {
        return None;
    }
    let digits: String = s.chars().filter(|&c| c != '_').collect();
    digits.chars().all(|c| c.is_ascii_digit()).then_some(digits)
}

/// `int(s)` for a `str`.
///
/// # Errors
///
/// `Ok(None)` is Python's `ValueError`; [`Unsupported`] for non-ASCII
/// digits, which `int()` accepts.
pub fn py_int(s: &str) -> Result<Option<PyInt>, Unsupported> {
    let s = strip(s);
    if s.chars().any(|c| !c.is_ascii() && c.is_numeric()) {
        return Err(Unsupported);
    }
    let (negative, body) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let Some(digits) = digits_with_underscores(body) else {
        return Ok(None);
    };
    let trimmed = digits.trim_start_matches('0');
    if trimmed.len() > 18 {
        return Ok(Some(PyInt::Big { negative }));
    }
    let value: i64 = if trimmed.is_empty() {
        0
    } else {
        trimmed.parse().map_err(|_| Unsupported)?
    };
    Ok(Some(PyInt::Small(if negative { -value } else { value })))
}

/// `float(1e50)` exactly: django-filter's `NumberFilter` adds
/// `MaxValueValidator(1e50)`, and `Decimal > float` compares exactly.
const FLOAT_1E50: &str = "100000000000000007629769841091887003294964970946560";

/// A finite `Decimal(s)`: its integer part (no leading zeros) and whether
/// a non-zero fraction follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyDecimal {
    pub negative: bool,
    pub int_digits: String,
    pub has_fraction: bool,
}

impl PyDecimal {
    /// `int(value)`: truncated toward zero.
    pub fn to_int(&self) -> PyInt {
        if self.int_digits.len() > 18 {
            return PyInt::Big {
                negative: self.negative,
            };
        }
        let value: i64 = if self.int_digits.is_empty() {
            0
        } else {
            self.int_digits.parse().unwrap_or(i64::MAX)
        };
        PyInt::Small(if self.negative { -value } else { value })
    }

    /// `value > 1e50` (`MaxValueValidator.compare`).
    pub fn exceeds_1e50(&self) -> bool {
        if self.negative {
            return false;
        }
        let limit = FLOAT_1E50;
        match self.int_digits.len().cmp(&limit.len()) {
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => false,
            std::cmp::Ordering::Equal => match self.int_digits.as_str().cmp(limit) {
                std::cmp::Ordering::Greater => true,
                std::cmp::Ordering::Equal => self.has_fraction,
                std::cmp::Ordering::Less => false,
            },
        }
    }
}

/// `Decimal(s)` for `forms.DecimalField`: `Ok(None)` when it raises or is
/// not finite (both "Enter a number.").
///
/// # Errors
///
/// [`Unsupported`] for non-ASCII digits.
pub fn py_decimal(s: &str) -> Result<Option<PyDecimal>, Unsupported> {
    let s = strip(s);
    if s.chars().any(|c| !c.is_ascii() && c.is_numeric()) {
        return Err(Unsupported);
    }
    let (negative, body) = match s.as_bytes().first() {
        Some(b'-') => (true, &s[1..]),
        Some(b'+') => (false, &s[1..]),
        _ => (false, s),
    };
    let lower = body.to_ascii_lowercase();
    if matches!(lower.as_str(), "inf" | "infinity")
        || lower.starts_with("nan")
        || lower.starts_with("snan")
    {
        // Parses, but `is_finite()` is false; a malformed NaN payload is a
        // parse error with the same message.
        return Ok(None);
    }
    let (mantissa, exponent) = match lower.split_once('e') {
        Some((m, e)) => {
            let (exp_negative, exp_digits) = match e.as_bytes().first() {
                Some(b'-') => (true, &e[1..]),
                Some(b'+') => (false, &e[1..]),
                _ => (false, e),
            };
            let Some(exp_digits) = digits_with_underscores(exp_digits) else {
                return Ok(None);
            };
            let exp_digits = exp_digits.trim_start_matches('0');
            // Exponents this large only matter through their sign.
            let exp: i64 = if exp_digits.len() > 12 {
                1_000_000_000_000
            } else if exp_digits.is_empty() {
                0
            } else {
                exp_digits.parse().map_err(|_| Unsupported)?
            };
            (m, if exp_negative { -exp } else { exp })
        }
        None => (lower.as_str(), 0),
    };
    let (int_part, frac_part) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if int_part.is_empty() && frac_part.is_empty() {
        return Ok(None);
    }
    let parse = |part: &str| {
        if part.is_empty() {
            Some(String::new())
        } else {
            digits_with_underscores(part)
        }
    };
    let (Some(int_digits), Some(frac_digits)) = (parse(int_part), parse(frac_part)) else {
        return Ok(None);
    };
    let all = format!("{int_digits}{frac_digits}");
    let all = all.trim_start_matches('0');
    if all.is_empty() {
        return Ok(Some(PyDecimal {
            negative,
            int_digits: String::new(),
            has_fraction: false,
        }));
    }
    // Position of the decimal point within `all` (after dropping leading
    // zeros, which only shift digits left of the point).
    let lead = format!("{int_digits}{frac_digits}").len() - all.len();
    let point = i64::try_from(int_digits.len()).map_err(|_| Unsupported)?
        - i64::try_from(lead).map_err(|_| Unsupported)?
        + exponent;
    let digits = i64::try_from(all.len()).map_err(|_| Unsupported)?;
    if point <= 0 {
        return Ok(Some(PyDecimal {
            negative,
            int_digits: String::new(),
            has_fraction: true,
        }));
    }
    if point > 1000 {
        // Far past any limit: a digit string that long compares the same.
        return Ok(Some(PyDecimal {
            negative,
            int_digits: "9".repeat(1001),
            has_fraction: false,
        }));
    }
    let point_usize = usize::try_from(point).map_err(|_| Unsupported)?;
    let (int_digits, has_fraction) = if point >= digits {
        (
            format!("{all}{}", "0".repeat(point_usize - all.len())),
            false,
        )
    } else {
        let (i, f) = all.split_at(point_usize);
        (i.to_owned(), f.bytes().any(|b| b != b'0'))
    };
    Ok(Some(PyDecimal {
        negative,
        int_digits,
        has_fraction,
    }))
}

/// The value an `IntegerField`/`AutoField` lookup can match: Django turns
/// an out-of-range value into an empty result (`IntegerFieldOverflow`).
pub fn int4(value: PyInt) -> Option<i32> {
    match value {
        PyInt::Small(v) => i32::try_from(v).ok(),
        PyInt::Big { .. } => None,
    }
}

/// `uuid.UUID(hex=s)` as Django's `UUIDField.to_python` calls it.
///
/// # Errors
///
/// `Ok(None)` cannot happen: anything that is not a plain 32-digit hex
/// UUID (with optional braces, dashes and `urn:`/`uuid:` text) returns
/// [`Unsupported`], since Django then either raises (a 500 for the query
/// filters) or accepts `int(…, 16)` syntax that is not reproduced.
pub fn py_uuid(s: &str) -> Result<Uuid, Unsupported> {
    let hex = s.replace("urn:", "").replace("uuid:", "");
    let hex = hex.trim_matches(['{', '}']).replace('-', "");
    if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Unsupported);
    }
    Uuid::parse_str(&hex).map_err(|_| Unsupported)
}

/// How Django's `queryset.get(pk=value)` reads a `UUIDField` lookup value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UuidLookup {
    Valid(Uuid),
    /// `uuid.UUID(hex=…)` raises: DRF's `get_object_or_404` answers
    /// "Not found.", a `ModelChoiceField` "Select a valid choice."
    Invalid,
}

/// `uuid.UUID(hex=value)` for a lookup value.
///
/// # Errors
///
/// [`Unsupported`] for 32 characters of `int(…, 16)` syntax (signs,
/// underscores, spaces), which `uuid` may accept.
pub fn uuid_lookup(value: &str) -> Result<UuidLookup, Unsupported> {
    if let Ok(uuid) = py_uuid(value) {
        return Ok(UuidLookup::Valid(uuid));
    }
    // After the replacements anything but 32 characters is a ValueError.
    let hex = value.replace("urn:", "").replace("uuid:", "");
    let hex = hex.trim_matches(['{', '}']).replace('-', "");
    if hex.chars().count() != 32
        || !hex
            .chars()
            .all(|c| c.is_ascii_hexdigit() || matches!(c, '_' | '+' | '-' | ' '))
    {
        return Ok(UuidLookup::Invalid);
    }
    Err(Unsupported)
}

/// `django.utils.text.smart_split`: whitespace-separated bits, keeping
/// quoted phrases (with backslash escapes) together.
pub fn smart_split(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        if isspace(chars[i]) {
            i += 1;
            continue;
        }
        // Try the quoted alternative: [^\s'"]* ( quoted [^\s'"]* )+
        if let Some(end) = match_quoted_bit(&chars, i) {
            out.push(chars[i..end].iter().collect());
            i = end;
            continue;
        }
        // \S+
        let start = i;
        while i < chars.len() && !isspace(chars[i]) {
            i += 1;
        }
        out.push(chars[start..i].iter().collect());
    }
    out
}

fn is_plain(c: char) -> bool {
    !isspace(c) && c != '\'' && c != '"'
}

/// End of `[^\s'"]* (?:("…"|'…')[^\s'"]*)+` starting at `start`, if it
/// matches (at least one quoted group).
fn match_quoted_bit(chars: &[char], start: usize) -> Option<usize> {
    let mut i = start;
    while i < chars.len() && is_plain(chars[i]) {
        i += 1;
    }
    let mut groups = 0_usize;
    while let Some(&quote) = chars.get(i) {
        if quote != '"' && quote != '\'' {
            break;
        }
        let mut j = i + 1;
        let mut closed = false;
        while j < chars.len() {
            match chars[j] {
                '\\' if j + 1 < chars.len() => j += 2,
                c if c == quote => {
                    closed = true;
                    break;
                }
                _ => j += 1,
            }
        }
        if !closed {
            break;
        }
        i = j + 1;
        while i < chars.len() && is_plain(chars[i]) {
            i += 1;
        }
        groups += 1_usize;
    }
    (groups > 0).then_some(i)
}

/// `django.utils.text.unescape_string_literal` (callers check the quotes).
pub fn unescape_string_literal(s: &str) -> String {
    let quote = s.chars().next().unwrap_or('"');
    let inner: String = s
        .chars()
        .skip(1)
        .take(s.chars().count().saturating_sub(2))
        .collect();
    inner
        .replace(&format!("\\{quote}"), &quote.to_string())
        .replace("\\\\", "\\")
}

/// DRF's `search_smart_split`.
pub fn search_smart_split(search_terms: &str) -> Vec<String> {
    let mut split = Vec::new();
    for term in smart_split(search_terms) {
        let term = term.trim_matches(',');
        let first = term.chars().next();
        let last = term.chars().last();
        if matches!(first, Some('"' | '\'')) && first == last {
            split.push(unescape_string_literal(term));
        } else {
            for sub in term.split(',') {
                if !sub.is_empty() {
                    split.push(strip(sub).to_owned());
                }
            }
        }
    }
    split
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_dict_matches_django() {
        let q = QueryDict::parse("a=1&a=2&b=&c&d=x+y%20z&e=%FF").expect("parse");
        assert_eq!(q.get("a"), Some("2"));
        assert_eq!(q.getlist("a"), vec!["1", "2"]);
        assert_eq!(q.get("b"), Some(""));
        assert_eq!(q.get("c"), Some(""));
        assert_eq!(q.get("d"), Some("x y z"));
        assert_eq!(q.get("e"), Some("\u{fffd}"));
        QueryDict::parse(&"&".repeat(999)).expect("999 separators are 1000 fields");
        assert!(matches!(
            QueryDict::parse(&"&".repeat(1000)),
            Err(Unsupported)
        ));
    }

    #[test]
    fn ints_match_python() {
        assert_eq!(py_int(" 4"), Ok(Some(PyInt::Small(4))));
        assert_eq!(py_int("+1_0"), Ok(Some(PyInt::Small(10))));
        assert_eq!(py_int("1__0"), Ok(None));
        assert_eq!(py_int("2.0"), Ok(None));
        assert_eq!(py_int(""), Ok(None));
        assert_eq!(py_int("-0"), Ok(Some(PyInt::Small(0))));
        assert_eq!(
            py_int("99999999999999999999"),
            Ok(Some(PyInt::Big { negative: false }))
        );
        assert_eq!(py_int("\u{0663}"), Err(Unsupported));
    }

    #[test]
    fn decimals_truncate_like_python() {
        let d = |s| py_decimal(s).expect("ascii").map(|d| d.to_int());
        assert_eq!(d("1.5"), Some(PyInt::Small(1)));
        assert_eq!(d("-1.9"), Some(PyInt::Small(-1)));
        assert_eq!(d("1e3"), Some(PyInt::Small(1000)));
        assert_eq!(d(".5"), Some(PyInt::Small(0)));
        assert_eq!(d("5."), Some(PyInt::Small(5)));
        assert_eq!(d("12e-1"), Some(PyInt::Small(1)));
        assert_eq!(d("1_000"), Some(PyInt::Small(1000)));
        assert_eq!(d("007"), Some(PyInt::Small(7)));
        assert_eq!(d("0.0012e3"), Some(PyInt::Small(1)));
        assert_eq!(d("Infinity"), None);
        assert_eq!(d("nan"), None);
        assert_eq!(d("abc"), None);
        assert_eq!(d("."), None);
        assert_eq!(d("1e400"), Some(PyInt::Big { negative: false }));
    }

    #[test]
    fn max_value_matches_float_1e50() {
        let x = |s| {
            py_decimal(s)
                .expect("ascii")
                .expect("finite")
                .exceeds_1e50()
        };
        assert!(!x("1e50"));
        assert!(!x("100000000000000007629769841091887003294964970946560"));
        assert!(x("100000000000000007629769841091887003294964970946560.1"));
        assert!(x("100000000000000007629769841091887003294964970946561"));
        assert!(x("1e400"));
        assert!(!x("-1e400"));
    }

    #[test]
    fn search_split_matches_drf() {
        assert_eq!(search_smart_split("dup a"), vec!["dup", "a"]);
        assert_eq!(search_smart_split("m6,dup"), vec!["m6", "dup"]);
        assert_eq!(search_smart_split("\"m6-dup\""), vec!["m6-dup"]);
        assert_eq!(search_smart_split("'a b' c"), vec!["a b", "c"]);
        assert_eq!(search_smart_split(",,"), Vec::<String>::new());
        assert_eq!(
            smart_split(r#"A "\"funky\" style" test."#),
            vec!["A", r#""\"funky\" style""#, "test."]
        );
    }

    #[test]
    fn uuids_match_python() {
        let want = Uuid::parse_str("a6b31a8e-78a4-4fd4-a1fd-3f65ab4b6aa8").expect("uuid");
        assert_eq!(py_uuid("a6b31a8e-78a4-4fd4-a1fd-3f65ab4b6aa8"), Ok(want));
        assert_eq!(py_uuid("{A6B31A8E78A44FD4A1FD3F65AB4B6AA8}"), Ok(want));
        assert_eq!(
            py_uuid("urn:uuid:a6b31a8e-78a4-4fd4-a1fd-3f65ab4b6aa8"),
            Ok(want)
        );
        assert_eq!(py_uuid("not-a-uuid"), Err(Unsupported));
    }
}
