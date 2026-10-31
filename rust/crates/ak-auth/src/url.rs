//! The URL handling Django's CSRF and redirect code relies on.
//!
//! `CPython` 3.14's `urlsplit`, `SplitResult.geturl()` (`urlunsplit`) and
//! `quote`, plus Django's `escape_uri_path`, `iri_to_uri` and
//! `repercent_broken_unicode`.

use unicode_normalization::UnicodeNormalization as _;

/// `_WHATWG_C0_CONTROL_OR_SPACE`.
fn is_c0_or_space(c: char) -> bool {
    c <= ' '
}

/// `scheme_chars`.
fn is_scheme_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.')
}

/// `uses_netloc`.
const USES_NETLOC: [&str; 27] = [
    "",
    "ftp",
    "http",
    "gopher",
    "nntp",
    "telnet",
    "imap",
    "wais",
    "file",
    "mms",
    "https",
    "shttp",
    "snews",
    "prospero",
    "rtsp",
    "rtsps",
    "rtspu",
    "rsync",
    "svn",
    "svn+ssh",
    "sftp",
    "nfs",
    "git",
    "git+ssh",
    "ws",
    "wss",
    "itms-services",
];

/// `urlsplit`'s `ValueError`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidUrl;

/// `SplitResult`: missing components are empty strings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SplitResult {
    pub scheme: String,
    pub netloc: String,
    pub path: String,
    pub query: String,
    pub fragment: String,
}

/// `_splitnetloc(url, 2)`.
fn split_netloc(url: &str) -> (&str, &str) {
    let rest = &url[2..];
    let delim = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    (&rest[..delim], &rest[delim..])
}

/// `ipaddress.ip_address(s)`: `Some(true)` for IPv4, `Some(false)` for IPv6.
fn ip_version_is_v4(s: &str) -> Option<bool> {
    if s.parse::<std::net::Ipv4Addr>().is_ok() {
        return Some(true);
    }
    if s.contains('/') {
        return None;
    }
    let addr = match s.split_once('%') {
        Some((_, scope)) if scope.is_empty() || scope.contains('%') => return None,
        Some((addr, _)) => addr,
        None => s,
    };
    addr.parse::<std::net::Ipv6Addr>().ok().map(|_| false)
}

/// `_check_bracketed_host`.
fn check_bracketed_host(hostname: &str) -> Result<(), InvalidUrl> {
    if let Some(rest) = hostname.strip_prefix('v') {
        // `\Av[a-fA-F0-9]+\..+\z`
        let hex = rest
            .find(|c: char| !c.is_ascii_hexdigit())
            .unwrap_or(rest.len());
        return match rest[hex..].strip_prefix('.') {
            Some(tail) if hex > 0 && !tail.is_empty() => Ok(()),
            _ => Err(InvalidUrl),
        };
    }
    match ip_version_is_v4(hostname) {
        Some(false) => Ok(()),
        _ => Err(InvalidUrl),
    }
}

/// `_check_bracketed_netloc`.
fn check_bracketed_netloc(netloc: &str) -> Result<(), InvalidUrl> {
    let host_port = netloc.rsplit_once('@').map_or(netloc, |(_, h)| h);
    let hostname = if let Some((before, bracketed)) = host_port.split_once('[') {
        if !before.is_empty() {
            return Err(InvalidUrl);
        }
        let (hostname, port) = bracketed.split_once(']').unwrap_or((bracketed, ""));
        if !port.is_empty() && !port.starts_with(':') {
            return Err(InvalidUrl);
        }
        hostname
    } else {
        host_port.split_once(':').map_or(host_port, |(h, _)| h)
    };
    check_bracketed_host(hostname)
}

/// `_checknetloc`: characters that NFKC-normalize into URL delimiters.
fn check_netloc(netloc: &str) -> Result<(), InvalidUrl> {
    if netloc.is_ascii() {
        return Ok(());
    }
    let n: String = netloc
        .chars()
        .filter(|c| !matches!(c, '@' | ':' | '#' | '?'))
        .collect();
    let normalized: String = n.nfkc().collect();
    if n == normalized {
        return Ok(());
    }
    if normalized.contains(['/', '?', '#', '@', ':']) {
        return Err(InvalidUrl);
    }
    Ok(())
}

/// `urllib.parse.urlsplit(url)`.
///
/// # Errors
///
/// [`InvalidUrl`] where Python raises `ValueError`.
pub fn urlsplit(url: &str) -> Result<SplitResult, InvalidUrl> {
    let url: String = url
        .trim_start_matches(is_c0_or_space)
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut url = url.as_str();
    let mut out = SplitResult::default();
    if let Some(i) = url.find(':')
        && i > 0
        && url.starts_with(|c: char| c.is_ascii_alphabetic())
        && url[..i].chars().all(is_scheme_char)
    {
        out.scheme = url[..i].to_ascii_lowercase();
        url = &url[i + 1..];
    }
    if url.starts_with("//") {
        let (netloc, rest) = split_netloc(url);
        if netloc.contains('[') != netloc.contains(']') {
            return Err(InvalidUrl);
        }
        if netloc.contains('[') {
            check_bracketed_netloc(netloc)?;
        }
        netloc.clone_into(&mut out.netloc);
        url = rest;
    }
    if let Some((path, fragment)) = url.split_once('#') {
        fragment.clone_into(&mut out.fragment);
        url = path;
    }
    if let Some((path, query)) = url.split_once('?') {
        query.clone_into(&mut out.query);
        url = path;
    }
    url.clone_into(&mut out.path);
    check_netloc(&out.netloc)?;
    Ok(out)
}

impl SplitResult {
    /// `SplitResult.geturl()`, i.e. `urlunsplit(self)`.
    #[must_use]
    pub fn geturl(&self) -> String {
        let netloc = if !self.netloc.is_empty() {
            Some(self.netloc.as_str())
        } else if !self.scheme.is_empty()
            && USES_NETLOC.contains(&self.scheme.as_str())
            && (self.path.is_empty() || self.path.starts_with('/'))
        {
            Some("")
        } else {
            None
        };
        let mut url = self.path.clone();
        if let Some(netloc) = netloc {
            if !url.is_empty() && !url.starts_with('/') {
                url.insert(0, '/');
            }
            url = format!("//{netloc}{url}");
        } else if url.starts_with("//") {
            url = format!("//{url}");
        }
        if !self.scheme.is_empty() {
            url = format!("{}:{url}", self.scheme);
        }
        if !self.query.is_empty() {
            url = format!("{url}?{}", self.query);
        }
        if !self.fragment.is_empty() {
            url = format!("{url}#{}", self.fragment);
        }
        url
    }
}

/// `urllib.parse.quote(bytes, safe)`: `_ALWAYS_SAFE` plus `safe` stay,
/// everything else becomes `%XX`.
#[must_use]
pub fn quote(bytes: &[u8], safe: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if b.is_ascii_alphanumeric() || b"_.-~".contains(&b) || safe.contains(&b) {
            out.push(char::from(b));
        } else {
            use std::fmt::Write as _;
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// Django's `repercent_broken_unicode`: every byte sequence that is not
/// valid UTF-8 is percent-encoded, as `UnicodeDecodeError` delimits it.
#[must_use]
pub fn repercent_broken_unicode(mut path: &[u8]) -> String {
    let mut out = String::new();
    loop {
        match std::str::from_utf8(path) {
            Ok(valid) => {
                out.push_str(valid);
                return out;
            }
            Err(err) => {
                let start = err.valid_up_to();
                let end = err.error_len().map_or(path.len(), |len| start + len);
                out.push_str(std::str::from_utf8(&path[..start]).unwrap_or_default());
                out.push_str(&quote(&path[start..end], b"/#%[]=:;$&()+,!?*@'~"));
                path = &path[end..];
            }
        }
    }
}

/// Django's `escape_uri_path`.
#[must_use]
pub fn escape_uri_path(path: &str) -> String {
    quote(path.as_bytes(), b"/:@&+$,-_.!~*'()")
}

/// Django's `iri_to_uri`.
#[must_use]
pub fn iri_to_uri(iri: &str) -> String {
    quote(iri.as_bytes(), b"/#%[]=:;$&()+,!?*@'~")
}

/// `HttpRequest.get_full_path()`: `path` is the decoded `request.path`,
/// `query_string` the WSGI `QUERY_STRING` (raw bytes as Latin-1).
#[must_use]
pub fn get_full_path(path: &str, query_string: &str) -> String {
    if query_string.is_empty() {
        escape_uri_path(path)
    } else {
        format!("{}?{}", escape_uri_path(path), iri_to_uri(query_string))
    }
}

/// The request's decoded `path_info` as gunicorn and Django derive it from
/// the raw request path: `unquote_to_bytes`, then `repercent_broken_unicode`.
#[must_use]
pub fn path_info(raw_path: &[u8]) -> String {
    let mut bytes = Vec::with_capacity(raw_path.len());
    let mut i = 0;
    while i < raw_path.len() {
        let hex = |b: u8| {
            let digit = char::from(b).to_digit(16)?;
            u8::try_from(digit).ok()
        };
        if raw_path[i] == b'%'
            && let (Some(&h), Some(&l)) = (raw_path.get(i + 1), raw_path.get(i + 2))
            && let (Some(h), Some(l)) = (hex(h), hex(l))
        {
            bytes.push(h << 4_u8 | l);
            i += 3;
        } else {
            bytes.push(raw_path[i]);
            i += 1;
        }
    }
    let path = repercent_broken_unicode(&bytes);
    if path.is_empty() {
        "/".to_owned()
    } else {
        path
    }
}

/// `request.path` from `path_info` with an empty `SCRIPT_NAME`:
/// `"/" + path_info.replace("/", "", 1)`.
#[must_use]
pub fn request_path(path_info: &str) -> String {
    format!("/{}", path_info.replacen('/', "", 1))
}

/// `QueryDict` with one key, `urlencode(safe="/")`.
#[must_use]
pub fn urlencode_pair(key: &str, value: &str) -> String {
    format!(
        "{}={}",
        quote(key.as_bytes(), b"/"),
        quote(value.as_bytes(), b"/")
    )
}

/// `redirect_to_login(next)` with authentik's `LOGIN_URL`
/// (`authentik_flows:default-authentication` under `web.path`): the
/// `Location` of the 302.
#[must_use]
pub fn login_redirect(web_path: &str, next: &str) -> String {
    format!(
        "{web_path}flows/-/default/authentication/?{}",
        urlencode_pair("next", next)
    )
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../testdata/python_vectors.json")).expect("vectors")
    }

    #[test]
    fn urlsplit_matches_cpython() {
        let v = vectors();
        let cases = v["urlsplit"].as_array().expect("urlsplit");
        for case in cases {
            let url = case[0].as_str().expect("url");
            let got = match urlsplit(url) {
                Ok(r) => {
                    let geturl = r.geturl();
                    serde_json::json!([r.scheme, r.netloc, r.path, r.query, r.fragment, geturl])
                }
                Err(InvalidUrl) => serde_json::json!("ValueError"),
            };
            assert_eq!(got, case[1], "urlsplit({url:?})");
        }
        assert!(cases.len() > 400);
    }

    #[test]
    fn quote_matches_cpython() {
        for case in vectors()["quote"].as_array().expect("quote") {
            let hex = case[0].as_str().expect("hex");
            let bytes: Vec<u8> = (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
                .collect();
            let safe = case[1].as_str().expect("safe").as_bytes();
            assert_eq!(quote(&bytes, safe), case[2], "quote({hex}, {safe:?})");
        }
    }
}
