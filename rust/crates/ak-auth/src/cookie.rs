//! Response cookies as 2026.2.7 sets them.
//!
//! Django's `set_cookie` / `delete_cookie` rendered by Python's
//! `http.cookies.Morsel`, authentik's `SessionMiddleware.process_response`
//! (the JWT session cookie, `SameSite` by TLS) and
//! `CsrfViewMiddleware._set_csrf_cookie`.

use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::{Digest as _, Sha256};

use crate::{
    csrf::{CSRF_COOKIE_AGE, CSRF_COOKIE_NAME, CsrfState},
    python::isspace,
    session::{SESSION_COOKIE_NAME, signing_hash},
};

/// `http.cookies._LegalChars`.
fn is_legal_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~:".contains(c)
}

/// `http.cookies._quote(value)`.
fn quote(value: &str) -> String {
    if !value.is_empty() && value.chars().all(is_legal_char) {
        return value.to_owned();
    }
    let mut out = String::from("\"");
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0}'..='\u{1f}' | ',' | ';' | '\u{7f}'..='\u{ff}' => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\{:03o}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `django.utils.http.http_date(epoch_seconds)` (`formatdate(usegmt=True)`).
#[must_use]
pub fn http_date(epoch_seconds: f64) -> String {
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "time.gmtime floors"
    )]
    let secs = epoch_seconds.floor() as i64;
    DateTime::<Utc>::from_timestamp(secs, 0)
        .unwrap_or_default()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

/// `http.cookies.CookieError`: Python refuses control characters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CookieError;

/// A Django `set_cookie` call.
#[derive(Debug, Clone, Default)]
pub struct Cookie {
    pub name: String,
    pub value: String,
    /// `max_age` seconds (`int()` truncates).
    pub max_age: Option<f64>,
    /// `expires` as given (a string); `None` is `""`.
    pub expires: Option<String>,
    pub path: Option<String>,
    pub domain: Option<String>,
    pub secure: bool,
    pub httponly: bool,
    pub samesite: Option<&'static str>,
}

impl Cookie {
    /// `Morsel.OutputString()` after `set_cookie`, at time `now`: the
    /// `Set-Cookie` value. Attributes come out sorted by their lowercase
    /// name, empty ones skipped.
    ///
    /// # Errors
    ///
    /// [`CookieError`] for a control character in the value or an attribute.
    pub fn output(&self, now: f64) -> Result<String, CookieError> {
        let has_control = |s: &str| s.chars().any(|c| c <= '\u{1f}' || c == '\u{7f}');
        if [
            Some(self.value.as_str()),
            self.path.as_deref(),
            self.domain.as_deref(),
            self.expires.as_deref(),
        ]
        .into_iter()
        .flatten()
        .any(has_control)
        {
            return Err(CookieError);
        }
        let mut expires = self.expires.clone().unwrap_or_default();
        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            reason = "int(max_age)"
        )]
        let max_age = self.max_age.map(|m| m.trunc() as i64);
        if let Some(seconds) = self.max_age
            && expires.is_empty()
        {
            expires = http_date(now + seconds);
        }
        let mut parts = vec![format!("{}={}", self.name, quote(&self.value))];
        // Sorted: domain, expires, httponly, max-age, path, samesite, secure.
        if let Some(domain) = self.domain.as_deref().filter(|d| !d.is_empty()) {
            parts.push(format!("Domain={domain}"));
        }
        if !expires.is_empty() {
            parts.push(format!("expires={expires}"));
        }
        if self.httponly {
            parts.push("HttpOnly".to_owned());
        }
        if let Some(max_age) = max_age {
            parts.push(format!("Max-Age={max_age}"));
        }
        if let Some(path) = self.path.as_deref().filter(|p| !p.is_empty()) {
            parts.push(format!("Path={path}"));
        }
        if let Some(samesite) = self.samesite {
            parts.push(format!("SameSite={samesite}"));
        }
        if self.secure {
            parts.push("Secure".to_owned());
        }
        Ok(parts.join("; "))
    }

    /// `delete_cookie(name, path, domain, samesite)`.
    #[must_use]
    pub fn delete(
        name: &str,
        path: &str,
        domain: Option<&str>,
        samesite: Option<&'static str>,
    ) -> Self {
        Self {
            name: name.to_owned(),
            value: String::new(),
            max_age: Some(0.0),
            expires: Some("Thu, 01 Jan 1970 00:00:00 GMT".to_owned()),
            path: Some(path.to_owned()),
            domain: domain.map(str::to_owned),
            secure: name.starts_with("__Secure-")
                || name.starts_with("__Host-")
                || samesite.is_some_and(|s| s.eq_ignore_ascii_case("none")),
            httponly: false,
            samesite,
        }
    }
}

/// `patch_vary_headers(response, newheaders)`: the new `Vary` value.
#[must_use]
pub fn patch_vary_headers(existing: Option<&str>, new: &[&str]) -> String {
    // `cc_delim_re.split(value)`, `cc_delim_re = r"\s*,\s*"`: whitespace
    // around commas goes, the ends keep theirs.
    let mut headers: Vec<String> = existing.map_or_else(Vec::new, |value| {
        let parts: Vec<&str> = value.split(',').collect();
        let last = parts.len() - 1;
        parts
            .iter()
            .enumerate()
            .map(|(i, part)| {
                let part = if i == 0 {
                    part
                } else {
                    part.trim_start_matches(isspace)
                };
                let part = if i == last {
                    part
                } else {
                    part.trim_end_matches(isspace)
                };
                part.to_owned()
            })
            .collect()
    });
    let lower: Vec<String> = headers.iter().map(|h| h.to_lowercase()).collect();
    for header in new {
        if !lower.contains(&header.to_lowercase()) {
            headers.push((*header).to_owned());
        }
    }
    if headers.iter().any(|h| h == "*") {
        "*".to_owned()
    } else {
        headers.join(", ")
    }
}

/// `SessionMiddleware.is_secure(request)`.
#[must_use]
pub fn session_is_secure(
    request_secure: bool,
    host: Option<&str>,
    debug: bool,
    user_agent: &str,
) -> bool {
    if request_secure {
        return true;
    }
    let host = host.map_or("", |h| h.split(':').next().unwrap_or_default());
    if host == "localhost" && debug {
        let lower = user_agent.to_lowercase();
        return !(user_agent.starts_with("goauthentik.io/outpost/")
            || (lower.contains("safari") && !lower.contains("chrome")));
    }
    false
}

/// `User.uid`: `sha256(f"{id}-{get_unique_identifier()}")`.
#[must_use]
pub fn user_uid(user_id: i32, unique_identifier: &str) -> String {
    Sha256::digest(format!("{user_id}-{unique_identifier}").as_bytes())
        .iter()
        .fold(String::new(), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        })
}

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// `json.dumps(s)` with `ensure_ascii`.
fn json_str(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::from("\"");
    for unit in s.encode_utf16() {
        match unit {
            0x22 => out.push_str("\\\""),
            0x5c => out.push_str("\\\\"),
            0x0a => out.push_str("\\n"),
            0x0d => out.push_str("\\r"),
            0x09 => out.push_str("\\t"),
            0x08 => out.push_str("\\b"),
            0x0c => out.push_str("\\f"),
            0x20..=0x7e => out.push(char::from(u8::try_from(unit).unwrap_or(b'?'))),
            _ => {
                let _ = write!(out, "\\u{unit:04x}");
            }
        }
    }
    out.push('"');
    out
}

/// `SessionMiddleware.encode_session(session_key, user)`: `PyJWT`'s HS256
/// encoding of `{"sid", "iss", "sub", "authenticated", "acr"}`, `sub` the
/// user's `uid` when authenticated.
#[must_use]
pub fn encode_session(session_key: &str, user_uid: Option<&str>, secret_key: &str) -> String {
    let payload = format!(
        "{{\"sid\":{},\"iss\":\"authentik\",\"sub\":{},\"authenticated\":{},\"acr\":\"goauthentik.\
         io/core/default\"}}",
        json_str(session_key),
        json_str(user_uid.unwrap_or("anonymous")),
        if user_uid.is_some() { "true" } else { "false" },
    );
    let signing_input = format!(
        "{}.{}",
        b64url(br#"{"alg":"HS256","typ":"JWT"}"#),
        b64url(payload.as_bytes())
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(signing_hash(secret_key).as_bytes())
        .unwrap_or_else(|_| unreachable!("HMAC takes any key length"));
    mac.update(signing_input.as_bytes());
    format!("{signing_input}.{}", b64url(&mac.finalize().into_bytes()))
}

/// The session store's state when the response is processed.
#[expect(clippy::struct_excessive_bools, reason = "Django's flags, one each")]
#[derive(Debug, Clone)]
pub struct SessionResponse<'a> {
    /// Whether the request carried an `authentik_session` cookie.
    pub had_cookie: bool,
    pub accessed: bool,
    pub modified: bool,
    /// `is_empty()`: no session key and no data.
    pub empty: bool,
    pub session_key: Option<&'a str>,
    /// `request.user.uid` when authenticated.
    pub user_uid: Option<&'a str>,
    /// `_session_expiry` as `get_expiry_age()` uses it; `None` expires at
    /// browser close.
    pub expiry_age: Option<f64>,
    pub status: u16,
    pub secure: bool,
    pub web_path: &'a str,
    pub cookie_domain: Option<&'a str>,
}

/// What `SessionMiddleware.process_response` does to the response.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionEffect {
    /// `Set-Cookie` values.
    pub cookies: Vec<String>,
    /// Add `Cookie` to `Vary`.
    pub vary_cookie: bool,
    /// `request.session.save()` (the write layer's).
    pub save: bool,
}

/// `SessionMiddleware.process_response`.
///
/// # Errors
///
/// [`CookieError`] from a path or domain with control characters.
pub fn session_process_response(
    s: &SessionResponse<'_>,
    secret_key: &str,
    now: f64,
) -> Result<SessionEffect, CookieError> {
    let same_site = if s.secure { "None" } else { "Lax" };
    let mut effect = SessionEffect::default();
    if s.had_cookie && s.empty {
        effect.cookies.push(
            Cookie::delete(
                SESSION_COOKIE_NAME,
                s.web_path,
                s.cookie_domain,
                Some(same_site),
            )
            .output(now)?,
        );
        effect.vary_cookie = true;
        return Ok(effect);
    }
    effect.vary_cookie = s.accessed;
    if s.modified && !s.empty && s.status != 500 {
        effect.save = true;
        let (max_age, expires) = match s.expiry_age {
            None => (None, None),
            Some(age) => (Some(age), Some(http_date(now + age))),
        };
        let session_key = s.session_key.unwrap_or_default();
        effect.cookies.push(
            Cookie {
                name: SESSION_COOKIE_NAME.to_owned(),
                value: encode_session(session_key, s.user_uid, secret_key),
                max_age,
                expires,
                path: Some(s.web_path.to_owned()),
                domain: s.cookie_domain.map(str::to_owned),
                secure: s.secure,
                // `SESSION_COOKIE_HTTPONLY` is `True`.
                httponly: true,
                samesite: Some(same_site),
            }
            .output(now)?,
        );
    }
    Ok(effect)
}

/// `CsrfViewMiddleware.process_response`: the `authentik_csrf` cookie when
/// it needs an update (authentik's `_set_csrf_cookie`: `Secure` by TLS,
/// `SameSite=Lax`, a year).
///
/// # Errors
///
/// [`CookieError`] from a path with control characters.
pub fn csrf_process_response(
    state: &CsrfState,
    secure: bool,
    web_path: &str,
    now: f64,
) -> Result<Option<String>, CookieError> {
    if !state.needs_update {
        return Ok(None);
    }
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "a small constant"
    )]
    let max_age = CSRF_COOKIE_AGE as f64;
    Cookie {
        name: CSRF_COOKIE_NAME.to_owned(),
        value: state.cookie.clone().unwrap_or_default(),
        max_age: Some(max_age),
        expires: None,
        path: Some(web_path.to_owned()),
        domain: None,
        secure,
        httponly: false,
        samesite: Some("Lax"),
    }
    .output(now)
    .map(Some)
}
