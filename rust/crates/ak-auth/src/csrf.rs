//! Django 5.2's `CsrfViewMiddleware` with authentik's settings.
//!
//! That is `CSRF_COOKIE_NAME = "authentik_csrf"`, `CSRF_HEADER_NAME =
//! "HTTP_X_AUTHENTIK_CSRF"`, no `CSRF_TRUSTED_ORIGINS`, no
//! `CSRF_COOKIE_DOMAIN`, cookies rather than sessions; and DRF's
//! `SessionAuthentication.enforce_csrf`, which runs the same checks for API
//! requests made with a logged-in session.

use subtle::ConstantTimeEq as _;

use crate::{
    host::get_host,
    python::isspace,
    url::{SplitResult, urlsplit},
};

/// `CSRF_SECRET_LENGTH`.
pub const CSRF_SECRET_LENGTH: usize = 32;
/// `CSRF_TOKEN_LENGTH`.
pub const CSRF_TOKEN_LENGTH: usize = 2 * CSRF_SECRET_LENGTH;
/// `CSRF_ALLOWED_CHARS` (`string.ascii_letters + string.digits`).
const CSRF_ALLOWED_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
/// `CSRF_COOKIE_AGE`: a year.
pub const CSRF_COOKIE_AGE: i64 = 60 * 60 * 24 * 7 * 52;
/// `settings.CSRF_COOKIE_NAME`.
pub const CSRF_COOKIE_NAME: &str = "authentik_csrf";

/// `_get_new_csrf_string()`.
#[must_use]
pub fn new_csrf_string() -> String {
    ak_passwords::get_random_string(CSRF_SECRET_LENGTH)
}

fn char_index(c: char) -> Option<usize> {
    let b = u8::try_from(c).ok()?;
    CSRF_ALLOWED_CHARS.iter().position(|&a| a == b)
}

/// `_mask_cipher_secret(secret)` with a given mask (Django draws it at
/// random: [`mask_cipher_secret`]).
#[must_use]
pub fn mask_with(secret: &str, mask: &str) -> String {
    let n = CSRF_ALLOWED_CHARS.len();
    let cipher: String = secret
        .chars()
        .zip(mask.chars())
        .filter_map(|(s, m)| {
            Some(char::from(
                CSRF_ALLOWED_CHARS[(char_index(s)? + char_index(m)?) % n],
            ))
        })
        .collect();
    format!("{mask}{cipher}")
}

/// `_mask_cipher_secret(secret)`.
#[must_use]
pub fn mask_cipher_secret(secret: &str) -> String {
    mask_with(secret, &new_csrf_string())
}

/// `_unmask_cipher_token(token)`; `token` has passed [`check_token_format`].
#[must_use]
pub fn unmask_cipher_token(token: &str) -> String {
    let n = CSRF_ALLOWED_CHARS.len();
    let (mask, cipher) = token.split_at(CSRF_SECRET_LENGTH.min(token.len()));
    cipher
        .chars()
        .zip(mask.chars())
        .filter_map(|(t, m)| {
            Some(char::from(
                CSRF_ALLOWED_CHARS[(char_index(t)? + n - char_index(m)?) % n],
            ))
        })
        .collect()
}

/// `InvalidTokenFormat.reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidTokenFormat {
    /// `REASON_INCORRECT_LENGTH`.
    IncorrectLength,
    /// `REASON_INVALID_CHARACTERS`.
    InvalidCharacters,
}

impl InvalidTokenFormat {
    const fn reason(self) -> &'static str {
        match self {
            Self::IncorrectLength => "has incorrect length",
            Self::InvalidCharacters => "has invalid characters",
        }
    }
}

/// `_check_token_format(token)`: `len()` counts code points.
///
/// # Errors
///
/// The [`InvalidTokenFormat`] Django raises.
pub fn check_token_format(token: &str) -> Result<(), InvalidTokenFormat> {
    if !matches!(
        token.chars().count(),
        CSRF_TOKEN_LENGTH | CSRF_SECRET_LENGTH
    ) {
        return Err(InvalidTokenFormat::IncorrectLength);
    }
    if !token.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(InvalidTokenFormat::InvalidCharacters);
    }
    Ok(())
}

/// `_get_secret(request)`: the unmasked secret of the `authentik_csrf`
/// cookie, if there is one.
///
/// # Errors
///
/// The cookie's [`InvalidTokenFormat`].
pub fn get_secret(cookie: Option<&str>) -> Result<Option<String>, InvalidTokenFormat> {
    let Some(secret) = cookie else {
        return Ok(None);
    };
    check_token_format(secret)?;
    Ok(Some(if secret.len() == CSRF_TOKEN_LENGTH {
        unmask_cipher_token(secret)
    } else {
        secret.to_owned()
    }))
}

/// `request.META["CSRF_COOKIE"]` and `["CSRF_COOKIE_NEEDS_UPDATE"]` after
/// `process_request`; [`get_token`] and [`rotate_token`] change them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CsrfState {
    pub cookie: Option<String>,
    pub needs_update: bool,
}

/// `CsrfViewMiddleware.process_request`.
#[must_use]
pub fn process_request(cookie: Option<&str>) -> CsrfState {
    match get_secret(cookie) {
        // `_add_new_csrf_cookie`.
        Err(_) => CsrfState {
            cookie: Some(new_csrf_string()),
            needs_update: true,
        },
        Ok(secret) => CsrfState {
            cookie: secret,
            needs_update: false,
        },
    }
}

/// `get_token(request)`: a masked token for the response, marking the
/// cookie to be (re)sent.
pub fn get_token(state: &mut CsrfState) -> String {
    let secret = state.cookie.get_or_insert_with(new_csrf_string).clone();
    state.needs_update = true;
    mask_cipher_secret(&secret)
}

/// `rotate_token(request)`.
pub fn rotate_token(state: &mut CsrfState) {
    state.cookie = Some(new_csrf_string());
    state.needs_update = true;
}

/// The form field `csrfmiddlewaretoken` as `request.POST` yields it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostToken<'a> {
    /// Not a POST, not a form, no such field, or `UnreadablePostError`:
    /// Django falls back to the header.
    Absent,
    Value(&'a str),
    /// DRF's parsing of the body raised (`UnsupportedMediaType` for a form
    /// body, as only the JSON parser is configured, or `ParseError`): the
    /// exception escapes the check (a 415 or 400).
    BodyError,
}

/// The facts of the request the checks read.
#[derive(Debug, Clone, Copy)]
pub struct Request<'a> {
    pub method: &'a str,
    /// The raw `Host` header (Django's `get_host()` validates it).
    pub host: &'a str,
    /// `request.is_secure()`.
    pub secure: bool,
    pub origin: Option<&'a str>,
    pub referer: Option<&'a str>,
    /// `X-authentik-CSRF`.
    pub header_token: Option<&'a str>,
    pub post_token: PostToken<'a>,
}

/// The outcome of `process_view`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Accept,
    /// `_reject(request, reason)`: Django's failure view answers 403, DRF
    /// `{"detail": "CSRF Failed: <reason>"}` with 403.
    Reject(String),
    /// See [`PostToken::BodyError`].
    BodyError,
}

/// `request.is_secure()` with `SECURE_PROXY_SSL_HEADER =
/// ("HTTP_X_FORWARDED_PROTO", "https")`; `wsgi_scheme` is the WSGI
/// server's `wsgi.url_scheme`.
#[must_use]
pub fn is_secure(x_forwarded_proto: Option<&str>, wsgi_scheme: &str) -> bool {
    match x_forwarded_proto {
        Some(value) => {
            value
                .split(',')
                .next()
                .unwrap_or_default()
                .trim_matches(isspace)
                == "https"
        }
        None => wsgi_scheme == "https",
    }
}

/// `is_same_domain(host, pattern)`.
#[must_use]
pub fn is_same_domain(host: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    let pattern = pattern.to_lowercase();
    pattern
        .strip_prefix('.')
        .is_some_and(|bare| host.ends_with(&pattern) || host == bare)
        || pattern == host
}

/// `_origin_verified`: with no trusted origins only the request's own
/// origin passes.
fn origin_verified(request: &Request<'_>, origin: &str) -> bool {
    get_host(request.host).is_ok_and(|host| {
        let scheme = if request.secure { "https" } else { "http" };
        origin == format!("{scheme}://{host}")
    })
}

/// `_check_referer`.
fn check_referer(request: &Request<'_>) -> Result<(), String> {
    let referer = request
        .referer
        .ok_or("Referer checking failed - no Referer.")?;
    let malformed = || "Referer checking failed - Referer is malformed.".to_owned();
    let referer: SplitResult = urlsplit(referer).map_err(|_| malformed())?;
    if referer.scheme.is_empty() || referer.netloc.is_empty() {
        return Err(malformed());
    }
    if referer.scheme != "https" {
        return Err(
            "Referer checking failed - Referer is insecure while host is secure.".to_owned(),
        );
    }
    let bad = || {
        format!(
            "Referer checking failed - {} does not match any trusted origins.",
            referer.geturl()
        )
    };
    let good_referer = get_host(request.host).map_err(|_| bad())?;
    if !is_same_domain(&referer.netloc, good_referer) {
        return Err(bad());
    }
    Ok(())
}

/// `_bad_token_message(reason, token_source)`.
fn bad_token_message(reason: &str, from_header: bool) -> String {
    if from_header {
        // `HttpHeaders.parse_header_name("HTTP_X_AUTHENTIK_CSRF")`, `!r`.
        format!("CSRF token from the 'X-Authentik-Csrf' HTTP header {reason}.")
    } else {
        format!("CSRF token from POST {reason}.")
    }
}

/// `_check_token`.
fn check_token(request: &Request<'_>, cookie: Option<&str>) -> Result<(), Outcome> {
    let reject = |reason: String| Outcome::Reject(reason);
    let secret = get_secret(cookie)
        .map_err(|err| reject(format!("CSRF cookie {}.", err.reason())))?
        .ok_or_else(|| reject("CSRF cookie not set.".to_owned()))?;
    let mut token = "";
    if request.method == "POST" {
        match request.post_token {
            PostToken::Absent => {}
            PostToken::Value(value) => token = value,
            PostToken::BodyError => return Err(Outcome::BodyError),
        }
    }
    let from_header = token.is_empty();
    if from_header {
        token = request
            .header_token
            .ok_or_else(|| reject("CSRF token missing.".to_owned()))?;
    }
    check_token_format(token)
        .map_err(|err| reject(bad_token_message(err.reason(), from_header)))?;
    // `_does_token_match`.
    let unmasked;
    let token = if token.len() == CSRF_TOKEN_LENGTH {
        unmasked = unmask_cipher_token(token);
        unmasked.as_str()
    } else {
        token
    };
    if !bool::from(token.as_bytes().ct_eq(secret.as_bytes())) {
        return Err(reject(bad_token_message("incorrect", from_header)));
    }
    Ok(())
}

/// `process_view` for a view that is not `csrf_exempt`, or DRF's
/// `enforce_csrf` (which runs `process_request` on the same cookie first).
#[must_use]
pub fn process_view(request: &Request<'_>, cookie: Option<&str>) -> Outcome {
    if matches!(request.method, "GET" | "HEAD" | "OPTIONS" | "TRACE") {
        return Outcome::Accept;
    }
    if let Some(origin) = request.origin {
        if !origin_verified(request, origin) {
            return Outcome::Reject(format!(
                "Origin checking failed - {origin} does not match any trusted origins."
            ));
        }
    } else if request.secure
        && let Err(reason) = check_referer(request)
    {
        return Outcome::Reject(reason);
    }
    match check_token(request, cookie) {
        Ok(()) => Outcome::Accept,
        Err(outcome) => outcome,
    }
}
