//! Who a request with an `authentik_session` cookie acts as.
//!
//! As 2026.2.7's middleware decides it: `SessionMiddleware.decode_session_key` (`PyJWT`
//! 2.11 `decode(cookie, sha512(SECRET_KEY).hexdigest(), ["HS256"])`),
//! `SessionStore` (key validation, `expires > now`), `BoundSessionMiddleware`
//! (unchanged IP or no binding), `AuthenticationMiddleware` (an inactive
//! user is logged out with a 400) and `ImpersonateMiddleware`.

use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::{Digest as _, Sha256, Sha512};
use sqlx::PgPool;

use crate::python::{PyError, PyValue, base64url_decode, json_loads};

/// `authentik/impersonate/user`.
const SESSION_KEY_IMPERSONATE_USER: &str = "authentik/impersonate/user";
/// `authentik/stages/user_login/binding/net` and `…/geo`.
const SESSION_KEY_BINDINGS: [&str; 2] = [
    "authentik/stages/user_login/binding/net",
    "authentik/stages/user_login/binding/geo",
];

/// The request's identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestUser {
    Anonymous,
    User(i32),
    /// `ImpersonateMiddleware`: the session's pickled user replaces the
    /// authenticated one (`real` may be `None`, as Django does not check).
    Impersonating {
        real: Option<i32>,
        as_user: i32,
    },
    /// The session's user is inactive: Django flushes the session and
    /// answers 400 (the flush is the write layer's, M8).
    InactiveLogout,
    /// A network or `GeoIP` binding is configured and the IP changed:
    /// deciding needs the ASN and `GeoIP` databases (M5 part 2b).
    BindingCheckRequired,
}

/// A Django 500: the exception that escapes the middleware.
#[derive(Debug)]
pub enum Error {
    Python(&'static str),
    Database(sqlx::Error),
}

impl From<sqlx::Error> for Error {
    fn from(err: sqlx::Error) -> Self {
        Self::Database(err)
    }
}

fn py_error(err: PyError) -> Error {
    Error::Python(match err {
        PyError::ValueError => "ValueError",
        PyError::TypeError => "TypeError",
        PyError::OverflowError => "OverflowError",
        PyError::RecursionError => "RecursionError",
    })
}

/// The HMAC key: `sha512(SECRET_KEY.encode()).hexdigest()`.
#[must_use]
pub fn signing_hash(secret_key: &str) -> String {
    Sha512::digest(secret_key.as_bytes())
        .iter()
        .fold(String::new(), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// `PyJWT` `decode` with `algorithms=["HS256"]` and default options: the
/// payload, `Ok(None)` for any `PyJWTError`.
fn jwt_decode(token: &[u8], key: &str, now: f64) -> Result<Option<PyValue>, Error> {
    let Some(dot) = token.iter().rposition(|&b| b == b'.') else {
        return Ok(None);
    };
    let (signing_input, crypto_segment) = (&token[..dot], &token[dot + 1..]);
    let Some(first) = signing_input.iter().position(|&b| b == b'.') else {
        return Ok(None);
    };
    let (header_segment, payload_segment) = (&signing_input[..first], &signing_input[first + 1..]);
    let Some(header_bytes) = base64url_decode(header_segment) else {
        return Ok(None);
    };
    let header = match json_loads(&header_bytes) {
        Ok(header @ PyValue::Dict(_)) => header,
        Ok(_) | Err(PyError::ValueError) => return Ok(None),
        Err(err) => return Err(py_error(err)),
    };
    let (Some(payload_bytes), Some(signature)) = (
        base64url_decode(payload_segment),
        base64url_decode(crypto_segment),
    ) else {
        return Ok(None);
    };
    if header.get("b64") == Some(&PyValue::Bool(false)) {
        return Ok(None);
    }
    match header.get("alg") {
        Some(PyValue::Str(alg)) if alg.to_string_lossless().as_deref() == Some("HS256") => {}
        _ => return Ok(None),
    }
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key.as_bytes()) else {
        return Ok(None);
    };
    mac.update(signing_input);
    if mac.verify_slice(&signature).is_err() {
        return Ok(None);
    }
    let payload = match json_loads(&payload_bytes) {
        Ok(payload @ PyValue::Dict(_)) => payload,
        Ok(_) | Err(PyError::ValueError) => return Ok(None),
        Err(err) => return Err(py_error(err)),
    };
    // `_validate_claims`: iat, nbf, exp; aud without an expected audience;
    // sub and jti must be strings.
    // `iat`/`nbf` must not be in the future; `exp` must be in the future.
    for (claim, is_exp) in [("iat", false), ("nbf", false), ("exp", true)] {
        if let Some(value) = payload.get(claim) {
            match value.to_int() {
                Ok(v) if (is_exp && v <= now) || (!is_exp && v > now) => return Ok(None),
                Ok(_) => {}
                Err(PyError::ValueError) => return Ok(None),
                Err(err) => return Err(py_error(err)),
            }
        }
    }
    if payload.get("aud").is_some_and(PyValue::truthy) {
        return Ok(None);
    }
    for claim in ["sub", "jti"] {
        if payload
            .get(claim)
            .is_some_and(|v| !matches!(v, PyValue::Str(_)))
        {
            return Ok(None);
        }
    }
    Ok(Some(payload))
}

/// `decode_session_key(cookie)` followed by `SessionStore`'s key validation
/// (`key and len(key) >= 8`): the session key to look up, if any.
///
/// The cookie is the value Django parsed (a `str` of Latin-1 code points);
/// `PyJWT` encodes it as UTF-8 before splitting.
///
/// # Errors
///
/// [`Error::Python`] where Django raises past the middleware.
pub fn session_key(
    cookie: Option<&str>,
    secret_key: &str,
    now: DateTime<Utc>,
) -> Result<Option<String>, Error> {
    let Some(cookie) = cookie else {
        return Ok(None);
    };
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "a timestamp"
    )]
    let now = now.timestamp_micros() as f64 / 1e6_f64;
    let Some(payload) = jwt_decode(cookie.as_bytes(), &signing_hash(secret_key), now)? else {
        return Ok(None);
    };
    let Some(sid) = payload.get("sid") else {
        return Ok(None);
    };
    if !sid.truthy() {
        return Ok(None);
    }
    if sid.py_len().map_err(py_error)? < 8 {
        return Ok(None);
    }
    match sid {
        // A str that UTF-8 cannot hold fails when psycopg encodes it.
        PyValue::Str(s) => s
            .to_string_lossless()
            .map(Some)
            .ok_or(Error::Python("UnicodeEncodeError")),
        // `str(list)`/`str(dict)` starts with `[`/`{` and never matches a key.
        _ => Ok(None),
    }
}

/// The session's authenticated user and whether they are active, its pickled
/// data, and its last IP.
type SessionRow = (Option<i32>, Option<bool>, Vec<u8>, Option<String>);

/// The request's identity for a session cookie and client IP.
///
/// # Errors
///
/// [`Error::Python`] where Django answers 500, or a database error.
pub async fn resolve(
    pool: &PgPool,
    cookie: Option<&str>,
    client_ip: &str,
    secret_key: &str,
    now: DateTime<Utc>,
) -> Result<RequestUser, Error> {
    let Some(key) = session_key(cookie, secret_key, now)? else {
        return Ok(RequestUser::Anonymous);
    };
    // `_get_session_from_db`, with `select_related("authenticatedsession__user")`.
    let row: Option<SessionRow> = sqlx::query_as(
        "SELECT a.user_id, u.is_active, s.session_data, host(s.last_ip) FROM \
         authentik_core_session s LEFT JOIN authentik_core_authenticatedsession a ON a.session_id \
         = s.session_key LEFT JOIN authentik_core_user u ON u.id = a.user_id WHERE s.session_key \
         = $1 AND s.expires > $2",
    )
    .bind(&key)
    .bind(now)
    .fetch_optional(pool)
    .await?;
    let Some((user, is_active, session_data, last_ip)) = row else {
        return Ok(RequestUser::Anonymous);
    };
    // `SessionStore.decode`: an unreadable pickle is an empty session.
    let data = ak_pickle::loads(&session_data).ok();
    let get = |key: &str| {
        let d = data.as_ref()?;
        d.get(key)
    };

    // BoundSessionMiddleware: only a changed IP with a binding needs a check.
    if last_ip.as_deref() != Some(client_ip)
        && SESSION_KEY_BINDINGS
            .iter()
            .any(|k| get(k).is_some_and(|v| v.as_str() != Some("no_binding")))
    {
        return Ok(RequestUser::BindingCheckRequired);
    }
    // AuthenticationMiddleware.
    if user.is_some() && is_active == Some(false) {
        return Ok(RequestUser::InactiveLogout);
    }
    // ImpersonateMiddleware: the pickled User (`model_unpickle`) state's `id`.
    if let Some(impersonated) = get(SESSION_KEY_IMPERSONATE_USER) {
        let id = match &impersonated {
            ak_pickle::Value::Object(object) => {
                object.borrow().state.as_ref().and_then(|s| s.get("id"))
            }
            _ => None,
        };
        if let Some(ak_pickle::Value::Int(id)) = id
            && let Ok(as_user) = i32::try_from(id)
        {
            return Ok(RequestUser::Impersonating {
                real: user,
                as_user,
            });
        }
    }
    Ok(user.map_or(RequestUser::Anonymous, RequestUser::User))
}
