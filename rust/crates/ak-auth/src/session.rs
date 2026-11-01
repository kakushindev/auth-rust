//! Who a request with an `authentik_session` cookie acts as.
//!
//! As 2026.2.7's middleware decides it: `SessionMiddleware.decode_session_key` (`PyJWT`
//! 2.11 `decode(cookie, sha512(SECRET_KEY).hexdigest(), ["HS256"])`),
//! `SessionStore` (key validation, `expires > now`), `BoundSessionMiddleware`
//! (network and `GeoIP` bindings), `AuthenticationMiddleware` (an inactive
//! user is logged out with a 400) and `ImpersonateMiddleware`.

use chrono::{DateTime, Utc};
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::{Digest as _, Sha256, Sha512};
use sqlx::PgPool;

use crate::{
    binding::{self, Binding, GeoIp, Recheck, SESSION_KEY_BINDING_GEO, SESSION_KEY_BINDING_NET},
    python::{PyError, PyValue, base64url_decode, json_loads},
};

/// `settings.SESSION_COOKIE_NAME`.
pub const SESSION_COOKIE_NAME: &str = "authentik_session";
/// `authentik/impersonate/user`.
const SESSION_KEY_IMPERSONATE_USER: &str = "authentik/impersonate/user";
/// `Session.Keys.LAST_IP`.
const SESSION_KEY_LAST_IP: &str = "last_ip";
/// Django's `_session_expiry`.
const SESSION_KEY_EXPIRY: &str = "_session_expiry";

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
    /// `SessionBindingBroken(reason)`: the session is flushed (with a
    /// `user_logged_out` event, the write layer's) and the response is a
    /// redirect to login ([`crate::url::login_redirect`]).
    BindingBroken(&'static str),
}

/// The request's identity and the session state the response needs.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolved {
    pub user: RequestUser,
    /// The live session's key; `None` when there is none or it was flushed
    /// (the session is then empty).
    pub session_key: Option<String>,
    /// `session["last_ip"] = client_ip` (the session is modified and saved).
    pub set_last_ip: Option<String>,
    /// `get_expiry_age()` for the cookie, `None` to expire at browser close.
    pub expiry_age: Option<f64>,
    /// With `set_last_ip`: how to save the modified session, `None` when the
    /// save is not reproduced (the caller declines).
    pub save: Option<SessionSave>,
    /// For [`RequestUser::InactiveLogout`] and [`RequestUser::BindingBroken`]:
    /// the session Django logs out and flushes.
    pub flush: Option<Flush>,
}

/// A session `logout()` / `logout_extra()` flushes, with what the logout's
/// event and signals read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flush {
    pub session_key: String,
    /// The `AuthenticatedSession`'s user: id and `is_active`.
    pub user: Option<(i32, bool)>,
    /// The stored pickle (the event reads impersonation and a flow plan).
    pub session_data: Vec<u8>,
    /// A broken binding's `SessionBindingBroken.to_event()`, which the
    /// logout event's context is updated with.
    pub event_extra: Option<serde_json::Map<String, serde_json::Value>>,
}

/// `SessionStore.save()` for a session whose only change is `last_ip`.
///
/// `create_model_instance` re-pickles the loaded dict. `CPython`'s pickling of
/// session contents is not even deterministic between two `dumps` of one
/// object (memo sharing of equal strings, Django model `__getstate__`), so
/// the stored bytes, which unpickle to that same dict, are kept. The
/// columns are what Django writes: `expires = get_expiry_date()`,
/// `expiring` (the model default), `last_ip`, and `last_used` (`auto_now`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSave {
    pub session_key: String,
    pub last_ip: String,
    pub expires: DateTime<Utc>,
}

/// Keys `create_model_instance` moves out of `session_data` (model fields)
/// or drops (Django's auth keys, the related `AuthenticatedSession`).
const NOT_IN_SESSION_DATA: &[&str] = &[
    "last_ip",
    "last_user_agent",
    "last_used",
    "_auth_user_id",
    "_auth_user_backend",
    "_auth_user_hash",
    "authenticatedsession",
];

/// Modules whose classes can appear in authentik's session pickles; an
/// unknown one might fail `pickle.loads` in Python (`decode()` then yields
/// an empty session, or raises), which reusing the bytes would not.
const KNOWN_MODULES: &[&str] = &[
    "authentik.",
    "django.",
    "builtins",
    "copyreg",
    "collections",
    "datetime",
    "uuid",
    "decimal",
    "ipaddress",
    "_codecs",
    "enum",
];

fn globals_known(value: &ak_pickle::Value) -> bool {
    use ak_pickle::Value as V;
    let known = |module: &str| {
        KNOWN_MODULES.iter().any(|m| {
            if m.ends_with('.') {
                module.starts_with(m)
            } else {
                module == *m
                    || module
                        .strip_prefix(m)
                        .is_some_and(|rest| rest.starts_with('.'))
            }
        })
    };
    // Iterative, with shared containers visited once: session graphs are
    // deep (flow history) and may be cyclic.
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![value.clone()];
    while let Some(v) = stack.pop() {
        match &v {
            V::Global { module, .. } => {
                if !known(module) {
                    return false;
                }
            }
            V::Tuple(items) | V::FrozenSet(items) => {
                if seen.insert(std::rc::Rc::as_ptr(items).cast::<()>()) {
                    stack.extend(items.iter().cloned());
                }
            }
            V::List(items) | V::Set(items) => {
                if seen.insert(std::rc::Rc::as_ptr(items).cast::<()>()) {
                    stack.extend(items.borrow().iter().cloned());
                }
            }
            V::Dict(items) => {
                if seen.insert(std::rc::Rc::as_ptr(items).cast::<()>()) {
                    for (k, x) in items.borrow().iter() {
                        stack.push(k.clone());
                        stack.push(x.clone());
                    }
                }
            }
            V::Object(object) if seen.insert(std::rc::Rc::as_ptr(object).cast::<()>()) => {
                let object = object.borrow();
                stack.push(object.callable.clone());
                stack.push(object.args.clone());
                stack.extend(object.kwargs.iter().cloned());
                stack.extend(object.state.iter().cloned());
                stack.extend(object.list_items.iter().cloned());
                for (k, x) in &object.dict_items {
                    stack.push(k.clone());
                    stack.push(x.clone());
                }
            }
            _ => {}
        }
    }
    true
}

/// `SessionBase.get_expiry_date()` at `now`.
fn expiry_date(
    expiry: Option<&ak_pickle::Value>,
    cookie_age: f64,
    now: DateTime<Utc>,
) -> Option<DateTime<Utc>> {
    use ak_pickle::Value as V;
    let after = |seconds: f64| {
        #[expect(
            clippy::as_conversions,
            clippy::cast_possible_truncation,
            reason = "microseconds"
        )]
        let micros = (seconds * 1e6_f64).round() as i64;
        now.checked_add_signed(chrono::Duration::microseconds(micros))
    };
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "seconds"
    )]
    match expiry {
        // `expiry or self.get_session_cookie_age()`.
        None | Some(V::None | V::Bool(false) | V::Int(0)) => after(cookie_age),
        Some(V::Float(f)) if *f == 0.0_f64 => after(cookie_age),
        Some(V::Str(s)) if s.is_empty() => after(cookie_age),
        Some(V::Bool(true)) => after(1.0_f64),
        Some(V::Int(n)) => after(*n as f64),
        Some(V::Float(f)) => after(*f),
        Some(V::Str(s)) => DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|d| d.with_timezone(&Utc)),
        Some(_) => None,
    }
}

/// Run the [`SessionSave`]; the number of rows updated (0: the session
/// was deleted meanwhile, Django's `UpdateError`).
///
/// # Errors
///
/// A database error.
pub async fn save_last_ip(
    pool: &PgPool,
    save: &SessionSave,
    now: DateTime<Utc>,
) -> Result<u64, Error> {
    let done = sqlx::query(
        "UPDATE authentik_core_session SET expires = $1, expiring = true, last_ip = $2::inet, \
         last_used = $3 WHERE session_key = $4",
    )
    .bind(save.expires)
    .bind(&save.last_ip)
    .bind(now)
    .bind(&save.session_key)
    .execute(pool)
    .await?;
    Ok(done.rows_affected())
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

impl From<binding::Error> for Error {
    fn from(err: binding::Error) -> Self {
        Self::Python(match err {
            binding::Error::Type => "TypeError",
            binding::Error::InvalidDatabase => "InvalidDatabaseError",
        })
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

/// A binding as stored: a string, or a pickled `TextChoices` member
/// (`NetworkBinding("bind_asn")`), which compares equal to its value.
fn binding_value(value: Option<ak_pickle::Value>) -> Binding {
    let value = value?;
    if let Some(s) = value.as_str() {
        return Some(Some(s.to_owned()));
    }
    if let ak_pickle::Value::Object(object) = &value {
        let object = object.borrow();
        if let ak_pickle::Value::Global { name, .. } = &object.callable
            && name.ends_with("Binding")
            && let Some([arg]) = object.args.items().as_deref()
            && let Some(s) = arg.as_str()
        {
            return Some(Some(s.to_owned()));
        }
    }
    Some(None)
}

/// `get_expire_at_browser_close()` / `get_expiry_age()` for the stored
/// `_session_expiry`, `cookie_age` being `SESSION_COOKIE_AGE`
/// (`sessions.unauthenticated_age`).
fn expiry_age(
    expiry: Option<&ak_pickle::Value>,
    cookie_age: f64,
    now: DateTime<Utc>,
) -> Result<Option<f64>, Error> {
    use ak_pickle::Value as V;
    #[expect(
        clippy::as_conversions,
        clippy::cast_precision_loss,
        reason = "seconds"
    )]
    match expiry {
        None | Some(V::None | V::Bool(false) | V::Int(0)) => Ok(None),
        Some(V::Float(f)) if *f == 0.0 => Ok(None),
        Some(V::Bool(true)) => Ok(Some(1.0)),
        Some(V::Int(n)) => Ok(Some(*n as f64)),
        Some(V::Float(f)) => Ok(Some(*f)),
        Some(V::Str(s)) if s.is_empty() => Ok(Some(cookie_age)),
        Some(V::Str(s)) => {
            // `datetime.fromisoformat(expiry) - timezone.now()`; a naive
            // value cannot be subtracted (`TypeError`).
            let expiry = DateTime::parse_from_rfc3339(s)
                .map_err(|_| Error::Python("ValueError"))?
                .with_timezone(&Utc);
            Ok(Some(
                (expiry - now)
                    .num_microseconds()
                    .map_or(0.0, |us| (us as f64 / 1e6).floor()),
            ))
        }
        // A pickled datetime: Django 5 stores ISO strings instead.
        Some(_) => Ok(Some(cookie_age)),
    }
}

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
    geoip: &GeoIp,
    cookie_age: f64,
    now: DateTime<Utc>,
) -> Result<Resolved, Error> {
    let anonymous = Resolved {
        user: RequestUser::Anonymous,
        session_key: None,
        set_last_ip: None,
        expiry_age: None,
        save: None,
        flush: None,
    };
    let Some(key) = session_key(cookie, secret_key, now)? else {
        return Ok(anonymous);
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
        return Ok(anonymous);
    };
    let user_id = user;
    // `SessionStore.decode`: an unreadable pickle is an empty session. The
    // pickled data overrides the model fields in `load()`.
    let data = ak_pickle::loads(&session_data).ok();
    let get = |key: &str| {
        let d = data.as_ref()?;
        d.get(key)
    };
    let last_ip = match get(SESSION_KEY_LAST_IP) {
        Some(value) => value.as_str().map(str::to_owned),
        None => last_ip,
    };
    let flushed = |user, event_extra| Resolved {
        user,
        session_key: None,
        set_last_ip: None,
        expiry_age: None,
        save: None,
        flush: Some(Flush {
            session_key: key.clone(),
            user: user_id.zip(is_active),
            session_data: session_data.clone(),
            event_extra,
        }),
    };

    // BoundSessionMiddleware.
    let set_last_ip = match binding::recheck(
        geoip,
        &binding_value(get(SESSION_KEY_BINDING_NET)),
        &binding_value(get(SESSION_KEY_BINDING_GEO)),
        last_ip.as_deref(),
        client_ip,
    )? {
        Recheck::Broken(broken) => {
            let extra = serde_json::json!({
                "logout_reason": "Session binding broken",
                "binding": {
                    "reason": broken.reason,
                    "previous_value": broken.previous,
                    "new_value": broken.new,
                },
                "ip": {"previous": last_ip, "new": client_ip},
            });
            let serde_json::Value::Object(extra) = extra else {
                unreachable!("an object literal")
            };
            return Ok(flushed(
                RequestUser::BindingBroken(broken.reason),
                Some(extra),
            ));
        }
        Recheck::Passed { set_last_ip: true } => Some(client_ip.to_owned()),
        Recheck::Passed { set_last_ip: false } | Recheck::Unchanged => None,
    };
    // AuthenticationMiddleware.
    if user.is_some() && is_active == Some(false) {
        return Ok(flushed(RequestUser::InactiveLogout, None));
    }
    let expiry_age = expiry_age(get(SESSION_KEY_EXPIRY).as_ref(), cookie_age, now)?;
    let save = set_last_ip.as_ref().and_then(|ip| {
        let data = data.as_ref()?;
        let ak_pickle::Value::Dict(items) = data else {
            return None;
        };
        let clean = items.borrow().iter().all(|(k, _)| {
            matches!(k, ak_pickle::Value::Str(k) if !NOT_IN_SESSION_DATA.contains(&k.as_str()))
        });
        if !clean || !globals_known(data) {
            return None;
        }
        Some(SessionSave {
            session_key: key.clone(),
            last_ip: ip.clone(),
            expires: expiry_date(get(SESSION_KEY_EXPIRY).as_ref(), cookie_age, now)?,
        })
    });
    let resolved = |user| Resolved {
        user,
        session_key: Some(key.clone()),
        set_last_ip: set_last_ip.clone(),
        expiry_age,
        save: save.clone(),
        flush: None,
    };
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
            return Ok(resolved(RequestUser::Impersonating {
                real: user,
                as_user,
            }));
        }
    }
    Ok(resolved(
        user.map_or(RequestUser::Anonymous, RequestUser::User),
    ))
}

/// `get_install_id()` (`get_unique_identifier()` without tenants): the
/// value `User.uid` hashes.
///
/// # Errors
///
/// A database error.
pub async fn install_id(pool: &PgPool) -> Result<String, Error> {
    let id: String = sqlx::query_scalar("SELECT id FROM authentik_install_id ORDER BY id LIMIT 1")
        .fetch_one(pool)
        .await?;
    Ok(id)
}
