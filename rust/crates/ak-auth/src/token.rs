//! `authentik.api.authentication.TokenAuthentication.bearer_auth`.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use subtle::ConstantTimeEq as _;
use uuid::Uuid;

/// `SCOPE_AUTHENTIK_API`.
const SCOPE_AUTHENTIK_API: &str = "goauthentik.io/api";
/// `MANAGED_OUTPOST`.
const MANAGED_OUTPOST: &str = "goauthentik.io/outposts/embedded";
/// `USER_PREFIX_OUTPOSTS`.
const USER_PREFIX_OUTPOSTS: &str = "ak-outpost-";

/// What a bearer credential authenticated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Authenticated {
    /// An API-intent `Token` (`auth_via` `api_token`).
    ApiToken { token: Uuid, user: i32 },
    /// An `OAuth2` `AccessToken` with the `goauthentik.io/api` scope (`jwt`).
    Jwt { access_token: i32, user: i32 },
    /// `SECRET_KEY`, as the embedded outpost (`secret_key`). `user` is `None`
    /// when the outpost's service user does not exist yet: Django creates it
    /// then (write layer, M8).
    SecretKey { outpost: Uuid, user: Option<i32> },
    /// The IPC key: the virtual `authentik:system` user (`ipc`).
    Ipc,
}

/// How Django fails.
#[derive(Debug)]
pub enum Error {
    /// `AuthenticationFailed(message)`: a 401/403 with that message.
    Failed(&'static str),
    /// An unhandled Python exception (a 500): `UnicodeDecodeError` for a
    /// header that is not UTF-8, `TypeError` from `compare_digest` on
    /// non-ASCII text.
    Python(&'static str),
    Database(sqlx::Error),
}

impl From<sqlx::Error> for Error {
    fn from(err: sqlx::Error) -> Self {
        Self::Database(err)
    }
}

/// Python's `str.isspace()`: Unicode whitespace plus the separators
/// U+001C..U+001F, which Rust's `char::is_whitespace` leaves out.
fn py_isspace(c: char) -> bool {
    c.is_whitespace() || matches!(c, '\u{1c}'..='\u{1f}')
}

/// `hmac.compare_digest` on two `str`s.
fn compare_digest(a: &str, b: &str) -> Result<bool, Error> {
    if !a.is_ascii() || !b.is_ascii() {
        return Err(Error::Python("TypeError"));
    }
    Ok(bool::from(a.as_bytes().ct_eq(b.as_bytes())))
}

/// `validate_auth(header, "bearer")`: the credentials of a `Bearer` header,
/// or `None` when the header is absent, empty, has no space, or another
/// scheme.
///
/// # Errors
///
/// `Malformed header` for `Bearer` with empty credentials, and Python's
/// exceptions as [`Error::Python`].
pub fn validate_auth(raw_header: &[u8]) -> Result<Option<&str>, Error> {
    let header =
        std::str::from_utf8(raw_header).map_err(|_| Error::Python("UnicodeDecodeError"))?;
    let header = header.trim_matches(py_isspace);
    let Some((auth_type, credentials)) = header.split_once(' ') else {
        return Ok(None);
    };
    if !compare_digest(&auth_type.to_lowercase(), "bearer")? {
        return Ok(None);
    }
    if credentials.is_empty() {
        return Err(Error::Failed("Malformed header"));
    }
    Ok(Some(credentials))
}

async fn is_active(pool: &PgPool, user: i32) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar("SELECT is_active FROM authentik_core_user WHERE id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
}

/// `bearer_auth(raw_header)`: `Ok(None)` when there is no bearer credential
/// at all (DRF then tries the next authenticator).
///
/// Django deletes expired tokens and access tokens that match while looking
/// them up (`filter_not_expired`); they are treated as absent here, which is
/// the decision Django reaches, but not deleted (write layer, M8). `revoked`
/// access tokens still authenticate, as in Django.
///
/// # Errors
///
/// [`Error::Failed`] where Django raises `AuthenticationFailed`,
/// [`Error::Python`] where it raises another exception.
pub async fn bearer_auth(
    pool: &PgPool,
    raw_header: &[u8],
    now: DateTime<Utc>,
    secret_key: &str,
    ipc_key: Option<&str>,
) -> Result<Option<Authenticated>, Error> {
    let Some(credentials) = validate_auth(raw_header)? else {
        return Ok(None);
    };
    let authenticated = auth_user_lookup(pool, credentials, now, secret_key, ipc_key).await?;
    let user = match &authenticated {
        Authenticated::ApiToken { user, .. } | Authenticated::Jwt { user, .. } => Some(*user),
        Authenticated::SecretKey { user, .. } => *user,
        Authenticated::Ipc => None,
    };
    if let Some(user) = user
        && !is_active(pool, user).await?
    {
        return Err(Error::Failed("Token invalid/expired"));
    }
    Ok(Some(authenticated))
}

async fn auth_user_lookup(
    pool: &PgPool,
    credentials: &str,
    now: DateTime<Utc>,
    secret_key: &str,
    ipc_key: Option<&str>,
) -> Result<Authenticated, Error> {
    // `Token.filter_not_expired(key=…, intent=API).first()`.
    let token: Option<(Uuid, i32)> = sqlx::query_as(
        "SELECT token_uuid, user_id FROM authentik_core_token WHERE intent = 'api' AND key = $1 \
         AND NOT COALESCE(expiring AND expires < $2, false) ORDER BY token_uuid LIMIT 1",
    )
    .bind(credentials)
    .bind(now)
    .fetch_optional(pool)
    .await?;
    if let Some((token, user)) = token {
        return Ok(Authenticated::ApiToken { token, user });
    }

    // `AccessToken.filter_not_expired(token=…, _scope__icontains=API).first()`,
    // then the parsed scope must contain it exactly.
    let access: Option<(i32, i32, String)> = sqlx::query_as(
        "SELECT id, user_id, _scope FROM authentik_providers_oauth2_accesstoken WHERE \
         UPPER(_scope::text) LIKE UPPER('%goauthentik.io/api%') AND token = $1 AND NOT \
         COALESCE(expiring AND expires < $2, false) ORDER BY id LIMIT 1",
    )
    .bind(credentials)
    .bind(now)
    .fetch_optional(pool)
    .await?;
    if let Some((access_token, user, scope)) = access {
        if !scope.split(py_isspace).any(|s| s == SCOPE_AUTHENTIK_API) {
            return Err(Error::Failed("Token invalid/expired"));
        }
        return Ok(Authenticated::Jwt { access_token, user });
    }

    // `token_secret_key`.
    if compare_digest(credentials, secret_key)? {
        let outpost: Option<Uuid> = sqlx::query_scalar(
            "SELECT uuid FROM authentik_outposts_outpost WHERE managed = $1 ORDER BY uuid LIMIT 1",
        )
        .bind(MANAGED_OUTPOST)
        .fetch_optional(pool)
        .await?;
        if let Some(outpost) = outpost {
            let user = sqlx::query_scalar(
                "SELECT id FROM authentik_core_user WHERE username = $1 ORDER BY id LIMIT 1",
            )
            .bind(format!("{USER_PREFIX_OUTPOSTS}{}", outpost.simple()))
            .fetch_optional(pool)
            .await?;
            return Ok(Authenticated::SecretKey { outpost, user });
        }
    }

    // `token_ipc`.
    if let Some(ipc_key) = ipc_key.filter(|key| !key.is_empty())
        && compare_digest(credentials, ipc_key)?
    {
        return Ok(Authenticated::Ipc);
    }
    Err(Error::Failed("Token invalid/expired"))
}
