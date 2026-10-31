//! What Django and DRF do around every read view.
//!
//! Request admission (what this crate answers at all), content
//! negotiation, authentication, the error bodies of
//! `rest_framework.views.exception_handler`, and the response headers the
//! middleware stack adds.

use ak_rbac::Subject;
use chrono::{DateTime, Utc};
use http::{HeaderMap, header};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

use crate::{Answer, Decline, py::QueryDict};

/// What the request needs from the server: the database, Django's secret
/// key and the core IPC key.
pub struct Context<'a> {
    pub pool: &'a PgPool,
    pub secret_key: &'a str,
    pub ipc_key: Option<&'a str>,
    pub now: DateTime<Utc>,
}

/// The request exactly as Django receives it from the front server.
pub struct ApiRequest<'a> {
    /// Decoded path (`request.path_info`).
    pub path: &'a str,
    /// Raw query string.
    pub query: &'a str,
    pub headers: &'a HeaderMap,
}

fn header_str<'a>(headers: &'a HeaderMap, name: &header::HeaderName) -> Option<&'a str> {
    headers.get(name)?.to_str().ok()
}

/// The cookies Django parses (`django.http.parse_cookie`), just to see
/// whether a given one is present.
fn has_cookie(headers: &HeaderMap, name: &str) -> bool {
    headers.get_all(header::COOKIE).iter().any(|value| {
        String::from_utf8_lossy(value.as_bytes())
            .split(';')
            .any(|chunk| chunk.split_once('=').map_or(chunk, |(k, _)| k).trim() == name)
    })
}

/// `request.LANGUAGE_CODE` must be `en`: no language cookie, and every
/// `Accept-Language` tag is one that resolves to `en` (`en-gb` and other
/// variants have their own `Content-Language`).
fn english(headers: &HeaderMap) -> bool {
    if has_cookie(headers, "authentik_language") {
        return false;
    }
    headers
        .get_all(header::ACCEPT_LANGUAGE)
        .iter()
        .all(|value| match value.to_str() {
            Ok(value) => value.split(',').all(|item| {
                let tag = item.split(';').next().unwrap_or_default().trim();
                tag.is_empty() || matches!(tag.to_ascii_lowercase().as_str(), "en" | "en-us" | "*")
            }),
            Err(_) => false,
        })
}

/// DRF's `DefaultContentNegotiation` with authentik's single
/// `ORJSONRenderer`: JSON is chosen if any accepted media type matches
/// `application/json`. Media type parameters (other than `q`) change the
/// renderer's output and are left to Django, as is a 406.
fn accepts_json(headers: &HeaderMap) -> bool {
    let values: Vec<_> = headers.get_all(header::ACCEPT).iter().collect();
    if values.is_empty() {
        return true;
    }
    let mut any = false;
    for value in values {
        let Ok(value) = value.to_str() else {
            return false;
        };
        // An empty header is one empty media type: nothing matches (406).
        for item in value.split(',') {
            let mut parts = item.split(';');
            let media = parts.next().unwrap_or_default().trim();
            let params_ok = parts.all(|p| p.trim().starts_with("q="));
            let matches = matches!(media, "application/json" | "application/*" | "*/*");
            if matches && !params_ok {
                return false;
            }
            any |= matches;
        }
    }
    any
}

/// Checks that make Django, not this crate, answer the request.
///
/// # Errors
///
/// The reason the request is left to Django.
pub fn admit(req: &ApiRequest<'_>, query: &QueryDict) -> Result<(), Decline> {
    // Session-authenticated requests save or flush sessions and set
    // cookies (M8), so they stay with Django for now.
    if has_cookie(req.headers, "authentik_session") {
        return Err(Decline("session cookie"));
    }
    if !english(req.headers) {
        return Err(Decline("language other than en"));
    }
    if !accepts_json(req.headers) {
        return Err(Decline("accept header"));
    }
    if query.contains("format") {
        return Err(Decline("format override"));
    }
    Ok(())
}

/// The public tenant's pagination sizes, once Django's host and tenant
/// middleware would accept the request.
pub struct Tenant {
    pub default_page_size: i64,
    pub max_page_size: i64,
    /// `Tenant.avatars`: comma-separated avatar modes.
    pub avatars: String,
}

/// The request's tenant, as `DefaultTenantMiddleware` resolves it.
///
/// Only the default (public schema) tenant is served, and the Enterprise
/// search backend must be disabled (no license rows), as it then defers to
/// DRF's `SearchFilter`.
///
/// # Errors
///
/// A [`Decline`] for anything else, or a database error as a decline.
pub async fn tenant(ctx: &Context<'_>, req: &ApiRequest<'_>) -> Result<Tenant, Decline> {
    let raw_host = header_str(req.headers, &header::HOST).ok_or(Decline("no host"))?;
    let hostname =
        ak_auth::host::tenant_hostname(raw_host).map_err(|_| Decline("disallowed host"))?;
    let uuid = ak_auth::tenant::resolve(ctx.pool, hostname)
        .await
        .map_err(|_| Decline("database error"))?
        .ok_or(Decline("no tenant"))?;
    let row: Option<(String, bool, i32, i32, String)> = sqlx::query_as(
        "SELECT schema_name, ready, pagination_default_page_size, pagination_max_page_size, \
         avatars FROM authentik_tenants_tenant WHERE tenant_uuid = $1",
    )
    .bind(uuid)
    .fetch_optional(ctx.pool)
    .await
    .map_err(|_| Decline("database error"))?;
    let (schema, ready, default_page_size, max_page_size, avatars) =
        row.ok_or(Decline("no tenant"))?;
    if schema != "public" || !ready {
        return Err(Decline("tenant"));
    }
    let licensed: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM authentik_enterprise_license)")
            .fetch_one(ctx.pool)
            .await
            .map_err(|_| Decline("database error"))?;
    if licensed {
        return Err(Decline("enterprise license"));
    }
    Ok(Tenant {
        default_page_size: i64::from(default_page_size),
        max_page_size: i64::from(max_page_size),
        avatars,
    })
}

/// `request.user` after DRF authentication.
pub enum User {
    Anonymous(Subject),
    Authenticated(Subject),
}

impl User {
    pub fn subject(&self) -> &Subject {
        match self {
            Self::Anonymous(subject) | Self::Authenticated(subject) => subject,
        }
    }

    pub fn is_authenticated(&self) -> bool {
        matches!(self, Self::Authenticated(_))
    }
}

/// `TokenAuthentication` then `SessionAuthentication`.
///
/// No session cookie gets here, so the session user is anonymous. A token
/// Django would delete while looking it up, or an outpost/IPC identity, is
/// declined.
///
/// # Errors
///
/// `Ok(Err(answer))` is DRF's `AuthenticationFailed` response.
pub async fn authenticate(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
    allow: &'static str,
) -> Result<Result<User, Answer>, Decline> {
    let db = |_| Decline("database error");
    if let Some(raw) = req.headers.get(header::AUTHORIZATION) {
        if let Some(credentials) = ak_auth::token::validate_auth(raw.as_bytes()).ok().flatten() {
            // `filter_not_expired` deletes matching expired rows (M8).
            let expired: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM authentik_core_token WHERE key = $1 AND intent = \
                 'api' AND expiring AND expires < $2) OR EXISTS (SELECT 1 FROM \
                 authentik_providers_oauth2_accesstoken WHERE token = $1 AND UPPER(_scope::text) \
                 LIKE UPPER('%goauthentik.io/api%') AND expiring AND expires < $2)",
            )
            .bind(credentials)
            .bind(ctx.now)
            .fetch_one(ctx.pool)
            .await
            .map_err(db)?;
            if expired {
                return Err(Decline("expired token"));
            }
        }
        match ak_auth::token::bearer_auth(
            ctx.pool,
            raw.as_bytes(),
            ctx.now,
            ctx.secret_key,
            ctx.ipc_key,
        )
        .await
        {
            Ok(None) => {}
            Ok(Some(
                ak_auth::token::Authenticated::ApiToken { user, .. }
                | ak_auth::token::Authenticated::Jwt { user, .. },
            )) => {
                let subject = Subject::load(ctx.pool, user, None)
                    .await
                    .map_err(|_| Decline("database error"))?;
                return Ok(Ok(User::Authenticated(subject)));
            }
            Ok(Some(_)) => return Err(Decline("outpost or ipc identity")),
            Err(ak_auth::token::Error::Failed(message)) => {
                return Ok(Err(detail(403, message, allow)));
            }
            Err(_) => return Err(Decline("authentication raised")),
        }
    }
    let subject = Subject::anonymous(ctx.pool)
        .await
        .map_err(|_| Decline("database error"))?;
    Ok(Ok(User::Anonymous(subject)))
}

/// The headers Django's middleware and DRF put on every API response.
fn headers(allow: &'static str) -> Vec<(&'static str, String)> {
    vec![
        ("allow", allow.to_owned()),
        ("content-language", "en".to_owned()),
        ("content-type", "application/json".to_owned()),
        ("referrer-policy", "same-origin".to_owned()),
        ("vary", "Accept-Language, Cookie".to_owned()),
        ("x-content-type-options", "nosniff".to_owned()),
        ("x-frame-options", "DENY".to_owned()),
        ("x-authentik-id", Uuid::new_v4().simple().to_string()),
    ]
}

/// A rendered response (`ORJSONRenderer`: compact JSON).
pub fn json<T: Serialize + ?Sized>(status: u16, body: &T, allow: &'static str) -> Answer {
    Answer {
        status,
        headers: headers(allow),
        body: serde_json::to_vec(body).unwrap_or_default(),
    }
}

#[derive(Serialize)]
struct Detail<'a> {
    detail: &'a str,
}

/// `{"detail": message}`.
pub fn detail(status: u16, message: &str, allow: &'static str) -> Answer {
    json(status, &Detail { detail: message }, allow)
}

/// A `ValidationError` raised with a dict: `{"field": ["message", …], …}`
/// in field order.
pub fn field_errors(errors: &[(&str, String)], allow: &'static str) -> Answer {
    let mut body = String::from("{");
    for (i, (field, message)) in errors.iter().enumerate() {
        if i > 0 {
            body.push(',');
        }
        body.push_str(&serde_json::to_string(field).unwrap_or_default());
        body.push_str(":[");
        body.push_str(&serde_json::to_string(message).unwrap_or_default());
        body.push(']');
    }
    body.push('}');
    Answer {
        status: 400,
        headers: headers(allow),
        body: body.into_bytes(),
    }
}

/// `NotAuthenticated` for anonymous users, else `PermissionDenied` (both
/// 403: authentik's `TokenAuthentication` sends no `WWW-Authenticate`).
pub fn permission_denied(user: &User, allow: &'static str) -> Answer {
    if user.is_authenticated() {
        detail(
            403,
            "You do not have permission to perform this action.",
            allow,
        )
    } else {
        detail(403, "Authentication credentials were not provided.", allow)
    }
}

/// DRF `DateTimeField.to_representation` under `TIME_ZONE = "UTC"`:
/// `isoformat()` (microseconds only when non-zero), `+00:00` as `Z`.
pub fn datetime(value: DateTime<Utc>) -> String {
    use chrono::Timelike as _;
    if value.nanosecond() / 1000 == 0 {
        value.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    } else {
        value.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
    }
}

#[cfg(test)]
mod tests {
    use http::HeaderValue;

    use super::*;

    fn map(pairs: &[(header::HeaderName, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(name.clone(), HeaderValue::from_static(value));
        }
        headers
    }

    #[test]
    fn negotiation() {
        assert!(accepts_json(&map(&[])));
        assert!(accepts_json(&map(&[(
            header::ACCEPT,
            "text/html, application/json;q=0.5"
        )])));
        assert!(!accepts_json(&map(&[(header::ACCEPT, "text/html")])));
        assert!(!accepts_json(&map(&[(header::ACCEPT, "")])));
        assert!(!accepts_json(&map(&[(
            header::ACCEPT,
            "application/json; indent=4"
        )])));
        assert!(english(&map(&[(
            header::ACCEPT_LANGUAGE,
            "en-US,en;q=0.9"
        )])));
        assert!(!english(&map(&[(header::ACCEPT_LANGUAGE, "en-GB")])));
        assert!(!english(&map(&[(header::COOKIE, "authentik_language=en")])));
        assert!(has_cookie(
            &map(&[(header::COOKIE, "a=1; authentik_session=x")]),
            "authentik_session"
        ));
    }

    #[test]
    fn datetime_matches_drf() {
        use chrono::TimeZone as _;
        let t = Utc.with_ymd_and_hms(2026, 1, 2, 3, 4, 5).unwrap();
        assert_eq!(datetime(t), "2026-01-02T03:04:05Z");
        let t = t + chrono::Duration::microseconds(120);
        assert_eq!(datetime(t), "2026-01-02T03:04:05.000120Z");
    }
}
