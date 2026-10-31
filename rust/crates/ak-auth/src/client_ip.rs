//! `ClientIPMiddleware`: the request's client IP.
//!
//! The first `X-Forwarded-For` address, else `REMOTE_ADDR`, normalized as
//! `str(ip_address(…))`. An outpost may override it with
//! `X-authentik-remote-ip` when it also sends `X-authentik-outpost-token`,
//! an API token of an internal service account.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::python::isspace;

/// `ClientIPMiddleware.default_ip`.
pub const DEFAULT_IP: &str = "255.255.255.255";
/// `UserTypes.INTERNAL_SERVICE_ACCOUNT`.
const INTERNAL_SERVICE_ACCOUNT: &str = "internal_service_account";

/// `str(ipaddress.ip_address(s))`, or `None` for `ValueError`.
#[must_use]
pub fn normalize_ip(s: &str) -> Option<String> {
    if let Ok(v4) = s.parse::<std::net::Ipv4Addr>() {
        return Some(v4.to_string());
    }
    // `IPv6Address`: no `/` anywhere; a `%scope` must be non-empty and has
    // no further `%`; it is kept.
    if s.contains('/') {
        return None;
    }
    let (addr, scope) = match s.split_once('%') {
        Some((_, scope)) if scope.is_empty() || scope.contains('%') => return None,
        Some((addr, scope)) => (addr, Some(scope)),
        None => (s, None),
    };
    let v6 = addr.parse::<std::net::Ipv6Addr>().ok()?;
    Some(match scope {
        Some(scope) => format!("{v6}%{scope}"),
        None => v6.to_string(),
    })
}

/// `_get_client_ip_from_meta`: headers are WSGI strings (Latin-1).
#[must_use]
pub fn from_meta(x_forwarded_for: Option<&str>, remote_addr: Option<&str>) -> String {
    let Some(value) = x_forwarded_for.or(remote_addr) else {
        return DEFAULT_IP.to_owned();
    };
    let first = value.split(',').next().unwrap_or_default();
    normalize_ip(first.trim_matches(isspace)).unwrap_or_else(|| DEFAULT_IP.to_owned())
}

/// The client IP and the outpost service account that set it, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientIp {
    pub ip: String,
    /// `request.outpost_user`.
    pub outpost_user: Option<i32>,
}

/// `ClientIPMiddleware._get_client_ip(request)`.
///
/// Django deletes expired tokens matching the outpost token while looking
/// it up (`filter_not_expired`); they are absent here, not deleted (M8).
///
/// # Errors
///
/// A database error.
pub async fn client_ip(
    pool: &PgPool,
    x_forwarded_for: Option<&str>,
    remote_addr: Option<&str>,
    remote_ip_header: Option<&str>,
    outpost_token: Option<&str>,
    now: DateTime<Utc>,
) -> Result<ClientIp, sqlx::Error> {
    let from_meta = || ClientIp {
        ip: from_meta(x_forwarded_for, remote_addr),
        outpost_user: None,
    };
    let (Some(delegated), Some(key)) = (remote_ip_header, outpost_token) else {
        return Ok(from_meta());
    };
    // `Token.filter_not_expired(key=…, intent=API).select_related("user").first()`.
    let token: Option<(i32, String)> = sqlx::query_as(
        "SELECT u.id, u.type FROM authentik_core_token t JOIN authentik_core_user u ON u.id = \
         t.user_id WHERE t.intent = 'api' AND t.key = $1 AND NOT COALESCE(t.expiring AND \
         t.expires < $2, false) ORDER BY t.token_uuid LIMIT 1",
    )
    .bind(key)
    .bind(now)
    .fetch_optional(pool)
    .await?;
    let Some((user, user_type)) = token else {
        return Ok(from_meta());
    };
    if user_type != INTERNAL_SERVICE_ACCOUNT {
        return Ok(from_meta());
    }
    // The outpost user is set even when its IP does not parse.
    Ok(match normalize_ip(delegated) {
        Some(ip) => ClientIp {
            ip,
            outpost_user: Some(user),
        },
        None => ClientIp {
            outpost_user: Some(user),
            ..from_meta()
        },
    })
}
