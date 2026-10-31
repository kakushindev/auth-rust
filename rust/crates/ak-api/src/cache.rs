//! Django's `default` cache, as authentik configures it.
//!
//! The backend is `django_postgres_cache.backend.DatabaseCache` over
//! `django_postgres_cache_cacheentry`, keys from `django_tenants.cache.make_key`
//! (`<schema>:<prefix>:<version>:<key>`), values base64 of a pickle.
//!
//! Only what the read API needs: `get` (which deletes expired rows, as
//! Django's `get_many` does), `has_key` and `touch`. Reads come first and
//! writes are returned as [`Write`]s, so a view can still decline before it
//! changes anything.

use base64::Engine as _;
use chrono::{DateTime, Duration, SubsecRound as _, Utc};
use sqlx::PgPool;

use crate::Decline;

/// `settings.CACHES["default"]` has no `TIMEOUT`: Django's 300 seconds.
pub const DEFAULT_TIMEOUT_SECONDS: i64 = 300;

/// `make_key(key, "", 1)` in the public schema.
#[must_use]
pub fn make_key(key: &str) -> String {
    format!("public::1:{key}")
}

/// A pickled value this module can read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PyValue {
    None,
    Bool(bool),
    Str(String),
}

impl PyValue {
    /// Python truthiness.
    #[must_use]
    pub fn truthy(&self) -> bool {
        match self {
            Self::None => false,
            Self::Bool(b) => *b,
            Self::Str(s) => !s.is_empty(),
        }
    }
}

fn unsupported() -> Decline {
    Decline("cache value")
}

/// `pickle.loads` for protocol 5 dumps of `None`, a bool or a `str`.
fn unpickle(data: &[u8]) -> Result<PyValue, Decline> {
    let mut rest = data.strip_prefix(b"\x80\x05").ok_or_else(unsupported)?;
    // FRAME <u64 length>.
    if let Some(after) = rest.strip_prefix(b"\x95") {
        rest = after.get(8..).ok_or_else(unsupported)?;
    }
    let (op, mut rest) = rest.split_first().ok_or_else(unsupported)?;
    let take = |rest: &[u8], width: usize| -> Result<(String, Vec<u8>), Decline> {
        let len_bytes = rest.get(..width).ok_or_else(unsupported)?;
        let mut buf = [0_u8; 8];
        buf[..width].copy_from_slice(len_bytes);
        let len = usize::try_from(u64::from_le_bytes(buf)).map_err(|_| unsupported())?;
        let body = rest
            .get(width..width.checked_add(len).ok_or_else(unsupported)?)
            .ok_or_else(unsupported)?;
        let text = String::from_utf8(body.to_vec()).map_err(|_| unsupported())?;
        Ok((text, rest[width + len..].to_vec()))
    };
    let owned;
    let value = match op {
        b'N' => PyValue::None,
        0x88 => PyValue::Bool(true),
        0x89 => PyValue::Bool(false),
        0x8c | b'X' | 0x8d => {
            let width = match op {
                0x8c => 1,
                b'X' => 4,
                _ => 8,
            };
            let (text, after) = take(rest, width)?;
            owned = after;
            rest = &owned;
            PyValue::Str(text)
        }
        _ => return Err(unsupported()),
    };
    // MEMOIZE, then STOP.
    let rest = rest.strip_prefix(b"\x94").unwrap_or(rest);
    if rest == b"." {
        Ok(value)
    } else {
        Err(unsupported())
    }
}

/// A write Django makes while reading the cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Write {
    /// `_base_delete_many` of an expired row found by `get`.
    DeleteExpired(String),
    /// `touch(key)`: `expires = now + DEFAULT_TIMEOUT`.
    Touch(String),
}

/// `cache.get(key)`: `None` when missing or expired (the expired row is
/// queued for deletion).
///
/// # Errors
///
/// A database error, or a value that is not a supported pickle.
pub async fn get(
    pool: &PgPool,
    now: DateTime<Utc>,
    key: &str,
    writes: &mut Vec<Write>,
) -> Result<Option<PyValue>, Decline> {
    let full = make_key(key);
    let row: Option<(String, DateTime<Utc>)> = sqlx::query_as(
        "SELECT \"value\", \"expires\" FROM \"django_postgres_cache_cacheentry\" WHERE \
         \"cache_key\" IN ($1)",
    )
    .bind(&full)
    .fetch_optional(pool)
    .await
    .map_err(|_| Decline("database error"))?;
    let Some((value, expires)) = row else {
        return Ok(None);
    };
    if expires < now {
        writes.push(Write::DeleteExpired(full));
        return Ok(None);
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|_| unsupported())?;
    unpickle(&bytes).map(Some)
}

/// `cache.get(key)` right after `touch(key)` succeeded: the row is fresh,
/// so only its value matters.
///
/// # Errors
///
/// A database error, or a value that is not a supported pickle.
pub async fn get_touched(pool: &PgPool, key: &str) -> Result<Option<PyValue>, Decline> {
    let value: Option<String> = sqlx::query_scalar(
        "SELECT \"value\" FROM \"django_postgres_cache_cacheentry\" WHERE \"cache_key\" IN ($1)",
    )
    .bind(make_key(key))
    .fetch_optional(pool)
    .await
    .map_err(|_| Decline("database error"))?;
    value
        .map(|v| {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(v.as_bytes())
                .map_err(|_| unsupported())?;
            unpickle(&bytes)
        })
        .transpose()
}

/// `cache.has_key(key)`: `expires` later than now, to the second.
///
/// # Errors
///
/// A database error.
pub async fn has_key(pool: &PgPool, now: DateTime<Utc>, key: &str) -> Result<bool, Decline> {
    let found: Option<String> = sqlx::query_scalar(
        "SELECT \"cache_key\" FROM \"django_postgres_cache_cacheentry\" WHERE \"cache_key\" = $1 \
         and \"expires\" > $2",
    )
    .bind(make_key(key))
    .bind(now.trunc_subsecs(0))
    .fetch_optional(pool)
    .await
    .map_err(|_| Decline("database error"))?;
    Ok(found.is_some())
}

/// Apply the queued writes in order, as Django would have made them.
///
/// # Errors
///
/// A database error, as a decline (the response has not been sent yet).
pub async fn apply(pool: &PgPool, writes: &[Write]) -> Result<(), Decline> {
    for write in writes {
        let result =
            match write {
                Write::DeleteExpired(key) => sqlx::query(
                    "DELETE FROM \"django_postgres_cache_cacheentry\" WHERE \"cache_key\" IN ($1)",
                )
                .bind(key)
                .execute(pool)
                .await,
                Write::Touch(key) => {
                    sqlx::query(
                        "UPDATE \"django_postgres_cache_cacheentry\" SET \"expires\" = $1 WHERE \
                     \"django_postgres_cache_cacheentry\".\"cache_key\" = $2",
                    )
                    .bind(Utc::now() + Duration::seconds(DEFAULT_TIMEOUT_SECONDS))
                    .bind(key)
                    .execute(pool)
                    .await
                }
            };
        result.map_err(|_| Decline("database error"))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_pickles_django_writes() {
        // pickle.dumps(x, 5) for None, False, "https://x/a", "é".
        assert_eq!(unpickle(b"\x80\x05N."), Ok(PyValue::None));
        assert_eq!(unpickle(b"\x80\x05\x89."), Ok(PyValue::Bool(false)));
        assert_eq!(
            unpickle(b"\x80\x05\x95\x0f\x00\x00\x00\x00\x00\x00\x00\x8c\x0bhttps://x/a\x94."),
            Ok(PyValue::Str("https://x/a".into()))
        );
        assert_eq!(
            unpickle(b"\x80\x05\x95\x06\x00\x00\x00\x00\x00\x00\x00\x8c\x02\xc3\xa9\x94."),
            Ok(PyValue::Str("\u{e9}".into()))
        );
        assert_eq!(unpickle(b"\x80\x05K\x01."), Err(unsupported()));
        assert_eq!(make_key("a/b"), "public::1:a/b");
    }
}
