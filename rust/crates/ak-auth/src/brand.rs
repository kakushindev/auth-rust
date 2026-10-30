//! `authentik.brands.utils.get_brand_for_request`.

use sqlx::{Executor, Postgres};
use uuid::Uuid;

/// The brand for a request's `get_host()`, port included.
///
/// That is the brand with the longest domain that equals the host or is a
/// `.`-suffix of it, case insensitively, else the default brand. `None` is
/// Django's unsaved `DEFAULT_BRAND` fallback. The SQL is Django's, so `%` and
/// `_` in domains and Unicode case folding behave identically.
///
/// # Errors
///
/// A database error.
pub async fn resolve<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    host: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    const MATCH_PRIORITY: &str = r"CASE WHEN (UPPER($1::text) = UPPER((b.domain)) OR UPPER($1::text) LIKE '%' || UPPER(REPLACE(REPLACE(REPLACE((COALESCE('.', '') || COALESCE(b.domain, '')), E'\\', E'\\\\'), E'%', E'\\%'), E'_', E'\\_'))) THEN LENGTH(b.domain) ELSE -1 END";
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT b.brand_uuid FROM authentik_brands_brand b WHERE ({MATCH_PRIORITY} > -1 OR \
         b.\"default\") ORDER BY {MATCH_PRIORITY} DESC, CASE WHEN (b.\"default\") THEN 0 ELSE -2 \
         END DESC LIMIT 1"
    )))
    .bind(host)
    .fetch_optional(executor)
    .await
}
