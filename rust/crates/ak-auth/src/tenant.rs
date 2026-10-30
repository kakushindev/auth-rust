//! `authentik.tenants.middleware.DefaultTenantMiddleware.get_tenant`.

use sqlx::{Executor, Postgres};
use uuid::Uuid;

/// The tenant for a `tenant_hostname`: the tenant owning that exact domain,
/// else the public tenant (Django's `UNION … ORDER BY default DESC LIMIT 1`).
/// `None` means Django raises `Domain.DoesNotExist`.
///
/// # Errors
///
/// A database error.
pub async fn resolve<'e, E: Executor<'e, Database = Postgres>>(
    executor: E,
    hostname: &str,
) -> Result<Option<Uuid>, sqlx::Error> {
    let tenant: Option<(Uuid, i32)> = sqlx::query_as(
        "(SELECT t.tenant_uuid, 100 AS \"default\" FROM authentik_tenants_tenant t INNER JOIN \
         authentik_tenants_domain d ON (t.tenant_uuid = d.tenant_id) WHERE d.domain = $1) UNION \
         (SELECT t.tenant_uuid, 10 AS \"default\" FROM authentik_tenants_tenant t WHERE \
         t.schema_name = 'public') ORDER BY 2 DESC LIMIT 1",
    )
    .bind(hostname)
    .fetch_optional(executor)
    .await?;
    Ok(tenant.map(|(tenant, _)| tenant))
}
