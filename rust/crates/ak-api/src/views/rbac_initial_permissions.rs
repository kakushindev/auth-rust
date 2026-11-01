//! `authentik.rbac.api.initial_permissions.InitialPermissionsViewSet`.
//!
//! `list` and `retrieve` on the default backends (`QLSearch` →
//! `SearchFilter` on `name`, `ObjectFilter`, `filterset_fields = ["name"]`,
//! `OrderingFilter` with default `ordering = ["name"]`).

use ak_rbac::{Access, Model, Object, PkCast};
use serde::Serialize;
use sqlx::Row as _;
use uuid::Uuid;

use crate::{
    Answer, Decline,
    drf::{self, ApiRequest, Context, User},
    pagination::{Page, page_size},
    py::{QueryDict, int4, py_int},
    sql::{Bind, QuerySet},
    views::{
        common::{char_field, object_filter, ordering, search_terms},
        rbac_permissions::{Permission, permission},
    },
};

pub(crate) const ALLOW_LIST: &str = "GET, POST, HEAD, OPTIONS";
pub(crate) const ALLOW_DETAIL: &str = "GET, PUT, PATCH, DELETE, HEAD, OPTIONS";

pub(crate) const MODEL: Model<'static> = Model {
    app_label: "authentik_rbac",
    model_name: "initialpermissions",
    ctype_app_label: "authentik_rbac",
    ctype_model: "initialpermissions",
    pk_cast: PkCast::Bigint,
    db_table: "authentik_rbac_initialpermissions",
    pk_column: "id",
};

/// Readable serializer sources; `permissions` (the m2m, also the source of
/// `permissions_obj`) orders through a join that duplicates rows and is
/// left to Django.
const ORDERING: &[(&str, &str)] = &[
    ("pk", "t.\"id\""),
    ("name", "t.\"name\""),
    ("role", "t.\"role_id\""),
];

/// `InitialPermissionsSerializer`.
#[derive(Serialize)]
pub(crate) struct InitialPermissions {
    pk: i32,
    name: String,
    role: String,
    permissions: Vec<i32>,
    permissions_obj: Vec<Permission>,
}

pub(crate) async fn filter_queryset(
    ctx: &Context<'_>,
    query: &QueryDict,
    user: &User,
    allow: &'static str,
) -> Result<Result<QuerySet, Answer>, Decline> {
    let mut qs = QuerySet::new(MODEL.db_table, MODEL.pk_column);
    let terms = match search_terms(query, allow) {
        Ok(terms) => terms,
        Err(answer) => return Ok(Err(answer)),
    };
    for term in &terms {
        let cond = qs.icontains("name", term);
        qs.filter(cond);
    }
    if let Err(answer) = object_filter(ctx, user, &MODEL, &mut qs, allow).await? {
        return Ok(Err(answer));
    }
    match char_field(query.get("name")) {
        Ok(name) if !name.is_empty() => {
            let p = qs.bind(Bind::Text(name));
            qs.filter(format!("t.\"name\" = {p}"));
        }
        Ok(_) => {}
        Err(e) => return Ok(Err(drf::field_errors(&[("name", e.to_owned())], allow))),
    }
    Ok(Ok(qs))
}

/// The rows plus their `permissions.all()` in `Permission`'s default
/// ordering (`content_type__app_label`, `content_type__model`, `codename`).
pub(crate) async fn serialize(
    ctx: &Context<'_>,
    rows: &[sqlx::postgres::PgRow],
) -> Result<Vec<InitialPermissions>, Decline> {
    let db = |_| Decline("database error");
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let role: Uuid = row.try_get(2).map_err(db)?;
        out.push(InitialPermissions {
            pk: row.try_get(0).map_err(db)?,
            name: row.try_get(1).map_err(db)?,
            role: role.to_string(),
            permissions: Vec::new(),
            permissions_obj: Vec::new(),
        });
    }
    let ids: Vec<i32> = out.iter().map(|ip| ip.pk).collect();
    if ids.is_empty() {
        return Ok(out);
    }
    let perms = sqlx::query(
        "SELECT p.id, p.name, p.content_type_id, p.codename, c.id, c.app_label, c.model, \
         x.initialpermissions_id FROM auth_permission p INNER JOIN \
         authentik_rbac_initialpermissions_permissions x ON x.permission_id = p.id INNER JOIN \
         django_content_type c ON c.id = p.content_type_id WHERE x.initialpermissions_id = \
         ANY($1) ORDER BY c.app_label ASC, c.model ASC, p.codename ASC",
    )
    .bind(&ids)
    .fetch_all(ctx.pool)
    .await
    .map_err(db)?;
    for row in &perms {
        let owner: i32 = row.try_get(7).map_err(db)?;
        if let Some(ip) = out.iter_mut().find(|ip| ip.pk == owner) {
            let perm = permission(row)?;
            ip.permissions.push(perm.id);
            ip.permissions_obj.push(perm);
        }
    }
    Ok(out)
}

pub(crate) const COLUMNS: &str = "t.\"id\", t.\"name\", t.\"role_id\"";

/// `GET /api/v3/rbac/initial_permissions/`.
pub async fn list(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
    query: &QueryDict,
) -> Result<Answer, Decline> {
    let tenant = drf::tenant(ctx, req).await?;
    let user = match drf::authenticate(ctx, req, ALLOW_LIST).await? {
        Ok(user) => user,
        Err(answer) => return Ok(answer),
    };
    if !user.is_authenticated() {
        return Ok(drf::permission_denied(&user, ALLOW_LIST));
    }
    let qs = match filter_queryset(ctx, query, &user, ALLOW_LIST).await? {
        Ok(qs) => qs,
        Err(answer) => return Ok(answer),
    };
    let order = ordering(query, ORDERING, &["permissions"], &["t.\"name\" ASC"])?;
    let size = page_size(query, &tenant)?;
    let count = qs.count(ctx.pool).await?;
    let Some(page) = Page::choose(query, size, count)? else {
        return Ok(drf::detail(404, "Invalid page.", ALLOW_LIST));
    };
    let rows = qs
        .fetch(ctx.pool, COLUMNS, &order, Some(page.slice()))
        .await?;
    let results = serialize(ctx, &rows).await?;
    Ok(drf::json(200, &page.response(results), ALLOW_LIST))
}

/// `GET /api/v3/rbac/initial_permissions/{pk}/`.
pub async fn retrieve(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
    query: &QueryDict,
    pk: &str,
) -> Result<Answer, Decline> {
    drf::tenant(ctx, req).await?;
    let user = match drf::authenticate(ctx, req, ALLOW_DETAIL).await? {
        Ok(user) => user,
        Err(answer) => return Ok(answer),
    };
    let mut qs = match filter_queryset(ctx, query, &user, ALLOW_DETAIL).await? {
        Ok(qs) => qs,
        Err(answer) => return Ok(answer),
    };
    let not_found = "No InitialPermissions matches the given query.";
    let id = match py_int(pk).map_err(|_| Decline("pk digits"))? {
        None => return Ok(drf::detail(404, "Not found.", ALLOW_DETAIL)),
        Some(value) => int4(value),
    };
    let Some(id) = id else {
        return Ok(drf::detail(404, not_found, ALLOW_DETAIL));
    };
    let p = qs.bind(Bind::Int(id));
    qs.filter(format!("t.\"id\" = {p}"));
    let rows = qs.fetch(ctx.pool, COLUMNS, &[], None).await?;
    if rows.is_empty() {
        return Ok(drf::detail(404, not_found, ALLOW_DETAIL));
    }
    let pk_text = id.to_string();
    let access = ak_rbac::has_object_permission(
        ctx.pool,
        user.subject(),
        "GET",
        &Object {
            model: MODEL,
            pk: &pk_text,
        },
        false,
    )
    .await
    .map_err(|_| Decline("object permission raised"))?;
    match access {
        Access::Allow => {
            let mut results = serialize(ctx, &rows).await?;
            let one = results.pop().ok_or(Decline("database error"))?;
            Ok(drf::json(200, &one, ALLOW_DETAIL))
        }
        Access::NotFound => Ok(drf::detail(404, "Not found.", ALLOW_DETAIL)),
        Access::Deny => Ok(drf::permission_denied(&user, ALLOW_DETAIL)),
    }
}
