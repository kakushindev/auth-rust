//! `authentik.rbac.api.rbac.RBACPermissionViewSet`: `list` and `retrieve`.
//!
//! `permission_classes = [IsAuthenticated]`, `filter_backends =
//! [DjangoFilterBackend, OrderingFilter, SearchFilter]` on
//! `Permission.objects.select_related("content_type")` limited to
//! `authentik*` apps. Permission names repeat, so the SQL is Django's.

use serde::Serialize;
use sqlx::Row as _;

use crate::{
    Answer, Decline,
    drf::{self, ApiRequest, Context},
    pagination::{Page, page_size},
    py::{QueryDict, UuidLookup, int4, py_int, search_smart_split, strip, uuid_lookup},
    registry::{app_verbose_name, model_verbose_name},
    sql::{Bind, DjangoQuery},
};

const ALLOW: &str = "GET, HEAD, OPTIONS";

const FROM: &str = "\"auth_permission\"";
const SELECT: &str = "\"auth_permission\".\"id\", \"auth_permission\".\"name\", \
                      \"auth_permission\".\"content_type_id\", \"auth_permission\".\"codename\", \
                      \"django_content_type\".\"id\", \"django_content_type\".\"app_label\", \
                      \"django_content_type\".\"model\"";
const JOIN_CONTENT_TYPE: &str = "INNER JOIN \"django_content_type\" ON \
                                 (\"auth_permission\".\"content_type_id\" = \
                                 \"django_content_type\".\"id\")";
const JOIN_ROLE: &str = "INNER JOIN \"guardian_rolemodelpermission\" ON \
                         (\"auth_permission\".\"id\" = \
                         \"guardian_rolemodelpermission\".\"permission_id\")";

const NAME: &str = "\"auth_permission\".\"name\"";
const CODENAME: &str = "\"auth_permission\".\"codename\"";
const MODEL: &str = "\"django_content_type\".\"model\"";
const APP_LABEL: &str = "\"django_content_type\".\"app_label\"";

/// `PermissionSerializer`.
#[derive(Serialize)]
pub(crate) struct Permission {
    pub(crate) id: i32,
    name: String,
    codename: String,
    model: String,
    app_label: String,
    app_label_verbose: String,
    model_verbose: String,
}

/// `get_queryset()`.
fn queryset() -> DjangoQuery {
    let mut qs = DjangoQuery::new(FROM, SELECT, &[JOIN_CONTENT_TYPE]);
    let p = qs.bind(Bind::Text("authentik%".to_owned()));
    qs.filter(format!("{APP_LABEL}::text LIKE {p}"));
    qs
}

/// `forms.CharField.clean` (`strip=True`, no NUL).
fn char_field(value: Option<&str>) -> Result<String, &'static str> {
    let value = strip(value.unwrap_or_default());
    if value.contains('\0') {
        return Err("Null characters are not allowed.");
    }
    Ok(value.to_owned())
}

/// `PermissionFilter` validation and filtering (`codename`,
/// `content_type__model`, `content_type__app_label` exact; `role` a
/// `ModelChoiceFilter` on roles).
async fn filterset(
    ctx: &Context<'_>,
    query: &QueryDict,
    qs: &mut DjangoQuery,
) -> Result<Option<Answer>, Decline> {
    let mut errors: Vec<(&str, String)> = Vec::new();
    let mut exact = Vec::new();
    for (field, column) in [
        ("codename", CODENAME),
        ("content_type__model", MODEL),
        ("content_type__app_label", APP_LABEL),
    ] {
        match char_field(query.get(field)) {
            Ok(value) if !value.is_empty() => exact.push((column, value)),
            Ok(_) => {}
            Err(e) => errors.push((field, e.to_owned())),
        }
    }
    let mut role = None;
    if let Some(raw) = query.get("role").filter(|v| !v.is_empty()) {
        let invalid = "Select a valid choice. That choice is not one of the available choices.";
        match uuid_lookup(raw).map_err(|_| Decline("role syntax"))? {
            // `UUIDField.to_python` raises its own message, which the
            // choice field passes on.
            UuidLookup::Invalid => errors.push((
                "role",
                format!("\u{201c}{raw}\u{201d} is not a valid UUID."),
            )),
            UuidLookup::Valid(uuid) => {
                let exists: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM authentik_rbac_role WHERE uuid = $1)",
                )
                .bind(uuid)
                .fetch_one(ctx.pool)
                .await
                .map_err(|_| Decline("database error"))?;
                if exists {
                    role = Some(uuid);
                } else {
                    errors.push(("role", invalid.to_owned()));
                }
            }
        }
    }
    if !errors.is_empty() {
        return Ok(Some(drf::field_errors(&errors, ALLOW)));
    }
    for (column, value) in exact {
        let p = qs.bind(Bind::Text(value));
        qs.filter(format!("{column} = {p}"));
    }
    if let Some(role) = role {
        qs.join(JOIN_ROLE);
        let p = qs.bind(Bind::Uuid(role));
        qs.filter(format!(
            "\"guardian_rolemodelpermission\".\"role_id\" = {p}"
        ));
    }
    Ok(None)
}

/// `OrderingFilter`: the serializer's readable sources, default `name`.
fn ordering(query: &QueryDict) -> Vec<String> {
    let column = |term: &str| match term {
        "id" => Some("\"auth_permission\".\"id\""),
        "name" => Some(NAME),
        "codename" => Some(CODENAME),
        "content_type__model" => Some(MODEL),
        "content_type__app_label" => Some(APP_LABEL),
        _ => None,
    };
    let terms: Vec<String> = query
        .get("ordering")
        .filter(|v| !v.is_empty())
        .map(|v| {
            v.split(',')
                .map(strip)
                .filter_map(|term| {
                    let (desc, field) = match term.strip_prefix('-') {
                        Some(f) => (true, f),
                        None => (false, term),
                    };
                    column(field).map(|c| format!("{c} {}", if desc { "DESC" } else { "ASC" }))
                })
                .collect()
        })
        .unwrap_or_default();
    if terms.is_empty() {
        vec![format!("{NAME} ASC")]
    } else {
        terms
    }
}

/// `filter_queryset`: filterset, then search (ordering is applied at
/// fetch time).
async fn filter_queryset(
    ctx: &Context<'_>,
    query: &QueryDict,
) -> Result<Result<DjangoQuery, Answer>, Decline> {
    let mut qs = queryset();
    if let Some(answer) = filterset(ctx, query, &mut qs).await? {
        return Ok(Err(answer));
    }
    let value = query.get("search").unwrap_or_default();
    if value.contains('\0') {
        return Ok(Err(drf::json(
            400,
            &["Null characters are not allowed."],
            ALLOW,
        )));
    }
    for term in search_smart_split(value) {
        let ors: Vec<String> = [NAME, CODENAME, MODEL, APP_LABEL]
            .iter()
            .map(|column| qs.icontains(column, &term))
            .collect();
        qs.filter(format!("({})", ors.join(" OR ")));
    }
    Ok(Ok(qs))
}

pub(crate) fn permission(row: &sqlx::postgres::PgRow) -> Result<Permission, Decline> {
    let db = |_| Decline("database error");
    let app_label: String = row.try_get(5).map_err(db)?;
    let model: String = row.try_get(6).map_err(db)?;
    let fallback = format!("{app_label}.{model}");
    Ok(Permission {
        id: row.try_get(0).map_err(db)?,
        name: row.try_get(1).map_err(db)?,
        codename: row.try_get(3).map_err(db)?,
        app_label_verbose: app_verbose_name(&app_label)
            .map_or_else(|| fallback.clone(), str::to_owned),
        model_verbose: model_verbose_name(&app_label, &model).map_or(fallback, str::to_owned),
        model,
        app_label,
    })
}

/// `IsAuthenticated`.
async fn authenticated(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
) -> Result<Result<(), Answer>, Decline> {
    let user = match drf::authenticate(ctx, req, ALLOW).await? {
        Ok(user) => user,
        Err(answer) => return Ok(Err(answer)),
    };
    if !user.is_authenticated() {
        return Ok(Err(drf::permission_denied(&user, ALLOW)));
    }
    Ok(Ok(()))
}

/// `GET /api/v3/rbac/permissions/`.
pub async fn list(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
    query: &QueryDict,
) -> Result<Answer, Decline> {
    let tenant = drf::tenant(ctx, req).await?;
    if let Err(answer) = authenticated(ctx, req).await? {
        return Ok(answer);
    }
    let qs = match filter_queryset(ctx, query).await? {
        Ok(qs) => qs,
        Err(answer) => return Ok(answer),
    };
    let size = page_size(query, &tenant)?;
    let count = qs.count(ctx.pool).await?;
    let Some(page) = Page::choose(query, size, count)? else {
        return Ok(drf::detail(404, "Invalid page.", ALLOW));
    };
    let rows = qs
        .fetch(ctx.pool, &ordering(query), Some(page.slice()))
        .await?;
    let results = rows.iter().map(permission).collect::<Result<Vec<_>, _>>()?;
    Ok(drf::json(200, &page.response(results), ALLOW))
}

/// `GET /api/v3/rbac/permissions/{pk}/`.
pub async fn retrieve(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
    query: &QueryDict,
    pk: &str,
) -> Result<Answer, Decline> {
    drf::tenant(ctx, req).await?;
    if let Err(answer) = authenticated(ctx, req).await? {
        return Ok(answer);
    }
    let mut qs = match filter_queryset(ctx, query).await? {
        Ok(qs) => qs,
        Err(answer) => return Ok(answer),
    };
    // `get(pk=value)`: `int(value)`; a ValueError is DRF's bare Http404, an
    // out-of-range value an empty result (DoesNotExist).
    let id = match py_int(pk).map_err(|_| Decline("pk digits"))? {
        None => return Ok(drf::detail(404, "Not found.", ALLOW)),
        Some(value) => int4(value),
    };
    let Some(id) = id else {
        return Ok(drf::detail(
            404,
            "No Permission matches the given query.",
            ALLOW,
        ));
    };
    let p = qs.bind(Bind::Int(id));
    qs.filter(format!("\"auth_permission\".\"id\" = {p}"));
    let rows = qs.fetch(ctx.pool, &[], None).await?;
    match rows.as_slice() {
        [] => Ok(drf::detail(
            404,
            "No Permission matches the given query.",
            ALLOW,
        )),
        [row] => Ok(drf::json(200, &permission(row)?, ALLOW)),
        // MultipleObjectsReturned: a 500 left to Django.
        _ => Err(Decline("multiple objects")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_uses_sources() {
        let o = |s: &str| ordering(&QueryDict::parse(s).expect("query"));
        assert_eq!(o(""), vec![format!("{NAME} ASC")]);
        assert_eq!(o("ordering=model"), vec![format!("{NAME} ASC")]);
        assert_eq!(
            o("ordering=-content_type__model,id"),
            vec![
                format!("{MODEL} DESC"),
                "\"auth_permission\".\"id\" ASC".to_owned()
            ]
        );
    }
}
