//! `authentik.rbac.api.rbac_assigned_by_roles.RoleAssignedPermissionViewSet`:
//! `list`.
//!
//! Roles holding a permission on one model (and, with `object_pk`, on
//! one object). `RoleAssignedPermissionFilter` requires `model` (one of
//! `model_choices()`), and its `filter_queryset` does the filtering with
//! the subqueries below, as Django sends them. It keeps the default
//! pagination (`autocomplete: {}`).

use serde::Serialize;
use sqlx::Row as _;
use uuid::Uuid;

use crate::{
    Answer, Decline,
    drf::{self, ApiRequest, Context, User},
    pagination::{Page, page_size},
    py::{QueryDict, strip},
    registry,
    sql::{Bind, DjangoQuery},
    views::{
        common::{django_object_filter, django_search, ordering, search_terms},
        rbac_roles,
    },
};

const ALLOW_LIST: &str = "GET, HEAD, OPTIONS";

const FROM: &str = "\"authentik_rbac_role\"";
const SELECT: &str = "\"authentik_rbac_role\".\"managed\", \"authentik_rbac_role\".\"uuid\", \
                      \"authentik_rbac_role\".\"name\"";

/// `ordering = ["name"]`; the serializer's readable sources are `pk`
/// (`role_pk`) and `name`.
const ORDERING: &[(&str, &str)] = &[
    ("pk", "\"authentik_rbac_role\".\"uuid\""),
    ("name", "\"authentik_rbac_role\".\"name\""),
];

/// `RoleObjectPermissionSerializer`.
#[derive(Serialize)]
struct ObjectPermission {
    id: i32,
    codename: String,
    model: String,
    app_label: String,
    object_pk: String,
    name: String,
}

/// `RoleModelPermissionSerializer`.
#[derive(Serialize)]
struct ModelPermission {
    id: i32,
    codename: String,
    model: String,
    app_label: String,
    name: String,
}

/// `RoleAssignedObjectPermissionSerializer`.
#[derive(Serialize)]
struct RoleAssigned {
    role_pk: String,
    name: String,
    object_permissions: Vec<ObjectPermission>,
    model_permissions: Vec<ModelPermission>,
}

fn db(_: sqlx::Error) -> Decline {
    Decline("database error")
}

/// `(codename, name)` of a permission and `(app_label, model)` of a
/// content type, as the serializer's `source` lookups read them.
async fn permission(pool: &sqlx::PgPool, id: i32) -> Result<(String, String), Decline> {
    sqlx::query_as("SELECT codename, name FROM auth_permission WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(db)
}

async fn content_type(pool: &sqlx::PgPool, id: i32) -> Result<(String, String), Decline> {
    sqlx::query_as("SELECT app_label, model FROM django_content_type WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .map_err(db)
}

async fn serialize(
    ctx: &Context<'_>,
    rows: &[sqlx::postgres::PgRow],
) -> Result<Vec<RoleAssigned>, Decline> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let uuid: Uuid = row.try_get(1).map_err(db)?;
        let objects = sqlx::query(
            "SELECT \"guardian_roleobjectpermission\".\"id\", \"guardian_roleobjectpermission\".\"content_type_id\", \
             \"guardian_roleobjectpermission\".\"permission_id\", \"guardian_roleobjectpermission\".\"role_id\", \
             \"guardian_roleobjectpermission\".\"object_pk\" FROM \"guardian_roleobjectpermission\" WHERE \
             \"guardian_roleobjectpermission\".\"role_id\" = $1",
        )
        .bind(uuid)
        .fetch_all(ctx.pool)
        .await
        .map_err(db)?;
        let models = sqlx::query(
            "SELECT \"guardian_rolemodelpermission\".\"id\", \"guardian_rolemodelpermission\".\"content_type_id\", \
             \"guardian_rolemodelpermission\".\"permission_id\", \"guardian_rolemodelpermission\".\"role_id\" \
             FROM \"guardian_rolemodelpermission\" WHERE \"guardian_rolemodelpermission\".\"role_id\" = $1",
        )
        .bind(uuid)
        .fetch_all(ctx.pool)
        .await
        .map_err(db)?;
        let mut object_permissions = Vec::with_capacity(objects.len());
        for r in &objects {
            let (app_label, model) = content_type(ctx.pool, r.try_get(1).map_err(db)?).await?;
            let (codename, name) = permission(ctx.pool, r.try_get(2).map_err(db)?).await?;
            object_permissions.push(ObjectPermission {
                id: r.try_get(0).map_err(db)?,
                codename,
                model,
                app_label,
                object_pk: r.try_get(4).map_err(db)?,
                name,
            });
        }
        let mut model_permissions = Vec::with_capacity(models.len());
        for r in &models {
            let (app_label, model) = content_type(ctx.pool, r.try_get(1).map_err(db)?).await?;
            let (codename, name) = permission(ctx.pool, r.try_get(2).map_err(db)?).await?;
            model_permissions.push(ModelPermission {
                id: r.try_get(0).map_err(db)?,
                codename,
                model,
                app_label,
                name,
            });
        }
        out.push(RoleAssigned {
            role_pk: uuid.to_string(),
            name: row.try_get(2).map_err(db)?,
            object_permissions,
            model_permissions,
        });
    }
    Ok(out)
}

async fn filter_queryset(
    ctx: &Context<'_>,
    query: &QueryDict,
    user: &User,
    allow: &'static str,
) -> Result<Result<DjangoQuery, Answer>, Decline> {
    let mut qs = DjangoQuery::new(FROM, SELECT, &[]);
    let terms = match search_terms(query, allow) {
        Ok(terms) => terms,
        Err(answer) => return Ok(Err(answer)),
    };
    django_search(&mut qs, &["\"authentik_rbac_role\".\"name\""], &terms);
    if let Err(answer) = django_object_filter(ctx, user, &rbac_roles::MODEL, &mut qs, allow).await?
    {
        return Ok(Err(answer));
    }
    // `RoleAssignedPermissionFilter`: `model` (required `ChoiceField`, not
    // stripped), then `object_pk` (`CharField`).
    let mut errors = Vec::new();
    let model = query.get("model").unwrap_or_default();
    if model.is_empty() {
        errors.push(("model", "This field is required.".to_owned()));
    } else if !registry::is_model_choice(model) {
        errors.push((
            "model",
            format!("Select a valid choice. {model} is not one of the available choices."),
        ));
    }
    let object_pk = strip(query.get("object_pk").unwrap_or_default());
    if object_pk.contains('\0') {
        errors.push(("object_pk", "Null characters are not allowed.".to_owned()));
    }
    if !errors.is_empty() {
        return Ok(Err(drf::field_errors(&errors, allow)));
    }
    let (app, model) = model.split_once('.').ok_or(Decline("model choice"))?;
    let pa = qs.bind(Bind::Text(app.to_owned()));
    let pm = qs.bind(Bind::Text(model.to_owned()));
    let by_model = format!(
        "\"authentik_rbac_role\".\"uuid\" IN (SELECT DISTINCT U2.\"role_id\" AS \"rolemodelpermission__role\" \
         FROM \"auth_permission\" U0 INNER JOIN \"django_content_type\" U1 ON (U0.\"content_type_id\" = U1.\"id\") \
         LEFT OUTER JOIN \"guardian_rolemodelpermission\" U2 ON (U0.\"id\" = U2.\"permission_id\") WHERE \
         (U1.\"app_label\" = {pa} AND U1.\"model\" = {pm}))"
    );
    if object_pk.is_empty() {
        // `pk__in=[]` drops out of the OR.
        qs.filter(by_model);
    } else {
        let po = qs.bind(Bind::Text(object_pk.to_owned()));
        qs.filter(format!(
            "({by_model} OR \"authentik_rbac_role\".\"uuid\" IN (SELECT DISTINCT V0.\"role_id\" AS \"role\" FROM \
             \"guardian_roleobjectpermission\" V0 WHERE (V0.\"object_pk\" = {po} AND V0.\"permission_id\" IN \
             (SELECT U0.\"id\" FROM \"auth_permission\" U0 INNER JOIN \"django_content_type\" U1 ON \
             (U0.\"content_type_id\" = U1.\"id\") WHERE (U1.\"app_label\" = {pa} AND U1.\"model\" = {pm})))))"
        ));
    }
    Ok(Ok(qs))
}

/// `GET /api/v3/rbac/permissions/assigned_by_roles/`.
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
    // The nested serializers' sources are reverse relations Django cannot
    // order by (`FieldError`).
    let order = ordering(
        query,
        ORDERING,
        &["roleobjectpermission_set", "rolemodelpermission_set"],
        &["\"authentik_rbac_role\".\"name\" ASC"],
    )?;
    let size = page_size(query, &tenant)?;
    let count = qs.count(ctx.pool).await?;
    let Some(page) = Page::choose(query, size, count)? else {
        return Ok(drf::detail(404, "Invalid page.", ALLOW_LIST));
    };
    let rows = qs.fetch(ctx.pool, &order, Some(page.slice())).await?;
    let results = serialize(ctx, &rows).await?;
    Ok(drf::json(200, &page.response(results), ALLOW_LIST))
}
