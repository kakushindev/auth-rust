//! `ApplicationEntitlementViewSet`: `list` and `retrieve`.
//!
//! `authentik.core.api.application_entitlements`, on the default backends.
//! The model inherits `PolicyBindingModel`; `name` is only unique per
//! `app`, so ordering ties are possible and the SQL is Django's text.

use ak_rbac::{Access, Model, Object, PkCast};
use serde::Serialize;
use serde_json::value::RawValue;
use sqlx::Row as _;
use uuid::Uuid;

use crate::{
    Answer, Decline,
    drf::{self, ApiRequest, Context, User},
    filters::{self, Field, Kind},
    json::render_jsonb,
    pagination::{Page, page_size},
    py::{QueryDict, UuidLookup, uuid_lookup},
    sql::{Bind, DjangoQuery},
    views::common::{django_object_filter, django_search, ordering, search_terms},
};

const ALLOW_LIST: &str = "GET, POST, HEAD, OPTIONS";
const ALLOW_DETAIL: &str = "GET, PUT, PATCH, DELETE, HEAD, OPTIONS";

const MODEL: Model<'static> = Model {
    app_label: "authentik_core",
    model_name: "applicationentitlement",
    ctype_app_label: "authentik_core",
    ctype_model: "applicationentitlement",
    pk_cast: PkCast::Uuid,
    db_table: "authentik_core_applicationentitlement",
    pk_column: "policybindingmodel_ptr_id",
};

macro_rules! col {
    ($c:literal) => {
        concat!("\"authentik_core_applicationentitlement\".\"", $c, "\"")
    };
}

const FROM: &str = "\"authentik_core_applicationentitlement\"";
const SELECT: &str = concat!(
    "\"authentik_policies_policybindingmodel\".\"pbm_uuid\", ",
    "\"authentik_policies_policybindingmodel\".\"policy_engine_mode\", ",
    col!("policybindingmodel_ptr_id"),
    ", ",
    col!("attributes"),
    "::text, ",
    col!("name"),
    ", ",
    col!("app_id"),
);
const JOIN_PARENT: &str = "INNER JOIN \"authentik_policies_policybindingmodel\" ON \
                           (\"authentik_core_applicationentitlement\".\"policybindingmodel_ptr_id\" = \
                           \"authentik_policies_policybindingmodel\".\"pbm_uuid\")";
/// `app__…` search lookups (a non-null foreign key: `INNER`).
const JOIN_APP: &str = "INNER JOIN \"authentik_core_application\" ON \
                        (\"authentik_core_applicationentitlement\".\"app_id\" = \
                        \"authentik_core_application\".\"policybindingmodel_ptr_id\")";

const FILTERS: &[Field] = &[
    Field {
        name: "pbm_uuid",
        kind: Kind::Uuid {
            column: col!("policybindingmodel_ptr_id"),
        },
    },
    Field {
        name: "name",
        kind: Kind::Char {
            column: col!("name"),
        },
    },
    Field {
        name: "app",
        kind: Kind::ForeignKeyUuid {
            column: col!("app_id"),
            target: ("authentik_core_application", "policybindingmodel_ptr_id"),
        },
    },
];

const SEARCH: &[&str] = &[
    col!("policybindingmodel_ptr_id"),
    col!("name"),
    "\"authentik_core_application\".\"name\"",
    "\"authentik_core_application\".\"slug\"",
    col!("attributes"),
];

const ORDERING: &[(&str, &str)] = &[
    ("pbm_uuid", col!("policybindingmodel_ptr_id")),
    ("name", col!("name")),
    ("app", col!("app_id")),
    ("attributes", col!("attributes")),
];

/// `ApplicationEntitlementSerializer`.
#[derive(Serialize)]
struct EntitlementData {
    pbm_uuid: String,
    name: String,
    app: String,
    attributes: Box<RawValue>,
}

fn db(_: sqlx::Error) -> Decline {
    Decline("database error")
}

fn entitlement(row: &sqlx::postgres::PgRow) -> Result<EntitlementData, Decline> {
    let pk: Uuid = row.try_get(2).map_err(db)?;
    let attributes: String = row.try_get(3).map_err(db)?;
    let app: Uuid = row.try_get(5).map_err(db)?;
    Ok(EntitlementData {
        pbm_uuid: pk.to_string(),
        name: row.try_get(4).map_err(db)?,
        app: app.to_string(),
        attributes: RawValue::from_string(render_jsonb(&attributes)?)
            .map_err(|_| Decline("jsonb rendering"))?,
    })
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
    if !terms.is_empty() {
        qs.join(JOIN_APP);
    }
    qs.join(JOIN_PARENT);
    django_search(&mut qs, SEARCH, &terms);
    if let Err(answer) = django_object_filter(ctx, user, &MODEL, &mut qs, allow).await? {
        return Ok(Err(answer));
    }
    match filters::clean(ctx.pool, query, FILTERS).await? {
        Ok(form) => {
            form.apply(&mut qs);
        }
        Err(errors) => return Ok(Err(drf::field_errors(&errors, allow))),
    }
    Ok(Ok(qs))
}

/// `GET /api/v3/core/application_entitlements/`.
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
    let order = ordering(
        query,
        ORDERING,
        &[],
        &[concat!(
            "\"authentik_core_applicationentitlement\".\"name\"",
            " ASC"
        )],
    )?;
    let size = page_size(query, &tenant)?;
    let count = qs.count(ctx.pool).await?;
    let Some(page) = Page::choose(query, size, count)? else {
        return Ok(drf::detail(404, "Invalid page.", ALLOW_LIST));
    };
    let rows = qs.fetch(ctx.pool, &order, Some(page.slice())).await?;
    let results = rows
        .iter()
        .map(entitlement)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(drf::json(200, &page.response(results), ALLOW_LIST))
}

/// `GET /api/v3/core/application_entitlements/{pk}/`.
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
    let uuid = match uuid_lookup(pk).map_err(|_| Decline("pk syntax"))? {
        UuidLookup::Valid(uuid) => uuid,
        UuidLookup::Invalid => return Ok(drf::detail(404, "Not found.", ALLOW_DETAIL)),
    };
    let p = qs.bind(Bind::Uuid(uuid));
    qs.filter(format!("{} = {p}", col!("policybindingmodel_ptr_id")));
    let rows = qs.fetch(ctx.pool, &[], None).await?;
    let row = match rows.as_slice() {
        [] => {
            return Ok(drf::detail(
                404,
                "No ApplicationEntitlement matches the given query.",
                ALLOW_DETAIL,
            ));
        }
        [row] => row,
        _ => return Err(Decline("multiple objects")),
    };
    let pk_text = uuid.to_string();
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
        Access::Allow => Ok(drf::json(200, &entitlement(row)?, ALLOW_DETAIL)),
        Access::NotFound => Ok(drf::detail(404, "Not found.", ALLOW_DETAIL)),
        Access::Deny => Ok(drf::permission_denied(&user, ALLOW_DETAIL)),
    }
}
