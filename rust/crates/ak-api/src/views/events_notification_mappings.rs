//! `NotificationWebhookMappingViewSet`: `list` and `retrieve`.
//!
//! `authentik.events.api.notification_mappings`, on the default backends
//! with `filterset_fields`, `search_fields` and `ordering` all `name`. The
//! model inherits `PropertyMapping` (multi-table), so Django joins the
//! parent table.

use ak_rbac::{Access, Model, Object, PkCast};
use serde::Serialize;
use sqlx::Row as _;
use uuid::Uuid;

use crate::{
    Answer, Decline,
    drf::{self, ApiRequest, Context, User},
    filters::{self, Field, Kind},
    pagination::{Page, page_size},
    py::{QueryDict, UuidLookup, uuid_lookup},
    sql::{Bind, DjangoQuery},
    views::common::{django_object_filter, django_search, ordering, search_terms},
};

const ALLOW_LIST: &str = "GET, POST, HEAD, OPTIONS";
const ALLOW_DETAIL: &str = "GET, PUT, PATCH, DELETE, HEAD, OPTIONS";

const MODEL: Model<'static> = Model {
    app_label: "authentik_events",
    model_name: "notificationwebhookmapping",
    ctype_app_label: "authentik_events",
    ctype_model: "notificationwebhookmapping",
    pk_cast: PkCast::Uuid,
    db_table: "authentik_events_notificationwebhookmapping",
    pk_column: "propertymapping_ptr_id",
};

const PK: &str = "\"authentik_events_notificationwebhookmapping\".\"propertymapping_ptr_id\"";
const NAME: &str = "\"authentik_core_propertymapping\".\"name\"";
const FROM: &str = "\"authentik_events_notificationwebhookmapping\"";
const SELECT: &str = "\"authentik_core_propertymapping\".\"pm_uuid\", \
                      \"authentik_core_propertymapping\".\"managed\", \
                      \"authentik_core_propertymapping\".\"name\", \
                      \"authentik_core_propertymapping\".\"expression\", \
                      \"authentik_events_notificationwebhookmapping\".\"propertymapping_ptr_id\"";
const JOIN_PARENT: &str = "INNER JOIN \"authentik_core_propertymapping\" ON \
                           (\"authentik_events_notificationwebhookmapping\".\"propertymapping_ptr_id\" \
                           = \"authentik_core_propertymapping\".\"pm_uuid\")";

const FILTERS: &[Field] = &[Field {
    name: "name",
    kind: Kind::Char { column: NAME },
}];

const ORDERING: &[(&str, &str)] = &[
    ("pk", PK),
    ("name", NAME),
    (
        "expression",
        "\"authentik_core_propertymapping\".\"expression\"",
    ),
];

/// `NotificationWebhookMappingSerializer`.
#[derive(Serialize)]
struct Mapping {
    pk: String,
    name: String,
    expression: String,
}

fn mapping(row: &sqlx::postgres::PgRow) -> Result<Mapping, Decline> {
    let db = |_| Decline("database error");
    let pk: Uuid = row.try_get(4).map_err(db)?;
    Ok(Mapping {
        pk: pk.to_string(),
        name: row.try_get(2).map_err(db)?,
        expression: row.try_get(3).map_err(db)?,
    })
}

async fn filter_queryset(
    ctx: &Context<'_>,
    query: &QueryDict,
    user: &User,
    allow: &'static str,
) -> Result<Result<DjangoQuery, Answer>, Decline> {
    let mut qs = DjangoQuery::new(FROM, SELECT, &[JOIN_PARENT]);
    let terms = match search_terms(query, allow) {
        Ok(terms) => terms,
        Err(answer) => return Ok(Err(answer)),
    };
    django_search(&mut qs, &[NAME], &terms);
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

/// `GET /api/v3/propertymappings/notification/`.
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
        &["\"authentik_core_propertymapping\".\"name\" ASC"],
    )?;
    let size = page_size(query, &tenant)?;
    let count = qs.count(ctx.pool).await?;
    let Some(page) = Page::choose(query, size, count)? else {
        return Ok(drf::detail(404, "Invalid page.", ALLOW_LIST));
    };
    let rows = qs.fetch(ctx.pool, &order, Some(page.slice())).await?;
    let results = rows.iter().map(mapping).collect::<Result<Vec<_>, _>>()?;
    Ok(drf::json(200, &page.response(results), ALLOW_LIST))
}

/// `GET /api/v3/propertymappings/notification/{pk}/`.
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
    qs.filter(format!("{PK} = {p}"));
    let rows = qs.fetch(ctx.pool, &[], None).await?;
    let Some(row) = rows.first() else {
        return Ok(drf::detail(
            404,
            "No NotificationWebhookMapping matches the given query.",
            ALLOW_DETAIL,
        ));
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
        Access::Allow => Ok(drf::json(200, &mapping(row)?, ALLOW_DETAIL)),
        Access::NotFound => Ok(drf::detail(404, "Not found.", ALLOW_DETAIL)),
        Access::Deny => Ok(drf::permission_denied(&user, ALLOW_DETAIL)),
    }
}
