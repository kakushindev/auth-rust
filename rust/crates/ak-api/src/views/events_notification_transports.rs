//! `NotificationTransportViewSet`: `list` and `retrieve`.
//!
//! `authentik.events.api.notification_transports`, on the default backends (`QLSearch` →
//! `SearchFilter`, `ObjectFilter`, `filterset_fields`, `OrderingFilter`
//! with `ordering = ["name"]`).

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
    model_name: "notificationtransport",
    ctype_app_label: "authentik_events",
    ctype_model: "notificationtransport",
    pk_cast: PkCast::Uuid,
    db_table: "authentik_events_notificationtransport",
    pk_column: "uuid",
};

macro_rules! col {
    ($c:literal) => {
        concat!("\"authentik_events_notificationtransport\".\"", $c, "\"")
    };
}

const FROM: &str = "\"authentik_events_notificationtransport\"";
/// Django's select list, in model field order.
const SELECT: &str = concat!(
    col!("uuid"),
    ", ",
    col!("name"),
    ", ",
    col!("mode"),
    ", ",
    col!("send_once"),
    ", ",
    col!("email_subject_prefix"),
    ", ",
    col!("email_template"),
    ", ",
    col!("webhook_url"),
    ", ",
    col!("webhook_mapping_body_id"),
    ", ",
    col!("webhook_mapping_headers_id"),
);

/// `TransportMode`: value and label.
const MODES: &[(&str, &str)] = &[
    ("local", "authentik inbuilt notifications"),
    ("webhook", "Generic Webhook"),
    ("webhook_slack", "Slack Webhook (Slack/Discord)"),
    ("email", "Email"),
];

const FILTERS: &[Field] = &[
    Field {
        name: "name",
        kind: Kind::Char {
            column: col!("name"),
        },
    },
    Field {
        name: "mode",
        kind: Kind::Choice {
            column: col!("mode"),
            choices: &["local", "webhook", "webhook_slack", "email"],
        },
    },
    Field {
        name: "webhook_url",
        kind: Kind::Char {
            column: col!("webhook_url"),
        },
    },
    Field {
        name: "send_once",
        kind: Kind::Boolean {
            column: col!("send_once"),
        },
    },
];

const SEARCH: &[&str] = &[col!("name"), col!("mode"), col!("webhook_url")];

/// Readable serializer sources (`mode_verbose` is a method field). The
/// mapping model has no `Meta.ordering`, so its keys sort by the column.
const ORDERING: &[(&str, &str)] = &[
    ("pk", col!("uuid")),
    ("name", col!("name")),
    ("mode", col!("mode")),
    ("webhook_url", col!("webhook_url")),
    ("webhook_mapping_body", col!("webhook_mapping_body_id")),
    (
        "webhook_mapping_headers",
        col!("webhook_mapping_headers_id"),
    ),
    ("email_subject_prefix", col!("email_subject_prefix")),
    ("email_template", col!("email_template")),
    ("send_once", col!("send_once")),
];

/// `NotificationTransportSerializer`.
#[derive(Serialize)]
struct NotificationTransport {
    pk: String,
    name: String,
    mode: String,
    mode_verbose: &'static str,
    webhook_url: String,
    webhook_mapping_body: Option<String>,
    webhook_mapping_headers: Option<String>,
    email_subject_prefix: String,
    email_template: String,
    send_once: bool,
}

fn transport(row: &sqlx::postgres::PgRow) -> Result<NotificationTransport, Decline> {
    let db = |_| Decline("database error");
    let uuid: Uuid = row.try_get(0).map_err(db)?;
    let mode: String = row.try_get(2).map_err(db)?;
    // `TransportMode(instance.mode)` raises for a value outside the enum.
    let Some((_, label)) = MODES.iter().find(|(value, _)| *value == mode) else {
        return Err(Decline("unknown transport mode"));
    };
    let mapping = |i: usize| -> Result<Option<String>, Decline> {
        Ok(row
            .try_get::<Option<Uuid>, _>(i)
            .map_err(|_| Decline("database error"))?
            .map(|u| u.to_string()))
    };
    Ok(NotificationTransport {
        pk: uuid.to_string(),
        name: row.try_get(1).map_err(db)?,
        mode,
        mode_verbose: label,
        webhook_url: row.try_get(6).map_err(db)?,
        webhook_mapping_body: mapping(7)?,
        webhook_mapping_headers: mapping(8)?,
        email_subject_prefix: row.try_get(4).map_err(db)?,
        email_template: row.try_get(5).map_err(db)?,
        send_once: row.try_get(3).map_err(db)?,
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

/// `GET /api/v3/events/transports/`.
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
            "\"authentik_events_notificationtransport\".\"name\"",
            " ASC"
        )],
    )?;
    let size = page_size(query, &tenant)?;
    let count = qs.count(ctx.pool).await?;
    let Some(page) = Page::choose(query, size, count)? else {
        return Ok(drf::detail(404, "Invalid page.", ALLOW_LIST));
    };
    let rows = qs.fetch(ctx.pool, &order, Some(page.slice())).await?;
    let results = rows.iter().map(transport).collect::<Result<Vec<_>, _>>()?;
    Ok(drf::json(200, &page.response(results), ALLOW_LIST))
}

/// `GET /api/v3/events/transports/{pk}/`.
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
    qs.filter(format!("{} = {p}", col!("uuid")));
    let rows = qs.fetch(ctx.pool, &[], None).await?;
    let Some(row) = rows.first() else {
        return Ok(drf::detail(
            404,
            "No NotificationTransport matches the given query.",
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
        Access::Allow => Ok(drf::json(200, &transport(row)?, ALLOW_DETAIL)),
        Access::NotFound => Ok(drf::detail(404, "Not found.", ALLOW_DETAIL)),
        Access::Deny => Ok(drf::permission_denied(&user, ALLOW_DETAIL)),
    }
}
