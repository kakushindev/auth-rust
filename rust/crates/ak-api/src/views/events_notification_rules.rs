//! `NotificationRuleViewSet`: `list` and `retrieve`.
//!
//! `authentik.events.api.notification_rules`, on the default backends. The
//! model inherits `PolicyBindingModel`. `destination_group__name` lookups
//! join the group: `LEFT OUTER` for the search alone (an OR), `INNER` once
//! the filter (an AND) uses it. `destination_group_obj` is `GroupSerializer`
//! on `rule.destination_group`, without prefetches.

use ak_rbac::{Access, Model, Object, PkCast};
use serde::Serialize;
use sqlx::Row as _;
use uuid::Uuid;

use crate::{
    Answer, Decline,
    drf::{self, ApiRequest, Context, User},
    filters::{self, Field, Kind},
    pagination::{Page, page_size},
    py::{QueryDict, UuidLookup, strip, uuid_lookup},
    sql::{Bind, DjangoQuery},
    views::{
        common::{django_object_filter, django_search, ordering, search_terms},
        core_groups::{self, GroupData},
    },
};

const ALLOW_LIST: &str = "GET, POST, HEAD, OPTIONS";
const ALLOW_DETAIL: &str = "GET, PUT, PATCH, DELETE, HEAD, OPTIONS";

const MODEL: Model<'static> = Model {
    app_label: "authentik_events",
    model_name: "notificationrule",
    ctype_app_label: "authentik_events",
    ctype_model: "notificationrule",
    pk_cast: PkCast::Uuid,
    db_table: "authentik_events_notificationrule",
    pk_column: "policybindingmodel_ptr_id",
};

macro_rules! col {
    ($c:literal) => {
        concat!("\"authentik_events_notificationrule\".\"", $c, "\"")
    };
}

const FROM: &str = "\"authentik_events_notificationrule\"";
const SELECT: &str = concat!(
    "\"authentik_policies_policybindingmodel\".\"pbm_uuid\", ",
    "\"authentik_policies_policybindingmodel\".\"policy_engine_mode\", ",
    col!("policybindingmodel_ptr_id"),
    ", ",
    col!("name"),
    ", ",
    col!("severity"),
    ", ",
    col!("destination_group_id"),
    ", ",
    col!("destination_event_user"),
);
const JOIN_PARENT: &str = "INNER JOIN \"authentik_policies_policybindingmodel\" ON \
                           (\"authentik_events_notificationrule\".\"policybindingmodel_ptr_id\" = \
                           \"authentik_policies_policybindingmodel\".\"pbm_uuid\")";
const JOIN_GROUP_OUTER: &str = "LEFT OUTER JOIN \"authentik_core_group\" ON \
                                (\"authentik_events_notificationrule\".\"destination_group_id\" = \
                                \"authentik_core_group\".\"group_uuid\")";
const JOIN_GROUP_INNER: &str = "INNER JOIN \"authentik_core_group\" ON \
                                (\"authentik_events_notificationrule\".\"destination_group_id\" = \
                                \"authentik_core_group\".\"group_uuid\")";
const GROUP_NAME: &str = "\"authentik_core_group\".\"name\"";

const FILTERS: &[Field] = &[
    Field {
        name: "name",
        kind: Kind::Char {
            column: col!("name"),
        },
    },
    Field {
        name: "severity",
        kind: Kind::Choice {
            column: col!("severity"),
            choices: &["notice", "warning", "alert"],
        },
    },
    Field {
        name: "destination_group__name",
        kind: Kind::Char { column: GROUP_NAME },
    },
];

const ORDERING: &[(&str, &str)] = &[
    ("pk", col!("policybindingmodel_ptr_id")),
    ("name", col!("name")),
    ("severity", col!("severity")),
    ("destination_group", col!("destination_group_id")),
    ("destination_event_user", col!("destination_event_user")),
];

/// `NotificationRuleSerializer`.
#[derive(Serialize)]
struct RuleData {
    pk: String,
    name: String,
    transports: Vec<String>,
    severity: String,
    destination_group: Option<String>,
    destination_group_obj: Option<GroupData>,
    destination_event_user: bool,
}

fn db(_: sqlx::Error) -> Decline {
    Decline("database error")
}

async fn serialize(
    ctx: &Context<'_>,
    query: &QueryDict,
    rows: &[sqlx::postgres::PgRow],
) -> Result<Vec<RuleData>, Decline> {
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let pk: Uuid = row.try_get(2).map_err(db)?;
        let transports: Vec<Uuid> = sqlx::query_scalar(
            "SELECT \"authentik_events_notificationtransport\".\"uuid\" FROM \
             \"authentik_events_notificationtransport\" INNER JOIN \
             \"authentik_events_notificationrule_transports\" ON \
             (\"authentik_events_notificationtransport\".\"uuid\" = \
             \"authentik_events_notificationrule_transports\".\"notificationtransport_id\") WHERE \
             \"authentik_events_notificationrule_transports\".\"notificationrule_id\" = $1",
        )
        .bind(pk)
        .fetch_all(ctx.pool)
        .await
        .map_err(db)?;
        let group: Option<Uuid> = row.try_get(5).map_err(db)?;
        let group_obj = match group {
            None => None,
            Some(id) => {
                let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
                    "SELECT {} FROM \"authentik_core_group\" WHERE \
                     \"authentik_core_group\".\"group_uuid\" = $1 LIMIT 21",
                    core_groups::SELECT
                )))
                .bind(id)
                .fetch_all(ctx.pool)
                .await
                .map_err(db)?;
                core_groups::serialize_groups(ctx, query, &rows, false)
                    .await?
                    .pop()
            }
        };
        out.push(RuleData {
            pk: pk.to_string(),
            name: row.try_get(3).map_err(db)?,
            transports: transports.iter().map(Uuid::to_string).collect(),
            severity: row.try_get(4).map_err(db)?,
            destination_group: group.map(|g| g.to_string()),
            destination_group_obj: group_obj,
            destination_event_user: row.try_get(6).map_err(db)?,
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
    let group_filter = {
        let v = strip(query.get("destination_group__name").unwrap_or_default());
        !v.is_empty() && !v.contains('\0')
    };
    if !terms.is_empty() {
        qs.join(JOIN_GROUP_OUTER);
    }
    qs.join(JOIN_PARENT);
    django_search(&mut qs, &[col!("name"), GROUP_NAME], &terms);
    // `ObjectFilter`'s `exists()` sees only the search's join.
    if let Err(answer) = django_object_filter(ctx, user, &MODEL, &mut qs, allow).await? {
        return Ok(Err(answer));
    }
    if group_filter {
        qs.demote_join(JOIN_GROUP_OUTER, JOIN_GROUP_INNER);
    }
    match filters::clean(ctx.pool, query, FILTERS).await? {
        Ok(form) => {
            form.apply(&mut qs);
        }
        Err(errors) => return Ok(Err(drf::field_errors(&errors, allow))),
    }
    Ok(Ok(qs))
}

/// `GET /api/v3/events/rules/`.
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
        &["transports"],
        &[concat!(
            "\"authentik_events_notificationrule\".\"name\"",
            " ASC"
        )],
    )?;
    let size = page_size(query, &tenant)?;
    let count = qs.count(ctx.pool).await?;
    let Some(page) = Page::choose(query, size, count)? else {
        return Ok(drf::detail(404, "Invalid page.", ALLOW_LIST));
    };
    let rows = qs.fetch(ctx.pool, &order, Some(page.slice())).await?;
    let results = serialize(ctx, query, &rows).await?;
    Ok(drf::json(200, &page.response(results), ALLOW_LIST))
}

/// `GET /api/v3/events/rules/{pk}/`.
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
    match rows.len() {
        0 => {
            return Ok(drf::detail(
                404,
                "No NotificationRule matches the given query.",
                ALLOW_DETAIL,
            ));
        }
        1 => {}
        _ => return Err(Decline("multiple objects")),
    }
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
        Access::Allow => {
            let mut one = serialize(ctx, query, &rows).await?;
            Ok(drf::json(
                200,
                &one.pop().ok_or(Decline("database error"))?,
                ALLOW_DETAIL,
            ))
        }
        Access::NotFound => Ok(drf::detail(404, "Not found.", ALLOW_DETAIL)),
        Access::Deny => Ok(drf::permission_denied(&user, ALLOW_DETAIL)),
    }
}
