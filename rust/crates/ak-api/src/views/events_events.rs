//! `authentik.events.api.events.EventViewSet`: `list` and `retrieve`.
//!
//! Default backends with `EventsFilter` (JSON key lookups on `context`,
//! `user` and `brand`) and the QL `autocomplete` (R2), whose `app` options
//! are `SELECT DISTINCT app … ORDER BY 1` over every event.

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
    py::{QueryDict, UuidLookup, py_int, strip, uuid_lookup},
    sql::{Bind, DjangoQuery},
    views::common::{django_object_filter, ordering, search_terms},
};

const ALLOW_LIST: &str = "GET, POST, HEAD, OPTIONS";
const ALLOW_DETAIL: &str = "GET, PUT, PATCH, DELETE, HEAD, OPTIONS";

/// `detail=False` actions, routed before the detail route.
pub const ACTIONS: &[&str] = &["export", "top_per_user", "volume", "actions"];

const MODEL: Model<'static> = Model {
    app_label: "authentik_events",
    model_name: "event",
    ctype_app_label: "authentik_events",
    ctype_model: "event",
    pk_cast: PkCast::Uuid,
    db_table: "authentik_events_event",
    pk_column: "event_uuid",
};

macro_rules! col {
    ($c:literal) => {
        concat!("\"authentik_events_event\".\"", $c, "\"")
    };
}

const FROM: &str = "\"authentik_events_event\"";
/// Django's select list; `client_ip` through inet's output function (what
/// psycopg hands Django as text), the JSON columns as text.
pub(crate) const SELECT: &str = concat!(
    col!("expiring"),
    ", ",
    col!("event_uuid"),
    ", ",
    col!("user"),
    "::text, ",
    col!("action"),
    ", ",
    col!("app"),
    ", ",
    col!("context"),
    "::text, CASE WHEN ",
    col!("client_ip"),
    " IS NULL THEN NULL ELSE format('%s', ",
    col!("client_ip"),
    ") END, ",
    col!("created"),
    ", ",
    col!("brand"),
    "::text, ",
    col!("expires"),
);

/// `EventAction` values.
const EVENT_ACTIONS: &[&str] = &[
    "login",
    "login_failed",
    "logout",
    "user_write",
    "suspicious_request",
    "password_set",
    "secret_view",
    "secret_rotate",
    "invitation_used",
    "authorize_application",
    "source_linked",
    "impersonation_started",
    "impersonation_ended",
    "flow_execution",
    "policy_execution",
    "policy_exception",
    "property_mapping_exception",
    "system_task_execution",
    "system_task_exception",
    "system_exception",
    "configuration_error",
    "configuration_warning",
    "model_created",
    "model_updated",
    "model_deleted",
    "email_sent",
    "update_available",
    "export_ready",
    "review_initiated",
    "review_overdue",
    "review_attested",
    "review_completed",
    "custom_",
];

/// `EventsFilter.base_filters` after `action` (applied by the view):
/// `actions` is the only generic one; the rest are JSON lookups.
const ACTIONS_FILTER: &[Field] = &[Field {
    name: "actions",
    kind: Kind::MultipleChoice {
        column: col!("action"),
        choices: EVENT_ACTIONS,
    },
}];

const SEARCH: &[&str] = &[
    col!("event_uuid"),
    col!("user"),
    col!("action"),
    col!("app"),
    col!("context"),
];

const ORDERING: &[(&str, &str)] = &[
    ("pk", col!("event_uuid")),
    ("user", col!("user")),
    ("action", col!("action")),
    ("app", col!("app")),
    ("context", col!("context")),
    ("client_ip", col!("client_ip")),
    ("created", col!("created")),
    ("expires", col!("expires")),
    ("brand", col!("brand")),
];

const AUTOCOMPLETE_HEAD: &str = r#"{"current_model":"authentik_events.event","models":{"authentik_events.event":{"action":{"type":"str","nullable":false,"options":["login","login_failed","logout","user_write","suspicious_request","password_set","secret_view","secret_rotate","invitation_used","authorize_application","source_linked","impersonation_started","impersonation_ended","flow_execution","policy_execution","policy_exception","property_mapping_exception","system_task_execution","system_task_exception","system_exception","configuration_error","configuration_warning","model_created","model_updated","model_deleted","email_sent","update_available","export_ready","review_initiated","review_overdue","review_attested","review_completed","custom_"]},"event_uuid":{"type":"str","nullable":false,"options":null},"app":{"type":"str","nullable":false,"options":"#;
const AUTOCOMPLETE_TAIL: &str = r#"},"client_ip":{"type":"str","nullable":false,"options":null},"user":{"type":"relation","nullable":false,"options":null,"relation":"authentik_events.event_user"},"brand":{"type":"relation","nullable":false,"options":null,"relation":"authentik_events.event_brand"},"context":{"type":"relation","nullable":false,"options":null,"relation":"authentik_events.event_context"},"created":{"type":"datetime","nullable":false,"options":[]}},"authentik_events.event_user":{"pk":{"type":"int","nullable":false,"options":null},"username":{"type":"str","nullable":false,"options":null},"email":{"type":"str","nullable":false,"options":null}},"authentik_events.event_brand":{"pk":{"type":"str","nullable":false,"options":null},"app":{"type":"str","nullable":false,"options":null},"name":{"type":"str","nullable":false,"options":null},"model_name":{"type":"str","nullable":false,"options":null}},"authentik_events.event_context":{"http_request":{"type":"relation","nullable":false,"options":null,"relation":"authentik_events.event_context_http_request"}},"authentik_events.event_context_http_request":{"args":{"type":"relation","nullable":false,"options":null,"relation":"authentik_events.event_context_http_request_args"},"path":{"type":"str","nullable":false,"options":null},"method":{"type":"str","nullable":false,"options":null},"request_id":{"type":"str","nullable":false,"options":null},"user_agent":{"type":"str","nullable":false,"options":null}}}}"#;

/// `EventSerializer`.
#[derive(Serialize)]
pub(crate) struct EventData {
    pk: String,
    user: Box<RawValue>,
    action: String,
    app: String,
    context: Box<RawValue>,
    client_ip: Option<String>,
    created: String,
    expires: String,
    brand: Box<RawValue>,
}

fn db(_: sqlx::Error) -> Decline {
    Decline("database error")
}

fn raw_json(text: &str) -> Result<Box<RawValue>, Decline> {
    RawValue::from_string(render_jsonb(text)?).map_err(|_| Decline("jsonb rendering"))
}

pub(crate) fn event(row: &sqlx::postgres::PgRow) -> Result<EventData, Decline> {
    let uuid: Uuid = row.try_get(1).map_err(db)?;
    let user: String = row.try_get(2).map_err(db)?;
    let context: String = row.try_get(5).map_err(db)?;
    let brand: String = row.try_get(8).map_err(db)?;
    let created: chrono::DateTime<chrono::Utc> = row.try_get(7).map_err(db)?;
    let expires: chrono::DateTime<chrono::Utc> = row.try_get(9).map_err(db)?;
    Ok(EventData {
        pk: uuid.to_string(),
        user: raw_json(&user)?,
        action: row.try_get(3).map_err(db)?,
        app: row.try_get(4).map_err(db)?,
        context: raw_json(&context)?,
        client_ip: row.try_get(6).map_err(db)?,
        created: drf::datetime(created),
        expires: drf::datetime(expires),
        brand: raw_json(&brand)?,
    })
}

/// A `CharFilter` value: stripped, `Err` for NUL, `None` when blank.
fn char_value<'a>(
    query: &'a QueryDict,
    name: &'static str,
) -> Result<Option<&'a str>, (&'static str, String)> {
    let value = strip(query.get(name).unwrap_or_default());
    if value.contains('\0') {
        return Err((name, "Null characters are not allowed.".to_owned()));
    }
    Ok(Some(value).filter(|v| !v.is_empty()))
}

/// `<column> <path> = json.dumps(value)::jsonb`.
fn json_equals(qs: &mut DjangoQuery, path: &str, value: &serde_json::Value) -> String {
    let p = qs.bind(Bind::Text(value.to_string()));
    format!("({path}) = {p}::jsonb")
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
    for term in &terms {
        let mut ors: Vec<String> = SEARCH.iter().map(|c| qs.icontains(c, term)).collect();
        // `GenericIPAddressField` lookups use `HOST(…)` rather than `::text`.
        let p = qs.bind(Bind::Text(format!("%{}%", crate::sql::prep_for_like(term))));
        ors.push(format!(
            "UPPER(HOST({})) LIKE UPPER({p})",
            col!("client_ip")
        ));
        qs.filter(format!("({})", ors.join(" OR ")));
    }
    if let Err(answer) = django_object_filter(ctx, user, &MODEL, &mut qs, allow).await? {
        return Ok(Err(answer));
    }
    // `EventsFilter`, field by field (errors in declaration order).
    let mut errors = Vec::new();
    let mut values = Vec::new();
    for name in [
        "action",
        "client_ip",
        "username",
        "context_model_pk",
        "context_model_name",
        "context_model_app",
        "context_authorized_app",
    ] {
        match char_value(query, name) {
            Ok(v) => values.push(v),
            Err(e) => {
                errors.push(e);
                values.push(None);
            }
        }
    }
    let actions = filters::clean(ctx.pool, query, ACTIONS_FILTER).await?;
    let brand_name = char_value(query, "brand_name");
    let actions = match actions {
        Ok(form) => Some(form),
        Err(e) => {
            errors.extend(e);
            None
        }
    };
    let brand_name = match brand_name {
        Ok(v) => v,
        Err(e) => {
            errors.push(e);
            None
        }
    };
    if !errors.is_empty() {
        return Ok(Err(drf::field_errors(&errors, allow)));
    }
    let [
        action,
        client_ip,
        username,
        model_pk,
        model_name,
        model_app,
        authorized_app,
    ] = values.as_slice()
    else {
        return Err(Decline("filters"));
    };
    if let Some(action) = action {
        let cond = qs.icontains(col!("action"), action);
        qs.filter(cond);
    }
    if let Some(ip) = client_ip {
        // An invalid address is a database error in Django (500).
        let addr: std::net::IpAddr = ip.parse().map_err(|_| Decline("client_ip value"))?;
        if ip.contains(':') {
            return Err(Decline("ipv6 normalization"));
        }
        let p = qs.bind(Bind::Text(addr.to_string()));
        qs.filter(format!("{} = {p}::inet", col!("client_ip")));
    }
    if let Some(name) = username {
        let v = serde_json::Value::from(*name);
        let a = json_equals(
            &mut qs,
            concat!("\"authentik_events_event\".\"user\"", " -> 'username'"),
            &v,
        );
        let b = json_equals(
            &mut qs,
            concat!("\"authentik_events_event\".\"context\"", " -> 'username'"),
            &v,
        );
        qs.filter(format!("({a} OR {b})"));
    }
    if let Some(pk) = model_pk {
        let value = pk.replace('-', "");
        let path = concat!("\"authentik_events_event\".\"context\"", " #> '{model,pk}'");
        let text = json_equals(&mut qs, path, &serde_json::Value::from(value.as_str()));
        match py_int(&value).map_err(|_| Decline("int syntax"))? {
            None => qs.filter(text),
            Some(crate::py::PyInt::Small(n)) => {
                let number = json_equals(&mut qs, path, &serde_json::Value::from(n));
                qs.filter(format!("({text} OR {number})"));
            }
            Some(crate::py::PyInt::Big { .. }) => return Err(Decline("big int")),
        }
    }
    for (value, path) in [
        (
            model_name,
            concat!(
                "\"authentik_events_event\".\"context\"",
                " #> '{model,model_name}'"
            ),
        ),
        (
            model_app,
            concat!(
                "\"authentik_events_event\".\"context\"",
                " #> '{model,app}'"
            ),
        ),
        (
            authorized_app,
            concat!(
                "\"authentik_events_event\".\"context\"",
                " #> '{authorized_application,pk}'"
            ),
        ),
    ] {
        if let Some(v) = value {
            let cond = json_equals(&mut qs, path, &serde_json::Value::from(*v));
            qs.filter(cond);
        }
    }
    if let Some(form) = actions {
        form.apply(&mut qs);
    }
    if let Some(name) = brand_name {
        let cond = json_equals(
            &mut qs,
            concat!("\"authentik_events_event\".\"brand\"", " -> 'name'"),
            &serde_json::Value::from(name),
        );
        qs.filter(cond);
    }
    Ok(Ok(qs))
}

/// `GET /api/v3/events/events/`.
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
        &[concat!("\"authentik_events_event\".\"created\"", " DESC")],
    )?;
    let size = page_size(query, &tenant)?;
    let count = qs.count(ctx.pool).await?;
    let Some(page) = Page::choose(query, size, count)? else {
        return Ok(drf::detail(404, "Invalid page.", ALLOW_LIST));
    };
    let rows = qs.fetch(ctx.pool, &order, Some(page.slice())).await?;
    let results = rows.iter().map(event).collect::<Result<Vec<_>, _>>()?;
    // `StrField(Event, "app", suggest_options=True).get_options("")`.
    let apps: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT \"authentik_events_event\".\"app\" AS \"app\" FROM \"authentik_events_event\" ORDER BY 1 ASC",
    )
    .fetch_all(ctx.pool)
    .await
    .map_err(db)?;
    let options = serde_json::to_string(&apps).map_err(|_| Decline("autocomplete"))?;
    let autocomplete =
        RawValue::from_string(format!("{AUTOCOMPLETE_HEAD}{options}{AUTOCOMPLETE_TAIL}"))
            .map_err(|_| Decline("autocomplete"))?;
    Ok(drf::json(
        200,
        &page.response_with(results, autocomplete),
        ALLOW_LIST,
    ))
}

/// `GET /api/v3/events/events/{pk}/`.
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
    qs.filter(format!("{} = {p}", col!("event_uuid")));
    let rows = qs.fetch(ctx.pool, &[], None).await?;
    let row = match rows.as_slice() {
        [] => {
            return Ok(drf::detail(
                404,
                "No Event matches the given query.",
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
        Access::Allow => Ok(drf::json(200, &event(row)?, ALLOW_DETAIL)),
        Access::NotFound => Ok(drf::detail(404, "Not found.", ALLOW_DETAIL)),
        Access::Deny => Ok(drf::permission_denied(&user, ALLOW_DETAIL)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autocomplete_assembles_to_json() {
        let text = format!("{AUTOCOMPLETE_HEAD}[\"a\"]{AUTOCOMPLETE_TAIL}");
        serde_json::from_str::<serde_json::Value>(&text).expect("json");
    }
}
