//! `Event.new(action, app, **kwargs).from_http(request, user)`: an audit
//! event row as authentik writes it, and the `event_trigger_dispatch` task
//! its `post_save` receiver enqueues.
//!
//! `new` runs `cleanse_dict(sanitize_dict(kwargs))`. `from_http` adds the
//! `http_request` context (path, method, cleansed query arguments, user
//! agent, request id; a flow's wrapped `query`), the brand
//! (`model_to_dict`), the user (`get_user`, then an override, then
//! impersonation and a flow's pending user from the session), the client
//! IP, and the ASN and `GeoIP` context processors. `expires` is the
//! tenant's `event_retention` from now.

use std::sync::LazyLock;

use ak_auth::{
    binding::{GeoIp, asn_to_dict, city_to_dict},
    python::timedelta_seconds,
};
use ak_pickle::Value as Pickled;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use sqlx::PgConnection;
use uuid::Uuid;

use crate::{Error, task};

/// `guardian`'s `ANONYMOUS_USER_NAME`.
const ANONYMOUS_USER_NAME: &str = "AnonymousUser";
/// `SafeExceptionReporterFilter.cleansed_substitute`.
const CLEANSED: &str = "********************";
/// `SESSION_KEY_IMPERSONATE_USER` / `…_ORIGINAL_USER`.
const SESSION_KEY_IMPERSONATE_USER: &str = "authentik/impersonate/user";
const SESSION_KEY_IMPERSONATE_ORIGINAL_USER: &str = "authentik/impersonate/original_user";
/// `SESSION_KEY_PLAN`, `PLAN_CONTEXT_PENDING_USER`, `QS_QUERY`.
const SESSION_KEY_PLAN: &str = "authentik/flows/plan";
const PLAN_CONTEXT_PENDING_USER: &str = "pending_user";
const QS_QUERY: &str = "query";
/// Django's `DATA_UPLOAD_MAX_NUMBER_FIELDS`.
const MAX_NUM_FIELDS: usize = 1000;

/// `DEFAULT_BRAND = Brand(domain="fallback")`: never saved, so its primary
/// key is drawn once per process.
static DEFAULT_BRAND_PK: LazyLock<Uuid> = LazyLock::new(Uuid::new_v4);

/// `SafeExceptionReporterFilter.hidden_settings` (`re.I`, `search`).
fn is_hidden_key(key: &str) -> bool {
    let upper = key.to_uppercase();
    [
        "API",
        "AUTH",
        "TOKEN",
        "KEY",
        "SECRET",
        "PASS",
        "SIGNATURE",
        "HTTP_COOKIE",
    ]
    .iter()
    .any(|word| upper.contains(word))
}

/// `ALLOWED_SPECIAL_KEYS`: `passing|password_change_date|^auth_method(_args)?$`.
fn is_allowed_special_key(key: &str) -> bool {
    let lower = key.to_lowercase();
    lower.contains("passing")
        || lower.contains("password_change_date")
        || lower
            .strip_prefix("auth_method")
            .is_some_and(|rest| rest.is_empty() || rest == "_args")
}

/// `cleanse_item(key, value)`.
fn cleanse_item(key: &str, value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(cleanse_dict(map)),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(|item| cleanse_item(key, item))
                .collect(),
        ),
        _ if is_hidden_key(key) && !is_allowed_special_key(key) => json!(CLEANSED),
        value => value,
    }
}

/// `cleanse_dict(source)`.
#[must_use]
pub fn cleanse_dict(source: Map<String, Value>) -> Map<String, Value> {
    source
        .into_iter()
        .map(|(k, v)| {
            let v = cleanse_item(&k, v);
            (k, v)
        })
        .collect()
}

/// Python truthiness of a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0_f64),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `sanitize_item(value)` for JSON values: strings lose NUL characters
/// (`cleanse_str`), lists drop falsy items.
fn sanitize_item(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(sanitize_dict(map)),
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(sanitize_item)
                .filter(truthy)
                .collect(),
        ),
        Value::String(s) => Value::String(s.replace('\0', "")),
        value => value,
    }
}

/// `sanitize_dict(source)`.
#[must_use]
pub fn sanitize_dict(source: Map<String, Value>) -> Map<String, Value> {
    source
        .into_iter()
        .map(|(k, v)| (k, sanitize_item(v)))
        .collect()
}

/// `urllib.parse.unquote(s, errors="replace")` after `+` → space.
fn unquote_plus(s: &str) -> String {
    let s = s.replace('+', " ");
    let mut out = String::new();
    let mut bytes: Vec<u8> = Vec::new();
    let flush = |bytes: &mut Vec<u8>, out: &mut String| {
        if !bytes.is_empty() {
            out.push_str(&String::from_utf8_lossy(bytes));
            bytes.clear();
        }
    };
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%'
            && let (Some(h), Some(l)) = (
                chars.get(i + 1).and_then(|c| c.to_digit(16)),
                chars.get(i + 2).and_then(|c| c.to_digit(16)),
            )
        {
            bytes.push(u8::try_from(h * 16 + l).unwrap_or_default());
            i += 3;
            continue;
        }
        flush(&mut bytes, &mut out);
        out.push(chars[i]);
        i += 1;
    }
    flush(&mut bytes, &mut out);
    out
}

/// `cleanse_dict(QueryDict(query_string))`: `parse_qsl(keep_blank_values=True)`
/// on `&`, the last value of each key.
///
/// # Errors
///
/// [`Error::Unsupported`] past `DATA_UPLOAD_MAX_NUMBER_FIELDS`
/// (`TooManyFieldsSent`).
fn query_args(query_string: &str) -> Result<Map<String, Value>, Error> {
    if !query_string.is_empty() && 1 + query_string.matches('&').count() > MAX_NUM_FIELDS {
        return Err(Error::Unsupported("too many query fields"));
    }
    let mut args = Map::new();
    for field in query_string.split('&').filter(|f| !f.is_empty()) {
        let (name, value) = field.split_once('=').unwrap_or((field, ""));
        args.insert(unquote_plus(name), Value::String(unquote_plus(value)));
    }
    Ok(cleanse_dict(args))
}

/// Who `get_user` describes.
#[derive(Debug, Clone)]
pub enum UserRef {
    /// Django's `AnonymousUser`: the `AnonymousUser` row stands in.
    Anonymous,
    /// A user row.
    Id(i32),
}

/// `get_user(user)` for a row.
async fn user_dict(conn: &mut PgConnection, user: &UserRef) -> Result<Map<String, Value>, Error> {
    let row: Option<(i32, String, String)> = match user {
        UserRef::Anonymous => {
            sqlx::query_as(
                "SELECT id, username, email FROM authentik_core_user WHERE username = $1",
            )
            .bind(ANONYMOUS_USER_NAME)
            .fetch_optional(&mut *conn)
            .await?
        }
        UserRef::Id(id) => {
            sqlx::query_as("SELECT id, username, email FROM authentik_core_user WHERE id = $1")
                .bind(id)
                .fetch_optional(&mut *conn)
                .await?
        }
    };
    let Some((pk, username, email)) = row else {
        // `get_anonymous_user()` raising `DoesNotExist` gives `{}`; a missing
        // row for an id cannot be a live user object.
        return match user {
            UserRef::Anonymous => Ok(Map::new()),
            UserRef::Id(_) => Err(Error::Unsupported("user row missing")),
        };
    };
    Ok(describe_user(&username, i64::from(pk), &email))
}

fn describe_user(username: &str, pk: i64, email: &str) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert("username".to_owned(), json!(username));
    out.insert("pk".to_owned(), json!(pk));
    out.insert("email".to_owned(), json!(email));
    if username == ANONYMOUS_USER_NAME {
        out.insert("is_anonymous".to_owned(), json!(true));
    }
    out
}

/// `get_user(obj)` for a user pickled in the session (`model_unpickle`
/// state: `id`, `username`, `email`).
fn pickled_user_dict(obj: &Pickled) -> Result<Map<String, Value>, Error> {
    let Pickled::Object(object) = obj else {
        return Err(Error::Unsupported("pickled user is not an object"));
    };
    let object = object.borrow();
    let state = object
        .state
        .as_ref()
        .ok_or(Error::Unsupported("pickled user without state"))?;
    let username = state
        .get("username")
        .and_then(|v| v.as_str().map(str::to_owned));
    let email = state
        .get("email")
        .and_then(|v| v.as_str().map(str::to_owned));
    let pk = match state.get("id") {
        Some(Pickled::Int(id)) => i64::try_from(id).ok(),
        _ => None,
    };
    match (username, pk, email) {
        (Some(username), Some(pk), Some(email)) => Ok(describe_user(&username, pk, &email)),
        _ => Err(Error::Unsupported("pickled user fields")),
    }
}

/// An attribute from a `BUILD` state: a `__dict__`, or the
/// `(dict_state, slots_state)` pair a `__slots__` class (`FlowPlan`) pickles.
fn state_get(state: &Pickled, key: &str) -> Option<Pickled> {
    if let Pickled::Tuple(parts) = state
        && let [dict_state, slots_state] = parts.as_slice()
    {
        return slots_state.get(key).or_else(|| dict_state.get(key));
    }
    state.get(key)
}

/// A pending user: its `pk` (`None` when unsaved) and `get_user` of it.
type Pending = (Option<i64>, Map<String, Value>);

/// The pending user of a pickled `FlowPlan`.
fn pending_user(plan: &Pickled) -> Result<Option<Pending>, Error> {
    let Pickled::Object(object) = plan else {
        return Err(Error::Unsupported("flow plan is not an object"));
    };
    let object = object.borrow();
    let state = object
        .state
        .as_ref()
        .ok_or(Error::Unsupported("flow plan without state"))?;
    let Some(context) = state_get(state, "context") else {
        return Err(Error::Unsupported("flow plan without context"));
    };
    let Some(user) = context.get(PLAN_CONTEXT_PENDING_USER) else {
        return Ok(None);
    };
    if matches!(user, Pickled::None) {
        return Ok(None);
    }
    let pk = match &user {
        Pickled::Object(o) => match o.borrow().state.as_ref().and_then(|s| s.get("id")) {
            Some(Pickled::Int(id)) => i64::try_from(id).ok(),
            Some(Pickled::None) | None => None,
            _ => return Err(Error::Unsupported("pending user id")),
        },
        _ => return Err(Error::Unsupported("pending user is not an object")),
    };
    // An unsaved pending user has no `id` to describe; not reproduced.
    let described = pickled_user_dict(&user)?;
    Ok(Some((pk, described)))
}

/// The brand on the request: `model_to_dict(brand)` with the pk as hex.
#[derive(Debug, Clone)]
pub struct BrandRef {
    pub uuid: Uuid,
    pub domain: String,
    pub default: bool,
}

fn brand_dict(brand: &BrandRef) -> Value {
    // `Brand.__str__`; brands have no `name`.
    let name = if brand.default {
        "Default brand".to_owned()
    } else {
        format!("Brand {}", brand.domain)
    };
    json!({
        "app": "authentik_brands",
        "model_name": "brand",
        "pk": brand.uuid.simple().to_string(),
        "name": name,
    })
}

/// `default_brand()`: `DEFAULT_BRAND`, with this process's random pk.
#[must_use]
pub fn default_brand() -> Value {
    brand_dict(&BrandRef {
        uuid: *DEFAULT_BRAND_PK,
        domain: "fallback".to_owned(),
        default: false,
    })
}

/// What `from_http` reads from the session: the impersonation pair
/// (`original_user`, `user`) and a flow plan's pending user, taken out of
/// the pickled data before any database work.
#[derive(Debug, Clone, Default)]
pub struct SessionUsers {
    impersonation: Option<(Map<String, Value>, Map<String, Value>)>,
    pending: Option<Pending>,
}

impl SessionUsers {
    /// From the session's unpickled data.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] where Django would raise (an impersonation
    /// without its user) or the pickled objects are not reproduced.
    pub fn from_session(session: &Pickled) -> Result<Self, Error> {
        let impersonation = match (
            session.get(SESSION_KEY_IMPERSONATE_ORIGINAL_USER),
            session.get(SESSION_KEY_IMPERSONATE_USER),
        ) {
            (Some(original), Some(user)) => {
                Some((pickled_user_dict(&original)?, pickled_user_dict(&user)?))
            }
            (Some(_), None) => {
                return Err(Error::Unsupported(
                    "impersonation without the impersonated user",
                ));
            }
            (None, _) => None,
        };
        let pending = match session.get(SESSION_KEY_PLAN) {
            Some(plan) => pending_user(&plan)?,
            None => None,
        };
        Ok(Self {
            impersonation,
            pending,
        })
    }
}

/// The request `from_http` reads; `None` fields are attributes the request
/// does not have.
#[derive(Debug, Clone)]
pub struct HttpRequest<'a> {
    /// `request.path`, decoded.
    pub path: &'a str,
    pub method: &'a str,
    /// The WSGI `QUERY_STRING` (raw bytes as Latin-1).
    pub query_string: &'a str,
    pub user_agent: &'a str,
    /// `request.request_id`, set by `RequestIDMiddleware`.
    pub request_id: Option<&'a str>,
    /// `request.brand`, set by `BrandMiddleware`.
    pub brand: Option<BrandRef>,
    /// `request.user`.
    pub user: Option<UserRef>,
    /// From `request.session`, when the request has a session.
    pub session: Option<SessionUsers>,
    /// `ClientIPMiddleware.get_client_ip(request)`.
    pub client_ip: &'a str,
}

/// `EventAction` members, or anything else (`custom_`-prefixed).
#[derive(Debug, Clone, Copy)]
pub enum Action<'a> {
    Known(&'a str),
    Custom(&'a str),
}

/// What [`new_from_http`] wrote.
#[derive(Debug, Clone)]
pub struct Written {
    pub event_uuid: Uuid,
    /// The `event_trigger_dispatch` message.
    pub task: Uuid,
}

/// `enrich_event` of the ASN and `GeoIP` context processors:
/// `asn_dict(client_ip)` / `city_dict(client_ip)` when found.
fn enrich(context: &mut Map<String, Value>, geoip: &GeoIp, client_ip: &str) -> Result<(), Error> {
    if let Some(asn) = geoip
        .asn(client_ip)
        .map_err(|_| Error::Unsupported("ASN lookup raised"))?
    {
        context.insert("asn".to_owned(), asn_to_dict(Some(&asn)));
    }
    if let Some(city) = geoip
        .city(client_ip)
        .map_err(|_| Error::Unsupported("GeoIP lookup raised"))?
    {
        context.insert("geo".to_owned(), city_to_dict(Some(&city)));
    }
    Ok(())
}

/// `GenericIPAddressField.get_prep_value`: IPv6 is stored compressed; a
/// scope does not fit `inet`.
fn prep_ip(ip: &str) -> Result<String, Error> {
    if ip.contains(':') {
        let v6: std::net::Ipv6Addr = ip.parse().map_err(|_| Error::Unsupported("client IP"))?;
        return Ok(v6.to_string());
    }
    Ok(ip.to_owned())
}

/// No `\u0000` may reach `jsonb`, and NaN/Infinity are not JSON.
fn storable(value: &Value) -> bool {
    match value {
        Value::String(s) => !s.contains('\0'),
        Value::Array(items) => items.iter().all(storable),
        Value::Object(map) => map.iter().all(|(k, v)| !k.contains('\0') && storable(v)),
        _ => true,
    }
}

/// `Event.new(action, app, **kwargs).from_http(request, user=user)` and the
/// `post_save` task, inside the caller's transaction.
///
/// `kwargs` are the keyword arguments as JSON; `extra` is merged into the
/// context after cleansing, as `event.context.update(...)` does.
///
/// # Errors
///
/// A database error, or [`Error::Unsupported`] for inputs Django would
/// fail on or this port does not reproduce (the caller declines).
#[expect(
    clippy::too_many_arguments,
    reason = "Event.new and from_http's inputs"
)]
pub async fn new_from_http(
    conn: &mut PgConnection,
    tenant: Uuid,
    action: Action<'_>,
    app: &str,
    kwargs: Map<String, Value>,
    extra: Option<Map<String, Value>>,
    request: Option<&HttpRequest<'_>>,
    user: Option<&UserRef>,
    geoip: &GeoIp,
    now: DateTime<Utc>,
) -> Result<Written, Error> {
    let action = match action {
        Action::Known(a) => a.to_owned(),
        Action::Custom(a) => format!("custom_{a}"),
    };
    let mut context = cleanse_dict(sanitize_dict(kwargs));
    if let Some(extra) = extra {
        context.extend(extra);
    }
    let mut brand = default_brand();
    let mut event_user = Map::new();
    let client_ip = request.map_or("255.255.255.255", |r| r.client_ip);
    if let Some(req) = request {
        let mut http = Map::new();
        http.insert("path".to_owned(), json!(req.path));
        http.insert("method".to_owned(), json!(req.method));
        let mut args = query_args(req.query_string)?;
        http.insert("user_agent".to_owned(), json!(req.user_agent));
        if let Some(id) = req.request_id {
            http.insert("request_id".to_owned(), json!(id));
        }
        if let Some(Value::String(wrapped)) = args.get(QS_QUERY).cloned() {
            args = query_args(&wrapped)?;
        }
        http.insert("args".to_owned(), Value::Object(args));
        context.insert("http_request".to_owned(), Value::Object(http));
        if let Some(b) = &req.brand {
            brand = brand_dict(b);
        }
        if let Some(u) = &req.user {
            event_user = user_dict(conn, u).await?;
        }
    }
    if let Some(u) = user {
        event_user = user_dict(conn, u).await?;
    }
    if let Some(session) = request.and_then(|r| r.session.as_ref()) {
        if let Some((original, on_behalf_of)) = &session.impersonation {
            event_user = original.clone();
            event_user.insert(
                "on_behalf_of".to_owned(),
                Value::Object(on_behalf_of.clone()),
            );
        }
        if let Some((pk, pending)) = &session.pending {
            let current = event_user.get("pk").and_then(Value::as_i64);
            if pk.is_none_or(|pk| Some(pk) != current) {
                let mut user = Map::new();
                user.insert("authenticated_as".to_owned(), Value::Object(event_user));
                user.extend(pending.clone());
                event_user = user;
            }
        }
    }
    let client_ip = prep_ip(client_ip)?;
    enrich(&mut context, geoip, &client_ip)?;
    let context = Value::Object(context);
    let event_user = Value::Object(event_user);
    if !storable(&context) || !storable(&event_user) {
        return Err(Error::Unsupported("NUL in event JSON"));
    }

    // `default_event_duration()`: the tenant's `event_retention`.
    let retention: Option<String> = sqlx::query_scalar(
        "SELECT event_retention FROM authentik_tenants_tenant WHERE tenant_uuid = $1",
    )
    .bind(tenant)
    .fetch_optional(&mut *conn)
    .await?;
    let seconds = match retention {
        Some(r) => timedelta_seconds(&r).ok_or(Error::Unsupported("event_retention"))?,
        None => 365.0_f64 * 86400.0_f64,
    };
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "microseconds"
    )]
    let expires = now + chrono::Duration::microseconds((seconds * 1e6).round() as i64);

    let event_uuid = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO authentik_events_event (event_uuid, action, app, context, client_ip, \
         created, \"user\", expires, expiring, brand) VALUES ($1, $2, $3, $4::jsonb, $5::inet, \
         $6, $7::jsonb, $8, true, $9::jsonb)",
    )
    .bind(event_uuid)
    .bind(&action)
    .bind(app)
    .bind(context.to_string())
    .bind(&client_ip)
    .bind(now)
    .bind(event_user.to_string())
    .bind(expires)
    .bind(brand.to_string())
    .execute(&mut *conn)
    .await?;
    // `event_post_save_notification`.
    let task = task::enqueue(
        conn,
        tenant,
        "authentik.events.tasks.event_trigger_dispatch",
        vec![ak_pickle::write::Obj::uuid(event_uuid.as_u128())],
        now,
    )
    .await?;
    Ok(Written { event_uuid, task })
}
