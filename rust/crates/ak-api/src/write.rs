//! What every ported write shares (M8).
//!
//! DRF's request parsing for `ORJSONParser`, serializer field validation,
//! and the side effects of authentik's request middlewares:
//! `AuditMiddleware`'s `model_created`/`model_updated`/`model_deleted`
//! events (with their dispatch tasks) and `InitialPermissionsMiddleware`.
//!
//! A write runs in one transaction. Anything this port does not reproduce
//! rolls it back and declines, so Django then answers from the same state.

use ak_auth::python::{PyStr, PyValue, isspace, json_loads};
use http::header;
use serde_json::{Map, Value, json};
use sqlx::PgConnection;

use crate::{
    Answer, Decline,
    drf::{ApiRequest, Context, Tenant, User},
};

/// `DATA_UPLOAD_MAX_MEMORY_SIZE`: bodies above it stay with Django.
pub const MAX_BODY: usize = 2_621_440;

fn db(_: sqlx::Error) -> Decline {
    Decline("database error")
}

/// The JSON object a write sent, as `request.data`.
pub(crate) struct Data(Vec<(PyStr, PyValue)>);

impl Data {
    /// `data.get(name)`: the last occurrence (`orjson` keeps the last).
    pub(crate) fn get(&self, name: &str) -> Option<&PyValue> {
        let key = PyStr::from_text(name);
        self.0.iter().rev().find(|(k, _)| *k == key).map(|(_, v)| v)
    }
}

/// `orjson.loads` refuses integers outside 64 bits and strings with lone
/// surrogates, with messages this port does not reproduce, and nests at
/// most 1024 deep.
fn orjson_accepts(value: &PyValue, depth: usize) -> bool {
    if depth > 512 {
        return false;
    }
    match value {
        PyValue::Int(digits) => digits.parse::<i64>().is_ok() || digits.parse::<u64>().is_ok(),
        PyValue::Str(s) => s.to_string_lossless().is_some(),
        PyValue::List(items) => items.iter().all(|v| orjson_accepts(v, depth + 1)),
        PyValue::Dict(items) => items
            .iter()
            .all(|(k, v)| k.to_string_lossless().is_some() && orjson_accepts(v, depth + 1)),
        // `json.loads` reads `NaN`/`Infinity` (and overflows to them); orjson refuses.
        PyValue::Float(f) => f.is_finite(),
        PyValue::None | PyValue::Bool(_) => true,
    }
}

/// `request.data` through `ORJSONParser`, for a body that is a JSON object.
/// Other media types (Django's 415), parse errors (orjson's messages), an
/// empty body and non-object data are declined.
pub(crate) fn json_body(req: &ApiRequest<'_>) -> Result<Data, Decline> {
    let content_type = req
        .headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .ok_or(Decline("no content type"))?;
    let mut parts = content_type.split(';').map(str::trim);
    if !parts
        .next()
        .is_some_and(|t| t.eq_ignore_ascii_case("application/json"))
    {
        return Err(Decline("content type"));
    }
    for param in parts {
        if !param.eq_ignore_ascii_case("charset=utf-8") {
            return Err(Decline("content type parameter"));
        }
    }
    if req.body.is_empty() {
        return Err(Decline("empty body"));
    }
    // orjson reads UTF-8 only; `json.loads` also detects UTF-16/32 and a BOM.
    if std::str::from_utf8(req.body).is_err() || req.body.starts_with(b"\xef\xbb\xbf") {
        return Err(Decline("body encoding"));
    }
    let value = json_loads(req.body).map_err(|_| Decline("json parse error"))?;
    if !orjson_accepts(&value, 0) {
        return Err(Decline("json orjson refuses"));
    }
    let mut value = value;
    match &mut value {
        PyValue::Dict(items) => Ok(Data(std::mem::take(items))),
        _ => Err(Decline("json not an object")),
    }
}

/// A serializer field's input: absent from the data, `null`, or a value.
pub(crate) enum Input<T> {
    Absent,
    Null,
    Value(T),
}

impl<T> Input<T> {
    /// The value, for a field that cannot be null.
    pub(crate) fn value(self) -> Option<T> {
        match self {
            Self::Value(value) => Some(value),
            Self::Absent | Self::Null => None,
        }
    }
}

/// A field's error: `Ok(message)` for DRF's 400, `Err` when that error is
/// not reproduced.
pub(crate) type FieldError = Result<String, Decline>;

fn error<T>(message: &str) -> Result<T, FieldError> {
    Err(Ok(message.to_owned()))
}

/// `Field.validate_empty_values` for a field that is required unless the
/// update is partial.
fn present<'d>(
    data: &'d Data,
    name: &str,
    required: bool,
    allow_null: bool,
) -> Result<Option<&'d PyValue>, FieldError> {
    match data.get(name) {
        None if required => error("This field is required."),
        None => Ok(None),
        Some(PyValue::None) if allow_null => Ok(None),
        Some(PyValue::None) => error("This field may not be null."),
        Some(value) => Ok(Some(value)),
    }
}

/// A `CharField` with `trim_whitespace=True`.
pub(crate) struct CharField {
    pub required: bool,
    pub allow_blank: bool,
    pub allow_null: bool,
    pub max_length: Option<usize>,
}

impl CharField {
    /// `allow_blank=False`, `allow_null=False`, no `max_length`.
    pub(crate) const fn new(required: bool) -> Self {
        Self {
            required,
            allow_blank: false,
            allow_null: false,
            max_length: None,
        }
    }

    /// `run_validation(data[name])`.
    pub(crate) fn validate(&self, data: &Data, name: &str) -> Result<Input<String>, FieldError> {
        let value = match present(data, name, self.required, self.allow_null)? {
            Some(value) => value,
            None if data.get(name).is_some() => return Ok(Input::Null),
            None => return Ok(Input::Absent),
        };
        let text = match value {
            PyValue::Str(s) => s.to_string_lossless().ok_or(Err(Decline("surrogate")))?,
            // `str(int)`; JSON integers are canonical except `-0`.
            PyValue::Int(digits) if digits != "-0" => digits.clone(),
            // `str(float)` is not reproduced.
            PyValue::Int(_) | PyValue::Float(_) => return Err(Err(Decline("number as string"))),
            // `run_validation` checks blankness on `str(data)` first, which
            // for these is never blank; `to_internal_value` then refuses them.
            PyValue::Bool(_) | PyValue::List(_) | PyValue::Dict(_) => {
                return error("Not a valid string.");
            }
            PyValue::None => unreachable!("handled by present"),
        };
        let trimmed = text.trim_matches(isspace);
        if trimmed.is_empty() {
            return if self.allow_blank {
                Ok(Input::Value(String::new()))
            } else {
                error("This field may not be blank.")
            };
        }
        // `ProhibitNullCharactersValidator` (its message joins any other
        // validator's, and a `UniqueValidator` query with it is refused by
        // PostgreSQL: Django's 500).
        if trimmed.contains('\0') {
            return Err(Err(Decline("NUL in field")));
        }
        if let Some(max) = self.max_length
            && trimmed.chars().count() > max
        {
            return Err(Ok(format!(
                "Ensure this field has no more than {max} characters."
            )));
        }
        Ok(Input::Value(trimmed.to_owned()))
    }
}

/// A `BooleanField` (`allow_null=False`), DRF 3.16: strings compared
/// lowercased (`str.lower()` maps no non-ASCII character onto these).
pub(crate) fn boolean_field(
    data: &Data,
    name: &str,
    required: bool,
) -> Result<Input<bool>, FieldError> {
    let Some(value) = present(data, name, required, false)? else {
        return Ok(Input::Absent);
    };
    let parsed = match value {
        PyValue::Bool(b) => Some(*b),
        PyValue::Int(digits) => match digits.as_str() {
            "1" => Some(true),
            "0" | "-0" => Some(false),
            _ => None,
        },
        // `1.0 == 1` and `0.0 == -0.0 == 0` in the sets.
        #[expect(clippy::float_cmp, reason = "Python's set membership is exact equality")]
        PyValue::Float(f) if *f == 1.0_f64 => Some(true),
        PyValue::Float(f) if *f == 0.0_f64 => Some(false),
        PyValue::Str(s) => match s.to_string_lossless() {
            Some(text) => match text.to_ascii_lowercase().as_str() {
                "t" | "y" | "yes" | "true" | "on" | "1" if text.is_ascii() => Some(true),
                "f" | "n" | "no" | "false" | "off" | "0" if text.is_ascii() => Some(false),
                _ => None,
            },
            None => return Err(Err(Decline("surrogate"))),
        },
        _ => None,
    };
    match parsed {
        Some(b) => Ok(Input::Value(b)),
        None => error("Must be a valid boolean."),
    }
}

/// DRF's 400 for field errors, in field order.
pub(crate) fn field_errors(errors: &[(&str, String)], allow: &'static str) -> Answer {
    crate::drf::field_errors(errors, allow)
}

/// A 204 as DRF sends it: no body, no `Content-Type` (Django's
/// `LocaleMiddleware` still adds `Content-Language`).
pub(crate) fn no_content(allow: &'static str) -> Answer {
    let mut answer = crate::drf::json(204, &(), allow);
    answer.body.clear();
    answer.headers.retain(|(name, _)| *name != "content-type");
    answer
}

/// The pieces of `request` an audit event reads.
pub(crate) struct Audit<'a> {
    tenant: uuid::Uuid,
    http: ak_events::event::HttpRequest<'a>,
    user: ak_events::event::UserRef,
    geoip: &'a ak_auth::binding::GeoIp,
}

/// `Brand` for the request (`BrandMiddleware`), `None` for the fallback.
async fn brand(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
) -> Result<Option<ak_events::event::BrandRef>, Decline> {
    let host = req
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .ok_or(Decline("no host"))?;
    let Some(uuid) = ak_auth::brand::resolve(ctx.pool, host).await.map_err(db)? else {
        return Ok(None);
    };
    let (domain, default): (String, bool) = sqlx::query_as(
        "SELECT domain, \"default\" FROM authentik_brands_brand WHERE brand_uuid = $1",
    )
    .bind(uuid)
    .fetch_one(ctx.pool)
    .await
    .map_err(db)?;
    Ok(Some(ak_events::event::BrandRef {
        uuid,
        domain,
        default,
    }))
}

impl<'a> Audit<'a> {
    /// What `AuditMiddleware` reads off a request that DRF authenticated as
    /// `user` (it writes `request.user` back).
    pub(crate) async fn new(
        ctx: &'a Context<'_>,
        req: &'a ApiRequest<'_>,
        tenant: &Tenant,
        user: &User,
        user_agent: &'a str,
        client_ip: &'a str,
    ) -> Result<Self, Decline> {
        let geoip = &ctx.sessions.ok_or(Decline("no GeoIP settings"))?.geoip;
        let user = if user.is_authenticated() {
            ak_events::event::UserRef::Id(user.subject().user_id)
        } else {
            ak_events::event::UserRef::Anonymous
        };
        Ok(Self {
            tenant: tenant.uuid,
            http: ak_events::event::HttpRequest {
                path: req.path,
                method: req.method,
                query_string: req.query,
                user_agent,
                request_id: Some(&req.request_id),
                brand: brand(ctx, req).await?,
                user: Some(user.clone()),
                session: None,
                client_ip,
            },
            user,
            geoip,
        })
    }

    /// `EventNewThread(action, request, user=user, model=model_to_dict(o))`.
    pub(crate) async fn event(
        &self,
        conn: &mut PgConnection,
        action: &str,
        model: Value,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Decline> {
        let mut kwargs = Map::new();
        kwargs.insert("model".to_owned(), model);
        ak_events::event::new_from_http(
            conn,
            self.tenant,
            ak_events::event::Action::Known(action),
            "authentik.events.middleware",
            kwargs,
            None,
            Some(&self.http),
            Some(&self.user),
            self.geoip,
            now,
        )
        .await
        .map(|_| ())
        .map_err(|_| Decline("audit event not reproduced"))
    }
}

/// `model_to_dict(instance)`: `pk` as the event stores it (a UUID as hex),
/// and the instance's `name` (or `str()`).
pub(crate) fn model_dict(app: &str, model_name: &str, pk: &Value, name: &str) -> Value {
    json!({"app": app, "model_name": model_name, "pk": pk, "name": name})
}

/// `InitialPermissionsMiddleware` assigns the user's roles' initial
/// permissions to every instance the request creates. That assignment is
/// not ported: decline whenever one of them would apply to a created
/// instance of `models` (`(app_label, model)`).
pub(crate) async fn initial_permissions_apply(
    ctx: &Context<'_>,
    user: &User,
    models: &[(&str, &str)],
) -> Result<bool, Decline> {
    if !user.is_authenticated() || user.subject().roles.is_empty() {
        return Ok(false);
    }
    let (apps, names): (Vec<&str>, Vec<&str>) = models.iter().copied().unzip();
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM authentik_rbac_initialpermissions ip JOIN \
         authentik_rbac_initialpermissions_permissions ipp ON ipp.initialpermissions_id = ip.id \
         JOIN auth_permission p ON p.id = ipp.permission_id JOIN django_content_type c ON c.id = \
         p.content_type_id JOIN unnest($2::text[], $3::text[]) AS m(app, model) ON m.app = \
         c.app_label AND m.model = c.model WHERE ip.role_id = ANY($1))",
    )
    .bind(&user.subject().roles)
    .bind(&apps)
    .bind(&names)
    .fetch_one(ctx.pool)
    .await
    .map_err(db)
}

/// The models every audited write creates rows of besides its own: the
/// event, its dispatch task and that task's log.
pub(crate) const SIDE_EFFECT_MODELS: &[(&str, &str)] = &[
    ("authentik_events", "event"),
    ("authentik_tasks", "task"),
    ("authentik_tasks", "tasklog"),
];

/// `ClientIPMiddleware`'s IP and `META["HTTP_USER_AGENT"]` (Latin-1).
pub(crate) fn client(req: &ApiRequest<'_>) -> Result<(String, String), Decline> {
    if req.headers.contains_key("x-authentik-outpost-token") {
        return Err(Decline("outpost client ip"));
    }
    let forwarded_for = req
        .headers
        .get("x-forwarded-for")
        .map(|v| v.to_str().map_err(|_| Decline("x-forwarded-for bytes")))
        .transpose()?
        .ok_or(Decline("no x-forwarded-for"))?;
    let ip = ak_auth::client_ip::from_meta(Some(forwarded_for), None);
    let user_agent = req
        .headers
        .get(header::USER_AGENT)
        .map(|v| v.as_bytes().iter().copied().map(char::from).collect())
        .unwrap_or_default();
    Ok((ip, user_agent))
}
