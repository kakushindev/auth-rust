//! Generic `ModelViewSet` writes (M8).
//!
//! A viewset describes its model and its serializer's writable fields
//! ([`Spec`]), and how `get_object()` finds a row and what the response
//! holds ([`Resource`]). [`create`], [`update`] and [`destroy`] then run
//! DRF's and Django's steps in their order:
//!
//! 1. the tenant, authentication, and `has_permission`, or `get_object()`
//!    with the object permission;
//! 2. `ORJSONParser` and the fields' validation, every error reported in
//!    field order;
//! 3. `InitialPermissionsMiddleware`'s check, declined when it would
//!    assign anything;
//! 4. one transaction: `save()` (an INSERT, or an UPDATE of every column
//!    with the values `get_object()` read), `AuditMiddleware`'s event,
//!    then each many-to-many `set()`;
//! 5. for a delete, the collector's related rows ([`Resource::collect`]):
//!    their events, then the instance's, then the deletes.
//!
//! Porting a viewset's writes:
//! 1. Write its [`Spec`]: the writable fields in the serializer's order,
//!    each field's DRF kwargs (from `ModelSerializer`'s field mapping),
//!    unique validators and messages, and whether the model is audited.
//! 2. Implement [`Resource`]: `find` reuses the read view's
//!    `filter_queryset` and lookup; `render` reuses its serializer.
//!    `collect` lists what Django's collector deletes with a row.
//! 3. Route its methods in `lib.rs`, add a case group to
//!    `tests/writes/write_diff.py`, and iterate with
//!    `tests/writes/quick.sh <group>`.
//!
//! A serializer with a `validate()`, a custom `create`/`update`, nested
//! writes or field kinds missing here needs those added first, or stays
//! with Django.
//!
//! Rows travel as `to_jsonb(row)`: a save writes every column through
//! `jsonb_populate_record`, so the values Django would write back are the
//! ones it read, of any column type, without per-table code. A create sets
//! the key and the validated fields; every other column is NULL, which is
//! only right for a model whose other fields default to `None`.

use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
};

use ak_auth::python::PyValue;
use ak_rbac::{Access, Model, Object, PkCast};
use serde_json::{Map, Value, json};
use sqlx::{PgConnection, Postgres, Transaction};

use crate::{
    Answer, Decline,
    drf::{self, ApiRequest, Context, Tenant, User},
    py::{PyInt, QueryDict, UuidLookup, int4, py_int, uuid_lookup},
    pyset::IntSet,
    write::{
        Audit, CharField, Data, FieldError, Input, SIDE_EFFECT_MODELS, boolean_field, client,
        field_errors, initial_permissions_apply, json_body, model_dict, no_content,
    },
};

/// A row as `to_jsonb(row)` renders it: column name → value.
pub(crate) type Row = Map<String, Value>;

fn db(_: sqlx::Error) -> Decline {
    Decline("database error")
}

/// How a created row gets its primary key.
#[derive(Clone, Copy)]
pub(crate) enum Pk {
    /// `UUIDField(default=uuid4)`.
    Uuid4,
    /// An `AutoField`: the column's sequence.
    Serial,
}

/// A many-to-many field's auto-created through table.
pub(crate) struct Through {
    pub table: &'static str,
    /// The column pointing at the instance.
    pub source: &'static str,
    /// The column pointing at the related row.
    pub target: &'static str,
}

/// A writable serializer field.
pub(crate) enum Kind {
    Char(CharField),
    Bool,
    /// `PrimaryKeyRelatedField` to a model with a UUID primary key.
    ForeignUuid {
        table: &'static str,
        column: &'static str,
    },
    /// `ManyRelatedField` of `PrimaryKeyRelatedField`s to an integer
    /// primary key.
    ManyInt {
        table: &'static str,
        column: &'static str,
        through: Through,
    },
}

pub(crate) struct Field {
    /// The serializer field.
    pub name: &'static str,
    /// The model column (unused for a many-to-many field).
    pub column: &'static str,
    pub kind: Kind,
    /// Required on create and PUT (`required=False` fields never are).
    pub required: bool,
    /// The `UniqueValidator`'s message.
    pub unique: Option<&'static str>,
}

/// `model_to_dict(instance)["name"]`.
pub(crate) enum Name {
    /// The instance's `name` attribute.
    Column(&'static str),
}

/// A model and its serializer's writable fields, in declaration order.
pub(crate) struct Spec {
    pub model: Model<'static>,
    pub pk: Pk,
    pub fields: &'static [Field],
    /// `None` for `AuditMiddleware`'s ignored models.
    pub audit: Option<Name>,
    /// Serializer fields whose write is not reproduced: their presence
    /// declines.
    pub decline_keys: &'static [&'static str],
}

/// What `get_object()` found before the object permission.
pub(crate) struct Found {
    /// `str(obj.pk)`.
    pub pk: String,
    /// The `owner_field` holds the requesting user.
    pub owner: bool,
}

/// Rows the collector deletes with the instance, in its order.
#[derive(Default)]
pub(crate) struct Collected {
    /// `model_to_dict` of every instance that gets a `pre_delete` event,
    /// sent before the instance's own.
    pub events: Vec<Value>,
    /// `(table, ids)`, deleted in this order before the instance.
    pub deletes: Vec<(&'static str, Vec<i32>)>,
}

/// A viewset served by this module.
pub(crate) trait Resource {
    const SPEC: Spec;
    const ALLOW_LIST: &'static str;
    const ALLOW_DETAIL: &'static str;

    /// `get_object()` up to the object permission: the list's filters and
    /// the lookup, or their 404.
    async fn find(
        ctx: &Context<'_>,
        query: &QueryDict,
        user: &User,
        pk: &str,
    ) -> Result<Result<Found, Answer>, Decline>;

    /// The serializer's output for the saved row.
    async fn render(
        ctx: &Context<'_>,
        row: &Row,
        status: u16,
        allow: &'static str,
    ) -> Result<Answer, Decline>;

    /// The rows deleted with `row`.
    async fn collect(_ctx: &Context<'_>, _row: &Row) -> Result<Collected, Decline> {
        Ok(Collected::default())
    }
}

/// A table's columns in `attnum` order, read once per process.
async fn columns(ctx: &Context<'_>, table: &'static str) -> Result<Vec<String>, Decline> {
    static CACHE: OnceLock<Mutex<HashMap<&'static str, Vec<String>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Mutex::default);
    if let Some(columns) = cache.lock().map_err(|_| Decline("lock"))?.get(table) {
        return Ok(columns.clone());
    }
    let columns: Vec<String> = sqlx::query_scalar(
        "SELECT attname::text FROM pg_attribute WHERE attrelid = $1::regclass AND attnum > 0 \
         AND NOT attisdropped ORDER BY attnum",
    )
    .bind(table)
    .fetch_all(ctx.pool)
    .await
    .map_err(db)?;
    if columns.is_empty() {
        return Err(Decline("no columns"));
    }
    cache
        .lock()
        .map_err(|_| Decline("lock"))?
        .insert(table, columns.clone());
    Ok(columns)
}

fn quoted(columns: &[String]) -> String {
    columns
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

fn row(value: Option<Value>) -> Result<Option<Row>, Decline> {
    match value {
        None => Ok(None),
        Some(Value::Object(row)) => Ok(Some(row)),
        Some(_) => Err(Decline("row shape")),
    }
}

/// The row `pk` identifies: `to_jsonb` of it.
async fn load(ctx: &Context<'_>, spec: &Spec, pk: &str) -> Result<Option<Row>, Decline> {
    let Model {
        db_table: table,
        pk_column,
        ..
    } = spec.model;
    let value: Option<Value> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT to_jsonb(x) FROM \"{table}\" AS x WHERE x.\"{pk_column}\" = (SELECT \
         \"{pk_column}\" FROM jsonb_populate_record(NULL::\"{table}\", $1))"
    )))
    .bind(json!({ pk_column: pk }))
    .fetch_optional(ctx.pool)
    .await
    .map_err(db)?;
    row(value)
}

/// Django's INSERT: every column but an `AutoField`, from `values`.
async fn insert(
    ctx: &Context<'_>,
    conn: &mut PgConnection,
    spec: &Spec,
    values: &Row,
) -> Result<Row, Decline> {
    let Model {
        db_table: table,
        pk_column,
        ..
    } = spec.model;
    let mut cols = columns(ctx, table).await?;
    if matches!(spec.pk, Pk::Serial) {
        cols.retain(|c| c != pk_column);
    }
    let cols = quoted(&cols);
    let value: Option<Value> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "INSERT INTO \"{table}\" AS x ({cols}) SELECT {cols} FROM \
         jsonb_populate_record(NULL::\"{table}\", $1) RETURNING to_jsonb(x)"
    )))
    .bind(Value::Object(values.clone()))
    .fetch_optional(conn)
    .await
    .map_err(db)?;
    row(value)?.ok_or(Decline("insert returned nothing"))
}

/// `save()` on an existing row: an UPDATE of every column but the key.
async fn update_row(
    ctx: &Context<'_>,
    conn: &mut PgConnection,
    spec: &Spec,
    values: &Row,
) -> Result<Option<Row>, Decline> {
    let Model {
        db_table: table,
        pk_column,
        ..
    } = spec.model;
    let mut cols = columns(ctx, table).await?;
    cols.retain(|c| c != pk_column);
    let cols = quoted(&cols);
    let value: Option<Value> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "UPDATE \"{table}\" AS x SET ({cols}) = (SELECT {cols} FROM \
         jsonb_populate_record(NULL::\"{table}\", $1)) WHERE x.\"{pk_column}\" = (SELECT \
         \"{pk_column}\" FROM jsonb_populate_record(NULL::\"{table}\", $1)) RETURNING \
         to_jsonb(x)"
    )))
    .bind(Value::Object(values.clone()))
    .fetch_optional(conn)
    .await
    .map_err(db)?;
    row(value)
}

/// `DELETE … WHERE id IN (…)` for a collected batch.
pub(crate) async fn delete_ids(
    conn: &mut PgConnection,
    table: &str,
    ids: &[i32],
) -> Result<(), Decline> {
    if ids.is_empty() {
        return Ok(());
    }
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "DELETE FROM \"{table}\" WHERE \"{table}\".\"id\" = ANY($1)"
    )))
    .bind(ids)
    .execute(conn)
    .await
    .map_err(db)?;
    Ok(())
}

/// `str(value)` of a JSON key as `to_jsonb` renders it.
fn pk_text(value: &Value) -> Result<String, Decline> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        _ => Err(Decline("pk shape")),
    }
}

/// `model_to_dict(instance)`.
fn audit_model(spec: &Spec, row: &Row) -> Result<Option<Value>, Decline> {
    let Some(name) = &spec.audit else {
        return Ok(None);
    };
    let Name::Column(column) = name;
    let name = row
        .get(*column)
        .and_then(Value::as_str)
        .ok_or(Decline("audit name"))?;
    let pk = row.get(spec.model.pk_column).ok_or(Decline("pk"))?;
    // `model_to_dict` gives a UUID as its hex.
    let pk = match spec.model.pk_cast {
        PkCast::Uuid => json!(
            uuid::Uuid::parse_str(pk.as_str().ok_or(Decline("pk"))?)
                .map_err(|_| Decline("pk"))?
                .simple()
                .to_string()
        ),
        PkCast::Bigint => pk.clone(),
    };
    Ok(Some(model_dict(
        spec.model.app_label,
        spec.model.model_name,
        &pk,
        name,
    )))
}

fn incorrect_type(type_name: &str) -> String {
    format!("Incorrect type. Expected pk value, received {type_name}.")
}

fn does_not_exist(raw: &str) -> String {
    format!("Invalid pk \"{raw}\" - object does not exist.")
}

/// A related row's key, for the existence lookup.
enum Key {
    Uuid(uuid::Uuid),
    Int(i32),
}

async fn exists(
    ctx: &Context<'_>,
    table: &str,
    column: &str,
    key: Key,
) -> Result<bool, FieldError> {
    let sql = format!("SELECT EXISTS (SELECT 1 FROM \"{table}\" WHERE \"{column}\" = $1)");
    let query = sqlx::query_scalar(sqlx::AssertSqlSafe(sql));
    let query = match key {
        Key::Uuid(uuid) => query.bind(uuid),
        Key::Int(id) => query.bind(id),
    };
    query.fetch_one(ctx.pool).await.map_err(|e| Err(db(e)))
}

/// `PrimaryKeyRelatedField.to_internal_value` for a UUID primary key, as
/// `UUIDField.to_python` reads the value.
async fn pk_uuid(
    ctx: &Context<'_>,
    table: &str,
    column: &str,
    value: &PyValue,
) -> Result<uuid::Uuid, FieldError> {
    let (uuid, raw) = match value {
        PyValue::Bool(_) => return Err(Ok(incorrect_type("bool"))),
        // `uuid.UUID(int=…)`; JSON integers are canonical except `-0`.
        PyValue::Int(digits) => match digits.parse::<u128>() {
            Ok(n) if digits != "-0" => (uuid::Uuid::from_u128(n), digits.clone()),
            _ if digits.starts_with('-') && digits != "-0" => {
                return Err(Ok(format!("\u{201c}{digits}\u{201d} is not a valid UUID.")));
            }
            _ => return Err(Err(Decline("uuid integer"))),
        },
        PyValue::Str(s) => {
            let raw = s.to_string_lossless().ok_or(Err(Decline("surrogate")))?;
            match uuid_lookup(&raw).map_err(|_| Err(Decline("uuid syntax")))? {
                UuidLookup::Valid(uuid) => (uuid, raw),
                UuidLookup::Invalid => {
                    return Err(Ok(format!("\u{201c}{raw}\u{201d} is not a valid UUID.")));
                }
            }
        }
        // `str()` of these in Django's message is not reproduced.
        _ => return Err(Err(Decline("uuid value"))),
    };
    if exists(ctx, table, column, Key::Uuid(uuid)).await? {
        Ok(uuid)
    } else {
        Err(Ok(does_not_exist(&raw)))
    }
}

/// `PrimaryKeyRelatedField.to_internal_value` for an integer primary key,
/// as `IntegerField.get_prep_value` (`int(value)`) reads the value.
async fn pk_int(
    ctx: &Context<'_>,
    table: &str,
    column: &str,
    value: &PyValue,
) -> Result<i32, FieldError> {
    let (id, raw) = match value {
        PyValue::Bool(_) => return Err(Ok(incorrect_type("bool"))),
        // `get(pk=None)` is an `IS NULL` lookup: nothing matches.
        PyValue::None => return Err(Ok(does_not_exist("None"))),
        PyValue::List(_) => return Err(Ok(incorrect_type("list"))),
        PyValue::Dict(_) => return Err(Ok(incorrect_type("dict"))),
        // `int(1.5)` truncates; not reproduced.
        PyValue::Float(_) => return Err(Err(Decline("pk float"))),
        // `-0` is the integer 0, which Django's message prints as `0`.
        PyValue::Int(digits) if digits == "-0" => return Err(Err(Decline("pk -0"))),
        PyValue::Int(digits) => {
            let parsed = py_int(digits).map_err(|_| Err(Decline("pk digits")))?;
            (parsed.and_then(int4), digits.clone())
        }
        PyValue::Str(s) => {
            let raw = s.to_string_lossless().ok_or(Err(Decline("surrogate")))?;
            // Python's `int()` takes whitespace, `+` and underscores too.
            if !raw.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
                return match py_int(&raw) {
                    Ok(None) => Err(Ok(incorrect_type("str"))),
                    _ => Err(Err(Decline("int syntax"))),
                };
            }
            match py_int(&raw).map_err(|_| Err(Decline("pk digits")))? {
                None => return Err(Ok(incorrect_type("str"))),
                Some(PyInt::Big { .. }) => (None, raw),
                Some(value) => (int4(value), raw),
            }
        }
    };
    // Out of the column's range: Django's lookup matches nothing.
    let Some(id) = id else {
        return Err(Ok(does_not_exist(&raw)));
    };
    if exists(ctx, table, column, Key::Int(id)).await? {
        Ok(id)
    } else {
        Err(Ok(does_not_exist(&raw)))
    }
}

/// `ManyRelatedField.to_internal_value`: the first bad item is the error.
async fn many_int(
    ctx: &Context<'_>,
    table: &str,
    column: &str,
    value: &PyValue,
) -> Result<Vec<i32>, FieldError> {
    let not_a_list = |t: &str| {
        Err(Ok(format!(
            "Expected a list of items but got type \"{t}\"."
        )))
    };
    let items = match value {
        PyValue::List(items) => items,
        PyValue::Str(_) => return not_a_list("str"),
        PyValue::Int(_) => return not_a_list("int"),
        PyValue::Bool(_) => return not_a_list("bool"),
        PyValue::Float(_) => return not_a_list("float"),
        PyValue::None => return Err(Ok("This field may not be null.".into())),
        // A dict iterates its keys.
        PyValue::Dict(_) => return Err(Err(Decline("many dict"))),
    };
    let mut ids = Vec::with_capacity(items.len());
    for item in items {
        ids.push(pk_int(ctx, table, column, item).await?);
    }
    Ok(ids)
}

/// The validated data: column values and many-to-many id lists.
pub(crate) struct Valid {
    pub values: Row,
    pub m2m: Vec<(&'static Through, Vec<i32>)>,
}

/// `UniqueValidator`: another row holds `value`.
async fn taken(
    ctx: &Context<'_>,
    spec: &Spec,
    column: &str,
    value: &str,
    except: Option<&str>,
) -> Result<bool, Decline> {
    let Model {
        db_table: table,
        pk_column,
        ..
    } = spec.model;
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT EXISTS (SELECT 1 FROM \"{table}\" WHERE \"{column}\" = $1 AND \
         \"{pk_column}\"::text IS DISTINCT FROM $2)"
    )))
    .bind(value)
    .bind(except)
    .fetch_one(ctx.pool)
    .await
    .map_err(db)
}

/// `serializer.is_valid()`: `Ok(Err(errors))` for its 400.
async fn validate(
    ctx: &Context<'_>,
    spec: &Spec,
    data: &Data,
    partial: bool,
    except: Option<&str>,
) -> Result<Result<Valid, Vec<(&'static str, String)>>, Decline> {
    let mut errors: Vec<(&'static str, String)> = Vec::new();
    let mut valid = Valid {
        values: Row::new(),
        m2m: Vec::new(),
    };
    for field in spec.fields {
        let required = field.required && !partial;
        let mut fail = |error: FieldError| match error {
            Ok(message) => {
                errors.push((field.name, message));
                Ok(())
            }
            Err(decline) => Err(decline),
        };
        match &field.kind {
            Kind::Char(char_field) => {
                // `UniqueValidator` runs before `max_length`'s validator.
                let base = CharField {
                    required,
                    max_length: None,
                    ..*char_field
                };
                let text = match base.validate(data, field.name) {
                    Ok(Input::Absent) => continue,
                    Ok(Input::Null) => {
                        valid.values.insert(field.column.into(), Value::Null);
                        continue;
                    }
                    Ok(Input::Value(text)) => text,
                    Err(error) => {
                        fail(error)?;
                        continue;
                    }
                };
                // `run_validators` reports every validator's message.
                let mut messages = Vec::new();
                if let Some(message) = field.unique
                    && taken(ctx, spec, field.column, &text, except).await?
                {
                    messages.push(message.to_owned());
                }
                if let Some(max) = char_field.max_length
                    && text.chars().count() > max
                {
                    messages.push(format!(
                        "Ensure this field has no more than {max} characters."
                    ));
                }
                match messages.len() {
                    0 => {
                        valid
                            .values
                            .insert(field.column.into(), Value::String(text));
                    }
                    1 => fail(Ok(messages.remove(0)))?,
                    _ => return Err(Decline("several validator messages")),
                }
            }
            Kind::Bool => match boolean_field(data, field.name, required) {
                Ok(Input::Value(b)) => {
                    valid.values.insert(field.column.into(), Value::Bool(b));
                }
                Ok(Input::Absent | Input::Null) => {}
                Err(error) => fail(error)?,
            },
            Kind::ForeignUuid { table, column } => match data.get(field.name) {
                None if required => fail(Ok("This field is required.".into()))?,
                None => {}
                Some(PyValue::None) => fail(Ok("This field may not be null.".into()))?,
                Some(value) => match pk_uuid(ctx, table, column, value).await {
                    Ok(uuid) => {
                        valid
                            .values
                            .insert(field.column.into(), Value::String(uuid.to_string()));
                    }
                    Err(error) => fail(error)?,
                },
            },
            Kind::ManyInt {
                table,
                column,
                through,
            } => match data.get(field.name) {
                None if required => fail(Ok("This field is required.".into()))?,
                None => {}
                Some(value) => match many_int(ctx, table, column, value).await {
                    Ok(ids) => valid.m2m.push((through, ids)),
                    Err(error) => fail(error)?,
                },
            },
        }
    }
    Ok(if errors.is_empty() {
        Ok(valid)
    } else {
        Err(errors)
    })
}

/// `instance.<field>.set(ids)`: the current ids, the collector's delete of
/// the dropped rows (auto-created rows get no signal), then `_add_items`.
/// `AuditMiddleware`'s global `m2m_changed` receiver rules out the fast add,
/// so the missing ids are inserted in the iteration order of
/// `target_ids.difference(queryset)`, a `CPython` set, which numbers the
/// new rows.
async fn set_m2m(
    conn: &mut PgConnection,
    through: &Through,
    owner: &Value,
    ids: &[i32],
) -> Result<(), Decline> {
    let Through {
        table,
        source,
        target,
    } = through;
    let owner = pk_text(owner)?;
    // The owner's key compared as text: an integer or UUID column alike.
    let current: Vec<i32> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT \"{target}\" FROM \"{table}\" WHERE \"{source}\"::text = $1"
    )))
    .bind(&owner)
    .fetch_all(&mut *conn)
    .await
    .map_err(db)?;
    let mut old = current;
    let mut new = Vec::new();
    for &id in ids {
        if let Some(at) = old.iter().position(|&o| o == id) {
            old.swap_remove(at);
        } else {
            new.push(id);
        }
    }
    if !old.is_empty() {
        let rows: Vec<i32> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT id FROM \"{table}\" WHERE (\"{source}\"::text = $1 AND \"{target}\" = \
             ANY($2))"
        )))
        .bind(&owner)
        .bind(&old)
        .fetch_all(&mut *conn)
        .await
        .map_err(db)?;
        delete_ids(conn, table, &rows).await?;
    }
    if new.is_empty() {
        return Ok(());
    }
    let mut target_ids = IntSet::new();
    for &id in &new {
        target_ids.add(i64::from(id));
    }
    let present: Vec<i32> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT \"{target}\" FROM \"{table}\" WHERE (\"{source}\"::text = $1 AND \"{target}\" \
         = ANY($2))"
    )))
    .bind(&owner)
    .bind(&new)
    .fetch_all(&mut *conn)
    .await
    .map_err(db)?;
    let missing: Vec<i32> = target_ids
        .difference_iter(present.into_iter().map(i64::from))
        .iter()
        .map(|id| i32::try_from(id).map_err(|_| Decline("m2m id")))
        .collect::<Result<_, _>>()?;
    if missing.is_empty() {
        return Ok(());
    }
    // `bulk_create(ignore_conflicts=True)`: one statement, rows numbered in
    // the set's order. The source column takes the owner's key as text.
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "INSERT INTO \"{table}\" (\"{source}\", \"{target}\") SELECT \
         (SELECT \"{source}\" FROM jsonb_populate_record(NULL::\"{table}\", \
         jsonb_build_object('{source}', $1::text))), u.p FROM unnest($2::int[]) WITH \
         ORDINALITY AS u(p, o) ORDER BY u.o ON CONFLICT DO NOTHING"
    )))
    .bind(&owner)
    .bind(&missing)
    .execute(&mut *conn)
    .await
    .map_err(db)?;
    Ok(())
}

/// A write's transaction with the audit context.
struct Session<'a> {
    tx: Transaction<'static, Postgres>,
    audit: Option<Audit<'a>>,
}

impl<'a> Session<'a> {
    /// The checks before `save()`: `InitialPermissionsMiddleware` (the
    /// created instance, if any, and an audited write's event, task and
    /// log), then the client and audit context.
    async fn begin(
        ctx: &'a Context<'_>,
        req: &'a ApiRequest<'_>,
        tenant: &Tenant,
        user: &User,
        spec: &Spec,
        inserts: bool,
        client: &'a (String, String),
    ) -> Result<Self, Decline> {
        let mut created: Vec<(&str, &str)> = Vec::new();
        if inserts {
            created.push((spec.model.ctype_app_label, spec.model.ctype_model));
        }
        if spec.audit.is_some() {
            created.extend(SIDE_EFFECT_MODELS.iter().copied());
        }
        if !created.is_empty() && initial_permissions_apply(ctx, user, &created).await? {
            return Err(Decline("initial permissions apply"));
        }
        let audit = if spec.audit.is_some() {
            let (ip, user_agent) = client;
            Some(Audit::new(ctx, req, tenant, user, user_agent, ip).await?)
        } else {
            None
        };
        Ok(Self {
            tx: ctx.pool.begin().await.map_err(db)?,
            audit,
        })
    }

    async fn event(
        &mut self,
        ctx: &Context<'_>,
        action: &str,
        model: Option<Value>,
    ) -> Result<(), Decline> {
        match (&self.audit, model) {
            (Some(audit), Some(model)) => audit.event(&mut self.tx, action, model, ctx.now).await,
            (None, None) => Ok(()),
            _ => Err(Decline("audit mismatch")),
        }
    }
}

/// The audit context's client; only an audited write needs it.
fn session_client(spec: &Spec, req: &ApiRequest<'_>) -> Result<(String, String), Decline> {
    if spec.audit.is_some() {
        client(req)
    } else {
        Ok((String::new(), String::new()))
    }
}

/// `get_object()`: [`Resource::find`], then the object permission.
async fn get_object<R: Resource>(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
    query: &QueryDict,
    user: &User,
    pk: &str,
) -> Result<Result<Row, Answer>, Decline> {
    let found = match R::find(ctx, query, user, pk).await? {
        Ok(found) => found,
        Err(answer) => return Ok(Err(answer)),
    };
    let access = ak_rbac::has_object_permission(
        ctx.pool,
        user.subject(),
        req.method,
        &Object {
            model: R::SPEC.model,
            pk: &found.pk,
        },
        found.owner,
    )
    .await
    .map_err(|_| Decline("object permission raised"))?;
    match access {
        Access::Allow => {}
        Access::NotFound => {
            return Ok(Err(drf::detail(404, "Not found.", R::ALLOW_DETAIL)));
        }
        Access::Deny => return Ok(Err(drf::permission_denied(user, R::ALLOW_DETAIL))),
    }
    load(ctx, &R::SPEC, &found.pk)
        .await?
        .map(Ok)
        .ok_or(Decline("row gone"))
}

fn body<'d>(spec: &Spec, data: &'d Data) -> Result<&'d Data, Decline> {
    if spec.decline_keys.iter().any(|k| data.get(k).is_some()) {
        return Err(Decline("field write not reproduced"));
    }
    Ok(data)
}

/// `create()`: `POST` on the list route.
pub(crate) async fn create<R: Resource>(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
) -> Result<Answer, Decline> {
    let spec = &R::SPEC;
    let tenant = drf::tenant(ctx, req).await?;
    let user = match drf::authenticate(ctx, req, R::ALLOW_LIST).await? {
        Ok(user) => user,
        Err(answer) => return Ok(answer),
    };
    let allowed =
        ak_rbac::has_permission(ctx.pool, user.subject(), "POST", &spec.model, false, false)
            .await
            .map_err(|_| Decline("permission raised"))?;
    if !allowed || !user.is_authenticated() {
        return Ok(drf::permission_denied(&user, R::ALLOW_LIST));
    }
    let data = json_body(req)?;
    let valid = match validate(ctx, spec, body(spec, &data)?, false, None).await? {
        Ok(valid) => valid,
        Err(errors) => return Ok(field_errors(&errors, R::ALLOW_LIST)),
    };
    let mut values = Row::new();
    if matches!(spec.pk, Pk::Uuid4) {
        values.insert(
            spec.model.pk_column.into(),
            Value::String(uuid::Uuid::new_v4().to_string()),
        );
    }
    values.extend(valid.values);
    let client = session_client(spec, req)?;
    let mut session = Session::begin(ctx, req, &tenant, &user, spec, true, &client).await?;
    let saved = insert(ctx, &mut session.tx, spec, &values).await?;
    session
        .event(ctx, "model_created", audit_model(spec, &saved)?)
        .await?;
    let pk = saved.get(spec.model.pk_column).ok_or(Decline("pk"))?;
    for (through, ids) in &valid.m2m {
        set_m2m(&mut session.tx, through, pk, ids).await?;
    }
    session.tx.commit().await.map_err(db)?;
    R::render(ctx, &saved, 201, R::ALLOW_LIST).await
}

/// `update()`/`partial_update()`: `PUT`/`PATCH` on the detail route.
pub(crate) async fn update<R: Resource>(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
    query: &QueryDict,
    pk: &str,
) -> Result<Answer, Decline> {
    let spec = &R::SPEC;
    let tenant = drf::tenant(ctx, req).await?;
    let user = match drf::authenticate(ctx, req, R::ALLOW_DETAIL).await? {
        Ok(user) => user,
        Err(answer) => return Ok(answer),
    };
    let current = match get_object::<R>(ctx, req, query, &user, pk).await? {
        Ok(row) => row,
        Err(answer) => return Ok(answer),
    };
    let key = current.get(spec.model.pk_column).ok_or(Decline("pk"))?;
    let key_text = pk_text(key)?;
    let data = json_body(req)?;
    let partial = req.method == "PATCH";
    let valid = match validate(ctx, spec, body(spec, &data)?, partial, Some(&key_text)).await? {
        Ok(valid) => valid,
        Err(errors) => return Ok(field_errors(&errors, R::ALLOW_DETAIL)),
    };
    let mut values = current.clone();
    values.extend(valid.values);
    let client = session_client(spec, req)?;
    let mut session = Session::begin(ctx, req, &tenant, &user, spec, false, &client).await?;
    // Deleted meanwhile: `save()` would insert it again.
    let saved = update_row(ctx, &mut session.tx, spec, &values)
        .await?
        .ok_or(Decline("row gone"))?;
    session
        .event(ctx, "model_updated", audit_model(spec, &saved)?)
        .await?;
    for (through, ids) in &valid.m2m {
        set_m2m(&mut session.tx, through, key, ids).await?;
    }
    session.tx.commit().await.map_err(db)?;
    R::render(ctx, &saved, 200, R::ALLOW_DETAIL).await
}

/// `destroy()`: `DELETE` on the detail route.
pub(crate) async fn destroy<R: Resource>(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
    query: &QueryDict,
    pk: &str,
) -> Result<Answer, Decline> {
    let spec = &R::SPEC;
    let tenant = drf::tenant(ctx, req).await?;
    let user = match drf::authenticate(ctx, req, R::ALLOW_DETAIL).await? {
        Ok(user) => user,
        Err(answer) => return Ok(answer),
    };
    let current = match get_object::<R>(ctx, req, query, &user, pk).await? {
        Ok(row) => row,
        Err(answer) => return Ok(answer),
    };
    let collected = R::collect(ctx, &current).await?;
    let client = session_client(spec, req)?;
    let mut session = Session::begin(ctx, req, &tenant, &user, spec, false, &client).await?;
    if spec.audit.is_none() && !collected.events.is_empty() {
        return Err(Decline("collected events without audit"));
    }
    for model in collected.events {
        session.event(ctx, "model_deleted", Some(model)).await?;
    }
    session
        .event(ctx, "model_deleted", audit_model(spec, &current)?)
        .await?;
    for (table, ids) in &collected.deletes {
        delete_ids(&mut session.tx, table, ids).await?;
    }
    let Model {
        db_table: table,
        pk_column,
        ..
    } = spec.model;
    let deleted = sqlx::query(sqlx::AssertSqlSafe(format!(
        "DELETE FROM \"{table}\" WHERE \"{table}\".\"{pk_column}\" IN (SELECT \"{pk_column}\" \
         FROM jsonb_populate_record(NULL::\"{table}\", $1))"
    )))
    .bind(Value::Object(current))
    .execute(&mut *session.tx)
    .await
    .map_err(db)?;
    if deleted.rows_affected() != 1 {
        return Err(Decline("row gone"));
    }
    session.tx.commit().await.map_err(db)?;
    Ok(no_content(R::ALLOW_DETAIL))
}
