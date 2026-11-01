//! `InitialPermissionsViewSet`'s writes: `create`, `update`/`partial_update`,
//! `destroy`.
//!
//! `InitialPermissionsSerializer` validates, in field order:
//! - `name`: a `CharField(max_length=150)` whose `UniqueValidator` runs
//!   before the length check;
//! - `role`: a `PrimaryKeyRelatedField` on every role (a UUID pk, read as
//!   `UUIDField.to_python` does);
//! - `permissions`: a `ManyRelatedField` of `Permission` pks, not required.
//!   The first bad item is the error.
//!
//! `save()` writes the row and `AuditMiddleware`'s event, then
//! `permissions.set()`. That reads the current ids, deletes the dropped
//! rows through the collector (no signals for auto-created rows), and
//! inserts the missing ids. A global `m2m_changed` receiver rules out
//! Django's fast add, so the insert follows `target_ids.difference(…)`'s
//! `CPython` set order, which numbers the new rows.

use serde_json::json;
use sqlx::{PgConnection, Row as _, postgres::PgRow};

use crate::{
    Answer, Decline,
    drf::{self, ApiRequest, Context, User},
    py::{PyInt, QueryDict, UuidLookup, int4, py_int, uuid_lookup},
    pyset::IntSet,
    sql::Bind,
    views::rbac_initial_permissions::{
        ALLOW_DETAIL, ALLOW_LIST, COLUMNS, MODEL, filter_queryset, serialize,
    },
    write::{
        Audit, CharField, Data, FieldError, SIDE_EFFECT_MODELS, client, field_errors,
        initial_permissions_apply, json_body, model_dict, no_content,
    },
};
use ak_auth::python::PyValue;

const UNIQUE: &str = "Initial Permissions with this name already exists.";
const MAX_NAME: usize = 150;

fn db(_: sqlx::Error) -> Decline {
    Decline("database error")
}

/// The validated fields; `None` where the data left a field out.
struct Valid {
    name: Option<String>,
    role: Option<uuid::Uuid>,
    permissions: Option<Vec<i32>>,
}

fn incorrect_type(type_name: &str) -> String {
    format!("Incorrect type. Expected pk value, received {type_name}.")
}

fn does_not_exist(raw: &str) -> String {
    format!("Invalid pk \"{raw}\" - object does not exist.")
}

/// `PrimaryKeyRelatedField(queryset=Role.objects.all())` on a value.
async fn role_pk(ctx: &Context<'_>, value: &PyValue) -> Result<uuid::Uuid, FieldError> {
    let (uuid, raw) = match value {
        PyValue::Bool(_) => return Err(Ok(incorrect_type("bool"))),
        // `uuid.UUID(int=…)`; JSON integers are canonical except `-0`.
        PyValue::Int(digits) => match digits.parse::<u128>() {
            Ok(n) if digits != "-0" => (uuid::Uuid::from_u128(n), digits.clone()),
            _ if digits.starts_with('-') && digits != "-0" => {
                return Err(Ok(format!("\u{201c}{digits}\u{201d} is not a valid UUID.")));
            }
            _ => return Err(Err(Decline("role integer"))),
        },
        PyValue::Str(s) => {
            let raw = s.to_string_lossless().ok_or(Err(Decline("surrogate")))?;
            match uuid_lookup(&raw).map_err(|_| Err(Decline("role uuid syntax")))? {
                UuidLookup::Valid(uuid) => (uuid, raw),
                UuidLookup::Invalid => {
                    return Err(Ok(format!("\u{201c}{raw}\u{201d} is not a valid UUID.")));
                }
            }
        }
        // `str()` of these in Django's message is not reproduced.
        _ => return Err(Err(Decline("role value"))),
    };
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM authentik_rbac_role WHERE uuid = $1)")
            .bind(uuid)
            .fetch_one(ctx.pool)
            .await
            .map_err(|e| Err(db(e)))?;
    if exists {
        Ok(uuid)
    } else {
        Err(Ok(does_not_exist(&raw)))
    }
}

/// `PrimaryKeyRelatedField(queryset=Permission.objects.all())` on one
/// item: `int(value)` as `IntegerField.get_prep_value` reads it.
async fn permission_pk(ctx: &Context<'_>, value: &PyValue) -> Result<i32, FieldError> {
    let (id, raw) = match value {
        PyValue::Bool(_) => return Err(Ok(incorrect_type("bool"))),
        // `get(pk=None)` is an `IS NULL` lookup: nothing matches.
        PyValue::None => return Err(Ok(does_not_exist("None"))),
        PyValue::List(_) => return Err(Ok(incorrect_type("list"))),
        PyValue::Dict(_) => return Err(Ok(incorrect_type("dict"))),
        // `int(1.5)` truncates; not reproduced.
        PyValue::Float(_) => return Err(Err(Decline("permission float"))),
        // `-0` is the integer 0, which Django's message prints as `0`.
        PyValue::Int(digits) if digits == "-0" => return Err(Err(Decline("permission -0"))),
        PyValue::Int(digits) => {
            let parsed = py_int(digits).map_err(|_| Err(Decline("permission digits")))?;
            (parsed.and_then(int4), digits.clone())
        }
        PyValue::Str(s) => {
            let raw = s.to_string_lossless().ok_or(Err(Decline("surrogate")))?;
            // Python's `int()` takes whitespace, `+` and underscores too.
            if !raw.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
                return match py_int(&raw) {
                    Ok(None) => Err(Ok(incorrect_type("str"))),
                    _ => Err(Err(Decline("permission int syntax"))),
                };
            }
            match py_int(&raw).map_err(|_| Err(Decline("permission digits")))? {
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
    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM auth_permission WHERE id = $1)")
            .bind(id)
            .fetch_one(ctx.pool)
            .await
            .map_err(|e| Err(db(e)))?;
    if exists {
        Ok(id)
    } else {
        Err(Ok(does_not_exist(&raw)))
    }
}

/// `ManyRelatedField.to_internal_value`.
async fn permissions_field(ctx: &Context<'_>, value: &PyValue) -> Result<Vec<i32>, FieldError> {
    let items = match value {
        PyValue::List(items) => items,
        PyValue::Str(_) => return Err(Ok("Expected a list of items but got type \"str\".".into())),
        PyValue::Int(_) => return Err(Ok("Expected a list of items but got type \"int\".".into())),
        PyValue::Bool(_) => {
            return Err(Ok("Expected a list of items but got type \"bool\".".into()));
        }
        PyValue::Float(_) => {
            return Err(Ok("Expected a list of items but got type \"float\".".into()));
        }
        PyValue::None => return Err(Ok("This field may not be null.".into())),
        // A dict iterates its keys.
        PyValue::Dict(_) => return Err(Err(Decline("permissions dict"))),
    };
    let mut ids = Vec::with_capacity(items.len());
    for item in items {
        ids.push(permission_pk(ctx, item).await?);
    }
    Ok(ids)
}

/// The serializer's validation; `Ok(Err(answer))` for its 400.
async fn validate(
    ctx: &Context<'_>,
    data: &Data,
    partial: bool,
    except: Option<i32>,
    allow: &'static str,
) -> Result<Result<Valid, Answer>, Decline> {
    let mut errors: Vec<(&str, String)> = Vec::new();
    let mut fail = |name: &'static str, error: FieldError| match error {
        Ok(message) => {
            errors.push((name, message));
            Ok(())
        }
        Err(decline) => Err(decline),
    };
    let name = match CharField::new(!partial).validate(data, "name") {
        Ok(input) => input.value(),
        Err(error) => {
            fail("name", error)?;
            None
        }
    };
    if let Some(name) = &name {
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM authentik_rbac_initialpermissions WHERE name = $1 \
             AND id IS DISTINCT FROM $2)",
        )
        .bind(name)
        .bind(except)
        .fetch_one(ctx.pool)
        .await
        .map_err(db)?;
        // `run_validators` reports every validator's message.
        let mut messages = Vec::new();
        if taken {
            messages.push(UNIQUE.to_owned());
        }
        if name.chars().count() > MAX_NAME {
            messages.push(format!(
                "Ensure this field has no more than {MAX_NAME} characters."
            ));
        }
        if messages.len() > 1 {
            return Err(Decline("several name errors"));
        }
        if let Some(message) = messages.pop() {
            fail("name", Ok(message))?;
        }
    }
    let role = match data.get("role") {
        None if partial => None,
        None => {
            fail("role", Ok("This field is required.".into()))?;
            None
        }
        Some(PyValue::None) => {
            fail("role", Ok("This field may not be null.".into()))?;
            None
        }
        Some(value) => match role_pk(ctx, value).await {
            Ok(uuid) => Some(uuid),
            Err(error) => {
                fail("role", error)?;
                None
            }
        },
    };
    let permissions = match data.get("permissions") {
        None => None,
        Some(value) => match permissions_field(ctx, value).await {
            Ok(ids) => Some(ids),
            Err(error) => {
                fail("permissions", error)?;
                None
            }
        },
    };
    if !errors.is_empty() {
        return Ok(Err(field_errors(&errors, allow)));
    }
    Ok(Ok(Valid {
        name,
        role,
        permissions,
    }))
}

/// `instance.permissions.set(ids)`.
async fn set_permissions(conn: &mut PgConnection, owner: i32, ids: &[i32]) -> Result<(), Decline> {
    let current: Vec<i32> = sqlx::query_scalar(
        "SELECT permission_id FROM authentik_rbac_initialpermissions_permissions WHERE \
         initialpermissions_id = $1",
    )
    .bind(owner)
    .fetch_all(&mut *conn)
    .await
    .map_err(db)?;
    let mut old: Vec<i32> = current;
    let mut new = Vec::new();
    for &id in ids {
        if let Some(at) = old.iter().position(|&o| o == id) {
            old.swap_remove(at);
        } else {
            new.push(id);
        }
    }
    if !old.is_empty() {
        // `QuerySet.delete()`: the collector selects the rows, then deletes
        // them by primary key.
        let rows: Vec<i32> = sqlx::query_scalar(
            "SELECT id FROM authentik_rbac_initialpermissions_permissions WHERE \
             (initialpermissions_id = $1 AND permission_id = ANY($2))",
        )
        .bind(owner)
        .bind(&old)
        .fetch_all(&mut *conn)
        .await
        .map_err(db)?;
        delete_ids(conn, "authentik_rbac_initialpermissions_permissions", &rows).await?;
    }
    if new.is_empty() {
        return Ok(());
    }
    let mut target = IntSet::new();
    for &id in &new {
        target.add(i64::from(id));
    }
    let present: Vec<i32> = sqlx::query_scalar(
        "SELECT permission_id FROM authentik_rbac_initialpermissions_permissions WHERE \
         (initialpermissions_id = $1 AND permission_id = ANY($2))",
    )
    .bind(owner)
    .bind(&new)
    .fetch_all(&mut *conn)
    .await
    .map_err(db)?;
    let missing: Vec<i32> = target
        .difference_iter(present.into_iter().map(i64::from))
        .iter()
        .map(|id| i32::try_from(id).map_err(|_| Decline("permission id")))
        .collect::<Result<_, _>>()?;
    if missing.is_empty() {
        return Ok(());
    }
    // `bulk_create(ignore_conflicts=True)`: one statement, rows numbered in
    // the set's order.
    sqlx::query(
        "INSERT INTO authentik_rbac_initialpermissions_permissions (initialpermissions_id, \
         permission_id) SELECT $1, u.p FROM unnest($2::int[]) WITH ORDINALITY AS u(p, o) \
         ORDER BY u.o ON CONFLICT DO NOTHING",
    )
    .bind(owner)
    .bind(&missing)
    .execute(&mut *conn)
    .await
    .map_err(db)?;
    Ok(())
}

async fn delete_ids(conn: &mut PgConnection, table: &str, ids: &[i32]) -> Result<(), Decline> {
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

fn model(id: i32, name: &str) -> serde_json::Value {
    model_dict("authentik_rbac", "initialpermissions", &json!(id), name)
}

/// The serializer's output for row `id`, after the write.
async fn respond(
    ctx: &Context<'_>,
    id: i32,
    status: u16,
    allow: &'static str,
) -> Result<Answer, Decline> {
    let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {COLUMNS} FROM authentik_rbac_initialpermissions t WHERE t.\"id\" = $1"
    )))
    .bind(id)
    .fetch_all(ctx.pool)
    .await
    .map_err(db)?;
    let mut one = serialize(ctx, &rows).await?;
    Ok(drf::json(
        status,
        &one.pop().ok_or(Decline("row gone"))?,
        allow,
    ))
}

/// `POST /api/v3/rbac/initial_permissions/`.
pub async fn create(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
    _query: &QueryDict,
) -> Result<Answer, Decline> {
    let tenant = drf::tenant(ctx, req).await?;
    let user = match drf::authenticate(ctx, req, ALLOW_LIST).await? {
        Ok(user) => user,
        Err(answer) => return Ok(answer),
    };
    let allowed = ak_rbac::has_permission(ctx.pool, user.subject(), "POST", &MODEL, false, false)
        .await
        .map_err(|_| Decline("permission raised"))?;
    if !allowed || !user.is_authenticated() {
        return Ok(drf::permission_denied(&user, ALLOW_LIST));
    }
    let data = json_body(req)?;
    let valid = match validate(ctx, &data, false, None, ALLOW_LIST).await? {
        Ok(valid) => valid,
        Err(answer) => return Ok(answer),
    };
    let (Some(name), Some(role)) = (valid.name, valid.role) else {
        return Err(Decline("required field missing"));
    };
    let created: Vec<(&str, &str)> = std::iter::once(("authentik_rbac", "initialpermissions"))
        .chain(SIDE_EFFECT_MODELS.iter().copied())
        .collect();
    if initial_permissions_apply(ctx, &user, &created).await? {
        return Err(Decline("initial permissions apply"));
    }
    let (ip, user_agent) = client(req)?;
    let audit = Audit::new(ctx, req, &tenant, &user, &user_agent, &ip).await?;
    let mut tx = ctx.pool.begin().await.map_err(db)?;
    let id: i32 = sqlx::query_scalar(
        "INSERT INTO authentik_rbac_initialpermissions (name, role_id) VALUES ($1, $2) \
         RETURNING id",
    )
    .bind(&name)
    .bind(role)
    .fetch_one(&mut *tx)
    .await
    .map_err(db)?;
    audit
        .event(&mut tx, "model_created", model(id, &name), ctx.now)
        .await?;
    if let Some(ids) = &valid.permissions {
        set_permissions(&mut tx, id, ids).await?;
    }
    tx.commit().await.map_err(db)?;
    respond(ctx, id, 201, ALLOW_LIST).await
}

/// `get_object()`: the row, or its 404/403.
async fn get_object(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
    query: &QueryDict,
    user: &User,
    pk: &str,
) -> Result<Result<PgRow, Answer>, Decline> {
    let mut qs = match filter_queryset(ctx, query, user, ALLOW_DETAIL).await? {
        Ok(qs) => qs,
        Err(answer) => return Ok(Err(answer)),
    };
    let not_found = "No InitialPermissions matches the given query.";
    let id = match py_int(pk).map_err(|_| Decline("pk digits"))? {
        None => return Ok(Err(drf::detail(404, "Not found.", ALLOW_DETAIL))),
        Some(value) => int4(value),
    };
    let Some(id) = id else {
        return Ok(Err(drf::detail(404, not_found, ALLOW_DETAIL)));
    };
    let p = qs.bind(Bind::Int(id));
    qs.filter(format!("t.\"id\" = {p}"));
    let mut rows = qs.fetch(ctx.pool, COLUMNS, &[], None).await?;
    if rows.is_empty() {
        return Ok(Err(drf::detail(404, not_found, ALLOW_DETAIL)));
    }
    let pk_text = id.to_string();
    let access = ak_rbac::has_object_permission(
        ctx.pool,
        user.subject(),
        req.method,
        &ak_rbac::Object {
            model: MODEL,
            pk: &pk_text,
        },
        false,
    )
    .await
    .map_err(|_| Decline("object permission raised"))?;
    Ok(match access {
        ak_rbac::Access::Allow => Ok(rows.remove(0)),
        ak_rbac::Access::NotFound => Err(drf::detail(404, "Not found.", ALLOW_DETAIL)),
        ak_rbac::Access::Deny => Err(drf::permission_denied(user, ALLOW_DETAIL)),
    })
}

/// `PUT`/`PATCH /api/v3/rbac/initial_permissions/{pk}/`.
pub async fn update(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
    query: &QueryDict,
    pk: &str,
) -> Result<Answer, Decline> {
    let tenant = drf::tenant(ctx, req).await?;
    let user = match drf::authenticate(ctx, req, ALLOW_DETAIL).await? {
        Ok(user) => user,
        Err(answer) => return Ok(answer),
    };
    let row = match get_object(ctx, req, query, &user, pk).await? {
        Ok(row) => row,
        Err(answer) => return Ok(answer),
    };
    let id: i32 = row.try_get(0).map_err(db)?;
    let data = json_body(req)?;
    let valid = match validate(ctx, &data, req.method == "PATCH", Some(id), ALLOW_DETAIL).await? {
        Ok(valid) => valid,
        Err(answer) => return Ok(answer),
    };
    let name = match valid.name {
        Some(name) => name,
        None => row.try_get(1).map_err(db)?,
    };
    let role: uuid::Uuid = match valid.role {
        Some(role) => role,
        None => row.try_get(2).map_err(db)?,
    };
    if initial_permissions_apply(ctx, &user, SIDE_EFFECT_MODELS).await? {
        return Err(Decline("initial permissions apply"));
    }
    let (ip, user_agent) = client(req)?;
    let audit = Audit::new(ctx, req, &tenant, &user, &user_agent, &ip).await?;
    let mut tx = ctx.pool.begin().await.map_err(db)?;
    let updated = sqlx::query(
        "UPDATE authentik_rbac_initialpermissions SET name = $1, role_id = $2 WHERE id = $3",
    )
    .bind(&name)
    .bind(role)
    .bind(id)
    .execute(&mut *tx)
    .await
    .map_err(db)?;
    // Deleted meanwhile: `save()` would insert it again.
    if updated.rows_affected() != 1 {
        return Err(Decline("row gone"));
    }
    audit
        .event(&mut tx, "model_updated", model(id, &name), ctx.now)
        .await?;
    if let Some(ids) = &valid.permissions {
        set_permissions(&mut tx, id, ids).await?;
    }
    tx.commit().await.map_err(db)?;
    respond(ctx, id, 200, ALLOW_DETAIL).await
}

/// `DELETE /api/v3/rbac/initial_permissions/{pk}/`: the event, then the
/// m2m rows (auto-created, no signal), then the row.
pub async fn destroy(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
    query: &QueryDict,
    pk: &str,
) -> Result<Answer, Decline> {
    let tenant = drf::tenant(ctx, req).await?;
    let user = match drf::authenticate(ctx, req, ALLOW_DETAIL).await? {
        Ok(user) => user,
        Err(answer) => return Ok(answer),
    };
    let row = match get_object(ctx, req, query, &user, pk).await? {
        Ok(row) => row,
        Err(answer) => return Ok(answer),
    };
    let id: i32 = row.try_get(0).map_err(db)?;
    let name: String = row.try_get(1).map_err(db)?;
    if initial_permissions_apply(ctx, &user, SIDE_EFFECT_MODELS).await? {
        return Err(Decline("initial permissions apply"));
    }
    let (ip, user_agent) = client(req)?;
    let audit = Audit::new(ctx, req, &tenant, &user, &user_agent, &ip).await?;
    let mut tx = ctx.pool.begin().await.map_err(db)?;
    let through: Vec<i32> = sqlx::query_scalar(
        "SELECT id FROM authentik_rbac_initialpermissions_permissions WHERE \
         initialpermissions_id = ANY($1)",
    )
    .bind([id])
    .fetch_all(&mut *tx)
    .await
    .map_err(db)?;
    audit
        .event(&mut tx, "model_deleted", model(id, &name), ctx.now)
        .await?;
    delete_ids(
        &mut tx,
        "authentik_rbac_initialpermissions_permissions",
        &through,
    )
    .await?;
    let deleted = sqlx::query("DELETE FROM authentik_rbac_initialpermissions WHERE id = ANY($1)")
        .bind([id])
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    if deleted.rows_affected() != 1 {
        return Err(Decline("row gone"));
    }
    tx.commit().await.map_err(db)?;
    Ok(no_content(ALLOW_DETAIL))
}
