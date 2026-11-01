//! `actor.send(*args)`: `PostgresBroker.enqueue` with authentik's broker
//! middlewares.
//!
//! The message is dramatiq's `Message.asdict()` through the default
//! `PickleEncoder`. Its options keep `model_create_defaults` with the
//! current tenant (`TenantMiddleware.before_enqueue`), because `encode()`
//! runs before the broker pops them. The `Task` row is what
//! `update_or_create` inserts: the triggers set `aggregated_status` and
//! `NOTIFY` the workers on commit. `TaskLogMiddleware.after_enqueue` adds
//! "Task has been queued".

use ak_auth::python::{PyValue, json_loads};
use ak_pickle::write::{Obj, dumps};
use chrono::{DateTime, Utc};
use sqlx::{PgConnection, Row as _};
use uuid::Uuid;

use crate::{DJANGO_VERSION, Error};

/// `json.loads` output as the Python objects pickle sees.
fn py_to_obj(value: &PyValue) -> Result<Obj, Error> {
    Ok(match value {
        PyValue::None => Obj::None,
        PyValue::Bool(b) => Obj::Bool(*b),
        PyValue::Int(digits) => {
            Obj::Int(digits.parse().map_err(|_| Error::Unsupported("big int"))?)
        }
        PyValue::Float(f) => Obj::Float(*f),
        PyValue::Str(s) => Obj::Str(
            s.to_string_lossless()
                .ok_or(Error::Unsupported("surrogate"))?,
        ),
        PyValue::List(items) => Obj::List(items.iter().map(py_to_obj).collect::<Result<_, _>>()?),
        PyValue::Dict(items) => Obj::Dict(
            items
                .iter()
                .map(|(k, v)| {
                    Ok((
                        Obj::Str(
                            k.to_string_lossless()
                                .ok_or(Error::Unsupported("surrogate"))?,
                        ),
                        py_to_obj(v)?,
                    ))
                })
                .collect::<Result<_, Error>>()?,
        ),
    })
}

fn jsonb(text: &str) -> Result<Obj, Error> {
    py_to_obj(&json_loads(text.as_bytes()).map_err(|_| Error::Unsupported("jsonb"))?)
}

/// The tenant as `get_current_tenant()` returns it: the row's fields in
/// the model's order.
pub(crate) async fn tenant_obj(conn: &mut PgConnection, tenant: Uuid) -> Result<Obj, Error> {
    let row = sqlx::query(
        "SELECT tenant_uuid, schema_name, name, ready, avatars, default_user_change_name, \
         default_user_change_email, default_user_change_username, event_retention, \
         reputation_lower_limit, reputation_upper_limit, footer_links::text, gdpr_compliance, \
         impersonation, impersonation_require_reason, default_token_duration, \
         default_token_length, pagination_default_page_size, pagination_max_page_size, \
         flags::text FROM authentik_tenants_tenant WHERE tenant_uuid = $1",
    )
    .bind(tenant)
    .fetch_one(&mut *conn)
    .await?;
    let text = |i: usize| -> Result<Obj, Error> { Ok(Obj::Str(row.try_get(i)?)) };
    let flag = |i: usize| -> Result<Obj, Error> { Ok(Obj::Bool(row.try_get(i)?)) };
    let int =
        |i: usize| -> Result<Obj, Error> { Ok(Obj::Int(i128::from(row.try_get::<i32, _>(i)?))) };
    let uuid: Uuid = row.try_get(0)?;
    Ok(Obj::model(
        "authentik_tenants",
        "Tenant",
        vec![
            ("tenant_uuid", Obj::uuid(uuid.as_u128())),
            ("schema_name", text(1)?),
            ("name", text(2)?),
            ("ready", flag(3)?),
            ("avatars", text(4)?),
            ("default_user_change_name", flag(5)?),
            ("default_user_change_email", flag(6)?),
            ("default_user_change_username", flag(7)?),
            ("event_retention", text(8)?),
            ("reputation_lower_limit", int(9)?),
            ("reputation_upper_limit", int(10)?),
            ("footer_links", jsonb(&row.try_get::<String, _>(11)?)?),
            ("gdpr_compliance", flag(12)?),
            ("impersonation", flag(13)?),
            ("impersonation_require_reason", flag(14)?),
            ("default_token_duration", text(15)?),
            ("default_token_length", int(16)?),
            ("pagination_default_page_size", int(17)?),
            ("pagination_max_page_size", int(18)?),
            ("flags", jsonb(&row.try_get::<String, _>(19)?)?),
        ],
        DJANGO_VERSION,
    ))
}

/// `Message.asdict()` before `encode()`.
fn message(
    actor_name: &str,
    args: Vec<Obj>,
    tenant: Obj,
    message_id: Uuid,
    now: DateTime<Utc>,
) -> Obj {
    let pair = |k: &str, v: Obj| (Obj::str(k), v);
    Obj::Dict(vec![
        // dramatiq's `queue_name="default"` constant, interned.
        pair("queue_name", Obj::interned("default")),
        pair("actor_name", Obj::str(actor_name)),
        pair("args", Obj::Tuple(args)),
        pair("kwargs", Obj::Dict(Vec::new())),
        pair(
            "options",
            Obj::Dict(vec![pair(
                "model_create_defaults",
                Obj::Dict(vec![pair("tenant", tenant)]),
            )]),
        ),
        pair("message_id", Obj::Str(message_id.to_string())),
        pair(
            "message_timestamp",
            Obj::Int(i128::from(now.timestamp_millis())),
        ),
    ])
}

/// `actor.send(*args)` on the `default` queue for `tenant`, inside the
/// caller's transaction; the new message id.
///
/// # Errors
///
/// A database error, or a tenant value this port does not pickle.
pub async fn enqueue(
    conn: &mut PgConnection,
    tenant: Uuid,
    actor_name: &str,
    args: Vec<Obj>,
    now: DateTime<Utc>,
) -> Result<Uuid, Error> {
    let tenant_obj = tenant_obj(conn, tenant).await?;
    let message_id = Uuid::new_v4();
    let body = dumps(&message(actor_name, args, tenant_obj, message_id, now));
    sqlx::query(
        "INSERT INTO authentik_tasks_task (message_id, queue_name, actor_name, message, state, \
         mtime, retries, eta, result, result_expiry, tenant_id, rel_obj_content_type_id, \
         rel_obj_id, _uid, _messages, _previous_messages, aggregated_status) VALUES ($1, \
         'default', $2, $3, 'queued', $4, 0, NULL, NULL, NULL, $5, NULL, NULL, NULL, '[]', '[]', '')",
    )
    .bind(message_id)
    .bind(actor_name)
    .bind(&body)
    .bind(now)
    .bind(tenant)
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "INSERT INTO authentik_tasks_tasklog (id, task_id, event, log_level, logger, timestamp, \
         attributes, previous) VALUES ($1, $2, 'Task has been queued', 'info', \
         'authentik.tasks.middleware.TaskLogMiddleware', $3, '{\"delay\": null}', false)",
    )
    .bind(Uuid::new_v4())
    .bind(message_id)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    Ok(message_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_becomes_python_objects() {
        assert_eq!(
            jsonb(r#"[{"name": "x", "href": "y", "n": 1, "f": 1.5, "z": null}]"#).expect("json"),
            Obj::List(vec![Obj::Dict(vec![
                (Obj::str("name"), Obj::str("x")),
                (Obj::str("href"), Obj::str("y")),
                (Obj::str("n"), Obj::Int(1)),
                (Obj::str("f"), Obj::Float(1.5_f64)),
                (Obj::str("z"), Obj::None),
            ])])
        );
    }
}
