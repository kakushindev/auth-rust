//! `NotificationViewSet`'s writes: `update`/`partial_update`, `destroy` and
//! `mark_all_seen`.
//!
//! `Notification` is one of `AuditMiddleware`'s ignored models, nothing
//! receives its signals, and these writes create no rows, so each write is
//! its statement alone. `NotificationSerializer` writes `hyperlink`
//! (`max_length=4096`) and `hyperlink_label`, both blank and null allowed,
//! and `seen`, none of them required. `event` is a nested serializer whose
//! write raises (declined).

use ak_rbac::{Access, Object};
use sqlx::{Row as _, postgres::PgRow};

use crate::{
    Answer, Decline,
    drf::{self, ApiRequest, Context, User},
    py::{QueryDict, UuidLookup, uuid_lookup},
    sql::Bind,
    views::events_notifications::{ALLOW_DETAIL, MODEL, SELECT, filter_queryset, serialize},
    write::{CharField, Input, boolean_field, field_errors, json_body, no_content},
};

const ALLOW_MARK_ALL_SEEN: &str = "POST, OPTIONS";

fn db(_: sqlx::Error) -> Decline {
    Decline("database error")
}

/// `get_object()`: the row (`SELECT`'s columns), or its 404/403.
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
    let uuid = match uuid_lookup(pk).map_err(|_| Decline("pk syntax"))? {
        UuidLookup::Valid(uuid) => uuid,
        UuidLookup::Invalid => return Ok(Err(drf::detail(404, "Not found.", ALLOW_DETAIL))),
    };
    let p = qs.bind(Bind::Uuid(uuid));
    qs.filter(format!("\"authentik_events_notification\".\"uuid\" = {p}"));
    let mut rows = qs.fetch(ctx.pool, &[], None).await?;
    let row = match rows.len() {
        0 => {
            return Ok(Err(drf::detail(
                404,
                "No Notification matches the given query.",
                ALLOW_DETAIL,
            )));
        }
        1 => rows.remove(0),
        _ => return Err(Decline("multiple objects")),
    };
    let owner: i32 = row.try_get(8).map_err(db)?;
    let pk_text = uuid.to_string();
    let access = ak_rbac::has_object_permission(
        ctx.pool,
        user.subject(),
        req.method,
        &Object {
            model: MODEL,
            pk: &pk_text,
        },
        owner == user.subject().user_id,
    )
    .await
    .map_err(|_| Decline("object permission raised"))?;
    Ok(match access {
        Access::Allow => Ok(row),
        Access::NotFound => Err(drf::detail(404, "Not found.", ALLOW_DETAIL)),
        Access::Deny => Err(drf::permission_denied(user, ALLOW_DETAIL)),
    })
}

const NULLABLE: CharField = CharField {
    required: false,
    allow_blank: true,
    allow_null: true,
    max_length: None,
};

/// `PUT`/`PATCH /api/v3/events/notifications/{pk}/`.
pub async fn update(
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
    let row = match get_object(ctx, req, query, &user, pk).await? {
        Ok(row) => row,
        Err(answer) => return Ok(answer),
    };
    let data = json_body(req)?;
    if data.get("event").is_some() {
        return Err(Decline("nested event write"));
    }
    // Fields in declaration order; every error is reported.
    let mut errors = Vec::new();
    let mut text = |name: &'static str, field: &CharField| match field.validate(&data, name) {
        Ok(input) => Ok(Some(input)),
        Err(Ok(message)) => {
            errors.push((name, message));
            Ok(None)
        }
        Err(Err(decline)) => Err(decline),
    };
    let hyperlink = text(
        "hyperlink",
        &CharField {
            max_length: Some(4096),
            ..NULLABLE
        },
    )?;
    let hyperlink_label = text("hyperlink_label", &NULLABLE)?;
    let seen = match boolean_field(&data, "seen", false) {
        Ok(input) => Some(input),
        Err(Ok(message)) => {
            errors.push(("seen", message));
            None
        }
        Err(Err(decline)) => return Err(decline),
    };
    let (Some(hyperlink), Some(hyperlink_label), Some(seen)) = (hyperlink, hyperlink_label, seen)
    else {
        return Ok(field_errors(&errors, ALLOW_DETAIL));
    };
    let current =
        |index: usize| -> Result<Option<String>, Decline> { row.try_get(index).map_err(db) };
    let merge = |input: Input<String>, index: usize| -> Result<Option<String>, Decline> {
        Ok(match input {
            Input::Absent => current(index)?,
            Input::Null => None,
            Input::Value(value) => Some(value),
        })
    };
    let hyperlink = merge(hyperlink, 3)?;
    let hyperlink_label = merge(hyperlink_label, 4)?;
    let seen = match seen {
        Input::Value(seen) => seen,
        Input::Absent | Input::Null => row.try_get(7).map_err(db)?,
    };
    // `Model.save()` writes every field, with the values it read.
    let uuid: uuid::Uuid = row.try_get(0).map_err(db)?;
    let updated = sqlx::query(sqlx::AssertSqlSafe(format!(
        "UPDATE \"authentik_events_notification\" SET \"severity\" = $1, \"body\" = $2, \
         \"hyperlink\" = $3, \"hyperlink_label\" = $4, \"created\" = $5, \"event_id\" = $6, \
         \"seen\" = $7, \"user_id\" = $8 WHERE \"authentik_events_notification\".\"uuid\" = $9 \
         RETURNING {SELECT}"
    )))
    .bind(row.try_get::<String, _>(1).map_err(db)?)
    .bind(row.try_get::<String, _>(2).map_err(db)?)
    .bind(&hyperlink)
    .bind(&hyperlink_label)
    .bind(
        row.try_get::<chrono::DateTime<chrono::Utc>, _>(5)
            .map_err(db)?,
    )
    .bind(row.try_get::<Option<uuid::Uuid>, _>(6).map_err(db)?)
    .bind(seen)
    .bind(row.try_get::<i32, _>(8).map_err(db)?)
    .bind(uuid)
    .fetch_all(ctx.pool)
    .await
    .map_err(db)?;
    // Deleted meanwhile: `save()` would insert it again.
    if updated.len() != 1 {
        return Err(Decline("notification gone"));
    }
    let mut one = serialize(ctx, &updated).await?;
    Ok(drf::json(
        200,
        &one.pop().ok_or(Decline("database error"))?,
        ALLOW_DETAIL,
    ))
}

/// `DELETE /api/v3/events/notifications/{pk}/`. Nothing references a
/// notification, so the collector deletes it alone.
pub async fn destroy(
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
    let row = match get_object(ctx, req, query, &user, pk).await? {
        Ok(row) => row,
        Err(answer) => return Ok(answer),
    };
    let uuid: uuid::Uuid = row.try_get(0).map_err(db)?;
    let deleted = sqlx::query(
        "DELETE FROM \"authentik_events_notification\" WHERE \
         \"authentik_events_notification\".\"uuid\" IN ($1)",
    )
    .bind(uuid)
    .execute(ctx.pool)
    .await
    .map_err(db)?;
    if deleted.rows_affected() != 1 {
        return Err(Decline("notification gone"));
    }
    Ok(no_content(ALLOW_DETAIL))
}

/// `POST /api/v3/events/notifications/mark_all_seen/`: `IsAuthenticated`
/// only, the body unread; `Response({}, status=204)` keeps its
/// `Content-Type` but no body reaches the client.
pub async fn mark_all_seen(ctx: &Context<'_>, req: &ApiRequest<'_>) -> Result<Answer, Decline> {
    drf::tenant(ctx, req).await?;
    let user = match drf::authenticate(ctx, req, ALLOW_MARK_ALL_SEEN).await? {
        Ok(user) => user,
        Err(answer) => return Ok(answer),
    };
    if !user.is_authenticated() {
        return Ok(drf::permission_denied(&user, ALLOW_MARK_ALL_SEEN));
    }
    sqlx::query(
        "UPDATE \"authentik_events_notification\" SET \"seen\" = true WHERE \
         (NOT \"authentik_events_notification\".\"seen\" AND \
         \"authentik_events_notification\".\"user_id\" = $1)",
    )
    .bind(user.subject().user_id)
    .execute(ctx.pool)
    .await
    .map_err(db)?;
    let mut answer = drf::json(204, &(), ALLOW_MARK_ALL_SEEN);
    answer.body.clear();
    Ok(answer)
}
