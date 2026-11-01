//! `NotificationViewSet`'s writes on [`crate::crud`]:
//! `update`/`partial_update` and `destroy`, plus the `mark_all_seen` action.
//!
//! `Notification` is one of `AuditMiddleware`'s ignored models, nothing
//! receives its signals or references it, and these writes create no rows,
//! so each write is its statement alone. `NotificationSerializer` writes
//! `hyperlink` (`max_length=4096`) and `hyperlink_label`, both blank and
//! null allowed, and `seen`, none of them required. `event` is a nested
//! serializer whose write raises (declined).

use sqlx::Row as _;

use crate::{
    Answer, Decline,
    crud::{Collected, Field, Found, Kind, Pk, Resource, Row, Spec},
    drf::{self, ApiRequest, Context, User},
    py::{QueryDict, UuidLookup, uuid_lookup},
    sql::Bind,
    views::events_notifications::{ALLOW_DETAIL, MODEL, SELECT, filter_queryset, serialize},
    write::CharField,
};

pub(crate) struct Notifications;

const ALLOW_MARK_ALL_SEEN: &str = "POST, OPTIONS";

fn db(_: sqlx::Error) -> Decline {
    Decline("database error")
}

const NULLABLE: CharField = CharField {
    required: false,
    allow_blank: true,
    allow_null: true,
    max_length: None,
};

impl Resource for Notifications {
    const SPEC: Spec = Spec {
        model: MODEL,
        pk: Pk::Uuid4,
        fields: &[
            Field {
                name: "hyperlink",
                column: "hyperlink",
                kind: Kind::Char(CharField {
                    max_length: Some(4096),
                    ..NULLABLE
                }),
                required: false,
                unique: None,
            },
            Field {
                name: "hyperlink_label",
                column: "hyperlink_label",
                kind: Kind::Char(NULLABLE),
                required: false,
                unique: None,
            },
            Field {
                name: "seen",
                column: "seen",
                kind: Kind::Bool,
                required: false,
                unique: None,
            },
        ],
        audit: None,
        decline_keys: &["event"],
    };
    // No create route.
    const ALLOW_LIST: &'static str = "GET, HEAD, OPTIONS";
    const ALLOW_DETAIL: &'static str = ALLOW_DETAIL;

    async fn find(
        ctx: &Context<'_>,
        query: &QueryDict,
        user: &User,
        pk: &str,
    ) -> Result<Result<Found, Answer>, Decline> {
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
        let rows = qs.fetch(ctx.pool, &[], None).await?;
        let row = match rows.as_slice() {
            [] => {
                return Ok(Err(drf::detail(
                    404,
                    "No Notification matches the given query.",
                    ALLOW_DETAIL,
                )));
            }
            [row] => row,
            _ => return Err(Decline("multiple objects")),
        };
        let owner: i32 = row.try_get(8).map_err(db)?;
        Ok(Ok(Found {
            pk: uuid.to_string(),
            owner: owner == user.subject().user_id,
        }))
    }

    /// `NotificationSerializer(instance).data`, nested event included.
    async fn render(
        ctx: &Context<'_>,
        row: &Row,
        status: u16,
        allow: &'static str,
    ) -> Result<Answer, Decline> {
        let uuid = row
            .get("uuid")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| uuid::Uuid::parse_str(s).ok())
            .ok_or(Decline("row"))?;
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {SELECT} FROM \"authentik_events_notification\" WHERE \
             \"authentik_events_notification\".\"uuid\" = $1"
        )))
        .bind(uuid)
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

    /// Nothing references a notification.
    async fn collect(_ctx: &Context<'_>, _row: &Row) -> Result<Collected, Decline> {
        Ok(Collected::default())
    }
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
