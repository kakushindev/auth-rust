//! `InitialPermissionsViewSet`'s writes on [`crate::crud`]: `create`,
//! `update`/`partial_update`, `destroy`.
//!
//! `InitialPermissionsSerializer` writes, in field order:
//! - `name`: `CharField(max_length=150)`, whose `UniqueValidator` runs
//!   before the length check;
//! - `role`: a `PrimaryKeyRelatedField` on every role;
//! - `permissions`: a `ManyRelatedField` of `Permission` pks, not required,
//!   saved by `permissions.set()` in `CPython`'s set order.
//!
//! A delete takes the m2m rows with it (auto-created, no signal).

use sqlx::Row as _;

use crate::{
    Answer, Decline,
    crud::{Collected, Field, Found, Kind, Name, Pk, Resource, Row, Spec, Through},
    drf::{self, Context, User},
    py::{QueryDict, int4, py_int},
    sql::Bind,
    views::rbac_initial_permissions::{
        ALLOW_DETAIL, ALLOW_LIST, COLUMNS, MODEL, filter_queryset, serialize,
    },
    write::CharField,
};

pub(crate) struct InitialPermissions;

fn db(_: sqlx::Error) -> Decline {
    Decline("database error")
}

const THROUGH: &str = "authentik_rbac_initialpermissions_permissions";

impl Resource for InitialPermissions {
    const SPEC: Spec = Spec {
        model: MODEL,
        pk: Pk::Serial,
        fields: &[
            Field {
                name: "name",
                column: "name",
                kind: Kind::Char(CharField {
                    max_length: Some(150),
                    ..CharField::new(true)
                }),
                required: true,
                unique: Some("Initial Permissions with this name already exists."),
            },
            Field {
                name: "role",
                column: "role_id",
                kind: Kind::ForeignUuid {
                    table: "authentik_rbac_role",
                    column: "uuid",
                },
                required: true,
                unique: None,
            },
            Field {
                name: "permissions",
                column: "",
                kind: Kind::ManyInt {
                    table: "auth_permission",
                    column: "id",
                    through: Through {
                        table: THROUGH,
                        source: "initialpermissions_id",
                        target: "permission_id",
                    },
                },
                required: false,
                unique: None,
            },
        ],
        audit: Some(Name::Column("name")),
        decline_keys: &[],
    };
    const ALLOW_LIST: &'static str = ALLOW_LIST;
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
        if qs.fetch(ctx.pool, COLUMNS, &[], None).await?.is_empty() {
            return Ok(Err(drf::detail(404, not_found, ALLOW_DETAIL)));
        }
        Ok(Ok(Found {
            pk: id.to_string(),
            owner: false,
        }))
    }

    async fn render(
        ctx: &Context<'_>,
        row: &Row,
        status: u16,
        allow: &'static str,
    ) -> Result<Answer, Decline> {
        let id = row
            .get("id")
            .and_then(serde_json::Value::as_i64)
            .and_then(|id| i32::try_from(id).ok())
            .ok_or(Decline("row"))?;
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

    async fn collect(ctx: &Context<'_>, row: &Row) -> Result<Collected, Decline> {
        let id = row
            .get("id")
            .and_then(serde_json::Value::as_i64)
            .and_then(|id| i32::try_from(id).ok())
            .ok_or(Decline("row"))?;
        let through = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT id FROM {THROUGH} WHERE initialpermissions_id = ANY($1)"
        )))
        .bind([id])
        .fetch_all(ctx.pool)
        .await
        .map_err(db)?
        .iter()
        .map(|r| r.try_get::<i32, _>(0).map_err(db))
        .collect::<Result<Vec<_>, _>>()?;
        Ok(Collected {
            events: Vec::new(),
            deletes: vec![(THROUGH, through)],
        })
    }
}
