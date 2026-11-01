//! `RoleViewSet`'s writes on [`crate::crud`]: `create`,
//! `update`/`partial_update`, `destroy`.
//!
//! `RoleSerializer` writes `name` (a `CharField` with a `UniqueValidator`).
//! A delete collects the role's relations as Django's `Collector` does: it
//! sends `pre_delete` in its sorted order (`RoleModelPermission` and
//! `InitialPermissions` events before the role's; auto-created m2m rows and
//! `RoleObjectPermission` get none), then deletes in `sort()` order.

use serde::Serialize;
use serde_json::json;
use sqlx::Row as _;
use uuid::Uuid;

use crate::{
    Answer, Decline,
    crud::{Collected, Field, Found, Kind, Name, Pk, Resource, Row, Spec},
    drf::{self, Context, User},
    py::{QueryDict, UuidLookup, uuid_lookup},
    sql::Bind,
    views::rbac_roles::{ALLOW_DETAIL, ALLOW_LIST, MODEL, filter_queryset},
    write::{CharField, model_dict},
};

pub(crate) struct Roles;

#[derive(Serialize)]
struct RoleData<'a> {
    pk: &'a str,
    name: &'a str,
}

fn db(_: sqlx::Error) -> Decline {
    Decline("database error")
}

/// The `table` rows pointing at the role, in Django's query order.
async fn related(
    ctx: &Context<'_>,
    table: &str,
    columns: &str,
    role: Uuid,
) -> Result<Vec<sqlx::postgres::PgRow>, Decline> {
    sqlx::query(sqlx::AssertSqlSafe(format!(
        "SELECT {columns} FROM \"{table}\" WHERE \"{table}\".\"role_id\" IN ($1)"
    )))
    .bind(role)
    .fetch_all(ctx.pool)
    .await
    .map_err(db)
}

fn ids(rows: &[sqlx::postgres::PgRow]) -> Result<Vec<i32>, Decline> {
    rows.iter()
        .map(|r| r.try_get::<i32, _>(0).map_err(db))
        .collect()
}

impl Resource for Roles {
    const SPEC: Spec = Spec {
        model: MODEL,
        pk: Pk::Uuid4,
        fields: &[Field {
            name: "name",
            column: "name",
            kind: Kind::Char(CharField::new(true)),
            required: true,
            unique: Some("Role with this name already exists."),
        }],
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
        let uuid = match uuid_lookup(pk).map_err(|_| Decline("pk syntax"))? {
            UuidLookup::Valid(uuid) => uuid,
            UuidLookup::Invalid => return Ok(Err(drf::detail(404, "Not found.", ALLOW_DETAIL))),
        };
        let p = qs.bind(Bind::Uuid(uuid));
        qs.filter(format!("t.\"uuid\" = {p}"));
        let rows = qs.fetch(ctx.pool, "t.\"uuid\"", &[], None).await?;
        if rows.is_empty() {
            return Ok(Err(drf::detail(
                404,
                "No Role matches the given query.",
                ALLOW_DETAIL,
            )));
        }
        Ok(Ok(Found {
            pk: uuid.to_string(),
            owner: false,
        }))
    }

    async fn render(
        _ctx: &Context<'_>,
        row: &Row,
        status: u16,
        allow: &'static str,
    ) -> Result<Answer, Decline> {
        let text = |column: &str| {
            row.get(column)
                .and_then(serde_json::Value::as_str)
                .ok_or(Decline("row"))
        };
        Ok(drf::json(
            status,
            &RoleData {
                pk: text("uuid")?,
                name: text("name")?,
            },
            allow,
        ))
    }

    /// `Collector.collect`, then `sort()`: models nothing depends on first,
    /// in collection order; `InitialPermissions` after its m2m rows.
    async fn collect(ctx: &Context<'_>, row: &Row) -> Result<Collected, Decline> {
        let role: Uuid = row
            .get("uuid")
            .and_then(serde_json::Value::as_str)
            .and_then(|s| Uuid::parse_str(s).ok())
            .ok_or(Decline("row"))?;
        let group_roles = ids(&related(
            ctx,
            "authentik_core_group_roles",
            "\"authentik_core_group_roles\".\"id\"",
            role,
        )
        .await?)?;
        let user_roles = ids(&related(
            ctx,
            "authentik_core_user_roles",
            "\"authentik_core_user_roles\".\"id\"",
            role,
        )
        .await?)?;
        let initial_rows = related(
            ctx,
            "authentik_rbac_initialpermissions",
            "\"authentik_rbac_initialpermissions\".\"id\", \
             \"authentik_rbac_initialpermissions\".\"name\", \
             \"authentik_rbac_initialpermissions\".\"role_id\"",
            role,
        )
        .await?;
        let mut initial = Vec::with_capacity(initial_rows.len());
        for row in &initial_rows {
            let id: i32 = row.try_get(0).map_err(db)?;
            let name: String = row.try_get(1).map_err(db)?;
            initial.push((id, name));
        }
        let initial_ids: Vec<i32> = initial.iter().map(|(id, _)| *id).collect();
        // `InitialPermissions.permissions`' rows, collected with them.
        let initial_perms = if initial_ids.is_empty() {
            Vec::new()
        } else {
            ids(&sqlx::query(
                "SELECT \"authentik_rbac_initialpermissions_permissions\".\"id\" FROM \
                 \"authentik_rbac_initialpermissions_permissions\" WHERE \
                 \"authentik_rbac_initialpermissions_permissions\".\"initialpermissions_id\" = \
                 ANY($1)",
            )
            .bind(&initial_ids)
            .fetch_all(ctx.pool)
            .await
            .map_err(db)?)?
        };
        let object_perms = ids(&related(
            ctx,
            "guardian_roleobjectpermission",
            "\"guardian_roleobjectpermission\".\"id\"",
            role,
        )
        .await?)?;
        let model_perm_rows = related(
            ctx,
            "guardian_rolemodelpermission",
            "\"guardian_rolemodelpermission\".\"id\", \
             \"guardian_rolemodelpermission\".\"content_type_id\", \
             \"guardian_rolemodelpermission\".\"permission_id\", \
             \"guardian_rolemodelpermission\".\"role_id\"",
            role,
        )
        .await?;
        let mut events = Vec::new();
        let mut model_perms = Vec::with_capacity(model_perm_rows.len());
        for row in &model_perm_rows {
            let id: i32 = row.try_get(0).map_err(db)?;
            let permission: i32 = row.try_get(2).map_err(db)?;
            model_perms.push(id);
            let name = format!("RoleModelPermission with role {role} and permission {permission}");
            events.push(model_dict(
                "guardian",
                "rolemodelpermission",
                &json!(id),
                &name,
            ));
        }
        for (id, name) in &initial {
            events.push(model_dict(
                "authentik_rbac",
                "initialpermissions",
                &json!(id),
                name,
            ));
        }
        Ok(Collected {
            events,
            deletes: vec![
                ("authentik_core_group_roles", group_roles),
                ("authentik_core_user_roles", user_roles),
                (
                    "authentik_rbac_initialpermissions_permissions",
                    initial_perms,
                ),
                ("guardian_roleobjectpermission", object_perms),
                ("guardian_rolemodelpermission", model_perms),
                ("authentik_rbac_initialpermissions", initial_ids),
            ],
        })
    }
}
