//! `RoleViewSet`'s writes: `create`, `update`/`partial_update`, `destroy`.
//!
//! DRF's order: authentication, `has_permission` (the model's `add_role`
//! for a create; detail routes pass and check the object instead),
//! `get_object` (the list's filters, the lookup, the object permission),
//! then `RoleSerializer` validation (`name`: `CharField` and a
//! `UniqueValidator`) and `save()`. The audit events follow
//! `AuditMiddleware`. A delete collects the role's relations as Django's
//! `Collector` does, sends `pre_delete` (an event for every instance that is
//! not an auto-created m2m row or an excluded model), then deletes in its
//! order.

use serde::Serialize;
use serde_json::json;
use sqlx::Row as _;
use uuid::Uuid;

use crate::{
    Answer, Decline,
    drf::{self, ApiRequest, Context, User},
    py::{QueryDict, UuidLookup, uuid_lookup},
    sql::Bind,
    views::rbac_roles::{ALLOW_DETAIL, ALLOW_LIST, MODEL, filter_queryset},
    write::{
        Audit, CharField, SIDE_EFFECT_MODELS, client, field_errors, initial_permissions_apply,
        json_body, model_dict, no_content,
    },
};

const UNIQUE: &str = "Role with this name already exists.";

#[derive(Serialize)]
struct RoleData<'a> {
    pk: String,
    name: &'a str,
}

fn db(_: sqlx::Error) -> Decline {
    Decline("database error")
}

/// The role `get_object()` finds, with its `managed` value (`save()`
/// writes every field).
struct Found {
    uuid: Uuid,
    name: String,
    managed: Option<String>,
}

/// `get_object()`: `Ok(Err(answer))` for its 404/403.
async fn get_object(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
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
    let rows = qs
        .fetch(ctx.pool, "t.\"uuid\", t.\"name\", t.\"managed\"", &[], None)
        .await?;
    let Some(row) = rows.first() else {
        return Ok(Err(drf::detail(
            404,
            "No Role matches the given query.",
            ALLOW_DETAIL,
        )));
    };
    let found = Found {
        uuid: row.try_get(0).map_err(db)?,
        name: row.try_get(1).map_err(db)?,
        managed: row.try_get(2).map_err(db)?,
    };
    let pk_text = found.uuid.to_string();
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
        ak_rbac::Access::Allow => Ok(found),
        ak_rbac::Access::NotFound => Err(drf::detail(404, "Not found.", ALLOW_DETAIL)),
        ak_rbac::Access::Deny => Err(drf::permission_denied(user, ALLOW_DETAIL)),
    })
}

/// `UniqueValidator(queryset=Role.objects.all())`, excluding the instance.
async fn name_taken(ctx: &Context<'_>, name: &str, except: Option<Uuid>) -> Result<bool, Decline> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM authentik_rbac_role WHERE name = $1 AND uuid IS DISTINCT FROM $2)",
    )
    .bind(name)
    .bind(except)
    .fetch_one(ctx.pool)
    .await
    .map_err(db)
}

/// The validated `name`, or the 400 / decline.
async fn validate_name(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
    required: bool,
    except: Option<Uuid>,
    allow: &'static str,
) -> Result<Result<Option<String>, Answer>, Decline> {
    let data = json_body(req)?;
    let name = match CharField::new(required).validate(&data, "name") {
        Ok(name) => name.value(),
        Err(Ok(message)) => return Ok(Err(field_errors(&[("name", message)], allow))),
        Err(Err(decline)) => return Err(decline),
    };
    if let Some(name) = &name
        && name_taken(ctx, name, except).await?
    {
        return Ok(Err(field_errors(&[("name", UNIQUE.to_owned())], allow)));
    }
    Ok(Ok(name))
}

fn role_model(uuid: Uuid, name: &str) -> serde_json::Value {
    model_dict(
        "authentik_rbac",
        "role",
        &json!(uuid.simple().to_string()),
        name,
    )
}

/// `POST /api/v3/rbac/roles/`.
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
    let name = match validate_name(ctx, req, true, None, ALLOW_LIST).await? {
        Ok(Some(name)) => name,
        Ok(None) => return Err(Decline("required name missing")),
        Err(answer) => return Ok(answer),
    };
    let created: Vec<(&str, &str)> = std::iter::once(("authentik_rbac", "role"))
        .chain(SIDE_EFFECT_MODELS.iter().copied())
        .collect();
    if initial_permissions_apply(ctx, &user, &created).await? {
        return Err(Decline("initial permissions apply"));
    }
    let (ip, user_agent) = client(req)?;
    let audit = Audit::new(ctx, req, &tenant, &user, &user_agent, &ip).await?;
    let uuid = Uuid::new_v4();
    let mut tx = ctx.pool.begin().await.map_err(db)?;
    sqlx::query("INSERT INTO authentik_rbac_role (uuid, name, managed) VALUES ($1, $2, NULL)")
        .bind(uuid)
        .bind(&name)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    audit
        .event(&mut tx, "model_created", role_model(uuid, &name), ctx.now)
        .await?;
    tx.commit().await.map_err(db)?;
    Ok(drf::json(
        201,
        &RoleData {
            pk: uuid.to_string(),
            name: &name,
        },
        ALLOW_LIST,
    ))
}

/// `PUT`/`PATCH /api/v3/rbac/roles/{pk}/`.
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
    let found = match get_object(ctx, req, query, &user, pk).await? {
        Ok(found) => found,
        Err(answer) => return Ok(answer),
    };
    let partial = req.method == "PATCH";
    let name = match validate_name(ctx, req, !partial, Some(found.uuid), ALLOW_DETAIL).await? {
        Ok(name) => name.unwrap_or(found.name),
        Err(answer) => return Ok(answer),
    };
    if initial_permissions_apply(ctx, &user, SIDE_EFFECT_MODELS).await? {
        return Err(Decline("initial permissions apply"));
    }
    let (ip, user_agent) = client(req)?;
    let audit = Audit::new(ctx, req, &tenant, &user, &user_agent, &ip).await?;
    let mut tx = ctx.pool.begin().await.map_err(db)?;
    // `Model.save()` on an existing row updates every field.
    let updated =
        sqlx::query("UPDATE authentik_rbac_role SET name = $1, managed = $2 WHERE uuid = $3")
            .bind(&name)
            .bind(&found.managed)
            .bind(found.uuid)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
    // Deleted meanwhile: `save()` would insert it again.
    if updated.rows_affected() != 1 {
        return Err(Decline("role gone"));
    }
    audit
        .event(
            &mut tx,
            "model_updated",
            role_model(found.uuid, &name),
            ctx.now,
        )
        .await?;
    tx.commit().await.map_err(db)?;
    Ok(drf::json(
        200,
        &RoleData {
            pk: found.uuid.to_string(),
            name: &name,
        },
        ALLOW_DETAIL,
    ))
}

/// The ids of `table` rows pointing at the role, in Django's query order.
async fn related_ids(
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

async fn delete_ids(
    conn: &mut sqlx::PgConnection,
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

/// `DELETE /api/v3/rbac/roles/{pk}/`.
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
    let found = match get_object(ctx, req, query, &user, pk).await? {
        Ok(found) => found,
        Err(answer) => return Ok(answer),
    };
    // `Collector.collect`, in Django's order.
    let id = |rows: &[sqlx::postgres::PgRow]| -> Result<Vec<i32>, Decline> {
        rows.iter()
            .map(|r| r.try_get::<i32, _>(0).map_err(db))
            .collect()
    };
    let group_roles = id(&related_ids(
        ctx,
        "authentik_core_group_roles",
        "\"authentik_core_group_roles\".\"id\"",
        found.uuid,
    )
    .await?)?;
    let user_roles = id(&related_ids(
        ctx,
        "authentik_core_user_roles",
        "\"authentik_core_user_roles\".\"id\"",
        found.uuid,
    )
    .await?)?;
    let initial_rows = related_ids(
        ctx,
        "authentik_rbac_initialpermissions",
        "\"authentik_rbac_initialpermissions\".\"id\", \"authentik_rbac_initialpermissions\".\"name\", \
         \"authentik_rbac_initialpermissions\".\"role_id\"",
        found.uuid,
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
        id(&sqlx::query(
            "SELECT \"authentik_rbac_initialpermissions_permissions\".\"id\" FROM \
             \"authentik_rbac_initialpermissions_permissions\" WHERE \
             \"authentik_rbac_initialpermissions_permissions\".\"initialpermissions_id\" = ANY($1)",
        )
        .bind(&initial_ids)
        .fetch_all(ctx.pool)
        .await
        .map_err(db)?)?
    };
    let object_perms = id(&related_ids(
        ctx,
        "guardian_roleobjectpermission",
        "\"guardian_roleobjectpermission\".\"id\"",
        found.uuid,
    )
    .await?)?;
    let model_perm_rows = related_ids(
        ctx,
        "guardian_rolemodelpermission",
        "\"guardian_rolemodelpermission\".\"id\", \"guardian_rolemodelpermission\".\"content_type_id\", \
         \"guardian_rolemodelpermission\".\"permission_id\", \"guardian_rolemodelpermission\".\"role_id\"",
        found.uuid,
    )
    .await?;
    let mut model_perms = Vec::with_capacity(model_perm_rows.len());
    for row in &model_perm_rows {
        let id: i32 = row.try_get(0).map_err(db)?;
        let permission: i32 = row.try_get(2).map_err(db)?;
        model_perms.push((id, permission));
    }
    if initial_permissions_apply(ctx, &user, SIDE_EFFECT_MODELS).await? {
        return Err(Decline("initial permissions apply"));
    }
    let (ip, user_agent) = client(req)?;
    let audit = Audit::new(ctx, req, &tenant, &user, &user_agent, &ip).await?;
    let mut tx = ctx.pool.begin().await.map_err(db)?;
    // `pre_delete`, in the sorted collector's order: auto-created m2m rows
    // get no event, `RoleObjectPermission` is not audited.
    for (id, permission) in &model_perms {
        let name = format!(
            "RoleModelPermission with role {} and permission {permission}",
            found.uuid
        );
        audit
            .event(
                &mut tx,
                "model_deleted",
                model_dict("guardian", "rolemodelpermission", &json!(id), &name),
                ctx.now,
            )
            .await?;
    }
    for (id, name) in &initial {
        audit
            .event(
                &mut tx,
                "model_deleted",
                model_dict("authentik_rbac", "initialpermissions", &json!(id), name),
                ctx.now,
            )
            .await?;
    }
    audit
        .event(
            &mut tx,
            "model_deleted",
            role_model(found.uuid, &found.name),
            ctx.now,
        )
        .await?;
    // `Collector.sort()`: models nothing else depends on first, in
    // collection order; then `InitialPermissions` (its m2m rows depend on
    // it), then the role.
    delete_ids(&mut tx, "authentik_core_group_roles", &group_roles).await?;
    delete_ids(&mut tx, "authentik_core_user_roles", &user_roles).await?;
    delete_ids(
        &mut tx,
        "authentik_rbac_initialpermissions_permissions",
        &initial_perms,
    )
    .await?;
    delete_ids(&mut tx, "guardian_roleobjectpermission", &object_perms).await?;
    let model_perm_ids: Vec<i32> = model_perms.iter().map(|(id, _)| *id).collect();
    delete_ids(&mut tx, "guardian_rolemodelpermission", &model_perm_ids).await?;
    delete_ids(&mut tx, "authentik_rbac_initialpermissions", &initial_ids).await?;
    let deleted = sqlx::query("DELETE FROM authentik_rbac_role WHERE uuid = $1")
        .bind(found.uuid)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
    if deleted.rows_affected() != 1 {
        return Err(Decline("role gone"));
    }
    tx.commit().await.map_err(db)?;
    Ok(no_content(ALLOW_DETAIL))
}
