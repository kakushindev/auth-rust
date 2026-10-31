//! `authentik.core.api.users.UserViewSet`: `list` and `retrieve`.
//!
//! Default backends (`QLSearch` → `SearchFilter`, `ObjectFilter`,
//! `UsersFilter`, `OrderingFilter`). The list carries the QL
//! `autocomplete` of `get_ql_fields` (owner decision R2). `UserSerializer`
//! reads `groups`/`roles` through the prefetches `get_queryset` sets up
//! (per-user queries when `include_groups`/`include_roles` are off), and
//! `avatar` through [`crate::avatar`].

use ak_rbac::{Access, Model, Object, PkCast};
use serde::Serialize;
use serde_json::value::RawValue;
use sha2::{Digest as _, Sha256};
use sqlx::{Row as _, postgres::PgRow};
use uuid::Uuid;

use crate::{
    Answer, Decline,
    avatar::{self, AvatarUser},
    cache,
    drf::{self, ApiRequest, Context, User},
    filters::{self, Field, Kind, null_boolean},
    json::render_jsonb,
    pagination::{Page, page_size},
    py::{QueryDict, int4, py_int},
    sql::{Bind, DjangoQuery},
    views::common::{django_object_filter, django_search, ordering, search_terms},
};

const ALLOW_LIST: &str = "GET, POST, HEAD, OPTIONS";
const ALLOW_DETAIL: &str = "GET, PUT, PATCH, DELETE, HEAD, OPTIONS";

/// `detail=False` actions, routed before the detail route.
pub const ACTIONS: &[&str] = &[
    "export",
    "service_account",
    "me",
    "impersonate_end",
    "paths",
];

const MODEL: Model<'static> = Model {
    app_label: "authentik_core",
    model_name: "user",
    ctype_app_label: "authentik_core",
    ctype_model: "user",
    pk_cast: PkCast::Bigint,
    db_table: "authentik_core_user",
    pk_column: "id",
};

macro_rules! col {
    ($c:literal) => {
        concat!("\"authentik_core_user\".\"", $c, "\"")
    };
}

const FROM: &str = "\"authentik_core_user\"";
/// Django's select list (`attributes` read as text for rendering).
const SELECT: &str = concat!(
    col!("id"),
    ", ",
    col!("password"),
    ", ",
    col!("last_login"),
    ", ",
    col!("username"),
    ", ",
    col!("first_name"),
    ", ",
    col!("last_name"),
    ", ",
    col!("email"),
    ", ",
    col!("is_active"),
    ", ",
    col!("date_joined"),
    ", ",
    col!("attributes"),
    "::text, ",
    col!("uuid"),
    ", ",
    col!("name"),
    ", ",
    col!("path"),
    ", ",
    col!("type"),
    ", ",
    col!("password_change_date"),
    ", ",
    col!("last_updated"),
);

/// `settings.ANONYMOUS_USER_NAME`.
const ANONYMOUS_USER_NAME: &str = "AnonymousUser";

/// `UserTypes` values.
const USER_TYPES: &[&str] = &[
    "internal",
    "external",
    "service_account",
    "internal_service_account",
];

const GROUPS_BY_NAME: &[&str] = &[
    "INNER JOIN \"authentik_core_user_groups\" ug_n ON (\"authentik_core_user\".\"id\" = ug_n.\"user_id\")",
    "INNER JOIN \"authentik_core_group\" g_n ON (ug_n.\"group_id\" = g_n.\"group_uuid\")",
];
const ROLES_BY_NAME: &[&str] = &[
    "INNER JOIN \"authentik_core_user_roles\" ur_n ON (\"authentik_core_user\".\"id\" = ur_n.\"user_id\")",
    "INNER JOIN \"authentik_rbac_role\" r_n ON (ur_n.\"role_id\" = r_n.\"uuid\")",
];
const GROUP: (&str, &str) = ("authentik_core_group", "group_uuid");
const ROLE: (&str, &str) = ("authentik_rbac_role", "uuid");

/// `UsersFilter.base_filters`, in order (`is_superuser` is a method filter
/// applied by the view, after `is_active`).
const FILTERS_HEAD: &[Field] = &[
    Field {
        name: "username",
        kind: Kind::Char {
            column: col!("username"),
        },
    },
    Field {
        name: "email",
        kind: Kind::Char {
            column: col!("email"),
        },
    },
    Field {
        name: "date_joined",
        kind: Kind::Declined,
    },
    Field {
        name: "last_updated",
        kind: Kind::Declined,
    },
    Field {
        name: "last_login",
        kind: Kind::Declined,
    },
    Field {
        name: "name",
        kind: Kind::Char {
            column: col!("name"),
        },
    },
    Field {
        name: "is_active",
        kind: Kind::NullBoolean {
            column: col!("is_active"),
        },
    },
];
const FILTERS_TAIL: &[Field] = &[
    Field {
        name: "attributes",
        kind: Kind::Declined,
    },
    Field {
        name: "groups_by_name",
        kind: Kind::ManyToManyField {
            joins: GROUPS_BY_NAME,
            column: "g_n.\"name\"",
            target: ("authentik_core_group", "name"),
        },
    },
    Field {
        name: "groups_by_pk",
        kind: Kind::ManyToManyUuid {
            join: "INNER JOIN \"authentik_core_user_groups\" ug_p ON (\"authentik_core_user\".\"id\" = ug_p.\"user_id\")",
            through_column: "ug_p.\"group_id\"",
            target: GROUP,
        },
    },
    Field {
        name: "roles_by_name",
        kind: Kind::ManyToManyField {
            joins: ROLES_BY_NAME,
            column: "r_n.\"name\"",
            target: ("authentik_rbac_role", "name"),
        },
    },
    Field {
        name: "roles_by_pk",
        kind: Kind::ManyToManyUuid {
            join: "INNER JOIN \"authentik_core_user_roles\" ur_p ON (\"authentik_core_user\".\"id\" = ur_p.\"user_id\")",
            through_column: "ur_p.\"role_id\"",
            target: ROLE,
        },
    },
    Field {
        name: "type",
        kind: Kind::MultipleChoice {
            column: col!("type"),
            choices: USER_TYPES,
        },
    },
    Field {
        name: "date_joined__lt",
        kind: Kind::Declined,
    },
    Field {
        name: "date_joined__gt",
        kind: Kind::Declined,
    },
    Field {
        name: "last_updated__lt",
        kind: Kind::Declined,
    },
    Field {
        name: "last_updated__gt",
        kind: Kind::Declined,
    },
    Field {
        name: "last_login__lt",
        kind: Kind::Declined,
    },
    Field {
        name: "last_login__gt",
        kind: Kind::Declined,
    },
    Field {
        name: "last_login__isnull",
        kind: Kind::IsNull {
            column: col!("last_login"),
        },
    },
    Field {
        name: "uuid",
        kind: Kind::Uuid {
            column: col!("uuid"),
        },
    },
    Field {
        name: "path",
        kind: Kind::Char {
            column: col!("path"),
        },
    },
    Field {
        name: "path_startswith",
        kind: Kind::StartsWith {
            column: col!("path"),
        },
    },
];

const SEARCH: &[&str] = &[col!("email"), col!("name"), col!("uuid"), col!("username")];

/// Readable serializer sources that are model columns. `is_superuser` and
/// `uid` are properties (Django raises `FieldError`), `groups`/`roles`
/// duplicate rows: declined.
const ORDERING: &[(&str, &str)] = &[
    ("pk", col!("id")),
    ("username", col!("username")),
    ("name", col!("name")),
    ("is_active", col!("is_active")),
    ("last_login", col!("last_login")),
    ("date_joined", col!("date_joined")),
    ("email", col!("email")),
    ("attributes", col!("attributes")),
    ("path", col!("path")),
    ("type", col!("type")),
    ("uuid", col!("uuid")),
    ("password_change_date", col!("password_change_date")),
    ("last_updated", col!("last_updated")),
];
const ORDERING_DECLINED: &[&str] = &["is_superuser", "uid", "groups", "roles"];
const DEFAULT_ORDERING: &[&str] = &[
    concat!(col!("username"), " ASC"),
    concat!(col!("date_joined"), " ASC"),
    concat!(col!("last_updated"), " ASC"),
    concat!(col!("last_login"), " ASC"),
];

/// `AKQLSchemaSerializer().serialize(schema(User))` for `get_ql_fields`.
const AUTOCOMPLETE: &str = r#"{"current_model":"authentik_core.user","models":{"authentik_core.user":{"username":{"type":"str","nullable":false,"options":null},"name":{"type":"str","nullable":false,"options":null},"email":{"type":"str","nullable":false,"options":null},"path":{"type":"str","nullable":false,"options":null},"is_active":{"type":"bool","nullable":true,"options":null},"type":{"type":"str","nullable":false,"options":["internal","external","service_account","internal_service_account"]},"attributes":{"type":"relation","nullable":false,"options":null,"relation":"authentik_core.user_attributes"}}}}"#;

/// `PartialGroupSerializer`.
#[derive(Serialize)]
pub(crate) struct PartialGroup {
    pk: String,
    num_pk: u64,
    name: String,
    is_superuser: bool,
    attributes: Box<RawValue>,
}

/// `RoleSerializer`.
#[derive(Serialize)]
pub(crate) struct Role {
    pk: String,
    name: String,
}

/// `UserSerializer`.
#[derive(Serialize)]
pub(crate) struct UserData {
    pk: i32,
    username: String,
    name: String,
    is_active: bool,
    last_login: Option<String>,
    date_joined: String,
    is_superuser: bool,
    groups: Vec<String>,
    groups_obj: Option<Vec<PartialGroup>>,
    roles: Vec<String>,
    roles_obj: Option<Vec<Role>>,
    email: String,
    avatar: String,
    attributes: Box<RawValue>,
    uid: String,
    path: String,
    #[serde(rename = "type")]
    user_type: String,
    uuid: String,
    password_change_date: String,
    last_updated: String,
}

/// `Group.num_pk`: the first five decimal digits of `pk.int`.
fn num_pk(uuid: Uuid) -> u64 {
    let digits = uuid.as_u128().to_string();
    digits[..digits.len().min(5)].parse().unwrap_or(0)
}

fn raw_json(text: &str) -> Result<Box<RawValue>, Decline> {
    RawValue::from_string(render_jsonb(text)?).map_err(|_| Decline("jsonb rendering"))
}

fn db(_: sqlx::Error) -> Decline {
    Decline("database error")
}

/// `str(request.query_params.get(name, "true")).lower() == "true"`.
fn include(query: &QueryDict, name: &str) -> bool {
    query.get(name).unwrap_or("true").to_lowercase() == "true"
}

/// A placeholder list `$1, $2, …` binding `ids`.
fn id_list(ids: &[i32]) -> String {
    (1..=ids.len())
        .map(|i| format!("${i}"))
        .collect::<Vec<_>>()
        .join(", ")
}

async fn bind_ids(sql: String, ids: &[i32], pool: &sqlx::PgPool) -> Result<Vec<PgRow>, Decline> {
    let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
    for id in ids {
        q = q.bind(*id);
    }
    q.fetch_all(pool).await.map_err(db)
}

fn partial_group(row: &PgRow, offset: usize) -> Result<PartialGroup, Decline> {
    let attributes: String = row.try_get(offset).map_err(db)?;
    let uuid: Uuid = row.try_get(offset + 1).map_err(db)?;
    Ok(PartialGroup {
        pk: uuid.to_string(),
        num_pk: num_pk(uuid),
        name: row.try_get(offset + 2).map_err(db)?,
        is_superuser: row.try_get(offset + 3).map_err(db)?,
        attributes: raw_json(&attributes)?,
    })
}

fn role(row: &PgRow, offset: usize) -> Result<Role, Decline> {
    let uuid: Uuid = row.try_get(offset + 1).map_err(db)?;
    Ok(Role {
        pk: uuid.to_string(),
        name: row.try_get(offset + 2).map_err(db)?,
    })
}

const GROUP_COLUMNS: &str = "\"authentik_core_group\".\"attributes\"::text, \
                             \"authentik_core_group\".\"group_uuid\", \"authentik_core_group\".\"name\", \
                             \"authentik_core_group\".\"is_superuser\"";
const GROUP_JOIN: &str = "FROM \"authentik_core_group\" INNER JOIN \"authentik_core_user_groups\" ON \
                          (\"authentik_core_group\".\"group_uuid\" = \"authentik_core_user_groups\".\"group_id\")";
const ROLE_COLUMNS: &str = "\"authentik_rbac_role\".\"managed\", \"authentik_rbac_role\".\"uuid\", \
                            \"authentik_rbac_role\".\"name\"";
const ROLE_JOIN: &str = "FROM \"authentik_rbac_role\" INNER JOIN \"authentik_core_user_roles\" ON \
                         (\"authentik_rbac_role\".\"uuid\" = \"authentik_core_user_roles\".\"role_id\")";

/// Each user's groups, through the prefetch (`IN` over the page) or
/// per-user queries, in the order `PostgreSQL` returns them.
async fn groups_of(
    pool: &sqlx::PgPool,
    ids: &[i32],
    prefetch: bool,
) -> Result<Vec<Vec<PartialGroup>>, Decline> {
    let mut out: Vec<Vec<PartialGroup>> = ids.iter().map(|_| Vec::new()).collect();
    if prefetch {
        let rows = bind_ids(
            format!(
                "SELECT (\"authentik_core_user_groups\".\"user_id\") AS \"_prefetch_related_val_user_id\", \
                 {GROUP_COLUMNS} {GROUP_JOIN} WHERE \"authentik_core_user_groups\".\"user_id\" IN ({})",
                id_list(ids)
            ),
            ids,
            pool,
        )
        .await?;
        for row in &rows {
            let owner: i32 = row.try_get(0).map_err(db)?;
            if let Some(i) = ids.iter().position(|id| *id == owner) {
                out[i].push(partial_group(row, 1)?);
            }
        }
    } else {
        for (i, id) in ids.iter().enumerate() {
            let rows = bind_ids(
                format!("SELECT {GROUP_COLUMNS} {GROUP_JOIN} WHERE \"authentik_core_user_groups\".\"user_id\" = $1"),
                &[*id],
                pool,
            )
            .await?;
            out[i] = rows
                .iter()
                .map(|r| partial_group(r, 0))
                .collect::<Result<_, _>>()?;
        }
    }
    Ok(out)
}

async fn roles_of(
    pool: &sqlx::PgPool,
    ids: &[i32],
    prefetch: bool,
) -> Result<Vec<Vec<Role>>, Decline> {
    let mut out: Vec<Vec<Role>> = ids.iter().map(|_| Vec::new()).collect();
    if prefetch {
        let rows = bind_ids(
            format!(
                "SELECT (\"authentik_core_user_roles\".\"user_id\") AS \"_prefetch_related_val_user_id\", \
                 {ROLE_COLUMNS} {ROLE_JOIN} WHERE \"authentik_core_user_roles\".\"user_id\" IN ({})",
                id_list(ids)
            ),
            ids,
            pool,
        )
        .await?;
        for row in &rows {
            let owner: i32 = row.try_get(0).map_err(db)?;
            if let Some(i) = ids.iter().position(|id| *id == owner) {
                out[i].push(role(row, 1)?);
            }
        }
    } else {
        for (i, id) in ids.iter().enumerate() {
            let rows = bind_ids(
                format!("SELECT {ROLE_COLUMNS} {ROLE_JOIN} WHERE \"authentik_core_user_roles\".\"user_id\" = $1"),
                &[*id],
                pool,
            )
            .await?;
            out[i] = rows.iter().map(|r| role(r, 0)).collect::<Result<_, _>>()?;
        }
    }
    Ok(out)
}

/// `User.is_superuser`: a superuser group among `all_groups()`.
async fn is_superuser(pool: &sqlx::PgPool, id: i32) -> Result<bool, Decline> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM authentik_core_group WHERE is_superuser AND group_uuid IN \
         (SELECT group_id FROM authentik_core_user_groups WHERE user_id = $1 UNION SELECT \
         ancestor_id FROM authentik_core_groupancestry WHERE descendant_id IN (SELECT group_id \
         FROM authentik_core_user_groups WHERE user_id = $1)))",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .map_err(db)
}

/// `UserSerializer(rows, many=True).data`. Avatars are resolved for every
/// row before any cache write, so a cache miss still declines cleanly.
pub(crate) async fn serialize_users(
    ctx: &Context<'_>,
    tenant: &drf::Tenant,
    query: &QueryDict,
    rows: &[PgRow],
) -> Result<Vec<UserData>, Decline> {
    let ids: Vec<i32> = rows
        .iter()
        .map(|r| r.try_get(0))
        .collect::<Result<_, _>>()
        .map_err(db)?;
    let with_groups = include(query, "include_groups");
    let with_roles = include(query, "include_roles");
    let groups = if ids.is_empty() {
        Vec::new()
    } else {
        groups_of(ctx.pool, &ids, with_groups).await?
    };
    let roles = if ids.is_empty() {
        Vec::new()
    } else {
        roles_of(ctx.pool, &ids, with_roles).await?
    };
    let install_id = ak_auth::session::install_id(ctx.pool)
        .await
        .map_err(|_| Decline("database error"))?;
    let mut writes = Vec::new();
    let mut out = Vec::with_capacity(rows.len());
    for ((row, groups), roles) in rows.iter().zip(groups).zip(roles) {
        let id = ids[out.len()];
        let username: String = row.try_get(3).map_err(db)?;
        let email: String = row.try_get(6).map_err(db)?;
        let name: String = row.try_get(11).map_err(db)?;
        let attributes_text: String = row.try_get(9).map_err(db)?;
        let attributes_value: serde_json::Value =
            serde_json::from_str(&attributes_text).map_err(|_| Decline("jsonb"))?;
        let avatar = avatar::resolve(
            ctx.pool,
            ctx.now,
            &tenant.avatars,
            &AvatarUser {
                username: &username,
                name: &name,
                email: &email,
                attributes: &attributes_value,
            },
            &mut writes,
        )
        .await?;
        let uuid: Uuid = row.try_get(10).map_err(db)?;
        let last_login: Option<chrono::DateTime<chrono::Utc>> = row.try_get(2).map_err(db)?;
        let date_joined: chrono::DateTime<chrono::Utc> = row.try_get(8).map_err(db)?;
        let password_change_date: chrono::DateTime<chrono::Utc> = row.try_get(14).map_err(db)?;
        let last_updated: chrono::DateTime<chrono::Utc> = row.try_get(15).map_err(db)?;
        out.push(UserData {
            pk: id,
            username,
            name,
            is_active: row.try_get(7).map_err(db)?,
            last_login: last_login.map(drf::datetime),
            date_joined: drf::datetime(date_joined),
            is_superuser: is_superuser(ctx.pool, id).await?,
            groups: groups.iter().map(|g| g.pk.clone()).collect(),
            groups_obj: with_groups.then_some(groups),
            roles: roles.iter().map(|r| r.pk.clone()).collect(),
            roles_obj: with_roles.then_some(roles),
            email,
            avatar,
            attributes: raw_json(&attributes_text)?,
            uid: hex::encode(Sha256::digest(format!("{id}-{install_id}").as_bytes())),
            path: row.try_get(12).map_err(db)?,
            user_type: row.try_get(13).map_err(db)?,
            uuid: uuid.to_string(),
            password_change_date: drf::datetime(password_change_date),
            last_updated: drf::datetime(last_updated),
        });
    }
    cache::apply(ctx.pool, &writes).await?;
    Ok(out)
}

async fn filter_queryset(
    ctx: &Context<'_>,
    query: &QueryDict,
    user: &User,
    allow: &'static str,
) -> Result<Result<DjangoQuery, Answer>, Decline> {
    let mut qs = DjangoQuery::new(FROM, SELECT, &[]);
    let p = qs.bind(Bind::Text(ANONYMOUS_USER_NAME.to_owned()));
    qs.filter(format!("NOT ({} = {p})", col!("username")));
    let terms = match search_terms(query, allow) {
        Ok(terms) => terms,
        Err(answer) => return Ok(Err(answer)),
    };
    django_search(&mut qs, SEARCH, &terms);
    if let Err(answer) = django_object_filter(ctx, user, &MODEL, &mut qs, allow).await? {
        return Ok(Err(answer));
    }
    let head = filters::clean(ctx.pool, query, FILTERS_HEAD).await?;
    let tail = filters::clean(ctx.pool, query, FILTERS_TAIL).await?;
    let (head, tail) = match (head, tail) {
        (Ok(head), Ok(tail)) => (head, tail),
        (head, tail) => {
            let mut errors = head.err().unwrap_or_default();
            errors.extend(tail.err().unwrap_or_default());
            return Ok(Err(drf::field_errors(&errors, allow)));
        }
    };
    head.apply(&mut qs);
    // `filter_is_superuser`: direct groups only.
    match null_boolean(query.get("is_superuser")) {
        Some(true) => {
            qs.join("INNER JOIN \"authentik_core_user_groups\" ug_s ON (\"authentik_core_user\".\"id\" = ug_s.\"user_id\")");
            qs.join("INNER JOIN \"authentik_core_group\" g_s ON (ug_s.\"group_id\" = g_s.\"group_uuid\")");
            qs.filter("g_s.\"is_superuser\"".to_owned());
            qs.distinct();
        }
        Some(false) => {
            qs.filter(
                "NOT (EXISTS(SELECT 1 AS \"a\" FROM \"authentik_core_user_groups\" U1 INNER JOIN \
                 \"authentik_core_group\" U2 ON (U1.\"group_id\" = U2.\"group_uuid\") WHERE \
                 (U2.\"is_superuser\" AND U1.\"user_id\" = (\"authentik_core_user\".\"id\")) LIMIT 1))"
                    .to_owned(),
            );
            qs.distinct();
        }
        None => {}
    }
    tail.apply(&mut qs);
    Ok(Ok(qs))
}

/// `TokenAuthentication`, `SessionAuthentication` (declined upstream of
/// this) and `AgentAuth`, whose `Bearer+agent` scheme is not ported.
pub(crate) fn agent_auth(req: &ApiRequest<'_>) -> bool {
    req.headers
        .get(http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split_whitespace().next())
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("bearer+agent"))
}

/// `GET /api/v3/core/users/`.
pub async fn list(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
    query: &QueryDict,
) -> Result<Answer, Decline> {
    if agent_auth(req) {
        return Err(Decline("agent authentication"));
    }
    let tenant = drf::tenant(ctx, req).await?;
    let user = match drf::authenticate(ctx, req, ALLOW_LIST).await? {
        Ok(user) => user,
        Err(answer) => return Ok(answer),
    };
    if !user.is_authenticated() {
        return Ok(drf::permission_denied(&user, ALLOW_LIST));
    }
    let qs = match filter_queryset(ctx, query, &user, ALLOW_LIST).await? {
        Ok(qs) => qs,
        Err(answer) => return Ok(answer),
    };
    let order = ordering(query, ORDERING, ORDERING_DECLINED, DEFAULT_ORDERING)?;
    let size = page_size(query, &tenant)?;
    let count = qs.count(ctx.pool).await?;
    let Some(page) = Page::choose(query, size, count)? else {
        return Ok(drf::detail(404, "Invalid page.", ALLOW_LIST));
    };
    let rows = qs.fetch(ctx.pool, &order, Some(page.slice())).await?;
    let results = serialize_users(ctx, &tenant, query, &rows).await?;
    let autocomplete =
        RawValue::from_string(AUTOCOMPLETE.to_owned()).map_err(|_| Decline("autocomplete"))?;
    Ok(drf::json(
        200,
        &page.response_with(results, autocomplete),
        ALLOW_LIST,
    ))
}

/// `GET /api/v3/core/users/{pk}/`.
pub async fn retrieve(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
    query: &QueryDict,
    pk: &str,
) -> Result<Answer, Decline> {
    if agent_auth(req) {
        return Err(Decline("agent authentication"));
    }
    let tenant = drf::tenant(ctx, req).await?;
    let user = match drf::authenticate(ctx, req, ALLOW_DETAIL).await? {
        Ok(user) => user,
        Err(answer) => return Ok(answer),
    };
    let mut qs = match filter_queryset(ctx, query, &user, ALLOW_DETAIL).await? {
        Ok(qs) => qs,
        Err(answer) => return Ok(answer),
    };
    let not_found = "No User matches the given query.";
    let id = match py_int(pk).map_err(|_| Decline("pk digits"))? {
        None => return Ok(drf::detail(404, "Not found.", ALLOW_DETAIL)),
        Some(value) => int4(value),
    };
    let Some(id) = id else {
        return Ok(drf::detail(404, not_found, ALLOW_DETAIL));
    };
    let p = qs.bind(Bind::Int(id));
    qs.filter(format!("{} = {p}", col!("id")));
    let rows = qs.fetch(ctx.pool, &[], None).await?;
    match rows.len() {
        0 => return Ok(drf::detail(404, not_found, ALLOW_DETAIL)),
        1 => {}
        _ => return Err(Decline("multiple objects")),
    }
    let pk_text = id.to_string();
    let access = ak_rbac::has_object_permission(
        ctx.pool,
        user.subject(),
        "GET",
        &Object {
            model: MODEL,
            pk: &pk_text,
        },
        false,
    )
    .await
    .map_err(|_| Decline("object permission raised"))?;
    match access {
        Access::Allow => {
            let mut users = serialize_users(ctx, &tenant, query, &rows).await?;
            let one = users.pop().ok_or(Decline("database error"))?;
            Ok(drf::json(200, &one, ALLOW_DETAIL))
        }
        Access::NotFound => Ok(drf::detail(404, "Not found.", ALLOW_DETAIL)),
        Access::Deny => Ok(drf::permission_denied(&user, ALLOW_DETAIL)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn num_pk_takes_five_digits() {
        let uuid = Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("uuid");
        assert_eq!(num_pk(uuid), 1);
        let uuid = Uuid::parse_str("ffffffff-ffff-ffff-ffff-ffffffffffff").expect("uuid");
        assert_eq!(num_pk(uuid), 34028);
    }

    #[test]
    fn autocomplete_is_json() {
        serde_json::from_str::<serde_json::Value>(AUTOCOMPLETE).expect("json");
    }
}
