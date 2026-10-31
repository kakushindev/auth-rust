//! `authentik.core.api.groups.GroupViewSet`: `list` and `retrieve`.
//!
//! Default backends (`QLSearch` → `SearchFilter`, `ObjectFilter`,
//! `GroupFilter`, `OrderingFilter`), with the QL `autocomplete` (R2).
//! `GroupSerializer` reads through the prefetches `get_queryset` sets up:
//! `roles` and `users` always, `children`/`parents` only when included
//! (per-group queries otherwise).

use ak_rbac::{Access, Model, Object, PkCast};
use serde::Serialize;
use serde_json::value::RawValue;
use sha2::{Digest as _, Sha256};
use sqlx::{Row as _, postgres::PgRow};
use uuid::Uuid;

use crate::{
    Answer, Decline,
    drf::{self, ApiRequest, Context, User},
    filters::{self, Field, Kind},
    json::render_jsonb,
    pagination::{Page, page_size},
    py::{QueryDict, UuidLookup, uuid_lookup},
    sql::{Bind, DjangoQuery},
    views::{
        common::{django_object_filter, django_search, ordering, search_terms},
        core_users::agent_auth,
    },
};

const ALLOW_LIST: &str = "GET, POST, HEAD, OPTIONS";
const ALLOW_DETAIL: &str = "GET, PUT, PATCH, DELETE, HEAD, OPTIONS";

const MODEL: Model<'static> = Model {
    app_label: "authentik_core",
    model_name: "group",
    ctype_app_label: "authentik_core",
    ctype_model: "group",
    pk_cast: PkCast::Uuid,
    db_table: "authentik_core_group",
    pk_column: "group_uuid",
};

macro_rules! col {
    ($c:literal) => {
        concat!("\"authentik_core_group\".\"", $c, "\"")
    };
}

const FROM: &str = "\"authentik_core_group\"";
pub(crate) const SELECT: &str = concat!(
    col!("attributes"),
    "::text, ",
    col!("group_uuid"),
    ", ",
    col!("name"),
    ", ",
    col!("is_superuser"),
);

/// `GroupFilter.base_filters`, in order.
const FILTERS: &[Field] = &[
    Field {
        name: "name",
        kind: Kind::Char {
            column: col!("name"),
        },
    },
    Field {
        name: "is_superuser",
        kind: Kind::NullBoolean {
            column: col!("is_superuser"),
        },
    },
    Field {
        name: "members_by_pk",
        kind: Kind::ManyToManyInt {
            join: "INNER JOIN \"authentik_core_user_groups\" ug_p ON (\"authentik_core_group\".\"group_uuid\" = ug_p.\"group_id\")",
            through_column: "ug_p.\"user_id\"",
            target: ("authentik_core_user", "id"),
        },
    },
    Field {
        name: "attributes",
        kind: Kind::Declined,
    },
    Field {
        name: "members_by_username",
        kind: Kind::ManyToManyField {
            joins: &[
                "INNER JOIN \"authentik_core_user_groups\" ug_n ON (\"authentik_core_group\".\"group_uuid\" = ug_n.\"group_id\")",
                "INNER JOIN \"authentik_core_user\" u_n ON (ug_n.\"user_id\" = u_n.\"id\")",
            ],
            column: "u_n.\"username\"",
            target: ("authentik_core_user", "username"),
        },
    },
];

const SEARCH: &[&str] = &[col!("name"), col!("is_superuser")];

/// Readable sources that are columns; `num_pk` is a property, the m2m
/// fields duplicate rows: declined.
const ORDERING: &[(&str, &str)] = &[
    ("pk", col!("group_uuid")),
    ("name", col!("name")),
    ("is_superuser", col!("is_superuser")),
    ("attributes", col!("attributes")),
];
const ORDERING_DECLINED: &[&str] = &["num_pk", "parents", "users", "roles", "children"];

/// `AKQLSchemaSerializer().serialize(schema(Group))` for `get_ql_fields`.
const AUTOCOMPLETE: &str = r#"{"current_model":"authentik_core.group","models":{"authentik_core.group":{"name":{"type":"str","nullable":false,"options":null},"is_superuser":{"type":"bool","nullable":true,"options":null},"attributes":{"type":"relation","nullable":false,"options":null,"relation":"authentik_core.group_attributes"}}}}"#;

/// `RelatedGroupSerializer`.
#[derive(Serialize)]
struct RelatedGroup {
    pk: String,
    name: String,
    is_superuser: bool,
    attributes: Box<RawValue>,
    group_uuid: String,
}

/// `PartialUserSerializer`.
#[derive(Serialize)]
struct PartialUser {
    pk: i32,
    username: String,
    name: String,
    is_active: bool,
    last_login: Option<String>,
    email: String,
    attributes: Box<RawValue>,
    uid: String,
}

#[derive(Serialize)]
struct Role {
    pk: String,
    name: String,
}

/// `GroupSerializer`.
#[derive(Serialize)]
pub(crate) struct GroupData {
    pk: String,
    num_pk: u64,
    name: String,
    is_superuser: bool,
    parents: Vec<String>,
    parents_obj: Option<Vec<RelatedGroup>>,
    users: Vec<i32>,
    users_obj: Option<Vec<PartialUser>>,
    attributes: Box<RawValue>,
    roles: Vec<String>,
    roles_obj: Vec<Role>,
    inherited_roles_obj: Option<Vec<Role>>,
    children: Vec<String>,
    children_obj: Option<Vec<RelatedGroup>>,
}

fn db(_: sqlx::Error) -> Decline {
    Decline("database error")
}

fn raw_json(text: &str) -> Result<Box<RawValue>, Decline> {
    RawValue::from_string(render_jsonb(text)?).map_err(|_| Decline("jsonb rendering"))
}

/// `Group.num_pk`.
fn num_pk(uuid: Uuid) -> u64 {
    let digits = uuid.as_u128().to_string();
    digits[..digits.len().min(5)].parse().unwrap_or(0)
}

/// `str(query_params.get(name, default)).lower() == "true"`.
fn include(query: &QueryDict, name: &str, default: bool) -> bool {
    query
        .get(name)
        .map_or(default, |v| v.to_lowercase() == "true")
}

fn placeholders(n: usize) -> String {
    (1..=n)
        .map(|i| format!("${i}"))
        .collect::<Vec<_>>()
        .join(", ")
}

async fn fetch_by_uuids(
    pool: &sqlx::PgPool,
    sql: String,
    ids: &[Uuid],
) -> Result<Vec<PgRow>, Decline> {
    let mut q = sqlx::query(sqlx::AssertSqlSafe(sql));
    for id in ids {
        q = q.bind(*id);
    }
    q.fetch_all(pool).await.map_err(db)
}

const GROUP_COLUMNS: &str = "\"authentik_core_group\".\"attributes\"::text, \
                             \"authentik_core_group\".\"group_uuid\", \"authentik_core_group\".\"name\", \
                             \"authentik_core_group\".\"is_superuser\"";

fn related_group(row: &PgRow, offset: usize) -> Result<RelatedGroup, Decline> {
    let attributes: String = row.try_get(offset).map_err(db)?;
    let uuid: Uuid = row.try_get(offset + 1).map_err(db)?;
    Ok(RelatedGroup {
        pk: uuid.to_string(),
        name: row.try_get(offset + 2).map_err(db)?,
        is_superuser: row.try_get(offset + 3).map_err(db)?,
        attributes: raw_json(&attributes)?,
        group_uuid: uuid.to_string(),
    })
}

/// Rows of a prefetch (`IN` over the page, owner in column 0) or of
/// per-group queries (`$1`), grouped by page position.
async fn per_group<T>(
    pool: &sqlx::PgPool,
    ids: &[Uuid],
    prefetch: Option<String>,
    single: String,
    parse: impl Fn(&PgRow, usize) -> Result<T, Decline>,
) -> Result<Vec<Vec<T>>, Decline> {
    let mut out: Vec<Vec<T>> = ids.iter().map(|_| Vec::new()).collect();
    if ids.is_empty() {
        return Ok(out);
    }
    if let Some(sql) = prefetch {
        for row in &fetch_by_uuids(pool, sql, ids).await? {
            let owner: Uuid = row.try_get(0).map_err(db)?;
            if let Some(i) = ids.iter().position(|id| *id == owner) {
                out[i].push(parse(row, 1)?);
            }
        }
    } else {
        for (i, id) in ids.iter().enumerate() {
            out[i] = fetch_by_uuids(pool, single.clone(), &[*id])
                .await?
                .iter()
                .map(|r| parse(r, 0))
                .collect::<Result<_, _>>()?;
        }
    }
    Ok(out)
}

/// `GroupSerializer(rows, many=True).data`; `prefetched` when the rows come
/// from `GroupViewSet.get_queryset`, not from a relation.
pub(crate) async fn serialize_groups(
    ctx: &Context<'_>,
    query: &QueryDict,
    rows: &[PgRow],
    prefetched: bool,
) -> Result<Vec<GroupData>, Decline> {
    let ids: Vec<Uuid> = rows
        .iter()
        .map(|r| r.try_get(1))
        .collect::<Result<_, _>>()
        .map_err(db)?;
    let n = ids.len();
    let with_users = include(query, "include_users", true);
    let with_children = include(query, "include_children", false);
    let with_parents = include(query, "include_parents", false);
    let with_inherited = include(query, "include_inherited_roles", false);

    let mut roles = per_group(
        ctx.pool,
        &ids,
        prefetched.then(|| format!(
            "SELECT (\"authentik_core_group_roles\".\"group_id\") AS \"_prefetch_related_val_group_id\", \
             \"authentik_rbac_role\".\"managed\", \"authentik_rbac_role\".\"uuid\", \"authentik_rbac_role\".\"name\" \
             FROM \"authentik_rbac_role\" INNER JOIN \"authentik_core_group_roles\" ON \
             (\"authentik_rbac_role\".\"uuid\" = \"authentik_core_group_roles\".\"role_id\") WHERE \
             \"authentik_core_group_roles\".\"group_id\" IN ({})",
            placeholders(n)
        )),
        "SELECT \"authentik_rbac_role\".\"managed\", \"authentik_rbac_role\".\"uuid\", \
         \"authentik_rbac_role\".\"name\" FROM \"authentik_rbac_role\" INNER JOIN \
         \"authentik_core_group_roles\" ON (\"authentik_rbac_role\".\"uuid\" = \
         \"authentik_core_group_roles\".\"role_id\") WHERE \"authentik_core_group_roles\".\"group_id\" = $1"
            .to_owned(),
        |row, o| {
            let uuid: Uuid = row.try_get(o + 1).map_err(db)?;
            Ok(Role {
                pk: uuid.to_string(),
                name: row.try_get(o + 2).map_err(db)?,
            })
        },
    )
    .await?;
    let user_columns = if with_users {
        "\"authentik_core_user\".\"id\", \"authentik_core_user\".\"last_login\", \
         \"authentik_core_user\".\"username\", \"authentik_core_user\".\"email\", \
         \"authentik_core_user\".\"is_active\", \"authentik_core_user\".\"attributes\"::text, \
         \"authentik_core_user\".\"name\""
    } else {
        "\"authentik_core_user\".\"id\""
    };
    let install_id = ak_auth::session::install_id(ctx.pool)
        .await
        .map_err(|_| Decline("database error"))?;
    let mut users = per_group(
        ctx.pool,
        &ids,
        prefetched.then(|| format!(
            "SELECT (\"authentik_core_user_groups\".\"group_id\") AS \"_prefetch_related_val_group_id\", \
             {user_columns} FROM \"authentik_core_user\" INNER JOIN \"authentik_core_user_groups\" ON \
             (\"authentik_core_user\".\"id\" = \"authentik_core_user_groups\".\"user_id\") WHERE \
             \"authentik_core_user_groups\".\"group_id\" IN ({})",
            placeholders(n)
        )),
        format!(
            "SELECT {user_columns} FROM \"authentik_core_user\" INNER JOIN \"authentik_core_user_groups\" \
             ON (\"authentik_core_user\".\"id\" = \"authentik_core_user_groups\".\"user_id\") WHERE \
             \"authentik_core_user_groups\".\"group_id\" = $1"
        ),
        |row, o| {
            let id: i32 = row.try_get(o).map_err(db)?;
            if !with_users {
                return Ok((id, None));
            }
            let last_login: Option<chrono::DateTime<chrono::Utc>> = row.try_get(o + 1).map_err(db)?;
            let attributes: String = row.try_get(o + 5).map_err(db)?;
            Ok((
                id,
                Some(PartialUser {
                    pk: id,
                    username: row.try_get(o + 2).map_err(db)?,
                    name: row.try_get(o + 6).map_err(db)?,
                    is_active: row.try_get(o + 4).map_err(db)?,
                    last_login: last_login.map(drf::datetime),
                    email: row.try_get(o + 3).map_err(db)?,
                    attributes: raw_json(&attributes)?,
                    uid: hex::encode(Sha256::digest(format!("{id}-{install_id}").as_bytes())),
                }),
            ))
        },
    )
    .await?;
    let mut children = per_group(
        ctx.pool,
        &ids,
        with_children.then(|| {
            format!(
                "SELECT (\"authentik_core_groupparentage\".\"parent_id\") AS \"_prefetch_related_val_parent_id\", \
                 {GROUP_COLUMNS} FROM \"authentik_core_group\" INNER JOIN \"authentik_core_groupparentage\" ON \
                 (\"authentik_core_group\".\"group_uuid\" = \"authentik_core_groupparentage\".\"child_id\") WHERE \
                 \"authentik_core_groupparentage\".\"parent_id\" IN ({})",
                placeholders(n)
            )
        }),
        format!(
            "SELECT {GROUP_COLUMNS} FROM \"authentik_core_group\" INNER JOIN \"authentik_core_groupparentage\" ON \
             (\"authentik_core_group\".\"group_uuid\" = \"authentik_core_groupparentage\".\"child_id\") WHERE \
             \"authentik_core_groupparentage\".\"parent_id\" = $1"
        ),
        related_group,
    )
    .await?;
    let mut parents = per_group(
        ctx.pool,
        &ids,
        with_parents.then(|| {
            format!(
                "SELECT (\"authentik_core_groupparentage\".\"child_id\") AS \"_prefetch_related_val_child_id\", \
                 {GROUP_COLUMNS} FROM \"authentik_core_group\" INNER JOIN \"authentik_core_groupparentage\" ON \
                 (\"authentik_core_group\".\"group_uuid\" = \"authentik_core_groupparentage\".\"parent_id\") WHERE \
                 \"authentik_core_groupparentage\".\"child_id\" IN ({})",
                placeholders(n)
            )
        }),
        format!(
            "SELECT {GROUP_COLUMNS} FROM \"authentik_core_group\" INNER JOIN \"authentik_core_groupparentage\" ON \
             (\"authentik_core_group\".\"group_uuid\" = \"authentik_core_groupparentage\".\"parent_id\") WHERE \
             \"authentik_core_groupparentage\".\"child_id\" = $1"
        ),
        related_group,
    )
    .await?;

    let mut out = Vec::with_capacity(n);
    for (i, row) in rows.iter().enumerate() {
        let id = ids[i];
        let attributes: String = row.try_get(0).map_err(db)?;
        // `all_roles().exclude(pk__in=direct roles)`, as Django sends it.
        let inherited = if with_inherited {
            let rows = sqlx::query(
                "SELECT DISTINCT \"authentik_rbac_role\".\"managed\", \"authentik_rbac_role\".\"uuid\", \
                 \"authentik_rbac_role\".\"name\" FROM \"authentik_rbac_role\" INNER JOIN \
                 \"authentik_core_group_roles\" ON (\"authentik_rbac_role\".\"uuid\" = \
                 \"authentik_core_group_roles\".\"role_id\") WHERE (\"authentik_core_group_roles\".\"group_id\" \
                 IN (SELECT DISTINCT V0.\"group_uuid\" FROM \"authentik_core_group\" V0 LEFT OUTER JOIN \
                 \"authentik_core_groupancestry\" V1 ON (V0.\"group_uuid\" = V1.\"ancestor_id\") WHERE \
                 (V0.\"group_uuid\" IN (SELECT U0.\"group_uuid\" AS \"pk\" FROM \"authentik_core_group\" U0 \
                 WHERE U0.\"group_uuid\" = $1) OR V1.\"descendant_id\" IN (SELECT U0.\"group_uuid\" AS \"pk\" \
                 FROM \"authentik_core_group\" U0 WHERE U0.\"group_uuid\" = $1))) AND NOT \
                 (\"authentik_rbac_role\".\"uuid\" IN (SELECT U0.\"uuid\" AS \"pk\" FROM \"authentik_rbac_role\" \
                 U0 INNER JOIN \"authentik_core_group_roles\" U1 ON (U0.\"uuid\" = U1.\"role_id\") WHERE \
                 U1.\"group_id\" = $1)))",
            )
            .bind(id)
            .fetch_all(ctx.pool)
            .await
            .map_err(db)?;
            Some(
                rows.iter()
                    .map(|r| {
                        let uuid: Uuid = r.try_get(1).map_err(db)?;
                        Ok(Role {
                            pk: uuid.to_string(),
                            name: r.try_get(2).map_err(db)?,
                        })
                    })
                    .collect::<Result<Vec<_>, Decline>>()?,
            )
        } else {
            None
        };
        let (user_ids, users_obj): (Vec<i32>, Vec<Option<PartialUser>>) =
            users[i].drain(..).unzip();
        out.push(GroupData {
            pk: id.to_string(),
            num_pk: num_pk(id),
            name: row.try_get(2).map_err(db)?,
            is_superuser: row.try_get(3).map_err(db)?,
            parents: parents[i].iter().map(|g| g.pk.clone()).collect(),
            parents_obj: None,
            users: user_ids,
            users_obj: with_users.then(|| users_obj.into_iter().flatten().collect()),
            attributes: raw_json(&attributes)?,
            roles: roles[i].iter().map(|r| r.pk.clone()).collect(),
            roles_obj: std::mem::take(&mut roles[i]),
            inherited_roles_obj: inherited,
            children: children[i].iter().map(|g| g.pk.clone()).collect(),
            children_obj: None,
        });
        let entry = out.last_mut().ok_or(Decline("serializer"))?;
        if with_parents {
            entry.parents_obj = Some(std::mem::take(&mut parents[i]));
        }
        if with_children {
            entry.children_obj = Some(std::mem::take(&mut children[i]));
        }
    }
    Ok(out)
}

async fn filter_queryset(
    ctx: &Context<'_>,
    query: &QueryDict,
    user: &User,
    allow: &'static str,
) -> Result<Result<DjangoQuery, Answer>, Decline> {
    let mut qs = DjangoQuery::new(FROM, SELECT, &[]);
    let terms = match search_terms(query, allow) {
        Ok(terms) => terms,
        Err(answer) => return Ok(Err(answer)),
    };
    django_search(&mut qs, SEARCH, &terms);
    if let Err(answer) = django_object_filter(ctx, user, &MODEL, &mut qs, allow).await? {
        return Ok(Err(answer));
    }
    match filters::clean(ctx.pool, query, FILTERS).await? {
        Ok(form) => {
            form.apply(&mut qs);
        }
        Err(errors) => return Ok(Err(drf::field_errors(&errors, allow))),
    }
    Ok(Ok(qs))
}

/// `GET /api/v3/core/groups/`.
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
    let order = ordering(
        query,
        ORDERING,
        ORDERING_DECLINED,
        &[concat!("\"authentik_core_group\".\"name\"", " ASC")],
    )?;
    let size = page_size(query, &tenant)?;
    let count = qs.count(ctx.pool).await?;
    let Some(page) = Page::choose(query, size, count)? else {
        return Ok(drf::detail(404, "Invalid page.", ALLOW_LIST));
    };
    let rows = qs.fetch(ctx.pool, &order, Some(page.slice())).await?;
    let results = serialize_groups(ctx, query, &rows, true).await?;
    let autocomplete =
        RawValue::from_string(AUTOCOMPLETE.to_owned()).map_err(|_| Decline("autocomplete"))?;
    Ok(drf::json(
        200,
        &page.response_with(results, autocomplete),
        ALLOW_LIST,
    ))
}

/// `GET /api/v3/core/groups/{pk}/`.
pub async fn retrieve(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
    query: &QueryDict,
    pk: &str,
) -> Result<Answer, Decline> {
    if agent_auth(req) {
        return Err(Decline("agent authentication"));
    }
    drf::tenant(ctx, req).await?;
    let user = match drf::authenticate(ctx, req, ALLOW_DETAIL).await? {
        Ok(user) => user,
        Err(answer) => return Ok(answer),
    };
    let mut qs = match filter_queryset(ctx, query, &user, ALLOW_DETAIL).await? {
        Ok(qs) => qs,
        Err(answer) => return Ok(answer),
    };
    let uuid = match uuid_lookup(pk).map_err(|_| Decline("pk syntax"))? {
        UuidLookup::Valid(uuid) => uuid,
        UuidLookup::Invalid => return Ok(drf::detail(404, "Not found.", ALLOW_DETAIL)),
    };
    let p = qs.bind(Bind::Uuid(uuid));
    qs.filter(format!("{} = {p}", col!("group_uuid")));
    let rows = qs.fetch(ctx.pool, &[], None).await?;
    match rows.len() {
        0 => {
            return Ok(drf::detail(
                404,
                "No Group matches the given query.",
                ALLOW_DETAIL,
            ));
        }
        1 => {}
        _ => return Err(Decline("multiple objects")),
    }
    let pk_text = uuid.to_string();
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
            let mut groups = serialize_groups(ctx, query, &rows, true).await?;
            let one = groups.pop().ok_or(Decline("database error"))?;
            Ok(drf::json(200, &one, ALLOW_DETAIL))
        }
        Access::NotFound => Ok(drf::detail(404, "Not found.", ALLOW_DETAIL)),
        Access::Deny => Ok(drf::permission_denied(&user, ALLOW_DETAIL)),
    }
}
