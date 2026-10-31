//! `authentik.rbac.api.roles.RoleViewSet`: `list` and `retrieve`.
//!
//! Filter backends run in the order the Enterprise search app configures
//! them (`QLSearch`, which without a license defers to DRF's
//! `SearchFilter`, then `ObjectFilter`, `DjangoFilterBackend` with
//! `RoleFilterSet`, `OrderingFilter`), on `Role.objects.all()`.

use ak_rbac::{Access, Model, Object, ObjectFilter, PkCast, Visible};
use serde::Serialize;
use sqlx::Row as _;
use uuid::Uuid;

use crate::{
    Answer, Decline,
    drf::{self, ApiRequest, Context, User},
    pagination::{Page, page_size},
    py::{
        PyInt, QueryDict, UuidLookup, int4, py_decimal, py_uuid, search_smart_split, strip,
        uuid_lookup,
    },
    sql::{Bind, QuerySet},
};

const ALLOW_LIST: &str = "GET, POST, HEAD, OPTIONS";
const ALLOW_DETAIL: &str = "GET, PUT, PATCH, DELETE, HEAD, OPTIONS";

pub(crate) const MODEL: Model<'static> = Model {
    app_label: "authentik_rbac",
    model_name: "role",
    ctype_app_label: "authentik_rbac",
    ctype_model: "role",
    pk_cast: PkCast::Uuid,
    db_table: "authentik_rbac_role",
    pk_column: "uuid",
};

/// `User.all_groups()`: the user's groups and their ancestors.
const USER_ALL_GROUPS: &str = "SELECT group_id FROM authentik_core_user_groups WHERE user_id = \
                               $USER UNION SELECT ancestor_id FROM authentik_core_groupancestry \
                               WHERE descendant_id IN (SELECT group_id FROM \
                               authentik_core_user_groups WHERE user_id = $USER)";

/// `RoleSerializer` (`fields = ["pk", "name"]`).
#[derive(Serialize)]
struct Role {
    pk: String,
    name: String,
}

fn queryset() -> QuerySet {
    QuerySet::new(MODEL.db_table, MODEL.pk_column)
}

/// `CharField(trim_whitespace=False, allow_blank=True)` validation of the
/// search term and the terms `search_smart_split` makes of it.
fn search_terms(query: &QueryDict) -> Result<Vec<String>, &'static str> {
    let value = query.get("search").unwrap_or_default();
    if value.contains('\0') {
        return Err("Null characters are not allowed.");
    }
    Ok(search_smart_split(value))
}

/// The cleaned `RoleFilterSet` form.
#[derive(Default)]
struct Form<'a> {
    name: String,
    managed: Vec<&'a str>,
    managed_isnull: Option<bool>,
    users: Option<PyInt>,
    groups: String,
}

/// `NullBooleanSelect.value_from_datadict` + `NullBooleanField.to_python`.
fn null_boolean(value: Option<&str>) -> Option<bool> {
    match value? {
        "True" | "true" | "2" => Some(true),
        "False" | "false" | "3" => Some(false),
        _ => None,
    }
}

/// `forms.CharField.clean` (`strip=True`, `ProhibitNullCharactersValidator`).
fn char_field(value: Option<&str>) -> Result<String, &'static str> {
    let value = strip(value.unwrap_or_default());
    if value.contains('\0') {
        return Err("Null characters are not allowed.");
    }
    Ok(value.to_owned())
}

/// The `managed` choices: `Role.objects.distinct().order_by("managed")
/// .values_list("managed", flat=True)`, compared as `str()`.
async fn managed_choices(ctx: &Context<'_>) -> Result<Vec<String>, Decline> {
    let values: Vec<Option<String>> =
        sqlx::query_scalar("SELECT DISTINCT managed FROM authentik_rbac_role")
            .fetch_all(ctx.pool)
            .await
            .map_err(|_| Decline("database error"))?;
    Ok(values
        .into_iter()
        .map(|v| v.unwrap_or_else(|| "None".to_owned()))
        .collect())
}

/// `RoleFilterSet(data=request.query_params).form` validation, errors in
/// filter order (`name`, `managed`, `managed__isnull`, `inherited`,
/// `users`, `groups`).
async fn clean<'a>(
    ctx: &Context<'_>,
    query: &'a QueryDict,
) -> Result<Result<Form<'a>, Vec<(&'static str, String)>>, Decline> {
    let mut errors = Vec::new();
    let mut form = Form::default();
    match char_field(query.get("name")) {
        Ok(v) => form.name = v,
        Err(e) => errors.push(("name", e.to_owned())),
    }
    form.managed = query.getlist("managed");
    if !form.managed.is_empty() {
        let choices = managed_choices(ctx).await?;
        if let Some(bad) = form
            .managed
            .iter()
            .find(|v| !choices.iter().any(|c| c == *v))
        {
            errors.push((
                "managed",
                format!("Select a valid choice. {bad} is not one of the available choices."),
            ));
        }
    }
    form.managed_isnull = null_boolean(query.get("managed__isnull"));
    match query.get("users").filter(|v| !v.is_empty()) {
        None => {}
        Some(raw) => match py_decimal(raw).map_err(|_| Decline("users digits"))? {
            Some(v) if v.exceeds_1e50() => errors.push((
                "users",
                "Ensure this value is less than or equal to 1e+50.".to_owned(),
            )),
            Some(v) => form.users = Some(v.to_int()),
            None => errors.push(("users", "Enter a number.".to_owned())),
        },
    }
    match char_field(query.get("groups")) {
        Ok(v) => form.groups = v,
        Err(e) => errors.push(("groups", e.to_owned())),
    }
    Ok(if errors.is_empty() {
        Ok(form)
    } else {
        Err(errors)
    })
}

/// `RoleFilterSet.qs` on `qs`.
async fn apply_filterset(
    ctx: &Context<'_>,
    query: &QueryDict,
    form: &Form<'_>,
    qs: &mut QuerySet,
) -> Result<(), Decline> {
    if !form.name.is_empty() {
        let p = qs.bind(Bind::Text(form.name.clone()));
        qs.filter(format!("t.\"name\" = {p}"));
    }
    if !form.managed.is_empty() {
        let mut ors = Vec::new();
        let mut seen: Vec<&str> = Vec::new();
        for value in &form.managed {
            if seen.contains(value) {
                continue;
            }
            seen.push(value);
            // `NULL_CHOICE_VALUE` means NULL.
            if *value == "null" {
                ors.push("t.\"managed\" IS NULL".to_owned());
            } else {
                let p = qs.bind(Bind::Text((*value).to_owned()));
                ors.push(format!("t.\"managed\" = {p}"));
            }
        }
        qs.filter(format!("({})", ors.join(" OR ")));
        qs.distinct();
    }
    match form.managed_isnull {
        Some(true) => qs.filter("t.\"managed\" IS NULL".to_owned()),
        Some(false) => qs.filter("t.\"managed\" IS NOT NULL".to_owned()),
        None => {}
    }
    let inherited = query.get("inherited").unwrap_or_default().to_lowercase() == "true";
    if let Some(users) = form.users {
        // `User.objects.filter(pk=value).first()`.
        let user: Option<i32> = match int4(users) {
            Some(pk) => sqlx::query_scalar("SELECT id FROM authentik_core_user WHERE id = $1")
                .bind(pk)
                .fetch_optional(ctx.pool)
                .await
                .map_err(|_| Decline("database error"))?,
            None => None,
        };
        match user {
            None => qs.none(),
            Some(user) if inherited => {
                // `user.all_roles()` replaces the queryset.
                let mut roles = queryset();
                let u = roles.bind(Bind::Int(user));
                roles.filter(format!(
                    "t.\"uuid\" IN (SELECT role_id FROM authentik_core_user_roles WHERE user_id = \
                     {u} UNION SELECT role_id FROM authentik_core_group_roles WHERE group_id IN \
                     ({}))",
                    USER_ALL_GROUPS.replace("$USER", &u)
                ));
                roles.distinct();
                qs.replace(roles);
            }
            Some(user) => {
                let p = qs.bind(Bind::Int(user));
                qs.filter(format!(
                    "t.\"uuid\" IN (SELECT role_id FROM authentik_core_user_roles WHERE user_id = \
                     {p})"
                ));
            }
        }
    }
    if !form.groups.is_empty() {
        // An invalid UUID raises Django's ValidationError: a 500 left to Django.
        let group = py_uuid(&form.groups).map_err(|_| Decline("groups value"))?;
        let found: Option<Uuid> =
            sqlx::query_scalar("SELECT group_uuid FROM authentik_core_group WHERE group_uuid = $1")
                .bind(group)
                .fetch_optional(ctx.pool)
                .await
                .map_err(|_| Decline("database error"))?;
        match found {
            None => qs.none(),
            Some(group) if inherited => {
                // `group.all_roles()`: the group and its ancestors.
                let mut roles = queryset();
                let g = roles.bind(Bind::Uuid(group));
                roles.filter(format!(
                    "t.\"uuid\" IN (SELECT role_id FROM authentik_core_group_roles WHERE group_id \
                     IN (SELECT {g}::uuid UNION SELECT ancestor_id FROM \
                     authentik_core_groupancestry WHERE descendant_id = {g}))"
                ));
                roles.distinct();
                qs.replace(roles);
            }
            Some(group) => {
                let p = qs.bind(Bind::Uuid(group));
                qs.filter(format!(
                    "t.\"uuid\" IN (SELECT role_id FROM authentik_core_group_roles WHERE group_id \
                     = {p})"
                ));
            }
        }
    }
    Ok(())
}

/// `OrderingFilter` with the serializer's readable fields (`pk`, `name`)
/// and the view's default `ordering = ["name"]`.
fn ordering(query: &QueryDict) -> Vec<String> {
    let column = |term: &str| match term {
        "pk" => Some("t.\"uuid\""),
        "name" => Some("t.\"name\""),
        _ => None,
    };
    let terms: Vec<String> = query
        .get("ordering")
        .filter(|v| !v.is_empty())
        .map(|v| {
            v.split(',')
                .map(strip)
                .filter_map(|term| {
                    let (desc, field) = match term.strip_prefix('-') {
                        Some(f) => (true, f),
                        None => (false, term),
                    };
                    column(field).map(|c| format!("{c} {}", if desc { "DESC" } else { "ASC" }))
                })
                .collect()
        })
        .unwrap_or_default();
    if terms.is_empty() {
        vec!["t.\"name\" ASC".to_owned()]
    } else {
        terms
    }
}

/// `filter_queryset(get_queryset())`.
async fn filter_queryset(
    ctx: &Context<'_>,
    query: &QueryDict,
    user: &User,
    allow: &'static str,
) -> Result<Result<QuerySet, Answer>, Decline> {
    let mut qs = queryset();
    // QLSearch → SearchFilter on `search_fields = ["name"]`.
    let terms = match search_terms(query) {
        Ok(terms) => terms,
        // A `ValidationError` raised with a list: the body is the list.
        Err(message) => return Ok(Err(drf::json(400, &[message], allow))),
    };
    for term in &terms {
        let cond = qs.icontains("name", term);
        qs.filter(cond);
    }
    // ObjectFilter.
    let filter = ak_rbac::object_filter(ctx.pool, user.subject(), &MODEL, false)
        .await
        .map_err(|_| Decline("object filter raised"))?;
    if let ObjectFilter::Visible {
        visible,
        deny_if_empty,
    } = filter
    {
        if let Visible::Pks(pks) = visible {
            let p = qs.bind(Bind::TextArray(pks));
            qs.filter(format!("t.\"uuid\"::text = ANY({p})"));
        }
        if deny_if_empty && !qs.exists(ctx.pool).await? {
            return Ok(Err(drf::detail(
                403,
                "You do not have permission to perform this action.",
                allow,
            )));
        }
    }
    // DjangoFilterBackend.
    let form = match clean(ctx, query).await? {
        Ok(form) => form,
        Err(errors) => return Ok(Err(drf::field_errors(&errors, allow))),
    };
    apply_filterset(ctx, query, &form, &mut qs).await?;
    Ok(Ok(qs))
}

fn role(row: &sqlx::postgres::PgRow) -> Result<Role, Decline> {
    let pk: Uuid = row.try_get(0).map_err(|_| Decline("database error"))?;
    let name: String = row.try_get(1).map_err(|_| Decline("database error"))?;
    Ok(Role {
        pk: pk.to_string(),
        name,
    })
}

/// `GET /api/v3/rbac/roles/`.
pub async fn list(
    ctx: &Context<'_>,
    req: &ApiRequest<'_>,
    query: &QueryDict,
) -> Result<Answer, Decline> {
    let tenant = drf::tenant(ctx, req).await?;
    let user = match drf::authenticate(ctx, req, ALLOW_LIST).await? {
        Ok(user) => user,
        Err(answer) => return Ok(answer),
    };
    // ObjectPermissions.has_permission: `GET` needs no model permission,
    // only an authenticated user.
    if !user.is_authenticated() {
        return Ok(drf::permission_denied(&user, ALLOW_LIST));
    }
    let qs = match filter_queryset(ctx, query, &user, ALLOW_LIST).await? {
        Ok(qs) => qs,
        Err(answer) => return Ok(answer),
    };
    let order = ordering(query);
    let size = page_size(query, &tenant)?;
    let count = qs.count(ctx.pool).await?;
    let Some(page) = Page::choose(query, size, count)? else {
        return Ok(drf::detail(404, "Invalid page.", ALLOW_LIST));
    };
    let rows = qs
        .fetch(
            ctx.pool,
            "t.\"uuid\", t.\"name\"",
            &order,
            Some(page.slice()),
        )
        .await?;
    let results = rows.iter().map(role).collect::<Result<Vec<_>, _>>()?;
    Ok(drf::json(200, &page.response(results), ALLOW_LIST))
}

/// `GET /api/v3/rbac/roles/{pk}/`.
pub async fn retrieve(
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
    // `has_permission` passes for detail views; object checks follow.
    let mut qs = match filter_queryset(ctx, query, &user, ALLOW_DETAIL).await? {
        Ok(qs) => qs,
        Err(answer) => return Ok(answer),
    };
    let uuid = match uuid_lookup(pk).map_err(|_| Decline("pk syntax"))? {
        UuidLookup::Valid(uuid) => uuid,
        UuidLookup::Invalid => return Ok(drf::detail(404, "Not found.", ALLOW_DETAIL)),
    };
    let p = qs.bind(Bind::Uuid(uuid));
    qs.filter(format!("t.\"uuid\" = {p}"));
    let rows = qs
        .fetch(ctx.pool, "t.\"uuid\", t.\"name\"", &[], None)
        .await?;
    let Some(row) = rows.first() else {
        return Ok(drf::detail(
            404,
            "No Role matches the given query.",
            ALLOW_DETAIL,
        ));
    };
    let role = role(row)?;
    let access = ak_rbac::has_object_permission(
        ctx.pool,
        user.subject(),
        "GET",
        &Object {
            model: MODEL,
            pk: &role.pk,
        },
        false,
    )
    .await
    .map_err(|_| Decline("object permission raised"))?;
    match access {
        Access::Allow => Ok(drf::json(200, &role, ALLOW_DETAIL)),
        Access::NotFound => Ok(drf::detail(404, "Not found.", ALLOW_DETAIL)),
        Access::Deny => Ok(drf::permission_denied(&user, ALLOW_DETAIL)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering_matches_drf() {
        let o = |s: &str| ordering(&QueryDict::parse(s).expect("query"));
        assert_eq!(o(""), vec!["t.\"name\" ASC"]);
        assert_eq!(
            o("ordering=-name,pk"),
            vec!["t.\"name\" DESC", "t.\"uuid\" ASC"]
        );
        assert_eq!(o("ordering=managed"), vec!["t.\"name\" ASC"]);
        assert_eq!(
            o("ordering=%20name%20,%20-pk%20"),
            vec!["t.\"name\" ASC", "t.\"uuid\" DESC"]
        );
        assert_eq!(o("ordering=pk&ordering=-name"), vec!["t.\"name\" DESC"]);
    }

    #[test]
    fn booleans_match_django() {
        assert_eq!(null_boolean(Some("true")), Some(true));
        assert_eq!(null_boolean(Some("1")), None);
        assert_eq!(null_boolean(Some("3")), Some(false));
        assert_eq!(null_boolean(Some("TRUE")), None);
    }
}
