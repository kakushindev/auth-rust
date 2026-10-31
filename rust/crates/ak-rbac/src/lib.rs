//! Permissions as 2026.2.7 decides them (milestone M6).
//!
//! authentik grants permissions only through roles: a role holds model-wide
//! permissions (`guardian_rolemodelpermission`) and per-object permissions
//! (`guardian_roleobjectpermission`), and a user has the roles assigned to
//! them and to their groups and those groups' ancestors. Superusers (members
//! of a superuser group, again with ancestors) have everything. Its auth
//! backends grant nothing themselves; only the `ak-guardian` fork's
//! `ObjectPermissionBackend` does.
//!
//! Ported here: `User.all_roles()` / `is_superuser`, `PermissionsMixin.has_perm`
//! with that backend chain (`ObjectPermissionChecker`), `has_perms`,
//! `get_objects_for_user`, authentik's `ObjectFilter`, `ObjectPermissions`
//! (DRF) and `permission_required`. Each runs the queries Django runs and is
//! checked against Django by `tests/rbac/run.sh`.

use std::collections::HashSet;

use sqlx::PgPool;
use uuid::Uuid;

/// `GUARDIAN_ANONYMOUS_USER_NAME`.
pub const ANONYMOUS_USER_NAME: &str = "AnonymousUser";
/// `UserTypes.INTERNAL_SERVICE_ACCOUNT`.
const INTERNAL_SERVICE_ACCOUNT: &str = "internal_service_account";

/// An exception Django raises (a 500, or the DRF error named).
#[derive(Debug)]
pub enum Error {
    /// A database error; [`Error::db_class`] names psycopg's exception.
    Database(sqlx::Error),
    /// `guardian.exceptions.WrongAppError`.
    WrongApp,
    /// `GuardianError` (a permission without an app label).
    Guardian,
    /// `MixedContentTypeError`.
    MixedContentType,
    /// `ContentType.DoesNotExist` / `MultipleObjectsReturned` resolving a
    /// permission's content type, or `User.DoesNotExist` for the anonymous
    /// user.
    DoesNotExist,
    MultipleObjectsReturned,
    /// DRF's `MethodNotAllowed` (a 405).
    MethodNotAllowed,
}

impl Error {
    /// The `django.db` exception class for a database error, by SQLSTATE
    /// class: `22` is `DataError` (an `object_pk` that does not cast), `42`
    /// `ProgrammingError` (a `bigint` cast compared with a text key).
    #[must_use]
    pub fn db_class(&self) -> Option<&'static str> {
        let Self::Database(sqlx::Error::Database(db)) = self else {
            return None;
        };
        Some(match db.code().as_deref().map(|c| &c[..2]) {
            Some("22") => "DataError",
            Some("42") => "ProgrammingError",
            Some("23") => "IntegrityError",
            _ => "DatabaseError",
        })
    }
}

impl From<sqlx::Error> for Error {
    fn from(err: sqlx::Error) -> Self {
        Self::Database(err)
    }
}

/// Who is asking: a user, or Django's `AnonymousUser`, whose permissions
/// guardian reads from the `AnonymousUser` row.
#[derive(Debug, Clone)]
pub struct Subject {
    pub user_id: i32,
    /// `request.user.is_active`; impersonation forces it to `true`.
    pub is_active: bool,
    /// Django's `AnonymousUser` (not the row standing in for it).
    pub anonymous: bool,
    pub user_type: String,
    /// `all_roles()`.
    pub roles: Vec<Uuid>,
    /// `is_superuser`: a superuser group among `all_groups()`.
    pub is_superuser: bool,
}

/// `User.all_groups()`: the user's groups and their ancestors.
const ALL_GROUPS: &str = "WITH g AS (SELECT group_id FROM authentik_core_user_groups WHERE \
                          user_id = $1) SELECT group_id AS id FROM g UNION SELECT ancestor_id \
                          FROM authentik_core_groupancestry WHERE descendant_id IN (SELECT \
                          group_id FROM g)";

impl Subject {
    /// The user with id `user_id`; `is_active` overrides the stored flag
    /// (`ImpersonateMiddleware` sets it).
    ///
    /// # Errors
    ///
    /// A database error, or [`Error::DoesNotExist`] for no such user.
    pub async fn load(pool: &PgPool, user_id: i32, is_active: Option<bool>) -> Result<Self, Error> {
        let row: Option<(bool, String)> =
            sqlx::query_as("SELECT is_active, type FROM authentik_core_user WHERE id = $1")
                .bind(user_id)
                .fetch_optional(pool)
                .await?;
        let (stored_active, user_type) = row.ok_or(Error::DoesNotExist)?;
        // `all_roles()`: `Q(users=self) | Q(groups__in=self.all_groups())`.
        let roles: Vec<Uuid> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT role_id FROM authentik_core_user_roles WHERE user_id = $1 UNION SELECT \
             role_id FROM authentik_core_group_roles WHERE group_id IN ({ALL_GROUPS})"
        )))
        .bind(user_id)
        .fetch_all(pool)
        .await?;
        let is_superuser: bool = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT EXISTS (SELECT 1 FROM authentik_core_group WHERE is_superuser AND group_uuid \
             IN ({ALL_GROUPS}))"
        )))
        .bind(user_id)
        .fetch_one(pool)
        .await?;
        Ok(Self {
            user_id,
            is_active: is_active.unwrap_or(stored_active),
            anonymous: false,
            user_type,
            roles,
            is_superuser,
        })
    }

    /// Django's `AnonymousUser`: guardian checks the `AnonymousUser` row.
    ///
    /// # Errors
    ///
    /// [`Error::DoesNotExist`] when that row is missing.
    pub async fn anonymous(pool: &PgPool) -> Result<Self, Error> {
        let id: Option<i32> =
            sqlx::query_scalar("SELECT id FROM authentik_core_user WHERE username = $1")
                .bind(ANONYMOUS_USER_NAME)
                .fetch_optional(pool)
                .await?;
        let mut subject = Self::load(pool, id.ok_or(Error::DoesNotExist)?, None).await?;
        subject.anonymous = true;
        Ok(subject)
    }

    /// `getattr(request.user, "type", None) == INTERNAL_SERVICE_ACCOUNT`.
    #[must_use]
    pub fn is_internal_service_account(&self) -> bool {
        !self.anonymous && self.user_type == INTERNAL_SERVICE_ACCOUNT
    }
}

/// How `get_objects_for_user` casts `object_pk` to the model's primary key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkCast {
    Uuid,
    Bigint,
}

impl PkCast {
    const fn sql(self) -> &'static str {
        match self {
            Self::Uuid => "uuid",
            Self::Bigint => "bigint",
        }
    }
}

/// A model, as permission checks see it.
///
/// Its `_meta.app_label` / `model_name` are what permission names use, its
/// concrete model's content type is what object permissions are stored
/// under, and its table and primary key column are what
/// `get_objects_for_user` filters.
#[derive(Debug, Clone, Copy)]
pub struct Model<'a> {
    pub app_label: &'a str,
    pub model_name: &'a str,
    pub ctype_app_label: &'a str,
    pub ctype_model: &'a str,
    /// guardian's `_cast_type(pk)`: `uuid` for a `UUIDField` (through
    /// foreign keys), else `bigint`, whatever the column really is.
    pub pk_cast: PkCast,
    pub db_table: &'a str,
    pub pk_column: &'a str,
}

/// A model instance: `str(obj.pk)` is what `object_pk` holds.
#[derive(Debug, Clone, Copy)]
pub struct Object<'a> {
    pub model: Model<'a>,
    pub pk: &'a str,
}

async fn content_type_id(pool: &PgPool, app_label: &str, model: &str) -> Result<i32, Error> {
    sqlx::query_scalar("SELECT id FROM django_content_type WHERE app_label = $1 AND model = $2")
        .bind(app_label)
        .bind(model)
        .fetch_optional(pool)
        .await?
        .ok_or(Error::DoesNotExist)
}

/// `ObjectPermissionChecker(user).get_perms(obj)` for a user that is active
/// and not a superuser: `app_label.codename` of every permission the
/// user's roles hold model-wide, or on `obj`.
///
/// # Errors
///
/// A database error.
pub async fn get_perms(
    pool: &PgPool,
    subject: &Subject,
    obj: Option<&Object<'_>>,
) -> Result<HashSet<String>, Error> {
    let rows: Vec<(String, String)> = match obj {
        None => {
            sqlx::query_as(
                "SELECT DISTINCT ct.app_label, p.codename FROM auth_permission p JOIN \
                 django_content_type ct ON ct.id = p.content_type_id WHERE p.id IN (SELECT \
                 permission_id FROM guardian_rolemodelpermission WHERE role_id = ANY($1))",
            )
            .bind(&subject.roles)
            .fetch_all(pool)
            .await?
        }
        Some(obj) => {
            let ctype =
                content_type_id(pool, obj.model.ctype_app_label, obj.model.ctype_model).await?;
            sqlx::query_as(
                "SELECT DISTINCT ct.app_label, p.codename FROM auth_permission p JOIN \
                 django_content_type ct ON ct.id = p.content_type_id WHERE p.id IN (SELECT \
                 permission_id FROM guardian_rolemodelpermission WHERE role_id = ANY($1)) OR p.id \
                 IN (SELECT permission_id FROM guardian_roleobjectpermission WHERE \
                 content_type_id = $2 AND object_pk = $3 AND role_id = ANY($1))",
            )
            .bind(&subject.roles)
            .bind(ctype)
            .bind(obj.pk)
            .fetch_all(pool)
            .await?
        }
    };
    Ok(rows
        .into_iter()
        .map(|(app, codename)| format!("{app}.{codename}"))
        .collect())
}

/// `user.has_perm(perm, obj)`: `PermissionsMixin` (active superusers have
/// everything; `AnonymousUser` skips that), then the backends, of which
/// only guardian's can grant.
///
/// # Errors
///
/// [`Error::WrongApp`] when `perm`'s app label is neither `obj`'s nor its
/// content type's, or a database error.
pub async fn has_perm(
    pool: &PgPool,
    subject: &Subject,
    perm: &str,
    obj: Option<&Object<'_>>,
) -> Result<bool, Error> {
    if !subject.anonymous && subject.is_active && subject.is_superuser {
        return Ok(true);
    }
    // `ObjectPermissionBackend.has_perm`.
    if let Some(obj) = obj
        && let Some((app_label, _)) = perm.split_once('.')
        && app_label != obj.model.app_label
        && app_label != obj.model.ctype_app_label
    {
        return Err(Error::WrongApp);
    }
    // `ObjectPermissionChecker.has_perm`.
    if !subject.is_active {
        return Ok(false);
    }
    if subject.is_superuser {
        return Ok(true);
    }
    let perms = get_perms(pool, subject, obj).await?;
    Ok(if perm.contains('.') {
        perms.contains(perm)
    } else {
        perms
            .iter()
            .any(|p| p.split_once('.').map_or(p.as_str(), |(_, c)| c) == perm)
    })
}

/// `user.has_perms(perm_list, obj)`: all of them (none is `True`).
///
/// # Errors
///
/// As [`has_perm`].
pub async fn has_perms(
    pool: &PgPool,
    subject: &Subject,
    perms: &[&str],
    obj: Option<&Object<'_>>,
) -> Result<bool, Error> {
    for perm in perms {
        if !has_perm(pool, subject, perm, obj).await? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Which objects of a model are visible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Visible {
    /// The queryset, unfiltered.
    All,
    /// The rows of `model.db_table` matching `pk IN (…)`: their primary
    /// keys as text.
    Pks(Vec<String>),
}

/// `get_objects_for_user(user, perms, model.objects)`: objects the user has
/// *all* of `perms` on (model-wide permissions count for every object).
///
/// With several permissions guardian counts matching
/// `guardian_roleobjectpermission` rows per object, so the same permission
/// granted through two roles counts twice; that is reproduced.
///
/// # Errors
///
/// [`Error::Guardian`] / [`Error::MixedContentType`] /
/// [`Error::DoesNotExist`] / [`Error::MultipleObjectsReturned`] as guardian
/// raises them, or a database error (an `object_pk` that does not cast).
pub async fn get_objects_for_user(
    pool: &PgPool,
    subject: &Subject,
    perms: &[&str],
    model: &Model<'_>,
) -> Result<Visible, Error> {
    let mut ctype: Option<i32> = None;
    let mut app_label: Option<&str> = None;
    let mut codenames: Vec<&str> = Vec::new();
    for perm in perms {
        let (new_app, new_codename) = perm.split_once('.').ok_or(Error::Guardian)?;
        if new_app.is_empty() || new_codename.is_empty() {
            return Err(Error::Guardian);
        }
        if app_label.is_some_and(|a| a != new_app) {
            return Err(Error::MixedContentType);
        }
        // `_get_ct_cached(app_label, codename)`.
        let ids: Vec<i32> = sqlx::query_scalar(
            "SELECT ct.id FROM django_content_type ct JOIN auth_permission p ON p.content_type_id \
             = ct.id WHERE ct.app_label = $1 AND p.codename = $2",
        )
        .bind(new_app)
        .bind(new_codename)
        .fetch_all(pool)
        .await?;
        let new_ctype = match ids.as_slice() {
            [] => return Err(Error::DoesNotExist),
            [id] => *id,
            _ => return Err(Error::MultipleObjectsReturned),
        };
        if ctype.is_some_and(|c| c != new_ctype) {
            return Err(Error::MixedContentType);
        }
        ctype = Some(new_ctype);
        app_label = Some(new_app);
        if !codenames.contains(&new_codename) {
            codenames.push(new_codename);
        }
    }
    // No permissions leave `ctype` `None`, which differs from the queryset's.
    let Some(ctype) = ctype else {
        return Err(Error::MixedContentType);
    };
    if ctype != content_type_id(pool, model.ctype_app_label, model.ctype_model).await? {
        return Err(Error::MixedContentType);
    }
    // `user.is_superuser` (Django's `AnonymousUser` is not).
    if !subject.anonymous && subject.is_superuser {
        return Ok(Visible::All);
    }
    // `AnonymousUser` becomes the `AnonymousUser` row, a real user.
    let user = Subject {
        anonymous: false,
        ..subject.clone()
    };
    let app_label = app_label.unwrap_or_default();
    let mut remaining = Vec::new();
    for code in &codenames {
        if !has_perm(pool, &user, &format!("{app_label}.{code}"), None).await? {
            remaining.push((*code).to_owned());
        }
    }
    if remaining.is_empty() {
        return Ok(Visible::All);
    }
    let having = if remaining.len() > 1 {
        "GROUP BY rop.object_pk HAVING COUNT(rop.object_pk) >= $4"
    } else {
        ""
    };
    // `queryset.filter(pk__in=RawSQL(cast subquery))`, as Django runs it, so
    // Postgres raises what it raises for Django.
    let sql = format!(
        "SELECT \"{pk}\"::text FROM \"{table}\" WHERE \"{pk}\" IN (SELECT \
         (\"permission_subquery\".\"object_pk\")::{cast} AS \"object_pk\" FROM (SELECT \
         rop.object_pk FROM guardian_roleobjectpermission rop JOIN auth_permission p ON p.id = \
         rop.permission_id WHERE rop.role_id = ANY($1) AND p.content_type_id = $2 AND p.codename \
         = ANY($3) {having}) \"permission_subquery\" OFFSET 0)",
        pk = model.pk_column,
        table = model.db_table,
        cast = model.pk_cast.sql(),
    );
    let count = i64::try_from(remaining.len()).unwrap_or(i64::MAX);
    let pks: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(sql))
        .bind(&subject.roles)
        .bind(ctype)
        .bind(&remaining)
        .bind(count)
        .fetch_all(pool)
        .await?;
    Ok(Visible::Pks(pks))
}

/// authentik's `ObjectFilter.filter_queryset`, up to the final `exists()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectFilter {
    /// The global `view_<model>` permission: everything.
    All,
    /// The view's `owner_field`: objects the user owns.
    Owner,
    /// `get_objects_for_user(user, view_<model>)`. When `deny_if_empty`,
    /// a result with no rows (after the view's other filters) is
    /// `PermissionDenied` (403); outposts' internal service accounts get
    /// the empty list instead.
    Visible {
        visible: Visible,
        deny_if_empty: bool,
    },
}

/// `ObjectFilter().filter_queryset(request, queryset, view)`.
///
/// # Errors
///
/// As [`has_perm`] and [`get_objects_for_user`].
pub async fn object_filter(
    pool: &PgPool,
    subject: &Subject,
    model: &Model<'_>,
    owner_field: bool,
) -> Result<ObjectFilter, Error> {
    let permission = format!("{}.view_{}", model.app_label, model.model_name);
    if has_perm(pool, subject, &permission, None).await? {
        return Ok(ObjectFilter::All);
    }
    if owner_field {
        return Ok(ObjectFilter::Owner);
    }
    let visible = get_objects_for_user(pool, subject, &[&permission], model).await?;
    Ok(ObjectFilter::Visible {
        visible,
        deny_if_empty: !subject.is_internal_service_account(),
    })
}

/// `DjangoObjectPermissions.perms_map[method]`.
///
/// # Errors
///
/// [`Error::MethodNotAllowed`] for other methods.
pub fn required_permissions(method: &str, model: &Model<'_>) -> Result<Vec<String>, Error> {
    let action = match method {
        "GET" | "OPTIONS" | "HEAD" => return Ok(Vec::new()),
        "POST" => "add",
        "PUT" | "PATCH" => "change",
        "DELETE" => "delete",
        _ => return Err(Error::MethodNotAllowed),
    };
    Ok(vec![format!(
        "{}.{action}_{}",
        model.app_label, model.model_name
    )])
}

/// authentik's `ObjectPermissions.has_permission(request, view)`.
///
/// # Errors
///
/// [`Error::MethodNotAllowed`], or as [`has_perm`].
pub async fn has_permission(
    pool: &PgPool,
    subject: &Subject,
    method: &str,
    model: &Model<'_>,
    has_lookup: bool,
    allow_create_without_perm: bool,
) -> Result<bool, Error> {
    if has_lookup {
        return Ok(true);
    }
    let required = required_permissions(method, model)?;
    if allow_create_without_perm
        && required.len() == 1
        && required[0] == format!("{}.add_{}", model.app_label, model.model_name)
    {
        return Ok(true);
    }
    // `DjangoModelPermissions.has_permission`: authenticated users only.
    if subject.anonymous {
        return Ok(false);
    }
    let required: Vec<&str> = required.iter().map(String::as_str).collect();
    has_perms(pool, subject, &required, None).await
}

/// The outcome of an object-level check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Allow,
    /// 403.
    Deny,
    /// `Http404`.
    NotFound,
}

/// authentik's `ObjectPermissions.has_object_permission(request, view, obj)`;
/// `owner_matches` is `getattr(obj, view.owner_field) == request.user` when
/// the view has an owner field.
///
/// # Errors
///
/// [`Error::MethodNotAllowed`], or as [`has_perm`].
pub async fn has_object_permission(
    pool: &PgPool,
    subject: &Subject,
    method: &str,
    obj: &Object<'_>,
    owner_matches: bool,
) -> Result<Access, Error> {
    let perms = required_permissions(method, &obj.model)?;
    let perms: Vec<&str> = perms.iter().map(String::as_str).collect();
    // Global permissions rank higher than per-object ones.
    if has_perms(pool, subject, &perms, None).await? || owner_matches {
        return Ok(Access::Allow);
    }
    // `DjangoObjectPermissions.has_object_permission`.
    if has_perms(pool, subject, &perms, Some(obj)).await? {
        return Ok(Access::Allow);
    }
    if matches!(method, "GET" | "HEAD" | "OPTIONS") {
        return Ok(Access::NotFound);
    }
    let read = required_permissions("GET", &obj.model)?;
    let read: Vec<&str> = read.iter().map(String::as_str).collect();
    if !has_perms(pool, subject, &read, Some(obj)).await? {
        return Ok(Access::NotFound);
    }
    Ok(Access::Deny)
}

/// authentik's `@permission_required(obj_perm, global_perms)`; `obj` is
/// what `self.get_object()` finds (`None`: it raises `Http404`).
///
/// # Errors
///
/// As [`has_perm`].
pub async fn permission_required(
    pool: &PgPool,
    subject: &Subject,
    obj_perm: Option<&str>,
    obj: Option<&Object<'_>>,
    global_perms: &[&str],
) -> Result<Access, Error> {
    if let Some(perm) = obj_perm
        && !has_perm(pool, subject, perm, None).await?
    {
        let Some(obj) = obj else {
            return Ok(Access::NotFound);
        };
        if !has_perm(pool, subject, perm, Some(obj)).await? {
            return Ok(Access::Deny);
        }
    }
    for perm in global_perms {
        if !has_perm(pool, subject, perm, None).await? {
            return Ok(Access::Deny);
        }
    }
    Ok(Access::Allow)
}
