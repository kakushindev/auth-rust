//! `CertificateKeyPairViewSet`: `list` and `retrieve`.
//!
//! `authentik.crypto.api`, with `filter_backends = [SecretKeyFilter,
//! OrderingFilter, SearchFilter]` over
//! `CertificateKeyPair.objects.exclude(managed=MANAGED_KEY)`.
//! `CertificateKeyPairFilter` adds `has_key` and `key_type` (method
//! filters) after the generated `name` and `managed`.

use ak_rbac::{Access, Model, Object, PkCast};
use serde::Serialize;
use sqlx::Row as _;
use uuid::Uuid;

use crate::{
    Answer, Decline,
    drf::{self, ApiRequest, Context, User},
    filters::{self, Field, Kind, null_boolean},
    pagination::{Page, page_size},
    py::{QueryDict, UuidLookup, uuid_lookup},
    sql::{Bind, DjangoQuery},
    views::common::{django_object_filter, django_search, ordering, search_terms},
};

const ALLOW_LIST: &str = "GET, POST, HEAD, OPTIONS";
const ALLOW_DETAIL: &str = "GET, PUT, PATCH, DELETE, HEAD, OPTIONS";

const MODEL: Model<'static> = Model {
    app_label: "authentik_crypto",
    model_name: "certificatekeypair",
    ctype_app_label: "authentik_crypto",
    ctype_model: "certificatekeypair",
    pk_cast: PkCast::Uuid,
    db_table: "authentik_crypto_certificatekeypair",
    pk_column: "kp_uuid",
};

/// `authentik.crypto.apps.MANAGED_KEY`.
const MANAGED_KEY: &str = "goauthentik.io/crypto/jwt-managed";

/// `KeyType` values.
const KEY_TYPES: &[&str] = &["rsa", "ec", "dsa", "ed25519", "ed448"];

macro_rules! col {
    ($c:literal) => {
        concat!("\"authentik_crypto_certificatekeypair\".\"", $c, "\"")
    };
}

const FROM: &str = "\"authentik_crypto_certificatekeypair\"";
/// Django's select list, in model field order.
const SELECT: &str = concat!(
    col!("created"),
    ", ",
    col!("last_updated"),
    ", ",
    col!("managed"),
    ", ",
    col!("kp_uuid"),
    ", ",
    col!("name"),
    ", ",
    col!("certificate_data"),
    ", ",
    col!("key_data"),
    ", ",
    col!("key_type"),
    ", ",
    col!("cert_expiry"),
    ", ",
    col!("cert_subject"),
    ", ",
    col!("fingerprint_sha256"),
    ", ",
    col!("fingerprint_sha1"),
    ", ",
    col!("kid"),
);

/// The generated `Meta.fields` filters.
const FILTERS: &[Field] = &[
    Field {
        name: "name",
        kind: Kind::Char {
            column: col!("name"),
        },
    },
    Field {
        name: "managed",
        kind: Kind::Char {
            column: col!("managed"),
        },
    },
];

/// Readable serializer sources (method and write-only fields excluded).
const ORDERING: &[(&str, &str)] = &[
    ("pk", col!("kp_uuid")),
    ("name", col!("name")),
    ("fingerprint_sha256", col!("fingerprint_sha256")),
    ("fingerprint_sha1", col!("fingerprint_sha1")),
    ("cert_expiry", col!("cert_expiry")),
    ("cert_subject", col!("cert_subject")),
    ("key_type", col!("key_type")),
    ("managed", col!("managed")),
];

/// `CertificateKeyPairSerializer`.
#[derive(Serialize)]
struct CertificateKeyPair {
    pk: String,
    name: String,
    fingerprint_sha256: Option<String>,
    fingerprint_sha1: Option<String>,
    cert_expiry: Option<String>,
    cert_subject: Option<String>,
    private_key_available: bool,
    key_type: Option<String>,
    certificate_download_url: String,
    private_key_download_url: String,
    managed: Option<String>,
}

fn keypair(row: &sqlx::postgres::PgRow) -> Result<CertificateKeyPair, Decline> {
    let db = |_| Decline("database error");
    let pk: Uuid = row.try_get(3).map_err(db)?;
    let key_data: String = row.try_get(6).map_err(db)?;
    let expiry: Option<chrono::DateTime<chrono::Utc>> = row.try_get(8).map_err(db)?;
    Ok(CertificateKeyPair {
        name: row.try_get(4).map_err(db)?,
        fingerprint_sha256: row.try_get(10).map_err(db)?,
        fingerprint_sha1: row.try_get(11).map_err(db)?,
        cert_expiry: expiry.map(drf::datetime),
        cert_subject: row.try_get(9).map_err(db)?,
        private_key_available: !key_data.is_empty(),
        key_type: row.try_get(7).map_err(db)?,
        certificate_download_url: format!(
            "/api/v3/crypto/certificatekeypairs/{pk}/view_certificate/?download"
        ),
        private_key_download_url: format!(
            "/api/v3/crypto/certificatekeypairs/{pk}/view_private_key/?download"
        ),
        managed: row.try_get(2).map_err(db)?,
        pk: pk.to_string(),
    })
}

/// `MultipleChoiceField.clean` for `key_type`: the first invalid value in
/// request order is the error.
fn key_types(query: &QueryDict) -> Result<Vec<String>, String> {
    let values = query.getlist("key_type");
    if let Some(bad) = values.iter().find(|v| !KEY_TYPES.contains(v)) {
        return Err(format!(
            "Select a valid choice. {bad} is not one of the available choices."
        ));
    }
    Ok(values.iter().map(|v| (*v).to_owned()).collect())
}

async fn filter_queryset(
    ctx: &Context<'_>,
    query: &QueryDict,
    user: &User,
    allow: &'static str,
) -> Result<Result<DjangoQuery, Answer>, Decline> {
    let mut qs = DjangoQuery::new(FROM, SELECT, &[]);
    let p = qs.bind(Bind::Text(MANAGED_KEY.to_owned()));
    qs.filter(format!(
        "NOT ({m} = {p} AND {m} IS NOT NULL)",
        m = col!("managed")
    ));
    // SecretKeyFilter → ObjectFilter, then the filterset.
    if let Err(answer) = django_object_filter(ctx, user, &MODEL, &mut qs, allow).await? {
        return Ok(Err(answer));
    }
    let (form, key_types) = match (
        filters::clean(ctx.pool, query, FILTERS).await?,
        key_types(query),
    ) {
        (Ok(form), Ok(key_types)) => (form, key_types),
        (form, key_types) => {
            let mut errors = form.err().unwrap_or_default();
            if let Err(message) = key_types {
                errors.push(("key_type", message));
            }
            return Ok(Err(drf::field_errors(&errors, allow)));
        }
    };
    form.apply(&mut qs);
    if null_boolean(query.get("has_key")) == Some(true) {
        let p = qs.bind(Bind::Text(String::new()));
        qs.filter(format!("NOT ({} = {p})", col!("key_data")));
    }
    if !key_types.is_empty() {
        let ps: Vec<String> = key_types
            .into_iter()
            .map(|v| qs.bind(Bind::Text(v)))
            .collect();
        qs.filter(format!("{} IN ({})", col!("key_type"), ps.join(", ")));
    }
    // OrderingFilter is applied at fetch time; SearchFilter last.
    let terms = match search_terms(query, allow) {
        Ok(terms) => terms,
        Err(answer) => return Ok(Err(answer)),
    };
    django_search(&mut qs, &[col!("name")], &terms);
    Ok(Ok(qs))
}

/// `GET /api/v3/crypto/certificatekeypairs/`.
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
        &[],
        &[concat!(
            "\"authentik_crypto_certificatekeypair\".\"name\"",
            " ASC"
        )],
    )?;
    let size = page_size(query, &tenant)?;
    let count = qs.count(ctx.pool).await?;
    let Some(page) = Page::choose(query, size, count)? else {
        return Ok(drf::detail(404, "Invalid page.", ALLOW_LIST));
    };
    let rows = qs.fetch(ctx.pool, &order, Some(page.slice())).await?;
    let results = rows.iter().map(keypair).collect::<Result<Vec<_>, _>>()?;
    Ok(drf::json(200, &page.response(results), ALLOW_LIST))
}

/// `GET /api/v3/crypto/certificatekeypairs/{pk}/`.
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
    let mut qs = match filter_queryset(ctx, query, &user, ALLOW_DETAIL).await? {
        Ok(qs) => qs,
        Err(answer) => return Ok(answer),
    };
    let uuid = match uuid_lookup(pk).map_err(|_| Decline("pk syntax"))? {
        UuidLookup::Valid(uuid) => uuid,
        UuidLookup::Invalid => return Ok(drf::detail(404, "Not found.", ALLOW_DETAIL)),
    };
    let p = qs.bind(Bind::Uuid(uuid));
    qs.filter(format!("{} = {p}", col!("kp_uuid")));
    let rows = qs.fetch(ctx.pool, &[], None).await?;
    let Some(row) = rows.first() else {
        return Ok(drf::detail(
            404,
            "No CertificateKeyPair matches the given query.",
            ALLOW_DETAIL,
        ));
    };
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
        Access::Allow => Ok(drf::json(200, &keypair(row)?, ALLOW_DETAIL)),
        Access::NotFound => Ok(drf::detail(404, "Not found.", ALLOW_DETAIL)),
        Access::Deny => Ok(drf::permission_denied(&user, ALLOW_DETAIL)),
    }
}
