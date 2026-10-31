//! `authentik.brands.api.BrandViewSet`: `list` and `retrieve`.
//!
//! `filter_backends = [SecretKeyFilter, OrderingFilter, SearchFilter]`:
//! `SecretKeyFilter` is `ObjectFilter` then `DjangoFilterBackend` (the
//! secret-key bypass belongs to the outpost identity, which is declined).
//! Search covers a many-to-many, so DRF filters through `EXISTS`.

use ak_rbac::{Access, Model, Object, PkCast};
use serde::Serialize;
use serde_json::value::RawValue;
use sqlx::Row as _;
use uuid::Uuid;

use crate::{
    Answer, Decline,
    drf::{self, ApiRequest, Context, User},
    filters::{self, Field, Kind},
    json::render_jsonb,
    pagination::{Page, page_size},
    py::{QueryDict, UuidLookup, uuid_lookup},
    sql::{Bind, DjangoQuery},
    views::common::{django_object_filter, ordering, search_terms},
};

const ALLOW_LIST: &str = "GET, POST, HEAD, OPTIONS";
const ALLOW_DETAIL: &str = "GET, PUT, PATCH, DELETE, HEAD, OPTIONS";

const MODEL: Model<'static> = Model {
    app_label: "authentik_brands",
    model_name: "brand",
    ctype_app_label: "authentik_brands",
    ctype_model: "brand",
    pk_cast: PkCast::Uuid,
    db_table: "authentik_brands_brand",
    pk_column: "brand_uuid",
};

const T: &str = "\"authentik_brands_brand\"";
const FROM: &str = "\"authentik_brands_brand\"";
/// Django's select list (`attributes` read as text for rendering).
const SELECT: &str = "\"authentik_brands_brand\".\"brand_uuid\", \"authentik_brands_brand\".\"domain\", \
                      \"authentik_brands_brand\".\"default\", \
                      \"authentik_brands_brand\".\"branding_title\", \
                      \"authentik_brands_brand\".\"branding_logo\", \
                      \"authentik_brands_brand\".\"branding_favicon\", \
                      \"authentik_brands_brand\".\"branding_custom_css\", \
                      \"authentik_brands_brand\".\"branding_default_flow_background\", \
                      \"authentik_brands_brand\".\"flow_authentication_id\", \
                      \"authentik_brands_brand\".\"flow_invalidation_id\", \
                      \"authentik_brands_brand\".\"flow_recovery_id\", \
                      \"authentik_brands_brand\".\"flow_unenrollment_id\", \
                      \"authentik_brands_brand\".\"flow_user_settings_id\", \
                      \"authentik_brands_brand\".\"flow_device_code_id\", \
                      \"authentik_brands_brand\".\"default_application_id\", \
                      \"authentik_brands_brand\".\"web_certificate_id\", \
                      \"authentik_brands_brand\".\"attributes\"::text";

const JOIN_CLIENT_CERTIFICATES: &str = "INNER JOIN \"authentik_brands_brand_client_certificates\" ON \
                                        (\"authentik_brands_brand\".\"brand_uuid\" = \
                                        \"authentik_brands_brand_client_certificates\".\"brand_id\")";

const FLOW: (&str, &str) = ("authentik_flows_flow", "flow_uuid");
const CERTIFICATE: (&str, &str) = ("authentik_crypto_certificatekeypair", "kp_uuid");

macro_rules! col {
    ($c:literal) => {
        concat!("\"authentik_brands_brand\".\"", $c, "\"")
    };
}

/// `filterset_fields`, in declaration order.
const FILTERS: &[Field] = &[
    Field {
        name: "brand_uuid",
        kind: Kind::Uuid {
            column: col!("brand_uuid"),
        },
    },
    Field {
        name: "domain",
        kind: Kind::Char {
            column: col!("domain"),
        },
    },
    Field {
        name: "default",
        kind: Kind::Boolean {
            column: col!("default"),
        },
    },
    Field {
        name: "branding_title",
        kind: Kind::Char {
            column: col!("branding_title"),
        },
    },
    Field {
        name: "branding_logo",
        kind: Kind::Char {
            column: col!("branding_logo"),
        },
    },
    Field {
        name: "branding_favicon",
        kind: Kind::Char {
            column: col!("branding_favicon"),
        },
    },
    Field {
        name: "branding_default_flow_background",
        kind: Kind::Char {
            column: col!("branding_default_flow_background"),
        },
    },
    Field {
        name: "flow_authentication",
        kind: Kind::ForeignKeyUuid {
            column: col!("flow_authentication_id"),
            target: FLOW,
        },
    },
    Field {
        name: "flow_invalidation",
        kind: Kind::ForeignKeyUuid {
            column: col!("flow_invalidation_id"),
            target: FLOW,
        },
    },
    Field {
        name: "flow_recovery",
        kind: Kind::ForeignKeyUuid {
            column: col!("flow_recovery_id"),
            target: FLOW,
        },
    },
    Field {
        name: "flow_unenrollment",
        kind: Kind::ForeignKeyUuid {
            column: col!("flow_unenrollment_id"),
            target: FLOW,
        },
    },
    Field {
        name: "flow_user_settings",
        kind: Kind::ForeignKeyUuid {
            column: col!("flow_user_settings_id"),
            target: FLOW,
        },
    },
    Field {
        name: "flow_device_code",
        kind: Kind::ForeignKeyUuid {
            column: col!("flow_device_code_id"),
            target: FLOW,
        },
    },
    Field {
        name: "web_certificate",
        kind: Kind::ForeignKeyUuid {
            column: col!("web_certificate_id"),
            target: CERTIFICATE,
        },
    },
    Field {
        name: "client_certificates",
        kind: Kind::ManyToManyUuid {
            join: JOIN_CLIENT_CERTIFICATES,
            through_column: "\"authentik_brands_brand_client_certificates\".\"certificatekeypair_id\"",
            target: CERTIFICATE,
        },
    },
];

/// Readable serializer sources; `client_certificates` orders through a
/// duplicating join and is left to Django.
const ORDERING: &[(&str, &str)] = &[
    ("brand_uuid", col!("brand_uuid")),
    ("domain", col!("domain")),
    ("default", col!("default")),
    ("branding_title", col!("branding_title")),
    ("branding_logo", col!("branding_logo")),
    ("branding_favicon", col!("branding_favicon")),
    ("branding_custom_css", col!("branding_custom_css")),
    (
        "branding_default_flow_background",
        col!("branding_default_flow_background"),
    ),
    ("flow_authentication", col!("flow_authentication_id")),
    ("flow_invalidation", col!("flow_invalidation_id")),
    ("flow_recovery", col!("flow_recovery_id")),
    ("flow_unenrollment", col!("flow_unenrollment_id")),
    ("flow_user_settings", col!("flow_user_settings_id")),
    ("flow_device_code", col!("flow_device_code_id")),
    ("default_application", col!("default_application_id")),
    ("web_certificate", col!("web_certificate_id")),
    ("attributes", col!("attributes")),
];

/// `BrandSerializer`.
#[derive(Serialize)]
struct Brand {
    brand_uuid: String,
    domain: String,
    default: bool,
    branding_title: String,
    branding_logo: String,
    branding_favicon: String,
    branding_custom_css: String,
    branding_default_flow_background: String,
    flow_authentication: Option<String>,
    flow_invalidation: Option<String>,
    flow_recovery: Option<String>,
    flow_unenrollment: Option<String>,
    flow_user_settings: Option<String>,
    flow_device_code: Option<String>,
    default_application: Option<String>,
    web_certificate: Option<String>,
    client_certificates: Vec<String>,
    attributes: Box<RawValue>,
}

/// `SearchFilter` with `must_call_distinct`: `base.filter(Exists(…))`.
fn search(qs: &mut DjangoQuery, terms: &[String]) {
    if terms.is_empty() {
        return;
    }
    let mut groups = Vec::new();
    for term in terms {
        let ors: Vec<String> = [
            "U0.\"domain\"",
            "U0.\"branding_title\"",
            "U1.\"name\"",
            "U3.\"name\"",
        ]
        .iter()
        .map(|column| qs.icontains(column, term))
        .collect();
        groups.push(format!("({})", ors.join(" OR ")));
    }
    qs.filter(format!(
        "EXISTS(SELECT 1 AS \"a\" FROM \"authentik_brands_brand\" U0 LEFT OUTER JOIN \
         \"authentik_crypto_certificatekeypair\" U1 ON (U0.\"web_certificate_id\" = U1.\"kp_uuid\") \
         LEFT OUTER JOIN \"authentik_brands_brand_client_certificates\" U2 ON (U0.\"brand_uuid\" = \
         U2.\"brand_id\") LEFT OUTER JOIN \"authentik_crypto_certificatekeypair\" U3 ON \
         (U2.\"certificatekeypair_id\" = U3.\"kp_uuid\") WHERE ({} AND U0.\"brand_uuid\" = \
         ({T}.\"brand_uuid\")) LIMIT 1)",
        groups.join(" AND ")
    ));
}

async fn filter_queryset(
    ctx: &Context<'_>,
    query: &QueryDict,
    user: &User,
    allow: &'static str,
) -> Result<Result<DjangoQuery, Answer>, Decline> {
    let mut qs = DjangoQuery::new(FROM, SELECT, &[]);
    // SecretKeyFilter → ObjectFilter.
    if let Err(answer) = django_object_filter(ctx, user, &MODEL, &mut qs, allow).await? {
        return Ok(Err(answer));
    }
    // SecretKeyFilter → DjangoFilterBackend.
    match filters::clean(ctx.pool, query, FILTERS).await? {
        Ok(form) => {
            form.apply(&mut qs);
        }
        Err(errors) => return Ok(Err(drf::field_errors(&errors, allow))),
    }
    // OrderingFilter is applied at fetch time; SearchFilter last.
    let terms = match search_terms(query, allow) {
        Ok(terms) => terms,
        Err(answer) => return Ok(Err(answer)),
    };
    search(&mut qs, &terms);
    Ok(Ok(qs))
}

async fn serialize(ctx: &Context<'_>, row: &sqlx::postgres::PgRow) -> Result<Brand, Decline> {
    let db = |_| Decline("database error");
    let uuid = |i: usize| -> Result<Option<String>, Decline> {
        Ok(row
            .try_get::<Option<Uuid>, _>(i)
            .map_err(|_| Decline("database error"))?
            .map(|u| u.to_string()))
    };
    let brand_uuid: Uuid = row.try_get(0).map_err(db)?;
    let certificates: Vec<Uuid> = sqlx::query_scalar(
        "SELECT \"authentik_crypto_certificatekeypair\".\"kp_uuid\" FROM \
         \"authentik_crypto_certificatekeypair\" INNER JOIN \
         \"authentik_brands_brand_client_certificates\" ON \
         (\"authentik_crypto_certificatekeypair\".\"kp_uuid\" = \
         \"authentik_brands_brand_client_certificates\".\"certificatekeypair_id\") WHERE \
         \"authentik_brands_brand_client_certificates\".\"brand_id\" = $1",
    )
    .bind(brand_uuid)
    .fetch_all(ctx.pool)
    .await
    .map_err(db)?;
    let attributes: String = row.try_get(16).map_err(db)?;
    let attributes = RawValue::from_string(render_jsonb(&attributes)?)
        .map_err(|_| Decline("jsonb rendering"))?;
    Ok(Brand {
        brand_uuid: brand_uuid.to_string(),
        domain: row.try_get(1).map_err(db)?,
        default: row.try_get(2).map_err(db)?,
        branding_title: row.try_get(3).map_err(db)?,
        branding_logo: row.try_get(4).map_err(db)?,
        branding_favicon: row.try_get(5).map_err(db)?,
        branding_custom_css: row.try_get(6).map_err(db)?,
        branding_default_flow_background: row.try_get(7).map_err(db)?,
        flow_authentication: uuid(8)?,
        flow_invalidation: uuid(9)?,
        flow_recovery: uuid(10)?,
        flow_unenrollment: uuid(11)?,
        flow_user_settings: uuid(12)?,
        flow_device_code: uuid(13)?,
        default_application: uuid(14)?,
        web_certificate: uuid(15)?,
        client_certificates: certificates.iter().map(Uuid::to_string).collect(),
        attributes,
    })
}

/// `GET /api/v3/core/brands/`.
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
        &["client_certificates"],
        &[concat!("\"authentik_brands_brand\".\"domain\"", " ASC")],
    )?;
    let size = page_size(query, &tenant)?;
    let count = qs.count(ctx.pool).await?;
    let Some(page) = Page::choose(query, size, count)? else {
        return Ok(drf::detail(404, "Invalid page.", ALLOW_LIST));
    };
    let rows = qs.fetch(ctx.pool, &order, Some(page.slice())).await?;
    let mut results = Vec::with_capacity(rows.len());
    for row in &rows {
        results.push(serialize(ctx, row).await?);
    }
    Ok(drf::json(200, &page.response(results), ALLOW_LIST))
}

/// `GET /api/v3/core/brands/{pk}/`.
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
    qs.filter(format!("{T}.\"brand_uuid\" = {p}"));
    let rows = qs.fetch(ctx.pool, &[], None).await?;
    let row = match rows.as_slice() {
        [] => {
            return Ok(drf::detail(
                404,
                "No Brand matches the given query.",
                ALLOW_DETAIL,
            ));
        }
        [row] => row,
        _ => return Err(Decline("multiple objects")),
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
        Access::Allow => Ok(drf::json(200, &serialize(ctx, row).await?, ALLOW_DETAIL)),
        Access::NotFound => Ok(drf::detail(404, "Not found.", ALLOW_DETAIL)),
        Access::Deny => Ok(drf::permission_denied(&user, ALLOW_DETAIL)),
    }
}
