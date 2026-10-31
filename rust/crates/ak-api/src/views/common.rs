//! Pieces every `ModelViewSet` on authentik's default backends shares.

use ak_rbac::{Model, ObjectFilter, Visible};

use crate::{
    Answer, Decline,
    drf::{self, Context, User},
    py::{QueryDict, search_smart_split, strip},
    sql::{Bind, QuerySet},
};

/// `forms.CharField.clean` (`strip=True`, `ProhibitNullCharactersValidator`).
pub(crate) fn char_field(value: Option<&str>) -> Result<String, &'static str> {
    let value = strip(value.unwrap_or_default());
    if value.contains('\0') {
        return Err("Null characters are not allowed.");
    }
    Ok(value.to_owned())
}

/// DRF `SearchFilter` (behind `QLSearch` without a license): the terms,
/// or the 400 its `CharField` validation raises for a NUL.
pub(crate) fn search_terms(query: &QueryDict, allow: &'static str) -> Result<Vec<String>, Answer> {
    let value = query.get("search").unwrap_or_default();
    if value.contains('\0') {
        return Err(drf::json(400, &["Null characters are not allowed."], allow));
    }
    Ok(search_smart_split(value))
}

/// `OrderingFilter`: the `ordering` terms whose field is a readable
/// serializer source (`fields` maps them to columns), else the view's
/// `ordering`. `Err` for a valid term that is not reproduced (`declined`).
pub(crate) fn ordering(
    query: &QueryDict,
    fields: &[(&str, &str)],
    declined: &[&str],
    default: &[&str],
) -> Result<Vec<String>, Decline> {
    let mut terms = Vec::new();
    if let Some(value) = query.get("ordering").filter(|v| !v.is_empty()) {
        for term in value.split(',').map(strip) {
            let (desc, field) = match term.strip_prefix('-') {
                Some(f) => (true, f),
                None => (false, term),
            };
            if declined.contains(&field) {
                return Err(Decline("ordering field"));
            }
            if let Some((_, column)) = fields.iter().find(|(name, _)| *name == field) {
                terms.push(format!("{column} {}", if desc { "DESC" } else { "ASC" }));
            }
        }
    }
    if terms.is_empty() {
        terms = default.iter().map(|t| (*t).to_owned()).collect();
    }
    Ok(terms)
}

/// `ObjectFilter.filter_queryset` on `qs` (after any earlier backend).
///
/// # Errors
///
/// `Ok(Err(answer))` is its `PermissionDenied`.
pub(crate) async fn object_filter(
    ctx: &Context<'_>,
    user: &User,
    model: &Model<'_>,
    qs: &mut QuerySet,
    allow: &'static str,
) -> Result<Result<(), Answer>, Decline> {
    let filter = ak_rbac::object_filter(ctx.pool, user.subject(), model, false)
        .await
        .map_err(|_| Decline("object filter raised"))?;
    if let ObjectFilter::Visible {
        visible,
        deny_if_empty,
    } = filter
    {
        if let Visible::Pks(pks) = visible {
            let p = qs.bind(Bind::TextArray(pks));
            qs.filter(format!("t.\"{}\"::text = ANY({p})", model.pk_column));
        }
        if deny_if_empty && !qs.exists(ctx.pool).await? {
            return Ok(Err(drf::detail(
                403,
                "You do not have permission to perform this action.",
                allow,
            )));
        }
    }
    Ok(Ok(()))
}
