//! django-filter `FilterSet` fields as `filterset_fields` generates them
//! for model fields, with Django 5.2's form-field validation messages.
//!
//! Validation runs over all fields first (errors keyed in declaration
//! order); only a valid form filters. Each kind names the Django form
//! field it reproduces.

use uuid::Uuid;

use crate::{
    Decline,
    py::{QueryDict, UuidLookup, strip, uuid_lookup},
    sql::{Bind, DjangoQuery, prep_for_like},
};

const NUL: &str = "Null characters are not allowed.";
const INVALID_CHOICE: &str =
    "Select a valid choice. That choice is not one of the available choices.";

/// A model field's generated filter.
#[derive(Debug, Clone, Copy)]
pub enum Kind {
    /// `CharFilter` (`forms.CharField`, `strip=True`), exact.
    Char { column: &'static str },
    /// `ChoiceFilter` (`forms.ChoiceField`, unstripped) for a non-null
    /// model field with `choices`, exact.
    Choice {
        column: &'static str,
        choices: &'static [&'static str],
    },
    /// `BooleanFilter` (`forms.NullBooleanField`, `NullBooleanSelect`),
    /// exact: declared on a plain `django_filters.FilterSet`.
    NullBoolean { column: &'static str },
    /// `BooleanFilter` with `BooleanWidget`, exact: what DRF's
    /// `DjangoFilterBackend` generates for a `BooleanField` in
    /// `filterset_fields` (`django_filters.rest_framework.FilterSet`).
    Boolean { column: &'static str },
    /// `UUIDFilter` (`forms.UUIDField`), exact.
    Uuid { column: &'static str },
    /// `ModelChoiceFilter` for a foreign key to a model with a UUID key:
    /// `target` is `(table, pk column)`.
    ForeignKeyUuid {
        column: &'static str,
        target: (&'static str, &'static str),
    },
    /// `CharFilter(lookup_expr="startswith")`.
    StartsWith { column: &'static str },
    /// `BooleanFilter(lookup_expr="isnull")` (`NullBooleanSelect`).
    IsNull { column: &'static str },
    /// `MultipleChoiceFilter`: `column = value` joined with OR and `.distinct()`;
    /// the first invalid value in request order is the error.
    MultipleChoice {
        column: &'static str,
        choices: &'static [&'static str],
    },
    /// A filter whose parsing is not ported: any non-empty value declines
    /// (`IsoDateTimeField` rejects a blank one).
    Declined,
    /// `ModelMultipleChoiceFilter(to_field_name=…)` across a many-to-many:
    /// `joins` (with their own aliases), `column = value` joined with OR,
    /// `.distinct()`; `target` is `(table, field column)`.
    ManyToManyField {
        joins: &'static [&'static str],
        column: &'static str,
        target: (&'static str, &'static str),
    },
    /// `ModelMultipleChoiceFilter` for a many-to-many to an integer-keyed
    /// model (the `id` `AutoField`).
    ManyToManyInt {
        join: &'static str,
        through_column: &'static str,
        target: (&'static str, &'static str),
    },
    /// `ModelMultipleChoiceFilter` for a many-to-many to a UUID-keyed
    /// model: Django joins `join`, ORs `through_column = pk` and applies
    /// `.distinct()`.
    ManyToManyUuid {
        join: &'static str,
        through_column: &'static str,
        target: (&'static str, &'static str),
    },
}

#[derive(Debug, Clone, Copy)]
pub struct Field {
    pub name: &'static str,
    pub kind: Kind,
}

/// A cleaned value that filters.
#[derive(Debug, Clone)]
enum Cleaned {
    Text(&'static str, String),
    Bool(&'static str, bool),
    Uuid(&'static str, Uuid),
    Many {
        join: &'static str,
        through_column: &'static str,
        values: Vec<Uuid>,
    },
    ManyInt {
        join: &'static str,
        through_column: &'static str,
        values: Vec<i32>,
    },
    StartsWith(&'static str, String),
    IsNull(&'static str, bool),
    AnyText {
        joins: &'static [&'static str],
        column: &'static str,
        values: Vec<String>,
    },
}

/// The form's cleaned data, ready to filter.
pub struct Form(Vec<Cleaned>);

/// `NullBooleanSelect.value_from_datadict` + `NullBooleanField.to_python`.
pub fn null_boolean(value: Option<&str>) -> Option<bool> {
    match value? {
        "True" | "true" | "2" => Some(true),
        "False" | "false" | "3" => Some(false),
        _ => None,
    }
}

/// `django_filters.widgets.BooleanWidget.value_from_datadict`.
pub fn boolean_widget(value: Option<&str>) -> Option<bool> {
    match value?.to_lowercase().as_str() {
        "1" | "true" => Some(true),
        "0" | "false" => Some(false),
        _ => None,
    }
}

/// `UUIDField.to_python`'s message (the model field's, which model choice
/// fields pass on).
fn not_a_uuid(value: &str) -> String {
    format!("\u{201c}{value}\u{201d} is not a valid UUID.")
}

async fn exists(pool: &sqlx::PgPool, target: (&str, &str), pk: Uuid) -> Result<bool, Decline> {
    sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT EXISTS (SELECT 1 FROM \"{}\" WHERE \"{}\" = $1)",
        target.0, target.1
    )))
    .bind(pk)
    .fetch_one(pool)
    .await
    .map_err(|_| Decline("database error"))
}

/// One problem per failing value, or a decline when several fail: Django
/// walks a `frozenset`, so which one it reports is hash order.
fn single<T>(mut failures: Vec<T>) -> Result<Option<T>, Decline> {
    match failures.len() {
        0 => Ok(None),
        1 => Ok(failures.pop()),
        _ => Err(Decline("several invalid choices")),
    }
}

/// `ModelMultipleChoiceField.clean` → `_check_values`.
async fn many(
    pool: &sqlx::PgPool,
    raw: &[&str],
    target: (&'static str, &'static str),
) -> Result<Result<Vec<Uuid>, String>, Decline> {
    let mut distinct: Vec<&str> = Vec::new();
    for value in raw {
        if !distinct.contains(value) {
            distinct.push(value);
        }
    }
    // First pass: NUL, then whether `filter(pk=value)` raises.
    let mut parsed = Vec::new();
    let mut failures = Vec::new();
    for value in &distinct {
        if value.contains('\0') {
            failures.push(NUL.to_owned());
            continue;
        }
        match uuid_lookup(value).map_err(|_| Decline("uuid syntax"))? {
            UuidLookup::Valid(uuid) => parsed.push((*value, uuid)),
            UuidLookup::Invalid => failures.push(not_a_uuid(value)),
        }
    }
    if let Some(message) = single(failures)? {
        return Ok(Err(message));
    }
    // Second pass: `str(val)` must be the canonical text of an existing row.
    let mut failures = Vec::new();
    for (value, uuid) in &parsed {
        if *value != uuid.to_string() || !exists(pool, target, *uuid).await? {
            failures.push(format!(
                "Select a valid choice. {value} is not one of the available choices."
            ));
        }
    }
    if let Some(message) = single(failures)? {
        return Ok(Err(message));
    }
    Ok(Ok(parsed.into_iter().map(|(_, uuid)| uuid).collect()))
}

/// `ModelMultipleChoiceField._check_values` on an integer key: `int()`
/// failing is "not a valid value", then `str(val)` must be an existing id.
async fn many_int(
    pool: &sqlx::PgPool,
    raw: &[&str],
    target: (&'static str, &'static str),
) -> Result<Result<Vec<i32>, String>, Decline> {
    let mut distinct: Vec<&str> = Vec::new();
    for value in raw {
        if !distinct.contains(value) {
            distinct.push(value);
        }
    }
    let mut parsed = Vec::new();
    let mut failures = Vec::new();
    for value in &distinct {
        if value.contains('\0') {
            failures.push(NUL.to_owned());
            continue;
        }
        match crate::py::py_int(value).map_err(|_| Decline("int syntax"))? {
            None => failures.push(format!("\u{201c}{value}\u{201d} is not a valid value.")),
            Some(n) => parsed.push((*value, crate::py::int4(n).ok_or(Decline("int range"))?)),
        }
    }
    if let Some(message) = single(failures)? {
        return Ok(Err(message));
    }
    let ids: Vec<i32> = parsed.iter().map(|(_, id)| *id).collect();
    let found: Vec<i32> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT \"{}\" FROM \"{}\" WHERE \"{}\" = ANY($1)",
        target.1, target.0, target.1
    )))
    .bind(&ids)
    .fetch_all(pool)
    .await
    .map_err(|_| Decline("database error"))?;
    let failures: Vec<String> = parsed
        .iter()
        .filter(|(value, id)| *value != id.to_string() || !found.contains(id))
        .map(|(value, _)| {
            format!("Select a valid choice. {value} is not one of the available choices.")
        })
        .collect();
    if let Some(message) = single(failures)? {
        return Ok(Err(message));
    }
    Ok(Ok(ids))
}

/// `ModelMultipleChoiceField._check_values` with a `to_field_name`: no
/// value can make the first pass raise (only NUL does), the second checks
/// that a row has each value.
async fn many_field(
    pool: &sqlx::PgPool,
    raw: &[&str],
    target: (&'static str, &'static str),
) -> Result<Result<Vec<String>, String>, Decline> {
    let mut distinct: Vec<&str> = Vec::new();
    for value in raw {
        if !distinct.contains(value) {
            distinct.push(value);
        }
    }
    if distinct.iter().any(|v| v.contains('\0')) {
        // Only NUL values fail the first pass; one message whichever it is.
        return Ok(Err(NUL.to_owned()));
    }
    let found: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT \"{}\"::text FROM \"{}\" WHERE \"{}\" = ANY($1)",
        target.1, target.0, target.1
    )))
    .bind(distinct.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>())
    .fetch_all(pool)
    .await
    .map_err(|_| Decline("database error"))?;
    let failures: Vec<String> = distinct
        .iter()
        .filter(|v| !found.iter().any(|f| f == *v))
        .map(|v| format!("Select a valid choice. {v} is not one of the available choices."))
        .collect();
    if let Some(message) = single(failures)? {
        return Ok(Err(message));
    }
    Ok(Ok(distinct.into_iter().map(str::to_owned).collect()))
}

/// `FilterSet(data=request.query_params).form.is_valid()`.
///
/// # Errors
///
/// `Ok(Err(errors))` is the 400 body, in field order.
pub async fn clean(
    pool: &sqlx::PgPool,
    query: &QueryDict,
    fields: &[Field],
) -> Result<Result<Form, Vec<(&'static str, String)>>, Decline> {
    let mut cleaned = Vec::new();
    let mut errors = Vec::new();
    for field in fields {
        let raw = query.get(field.name);
        match field.kind {
            Kind::Char { column } => {
                let value = strip(raw.unwrap_or_default());
                if value.contains('\0') {
                    errors.push((field.name, NUL.to_owned()));
                } else if !value.is_empty() {
                    cleaned.push(Cleaned::Text(column, value.to_owned()));
                }
            }
            Kind::Choice { column, choices } => {
                let Some(value) = raw.filter(|v| !v.is_empty()) else {
                    continue;
                };
                if choices.contains(&value) {
                    cleaned.push(Cleaned::Text(column, value.to_owned()));
                } else {
                    errors.push((
                        field.name,
                        format!(
                            "Select a valid choice. {value} is not one of the available choices."
                        ),
                    ));
                }
            }
            Kind::NullBoolean { column } => {
                if let Some(value) = null_boolean(raw) {
                    cleaned.push(Cleaned::Bool(column, value));
                }
            }
            Kind::IsNull { column } => {
                if let Some(value) = null_boolean(raw) {
                    cleaned.push(Cleaned::IsNull(column, value));
                }
            }
            Kind::StartsWith { column } => {
                let value = strip(raw.unwrap_or_default());
                if value.contains('\0') {
                    errors.push((field.name, NUL.to_owned()));
                } else if !value.is_empty() {
                    cleaned.push(Cleaned::StartsWith(column, value.to_owned()));
                }
            }
            Kind::Declined => {
                if !raw.unwrap_or_default().is_empty() {
                    return Err(Decline("filter not ported"));
                }
            }
            Kind::MultipleChoice { column, choices } => {
                let values = query.getlist(field.name);
                if values.is_empty() {
                    continue;
                }
                if let Some(bad) = values.iter().find(|v| !choices.contains(v)) {
                    errors.push((
                        field.name,
                        format!(
                            "Select a valid choice. {bad} is not one of the available choices."
                        ),
                    ));
                    continue;
                }
                let mut distinct: Vec<String> = Vec::new();
                for v in values {
                    if !distinct.iter().any(|d| d == v) {
                        distinct.push(v.to_owned());
                    }
                }
                cleaned.push(Cleaned::AnyText {
                    joins: &[],
                    column,
                    values: distinct,
                });
            }
            Kind::ManyToManyInt {
                join,
                through_column,
                target,
            } => {
                let values = query.getlist(field.name);
                if values.is_empty() {
                    continue;
                }
                match many_int(pool, &values, target).await? {
                    Ok(values) => cleaned.push(Cleaned::ManyInt {
                        join,
                        through_column,
                        values,
                    }),
                    Err(message) => errors.push((field.name, message)),
                }
            }
            Kind::ManyToManyField {
                joins,
                column,
                target,
            } => {
                let values = query.getlist(field.name);
                if values.is_empty() {
                    continue;
                }
                match many_field(pool, &values, target).await? {
                    Ok(values) => cleaned.push(Cleaned::AnyText {
                        joins,
                        column,
                        values,
                    }),
                    Err(message) => errors.push((field.name, message)),
                }
            }
            Kind::Boolean { column } => {
                if let Some(value) = boolean_widget(raw) {
                    cleaned.push(Cleaned::Bool(column, value));
                }
            }
            Kind::Uuid { column } => {
                let value = strip(raw.unwrap_or_default());
                if value.is_empty() {
                    continue;
                }
                match uuid_lookup(value).map_err(|_| Decline("uuid syntax"))? {
                    UuidLookup::Valid(uuid) => cleaned.push(Cleaned::Uuid(column, uuid)),
                    UuidLookup::Invalid => {
                        errors.push((field.name, "Enter a valid UUID.".to_owned()));
                    }
                }
            }
            Kind::ForeignKeyUuid { column, target } => {
                let Some(value) = raw.filter(|v| !v.is_empty()) else {
                    continue;
                };
                if value.contains('\0') {
                    errors.push((field.name, NUL.to_owned()));
                    continue;
                }
                match uuid_lookup(value).map_err(|_| Decline("uuid syntax"))? {
                    UuidLookup::Invalid => errors.push((field.name, not_a_uuid(value))),
                    UuidLookup::Valid(uuid) => {
                        if exists(pool, target, uuid).await? {
                            cleaned.push(Cleaned::Uuid(column, uuid));
                        } else {
                            errors.push((field.name, INVALID_CHOICE.to_owned()));
                        }
                    }
                }
            }
            Kind::ManyToManyUuid {
                join,
                through_column,
                target,
            } => {
                let values = query.getlist(field.name);
                if values.is_empty() {
                    continue;
                }
                match many(pool, &values, target).await? {
                    Ok(uuids) => cleaned.push(Cleaned::Many {
                        join,
                        through_column,
                        values: uuids,
                    }),
                    Err(message) => errors.push((field.name, message)),
                }
            }
        }
    }
    Ok(if errors.is_empty() {
        Ok(Form(cleaned))
    } else {
        Err(errors)
    })
}

impl Form {
    /// `FilterSet.qs` on `qs`; returns whether `.distinct()` was applied.
    pub fn apply(&self, qs: &mut DjangoQuery) -> bool {
        let mut distinct = false;
        for value in &self.0 {
            match value {
                Cleaned::Text(column, text) => {
                    let p = qs.bind(Bind::Text(text.clone()));
                    qs.filter(format!("{column} = {p}"));
                }
                Cleaned::Bool(column, b) => {
                    qs.filter(if *b {
                        (*column).to_owned()
                    } else {
                        format!("NOT {column}")
                    });
                }
                Cleaned::Uuid(column, uuid) => {
                    let p = qs.bind(Bind::Uuid(*uuid));
                    qs.filter(format!("{column} = {p}"));
                }
                Cleaned::ManyInt {
                    join,
                    through_column,
                    values,
                } => {
                    qs.join(join);
                    let ors: Vec<String> = values
                        .iter()
                        .map(|id| {
                            let p = qs.bind(Bind::Int(*id));
                            format!("{through_column} = {p}")
                        })
                        .collect();
                    qs.filter(if ors.len() == 1 {
                        ors.join("")
                    } else {
                        format!("({})", ors.join(" OR "))
                    });
                    qs.distinct();
                    distinct = true;
                }
                Cleaned::StartsWith(column, prefix) => {
                    let p = qs.bind(Bind::Text(format!("{}%", prep_for_like(prefix))));
                    qs.filter(format!("{column}::text LIKE {p}"));
                }
                Cleaned::IsNull(column, null) => {
                    qs.filter(format!(
                        "{column} IS {}NULL",
                        if *null { "" } else { "NOT " }
                    ));
                }
                Cleaned::AnyText {
                    joins,
                    column,
                    values,
                } => {
                    for join in *joins {
                        qs.join(join);
                    }
                    let ors: Vec<String> = values
                        .iter()
                        .map(|v| {
                            let p = qs.bind(Bind::Text(v.clone()));
                            format!("{column} = {p}")
                        })
                        .collect();
                    qs.filter(if ors.len() == 1 {
                        ors.join("")
                    } else {
                        format!("({})", ors.join(" OR "))
                    });
                    qs.distinct();
                    distinct = true;
                }
                Cleaned::Many {
                    join,
                    through_column,
                    values,
                } => {
                    qs.join(join);
                    let ors: Vec<String> = values
                        .iter()
                        .map(|uuid| {
                            let p = qs.bind(Bind::Uuid(*uuid));
                            format!("{through_column} = {p}")
                        })
                        .collect();
                    qs.filter(if ors.len() == 1 {
                        ors.join("")
                    } else {
                        format!("({})", ors.join(" OR "))
                    });
                    qs.distinct();
                    distinct = true;
                }
            }
        }
        distinct
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn several_failures_decline() {
        assert_eq!(single::<u8>(vec![]), Ok(None));
        assert_eq!(single(vec![1_u8]), Ok(Some(1_u8)));
        assert_eq!(
            single(vec![1_u8, 2_u8]),
            Err(Decline("several invalid choices"))
        );
    }

    #[test]
    fn widgets_map_like_django_filter() {
        assert_eq!(boolean_widget(Some("TRUE")), Some(true));
        assert_eq!(boolean_widget(Some("1")), Some(true));
        assert_eq!(boolean_widget(Some("0")), Some(false));
        assert_eq!(boolean_widget(Some("2")), None);
        assert_eq!(null_boolean(Some("2")), Some(true));
        assert_eq!(null_boolean(Some("1")), None);
    }

    #[test]
    fn uuid_message_matches_django() {
        assert_eq!(
            not_a_uuid("bogus"),
            "\u{201c}bogus\u{201d} is not a valid UUID."
        );
    }
}
