//! Machine-readable fingerprint of the authentik `PostgreSQL` schema contract.
//!
//! The upstream schema is immutable for the Rust implementation. A snapshot
//! captures every user-visible catalog object (relations, columns in logical
//! order, constraints, indexes, sequences, types, functions, triggers, views,
//! extensions and the Django migration history) in a canonical form, so two
//! databases can be compared and any drift reported precisely.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::{AssertSqlSafe, PgPool, Row as _, postgres::PgRow};

/// Schemas that belong to `PostgreSQL` itself.
const USER_NAMESPACES: &str = "n.nspname not in ('pg_catalog', 'information_schema') \
     and n.nspname not like 'pg\\_toast%' and n.nspname not like 'pg\\_temp%'";

/// Objects created by an extension are versioned by the extension, not by authentik.
const NOT_FROM_EXTENSION: &str = "not exists (select 1 from pg_depend dep \
     where dep.objid = $OID and dep.deptype = 'e')";

type Section = BTreeMap<String, Value>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// sha256 over the canonical JSON of `sections`.
    pub fingerprint: String,
    pub section_fingerprints: BTreeMap<String, String>,
    pub sections: BTreeMap<String, Section>,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SectionDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<(String, Value, Value)>,
}

impl SectionDiff {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

fn sha256_hex(value: &impl Serialize) -> String {
    let bytes = serde_json::to_vec(value).expect("snapshot sections are always serializable");
    hex::encode(Sha256::digest(bytes))
}

impl Snapshot {
    pub fn from_sections(sections: BTreeMap<String, Section>) -> Self {
        let section_fingerprints = sections
            .iter()
            .map(|(name, section)| (name.clone(), sha256_hex(section)))
            .collect();
        Self {
            fingerprint: sha256_hex(&sections),
            section_fingerprints,
            sections,
        }
    }

    /// Recompute fingerprints from the sections, so a hand-edited or
    /// truncated baseline cannot pass verification.
    pub fn is_consistent(&self) -> bool {
        *self == Self::from_sections(self.sections.clone())
    }

    /// Differences from `self` (baseline) to `other` (candidate), by section.
    pub fn diff(&self, other: &Self) -> BTreeMap<String, SectionDiff> {
        let empty = Section::new();
        let names: std::collections::BTreeSet<&String> =
            self.sections.keys().chain(other.sections.keys()).collect();
        let mut out = BTreeMap::new();
        for name in names {
            let before = self.sections.get(name).unwrap_or(&empty);
            let after = other.sections.get(name).unwrap_or(&empty);
            let mut diff = SectionDiff::default();
            for (key, value) in before {
                match after.get(key) {
                    None => diff.removed.push(key.clone()),
                    Some(v) if v != value => {
                        diff.changed.push((key.clone(), value.clone(), v.clone()));
                    }
                    Some(_) => {}
                }
            }
            diff.added = after
                .keys()
                .filter(|k| !before.contains_key(*k))
                .cloned()
                .collect();
            if !diff.is_empty() {
                out.insert(name.clone(), diff);
            }
        }
        out
    }
}

fn text(row: &PgRow, idx: usize) -> Result<String, sqlx::Error> {
    Ok(row.try_get::<Option<String>, _>(idx)?.unwrap_or_default())
}

/// Run `sql` and key each row by its first `key_cols` columns joined with
/// `.`; the remaining columns become a JSON object using `value_names`.
async fn collect(
    pool: &PgPool,
    sql: &str,
    key_cols: usize,
    value_names: &[&str],
) -> Result<Section, sqlx::Error> {
    // Every statement is built from constant fragments in this module.
    let rows = sqlx::query(AssertSqlSafe(sql.to_owned()))
        .fetch_all(pool)
        .await?;
    let mut section = Section::new();
    for row in rows {
        let key = (0..key_cols)
            .map(|i| text(&row, i))
            .collect::<Result<Vec<_>, _>>()?
            .join(".");
        let mut obj = serde_json::Map::new();
        for (offset, name) in value_names.iter().enumerate() {
            obj.insert(
                (*name).to_owned(),
                Value::String(text(&row, key_cols + offset)?),
            );
        }
        section.insert(key, Value::Object(obj));
    }
    Ok(section)
}

fn ext(oid: &str) -> String {
    NOT_FROM_EXTENSION.replace("$OID", oid)
}

/// Capture a snapshot of every user schema in the connected database.
pub async fn snapshot(pool: &PgPool) -> Result<Snapshot, sqlx::Error> {
    let mut sections = BTreeMap::new();

    sections.insert(
        "schemas".to_owned(),
        collect(
            pool,
            &format!(
                "select n.nspname::text, '' from pg_namespace n where {USER_NAMESPACES} \
                 and {}",
                ext("n.oid")
            ),
            1,
            &[],
        )
        .await?,
    );

    sections.insert(
        "relations".to_owned(),
        collect(
            pool,
            &format!(
                "select n.nspname::text, c.relname::text, c.relkind::text, \
                 c.relpersistence::text, coalesce(am.amname::text, '') \
                 from pg_class c join pg_namespace n on n.oid = c.relnamespace \
                 left join pg_am am on am.oid = c.relam \
                 where c.relkind in ('r', 'p', 'v', 'm', 'S', 'f') and {USER_NAMESPACES} and {}",
                ext("c.oid")
            ),
            2,
            &["kind", "persistence", "access_method"],
        )
        .await?,
    );

    // Logical position (ignoring dropped columns) rather than attnum, so a
    // restored dump and a migrated database compare equal.
    sections.insert(
        "columns".to_owned(),
        collect(
            pool,
            &format!(
                "select n.nspname::text, c.relname::text, a.attname::text, \
                 (row_number() over (partition by a.attrelid order by a.attnum))::text, \
                 format_type(a.atttypid, a.atttypmod), a.attnotnull::text, \
                 coalesce(pg_get_expr(d.adbin, d.adrelid), ''), a.attidentity::text, \
                 a.attgenerated::text, \
                 case when a.attcollation in (0, 100) then '' else co.collname::text end \
                 from pg_attribute a join pg_class c on c.oid = a.attrelid \
                 join pg_namespace n on n.oid = c.relnamespace \
                 left join pg_attrdef d on d.adrelid = a.attrelid and d.adnum = a.attnum \
                 left join pg_collation co on co.oid = a.attcollation \
                 where a.attnum > 0 and not a.attisdropped \
                 and c.relkind in ('r', 'p', 'v', 'm', 'f') and {USER_NAMESPACES} and {}",
                ext("c.oid")
            ),
            3,
            &[
                "position",
                "type",
                "not_null",
                "default",
                "identity",
                "generated",
                "collation",
            ],
        )
        .await?,
    );

    sections.insert(
        "constraints".to_owned(),
        collect(
            pool,
            &format!(
                "select n.nspname::text, coalesce(c.relname::text, t.typname::text), \
                 con.conname::text, con.contype::text, pg_get_constraintdef(con.oid, true), \
                 con.condeferrable::text, con.condeferred::text \
                 from pg_constraint con join pg_namespace n on n.oid = con.connamespace \
                 left join pg_class c on c.oid = con.conrelid \
                 left join pg_type t on t.oid = con.contypid \
                 where {USER_NAMESPACES} and {}",
                ext("con.oid")
            ),
            3,
            &["type", "definition", "deferrable", "deferred"],
        )
        .await?,
    );

    sections.insert(
        "indexes".to_owned(),
        collect(
            pool,
            &format!(
                "select n.nspname::text, i.relname::text, pg_get_indexdef(i.oid) \
                 from pg_index x join pg_class i on i.oid = x.indexrelid \
                 join pg_namespace n on n.oid = i.relnamespace \
                 where {USER_NAMESPACES} and {}",
                ext("i.oid")
            ),
            2,
            &["definition"],
        )
        .await?,
    );

    sections.insert(
        "sequences".to_owned(),
        collect(
            pool,
            &format!(
                "select n.nspname::text, c.relname::text, format_type(s.seqtypid, null), \
                 s.seqstart::text, s.seqincrement::text, s.seqmin::text, s.seqmax::text, \
                 s.seqcache::text, s.seqcycle::text, \
                 coalesce((select oc.relname || '.' || oa.attname from pg_depend dep \
                   join pg_class oc on oc.oid = dep.refobjid \
                   join pg_attribute oa on oa.attrelid = dep.refobjid and oa.attnum = dep.refobjsubid \
                   where dep.objid = c.oid and dep.deptype in ('a', 'i') \
                   and dep.classid = 'pg_class'::regclass limit 1), '') \
                 from pg_sequence s join pg_class c on c.oid = s.seqrelid \
                 join pg_namespace n on n.oid = c.relnamespace \
                 where {USER_NAMESPACES} and {}",
                ext("c.oid")
            ),
            2,
            &[
                "type", "start", "increment", "min", "max", "cache", "cycle", "owned_by",
            ],
        )
        .await?,
    );

    sections.insert(
        "types".to_owned(),
        collect(
            pool,
            &format!(
                "select n.nspname::text, t.typname::text, t.typtype::text, \
                 coalesce((select string_agg(e.enumlabel, ',' order by e.enumsortorder) \
                   from pg_enum e where e.enumtypid = t.oid), ''), \
                 case when t.typtype = 'd' then format_type(t.typbasetype, t.typtypmod) else '' end, \
                 t.typnotnull::text, coalesce(t.typdefault, '') \
                 from pg_type t join pg_namespace n on n.oid = t.typnamespace \
                 where t.typtype in ('e', 'd', 'c', 'r', 'm') \
                 and (t.typtype <> 'c' or (select c.relkind from pg_class c \
                   where c.oid = t.typrelid) = 'c') \
                 and {USER_NAMESPACES} and {}",
                ext("t.oid")
            ),
            2,
            &["kind", "enum_labels", "base_type", "not_null", "default"],
        )
        .await?,
    );

    sections.insert(
        "functions".to_owned(),
        collect(
            pool,
            &format!(
                "select n.nspname::text, p.proname::text, \
                 pg_get_function_identity_arguments(p.oid), p.prokind::text, \
                 case when p.prokind in ('f', 'p', 'w') then pg_get_functiondef(p.oid) else '' end \
                 from pg_proc p join pg_namespace n on n.oid = p.pronamespace \
                 where {USER_NAMESPACES} and {}",
                ext("p.oid")
            ),
            3,
            &["kind", "definition"],
        )
        .await?,
    );

    sections.insert(
        "triggers".to_owned(),
        collect(
            pool,
            &format!(
                "select n.nspname::text, c.relname::text, tg.tgname::text, \
                 pg_get_triggerdef(tg.oid, true), tg.tgenabled::text \
                 from pg_trigger tg join pg_class c on c.oid = tg.tgrelid \
                 join pg_namespace n on n.oid = c.relnamespace \
                 where not tg.tgisinternal and {USER_NAMESPACES}"
            ),
            3,
            &["definition", "enabled"],
        )
        .await?,
    );

    sections.insert(
        "views".to_owned(),
        collect(
            pool,
            &format!(
                "select n.nspname::text, c.relname::text, pg_get_viewdef(c.oid, true) \
                 from pg_class c join pg_namespace n on n.oid = c.relnamespace \
                 where c.relkind in ('v', 'm') and {USER_NAMESPACES} and {}",
                ext("c.oid")
            ),
            2,
            &["definition"],
        )
        .await?,
    );

    sections.insert(
        "extensions".to_owned(),
        collect(
            pool,
            "select e.extname::text, e.extversion::text, n.nspname::text \
             from pg_extension e join pg_namespace n on n.oid = e.extnamespace",
            1,
            &["version", "schema"],
        )
        .await?,
    );

    sections.insert("django_migrations".to_owned(), migrations(pool).await?);

    Ok(Snapshot::from_sections(sections))
}

/// The applied Django migration identifiers, per schema (django-tenants keeps
/// one `django_migrations` table per tenant schema).
async fn migrations(pool: &PgPool) -> Result<Section, sqlx::Error> {
    let schemas: Vec<String> = sqlx::query_scalar(
        "select table_schema::text from information_schema.tables \
         where table_name = 'django_migrations' order by 1",
    )
    .fetch_all(pool)
    .await?;
    let mut section = Section::new();
    for schema in schemas {
        let quoted = format!("\"{}\"", schema.replace('"', "\"\""));
        // The schema name comes from the catalog and is quoted as an identifier.
        let rows: Vec<(String, String)> = sqlx::query_as(AssertSqlSafe(format!(
            "select app::text, name::text from {quoted}.django_migrations"
        )))
        .fetch_all(pool)
        .await?;
        for (app, name) in rows {
            section.insert(format!("{schema}.{app}.{name}"), json!({}));
        }
    }
    Ok(section)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(columns: &[(&str, &str)]) -> Snapshot {
        let section = columns
            .iter()
            .map(|(k, t)| ((*k).to_owned(), json!({ "type": t })))
            .collect();
        Snapshot::from_sections(BTreeMap::from([("columns".to_owned(), section)]))
    }

    #[test]
    fn identical_snapshots_have_no_diff() {
        let a = snap(&[("public.t.id", "integer")]);
        assert!(a.diff(&a.clone()).is_empty());
        assert!(a.is_consistent());
    }

    #[test]
    fn diff_reports_added_removed_changed() {
        let a = snap(&[("public.t.id", "integer"), ("public.t.name", "text")]);
        let b = snap(&[("public.t.id", "bigint"), ("public.t.extra", "text")]);
        assert_ne!(a.fingerprint, b.fingerprint);
        let diff = a.diff(&b);
        let cols = &diff["columns"];
        assert_eq!(cols.added, vec!["public.t.extra"]);
        assert_eq!(cols.removed, vec!["public.t.name"]);
        assert_eq!(cols.changed.len(), 1);
        assert_eq!(cols.changed[0].0, "public.t.id");
    }

    #[test]
    fn tampered_baseline_is_inconsistent() {
        let mut a = snap(&[("public.t.id", "integer")]);
        a.sections
            .get_mut("columns")
            .expect("columns")
            .insert("public.t.x".to_owned(), json!({}));
        assert!(!a.is_consistent());
    }
}
