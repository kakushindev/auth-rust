//! Multi-table inheritance: which Django class a row of a hierarchy is.
//!
//! Django stores a subclass row in the parent's table plus one row per
//! subclass table, linked by primary key. `InheritanceManager` with
//! `select_subclasses()` returns each object as its most-derived class;
//! [`resolve`] computes the same class from the tables.

use std::collections::{HashMap, HashSet};

use sqlx::{AssertSqlSafe, PgPool, Row as _};

use crate::generated::{INHERITANCE, INHERITANCE_ROOTS};

/// The Django class of every row of the hierarchy rooted at `root_table`,
/// keyed by the root primary key rendered as text.
///
/// # Errors
///
/// A database error, or an unknown root table.
pub async fn resolve(
    pool: &PgPool,
    root_table: &str,
) -> Result<HashMap<String, String>, sqlx::Error> {
    let root_class = INHERITANCE_ROOTS
        .iter()
        .find(|(table, _)| *table == root_table)
        .map(|(_, class)| *class)
        .ok_or_else(|| sqlx::Error::Protocol(format!("{root_table} is not an inheritance root")))?;
    let root_key: String = sqlx::query_scalar(
        "SELECT a.attname FROM pg_index i JOIN pg_attribute a
           ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
         WHERE i.indrelid = $1::regclass AND i.indisprimary",
    )
    .bind(root_table)
    .fetch_one(pool)
    .await?;

    let mut classes: HashMap<String, String> = HashMap::new();
    // Identifiers come from the generated inheritance graph and the catalog.
    for row in sqlx::query(AssertSqlSafe(format!(
        "SELECT \"{root_key}\"::text AS pk FROM \"{root_table}\""
    )))
    .fetch_all(pool)
    .await?
    {
        classes.insert(row.try_get("pk")?, root_class.to_owned());
    }

    // Walk down level by level, so a deeper subclass overrides its parent.
    let mut level: HashSet<&str> = HashSet::from([root_table]);
    while !level.is_empty() {
        let mut next = HashSet::new();
        for (child, parent, column, class) in INHERITANCE {
            if !level.contains(parent) {
                continue;
            }
            let exists: bool = sqlx::query_scalar("SELECT to_regclass($1) IS NOT NULL")
                .bind(format!("public.{child}"))
                .fetch_one(pool)
                .await?;
            if !exists {
                continue;
            }
            for row in sqlx::query(AssertSqlSafe(format!(
                "SELECT \"{column}\"::text AS pk FROM \"{child}\""
            )))
            .fetch_all(pool)
            .await?
            {
                classes.insert(row.try_get("pk")?, (*class).to_owned());
            }
            next.insert(*child);
        }
        level = next;
    }
    Ok(classes)
}
