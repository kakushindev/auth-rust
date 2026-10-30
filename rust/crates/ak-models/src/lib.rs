//! Row models for authentik's identity tables (milestone M4).
//!
//! Every type in [`generated`] mirrors one table of the pinned 2026.2.7
//! schema column for column, with the exact Postgres type (jsonb as its
//! exact text, so writes do not renumber or reformat it). The [`Row`]
//! helpers read and write whole rows; [`inheritance`] resolves a row of a
//! multi-table-inheritance hierarchy to its most-derived Django class, as
//! `select_subclasses()` does.
//!
//! This is the storage layer only: typed domain models are built on it.

pub mod generated;
pub mod inheritance;

use sqlx::{
    AssertSqlSafe, Executor, Postgres,
    postgres::{PgArguments, PgRow},
    query::Query,
};

/// A table row with its full column list, in table order.
pub trait Row: for<'r> sqlx::FromRow<'r, PgRow> + Send + Sync + Unpin + Sized {
    /// Table name.
    const TABLE: &'static str;
    /// Every column, in table order.
    const COLUMNS: &'static [&'static str];
    /// Primary key columns.
    const PRIMARY_KEY: &'static [&'static str];
    /// False for materialized views, which Postgres maintains.
    const WRITABLE: bool;
    /// An identity column is `GENERATED ALWAYS`.
    const OVERRIDING_SYSTEM_VALUE: bool;

    /// Bind every column, in [`Self::COLUMNS`] order.
    fn bind_columns<'q>(
        &'q self,
        query: Query<'q, Postgres, PgArguments>,
    ) -> Query<'q, Postgres, PgArguments>;
}

fn quoted(columns: &[&str]) -> String {
    columns
        .iter()
        .map(|c| format!("\"{c}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

fn placeholders(n: usize) -> String {
    (1..=n)
        .map(|i| format!("${i}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `SELECT` statement for every row, ordered by primary key.
#[must_use]
pub fn select_sql<T: Row>() -> String {
    let order = if T::PRIMARY_KEY.is_empty() {
        String::new()
    } else {
        format!(" ORDER BY {}", quoted(T::PRIMARY_KEY))
    };
    format!("SELECT {} FROM \"{}\"{order}", quoted(T::COLUMNS), T::TABLE)
}

/// `INSERT` statement for one row.
#[must_use]
pub fn insert_sql<T: Row>() -> String {
    let overriding = if T::OVERRIDING_SYSTEM_VALUE {
        " OVERRIDING SYSTEM VALUE"
    } else {
        ""
    };
    format!(
        "INSERT INTO \"{}\" ({}){overriding} VALUES ({})",
        T::TABLE,
        quoted(T::COLUMNS),
        placeholders(T::COLUMNS.len())
    )
}

/// `UPDATE` statement writing every column of the row with this primary key.
/// The key columns are bound among the columns, so the key itself is
/// rewritten with its own value.
#[must_use]
pub fn update_sql<T: Row>() -> String {
    let key = T::PRIMARY_KEY
        .iter()
        .map(|k| {
            let index = T::COLUMNS
                .iter()
                .position(|c| c == k)
                .expect("primary key column is a column");
            format!("\"{k}\" = ${}", index + 1)
        })
        .collect::<Vec<_>>()
        .join(" AND ");
    format!(
        "UPDATE \"{}\" SET ({}) = ROW({}) WHERE {key}",
        T::TABLE,
        quoted(T::COLUMNS),
        placeholders(T::COLUMNS.len())
    )
}

/// Every row of the table.
///
/// # Errors
///
/// A database error, or a value that does not decode into its column type.
pub async fn fetch_all<'e, T: Row, E: Executor<'e, Database = Postgres>>(
    executor: E,
) -> Result<Vec<T>, sqlx::Error> {
    // Identifiers come from the generated schema constants only.
    sqlx::query_as::<_, T>(AssertSqlSafe(select_sql::<T>()))
        .fetch_all(executor)
        .await
}

/// Insert the row.
///
/// # Errors
///
/// A database error.
pub async fn insert<'e, T: Row, E: Executor<'e, Database = Postgres>>(
    row: &T,
    executor: E,
) -> Result<(), sqlx::Error> {
    // Identifiers come from the generated schema constants only.
    row.bind_columns(sqlx::query(AssertSqlSafe(insert_sql::<T>())))
        .execute(executor)
        .await?;
    Ok(())
}

/// Write every column of the row back, by primary key.
///
/// # Errors
///
/// A database error, or [`sqlx::Error::RowNotFound`] when no row has the key.
pub async fn update<'e, T: Row, E: Executor<'e, Database = Postgres>>(
    row: &T,
    executor: E,
) -> Result<(), sqlx::Error> {
    let done = row
        .bind_columns(sqlx::query(AssertSqlSafe(update_sql::<T>())))
        .execute(executor)
        .await?;
    if done.rows_affected() == 1 {
        Ok(())
    } else {
        Err(sqlx::Error::RowNotFound)
    }
}
