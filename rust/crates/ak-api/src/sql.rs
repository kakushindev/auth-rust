//! A queryset as the read API builds it: conditions with bound values, the
//! `.distinct()` and `.none()` flags, and the SQL Django's lookups use.

use std::fmt::Write as _;

use sqlx::{AssertSqlSafe, PgPool, Row as _, postgres::PgRow};
use uuid::Uuid;

use crate::Decline;

#[derive(Debug, Clone)]
pub enum Bind {
    Text(String),
    TextArray(Vec<String>),
    Uuid(Uuid),
    Int(i32),
}

/// One model's queryset.
#[derive(Debug, Clone)]
pub struct QuerySet {
    table: &'static str,
    pk: &'static str,
    conds: Vec<String>,
    binds: Vec<Bind>,
    distinct: bool,
    /// `.none()`.
    empty: bool,
}

/// Django's `connection.ops.prep_for_like_query`.
fn prep_for_like(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

impl QuerySet {
    /// `Model.objects.all()`; `table` is aliased as `t`.
    pub fn new(table: &'static str, pk: &'static str) -> Self {
        Self {
            table,
            pk,
            conds: Vec::new(),
            binds: Vec::new(),
            distinct: false,
            empty: false,
        }
    }

    /// The placeholder for a newly bound value.
    pub fn bind(&mut self, value: Bind) -> String {
        self.binds.push(value);
        format!("${}", self.binds.len())
    }

    /// `.filter(<raw SQL condition on alias t>)`.
    pub fn filter(&mut self, cond: String) {
        self.conds.push(cond);
    }

    /// `field__icontains=value`.
    pub fn icontains(&mut self, column: &str, value: &str) -> String {
        let p = self.bind(Bind::Text(format!("%{}%", prep_for_like(value))));
        format!("UPPER(t.\"{column}\"::text) LIKE UPPER({p})")
    }

    pub fn distinct(&mut self) {
        self.distinct = true;
    }

    pub fn none(&mut self) {
        self.empty = true;
    }

    pub fn is_none(&self) -> bool {
        self.empty
    }

    /// Replace the whole queryset, as a filter method returning a new
    /// queryset does (`user.all_roles()`).
    pub fn replace(&mut self, other: Self) {
        *self = other;
    }

    fn where_sql(&self) -> String {
        if self.conds.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", self.conds.join(" AND "))
        }
    }

    fn query(
        &self,
        sql: String,
    ) -> sqlx::query::Query<'static, sqlx::Postgres, sqlx::postgres::PgArguments> {
        let mut query = sqlx::query(AssertSqlSafe(sql));
        for bind in &self.binds {
            query = match bind {
                Bind::Text(v) => query.bind(v.clone()),
                Bind::TextArray(v) => query.bind(v.clone()),
                Bind::Uuid(v) => query.bind(*v),
                Bind::Int(v) => query.bind(*v),
            };
        }
        query
    }

    /// `.count()`.
    ///
    /// # Errors
    ///
    /// A database error, as a decline.
    pub async fn count(&self, pool: &PgPool) -> Result<i64, Decline> {
        if self.empty {
            return Ok(0);
        }
        let what = if self.distinct {
            format!("COUNT(DISTINCT t.\"{}\")", self.pk)
        } else {
            "COUNT(*)".to_owned()
        };
        let sql = format!(
            "SELECT {what} FROM \"{}\" t{}",
            self.table,
            self.where_sql()
        );
        let row = self
            .query(sql)
            .fetch_one(pool)
            .await
            .map_err(|_| Decline("database error"))?;
        row.try_get(0).map_err(|_| Decline("database error"))
    }

    /// `.exists()`.
    ///
    /// # Errors
    ///
    /// A database error, as a decline.
    pub async fn exists(&self, pool: &PgPool) -> Result<bool, Decline> {
        Ok(self.count(pool).await? > 0)
    }

    /// `SELECT columns … ORDER BY order LIMIT limit OFFSET offset`.
    ///
    /// # Errors
    ///
    /// A database error, as a decline.
    pub async fn fetch(
        &self,
        pool: &PgPool,
        columns: &str,
        order: &[String],
        limit: Option<(i64, i64)>,
    ) -> Result<Vec<PgRow>, Decline> {
        if self.empty {
            return Ok(Vec::new());
        }
        let mut sql = format!(
            "SELECT {}{columns} FROM \"{}\" t{}",
            if self.distinct { "DISTINCT " } else { "" },
            self.table,
            self.where_sql()
        );
        if !order.is_empty() {
            sql.push_str(" ORDER BY ");
            sql.push_str(&order.join(", "));
        }
        if let Some((limit, offset)) = limit {
            let _ = write!(sql, " LIMIT {limit} OFFSET {offset}");
        }
        self.query(sql)
            .fetch_all(pool)
            .await
            .map_err(|_| Decline("database error"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_escaping_matches_django() {
        assert_eq!(prep_for_like(r"a%b_c\d"), r"a\%b\_c\\d");
    }
}
