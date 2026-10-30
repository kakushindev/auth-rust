//! M4 acceptance against a populated database (`AK_MODELS_DATABASE_URL`,
//! skipped when unset; `tests/models/run.sh` provides one):
//!
//! 1. every row of every table decodes into its row type;
//! 2. writing every row back by primary key, and then deleting and re-inserting every table from
//!    the decoded rows, leaves each table (and the group ancestry view) byte-equal as Postgres
//!    renders it;
//! 3. all deferred foreign keys still hold.
//!
//! Everything runs in one transaction that is rolled back.

use std::collections::BTreeMap;

use ak_models::{Row, fetch_all, insert, update};
use sqlx::{AssertSqlSafe, PgConnection, PgPool, Postgres, Transaction};

/// Row count and a digest of the rows' text, independent of row order.
async fn snapshot(conn: &mut PgConnection, table: &str) -> (i64, String) {
    sqlx::query_as(AssertSqlSafe(format!(
        "SELECT count(*), md5(coalesce(string_agg(t::text, E'\\n' ORDER BY t::text), '')) FROM \
         \"{table}\" t"
    )))
    .fetch_one(conn)
    .await
    .unwrap_or_else(|err| panic!("{table}: {err}"))
}

#[derive(Default)]
struct Report {
    before: BTreeMap<&'static str, (i64, String)>,
    decoded: BTreeMap<&'static str, usize>,
}

async fn decode<T: Row>(pool: &PgPool, report: &mut Report) {
    let mut conn = pool.acquire().await.expect("connection");
    report
        .before
        .insert(T::TABLE, snapshot(&mut conn, T::TABLE).await);
    let rows: Vec<T> = fetch_all(&mut *conn)
        .await
        .unwrap_or_else(|err| panic!("{}: rows do not decode: {err}", T::TABLE));
    report.decoded.insert(T::TABLE, rows.len());
}

async fn rewrite<T: Row>(tx: &mut Transaction<'_, Postgres>) {
    if !T::WRITABLE {
        return;
    }
    let rows: Vec<T> = fetch_all(&mut **tx).await.expect("decode");
    for row in &rows {
        update(row, &mut **tx)
            .await
            .unwrap_or_else(|err| panic!("{}: update: {err}", T::TABLE));
    }
}

async fn reinsert<T: Row>(tx: &mut Transaction<'_, Postgres>) {
    if !T::WRITABLE {
        return;
    }
    let rows: Vec<T> = fetch_all(&mut **tx).await.expect("decode");
    sqlx::query(AssertSqlSafe(format!("DELETE FROM \"{}\"", T::TABLE)))
        .execute(&mut **tx)
        .await
        .unwrap_or_else(|err| panic!("{}: delete: {err}", T::TABLE));
    for row in &rows {
        insert(row, &mut **tx)
            .await
            .unwrap_or_else(|err| panic!("{}: insert: {err}", T::TABLE));
    }
}

async fn changed(tx: &mut Transaction<'_, Postgres>, report: &Report) -> Vec<String> {
    let mut different = Vec::new();
    for (table, before) in &report.before {
        let after = snapshot(&mut *tx, table).await;
        if &after != before {
            different.push(format!("{table}: {before:?} -> {after:?}"));
        }
    }
    different
}

async fn compare(tx: &mut Transaction<'_, Postgres>, report: &Report, step: &str) {
    let different = changed(tx, report).await;
    assert!(
        different.is_empty(),
        "{step} changed rows:\n{}",
        different.join("\n")
    );
}

#[expect(
    clippy::tests_outside_test_module,
    reason = "an integration test file is its own test crate"
)]
#[tokio::test]
async fn every_row_decodes_and_round_trips_byte_equal() {
    let Ok(url) = std::env::var("AK_MODELS_DATABASE_URL") else {
        eprintln!("AK_MODELS_DATABASE_URL unset; skipping (tests/models/run.sh sets it)");
        return;
    };
    let pool = PgPool::connect(&url).await.expect("connect");
    let mut report = Report::default();

    macro_rules! decode_rows {
        ($t:ty) => {
            decode::<$t>(&pool, &mut report).await;
        };
    }
    ak_models::for_each_row!(decode_rows);
    // The ancestry view is derived from group parentage; it must survive too.
    let mut conn = pool.acquire().await.expect("connection");
    report.before.insert(
        "authentik_core_groupancestry",
        snapshot(&mut conn, "authentik_core_groupancestry").await,
    );
    drop(conn);

    let mut tx = pool.begin().await.expect("begin");
    sqlx::query("SET CONSTRAINTS ALL DEFERRED")
        .execute(&mut *tx)
        .await
        .expect("defer");

    macro_rules! rewrite_rows {
        ($t:ty) => {
            rewrite::<$t>(&mut tx).await;
        };
    }
    ak_models::for_each_row!(rewrite_rows);
    compare(&mut tx, &report, "updating every row with its own values").await;

    macro_rules! reinsert_rows {
        ($t:ty) => {
            reinsert::<$t>(&mut tx).await;
        };
    }
    ak_models::for_each_row!(reinsert_rows);
    compare(&mut tx, &report, "deleting and re-inserting every table").await;

    sqlx::query("SET CONSTRAINTS ALL IMMEDIATE")
        .execute(&mut *tx)
        .await
        .expect("foreign keys hold after the round trip");

    // Self-test: the 30-digit integer in the populated attributes written
    // back through f64 (what a serde_json::Value round trip would do) must be
    // detected.
    sqlx::query(
        "UPDATE authentik_core_user SET attributes = replace(attributes::text, \
         '123456789012345678901234567890', '123456789012345680000000000000')::jsonb WHERE \
         attributes::text LIKE '%123456789012345678901234567890%'",
    )
    .execute(&mut *tx)
    .await
    .expect("seed a difference");
    assert_eq!(
        changed(&mut tx, &report).await.len(),
        1,
        "a seeded difference must be detected"
    );
    tx.rollback().await.expect("rollback");

    let total: usize = report.decoded.values().sum();
    let empty: Vec<_> = report
        .decoded
        .iter()
        .filter(|(_, n)| **n == 0)
        .map(|(t, _)| *t)
        .collect();
    eprintln!(
        "decoded {total} rows in {} tables; empty tables: {empty:?}",
        report.decoded.len()
    );
    for (table, (count, _)) in &report.before {
        if let Some(decoded) = report.decoded.get(table) {
            assert_eq!(
                i64::try_from(*decoded).expect("row count"),
                *count,
                "{table}: not every row decoded"
            );
        }
    }
}
