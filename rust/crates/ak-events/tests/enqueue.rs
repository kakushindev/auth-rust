//! Enqueue against a live database (`AK_EVENTS_DATABASE_URL`, a test
//! stack's), printing the message id for the reference-side comparison in
//! `tests/events/check_enqueue.py`. Skipped without the variable.

#[expect(
    clippy::tests_outside_test_module,
    reason = "an integration test file is its own test crate"
)]
#[expect(clippy::print_stdout, reason = "the id is the output, for the Python side")]
#[tokio::test]
async fn enqueue_event_dispatch() {
    let Ok(url) = std::env::var("AK_EVENTS_DATABASE_URL") else {
        return;
    };
    let pool = sqlx::PgPool::connect(&url).await.expect("db");
    let tenant: uuid::Uuid = sqlx::query_scalar(
        "SELECT tenant_uuid FROM authentik_tenants_tenant WHERE schema_name = 'public'",
    )
    .fetch_one(&pool)
    .await
    .expect("tenant");
    let event = uuid::Uuid::new_v4();
    let mut tx = pool.begin().await.expect("tx");
    let id = ak_events::task::enqueue(
        &mut tx,
        tenant,
        "authentik.events.tasks.event_trigger_dispatch",
        vec![ak_pickle::write::Obj::uuid(event.as_u128())],
        chrono::Utc::now(),
    )
    .await
    .expect("enqueue");
    tx.commit().await.expect("commit");
    println!("ENQUEUED {id}");
}
