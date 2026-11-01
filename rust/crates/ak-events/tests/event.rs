//! M8 event differential: every case Django recorded in `AK_EVENTS_DJANGO`
//! (`tests/events/event_decide.py`, written by `tests/events/run.sh`) is
//! replayed through `ak_events::event::new_from_http` in a rolled-back
//! transaction; the row and the task it enqueues must be Django's.

use ak_auth::binding::GeoIp;
use ak_events::event::{Action, BrandRef, HttpRequest, SessionUsers, UserRef, new_from_http};
use serde_json::{Value, json};
use sqlx::Row as _;
use uuid::Uuid;

/// `DEFAULT_BRAND`'s primary key is random per process.
fn mask_fallback_brand(row: &mut Value) {
    if row[5]["name"] == "Brand fallback" {
        row[5]["pk"] = json!("<fallback>");
    }
}

fn hex_bytes(hex: &str) -> Vec<u8> {
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("hex"))
        .collect()
}

#[expect(
    clippy::tests_outside_test_module,
    reason = "an integration test file is its own test crate"
)]
#[expect(clippy::too_many_lines, reason = "one replay per recorded case")]
#[tokio::test]
async fn events_match_django() {
    let (Ok(url), Ok(path), Ok(geoip_dir)) = (
        std::env::var("AK_EVENTS_DB"),
        std::env::var("AK_EVENTS_DJANGO"),
        std::env::var("AK_GEOIP_DIR"),
    ) else {
        eprintln!("AK_EVENTS_* unset; skipping (tests/events/run.sh sets them)");
        return;
    };
    let django: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read")).expect("JSON");
    let pool = sqlx::PgPool::connect(&url).await.expect("connect");
    let geoip = GeoIp::new(
        Some(&format!("{geoip_dir}/GeoLite2-ASN.mmdb")),
        Some(&format!("{geoip_dir}/GeoLite2-City.mmdb")),
    )
    .expect("GeoIP");
    let ids = &django["ids"];
    let id = |k: &str| i32::try_from(ids[k].as_i64().expect("id")).expect("id");
    let tenant: Uuid = sqlx::query_scalar(
        "SELECT tenant_uuid FROM authentik_tenants_tenant WHERE schema_name = 'public'",
    )
    .fetch_one(&pool)
    .await
    .expect("tenant");
    let brand_ref = |name: &str| -> BrandRef {
        match name {
            "default" => BrandRef {
                uuid: ids["default"]
                    .as_str()
                    .expect("uuid")
                    .parse()
                    .expect("uuid"),
                domain: "authentik-default".to_owned(),
                default: true,
            },
            "m8" => BrandRef {
                uuid: ids["brand"].as_str().expect("uuid").parse().expect("uuid"),
                domain: "m8.test".to_owned(),
                default: false,
            },
            _ => BrandRef {
                uuid: ids["fallback_pk"]
                    .as_str()
                    .expect("uuid")
                    .parse()
                    .expect("uuid"),
                domain: "fallback".to_owned(),
                default: false,
            },
        }
    };
    let user_ref = |name: &str| match name {
        "anonymous" => UserRef::Anonymous,
        "user" => UserRef::Id(id("user")),
        _ => UserRef::Id(id("other")),
    };

    let mut mismatches = Vec::new();
    let results = django["results"].as_array().expect("results");
    for result in results {
        let case = &result["case"];
        let session = case["session_pickle"].as_str().map(|hex| {
            let data = ak_pickle::loads(&hex_bytes(hex)).expect("session pickle");
            SessionUsers::from_session(&data).expect("session users")
        });
        let request = case["request"].as_object().map(|r| HttpRequest {
            path: r["path"].as_str().expect("path"),
            method: r["method"].as_str().expect("method"),
            query_string: r["query"].as_str().expect("query"),
            user_agent: r["ua"].as_str().expect("ua"),
            request_id: r["rid"].as_str(),
            brand: case["brand"].as_str().map(brand_ref),
            user: case["user"].as_str().map(user_ref),
            session: session.clone(),
            client_ip: case["client_ip"].as_str().expect("ip"),
        });
        let action = match case["action"].as_str().expect("action") {
            "foo" => Action::Custom("foo"),
            other => Action::Known(other),
        };
        let mut tx = pool.begin().await.expect("tx");
        let written = new_from_http(
            &mut tx,
            tenant,
            action,
            "authentik.events.signals",
            case["kwargs"].as_object().expect("kwargs").clone(),
            None,
            request.as_ref(),
            case["override"].as_str().map(user_ref).as_ref(),
            &geoip,
            chrono::Utc::now(),
        )
        .await
        .expect("event");
        let row = sqlx::query(
            "SELECT action, app, context::text, host(client_ip), \"user\"::text, brand::text, \
             round(extract(epoch from expires - created))::bigint, expiring FROM \
             authentik_events_event WHERE event_uuid = $1",
        )
        .bind(written.event_uuid)
        .fetch_one(&mut *tx)
        .await
        .expect("row");
        let parse =
            |i: usize| -> Value { serde_json::from_str(&row.get::<String, _>(i)).expect("jsonb") };
        let mut got = json!([
            row.get::<String, _>(0),
            row.get::<String, _>(1),
            parse(2),
            row.get::<Option<String>, _>(3),
            parse(4),
            parse(5),
            row.get::<i64, _>(6),
            row.get::<bool, _>(7),
        ]);
        let task = sqlx::query(
            "SELECT actor_name, queue_name, state::text, aggregated_status::text, retries FROM \
             authentik_tasks_task WHERE message_id = $1",
        )
        .bind(written.task)
        .fetch_one(&mut *tx)
        .await
        .expect("task");
        let logs: Vec<String> =
            sqlx::query_scalar("SELECT event FROM authentik_tasks_tasklog WHERE task_id = $1")
                .bind(written.task)
                .fetch_all(&mut *tx)
                .await
                .expect("logs");
        let got_tasks = json!([{
            "actor": task.get::<String, _>(0),
            "queue": task.get::<String, _>(1),
            "state": task.get::<String, _>(2),
            "aggregated_status": task.get::<String, _>(3),
            "retries": task.get::<i64, _>(4),
            "args_match": true,
            "logs": logs,
        }]);
        tx.rollback().await.expect("rollback");

        let mut want = result["row"].clone();
        mask_fallback_brand(&mut want);
        mask_fallback_brand(&mut got);
        if got != want {
            mismatches.push(format!("{case}:\n  Django {want}\n  Rust   {got}"));
        }
        if got_tasks != result["tasks"] {
            mismatches.push(format!(
                "{case} tasks:\n  Django {}\n  Rust   {got_tasks}",
                result["tasks"]
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches
            .iter()
            .take(20)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    eprintln!(
        "{} events and their dispatch tasks written as Django writes them",
        results.len()
    );
}
