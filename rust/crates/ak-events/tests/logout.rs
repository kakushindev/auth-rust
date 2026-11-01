//! M8 logout differential: each session Django's middlewares logged out in
//! `AK_EVENTS_LOGOUT` (`tests/events/logout_decide.py`) goes through
//! `ak_auth::session::resolve` and `ak_events::logout::logout` in a
//! rolled-back transaction. The response decision, the events, the tasks
//! and what remains of the session must be Django's; cases Django handles
//! with receivers this port does not reproduce must be declined.

use ak_auth::{
    binding::GeoIp,
    session::{RequestUser, resolve},
    url,
};
use ak_events::{
    Error,
    logout::{Request, logout},
};
use serde_json::{Value, json};
use sqlx::Row as _;
use uuid::Uuid;

fn mask(mut row: Value) -> Value {
    if row[5]["name"] == "Brand fallback" {
        row[5]["pk"] = json!("<fallback>");
    }
    row
}

#[expect(
    clippy::tests_outside_test_module,
    reason = "an integration test file is its own test crate"
)]
#[expect(clippy::too_many_lines, reason = "one replay per recorded case")]
#[tokio::test]
async fn logouts_match_django() {
    let (Ok(url), Ok(path), Ok(geoip_dir), Ok(secret_key)) = (
        std::env::var("AK_EVENTS_DB"),
        std::env::var("AK_EVENTS_LOGOUT"),
        std::env::var("AK_GEOIP_DIR"),
        std::env::var("AK_EVENTS_SECRET_KEY"),
    ) else {
        eprintln!("AK_EVENTS_* unset; skipping (tests/events/run.sh sets them)");
        return;
    };
    let django: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read")).expect("JSON");
    let pool = sqlx::PgPool::connect(&url).await.expect("connect");
    let geoip = GeoIp::new(
        Some(&format!("{geoip_dir}/GeoLite2-ASN.mmdb")),
        Some(&format!("{geoip_dir}/GeoLite2-City.mmdb")),
    )
    .expect("GeoIP");
    let tenant: Uuid = sqlx::query_scalar(
        "SELECT tenant_uuid FROM authentik_tenants_tenant WHERE schema_name = 'public'",
    )
    .fetch_one(&pool)
    .await
    .expect("tenant");
    let mut mismatches = Vec::new();
    let mut declined = 0_usize;
    for expected in &django {
        let case = &expected["case"];
        let name = case["name"].as_str().expect("name");
        let s = |k: &str| case[k].as_str().expect("case field");
        let now = chrono::Utc::now();
        let client_ip = ak_auth::client_ip::from_meta(None, Some(s("client_ip")));
        let resolved = resolve(
            &pool,
            Some(s("cookie")),
            &client_ip,
            &secret_key,
            &geoip,
            86400.0,
            now,
        )
        .await
        .expect("resolve");
        let result = match &resolved.user {
            RequestUser::InactiveLogout => "400:".to_owned(),
            RequestUser::BindingBroken(_) => {
                let path = url::request_path(&url::path_info(s("path").as_bytes()));
                format!(
                    "302:{}",
                    url::login_redirect("/", &url::get_full_path(&path, s("query")))
                )
            }
            other => format!("not a logout: {other:?}"),
        };
        let flush = resolved.flush.expect("flush");
        let mut tx = pool.begin().await.expect("tx");
        let written = logout(
            &mut tx,
            tenant,
            &flush,
            &Request {
                path: s("path"),
                method: "GET",
                query_string: s("query"),
                user_agent: s("user_agent"),
                client_ip: &client_ip,
            },
            &geoip,
            now,
        )
        .await;
        if name.starts_with("declined-") {
            match written {
                Err(Error::Unsupported(_)) => declined += 1,
                other => mismatches.push(format!("{name}: expected a decline, got {other:?}")),
            }
            tx.rollback().await.expect("rollback");
            continue;
        }
        let written = match written {
            Ok(w) => w,
            Err(err) => {
                mismatches.push(format!("{name}: {err:?}"));
                tx.rollback().await.expect("rollback");
                continue;
            }
        };
        let mut events = Vec::new();
        for event in &written.events {
            let row = sqlx::query(
                "SELECT action, app, context::text, host(client_ip), \"user\"::text, brand::text, \
                 round(extract(epoch from expires - created))::bigint, expiring FROM \
                 authentik_events_event WHERE event_uuid = $1",
            )
            .bind(event.event_uuid)
            .fetch_one(&mut *tx)
            .await
            .expect("event");
            let parse = |i: usize| -> Value {
                serde_json::from_str(&row.get::<String, _>(i)).expect("jsonb")
            };
            events.push(mask(json!([
                row.get::<String, _>(0),
                row.get::<String, _>(1),
                parse(2),
                row.get::<Option<String>, _>(3),
                parse(4),
                parse(5),
                row.get::<i64, _>(6),
                row.get::<bool, _>(7),
            ])));
        }
        let mut tasks: Vec<Value> = written
            .events
            .iter()
            .map(|_| {
                json!([
                    "authentik.events.tasks.event_trigger_dispatch",
                    "event",
                    "queued"
                ])
            })
            .chain(written.outpost_task.map(|_| {
                json!([
                    "authentik.outposts.tasks.outpost_session_end",
                    "session_key",
                    "queued"
                ])
            }))
            .collect();
        tasks.sort_by_key(ToString::to_string);
        let remaining = sqlx::query(
            "SELECT EXISTS (SELECT 1 FROM authentik_core_session WHERE session_key = $1), EXISTS \
             (SELECT 1 FROM authentik_core_authenticatedsession WHERE session_id = $1)",
        )
        .bind(&flush.session_key)
        .fetch_one(&mut *tx)
        .await
        .expect("remaining");
        tx.rollback().await.expect("rollback");

        let mut want_events: Vec<Value> = expected["events"]
            .as_array()
            .expect("events")
            .iter()
            .cloned()
            .map(mask)
            .collect();
        // Django orders by creation time; Rust's events share `now`.
        want_events.sort_by_key(ToString::to_string);
        events.sort_by_key(ToString::to_string);
        let got = json!({
            "result": result,
            "events": events,
            "tasks": tasks,
            "session": remaining.get::<bool, _>(0),
            "authenticated_session": remaining.get::<bool, _>(1),
        });
        let want = json!({
            "result": expected["result"],
            "events": want_events,
            "tasks": expected["tasks"],
            "session": expected["session"],
            "authenticated_session": expected["authenticated_session"],
        });
        if got != want {
            mismatches.push(format!("{name}:\n  Django {want}\n  Rust   {got}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    eprintln!(
        "{} logouts leave Django's state ({declined} declined where receivers are not reproduced)",
        django.len()
    );
}
