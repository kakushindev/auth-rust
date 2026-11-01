//! M5 session differential: for every cookie in `AK_AUTH_COOKIES` (real
//! sessions made over HTTP plus crafted JWTs, see `tests/auth/sessions.py`)
//! the request identity must equal Django's middleware decision (bound
//! sessions requested from other client IPs included), the response's
//! session cookie must be the one Django sets, and every
//! session row's pickled data must read as Django decodes it
//! (`AK_AUTH_SESSION_DJANGO`; both written by `tests/auth/run.sh`).

use ak_auth::{
    binding::GeoIp,
    cookie::{self, SessionResponse},
    session::{self, RequestUser, Resolved},
    url,
};
use serde_json::{Value, json};
use sqlx::PgPool;

#[expect(
    clippy::tests_outside_test_module,
    reason = "an integration test file is its own test crate"
)]
#[tokio::test]
async fn sessions_match_django() {
    let (Ok(url), Ok(cookies), Ok(django), Ok(secret_key), Ok(geoip_dir)) = (
        std::env::var("AK_AUTH_DATABASE_URL"),
        std::env::var("AK_AUTH_COOKIES"),
        std::env::var("AK_AUTH_SESSION_DJANGO"),
        std::env::var("AK_AUTH_SECRET_KEY"),
        std::env::var("AK_GEOIP_DIR"),
    ) else {
        eprintln!("AK_AUTH_* unset; skipping (tests/auth/run.sh sets them)");
        return;
    };
    let read = |path: &str| -> Value {
        serde_json::from_str(&std::fs::read_to_string(path).expect("read")).expect("JSON")
    };
    let (cookies, django) = (read(&cookies), read(&django));
    let pool = PgPool::connect(&url).await.expect("connect");
    let geoip = GeoIp::new(
        Some(&format!("{geoip_dir}/GeoLite2-ASN.mmdb")),
        Some(&format!("{geoip_dir}/GeoLite2-City.mmdb")),
    )
    .expect("GeoIP");
    let install_id = session::install_id(&pool).await.expect("install id");
    let now_secs = django["now"].as_f64().expect("now");
    #[expect(
        clippy::as_conversions,
        clippy::cast_possible_truncation,
        reason = "whole seconds"
    )]
    let now = chrono::DateTime::from_timestamp(now_secs as i64, 0).expect("time");
    let mut mismatches = Vec::new();
    let mut responses = 0_usize;

    let decisions = django["decisions"].as_array().expect("decisions");
    for (case, expected) in cookies.as_array().expect("cookies").iter().zip(decisions) {
        let cookie = case["cookie"].as_str();
        let client_ip = case["client_ip"].as_str().unwrap_or("203.0.113.9");
        let resolved =
            match session::resolve(&pool, cookie, client_ip, &secret_key, &geoip, 86400.0, now)
                .await
            {
                Ok(resolved) => resolved,
                Err(session::Error::Python(exception)) => {
                    let got = format!("error:{exception}");
                    if expected["result"].as_str() != Some(got.as_str()) {
                        mismatches.push(format!(
                            "{}: Django {} != Rust {got:?}",
                            case["name"], expected["result"]
                        ));
                    }
                    continue;
                }
                Err(session::Error::Database(err)) => panic!("database: {err}"),
            };
        let Resolved {
            user,
            session_key,
            set_last_ip,
            expiry_age,
            ..
        } = &resolved;
        let (got, status, uid_of) = match user {
            RequestUser::Anonymous => ("anonymous".to_owned(), 200, None),
            RequestUser::User(id) => (format!("user:{id}"), 200, Some(*id)),
            RequestUser::Impersonating { real, as_user } => (
                format!(
                    "impersonating:{}:{as_user}",
                    real.map_or_else(|| "None".to_owned(), |r| r.to_string())
                ),
                200,
                Some(*as_user),
            ),
            RequestUser::InactiveLogout => ("status:400".to_owned(), 400, None),
            RequestUser::BindingBroken(_) => (
                format!(
                    "redirect:{}",
                    url::login_redirect("/", &url::get_full_path("/", ""))
                ),
                302,
                None,
            ),
        };
        if expected["result"].as_str() != Some(got.as_str()) {
            mismatches.push(format!(
                "{}: Django {} != Rust {got:?}",
                case["name"], expected["result"]
            ));
        }
        // The response's session cookie.
        let uid = uid_of.map(|id| cookie::user_uid(id, &install_id));
        let effect = cookie::session_process_response(
            &SessionResponse {
                had_cookie: cookie.is_some(),
                accessed: true,
                modified: set_last_ip.is_some(),
                empty: session_key.is_none(),
                session_key: session_key.as_deref(),
                user_uid: uid.as_deref(),
                expiry_age: *expiry_age,
                status,
                secure: false,
                web_path: "/",
                cookie_domain: None,
            },
            &secret_key,
            now_secs,
        )
        .expect("cookie");
        let got = json!({
            "cookies": effect.cookies,
            "vary": effect.vary_cookie.then_some("Cookie"),
            "saved": effect.save,
        });
        let want = json!({"cookies": expected["cookies"], "vary": expected["vary"], "saved": expected["saved"]});
        if got != want {
            mismatches.push(format!(
                "{} response: Django {want} != Rust {got}",
                case["name"]
            ));
        }
        responses += 1;
    }

    let mut keys = 0_usize;
    let pickles = django["pickles"].as_array().expect("pickles");
    for row in pickles {
        let key = row["session_key"].as_str().expect("key");
        let data: Vec<u8> = sqlx::query_scalar(
            "SELECT session_data FROM authentik_core_session WHERE session_key = $1",
        )
        .bind(key)
        .fetch_one(&pool)
        .await
        .expect("session row");
        let root = ak_pickle::loads(&data).unwrap_or_else(|err| panic!("{key}: {err:?}"));
        for (name, expected) in row["data"].as_object().expect("data") {
            let value = root.get(name).unwrap_or_else(|| panic!("{key}: no {name}"));
            let (ty, scalar, len) = ak_pickle::describe(&value);
            let mut got = serde_json::json!({"type": ty});
            if expected.get("value").is_some() {
                got["value"] = Value::from(scalar);
            }
            if let Some(len) = len {
                got["len"] = Value::from(len);
            }
            if &got != expected {
                mismatches.push(format!(
                    "session {key} {name}: Django {expected} != Rust {got}"
                ));
            }
            keys += 1;
        }
    }

    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    eprintln!(
        "{} cookies resolve as Django does ({responses} session cookies set alike); {keys} keys \
         in {} session pickles read as Django decodes them",
        decisions.len(),
        pickles.len()
    );
}
