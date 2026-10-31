//! M5 session differential: for every cookie in `AK_AUTH_COOKIES` (real
//! sessions made over HTTP plus crafted JWTs, see `tests/auth/sessions.py`)
//! the request identity must equal Django's middleware decision, and every
//! session row's pickled data must read as Django decodes it
//! (`AK_AUTH_SESSION_DJANGO`; both written by `tests/auth/run.sh`).

use ak_auth::session::{self, RequestUser};
use serde_json::Value;
use sqlx::PgPool;

#[expect(
    clippy::tests_outside_test_module,
    reason = "an integration test file is its own test crate"
)]
#[tokio::test]
async fn sessions_match_django() {
    let (Ok(url), Ok(cookies), Ok(django), Ok(secret_key)) = (
        std::env::var("AK_AUTH_DATABASE_URL"),
        std::env::var("AK_AUTH_COOKIES"),
        std::env::var("AK_AUTH_SESSION_DJANGO"),
        std::env::var("AK_AUTH_SECRET_KEY"),
    ) else {
        eprintln!("AK_AUTH_* unset; skipping (tests/auth/run.sh sets them)");
        return;
    };
    let read = |path: &str| -> Value {
        serde_json::from_str(&std::fs::read_to_string(path).expect("read")).expect("JSON")
    };
    let (cookies, django) = (read(&cookies), read(&django));
    let pool = PgPool::connect(&url).await.expect("connect");
    let mut mismatches = Vec::new();

    let decisions = django["decisions"].as_array().expect("decisions");
    for (case, expected) in cookies.as_array().expect("cookies").iter().zip(decisions) {
        let cookie = case["cookie"].as_str();
        let got = match session::resolve(
            &pool,
            cookie,
            "203.0.113.9",
            &secret_key,
            chrono::Utc::now(),
        )
        .await
        {
            Ok(RequestUser::Anonymous) => "anonymous".to_owned(),
            Ok(RequestUser::User(id)) => format!("user:{id}"),
            Ok(RequestUser::Impersonating { real, as_user }) => format!(
                "impersonating:{}:{as_user}",
                real.map_or_else(|| "None".to_owned(), |r| r.to_string())
            ),
            Ok(RequestUser::InactiveLogout) => "status:400".to_owned(),
            Ok(RequestUser::BindingCheckRequired) => "binding_check".to_owned(),
            Err(session::Error::Python(exception)) => format!("error:{exception}"),
            Err(session::Error::Database(err)) => panic!("database: {err}"),
        };
        if expected["result"].as_str() != Some(got.as_str()) {
            mismatches.push(format!(
                "{}: Django {} != Rust {got:?}",
                case["name"], expected["result"]
            ));
        }
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
        "{} cookies resolve as Django does; {keys} keys in {} session pickles read as Django \
         decodes them",
        decisions.len(),
        pickles.len()
    );
}
