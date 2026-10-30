//! M5 request-identity differential: for every vector in
//! `tests/auth/vectors.json`, the decision here must equal Django's
//! (`AK_AUTH_DJANGO`, written by `tests/auth/run.sh`; skipped when unset).

use ak_auth::{
    brand, host, tenant,
    token::{self, Authenticated, Error},
};
use base64::Engine as _;
use serde_json::Value;
use sqlx::PgPool;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

fn read_json(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).expect("read")).expect("JSON")
}

#[expect(
    clippy::tests_outside_test_module,
    reason = "an integration test file is its own test crate"
)]
#[tokio::test]
async fn decisions_match_django() {
    let (Some(url), Some(vectors), Some(django), Some(secret_key), Some(ipc_key)) = (
        env("AK_AUTH_DATABASE_URL"),
        env("AK_AUTH_VECTORS"),
        env("AK_AUTH_DJANGO"),
        env("AK_AUTH_SECRET_KEY"),
        env("AK_AUTH_IPC_KEY"),
    ) else {
        eprintln!("AK_AUTH_* unset; skipping (tests/auth/run.sh sets them)");
        return;
    };
    let pool = PgPool::connect(&url).await.expect("connect");
    let vectors = read_json(&vectors);
    let django = read_json(&django);
    let mut mismatches = Vec::new();

    for (vector, expected) in vectors["hosts"]
        .as_array()
        .expect("hosts")
        .iter()
        .zip(django["hosts"].as_array().expect("Django hosts"))
    {
        let raw = vector.as_str().expect("host");
        let got_host =
            host::get_host(raw).map_or_else(|_| "DisallowedHost".to_owned(), str::to_owned);
        let got_brand = match host::get_host(raw) {
            Err(_) => "DisallowedHost".to_owned(),
            Ok(h) => brand::resolve(&pool, h)
                .await
                .expect("brand")
                .map_or_else(|| "fallback".to_owned(), |b| b.to_string()),
        };
        let (got_hostname, got_tenant) = match host::tenant_hostname(raw) {
            Err(_) => ("DisallowedHost".to_owned(), "DisallowedHost".to_owned()),
            Ok(h) => (
                h.to_owned(),
                tenant::resolve(&pool, h)
                    .await
                    .expect("tenant")
                    .map_or_else(|| "DoesNotExist".to_owned(), |t| t.to_string()),
            ),
        };
        for (field, got) in [
            ("get_host", got_host),
            ("brand", got_brand),
            ("tenant_hostname", got_hostname),
            ("tenant", got_tenant),
        ] {
            if expected[field].as_str() != Some(got.as_str()) {
                mismatches.push(format!(
                    "host {raw:?} {field}: Django {} != Rust {got:?}",
                    expected[field]
                ));
            }
        }
    }

    for (vector, expected) in vectors["headers"]
        .as_array()
        .expect("headers")
        .iter()
        .zip(django["headers"].as_array().expect("Django headers"))
    {
        let encoded = vector.as_str().expect("header");
        let raw = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("base64");
        // Substitute the key placeholders (ASCII) on the bytes.
        let mut raw = raw;
        for (needle, value) in [("{SECRET_KEY}", &secret_key), ("{IPC_KEY}", &ipc_key)] {
            if let Some(at) = raw
                .windows(needle.len())
                .position(|w| w == needle.as_bytes())
            {
                raw.splice(at..at + needle.len(), value.bytes());
            }
        }
        let got =
            match token::bearer_auth(&pool, &raw, chrono::Utc::now(), &secret_key, Some(&ipc_key))
                .await
            {
                Ok(None) => "none".to_owned(),
                Ok(Some(Authenticated::ApiToken { token, user })) => {
                    format!("api_token:{token}:{user}")
                }
                Ok(Some(Authenticated::Jwt { access_token, user })) => {
                    format!("jwt:{access_token}:{user}")
                }
                Ok(Some(Authenticated::SecretKey { outpost, user })) => format!(
                    "secret_key:{outpost}:{}",
                    user.map_or_else(|| "create".to_owned(), |u| u.to_string())
                ),
                Ok(Some(Authenticated::Ipc)) => "ipc".to_owned(),
                Err(Error::Failed(message)) => format!("failed:{message}"),
                Err(Error::Python(exception)) => format!("error:{exception}"),
                Err(Error::Database(err)) => panic!("database: {err}"),
            };
        if expected["result"].as_str() != Some(got.as_str()) {
            mismatches.push(format!(
                "header {encoded}: Django {} != Rust {got:?}",
                expected["result"]
            ));
        }
    }

    let hosts = vectors["hosts"].as_array().map_or(0, Vec::len);
    let headers = vectors["headers"].as_array().map_or(0, Vec::len);
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    eprintln!(
        "{hosts} hosts (get_host, brand, tenant) and {headers} Authorization headers match Django"
    );
}
