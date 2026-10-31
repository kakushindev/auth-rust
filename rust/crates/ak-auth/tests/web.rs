//! M5 request/response differential: Django's answers recorded by
//! `tests/auth/web_decide.py` (`AK_AUTH_WEB`, written by `tests/auth/run.sh`)
//! for CSRF, CSRF tokens, cookies, the session cookie, `is_secure`, login
//! redirects and session bindings (`AK_GEOIP_DIR`) must be ak-auth's.

use ak_auth::{
    binding::{self, GeoIp, Recheck},
    cookie::{self, Cookie, SessionResponse},
    csrf::{self, CsrfState, Outcome, PostToken},
    url,
};
use serde_json::{Value, json};

fn opt(v: &Value) -> Option<&str> {
    v.as_str()
}

fn samesite(v: &Value) -> Option<&'static str> {
    match v.as_str()? {
        "Lax" => Some("Lax"),
        "None" => Some("None"),
        "Strict" => Some("Strict"),
        "none" => Some("none"),
        other => panic!("samesite {other}"),
    }
}

fn outcome_json(outcome: &Outcome) -> Value {
    match outcome {
        Outcome::Accept => Value::Null,
        Outcome::Reject(reason) => json!(reason),
        Outcome::BodyError => json!("body_error"),
    }
}

fn check_csrf(web: &Value, mismatches: &mut Vec<String>) -> usize {
    let cases = web["csrf"].as_array().expect("csrf");
    for (i, case) in cases.iter().enumerate() {
        let host = case["host"].as_str().unwrap_or("authentik.test");
        let secure = csrf::is_secure(
            opt(&case["xfp"]),
            if case["secure"] == true {
                "https"
            } else {
                "http"
            },
        );
        if json!(secure) != case["is_secure"] {
            mismatches.push(format!(
                "csrf #{i} is_secure: Django {} != Rust {secure}",
                case["is_secure"]
            ));
        }
        let cookie = opt(&case["cookie_value"]);
        let state = csrf::process_request(cookie);
        let got_state = json!({"needs_update": state.needs_update, "meta_cookie": if state.needs_update { None } else { state.cookie.clone() }});
        let want_state =
            json!({"needs_update": case["needs_update"], "meta_cookie": case["meta_cookie"]});
        if got_state != want_state {
            mismatches.push(format!(
                "csrf #{i} process_request: Django {want_state} != Rust {got_state}"
            ));
        }
        if state.needs_update
            && state
                .cookie
                .as_deref()
                .is_none_or(|c| csrf::check_token_format(c).is_err())
        {
            mismatches.push(format!("csrf #{i}: new cookie is not a valid secret"));
        }
        let method = case["request_method"].as_str().expect("method");
        for (mode, post) in [("django", &case["post_token"]), ("drf", &case["drf_post"])] {
            let post = post.as_str().unwrap_or_default();
            let post_token = if post.starts_with("body_error:") {
                PostToken::BodyError
            } else if post.is_empty() {
                PostToken::Absent
            } else {
                PostToken::Value(post)
            };
            let request = csrf::Request {
                method,
                host,
                secure,
                origin: opt(&case["origin"]),
                referer: opt(&case["referer"]),
                header_token: opt(&case["header_value"]),
                post_token,
            };
            let got = outcome_json(&csrf::process_view(&request, cookie));
            let want = match case[mode].as_str() {
                Some(s) if s.starts_with("body_error:") => json!("body_error"),
                _ => case[mode].clone(),
            };
            if got != want {
                mismatches.push(format!(
                    "csrf #{i} {mode} {case}: Django {want} != Rust {got}"
                ));
            }
        }
    }
    cases.len()
}

fn check_tokens(web: &Value, mismatches: &mut Vec<String>) -> usize {
    let mut n = 0;
    for t in web["tokens"].as_array().expect("tokens") {
        let (secret, mask, token) = (
            t["secret"].as_str().expect("s"),
            t["mask"].as_str().expect("m"),
            t["token"].as_str().expect("t"),
        );
        if csrf::mask_with(secret, mask) != token
            || csrf::unmask_cipher_token(token) != t["unmasked"]
        {
            mismatches.push(format!("token {t}"));
        }
        n += 1;
    }
    for s in web["secrets"].as_array().expect("secrets") {
        let got = match csrf::get_secret(opt(&s["cookie"])) {
            Ok(secret) => json!({"cookie": s["cookie"], "secret": secret}),
            Err(csrf::InvalidTokenFormat::IncorrectLength) => {
                json!({"cookie": s["cookie"], "error": "has incorrect length"})
            }
            Err(csrf::InvalidTokenFormat::InvalidCharacters) => {
                json!({"cookie": s["cookie"], "error": "has invalid characters"})
            }
        };
        if &got != s {
            mismatches.push(format!("secret: Django {s} != Rust {got}"));
        }
        n += 1;
    }
    n
}

fn check_cookies(web: &Value, now: f64, mismatches: &mut Vec<String>) -> usize {
    let c = &web["cookies"];
    let mut n = 0;
    for case in c["set"].as_array().expect("set") {
        let cookie = Cookie {
            name: case["name"].as_str().expect("name").to_owned(),
            value: case["value"].as_str().expect("value").to_owned(),
            max_age: case["max_age"].as_f64(),
            expires: case["expires"].as_str().map(str::to_owned),
            path: Some(case["path"].as_str().unwrap_or("/").to_owned()),
            domain: case["domain"].as_str().map(str::to_owned),
            secure: case["secure"] == true,
            httponly: case["httponly"] == true,
            samesite: samesite(&case["samesite"]),
        };
        let got = cookie
            .output(now)
            .unwrap_or_else(|_| "error:CookieError".to_owned());
        if case["output"] != got.as_str() {
            mismatches.push(format!("set_cookie {case}: Rust {got:?}"));
        }
        n += 1;
    }
    for case in c["delete"].as_array().expect("delete") {
        let got = Cookie::delete(
            case["name"].as_str().expect("name"),
            case["path"].as_str().expect("path"),
            opt(&case["domain"]),
            samesite(&case["samesite"]),
        )
        .output(now)
        .expect("output");
        if case["output"] != got.as_str() {
            mismatches.push(format!("delete_cookie {case}: Rust {got:?}"));
        }
        n += 1;
    }
    for case in c["vary"].as_array().expect("vary") {
        let got = cookie::patch_vary_headers(opt(&case["existing"]), &["Cookie"]);
        if case["vary"] != got.as_str() {
            mismatches.push(format!("vary {case}: Rust {got:?}"));
        }
        n += 1;
    }
    for case in c["http_date"].as_array().expect("dates") {
        let got = cookie::http_date(case["t"].as_f64().expect("t"));
        if case["date"] != got.as_str() {
            mismatches.push(format!("http_date {case}: Rust {got:?}"));
        }
        n += 1;
    }
    n
}

fn check_session_cookie(web: &Value, now: f64, mismatches: &mut Vec<String>) -> usize {
    let s = &web["session_cookie"];
    let secret_key = s["secret_key"].as_str().expect("secret key");
    let web_path = s["web_path"].as_str().expect("web path");
    let mut n = 0;
    for case in s["encode"].as_array().expect("encode") {
        let got = cookie::encode_session(
            case["key"].as_str().expect("key"),
            opt(&case["uid"]),
            secret_key,
        );
        if case["jwt"] != got.as_str() {
            mismatches.push(format!("encode_session {case}: Rust {got}"));
        }
        n += 1;
    }
    for case in s["responses"].as_array().expect("responses") {
        let effect = cookie::session_process_response(
            &SessionResponse {
                had_cookie: case["had_cookie"] == true,
                accessed: case["accessed"] == true,
                modified: case["modified"] == true,
                empty: case["empty"] == true,
                session_key: opt(&case["key"]),
                user_uid: opt(&case["uid"]),
                expiry_age: case["expiry"].as_f64(),
                status: u16::try_from(case["status"].as_u64().expect("status")).expect("status"),
                secure: case["secure"] == true,
                web_path,
                cookie_domain: None,
            },
            secret_key,
            now,
        )
        .expect("cookie");
        let got = json!({"cookies": effect.cookies, "vary": effect.vary_cookie.then_some("Cookie"), "saved": effect.save});
        let want =
            json!({"cookies": case["cookies"], "vary": case["vary"], "saved": case["saved"]});
        if got != want {
            mismatches.push(format!("process_response {case}: Rust {got}"));
        }
        n += 1;
    }
    for case in s["csrf"].as_array().expect("csrf cookie") {
        let state = CsrfState {
            cookie: opt(&case["cookie"]).map(str::to_owned),
            needs_update: case["needs_update"] == true,
        };
        let got = cookie::csrf_process_response(&state, case["secure"] == true, web_path, now)
            .expect("cookie");
        let got = json!({"cookies": got.iter().collect::<Vec<_>>(), "vary": got.as_ref().map(|_| "Cookie")});
        let want = json!({"cookies": case["cookies"], "vary": case["vary"]});
        if got != want {
            mismatches.push(format!("csrf process_response {case}: Rust {got}"));
        }
        n += 1;
    }
    n
}

fn check_is_secure(web: &Value, mismatches: &mut Vec<String>) -> usize {
    let cases = web["is_secure"].as_array().expect("is_secure");
    for case in cases {
        let got = cookie::session_is_secure(
            case["request_secure"] == true,
            opt(&case["host"]),
            case["debug"] == true,
            case["ua"].as_str().expect("ua"),
        );
        if case["secure"] != got {
            mismatches.push(format!("is_secure {case}: Rust {got}"));
        }
    }
    cases.len()
}

fn check_redirects(web: &Value, mismatches: &mut Vec<String>) -> usize {
    let cases = web["redirects"].as_array().expect("redirects");
    for case in cases {
        let path = url::request_path(&url::path_info(
            case["path_info_raw"].as_str().expect("path").as_bytes(),
        ));
        let full_path = url::get_full_path(&path, case["query"].as_str().expect("query"));
        let location = url::login_redirect("/", &full_path);
        let got = json!({"full_path": full_path, "location": location});
        let want = json!({"full_path": case["full_path"], "location": case["location"]});
        if got != want {
            mismatches.push(format!(
                "redirect {}: Django {want} != Rust {got}",
                case["path_info_raw"]
            ));
        }
    }
    cases.len()
}

fn check_bindings(web: &Value, geoip: &GeoIp, mismatches: &mut Vec<String>) -> usize {
    let cases = web["bindings"].as_array().expect("bindings");
    for case in cases {
        let binding = |v: &Value| v.as_str().map(|s| Some(s.to_owned()));
        let got = match binding::recheck(
            geoip,
            &binding(&case["net"]),
            &binding(&case["geo"]),
            opt(&case["last_ip"]),
            case["new_ip"].as_str().expect("new ip"),
        ) {
            Ok(Recheck::Unchanged) => "unchanged".to_owned(),
            Ok(Recheck::Passed { set_last_ip: true }) => "passed:set_last_ip".to_owned(),
            Ok(Recheck::Passed { set_last_ip: false }) => "passed".to_owned(),
            Ok(Recheck::Broken(reason)) => format!("broken:{reason}"),
            Err(err) => format!("error:{err:?}"),
        };
        if case["result"] != got.as_str() {
            mismatches.push(format!("binding {case}: Rust {got}"));
        }
    }
    cases.len()
}

#[expect(
    clippy::tests_outside_test_module,
    reason = "an integration test file is its own test crate"
)]
#[test]
fn web_matches_django() {
    let (Ok(path), Ok(geoip_dir)) = (std::env::var("AK_AUTH_WEB"), std::env::var("AK_GEOIP_DIR"))
    else {
        eprintln!("AK_AUTH_WEB unset; skipping (tests/auth/run.sh sets it)");
        return;
    };
    let web: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read")).expect("JSON");
    let geoip = GeoIp::new(
        Some(&format!("{geoip_dir}/GeoLite2-ASN.mmdb")),
        Some(&format!("{geoip_dir}/GeoLite2-City.mmdb")),
    )
    .expect("GeoIP");
    let now = web["now"].as_f64().expect("now");
    let mut mismatches = Vec::new();
    let counts = [
        ("CSRF requests", check_csrf(&web, &mut mismatches)),
        ("tokens and secrets", check_tokens(&web, &mut mismatches)),
        (
            "cookies, Vary and dates",
            check_cookies(&web, now, &mut mismatches),
        ),
        (
            "session/CSRF cookie responses",
            check_session_cookie(&web, now, &mut mismatches),
        ),
        ("is_secure", check_is_secure(&web, &mut mismatches)),
        ("login redirects", check_redirects(&web, &mut mismatches)),
        (
            "binding rechecks",
            check_bindings(&web, &geoip, &mut mismatches),
        ),
    ];
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    let summary: Vec<String> = counts
        .iter()
        .map(|(what, n)| format!("{n} {what}"))
        .collect();
    eprintln!("identical to Django: {}", summary.join(", "));
}

/// `expires=…` differs by when the server answered; everything else must not.
fn without_expires(cookie: &str) -> String {
    cookie
        .split("; ")
        .filter(|part| !part.starts_with("expires="))
        .collect::<Vec<_>>()
        .join("; ")
}

#[expect(
    clippy::tests_outside_test_module,
    reason = "an integration test file is its own test crate"
)]
#[test]
fn http_answers_match() {
    let Ok(path) = std::env::var("AK_AUTH_HTTP") else {
        eprintln!("AK_AUTH_HTTP unset; skipping (tests/auth/run.sh sets it)");
        return;
    };
    let cases: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read")).expect("JSON");
    let mut mismatches = Vec::new();
    for case in &cases {
        let headers = &case["headers"];
        let secure = csrf::is_secure(opt(&headers["X-Forwarded-Proto"]), "http");
        let set_cookie: Vec<&str> = case["set_cookie"]
            .as_array()
            .expect("set-cookie")
            .iter()
            .filter_map(Value::as_str)
            .collect();
        if case["kind"] == "csrf" {
            let cookie = opt(&case["csrf_cookie"]);
            let outcome = csrf::process_view(
                &csrf::Request {
                    method: "POST",
                    host: "authentik.test",
                    secure,
                    origin: opt(&headers["Origin"]),
                    referer: opt(&headers["Referer"]),
                    header_token: opt(&headers["X-authentik-CSRF"]),
                    post_token: PostToken::Absent,
                },
                cookie,
            );
            let detail = case["detail"].as_str().unwrap_or_default();
            let ok = match &outcome {
                Outcome::Reject(reason) => detail == format!("CSRF Failed: {reason}"),
                Outcome::Accept => !detail.starts_with("CSRF Failed"),
                Outcome::BodyError => false,
            };
            if !ok || case["status"] != 403_u16 {
                mismatches.push(format!(
                    "{}: server {detail:?} vs Rust {outcome:?}",
                    case["name"]
                ));
            }
            // A malformed cookie is replaced by a fresh secret.
            let state = csrf::process_request(cookie);
            let expected: Vec<String> = cookie::csrf_process_response(&state, secure, "/", 0.0)
                .expect("cookie")
                .into_iter()
                .collect();
            let got: Vec<String> = set_cookie
                .iter()
                .map(|c| {
                    let value = c.split(';').next().unwrap_or_default();
                    let secret = value.trim_start_matches("authentik_csrf=");
                    without_expires(&c.replacen(
                        secret,
                        state.cookie.as_deref().unwrap_or_default(),
                        1,
                    ))
                })
                .collect();
            let expected: Vec<String> = expected.iter().map(|c| without_expires(c)).collect();
            if got != expected {
                mismatches.push(format!(
                    "{} cookies: server {set_cookie:?} vs Rust {expected:?}",
                    case["name"]
                ));
            }
        } else {
            let samesite = if secure { "None" } else { "Lax" };
            let expected = Cookie::delete("authentik_session", "/", None, Some(samesite))
                .output(0.0)
                .expect("cookie");
            if set_cookie != [expected.as_str()] {
                mismatches.push(format!(
                    "{}: server {set_cookie:?} vs Rust {expected:?}",
                    case["name"]
                ));
            }
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    eprintln!(
        "{} answers on the wire match (CSRF through DRF, cookie deletion)",
        cases.len()
    );
}

#[expect(
    clippy::tests_outside_test_module,
    reason = "an integration test file is its own test crate"
)]
#[tokio::test]
async fn client_ip_matches_django() {
    let (Ok(path), Ok(url)) = (
        std::env::var("AK_AUTH_WEB"),
        std::env::var("AK_AUTH_DATABASE_URL"),
    ) else {
        eprintln!("AK_AUTH_WEB unset; skipping (tests/auth/run.sh sets it)");
        return;
    };
    let web: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read")).expect("JSON");
    let pool = sqlx::PgPool::connect(&url).await.expect("connect");
    let cases = web["client_ip"].as_array().expect("client_ip");
    let mut mismatches = Vec::new();
    for case in cases {
        let got = ak_auth::client_ip::client_ip(
            &pool,
            opt(&case["xff"]),
            opt(&case["remote"]),
            opt(&case["remote_ip"]),
            opt(&case["token"]),
            chrono::Utc::now(),
        )
        .await
        .expect("client ip");
        let got = json!({"ip": got.ip, "outpost_user": got.outpost_user});
        let want = json!({"ip": case["ip"], "outpost_user": case["outpost_user"]});
        if got != want {
            mismatches.push(format!("{case}: Rust {got}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
    eprintln!(
        "{} client IPs (X-Forwarded-For, REMOTE_ADDR, outpost override) match",
        cases.len()
    );
}
