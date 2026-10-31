//! Lookups against the reference image's `GeoLite2` databases must equal
//! `CPython`'s `maxminddb` and `geoip2` on every address in the vectors
//! (`tests/geoip/gen_vectors.py`; `tests/geoip/run.sh` sets `AK_GEOIP_DIR`).

use std::path::PathBuf;

use ak_geoip::{LookupError, Reader, Record, Value, parse_ip};
use serde_json::{Value as Json, json};

fn to_json(value: &Value) -> Json {
    match value {
        Value::Str(s) => json!(s),
        Value::Double(f) | Value::Float(f) => json!(f),
        Value::Bytes(b) => json!(b),
        Value::Uint(n) => u64::try_from(*n).map_or_else(|_| json!(n.to_string()), |n| json!(n)),
        Value::Int(n) => json!(n),
        Value::Map(items) => {
            Json::Object(items.iter().map(|(k, v)| (k.clone(), to_json(v))).collect())
        }
        Value::Array(items) => Json::Array(items.iter().map(to_json).collect()),
        Value::Bool(b) => json!(b),
    }
}

fn record_json(record: &Record, fields: &[&str]) -> Json {
    Json::Object(
        fields
            .iter()
            .filter_map(|f| record.get(f).map(|v| ((*f).to_owned(), to_json(v))))
            .collect(),
    )
}

/// Equal, floats within one ULP (`serde_json` parses without `float_roundtrip`).
fn same(a: &Json, b: &Json) -> bool {
    match (a, b) {
        (Json::Number(x), Json::Number(y)) if x.is_f64() || y.is_f64() => {
            let (x, y) = (
                x.as_f64().unwrap_or(f64::NAN),
                y.as_f64().unwrap_or(f64::NAN),
            );
            x.to_bits().abs_diff(y.to_bits()) <= 1
        }
        (Json::Array(x), Json::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(p, q))
        }
        (Json::Object(x), Json::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w)))
        }
        _ => a == b,
    }
}

fn error_name(err: LookupError) -> &'static str {
    match err {
        LookupError::Value => "ValueError",
        LookupError::Type => "TypeError",
        LookupError::Invalid(_) => "InvalidDatabaseError",
    }
}

#[expect(
    clippy::tests_outside_test_module,
    reason = "an integration test file is its own test crate"
)]
#[test]
fn lookups_match_cpython() {
    let Ok(dir) = std::env::var("AK_GEOIP_DIR") else {
        eprintln!("AK_GEOIP_DIR unset; skipping (tests/geoip/run.sh sets it)");
        return;
    };
    let dir = PathBuf::from(dir);
    let asn = Reader::open(&dir.join("GeoLite2-ASN.mmdb")).expect("ASN database");
    let city = Reader::open(&dir.join("GeoLite2-City.mmdb")).expect("City database");
    let vectors: Json =
        serde_json::from_str(&std::fs::read_to_string(dir.join("vectors.json")).expect("vectors"))
            .expect("JSON");
    assert_eq!(asn.database_type(), vectors["metadata"]["asn"]["type"]);
    assert_eq!(city.database_type(), vectors["metadata"]["city"]["type"]);

    let mut mismatches = Vec::new();
    let mut check = |ip: &str, what: &str, got: Json, expected: &Json| {
        if !same(&got, expected) {
            mismatches.push(format!("{ip} {what}: Python {expected} != Rust {got}"));
        }
    };
    let cases = vectors["vectors"].as_array().expect("vectors");
    for case in cases {
        let ip_text = case["ip"].as_str().expect("ip");
        let ip = parse_ip(ip_text).expect("address");
        for (what, reader) in [("raw_asn", &asn), ("raw_city", &city)] {
            let got = match reader.get_with_prefix_len(ip) {
                Ok((record, prefix_len)) => {
                    json!({"ok": [record.as_ref().map(to_json), prefix_len]})
                }
                Err(err) => json!({"error": error_name(err)}),
            };
            check(ip_text, what, got, &case[what]);
        }
        let got = match asn.asn(ip) {
            Ok(Some(a)) => json!({"ok": {
                "number": a.autonomous_system_number.as_ref().map(to_json),
                "org": a.autonomous_system_organization.as_ref().map(to_json),
                "network": a.network.to_string(),
            }}),
            Ok(None) => json!({"error": "AddressNotFoundError"}),
            Err(err) => json!({"error": error_name(err)}),
        };
        check(ip_text, "asn", got, &case["asn"]);
        let got = match city.city(ip) {
            Ok(Some(c)) => json!({"ok": {
                "continent": record_json(&c.continent, &["code", "geoname_id", "names"]),
                "country": record_json(
                    &c.country,
                    &["confidence", "geoname_id", "is_in_european_union", "iso_code", "names"],
                ),
                "city": record_json(&c.city, &["confidence", "geoname_id", "names"]),
            }}),
            Ok(None) => json!({"error": "AddressNotFoundError"}),
            Err(err) => json!({"error": error_name(err)}),
        };
        check(ip_text, "city", got, &case["city"]);
        let got = match city.asn(ip) {
            Ok(_) => json!({"ok": null}),
            Err(err) => json!({"error": error_name(err)}),
        };
        check(ip_text, "asn_on_city", got, &case["asn_on_city"]);
    }
    assert!(
        mismatches.is_empty(),
        "{} mismatches:\n{}",
        mismatches.len(),
        mismatches
            .iter()
            .take(30)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    eprintln!(
        "{} addresses look up as CPython's maxminddb and geoip2 do",
        cases.len()
    );
}
