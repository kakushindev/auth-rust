//! M6 permission differential: for every subject in `AK_RBAC_DJANGO`
//! (`tests/rbac/rbac_decide.py`, written by `tests/rbac/run.sh`), every
//! permission decision must be Django's.

use ak_rbac::{
    Access, Error, Model, Object, ObjectFilter, PkCast, Subject, Visible, get_objects_for_user,
    has_object_permission, has_perm, has_permission, object_filter, permission_required,
};
use serde_json::{Value, json};
use sqlx::PgPool;

fn model(m: &Value) -> Model<'_> {
    let s = |k: &str| m[k].as_str().expect("model field");
    Model {
        app_label: s("app_label"),
        model_name: s("model_name"),
        ctype_app_label: s("ctype_app_label"),
        ctype_model: s("ctype_model"),
        db_table: s("db_table"),
        pk_column: s("pk_column"),
        pk_cast: if s("pk_cast") == "uuid" {
            PkCast::Uuid
        } else {
            PkCast::Bigint
        },
    }
}

fn error_name(err: &Error) -> String {
    match err {
        Error::Database(_) => format!("error:{}", err.db_class().unwrap_or("DatabaseError")),
        Error::WrongApp => "error:WrongAppError".to_owned(),
        Error::Guardian => "error:GuardianError".to_owned(),
        Error::MixedContentType => "error:MixedContentTypeError".to_owned(),
        Error::DoesNotExist => "error:DoesNotExist".to_owned(),
        Error::MultipleObjectsReturned => "error:MultipleObjectsReturned".to_owned(),
        Error::MethodNotAllowed => "MethodNotAllowed".to_owned(),
    }
}

fn strings(v: &Value) -> Vec<&str> {
    v.as_array()
        .expect("array")
        .iter()
        .filter_map(Value::as_str)
        .collect()
}

/// The rows a `Visible` leaves of the model's table, as Django lists them.
fn visible_rows(visible: &Visible, pks: &[&str]) -> Value {
    match visible {
        Visible::All => json!("all"),
        Visible::Pks(found) => {
            let mut rows: Vec<&str> = pks
                .iter()
                .copied()
                .filter(|pk| found.iter().any(|f| f == pk))
                .collect();
            rows.sort_unstable();
            json!(rows)
        }
    }
}

#[expect(
    clippy::tests_outside_test_module,
    reason = "an integration test file is its own test crate"
)]
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one pass over each recorded decision kind"
)]
async fn permissions_match_django() {
    let (Ok(url), Ok(path)) = (
        std::env::var("AK_RBAC_DATABASE_URL"),
        std::env::var("AK_RBAC_DJANGO"),
    ) else {
        eprintln!("AK_RBAC_* unset; skipping (tests/rbac/run.sh sets them)");
        return;
    };
    let django: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read")).expect("JSON");
    let pool = PgPool::connect(&url).await.expect("connect");
    let models = django["models"].as_array().expect("models");
    let all_perms: Vec<&str> = strings(&django["all_perms"])
        .into_iter()
        .chain(strings(&django["extra_perms"]))
        .collect();
    let mut mismatches = Vec::new();
    let mut counts = [0_usize; 6];

    for record in django["subjects"].as_array().expect("subjects") {
        let name = record["name"].as_str().expect("name");
        let subject = if record["anonymous"] == true {
            Subject::anonymous(&pool).await.expect("anonymous")
        } else {
            let id = i32::try_from(record["user_id"].as_i64().expect("id")).expect("id");
            Subject::load(&pool, id, record["is_active"].as_bool())
                .await
                .expect("subject")
        };

        // Global permissions.
        let mut granted = Vec::new();
        for perm in &all_perms {
            if has_perm(&pool, &subject, perm, None)
                .await
                .expect("has_perm")
            {
                granted.push(*perm);
            }
        }
        if json!(granted) != record["global"] {
            mismatches.push(format!(
                "{name} global: Django {} != Rust {granted:?}",
                record["global"]
            ));
        }
        counts[0] += all_perms.len();

        // Object permissions.
        for entry in record["objects"].as_array().expect("objects") {
            let m =
                &models[usize::try_from(entry["model"].as_u64().expect("model")).expect("index")];
            // The instance's own model: a parent model yields subclass rows.
            let own = |k: &str| entry[k].as_str().expect("object model");
            let obj = Object {
                model: Model {
                    app_label: own("obj_app_label"),
                    model_name: own("obj_model_name"),
                    ctype_app_label: own("obj_ctype_app_label"),
                    ctype_model: own("obj_ctype_model"),
                    ..model(m)
                },
                pk: entry["pk"].as_str().expect("pk"),
            };
            let (mut granted, mut errors) = (Vec::new(), serde_json::Map::new());
            for perm in strings(&entry["checked"]) {
                match has_perm(&pool, &subject, perm, Some(&obj)).await {
                    Ok(true) => granted.push(perm),
                    Ok(false) => {}
                    Err(err) => {
                        errors.insert(perm.to_owned(), json!(error_name(&err)));
                    }
                }
                counts[1] += 1;
            }
            let got = json!({"granted": granted, "errors": errors});
            let want = json!({"granted": entry["granted"], "errors": entry["errors"]});
            if got != want {
                mismatches.push(format!(
                    "{name} {}.{} {}: Django {want} != Rust {got}",
                    m["app_label"], m["model_name"], obj.pk
                ));
            }
        }

        // get_objects_for_user.
        for entry in record["get_objects"].as_array().expect("get_objects") {
            let m =
                &models[usize::try_from(entry["model"].as_u64().expect("model")).expect("index")];
            let perms = strings(&entry["perms"]);
            let got = match get_objects_for_user(&pool, &subject, &perms, &model(m)).await {
                Ok(visible) => visible_rows(&visible, &strings(&m["pks"])),
                Err(err) => json!(error_name(&err)),
            };
            if got != entry["result"] {
                mismatches.push(format!(
                    "{name} get_objects {}.{} {perms:?}: Django {} != Rust {got}",
                    m["app_label"], m["model_name"], entry["result"]
                ));
            }
            counts[2] += 1;
        }

        // ObjectFilter.
        for entry in record["object_filter"].as_array().expect("object_filter") {
            let m =
                &models[usize::try_from(entry["model"].as_u64().expect("model")).expect("index")];
            let pks = strings(&m["pks"]);
            let got = match object_filter(&pool, &subject, &model(m), entry["owner"] == true).await
            {
                Ok(ObjectFilter::All) => json!("all"),
                Ok(ObjectFilter::Owner) => json!("owner"),
                Ok(ObjectFilter::Visible {
                    visible,
                    deny_if_empty,
                }) => {
                    let rows = visible_rows(&visible, &pks);
                    let empty = match &rows {
                        Value::Array(a) => a.is_empty(),
                        _ => pks.is_empty(),
                    };
                    if deny_if_empty && empty {
                        json!("denied")
                    } else {
                        rows
                    }
                }
                Err(err) => json!(error_name(&err)),
            };
            if got != entry["result"] {
                mismatches.push(format!(
                    "{name} ObjectFilter {}.{} owner={}: Django {} != Rust {got}",
                    m["app_label"], m["model_name"], entry["owner"], entry["result"]
                ));
            }
            counts[3] += 1;
        }

        // DRF ObjectPermissions.
        for entry in record["drf"].as_array().expect("drf") {
            let m =
                &models[usize::try_from(entry["model"].as_u64().expect("model")).expect("index")];
            let method = entry["method"].as_str().expect("method");
            let got = if entry["kind"] == "has_permission" {
                match has_permission(
                    &pool,
                    &subject,
                    method,
                    &model(m),
                    entry["lookup"] == true,
                    entry["allow_create"] == true,
                )
                .await
                {
                    Ok(b) => json!(b),
                    Err(err) => json!(error_name(&err)),
                }
            } else {
                let obj = Object {
                    model: model(m),
                    pk: entry["pk"].as_str().expect("pk"),
                };
                match has_object_permission(
                    &pool,
                    &subject,
                    method,
                    &obj,
                    entry["owner_matches"] == true,
                )
                .await
                {
                    Ok(Access::Allow) => json!(true),
                    Ok(Access::Deny) => json!(false),
                    Ok(Access::NotFound) => json!("Http404"),
                    Err(err) => json!(error_name(&err)),
                }
            };
            if got != entry["result"] {
                mismatches.push(format!("{name} {entry}: Rust {got}"));
            }
            counts[4] += 1;
        }

        // permission_required.
        for entry in record["permission_required"]
            .as_array()
            .expect("permission_required")
        {
            let m =
                &models[usize::try_from(entry["model"].as_u64().expect("model")).expect("index")];
            let obj = entry["pk"].as_str().map(|pk| Object {
                model: model(m),
                pk,
            });
            let got = match permission_required(
                &pool,
                &subject,
                entry["obj_perm"].as_str(),
                obj.as_ref(),
                &strings(&entry["global_perms"]),
            )
            .await
            {
                Ok(Access::Allow) => json!("allow"),
                Ok(Access::Deny) => json!("deny"),
                Ok(Access::NotFound) => json!("not_found"),
                Err(err) => json!(error_name(&err)),
            };
            if got != entry["result"] {
                mismatches.push(format!("{name} {entry}: Rust {got}"));
            }
            counts[5] += 1;
        }
    }
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
    eprintln!(
        "identical to Django for {} subjects: {} global and {} object has_perm, {} \
         get_objects_for_user, {} ObjectFilter, {} ObjectPermissions, {} permission_required",
        django["subjects"].as_array().map_or(0, Vec::len),
        counts[0],
        counts[1],
        counts[2],
        counts[3],
        counts[4],
        counts[5]
    );
}
