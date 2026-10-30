//! Multi-table inheritance differential: the class [`ak_models::inheritance`]
//! resolves for every row of each hierarchy must be the one Django's
//! `select_subclasses()` returns (`AK_MODELS_DJANGO_CLASSES`, written by
//! `tests/models/run.sh`; skipped when unset).

use std::collections::BTreeMap;

use ak_models::generated::INHERITANCE_ROOTS;
use sqlx::PgPool;

#[expect(
    clippy::tests_outside_test_module,
    reason = "an integration test file is its own test crate"
)]
#[tokio::test]
async fn subclasses_match_django() {
    let (Ok(url), Ok(path)) = (
        std::env::var("AK_MODELS_DATABASE_URL"),
        std::env::var("AK_MODELS_DJANGO_CLASSES"),
    ) else {
        eprintln!("AK_MODELS_DATABASE_URL/AK_MODELS_DJANGO_CLASSES unset; skipping");
        return;
    };
    let django: BTreeMap<String, BTreeMap<String, String>> =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read classes")).expect("JSON");
    let pool = PgPool::connect(&url).await.expect("connect");
    for (root, _) in INHERITANCE_ROOTS {
        let rust: BTreeMap<String, String> = ak_models::inheritance::resolve(&pool, root)
            .await
            .expect("resolve")
            .into_iter()
            .collect();
        let expected = django.get(*root).expect("root in Django output");
        assert_eq!(&rust, expected, "{root}");
        eprintln!("{root}: {} rows match Django", rust.len());
    }
}
