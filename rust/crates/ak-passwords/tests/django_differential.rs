//! Differential test against the pinned upstream (authentik 2026.8.5,
//! Django 5.2.17). The fixture is produced by
//! `tests/differential/passwords/django_fixture.py` inside the reference
//! container; regenerate it with `tests/differential/passwords/run.sh`.

#[cfg(test)]
mod tests {
    use ak_passwords::{
        Argon2Hasher, BCryptSha256Hasher, Hasher as _, PasswordHashers, Pbkdf2Hasher,
        Pbkdf2Sha1Hasher, ScryptHasher, is_password_usable,
    };
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Fixture {
        encode: Vec<EncodeCase>,
        verify: Vec<VerifyCase>,
    }

    #[derive(Deserialize)]
    struct EncodeCase {
        algorithm: String,
        password: String,
        salt: String,
        iterations: Option<u32>,
        encoded: String,
    }

    #[derive(Deserialize)]
    struct VerifyCase {
        password: Option<String>,
        encoded: Option<String>,
        usable: bool,
        result: Outcome,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "lowercase")]
    enum Outcome {
        Ok((bool, bool)),
        Error(String),
    }

    fn fixture() -> Fixture {
        serde_json::from_str(include_str!("fixtures/django_hashers.json")).expect("fixture")
    }

    #[test]
    fn encodings_are_byte_identical() {
        let mut checked = 0_usize;
        for case in fixture().encode {
            let ours = match case.algorithm.as_str() {
                "pbkdf2_sha256" => Pbkdf2Hasher::default().encode_with_iterations(
                    &case.password,
                    &case.salt,
                    case.iterations.expect("iterations"),
                ),
                "pbkdf2_sha1" => Pbkdf2Sha1Hasher::default().encode_with_iterations(
                    &case.password,
                    &case.salt,
                    case.iterations.expect("iterations"),
                ),
                "argon2" => Argon2Hasher::default().encode(&case.password, &case.salt),
                "bcrypt_sha256" => BCryptSha256Hasher::default().encode(&case.password, &case.salt),
                "scrypt" => ScryptHasher::default().encode(&case.password, &case.salt),
                other => panic!("unexpected algorithm {other}"),
            }
            .expect("encode");
            assert_eq!(
                ours, case.encoded,
                "{} password={:?} salt={:?}",
                case.algorithm, case.password, case.salt
            );
            checked += 1_usize;
        }
        assert!(
            checked >= 150_usize,
            "fixture unexpectedly small: {checked}"
        );
    }

    #[test]
    fn verify_password_matches_django() {
        let hashers = PasswordHashers::default();
        for case in fixture().verify {
            let label = format!("password={:?} encoded={:?}", case.password, case.encoded);
            assert_eq!(
                is_password_usable(case.encoded.as_deref()),
                case.usable,
                "usable: {label}"
            );
            let ours = hashers.verify_password(case.password.as_deref(), case.encoded.as_deref());
            match case.result {
                Outcome::Ok((is_correct, must_update)) => {
                    let ours =
                        ours.unwrap_or_else(|e| panic!("Django returned, we raised {e}: {label}"));
                    assert_eq!(
                        (ours.is_correct, ours.must_update),
                        (is_correct, must_update),
                        "{label}"
                    );
                }
                Outcome::Error(exc) => {
                    assert!(
                        ours.is_err(),
                        "Django raised {exc}, we returned {ours:?}: {label}"
                    );
                }
            }
        }
    }
}
