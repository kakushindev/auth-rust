//! Verifies a hash read from a real authentik database against a password,
//! both passed via the environment so neither ends up in shell history.
#![expect(clippy::print_stdout, reason = "CLI output")]

use ak_passwords::PasswordHashers;

fn main() {
    let stored = std::env::var("AK_STORED_HASH").expect("AK_STORED_HASH");
    let password = std::env::var("AK_PASSWORD").expect("AK_PASSWORD");
    let algorithm = stored.split('$').next().unwrap_or_default();
    let hashers = PasswordHashers::default();
    let right = hashers
        .verify_password(Some(&password), Some(&stored))
        .expect("verify");
    let wrong = hashers
        .verify_password(Some(&format!("{password}x")), Some(&stored))
        .expect("verify");
    println!(
        "stored {algorithm} hash: correct password -> {}, wrong password -> {}, must_update -> {}",
        right.is_correct, wrong.is_correct, right.must_update
    );
    assert!(right.is_correct && !wrong.is_correct);
}
