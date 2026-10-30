//! Emits Rust-generated hashes as JSON lines so the reference Django can
//! verify them (reverse direction of the differential test).
#![expect(clippy::print_stdout, reason = "CLI output")]

use ak_passwords::{
    Argon2Hasher, BCryptSha256Hasher, Hasher, PasswordHashers, Pbkdf2Sha1Hasher, ScryptHasher,
};

fn main() {
    let passwords = [
        "",
        "password",
        "lètmein",
        "日本語パスワード",
        "🔐🔑 emoji",
        "a$b",
    ];
    let others: [&dyn Hasher; 4] = [
        &Pbkdf2Sha1Hasher::default(),
        &Argon2Hasher::default(),
        &BCryptSha256Hasher::default(),
        &ScryptHasher::default(),
    ];
    let hashers = PasswordHashers::default();
    for password in passwords {
        let mut encoded = vec![
            hashers
                .make_password(Some(password))
                .expect("make_password"),
        ];
        for hasher in others {
            encoded.push(hasher.encode(password, &hasher.salt()).expect("encode"));
        }
        for e in encoded {
            println!(
                "{}",
                serde_json::json!({"password": password, "encoded": e})
            );
        }
    }
    println!(
        "{}",
        serde_json::json!({"password": "x", "encoded": hashers.make_password(None).expect("unusable")})
    );
}
