# Runs inside the reference authentik container (`ak shell`). Produces the
# Django side of the password-hasher differential test: deterministic encodings
# with fixed salts, plus verify_password outcomes (or the exception Django raises)
# for correct, wrong, outdated and malformed hashes.
import json
import sys

from django.contrib.auth.hashers import (
    Argon2PasswordHasher,
    BCryptSHA256PasswordHasher,
    PBKDF2PasswordHasher,
    PBKDF2SHA1PasswordHasher,
    ScryptPasswordHasher,
    is_password_usable,
    make_password,
    verify_password,
)

PASSWORDS = [
    "",
    "password",
    "lètmein",
    "日本語パスワード",
    "🔐🔑 emoji",
    "pass word$with$dollars",
    "a" * 100,
    "nul\x00inside",
]
SALTS = ["seasalt2", "abcdefghijklmnopqrstuv", "x" * 30]


def outcome(fn):
    try:
        return {"ok": fn()}
    except Exception as exc:  # noqa: BLE001 - recording the exact upstream failure
        return {"error": type(exc).__name__}


encode = []
for password in PASSWORDS:
    for salt in SALTS:
        for iterations in (1, 1000, 1000000):
            encode.append(
                {
                    "algorithm": "pbkdf2_sha256",
                    "password": password,
                    "salt": salt,
                    "iterations": iterations,
                    "encoded": PBKDF2PasswordHasher().encode(password, salt, iterations),
                }
            )
        encode.append(
            {
                "algorithm": "pbkdf2_sha1",
                "password": password,
                "salt": salt,
                "iterations": 1000,
                "encoded": PBKDF2SHA1PasswordHasher().encode(password, salt, 1000),
            }
        )
        encode.append(
            {
                "algorithm": "scrypt",
                "password": password,
                "salt": salt,
                "encoded": ScryptPasswordHasher().encode(password, salt),
            }
        )
        encode.append(
            {
                "algorithm": "argon2",
                "password": password,
                "salt": salt,
                "encoded": Argon2PasswordHasher().encode(password, salt),
            }
        )
    bcrypt_salt = "$2b$12$abcdefghijklmnopqrstuu"
    encode.append(
        {
            "algorithm": "bcrypt_sha256",
            "password": password,
            "salt": bcrypt_salt,
            "encoded": BCryptSHA256PasswordHasher().encode(password, bcrypt_salt.encode()),
        }
    )

# Hashes produced with Django's own random salts, as stored in real databases.
generated = []
for password in PASSWORDS[:4]:
    for hasher in ("pbkdf2_sha256", "pbkdf2_sha1", "argon2", "bcrypt_sha256", "scrypt"):
        generated.append({"password": password, "encoded": make_password(password, hasher=hasher)})

stale_pbkdf2 = PBKDF2PasswordHasher().encode("password", "abcdefghijklmnopqrstuv", 1000)
short_salt = PBKDF2PasswordHasher().encode("password", "short", 1000000)
weak_argon2 = (
    "argon2$argon2id$v=19$m=8,t=1,p=1$YWJjZGVmZ2hpams$"
    + "A" * 43
)
verify_inputs = [
    (g["password"], g["encoded"]) for g in generated
] + [
    ("wrong", g["encoded"]) for g in generated
] + [
    ("password", stale_pbkdf2),
    ("wrong", stale_pbkdf2),
    ("password", short_salt),
    ("password", None),
    (None, stale_pbkdf2),
    ("password", ""),
    ("password", "!unusable"),
    ("password", "5f4dcc3b5aa765d61d8327deb882cf99"),
    ("password", "md5$$5f4dcc3b5aa765d61d8327deb882cf99"),
    ("password", "sha1$$5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"),
    ("password", "plaintext"),
    ("password", "pbkdf2_sha256$abc$salt$hash"),
    ("password", "pbkdf2_sha256$1000"),
    ("password", "pbkdf2_sha256$0$abcdefghijklmnopqrstuv$hash"),
    ("password", "pbkdf2_sha1$1000$salt"),
    ("password", "argon2$argon2id$v=19$m=8,t=1"),
    ("password", "argon2$argon2x$v=19$m=8,t=1,p=1$YWJjZGVmZ2g$aGFzaGhhc2g"),
    ("password", "argon2$argon2id$v=19$m=8,t=1,p=1$YWJj$aGFzaGhhc2g"),
    ("password", weak_argon2),
    ("password", "bcrypt_sha256$$2b$12$short"),
    ("password", "bcrypt_sha256$$2c$12$abcdefghijklmnopqrstuu"),
    ("password", "bcrypt_sha256$$2b$03$abcdefghijklmnopqrstuu"),
    ("password", "scrypt$32768$abcdefghijklmnopqrstuv$8$1$hash"),
    ("password", "scrypt$3$abcdefghijklmnopqrstuv$8$1$hash"),
    ("password", "scrypt$16384$abcdefghijklmnopqrstuv$8$1"),
]
verify = []
for password, encoded in verify_inputs:
    verify.append(
        {
            "password": password,
            "encoded": encoded,
            "usable": is_password_usable(encoded),
            "result": outcome(lambda: list(verify_password(password, encoded))),
        }
    )

sys.stdout.write(
    "@@FIXTURE@@"
    + json.dumps({"encode": encode, "verify": verify}, sort_keys=True, ensure_ascii=False)
    + "\n"
)
