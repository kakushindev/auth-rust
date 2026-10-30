//! Django-compatible password hashing, as used by authentik.
//!
//! authentik stores `User.password` with Django's default `PASSWORD_HASHERS`
//! (Django 5.2.17, no override in `authentik/root/settings.py`):
//!
//! 1. `pbkdf2_sha256` (preferred, 1 000 000 iterations)
//! 2. `pbkdf2_sha1`
//! 3. `argon2` (argon2-cffi format)
//! 4. `bcrypt_sha256`
//! 5. `scrypt`
//!
//! This crate mirrors `django.contrib.auth.hashers`: the encoded formats,
//! `identify_hasher`, `verify_password` (including `must_update` and
//! `harden_runtime`), `make_password` and `is_password_usable`. Places where
//! Django raises instead of returning `False` are surfaced as [`HashError`],
//! so callers can reproduce the upstream failure mode rather than silently
//! treating a malformed hash as a wrong password.

mod argon2_hasher;
mod bcrypt_hasher;
mod pbkdf2_hasher;
mod random;
mod scrypt_hasher;

pub use argon2_hasher::Argon2Hasher;
pub use bcrypt_hasher::BCryptSha256Hasher;
pub use pbkdf2_hasher::{PBKDF2_ITERATIONS, Pbkdf2Hasher, Pbkdf2Sha1Hasher};
pub use random::get_random_string;
pub use scrypt_hasher::ScryptHasher;

/// `django.contrib.auth.hashers.UNUSABLE_PASSWORD_PREFIX`
pub const UNUSABLE_PASSWORD_PREFIX: &str = "!";
/// `django.contrib.auth.hashers.UNUSABLE_PASSWORD_SUFFIX_LENGTH`
pub const UNUSABLE_PASSWORD_SUFFIX_LENGTH: usize = 40;
/// `BasePasswordHasher.salt_entropy`
pub const SALT_ENTROPY: f64 = 128.0;

/// Conditions under which the Django implementation raises an exception
/// rather than returning a boolean.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum HashError {
    /// The stored value could not be decoded by the hasher selected for it
    /// (Django: `ValueError` from tuple unpacking / `int()` in `decode`).
    #[error("malformed {algorithm} hash: {reason}")]
    Malformed {
        algorithm: &'static str,
        reason: &'static str,
    },
    /// The underlying KDF rejected the parameters (Django: `ValueError` from
    /// `hashlib`, `bcrypt` or `argon2`).
    #[error("{algorithm} rejected parameters: {reason}")]
    InvalidParameters {
        algorithm: &'static str,
        reason: String,
    },
    /// `_check_encode_args`: salt empty or containing `$`.
    #[error("salt must be provided and cannot contain $")]
    InvalidSalt,
    /// `identify_hasher(None)` calls `len(None)` (Django: `TypeError`).
    #[error("encoded password is None")]
    EncodedIsNone,
}

/// A single entry of `PASSWORD_HASHERS`.
pub trait Hasher: Send + Sync {
    fn algorithm(&self) -> &'static str;
    fn salt(&self) -> String;
    fn encode(&self, password: &str, salt: &str) -> Result<String, HashError>;
    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HashError>;
    fn must_update(&self, encoded: &str) -> Result<bool, HashError>;
    fn harden_runtime(&self, password: &str, encoded: &str) -> Result<(), HashError>;
}

/// Outcome of `verify_password`: `(is_correct, must_update)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verification {
    pub is_correct: bool,
    pub must_update: bool,
}

impl Verification {
    const REJECTED: Self = Self {
        is_correct: false,
        must_update: false,
    };

    /// `check_password` only calls the setter (re-hash and save) when the
    /// password was correct *and* the stored hash is outdated.
    pub fn needs_rehash(self) -> bool {
        self.is_correct && self.must_update
    }
}

/// The ordered `PASSWORD_HASHERS` list. The first entry is the preferred one.
pub struct PasswordHashers {
    hashers: Vec<Box<dyn Hasher>>,
}

impl Default for PasswordHashers {
    /// Django 5.2 default `PASSWORD_HASHERS`, which authentik does not override.
    fn default() -> Self {
        Self {
            hashers: vec![
                Box::new(Pbkdf2Hasher::default()),
                Box::new(Pbkdf2Sha1Hasher::default()),
                Box::new(Argon2Hasher::default()),
                Box::new(BCryptSha256Hasher::default()),
                Box::new(ScryptHasher::default()),
            ],
        }
    }
}

impl PasswordHashers {
    pub fn new(hashers: Vec<Box<dyn Hasher>>) -> Self {
        assert!(!hashers.is_empty(), "PASSWORD_HASHERS must not be empty");
        Self { hashers }
    }

    /// `get_hasher("default")`
    pub fn preferred(&self) -> &dyn Hasher {
        self.hashers[0].as_ref()
    }

    /// `get_hasher(algorithm)`
    pub fn get(&self, algorithm: &str) -> Option<&dyn Hasher> {
        self.hashers
            .iter()
            .find(|h| h.algorithm() == algorithm)
            .map(AsRef::as_ref)
    }

    /// `identify_hasher(encoded)`; `None` where Django raises `ValueError`.
    pub fn identify(&self, encoded: &str) -> Option<&dyn Hasher> {
        // Ancient versions of Django created plain MD5 / SHA1 hashes without
        // an algorithm prefix; those map to hashers not in the default list.
        let len = encoded.chars().count();
        let algorithm = if (len == 32 && !encoded.contains('$'))
            || (len == 37 && encoded.starts_with("md5$$"))
        {
            "unsalted_md5"
        } else if len == 46 && encoded.starts_with("sha1$$") {
            "unsalted_sha1"
        } else {
            encoded.split('$').next().unwrap_or_default()
        };
        self.get(algorithm)
    }

    /// `verify_password(password, encoded)`.
    ///
    /// `password` and `encoded` are `Option`s because Django accepts `None`
    /// for both (`User.password` is never NULL in authentik, but unusable
    /// passwords and missing input go through this path).
    pub fn verify_password(
        &self,
        password: Option<&str>,
        encoded: Option<&str>,
    ) -> Result<Verification, HashError> {
        let preferred = self.preferred();
        // `identify_hasher(None)` calls `len(None)`: a TypeError Django does not catch.
        let encoded = encoded.ok_or(HashError::EncodedIsNone)?;
        let hasher = self.identify(encoded);
        let (Some(password), Some(hasher), true) =
            (password, hasher, is_password_usable(Some(encoded)))
        else {
            // Run the default password hasher once to reduce the timing
            // difference between an existing user with an unusable password
            // and a nonexistent user or missing hasher (Django #20760).
            self.make_password(Some(&get_random_string(UNUSABLE_PASSWORD_SUFFIX_LENGTH)))?;
            return Ok(Verification::REJECTED);
        };
        let hasher_changed = hasher.algorithm() != preferred.algorithm();
        let must_update = hasher_changed || preferred.must_update(encoded)?;
        let is_correct = hasher.verify(password, encoded)?;
        // If the hasher didn't change (no enumeration protection otherwise) and
        // the password should get updated, close the timing gap.
        if !is_correct && !hasher_changed && must_update {
            hasher.harden_runtime(password, encoded)?;
        }
        Ok(Verification {
            is_correct,
            must_update,
        })
    }

    /// `make_password(password)` with a fresh salt from the preferred hasher.
    /// `None` produces an unusable password, exactly like Django.
    pub fn make_password(&self, password: Option<&str>) -> Result<String, HashError> {
        match password {
            None => Ok(format!(
                "{UNUSABLE_PASSWORD_PREFIX}{}",
                get_random_string(UNUSABLE_PASSWORD_SUFFIX_LENGTH)
            )),
            Some(password) => {
                let hasher = self.preferred();
                hasher.encode(password, &hasher.salt())
            }
        }
    }
}

/// `is_password_usable(encoded)`. Note that Django treats `None` as usable.
pub fn is_password_usable(encoded: Option<&str>) -> bool {
    encoded.is_none_or(|e| !e.starts_with(UNUSABLE_PASSWORD_PREFIX))
}

/// `django.utils.crypto.constant_time_compare`
pub(crate) fn constant_time_compare(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq as _;
    // hmac.compare_digest returns False for different lengths without
    // leaking contents; subtle does the same.
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// `must_update_salt(salt, expected_entropy)`
pub(crate) fn must_update_salt(salt: &str, expected_entropy: f64) -> bool {
    // Each character in the salt provides log_2(len(alphabet)) bits of entropy.
    let len = f64::from(u32::try_from(salt.chars().count()).unwrap_or(u32::MAX));
    len * random::BITS_PER_CHAR < expected_entropy
}

/// `BasePasswordHasher._check_encode_args`
pub(crate) fn check_salt(salt: &str) -> Result<(), HashError> {
    if salt.is_empty() || salt.contains('$') {
        return Err(HashError::InvalidSalt);
    }
    Ok(())
}

/// Python `int(str)` accepts surrounding whitespace, a sign and `_`
/// separators. Values outside `u32` cannot be produced by `hashlib` either
/// (it raises `OverflowError`), so they are treated as malformed.
pub(crate) fn parse_python_int(value: &str) -> Option<u32> {
    let trimmed = value.trim();
    let digits = trimmed.strip_prefix('+').unwrap_or(trimmed);
    if digits.is_empty()
        || digits.starts_with('_')
        || digits.ends_with('_')
        || digits.contains("__")
        || !digits.chars().all(|c| c.is_ascii_digit() || c == '_')
    {
        return None;
    }
    digits.replace('_', "").parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_int_parsing() {
        assert_eq!(parse_python_int(" 1_000 "), Some(1000));
        assert_eq!(parse_python_int("+5"), Some(5));
        assert_eq!(parse_python_int("1__0"), None);
        assert_eq!(parse_python_int("-1"), None);
        assert_eq!(parse_python_int(""), None);
    }

    #[test]
    fn unusable_passwords() {
        let hashers = PasswordHashers::default();
        let unusable = hashers.make_password(None).expect("make_password");
        assert!(unusable.starts_with('!'));
        assert_eq!(unusable.len(), 41);
        assert!(!is_password_usable(Some(&unusable)));
        assert!(is_password_usable(None));
        assert_eq!(
            hashers
                .verify_password(Some("x"), Some(&unusable))
                .expect("verify"),
            Verification::REJECTED
        );
        assert_eq!(
            hashers.verify_password(Some("x"), None),
            Err(HashError::EncodedIsNone)
        );
        assert_eq!(
            hashers
                .verify_password(None, Some("pbkdf2_sha256$1$a$b"))
                .expect("verify"),
            Verification::REJECTED
        );
        assert_eq!(
            hashers.verify_password(None, None),
            Err(HashError::EncodedIsNone)
        );
    }

    #[test]
    fn unknown_algorithms_are_rejected() {
        let hashers = PasswordHashers::default();
        for encoded in [
            "",
            "plaintext",
            "md5$salt$hash",
            "5f4dcc3b5aa765d61d8327deb882cf99",
            "sha1$$5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
            "unsalted_md5$x",
        ] {
            assert_eq!(
                hashers
                    .verify_password(Some("password"), Some(encoded))
                    .expect("verify"),
                Verification::REJECTED,
                "{encoded}"
            );
        }
    }

    #[test]
    fn salt_entropy() {
        assert!(must_update_salt("abc", SALT_ENTROPY));
        assert!(must_update_salt(&"a".repeat(21), SALT_ENTROPY));
        assert!(!must_update_salt(&"a".repeat(22), SALT_ENTROPY));
    }
}
