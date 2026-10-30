use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::{
    HashError, Hasher, SALT_ENTROPY, check_salt, constant_time_compare, must_update_salt,
    parse_python_int,
};

/// Django 5.2 `PBKDF2PasswordHasher.iterations`
pub const PBKDF2_ITERATIONS: u32 = 1_000_000;

#[derive(Clone, Copy)]
enum Digest {
    Sha256,
    Sha1,
}

struct Pbkdf2 {
    algorithm: &'static str,
    iterations: u32,
    digest: Digest,
}

struct Decoded<'a> {
    iterations: u32,
    salt: &'a str,
}

impl Pbkdf2 {
    fn derive(&self, password: &str, salt: &str, iterations: u32) -> String {
        let (password, salt) = (password.as_bytes(), salt.as_bytes());
        // dklen=None: the digest size.
        let hash = match self.digest {
            Digest::Sha256 => {
                pbkdf2::pbkdf2_hmac_array::<sha2::Sha256, 32>(password, salt, iterations).to_vec()
            }
            Digest::Sha1 => {
                pbkdf2::pbkdf2_hmac_array::<sha1::Sha1, 20>(password, salt, iterations).to_vec()
            }
        };
        STANDARD.encode(hash)
    }

    fn encode_with(
        &self,
        password: &str,
        salt: &str,
        iterations: u32,
    ) -> Result<String, HashError> {
        check_salt(salt)?;
        // `iterations = iterations or self.iterations`: a stored 0 falls back to
        // the default, which then fails the string comparison in `verify`.
        let iterations = if iterations == 0 {
            self.iterations
        } else {
            iterations
        };
        let hash = self.derive(password, salt, iterations);
        Ok(format!("{}${iterations}${salt}${hash}", self.algorithm))
    }

    fn decode<'a>(&self, encoded: &'a str) -> Result<Decoded<'a>, HashError> {
        let malformed = |reason| HashError::Malformed {
            algorithm: self.algorithm,
            reason,
        };
        // `algorithm, iterations, salt, hash = encoded.split("$", 3)`
        let mut parts = encoded.splitn(4, '$');
        let (Some(algorithm), Some(iterations), Some(salt), Some(_hash)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(malformed("expected 4 fields"));
        };
        if algorithm != self.algorithm {
            return Err(malformed("algorithm mismatch"));
        }
        let iterations = parse_python_int(iterations).ok_or(malformed("iterations"))?;
        Ok(Decoded { iterations, salt })
    }
}

macro_rules! pbkdf2_hasher {
    ($name:ident, $algorithm:literal, $digest:expr) => {
        pub struct $name(Pbkdf2);

        impl Default for $name {
            fn default() -> Self {
                Self::with_iterations(PBKDF2_ITERATIONS)
            }
        }

        impl $name {
            pub fn with_iterations(iterations: u32) -> Self {
                Self(Pbkdf2 {
                    algorithm: $algorithm,
                    iterations,
                    digest: $digest,
                })
            }

            pub fn encode_with_iterations(
                &self,
                password: &str,
                salt: &str,
                iterations: u32,
            ) -> Result<String, HashError> {
                self.0.encode_with(password, salt, iterations)
            }
        }

        impl Hasher for $name {
            fn algorithm(&self) -> &'static str {
                self.0.algorithm
            }

            fn salt(&self) -> String {
                crate::random::default_salt()
            }

            fn encode(&self, password: &str, salt: &str) -> Result<String, HashError> {
                self.0.encode_with(password, salt, self.0.iterations)
            }

            fn verify(&self, password: &str, encoded: &str) -> Result<bool, HashError> {
                let decoded = self.0.decode(encoded)?;
                let encoded_2 = self
                    .0
                    .encode_with(password, decoded.salt, decoded.iterations)?;
                Ok(constant_time_compare(encoded, &encoded_2))
            }

            fn must_update(&self, encoded: &str) -> Result<bool, HashError> {
                let decoded = self.0.decode(encoded)?;
                Ok(decoded.iterations != self.0.iterations
                    || must_update_salt(decoded.salt, SALT_ENTROPY))
            }

            fn harden_runtime(&self, password: &str, encoded: &str) -> Result<(), HashError> {
                let decoded = self.0.decode(encoded)?;
                if let Some(extra) = self.0.iterations.checked_sub(decoded.iterations)
                    && extra > 0
                {
                    self.0.encode_with(password, decoded.salt, extra)?;
                }
                Ok(())
            }
        }
    };
}

pbkdf2_hasher!(Pbkdf2Hasher, "pbkdf2_sha256", Digest::Sha256);
pbkdf2_hasher!(Pbkdf2Sha1Hasher, "pbkdf2_sha1", Digest::Sha1);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_iterations_never_verify() {
        let hasher = Pbkdf2Hasher::with_iterations(2);
        let real = hasher
            .encode_with_iterations("pw", "saltsalt", 2)
            .expect("encode");
        let hash = real.rsplit('$').next().expect("hash");
        let forged = format!("pbkdf2_sha256$0$saltsalt${hash}");
        assert!(!hasher.verify("pw", &forged).expect("verify"));
    }

    #[test]
    fn malformed_hash_errors_like_django() {
        let hasher = Pbkdf2Hasher::default();
        assert!(hasher.verify("pw", "pbkdf2_sha256$abc$salt$hash").is_err());
        assert!(hasher.verify("pw", "pbkdf2_sha256$1000").is_err());
        assert!(hasher.must_update("pbkdf2_sha256").is_err());
    }
}
