use base64::{
    Engine as _, alphabet,
    engine::general_purpose::{GeneralPurpose, NO_PAD},
};
use sha2::{Digest as _, Sha256};

use crate::{HashError, Hasher, constant_time_compare, parse_python_int};

const ALGORITHM: &str = "bcrypt_sha256";
/// pyca/bcrypt's `BASE64_ENGINE`
const BCRYPT_B64: GeneralPurpose = GeneralPurpose::new(&alphabet::BCRYPT, NO_PAD);

/// `django.contrib.auth.hashers.BCryptSHA256PasswordHasher` (pyca/bcrypt 5 backend).
pub struct BCryptSha256Hasher {
    pub rounds: u32,
}

impl Default for BCryptSha256Hasher {
    fn default() -> Self {
        Self { rounds: 12 }
    }
}

fn invalid_salt() -> HashError {
    HashError::InvalidParameters {
        algorithm: ALGORITHM,
        reason: "Invalid salt".to_owned(),
    }
}

/// pyca/bcrypt `hashpw(password, salt)`.
fn hashpw(password: &[u8], salt: &str) -> Result<String, HashError> {
    // bcrypt 5 refuses passwords over 72 bytes instead of truncating them.
    if password.len() > 72 {
        return Err(HashError::InvalidParameters {
            algorithm: ALGORITHM,
            reason: "password cannot be longer than 72 bytes".to_owned(),
        });
    }
    // `salt` is the modular-crypt prefix: [version, cost, salt(+checksum)].
    let parts: Vec<&str> = salt.split('$').filter(|s| !s.is_empty()).collect();
    let [version, cost, raw] = parts.as_slice() else {
        return Err(invalid_salt());
    };
    let version = match *version {
        "2y" => bcrypt::Version::TwoY,
        "2b" => bcrypt::Version::TwoB,
        "2a" => bcrypt::Version::TwoA,
        "2x" => bcrypt::Version::TwoX,
        _ => return Err(invalid_salt()),
    };
    let cost: u32 = cost.parse().map_err(|_| invalid_salt())?;
    let raw_salt: [u8; 16] = raw
        .get(..22)
        .and_then(|s| BCRYPT_B64.decode(s).ok())
        .and_then(|v| v.try_into().ok())
        .ok_or_else(invalid_salt)?;
    let hashed = bcrypt::hash_with_salt(password, cost, raw_salt).map_err(|_| invalid_salt())?;
    Ok(hashed.format_for_version(version))
}

impl BCryptSha256Hasher {
    /// Pre-hash to avoid bcrypt's 72 byte truncation (Django #20138).
    fn digest(password: &str) -> String {
        hex::encode(Sha256::digest(password.as_bytes()))
    }

    fn encode_raw(password: &str, salt: &str) -> Result<String, HashError> {
        let data = hashpw(Self::digest(password).as_bytes(), salt)?;
        Ok(format!("{ALGORITHM}${data}"))
    }

    fn data(encoded: &str) -> Result<&str, HashError> {
        match encoded.split_once('$') {
            Some((ALGORITHM, data)) => Ok(data),
            _ => Err(HashError::Malformed {
                algorithm: ALGORITHM,
                reason: "algorithm mismatch",
            }),
        }
    }

    /// `decode()["work_factor"]`
    fn work_factor(encoded: &str) -> Result<i64, HashError> {
        let malformed = |reason| HashError::Malformed {
            algorithm: ALGORITHM,
            reason,
        };
        // `algorithm, empty, algostr, work_factor, data = encoded.split("$", 4)`
        let parts: Vec<&str> = encoded.splitn(5, '$').collect();
        let [algorithm, _empty, _algostr, work_factor, _data] = parts.as_slice() else {
            return Err(malformed("expected 5 fields"));
        };
        if *algorithm != ALGORITHM {
            return Err(malformed("algorithm mismatch"));
        }
        parse_python_int(work_factor)
            .map(i64::from)
            .ok_or(malformed("work factor"))
    }
}

impl Hasher for BCryptSha256Hasher {
    fn algorithm(&self) -> &'static str {
        ALGORITHM
    }

    /// `bcrypt.gensalt(rounds)`
    fn salt(&self) -> String {
        let mut raw = [0u8; 16];
        rand::fill(&mut raw);
        format!("$2b${:02}${}", self.rounds, BCRYPT_B64.encode(raw))
    }

    fn encode(&self, password: &str, salt: &str) -> Result<String, HashError> {
        Self::encode_raw(password, salt)
    }

    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HashError> {
        let data = Self::data(encoded)?;
        let encoded_2 = Self::encode_raw(password, data)?;
        Ok(constant_time_compare(encoded, &encoded_2))
    }

    fn must_update(&self, encoded: &str) -> Result<bool, HashError> {
        Ok(Self::work_factor(encoded)? != i64::from(self.rounds))
    }

    fn harden_runtime(&self, password: &str, encoded: &str) -> Result<(), HashError> {
        let data = Self::data(encoded)?;
        // Length of the salt in bcrypt.
        let salt = data.get(..29).unwrap_or(data);
        let rounds =
            data.split('$')
                .nth(2)
                .and_then(parse_python_int)
                .ok_or(HashError::Malformed {
                    algorithm: ALGORITHM,
                    reason: "rounds",
                })?;
        // Work factor is logarithmic, adding one doubles the load.
        if let Some(diff) = self.rounds.checked_sub(rounds) {
            for _ in 1..(1u64 << diff.min(63)) {
                Self::encode_raw(password, salt)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashpw_rejects_bad_salts() {
        for salt in [
            "",
            "$2b$12",
            "$2c$12$abcdefghijklmnopqrstuv",
            "$2b$xx$abcdefghijklmnopqrstuv",
            "$2b$12$short",
        ] {
            assert!(hashpw(b"pw", salt).is_err(), "{salt}");
        }
    }

    #[test]
    fn gensalt_round_trips() {
        let hasher = BCryptSha256Hasher { rounds: 4 };
        let salt = hasher.salt();
        assert!(salt.starts_with("$2b$04$"));
        let encoded = hasher.encode("pw", &salt).expect("encode");
        assert!(hasher.verify("pw", &encoded).expect("verify"));
        assert!(!hasher.verify("pW", &encoded).expect("verify"));
        assert!(hasher.must_update(&encoded).is_ok_and(|u| !u));
        assert!(
            BCryptSha256Hasher::default()
                .must_update(&encoded)
                .is_ok_and(|u| u)
        );
    }
}
