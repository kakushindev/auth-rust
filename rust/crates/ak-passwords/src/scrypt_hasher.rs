use base64::{Engine as _, engine::general_purpose::STANDARD};

use crate::{HashError, Hasher, check_salt, constant_time_compare, parse_python_int};

const ALGORITHM: &str = "scrypt";
const DKLEN: usize = 64;
/// OpenSSL `SCRYPT_MAX_MEM`, used by `EVP_PBE_scrypt` when `maxmem == 0`.
const SCRYPT_MAX_MEM: u64 = 1024 * 1024 * 32;
/// OpenSSL `SCRYPT_PR_MAX`
const SCRYPT_PR_MAX: u64 = (1 << 30) - 1;

/// `django.contrib.auth.hashers.ScryptPasswordHasher` (`hashlib.scrypt` backend).
pub struct ScryptHasher {
    pub work_factor: u64,
    pub block_size: u64,
    pub parallelism: u64,
}

impl Default for ScryptHasher {
    fn default() -> Self {
        Self {
            work_factor: 1 << 14,
            block_size: 8,
            parallelism: 5,
        }
    }
}

struct Decoded<'a> {
    work_factor: u64,
    salt: &'a str,
    block_size: u64,
    parallelism: u64,
}

fn invalid(reason: &str) -> HashError {
    HashError::InvalidParameters {
        algorithm: ALGORITHM,
        reason: reason.to_owned(),
    }
}

/// The parameter validation `hashlib.scrypt` and OpenSSL's `EVP_PBE_scrypt`
/// perform before deriving anything (maxmem = 0, i.e. 32 MiB).
fn validate(n: u64, r: u64, p: u64) -> Result<u8, HashError> {
    if n < 2 || n & (n - 1) != 0 {
        return Err(invalid("n must be a power of 2."));
    }
    let combo = || invalid("Invalid parameter combination for n, r, p, maxmem.");
    if r == 0 || p == 0 || p > SCRYPT_PR_MAX / r {
        return Err(combo());
    }
    if 16 * r <= 63 && n >= 1_u64 << (16 * r) {
        return Err(combo());
    }
    let b_len = p * 128 * r;
    if b_len > u64::from(i32::MAX.unsigned_abs()) {
        return Err(combo());
    }
    if n + 2 > (u64::MAX / 128) / r {
        return Err(combo());
    }
    let v_len = 32 * r * (n + 2) * 4;
    if b_len > u64::MAX - v_len || b_len + v_len > SCRYPT_MAX_MEM {
        return Err(combo());
    }
    u8::try_from(n.trailing_zeros()).map_err(|_| combo())
}

impl ScryptHasher {
    fn encode_with(
        &self,
        password: &str,
        salt: &str,
        n: u64,
        r: u64,
        p: u64,
    ) -> Result<String, HashError> {
        check_salt(salt)?;
        // `n = n or self.work_factor` etc.
        let n = if n == 0 { self.work_factor } else { n };
        let r = if r == 0 { self.block_size } else { r };
        let p = if p == 0 { self.parallelism } else { p };
        let log_n = validate(n, r, p)?;
        let params = scrypt::Params::new(
            log_n,
            u32::try_from(r).map_err(|_| invalid("r"))?,
            u32::try_from(p).map_err(|_| invalid("p"))?,
        )
        .map_err(|e| invalid(&e.to_string()))?;
        let mut out = [0_u8; DKLEN];
        scrypt::scrypt(password.as_bytes(), salt.as_bytes(), &params, &mut out)
            .map_err(|e| invalid(&e.to_string()))?;
        let hash = STANDARD.encode(out);
        Ok(format!("{ALGORITHM}${n}${salt}${r}${p}${hash}"))
    }

    fn decode(encoded: &str) -> Result<Decoded<'_>, HashError> {
        let malformed = |reason| HashError::Malformed {
            algorithm: ALGORITHM,
            reason,
        };
        // `algorithm, work_factor, salt, block_size, parallelism, hash_ = encoded.split("$", 6)`
        let parts: Vec<&str> = encoded.splitn(7, '$').collect();
        let [algorithm, work_factor, salt, block_size, parallelism, _hash] = parts.as_slice()
        else {
            return Err(malformed("expected 6 fields"));
        };
        if *algorithm != ALGORITHM {
            return Err(malformed("algorithm mismatch"));
        }
        let int = |v: &str, what| {
            parse_python_int(v)
                .map(u64::from)
                .ok_or_else(|| malformed(what))
        };
        Ok(Decoded {
            work_factor: int(work_factor, "work factor")?,
            salt,
            block_size: int(block_size, "block size")?,
            parallelism: int(parallelism, "parallelism")?,
        })
    }
}

impl Hasher for ScryptHasher {
    fn algorithm(&self) -> &'static str {
        ALGORITHM
    }

    fn salt(&self) -> String {
        crate::random::default_salt()
    }

    fn encode(&self, password: &str, salt: &str) -> Result<String, HashError> {
        self.encode_with(
            password,
            salt,
            self.work_factor,
            self.block_size,
            self.parallelism,
        )
    }

    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HashError> {
        let d = Self::decode(encoded)?;
        let encoded_2 =
            self.encode_with(password, d.salt, d.work_factor, d.block_size, d.parallelism)?;
        Ok(constant_time_compare(encoded, &encoded_2))
    }

    fn must_update(&self, encoded: &str) -> Result<bool, HashError> {
        let d = Self::decode(encoded)?;
        Ok(d.work_factor != self.work_factor
            || d.block_size != self.block_size
            || d.parallelism != self.parallelism)
    }

    fn harden_runtime(&self, _password: &str, _encoded: &str) -> Result<(), HashError> {
        // The runtime for Scrypt is too complicated to implement a sensible
        // hardening algorithm (Django does nothing here either).
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openssl_memory_limit() {
        assert_eq!(validate(1 << 14, 8, 1), Ok(14));
        // 128 * r * (N + 2) exceeds 32 MiB for N = 2^15, r = 8.
        for (n, r, p) in [(1_u64 << 15_u32, 8_u64, 1_u64), (3, 8, 1), (1, 8, 1)] {
            assert!(matches!(
                validate(n, r, p),
                Err(HashError::InvalidParameters { .. })
            ));
        }
    }
}
