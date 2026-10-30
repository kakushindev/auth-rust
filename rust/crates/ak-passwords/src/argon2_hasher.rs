use argon2::{Algorithm, Argon2, Params, Version};
use base64::{
    Engine as _,
    engine::general_purpose::{GeneralPurpose, STANDARD_NO_PAD},
};
use subtle::ConstantTimeEq as _;

use crate::{HashError, Hasher, SALT_ENTROPY, must_update_salt};

const ALGORITHM: &str = "argon2";
/// `argon2.DEFAULT_HASH_LENGTH`
const DEFAULT_HASH_LENGTH: usize = 32;
const ARGON2_VERSION_10: u32 = 0x10;
const ARGON2_VERSION_13: u32 = 0x13;

/// libargon2's `from_base64`: standard alphabet, no padding, and the unused
/// trailing bits must be zero.
const B64: GeneralPurpose = STANDARD_NO_PAD;

/// `django.contrib.auth.hashers.Argon2PasswordHasher` (argon2-cffi backend).
pub struct Argon2Hasher {
    pub time_cost: u32,
    pub memory_cost: u32,
    pub parallelism: u32,
}

impl Default for Argon2Hasher {
    fn default() -> Self {
        Self {
            time_cost: 2,
            memory_cost: 102_400,
            parallelism: 8,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Encoded {
    algorithm: Algorithm,
    version: u32,
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
    salt: Vec<u8>,
    hash: Vec<u8>,
}

/// argon2-cffi `PasswordHasher.verify` picks the type from the first nine
/// bytes and raises `InvalidHashError` (uncaught by Django) for anything else.
fn header_type(rest: &str) -> Option<Algorithm> {
    match rest.as_bytes().get(..9)? {
        b"$argon2i$" => Some(Algorithm::Argon2i),
        b"$argon2d$" => Some(Algorithm::Argon2d),
        b"$argon2id" => Some(Algorithm::Argon2id),
        _ => None,
    }
}

/// Mirrors libargon2's `decode_string` for a hash of the given type. `None`
/// is `ARGON2_DECODING_FAIL`: argon2-cffi's `verify_secret` reports it as a
/// mismatch, while `extract_parameters` raises `InvalidHashError`.
fn decode_string(rest: &str) -> Option<Encoded> {
    let algorithm = header_type(rest)?;
    let prefix = match algorithm {
        Algorithm::Argon2d => "$argon2d",
        Algorithm::Argon2i => "$argon2i",
        Algorithm::Argon2id => "$argon2id",
    };
    let mut s = rest.strip_prefix(prefix)?;
    let mut version = ARGON2_VERSION_10;
    if let Some(after) = s.strip_prefix("$v=") {
        let (v, after) = decimal_u32(after)?;
        version = v;
        s = after;
    }
    let s = s.strip_prefix("$m=")?;
    let (memory_cost, s) = decimal_u32(s)?;
    let s = s.strip_prefix(",t=")?;
    let (time_cost, s) = decimal_u32(s)?;
    let s = s.strip_prefix(",p=")?;
    let (parallelism, s) = decimal_u32(s)?;
    let s = s.strip_prefix('$')?;
    let (salt, hash) = s.split_once('$')?;
    Some(Encoded {
        algorithm,
        version,
        memory_cost,
        time_cost,
        parallelism,
        salt: B64.decode(salt).ok()?,
        hash: B64.decode(hash).ok()?,
    })
}

/// libargon2 `decode_decimal` + the `UINT32_MAX` check of `DECIMAL_U32`.
fn decimal_u32(s: &str) -> Option<(u32, &str)> {
    let end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    if end == 0 {
        return None;
    }
    let value: u64 = s[..end].parse().ok()?;
    Some((u32::try_from(value).ok()?, &s[end..]))
}

impl Argon2Hasher {
    fn params(&self, output_len: usize) -> Result<Params, argon2::Error> {
        Params::new(
            self.memory_cost,
            self.time_cost,
            self.parallelism,
            Some(output_len),
        )
    }

    fn split(encoded: &str) -> Result<&str, HashError> {
        match encoded.split_once('$') {
            Some((ALGORITHM, rest)) => Ok(rest),
            _ => Err(HashError::Malformed {
                algorithm: ALGORITHM,
                reason: "algorithm mismatch",
            }),
        }
    }

    fn decode(encoded: &str) -> Result<Encoded, HashError> {
        // Django prepends the "$" it split off before handing it to argon2-cffi.
        let rest = format!("${}", Self::split(encoded)?);
        decode_string(&rest).ok_or(HashError::Malformed {
            algorithm: ALGORITHM,
            reason: "argon2 decoding failed",
        })
    }
}

impl Hasher for Argon2Hasher {
    fn algorithm(&self) -> &'static str {
        ALGORITHM
    }

    fn salt(&self) -> String {
        crate::random::default_salt()
    }

    fn encode(&self, password: &str, salt: &str) -> Result<String, HashError> {
        crate::check_salt(salt)?;
        let invalid = |e: argon2::Error| HashError::InvalidParameters {
            algorithm: ALGORITHM,
            reason: e.to_string(),
        };
        let params = self.params(DEFAULT_HASH_LENGTH).map_err(invalid)?;
        let mut out = [0_u8; DEFAULT_HASH_LENGTH];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut out)
            .map_err(invalid)?;
        // argon2.low_level.hash_secret output, prefixed with the algorithm.
        Ok(format!(
            "{ALGORITHM}$argon2id$v={ARGON2_VERSION_13}$m={},t={},p={}${}${}",
            self.memory_cost,
            self.time_cost,
            self.parallelism,
            B64.encode(salt.as_bytes()),
            B64.encode(out)
        ))
    }

    fn verify(&self, password: &str, encoded: &str) -> Result<bool, HashError> {
        let rest = format!("${}", Self::split(encoded)?);
        // `_ensure_bytes(hash, "ascii")` raises UnicodeEncodeError first.
        if !rest.is_ascii() || header_type(&rest).is_none() {
            return Err(HashError::Malformed {
                algorithm: ALGORITHM,
                reason: "unknown argon2 type header",
            });
        }
        let Some(decoded) = decode_string(&rest) else {
            return Ok(false);
        };
        let version = match decoded.version {
            ARGON2_VERSION_10 => Version::V0x10,
            ARGON2_VERSION_13 => Version::V0x13,
            // libargon2 rejects other versions with ARGON2_INCORRECT_TYPE,
            // which argon2-cffi raises as VerificationError -> False.
            _ => return Ok(false),
        };
        // Parameter / length validation failures (salt too short, memory too
        // little, ...) are libargon2 error codes other than DECODING_FAIL,
        // surfaced as VerificationError, which Django maps to False.
        let Ok(params) = Params::new(
            decoded.memory_cost,
            decoded.time_cost,
            decoded.parallelism,
            Some(decoded.hash.len()),
        ) else {
            return Ok(false);
        };
        let mut out = vec![0_u8; decoded.hash.len()];
        if Argon2::new(decoded.algorithm, version, params)
            .hash_password_into(password.as_bytes(), &decoded.salt, &mut out)
            .is_err()
        {
            return Ok(false);
        }
        Ok(out.ct_eq(&decoded.hash).into())
    }

    fn must_update(&self, encoded: &str) -> Result<bool, HashError> {
        let current = Self::decode(encoded)?;
        // `argon2.Parameters` equality with salt_len copied from the current hash.
        let params_differ = current.algorithm != Algorithm::Argon2id
            || current.version != ARGON2_VERSION_13
            || current.hash.len() != DEFAULT_HASH_LENGTH
            || current.time_cost != self.time_cost
            || current.memory_cost != self.memory_cost
            || current.parallelism != self.parallelism;
        // Django decodes the salt as latin1, so its length equals the byte count.
        let salt: String = current.salt.iter().map(|&b| char::from(b)).collect();
        Ok(params_differ || must_update_salt(&salt, SALT_ENTROPY))
    }

    fn harden_runtime(&self, _password: &str, _encoded: &str) -> Result<(), HashError> {
        // The runtime for Argon2 is too complicated to implement a sensible
        // hardening algorithm (Django does nothing here either).
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_rejects_malformed_strings() {
        for bad in [
            "$argon2x$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$aGFzaA",
            "$argon2idX$v=19$m=8,t=1,p=1$c2FsdHNhbHQ$aGFzaA",
            "$argon2id$v=19$t=1,m=8,p=1$c2FsdHNhbHQ$aGFzaA",
            "$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ",
            "$argon2id$v=19$m=,t=1,p=1$c2FsdHNhbHQ$aGFzaA",
            "$argon2id$v=19$m=4294967296,t=1,p=1$c2FsdHNhbHQ$aGFzaA",
            "$argon2id$v=19$m=8,t=1,p=1$c2FsdHNhbHQ=$aGFzaA",
        ] {
            assert_eq!(decode_string(bad), None, "{bad}");
        }
    }

    #[test]
    fn decode_accepts_missing_version() {
        let decoded = decode_string("$argon2i$m=8,t=1,p=1$c2FsdHNhbHQ$aGFzaA").expect("decode");
        assert_eq!(decoded.version, ARGON2_VERSION_10);
        assert_eq!(decoded.salt, b"saltsalt");
    }
}
