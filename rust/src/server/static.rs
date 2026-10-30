use std::{fmt::Write as _, path::PathBuf};

use ak_common::config::schema::StorageOverrideConfig;
use aws_lc_rs::digest;
use axum::extract::{Query, Request};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use time::OffsetDateTime;

use crate::config;

#[derive(Debug, Deserialize)]
struct StorageClaims {
    exp: Option<i64>,
    nbf: Option<i64>,
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct StorageTokenQuery {
    token: Option<String>,
}

/// authentik-rs: Go compares the claim with the path left after stripping
/// `files/<usage>/` (`internal/web/static.go`), so the caller passes it.
/// Upstream's stricter checks are kept on purpose (HS256 only, `exp` and
/// `nbf` required): every token the 2026.2.7 Python side issues satisfies
/// them, so only tokens forged with the secret key itself behave
/// differently. See `docs/SECURITY_INVARIANTS.md`.
pub(super) fn is_storage_token_valid_for_path(
    usage: &str,
    request_path: &str,
    request: &Request,
) -> bool {
    is_storage_token_valid(usage, &config::get().secret_key, request_path, request)
}

fn is_storage_token_valid(
    usage: &str,
    secret_key: &str,
    request_path: &str,
    request: &Request,
) -> bool {
    // Use typed query parsing so `token` is percent-decoded before JWT parsing.
    let token_string = match Query::<StorageTokenQuery>::try_from_uri(request.uri()) {
        Ok(query) => match query.0.token {
            Some(token) if !token.is_empty() => token,
            _ => return false,
        },
        Err(_) => return false,
    };

    let Ok(token_header) = decode_header(&token_string) else {
        return false;
    };

    // Must match what we use in authentik/admin/files/backends/file.py
    if token_header.alg != Algorithm::HS256 {
        return false;
    }

    // Derive a per-usage key so media and reports tokens are not interchangeable.
    let key = format!("{secret_key}:{usage}");
    let key_digest = digest::digest(&digest::SHA256, key.as_bytes());
    let key_hex_digest = key_digest
        .as_ref()
        .iter()
        .fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        });

    let mut validation = Validation::new(token_header.alg);
    validation.validate_exp = false;
    validation.validate_nbf = false;
    validation.validate_aud = false;
    validation.required_spec_claims.clear();

    let claims = match decode::<StorageClaims>(
        &token_string,
        &DecodingKey::from_secret(key_hex_digest.as_bytes()),
        &validation,
    ) {
        Ok(token) => token.claims,
        Err(_) => return false,
    };

    let now = OffsetDateTime::now_utc().unix_timestamp();
    if claims.exp.unwrap_or(0) < now {
        return false;
    }
    if claims.nbf.unwrap_or(now + 1) > now {
        return false;
    }

    let Some(claim_path) = claims.path else {
        return false;
    };
    // The caller passes the already percent-decoded path.
    let request_path = request_path.trim_start_matches('/');
    let expected_path = format!("{usage}/{request_path}");
    if claim_path != expected_path {
        return false;
    }

    true
}

/// authentik-rs: storage roots served from disk, as in `configureStatic`.
pub(super) struct StorageRoots {
    pub(super) media: Option<PathBuf>,
    pub(super) reports: Option<PathBuf>,
}

pub(super) fn storage_roots() -> StorageRoots {
    let config = config::get();
    // Go falls back to "file" and "./data" for empty settings.
    let default_backend = if config.storage.backend.is_empty() {
        "file".to_owned()
    } else {
        config.storage.backend.clone()
    };
    let default_path = if config.storage.file.path.as_os_str().is_empty() {
        PathBuf::from("./data")
    } else {
        config.storage.file.path.clone()
    };
    let root = |usage: Option<&StorageOverrideConfig>, sub: &str| {
        let usage = usage.cloned().unwrap_or_default();
        let backend = usage
            .backend
            .filter(|b| !b.is_empty())
            .unwrap_or_else(|| default_backend.clone());
        (backend == "file").then(|| {
            usage
                .file
                .unwrap_or_default()
                .path
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or_else(|| default_path.clone())
                .join(sub)
        })
    };
    StorageRoots {
        media: root(config.storage.media.as_ref(), "media"),
        reports: root(config.storage.reports.as_ref(), "reports"),
    }
}
