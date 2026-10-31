//! authentik-rs compatibility router (not part of upstream).
//!
//! Routes registered here are served natively in Rust instead of being
//! forwarded to gunicorn/Django by the fallback in `core::build_router`. A
//! route may only be added once its differential suite passes against the
//! pinned reference (see `docs/TEST_STRATEGY.md`); there is deliberately no
//! runtime switch that could widen this set.
//!
//! The read API (M7) is not routed here: `core::read_api` asks `ak_api`
//! on the request as Django would receive it, and anything `ak_api`
//! declines is forwarded unchanged. `PORTED_ROUTES` lists what it answers,
//! with the suite that verified each route.

use std::sync::Arc;

use axum::Router;

use crate::server::Server;

/// Method + path pattern of every route served by Rust, mirrored in
/// `docs/COMPATIBILITY_REPORT.md` (`{pk}` is DRF's `[^/.]+`). Verified by
/// `tests/api/run.sh`.
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "the registry is checked by tests")
)]
pub(super) const PORTED_ROUTES: &[(&str, &str)] = &[
    ("GET", "/api/v3/rbac/roles/"),
    ("GET", "/api/v3/rbac/roles/{pk}/"),
    ("GET", "/api/v3/rbac/permissions/"),
    ("GET", "/api/v3/rbac/permissions/{pk}/"),
    ("GET", "/api/v3/rbac/initial_permissions/"),
    ("GET", "/api/v3/rbac/initial_permissions/{pk}/"),
    ("GET", "/api/v3/core/brands/"),
    ("GET", "/api/v3/core/brands/{pk}/"),
    ("GET", "/api/v3/events/transports/"),
    ("GET", "/api/v3/events/transports/{pk}/"),
    ("GET", "/api/v3/propertymappings/notification/"),
    ("GET", "/api/v3/propertymappings/notification/{pk}/"),
    ("GET", "/api/v3/crypto/certificatekeypairs/"),
    ("GET", "/api/v3/crypto/certificatekeypairs/{pk}/"),
    ("GET", "/api/v3/core/users/"),
    ("GET", "/api/v3/core/users/{pk}/"),
    ("GET", "/api/v3/core/groups/"),
    ("GET", "/api/v3/core/groups/{pk}/"),
];

pub(super) fn build_router(server: &Arc<Server>) -> Router {
    Router::new().with_state(Arc::clone(server))
}

#[cfg(test)]
mod tests {
    use super::PORTED_ROUTES;

    #[test]
    fn registry_matches_ak_api() {
        // Raise this together with the evidence in docs/COMPATIBILITY_REPORT.md.
        for (method, pattern) in PORTED_ROUTES {
            let path = pattern.replace("{pk}", "00000000-0000-0000-0000-000000000000");
            assert!(ak_api::handles(method, &path), "{method} {pattern}");
        }
        assert!(!ak_api::handles("GET", "/api/v3/core/users/me/"));
        assert!(!ak_api::handles("GET", "/api/v3/core/brands/current/"));
    }
}
