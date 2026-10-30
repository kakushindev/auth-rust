//! authentik-rs compatibility router (not part of upstream).
//!
//! Routes registered here are served natively in Rust instead of being
//! forwarded to gunicorn/Django by the fallback in `core::build_router`. A
//! route may only be added once its differential suite passes against the
//! pinned reference (see `docs/TEST_STRATEGY.md`); there is deliberately no
//! runtime switch that could widen this set.
//!
//! The router is empty until the first endpoint is verified, so every
//! request still reaches Django and behavior is identical to upstream.

use std::sync::Arc;

use axum::Router;

use crate::server::Server;

/// Method + path pattern of every route served by Rust, mirrored in
/// `docs/COMPATIBILITY_REPORT.md`.
pub(super) const PORTED_ROUTES: &[(&str, &str)] = &[];

pub(super) fn build_router(server: &Arc<Server>) -> Router {
    Router::new().with_state(Arc::clone(server))
}

#[cfg(test)]
mod tests {
    use super::PORTED_ROUTES;

    #[test]
    fn no_unverified_routes() {
        // Raise this together with the evidence in docs/feature-status.json.
        assert!(PORTED_ROUTES.is_empty());
    }
}
