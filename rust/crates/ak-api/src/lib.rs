//! authentik's read API (milestone M7), answered in Rust exactly as Django
//! answers it, on top of `ak-auth` (request identity) and `ak-rbac`
//! (permissions).
//!
//! [`serve`] either produces Django's response or declines: whenever a
//! request takes a path this crate does not reproduce (sessions, which
//! write; other languages; Enterprise licenses; inputs whose Python
//! parsing is not ported), it returns [`Outcome::Decline`] before doing
//! anything, and the server forwards the request to Django unchanged.
//! Each view names the upstream code it ports; `tests/api/run.sh` checks
//! every route against the pinned reference.

pub mod drf;
pub mod pagination;
pub mod py;
pub mod sql;
pub mod views;

pub use drf::{ApiRequest, Context};

/// A response as Django would send it (the server adds framing).
#[derive(Debug, Clone)]
pub struct Answer {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

/// Why a request is left to Django.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Decline(pub &'static str);

/// What [`serve`] decided.
#[derive(Debug)]
pub enum Outcome {
    /// Rust's answer, for the named route.
    Serve { route: &'static str, answer: Answer },
    /// Forward to Django.
    Decline(Decline),
}

/// A route of DRF's `DefaultRouter` (no format suffixes): `pk` matches
/// `[^/.]+`.
enum Route<'a> {
    RolesList,
    RolesRetrieve(&'a str),
}

fn route(path: &str) -> Option<Route<'_>> {
    let rest = path.strip_prefix("/api/v3/rbac/roles/")?;
    if rest.is_empty() {
        return Some(Route::RolesList);
    }
    let pk = rest.strip_suffix('/')?;
    (!pk.is_empty() && !pk.contains(['/', '.'])).then_some(Route::RolesRetrieve(pk))
}

/// Whether `serve` might answer `GET path`; cheap, for the server to skip
/// everything else.
pub fn handles(method: &str, path: &str) -> bool {
    method == "GET" && route(path).is_some()
}

/// Answer `GET path?query` as Django would, or decline.
pub async fn serve(ctx: &Context<'_>, req: &ApiRequest<'_>) -> Outcome {
    let Some(route) = route(req.path) else {
        return Outcome::Decline(Decline("route"));
    };
    let query = match py::QueryDict::parse(req.query) {
        Ok(query) => query,
        Err(py::Unsupported) => return Outcome::Decline(Decline("too many fields")),
    };
    if let Err(decline) = drf::admit(req, &query) {
        return Outcome::Decline(decline);
    }
    let (name, result) = match route {
        Route::RolesList => (
            "rbac_roles",
            views::rbac_roles::list(ctx, req, &query).await,
        ),
        Route::RolesRetrieve(pk) => (
            "rbac_roles",
            views::rbac_roles::retrieve(ctx, req, &query, pk).await,
        ),
    };
    match result {
        Ok(answer) => Outcome::Serve {
            route: name,
            answer,
        },
        Err(decline) => Outcome::Decline(decline),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_match_drf_router() {
        assert!(matches!(
            route("/api/v3/rbac/roles/"),
            Some(Route::RolesList)
        ));
        assert!(matches!(
            route("/api/v3/rbac/roles/abc/"),
            Some(Route::RolesRetrieve("abc"))
        ));
        assert!(route("/api/v3/rbac/roles/abc").is_none());
        assert!(route("/api/v3/rbac/roles/a.b/").is_none());
        assert!(route("/api/v3/rbac/roles/abc/used_by/").is_none());
        assert!(route("/api/v3/rbac/roles").is_none());
        assert!(handles("GET", "/api/v3/rbac/roles/"));
        assert!(!handles("POST", "/api/v3/rbac/roles/"));
    }
}
