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
pub mod json;
pub mod pagination;
pub mod py;
mod registry;
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
    PermissionsList,
    PermissionsRetrieve(&'a str),
    InitialPermissionsList,
    InitialPermissionsRetrieve(&'a str),
}

/// A `DefaultRouter` path under one viewset prefix.
enum Viewset<'a> {
    List,
    Detail(&'a str),
}

/// `prefix` itself (list) or `prefix{pk}/` (detail).
fn viewset<'a>(path: &'a str, prefix: &str) -> Option<Viewset<'a>> {
    let rest = path.strip_prefix(prefix)?;
    if rest.is_empty() {
        return Some(Viewset::List);
    }
    let pk = rest.strip_suffix('/')?;
    (!pk.is_empty() && !pk.contains(['/', '.'])).then_some(Viewset::Detail(pk))
}

fn route(path: &str) -> Option<Route<'_>> {
    if let Some(v) = viewset(path, "/api/v3/rbac/roles/") {
        return Some(match v {
            Viewset::List => Route::RolesList,
            Viewset::Detail(pk) => Route::RolesRetrieve(pk),
        });
    }
    if let Some(v) = viewset(path, "/api/v3/rbac/initial_permissions/") {
        return Some(match v {
            Viewset::List => Route::InitialPermissionsList,
            Viewset::Detail(pk) => Route::InitialPermissionsRetrieve(pk),
        });
    }
    if let Some(v) = viewset(path, "/api/v3/rbac/permissions/") {
        return Some(match v {
            Viewset::List => Route::PermissionsList,
            Viewset::Detail(pk) => Route::PermissionsRetrieve(pk),
        });
    }
    None
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
        Route::PermissionsList => (
            "rbac_permissions",
            views::rbac_permissions::list(ctx, req, &query).await,
        ),
        Route::PermissionsRetrieve(pk) => (
            "rbac_permissions",
            views::rbac_permissions::retrieve(ctx, req, &query, pk).await,
        ),
        Route::InitialPermissionsList => (
            "rbac_initial_permissions",
            views::rbac_initial_permissions::list(ctx, req, &query).await,
        ),
        Route::InitialPermissionsRetrieve(pk) => (
            "rbac_initial_permissions",
            views::rbac_initial_permissions::retrieve(ctx, req, &query, pk).await,
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
