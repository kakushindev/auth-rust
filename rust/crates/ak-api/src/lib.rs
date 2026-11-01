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

pub mod avatar;
pub mod cache;
pub mod drf;
pub mod filters;
pub mod json;
pub mod pagination;
pub mod py;
mod registry;
mod session;
pub mod sql;
pub mod views;

pub use ak_auth::{binding::GeoIp, python::timedelta_seconds};
pub use drf::{ApiRequest, Context, SessionSettings};

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
    BrandsList,
    BrandsRetrieve(&'a str),
    TransportsList,
    TransportsRetrieve(&'a str),
    WebhookMappingsList,
    WebhookMappingsRetrieve(&'a str),
    CertificateKeyPairsList,
    CertificateKeyPairsRetrieve(&'a str),
    UsersList,
    UsersRetrieve(&'a str),
    GroupsList,
    GroupsRetrieve(&'a str),
    TokensList,
    TokensRetrieve(&'a str),
    EventsList,
    EventsRetrieve(&'a str),
    NotificationsList,
    NotificationsRetrieve(&'a str),
    RulesList,
    RulesRetrieve(&'a str),
    AssignedByRolesList,
    EntitlementsList,
    EntitlementsRetrieve(&'a str),
}

/// A `DefaultRouter` path under one viewset prefix.
enum Viewset<'a> {
    List,
    Detail(&'a str),
}

/// `prefix` itself (list) or `prefix{pk}/` (detail). The router lists a
/// viewset's `detail=False` actions (`actions`) before its detail route,
/// so `prefix{action}/` is never a pk.
fn viewset<'a>(path: &'a str, prefix: &str, actions: &[&str]) -> Option<Viewset<'a>> {
    let rest = path.strip_prefix(prefix)?;
    if rest.is_empty() {
        return Some(Viewset::List);
    }
    let pk = rest.strip_suffix('/')?;
    (!pk.is_empty() && !pk.contains(['/', '.']) && !actions.contains(&pk))
        .then_some(Viewset::Detail(pk))
}

fn route(path: &str) -> Option<Route<'_>> {
    if let Some(v) = viewset(path, "/api/v3/rbac/roles/", &[]) {
        return Some(match v {
            Viewset::List => Route::RolesList,
            Viewset::Detail(pk) => Route::RolesRetrieve(pk),
        });
    }
    if let Some(v) = viewset(path, "/api/v3/rbac/initial_permissions/", &[]) {
        return Some(match v {
            Viewset::List => Route::InitialPermissionsList,
            Viewset::Detail(pk) => Route::InitialPermissionsRetrieve(pk),
        });
    }
    if let Some(v) = viewset(
        path,
        "/api/v3/rbac/permissions/",
        // Viewsets registered under this prefix before it.
        &["assigned_by_roles", "roles"],
    ) {
        return Some(match v {
            Viewset::List => Route::PermissionsList,
            Viewset::Detail(pk) => Route::PermissionsRetrieve(pk),
        });
    }
    if let Some(v) = viewset(path, "/api/v3/core/brands/", &["current"]) {
        return Some(match v {
            Viewset::List => Route::BrandsList,
            Viewset::Detail(pk) => Route::BrandsRetrieve(pk),
        });
    }
    if let Some(v) = viewset(path, "/api/v3/events/transports/", &[]) {
        return Some(match v {
            Viewset::List => Route::TransportsList,
            Viewset::Detail(pk) => Route::TransportsRetrieve(pk),
        });
    }
    if let Some(v) = viewset(path, "/api/v3/propertymappings/notification/", &[]) {
        return Some(match v {
            Viewset::List => Route::WebhookMappingsList,
            Viewset::Detail(pk) => Route::WebhookMappingsRetrieve(pk),
        });
    }
    if let Some(v) = viewset(path, "/api/v3/crypto/certificatekeypairs/", &["generate"]) {
        return Some(match v {
            Viewset::List => Route::CertificateKeyPairsList,
            Viewset::Detail(pk) => Route::CertificateKeyPairsRetrieve(pk),
        });
    }
    if let Some(v) = viewset(path, "/api/v3/core/users/", views::core_users::ACTIONS) {
        return Some(match v {
            Viewset::List => Route::UsersList,
            Viewset::Detail(pk) => Route::UsersRetrieve(pk),
        });
    }
    if let Some(v) = viewset(path, "/api/v3/core/groups/", &[]) {
        return Some(match v {
            Viewset::List => Route::GroupsList,
            Viewset::Detail(pk) => Route::GroupsRetrieve(pk),
        });
    }
    if let Some(v) = viewset(path, "/api/v3/core/tokens/", &[]) {
        return Some(match v {
            Viewset::List => Route::TokensList,
            Viewset::Detail(pk) => Route::TokensRetrieve(pk),
        });
    }
    if let Some(v) = viewset(
        path,
        "/api/v3/events/events/",
        views::events_events::ACTIONS,
    ) {
        return Some(match v {
            Viewset::List => Route::EventsList,
            Viewset::Detail(pk) => Route::EventsRetrieve(pk),
        });
    }
    if let Some(v) = viewset(path, "/api/v3/events/notifications/", &["mark_all_seen"]) {
        return Some(match v {
            Viewset::List => Route::NotificationsList,
            Viewset::Detail(pk) => Route::NotificationsRetrieve(pk),
        });
    }
    // A list-only viewset (its one detail route is a POST action).
    if matches!(
        viewset(path, "/api/v3/rbac/permissions/assigned_by_roles/", &[]),
        Some(Viewset::List)
    ) {
        return Some(Route::AssignedByRolesList);
    }
    if let Some(v) = viewset(path, "/api/v3/core/application_entitlements/", &[]) {
        return Some(match v {
            Viewset::List => Route::EntitlementsList,
            Viewset::Detail(pk) => Route::EntitlementsRetrieve(pk),
        });
    }
    if let Some(v) = viewset(path, "/api/v3/events/rules/", &[]) {
        return Some(match v {
            Viewset::List => Route::RulesList,
            Viewset::Detail(pk) => Route::RulesRetrieve(pk),
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
    let mut session_state = match session::middleware(ctx, req).await {
        Ok(state) => state,
        Err(decline) => return Outcome::Decline(decline),
    };
    if let Some(answer) = session_state.early.take() {
        return Outcome::Serve {
            route: "session_logout",
            answer,
        };
    }
    let req = &ApiRequest {
        session_user: session_state.user.take(),
        ..req.clone()
    };
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
        Route::BrandsList => (
            "core_brands",
            views::core_brands::list(ctx, req, &query).await,
        ),
        Route::BrandsRetrieve(pk) => (
            "core_brands",
            views::core_brands::retrieve(ctx, req, &query, pk).await,
        ),
        Route::TransportsList => (
            "events_transports",
            views::events_notification_transports::list(ctx, req, &query).await,
        ),
        Route::TransportsRetrieve(pk) => (
            "events_transports",
            views::events_notification_transports::retrieve(ctx, req, &query, pk).await,
        ),
        Route::WebhookMappingsList => (
            "propertymappings_notification",
            views::events_notification_mappings::list(ctx, req, &query).await,
        ),
        Route::WebhookMappingsRetrieve(pk) => (
            "propertymappings_notification",
            views::events_notification_mappings::retrieve(ctx, req, &query, pk).await,
        ),
        Route::CertificateKeyPairsList => (
            "crypto_certificatekeypairs",
            views::crypto_certificatekeypairs::list(ctx, req, &query).await,
        ),
        Route::CertificateKeyPairsRetrieve(pk) => (
            "crypto_certificatekeypairs",
            views::crypto_certificatekeypairs::retrieve(ctx, req, &query, pk).await,
        ),
        Route::UsersList => (
            "core_users",
            views::core_users::list(ctx, req, &query).await,
        ),
        Route::UsersRetrieve(pk) => (
            "core_users",
            views::core_users::retrieve(ctx, req, &query, pk).await,
        ),
        Route::GroupsList => (
            "core_groups",
            views::core_groups::list(ctx, req, &query).await,
        ),
        Route::GroupsRetrieve(pk) => (
            "core_groups",
            views::core_groups::retrieve(ctx, req, &query, pk).await,
        ),
        Route::TokensList => (
            "core_tokens",
            views::core_tokens::list(ctx, req, &query).await,
        ),
        Route::TokensRetrieve(pk) => (
            "core_tokens",
            views::core_tokens::retrieve(ctx, req, &query, pk).await,
        ),
        Route::EventsList => (
            "events_events",
            views::events_events::list(ctx, req, &query).await,
        ),
        Route::EventsRetrieve(pk) => (
            "events_events",
            views::events_events::retrieve(ctx, req, &query, pk).await,
        ),
        Route::NotificationsList => (
            "events_notifications",
            views::events_notifications::list(ctx, req, &query).await,
        ),
        Route::NotificationsRetrieve(pk) => (
            "events_notifications",
            views::events_notifications::retrieve(ctx, req, &query, pk).await,
        ),
        Route::RulesList => (
            "events_rules",
            views::events_notification_rules::list(ctx, req, &query).await,
        ),
        Route::RulesRetrieve(pk) => (
            "events_rules",
            views::events_notification_rules::retrieve(ctx, req, &query, pk).await,
        ),
        Route::AssignedByRolesList => (
            "rbac_permissions_assigned_by_roles",
            views::rbac_assigned_by_roles::list(ctx, req, &query).await,
        ),
        Route::EntitlementsList => (
            "core_application_entitlements",
            views::core_application_entitlements::list(ctx, req, &query).await,
        ),
        Route::EntitlementsRetrieve(pk) => (
            "core_application_entitlements",
            views::core_application_entitlements::retrieve(ctx, req, &query, pk).await,
        ),
    };
    match result {
        Ok(mut answer) => match session::finish(ctx, req, session_state, answer.status).await {
            Ok(cookies) => {
                answer
                    .headers
                    .extend(cookies.into_iter().map(|c| ("set-cookie", c)));
                Outcome::Serve {
                    route: name,
                    answer,
                }
            }
            Err(decline) => Outcome::Decline(decline),
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
        assert!(route("/api/v3/core/brands/current/").is_none());
        assert!(route("/api/v3/rbac/permissions/roles/").is_none());
        assert!(matches!(
            route("/api/v3/rbac/permissions/assigned_by_roles/"),
            Some(Route::AssignedByRolesList)
        ));
        assert!(route("/api/v3/rbac/permissions/assigned_by_roles/x/").is_none());
        assert!(matches!(
            route("/api/v3/core/brands/currentx/"),
            Some(Route::BrandsRetrieve("currentx"))
        ));
        assert!(handles("GET", "/api/v3/rbac/roles/"));
        assert!(!handles("POST", "/api/v3/rbac/roles/"));
    }
}
