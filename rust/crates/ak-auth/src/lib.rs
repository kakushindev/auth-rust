//! Request identity for authentik 2026.2.7 (milestone M5): which host,
//! brand and tenant a request belongs to, its client IP, who its bearer
//! credential or session cookie authenticates (with network/`GeoIP`
//! session bindings and impersonation), whether it passes CSRF, and the
//! session and CSRF cookies the response sets.
//!
//! Each function makes the same decision as the Django code it names, using
//! Django's own SQL where Django queries, and is checked against Django by
//! `tests/auth/run.sh`. Side effects Django performs along the way (deleting
//! expired tokens, creating an outpost's service user, saving or flushing
//! sessions, logout events) belong to the write layer (M8) and are not done
//! here; each function says what it leaves to it.

pub mod binding;
pub mod brand;
pub mod client_ip;
pub mod cookie;
pub mod csrf;
pub mod host;
pub mod python;
pub mod session;
pub mod tenant;
pub mod token;
pub mod url;
